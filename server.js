const express = require('express');
const jsonServer = require('json-server');
const crypto = require('crypto');

const app = express();
const router = jsonServer.router('db.json'); // JSON Server DB
const middlewares = jsonServer.defaults();

app.use(middlewares);
app.use(express.json());

// Root route - should come first
app.get("/", (req, res) => {
  res.json({ message: "API is running..." });
});

// Login endpoint
app.post('/auth', (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }
    
    const db = router.db; // lowdb instance
    const user = db.get('users').find({ username, password }).value();
    
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    
    // Generate a new random access token
    const accessToken = crypto.randomBytes(32).toString('hex');
    
    // Save token in DB
    db.get('users').find({ id: user.id }).assign({ token: accessToken }).write();
    
    // Return user and token (excluding password)
    const { password: _, ...userWithoutPassword } = user;
    res.json({ accessToken, ...userWithoutPassword });
  } catch (error) {
    console.error('Auth error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Custom GET /api/users with pagination & sorting
app.get('/api/users', (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    
    const token = authHeader.split(' ')[1];
    const db = router.db;
    const validUser = db.get('users').find({ token }).value();
    
    if (!validUser) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    
    let users = db.get('users').value();
    
    // Remove passwords from response
    users = users.map(({ password, token, ...user }) => user);
    
    // Pagination
    const skip = parseInt(req.query.skip) || 0;
    const limit = parseInt(req.query.limit) || 10;
    
    // Filtering (username, email)
    if (req.query.username) {
      users = users.filter(u =>
        u.username.toLowerCase().includes(req.query.username.toLowerCase())
      );
    }
    if (req.query.email) {
      users = users.filter(u =>
        u.email.toLowerCase().includes(req.query.email.toLowerCase())
      );
    }
    
    // Sorting
    if (req.query.sortBy) {
      const sortField = req.query.sortBy;
      const order = req.query.order === 'desc' ? -1 : 1;
      users = users.sort((a, b) =>
        a[sortField] > b[sortField] ? 1 * order : -1 * order
      );
    }
    
    const paginatedUsers = users.slice(skip, skip + limit);
    
    res.json({
      users: paginatedUsers,
      total: users.length,
      skip,
      limit
    });
  } catch (error) {
    console.error('Users fetch error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Middleware for token validation (all other /api routes)
app.use('/api', (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer '))
      return res.status(401).json({ error: 'Unauthorized' });
    
    const token = authHeader.split(' ')[1];
    const db = router.db;
    const validUser = db.get('users').find({ token }).value();
    
    if (!validUser) return res.status(401).json({ error: 'Unauthorized' });
    
    next();
  } catch (error) {
    console.error('Auth middleware error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// JSON Server router for other /api routes
app.use('/api', router);

// Catch-all route for undefined endpoints
app.use('*', (req, res) => {
  res.status(404).json({ message: "404 Not Found", path: req.originalUrl });
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  res.status(500).json({ error: 'Internal server error' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));