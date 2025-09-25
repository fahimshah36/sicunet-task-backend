const path = require('path');
const express = require('express');
const jsonServer = require('json-server');
const crypto = require('crypto');
const fs = require('fs');

const app = express();

// Initialize db.json if it doesn't exist (important for Vercel)
const dbPath = path.join(__dirname, 'db.json');
if (!fs.existsSync(dbPath)) {
  const initialDb = {
    "users": [
      {
        "id": 1,
        "firstName": "Samantha",
        "lastName": "Martinez", 
        "username": "samanthal",
        "email": "samantha@example.com",
        "birthDate": "1997-09-03",
        "weight": 55.48,
        "image": "https://dummyimage.com/128x128/000/fff&text=S",
        "password": "password123" // Add default password
      }
    ]
  };
  fs.writeFileSync(dbPath, JSON.stringify(initialDb, null, 2));
}

const router = jsonServer.router(dbPath);
const middlewares = jsonServer.defaults({
  static: false // Disable static file serving from json-server
});

app.use(middlewares);
app.use(express.json());

// Login endpoint
app.post('/auth', (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }
    
    const db = router.db;
    const user = db.get('users').find({ username, password }).value();
    
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Generate a new random access token
    const accessToken = crypto.randomBytes(32).toString('hex');
    
    // Save token in DB
    db.get('users').find({ id: user.id }).assign({ token: accessToken }).write();
    
    // Return user and token (don't include password)
    const { password: pwd, ...userWithoutPassword } = user;
    res.json({ accessToken, user: userWithoutPassword });
  } catch (error) {
    console.error('Auth error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Middleware for token validation
app.use('/api', (req, res, next) => {
  try {
    // Skip auth for GET /api/users (if you want it public)
    const openGet = req.method === 'GET' && req.path === '/users';
    if (openGet) return next();
    
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Unauthorized - No token provided' });
    }
    
    const token = authHeader.split(' ')[1];
    if (!token) {
      return res.status(401).json({ error: 'Unauthorized - Invalid token format' });
    }
    
    const db = router.db;
    const validUser = db.get('users').find({ token }).value();
    
    if (!validUser) {
      return res.status(401).json({ error: 'Unauthorized - Invalid token' });
    }
    
    req.user = validUser; // Add user to request
    next();
  } catch (error) {
    console.error('Auth middleware error:', error);
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
    
    // Remove sensitive data
    users = users.map(({ password, token, ...user }) => user);
    
    // Pagination
    const skip = parseInt(req.query.skip) || 0;
    const limit = parseInt(req.query.limit) || 10;
    
    // Filtering
    if (req.query.username) {
      users = users.filter(u =>
        u.username && u.username.toLowerCase().includes(req.query.username.toLowerCase())
      );
    }
    if (req.query.email) {
      users = users.filter(u =>
        u.email && u.email.toLowerCase().includes(req.query.email.toLowerCase())
      );
    }
    
    // Sorting
    if (req.query.sortBy) {
      const sortField = req.query.sortBy;
      const order = req.query.order === 'desc' ? -1 : 1;
      users = users.sort((a, b) => {
        if (!a[sortField] && !b[sortField]) return 0;
        if (!a[sortField]) return 1 * order;
        if (!b[sortField]) return -1 * order;
        return a[sortField] > b[sortField] ? 1 * order : -1 * order;
      });
    }
    
    const totalFiltered = users.length;
    const paginatedUsers = users.slice(skip, skip + limit);
    
    res.json({
      users: paginatedUsers,
      total: totalFiltered,
      skip,
      limit
    });
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// JSON Server router for other /api routes
app.use('/api', router);

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Serve static files from React app (only in production)
if (process.env.NODE_ENV === 'production') {
  const buildPath = path.join(__dirname, 'client/build');
  if (fs.existsSync(buildPath)) {
    app.use(express.static(buildPath));
    
    app.get('*', (req, res) => {
      res.sendFile(path.join(buildPath, 'index.html'));
    });
  }
}

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  res.status(500).json({ error: 'Internal server error' });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ message: '404 Not Found' });
});

// Export for Vercel
module.exports = app;