const path = require('path');
const express = require('express');
const jsonServer = require('json-server');
const crypto = require('crypto');

const app = express();
const router = jsonServer.router('db.json'); // JSON Server DB
const middlewares = jsonServer.defaults();

app.use(middlewares);
app.use(express.json());

// Login endpoint
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const db = router.db; // lowdb instance
  const user = db.get('users').find({ username, password }).value();

  if (!user) return res.status(401).json({ error: 'Invalid credentials' });

  // Generate a new random access token
  const accessToken = crypto.randomBytes(32).toString('hex');

  // Save token in DB
  db.get('users').find({ id: user.id }).assign({ token: accessToken }).write();

  // Return user and token
  res.json({ accessToken, ...user });
});

// Middleware for token validation (all /api except GET /api/users)
app.use('/api', (req, res, next) => {
  const openGet = req.method === 'GET' && req.path === '/users';
  if (openGet) return next();

  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer '))
    return res.status(401).json({ error: 'Unauthorized' });

  const token = authHeader.split(' ')[1];
  const db = router.db;
  const validUser = db.get('users').find({ token }).value();

  if (!validUser) return res.status(401).json({ error: 'Unauthorized' });

  next();
});

// Custom GET /api/users with pagination & sorting
app.get('/api/users', (req, res) => {
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
});



// JSON Server router for /api
app.use('/api', router);

// Serve React build
// const staticPath = path.join(__dirname, 'static');
// app.use(express.static(staticPath));

// Serve static files from the React app
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "client/build", "index.html"));
});

// Middleware for handling unmatched routes
app.use((req, res, next) => {
  res.status(404).json({ message: "404 Not Found" });
});

// Routes
app.get("/", (_, res) => {
  res.send("API is running...");
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
