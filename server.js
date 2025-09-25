const jsonServer = require('json-server');
const express = require('express');
const crypto = require('crypto');

const app = express();
const router = jsonServer.router('db.json');
const middlewares = jsonServer.defaults();

app.use(middlewares);
app.use(express.json());

// Login endpoint
app.post('/auth', (req, res) => {
  const { username, password } = req.body;
  const db = router.db;
  const user = db.get('users').find({ username, password }).value();

  if (!user) return res.status(401).json({ error: 'Invalid credentials' });

  const accessToken = crypto.randomBytes(32).toString('hex');
  db.get('users').find({ id: user.id }).assign({ token: accessToken }).write();

  res.json({ accessToken, ...user });
});

// Middleware for token validation (except GET /api/users)
app.use('/api', (req, res, next) => {
  if (req.method === 'GET' && req.path === '/users') return next();

  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer '))
    return res.status(401).json({ error: 'Unauthorized' });

  const token = authHeader.split(' ')[1];
  const db = router.db;
  const validUser = db.get('users').find({ token }).value();
  if (!validUser) return res.status(401).json({ error: 'Unauthorized' });

  next();
});

// GET /api/users
app.get('/api/users', (req, res) => {
  const db = router.db;
  let users = db.get('users').value();

  const skip = parseInt(req.query.skip) || 0;
  const limit = parseInt(req.query.limit) || 10;

  if (req.query.username)
    users = users.filter(u => u.username.toLowerCase().includes(req.query.username.toLowerCase()));
  if (req.query.email)
    users = users.filter(u => u.email.toLowerCase().includes(req.query.email.toLowerCase()));

  if (req.query.sortBy) {
    const sortField = req.query.sortBy;
    const order = req.query.order === 'desc' ? -1 : 1;
    users = users.sort((a, b) =>
      a[sortField] > b[sortField] ? 1 * order : -1 * order
    );
  }

  const paginatedUsers = users.slice(skip, skip + limit);

  res.json({ users: paginatedUsers, total: users.length, skip, limit });
});

// JSON Server router for /api
app.use('/api', router);

// ❌ DO NOT serve React here
// Export for Vercel serverless
module.exports = app;
