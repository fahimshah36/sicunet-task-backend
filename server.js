const express = require('express');
const jsonServer = require('json-server');
const crypto = require('crypto');
const fs = require('fs');

const app = express();

// In-memory database for Vercel (since file system is read-only)
let dbData;
try {
  // Try to read from file first (for local development)
  const dbFile = fs.readFileSync('db.json', 'utf8');
  dbData = JSON.parse(dbFile);
} catch (error) {
  // Fallback data if file doesn't exist or can't be read
  dbData = {
    users: [
      {
        id: 1,
        username: "admin",
        password: "password",
        email: "admin@example.com",
        token: ""
      },
      {
        id: 2,
        username: "user1", 
        password: "password123",
        email: "user1@example.com",
        token: ""
      }
    ]
  };
}

// Create router with in-memory data
const router = jsonServer.router(dbData);
const middlewares = jsonServer.defaults();

app.use(middlewares);
app.use(express.json());

// Root route
app.get("/", (req, res) => {
  res.json({ 
    message: "API is running...",
    endpoints: {
      auth: "POST /auth",
      users: "GET /api/users",
      status: "GET /"
    }
  });
});

// Health check
app.get("/health", (req, res) => {
  res.json({ status: "OK", timestamp: new Date().toISOString() });
});

// Login endpoint
app.post('/auth', (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }
    
    // Find user in memory
    const user = dbData.users.find(u => u.username === username && u.password === password);
    
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Generate a new random access token
    const accessToken = crypto.randomBytes(32).toString('hex');
    
    // Update token in memory (since we can't write to file in Vercel)
    user.token = accessToken;
    
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
    const validUser = dbData.users.find(u => u.token === token);
    
    if (!validUser) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    
    // Get users without passwords and tokens
    let users = dbData.users.map(({ password, token, ...user }) => user);
    
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
      users = users.sort((a, b) => {
        if (a[sortField] > b[sortField]) return 1 * order;
        if (a[sortField] < b[sortField]) return -1 * order;
        return 0;
      });
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
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    
    const token = authHeader.split(' ')[1];
    const validUser = dbData.users.find(u => u.token === token);
    
    if (!validUser) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    
    next();
  } catch (error) {
    console.error('Auth middleware error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Simple API routes for testing
app.get('/api/test', (req, res) => {
  res.json({ message: 'API endpoint working', authenticated: true });
});

// Catch-all route for undefined endpoints
app.use('*', (req, res) => {
  res.status(404).json({ 
    message: "404 Not Found", 
    path: req.originalUrl,
    availableRoutes: ["/", "/health", "POST /auth", "GET /api/users", "GET /api/test"]
  });
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  res.status(500).json({ error: 'Internal server error' });
});

const PORT = process.env.PORT || 3000;

// Export for Vercel
module.exports = app;