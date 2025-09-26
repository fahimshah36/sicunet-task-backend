const express = require("express");
const crypto = require("crypto");
const { Redis } = require("@upstash/redis");

const app = express();

// CORS middleware - Allow all origins
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  res.header(
    "Access-Control-Allow-Headers",
    "Origin, X-Requested-With, Content-Type, Accept, Authorization"
  );

  // Handle preflight requests
  if (req.method === "OPTIONS") {
    res.sendStatus(200);
  } else {
    next();
  }
});

app.use(express.json());

// Initialize Upstash Redis client
const redis = new Redis({
  url: process.env.KV_REST_API_URL,
  token: process.env.KV_REST_API_TOKEN,
});

// Initialize default users in Redis store
async function initializeUsers() {
  try {
    // Check if users already exist
    const existingUsers = await redis.exists("users");

    if (!existingUsers) {
      console.log("Initializing default users in Redis store...");

      const defaultUsers = {
        1: {
          id: 1,
          username: "admin",
          password: "password",
          email: "admin@example.com",
          token: "",
          createdAt: new Date().toISOString(),
        },
        2: {
          id: 2,
          username: "user1",
          password: "password123",
          email: "user1@example.com",
          token: "",
          createdAt: new Date().toISOString(),
        },
      };

      // Store users in Redis as an object (Upstash handles JSON automatically)
      await redis.set("users", defaultUsers);

      // Also store a counter for new user IDs
      await redis.set("user_counter", 2);

      console.log("Default users initialized successfully");
    }
  } catch (error) {
    console.error("Redis initialization error:", error);
  }
}

// Root route with initialization
app.get("/", async (req, res) => {
  // Initialize users if needed
  await initializeUsers();

  res.json({
    message: "API is running with Upstash Redis storage...",
    endpoints: {
      auth: "POST /auth",
      users: "GET /api/users",
      createUser: "POST /api/users",
      updateUser: "PUT /api/users/:id",
      deleteUser: "DELETE /api/users/:id",
      logout: "POST /api/logout",
      status: "GET /",
      health: "GET /health",
    },
    storage: "Upstash Redis",
  });
});

// Health check
app.get("/health", async (req, res) => {
  try {
    // Test Redis connection
    await redis.ping();
    res.json({
      status: "OK",
      timestamp: new Date().toISOString(),
      storage: "Redis Connected",
    });
  } catch (error) {
    res.status(500).json({
      status: "ERROR",
      timestamp: new Date().toISOString(),
      error: "Redis Connection Failed",
    });
  }
});

// Login endpoint
app.post("/auth", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res
        .status(400)
        .json({ error: "Username and password are required" });
    }

    // Get users from Redis store
    const usersData = await redis.get("users");
    const users = usersData
      ? typeof usersData === "string"
        ? JSON.parse(usersData)
        : usersData
      : {};

    // Find user
    const user = Object.values(users).find(
      (u) => u.username === username && u.password === password
    );

    if (!user) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Generate a new random access token
    const accessToken = crypto.randomBytes(32).toString("hex");

    // Update user token in Redis store
    users[user.id] = { ...users[user.id], token: accessToken };
    await redis.set("users", users);

    // Return user and token (excluding password)
    const { password: _, ...userWithoutPassword } = {
      ...user,
      token: accessToken,
    };

    res.json({
      message: "Login successful",
      accessToken,
      user: userWithoutPassword,
    });
  } catch (error) {
    console.error("Auth error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Logout endpoint
app.post("/api/logout", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ error: "No token provided" });
    }

    const token = authHeader.split(" ")[1];

    // Get users and clear the token
    const usersData = await redis.get("users");
    const users = usersData
      ? typeof usersData === "string"
        ? JSON.parse(usersData)
        : usersData
      : {};
    const user = Object.values(users).find((u) => u.token === token);

    if (user) {
      users[user.id] = { ...users[user.id], token: "" };
      await redis.set("users", users);
    }

    res.json({ message: "Logout successful" });
  } catch (error) {
    console.error("Logout error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Middleware for token validation
async function validateToken(req, res, next) {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res
        .status(401)
        .json({ error: "Unauthorized - No token provided" });
    }

    const token = authHeader.split(" ")[1];

    // Get users from Redis store
    const usersData = await redis.get("users");
    const users = usersData
      ? typeof usersData === "string"
        ? JSON.parse(usersData)
        : usersData
      : {};
    const user = Object.values(users).find((u) => u.token === token);

    if (!user || !user.token) {
      return res.status(401).json({ error: "Unauthorized - Invalid token" });
    }

    // Add user to request object
    req.user = user;
    next();
  } catch (error) {
    console.error("Auth middleware error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
}

// Apply auth middleware to all /api routes
app.use("/api", validateToken);

// GET /api/users with pagination & sorting
app.get("/api/users", async (req, res) => {
  try {
    // Get users from Redis store
    const usersData = await redis.get("users");
    const users = usersData
      ? typeof usersData === "string"
        ? JSON.parse(usersData)
        : usersData
      : {};

    // Convert to array and remove sensitive data
    let usersList = Object.values(users).map(
      ({ password, token, ...user }) => user
    );

    // Pagination
    const skip = parseInt(req.query.skip) || 0;
    const limit = Math.min(parseInt(req.query.limit) || 10, 100); // Max 100

    // Filtering
    if (req.query.username) {
      usersList = usersList.filter((u) =>
        u.username.toLowerCase().includes(req.query.username.toLowerCase())
      );
    }
    if (req.query.email) {
      usersList = usersList.filter((u) =>
        u.email.toLowerCase().includes(req.query.email.toLowerCase())
      );
    }

    // Sorting
    if (req.query.sortBy) {
      const sortField = req.query.sortBy;
      const order = req.query.order === "desc" ? -1 : 1;
      usersList = usersList.sort((a, b) => {
        if (a[sortField] > b[sortField]) return 1 * order;
        if (a[sortField] < b[sortField]) return -1 * order;
        return 0;
      });
    }

    const paginatedUsers = usersList.slice(skip, skip + limit);

    res.json({
      users: paginatedUsers,
      total: usersList.length,
      skip,
      limit,
      hasMore: skip + limit < usersList.length,
    });
  } catch (error) {
    console.error("Users fetch error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// POST /api/users - Create new user
app.post("/api/users", async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({
        error: "Username, email, and password are required",
      });
    }

    // Get existing users and counter
    const usersData = await redis.get("users");
    const users = usersData
      ? typeof usersData === "string"
        ? JSON.parse(usersData)
        : usersData
      : {};
    const userCounter = (await redis.get("user_counter")) || 0;

    // Check if user already exists
    const existingUser = Object.values(users).find(
      (u) => u.username === username || u.email === email
    );

    if (existingUser) {
      return res.status(409).json({
        error: "User with this username or email already exists",
      });
    }

    // Create new user
    const newUserId = parseInt(userCounter) + 1;
    const newUser = {
      id: newUserId,
      username,
      email,
      password,
      token: "",
      createdAt: new Date().toISOString(),
    };

    // Update users and counter in Redis
    users[newUserId] = newUser;
    await redis.set("users", users);
    await redis.set("user_counter", newUserId);

    // Return user without password
    const { password: _, ...userWithoutPassword } = newUser;
    res.status(201).json({
      message: "User created successfully",
      user: userWithoutPassword,
    });
  } catch (error) {
    console.error("Create user error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// PUT /api/users/:id - Update user
app.put("/api/users/:id", async (req, res) => {
  try {
    const userId = parseInt(req.params.id);
    const { username, email, password } = req.body;

    if (!userId || isNaN(userId)) {
      return res.status(400).json({ error: "Valid user ID is required" });
    }

    // Get users from Redis
    const usersData = await redis.get("users");
    const users = usersData
      ? typeof usersData === "string"
        ? JSON.parse(usersData)
        : usersData
      : {};

    if (!users[userId]) {
      return res.status(404).json({ error: "User not found" });
    }

    // Check for duplicate username/email (excluding current user)
    if (username || email) {
      const duplicate = Object.values(users).find(
        (u) =>
          u.id !== userId &&
          ((username && u.username === username) ||
            (email && u.email === email))
      );

      if (duplicate) {
        return res.status(409).json({
          error: "Username or email already exists",
        });
      }
    }

    // Update user data
    const updatedUser = {
      ...users[userId],
      ...(username && { username }),
      ...(email && { email }),
      ...(password && { password }),
      updatedAt: new Date().toISOString(),
    };

    users[userId] = updatedUser;
    await redis.set("users", users);

    // Return user without password
    const { password: _, token, ...userWithoutPassword } = updatedUser;
    res.json({
      message: "User updated successfully",
      user: userWithoutPassword,
    });
  } catch (error) {
    console.error("Update user error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// DELETE /api/users/:id - Delete user
app.delete("/api/users/:id", async (req, res) => {
  try {
    const userId = parseInt(req.params.id);

    if (!userId || isNaN(userId)) {
      return res.status(400).json({ error: "Valid user ID is required" });
    }

    // Get users from Redis
    const usersData = await redis.get("users");
    const users = usersData
      ? typeof usersData === "string"
        ? JSON.parse(usersData)
        : usersData
      : {};

    if (!users[userId]) {
      return res.status(404).json({ error: "User not found" });
    }

    // Prevent deleting yourself
    if (req.user.id === userId) {
      return res.status(400).json({ error: "Cannot delete your own account" });
    }

    // Delete user
    delete users[userId];
    await redis.set("users", users);

    res.json({ message: "User deleted successfully" });
  } catch (error) {
    console.error("Delete user error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Test endpoint
app.get("/api/test", (req, res) => {
  res.json({
    message: "API endpoint working with Upstash Redis",
    authenticated: true,
    user: {
      id: req.user.id,
      username: req.user.username,
      email: req.user.email,
    },
    timestamp: new Date().toISOString(),
  });
});

// Debug endpoint (only in development)
app.get("/api/debug", async (req, res) => {
  if (process.env.NODE_ENV === "production") {
    return res.status(404).json({ error: "Not found" });
  }

  try {
    const usersData = await redis.get("users");
    const users = usersData
      ? typeof usersData === "string"
        ? JSON.parse(usersData)
        : usersData
      : {};
    const userCounter = (await redis.get("user_counter")) || 0;

    res.json({
      userCount: Object.keys(users).length,
      userCounter,
      users: Object.values(users).map(({ password, token, ...user }) => user),
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get Redis stats
app.get("/api/stats", async (req, res) => {
  try {
    const usersData = await redis.get("users");
    const users = usersData ? JSON.parse(usersData) : {};
    const userCounter = (await redis.get("user_counter")) || 0;

    // Count active sessions (users with tokens)
    const activeSessions = Object.values(users).filter(
      (u) => u.token && u.token !== ""
    ).length;

    res.json({
      totalUsers: Object.keys(users).length,
      activeSessions,
      lastUserId: userCounter,
      serverTime: new Date().toISOString(),
    });
  } catch (error) {
    console.error("Stats error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Catch-all route
app.use("*", (req, res) => {
  res.status(404).json({
    message: "404 Not Found",
    path: req.originalUrl,
    availableRoutes: [
      "GET /",
      "GET /health",
      "POST /auth",
      "POST /api/logout",
      "GET /api/users",
      "POST /api/users",
      "PUT /api/users/:id",
      "DELETE /api/users/:id",
      "GET /api/test",
      "GET /api/stats",
    ],
  });
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error("Unhandled error:", error);
  res.status(500).json({ error: "Internal server error" });
});

const PORT = process.env.PORT || 3000;

// For local development
if (process.env.NODE_ENV !== "production") {
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
}

// Export for Vercel
module.exports = app;
