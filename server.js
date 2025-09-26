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
          email: "admin@example.com",
          password: "password",
          birthDate: "1995-05-10",
          weight: 60.5,
          image: "https://i.pravatar.cc/150?img=1",
          token: "",
          createdAt: new Date().toISOString(),
        },
        2: {
          id: 2,
          username: "user1",
          email: "user1@example.com",
          password: "password123",
          birthDate: "1990-03-15",
          weight: 75.2,
          image: "https://i.pravatar.cc/150?img=2",
          token: "",
          createdAt: new Date().toISOString(),
        },
      };

      // Store users in Redis
      await redis.set("users", defaultUsers);
      await redis.set("user_counter", 2);

      console.log("Default users initialized successfully");
    }
  } catch (error) {
    console.error("Redis initialization error:", error);
  }
}

// Root route with initialization
app.get("/", async (req, res) => {
  await initializeUsers();

  res.json({
    message: "User Management API",
    endpoints: {
      auth: "POST /auth",
      logout: "POST /api/logout",
      users: "GET /api/users",
      createUser: "POST /api/users",
      updateUser: "PUT /api/users/:id",
      deleteUser: "DELETE /api/users/:id",
      stats: "GET /api/stats",
    },
    storage: "Upstash Redis",
  });
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

    // Generate access token
    const accessToken = crypto.randomBytes(32).toString("hex");

    // Update user token in Redis store
    users[user.id] = { ...users[user.id], token: accessToken };
    await redis.set("users", users);

    // Return user without password
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

    // Clear token from Redis
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
    const usersData = await redis.get("users");
    const users = usersData
      ? typeof usersData === "string"
        ? JSON.parse(usersData)
        : usersData
      : {};

    // Remove sensitive data
    let usersList = Object.values(users).map(
      ({ password, token, ...user }) => user
    );

    // Pagination
    const skip = parseInt(req.query.skip) || 0;
    const limit = Math.min(parseInt(req.query.limit) || 10, 100);

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
    const { username, email, password, birthDate, weight, image } = req.body;

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
      birthDate: birthDate || null,
      weight: weight ? parseFloat(weight) : null,
      image: image || `https://i.pravatar.cc/150?img=${newUserId}`,
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
    const { username, email, password, birthDate, weight, image } = req.body;

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
      ...(birthDate !== undefined && { birthDate }),
      ...(weight !== undefined && {
        weight: weight ? parseFloat(weight) : null,
      }),
      ...(image !== undefined && { image }),
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

// Get current user profile
app.get("/api/profile", (req, res) => {
  const { password, token, ...userProfile } = req.user;
  res.json({
    user: userProfile,
  });
});

// Update current user profile
app.put("/api/profile", async (req, res) => {
  try {
    const { username, email, password, birthDate, weight, image } = req.body;

    // Get users from Redis
    const usersData = await redis.get("users");
    const users = usersData
      ? typeof usersData === "string"
        ? JSON.parse(usersData)
        : usersData
      : {};

    // Check for duplicate username/email (excluding current user)
    if (username || email) {
      const duplicate = Object.values(users).find(
        (u) =>
          u.id !== req.user.id &&
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
      ...users[req.user.id],
      ...(username && { username }),
      ...(email && { email }),
      ...(password && { password }),
      ...(birthDate !== undefined && { birthDate }),
      ...(weight !== undefined && {
        weight: weight ? parseFloat(weight) : null,
      }),
      ...(image !== undefined && { image }),
      updatedAt: new Date().toISOString(),
    };

    users[req.user.id] = updatedUser;
    await redis.set("users", users);

    // Return user without password
    const { password: _, token, ...userWithoutPassword } = updatedUser;
    res.json({
      message: "Profile updated successfully",
      user: userWithoutPassword,
    });
  } catch (error) {
    console.error("Update profile error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Get stats
app.get("/api/stats", async (req, res) => {
  try {
    const usersData = await redis.get("users");
    const users = usersData
      ? typeof usersData === "string"
        ? JSON.parse(usersData)
        : usersData
      : {};
    const userCounter = (await redis.get("user_counter")) || 0;

    // Count active sessions
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
      "POST /auth",
      "POST /api/logout",
      "GET /api/users",
      "POST /api/users",
      "PUT /api/users/:id",
      "DELETE /api/users/:id",
      "GET /api/profile",
      "PUT /api/profile",
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

module.exports = app;
