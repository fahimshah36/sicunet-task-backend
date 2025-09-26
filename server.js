const express = require("express");
const crypto = require("crypto");
const { Redis } = require("@upstash/redis");
const multer = require("multer");
const FormData = require("form-data");
const fetch = require("node-fetch");
// CORS middleware - Ultra-permissive version that works with everything
app.use((req, res, next) => {
  // Set CORS headers for all requests
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Methods", "*");
  res.header("Access-Control-Allow-Headers", "*");
  res.header("Access-Control-Max-Age", "86400");
  res.header("Access-Control-Allow-Credentials", "true");

  // Handle preflight OPTIONS requests immediately
  if (req.method === "OPTIONS") {
    console.log(`OPTIONS request received for: ${req.url}`);
    return res.status(200).json({ message: "CORS preflight successful" });
  }

  console.log(`${req.method} request received for: ${req.url}`);
  next();
});
const app = express();

// Configure multer for file uploads (memory storage)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB limit
  },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith("image/")) {
      cb(null, true);
    } else {
      cb(new Error("Only image files are allowed"), false);
    }
  },
});

// Body parser middleware
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
      uploadImage: "POST /upload",
      profile: "GET /api/profile",
      updateProfile: "PUT /api/profile",
      stats: "GET /api/stats",
    },
    storage: "Upstash Redis",
    cors: "Enabled for all origins",
  });
});

// Image upload endpoint (public - placed BEFORE auth middleware)
app.post("/upload", upload.single("file"), async (req, res) => {
  try {
    console.log("Upload request received");

    if (!req.file) {
      return res.status(400).json({
        error: "No file uploaded",
        success: false,
      });
    }

    console.log("File details:", {
      originalname: req.file.originalname,
      mimetype: req.file.mimetype,
      size: req.file.size,
    });

    // Create FormData for tmpfiles.org
    const formData = new FormData();
    formData.append("file", req.file.buffer, {
      filename: req.file.originalname,
      contentType: req.file.mimetype,
    });

    console.log("Uploading to tmpfiles.org...");

    // Upload to tmpfiles.org
    const response = await fetch("https://tmpfiles.org/api/v1/upload", {
      method: "POST",
      body: formData,
      headers: {
        ...formData.getHeaders(),
        "User-Agent": "Mozilla/5.0 (compatible; API Client)",
      },
    });

    console.log("tmpfiles.org response status:", response.status);

    if (!response.ok) {
      const errorText = await response.text();
      console.error("tmpfiles.org error:", errorText);
      throw new Error(`tmpfiles.org responded with status: ${response.status}`);
    }

    const data = await response.json();
    console.log("tmpfiles.org response:", data);

    if (data.status === "success") {
      // Convert to direct download URL
      const imageUrl = data.data.url.replace(
        "tmpfiles.org/",
        "tmpfiles.org/dl/"
      );

      console.log("Upload successful, URL:", imageUrl);

      res.json({
        success: true,
        message: "Image uploaded successfully",
        data: {
          url: imageUrl,
          originalUrl: data.data.url,
          filename: req.file.originalname,
          size: req.file.size,
          mimetype: req.file.mimetype,
        },
      });
    } else {
      throw new Error("tmpfiles.org upload failed");
    }
  } catch (error) {
    console.error("Image upload error:", error);

    // Handle multer errors
    if (error instanceof multer.MulterError) {
      if (error.code === "LIMIT_FILE_SIZE") {
        return res.status(400).json({
          success: false,
          error: "File too large. Maximum size is 5MB.",
        });
      }
    }

    res.status(500).json({
      success: false,
      error: "Failed to upload image. Please try again.",
      details:
        process.env.NODE_ENV === "development" ? error.message : undefined,
    });
  }
});

// Login endpoint - Enhanced with better error handling
app.post("/auth", async (req, res) => {
  try {
    console.log("Auth request received:", {
      body: req.body,
      headers: req.headers,
      method: req.method,
    });

    const { username, password } = req.body;

    if (!username || !password) {
      console.log("Missing credentials");
      return res.status(400).json({
        error: "Username and password are required",
        success: false,
      });
    }

    // Get users from Redis store
    const usersData = await redis.get("users");
    const users = usersData
      ? typeof usersData === "string"
        ? JSON.parse(usersData)
        : usersData
      : {};

    console.log("Available users:", Object.keys(users));

    // Find user
    const user = Object.values(users).find(
      (u) => u.username === username && u.password === password
    );

    if (!user) {
      console.log("Invalid credentials for username:", username);
      return res.status(401).json({
        error: "Invalid credentials",
        success: false,
      });
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

    console.log("Login successful for user:", username);

    res.json({
      message: "Login successful",
      success: true,
      accessToken,
      user: userWithoutPassword,
    });
  } catch (error) {
    console.error("Auth error:", error);
    res.status(500).json({
      error: "Internal server error",
      success: false,
      details:
        process.env.NODE_ENV === "development" ? error.message : undefined,
    });
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

// Middleware for token validation - Modified to be more lenient
async function validateToken(req, res, next) {
  try {
    const authHeader = req.headers.authorization;

    // If no auth header is provided, skip validation for some endpoints
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        error: "Unauthorized - No token provided",
        message: "Please include Authorization header with Bearer token",
      });
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
      return res.status(401).json({
        error: "Unauthorized - Invalid token",
        message: "Token is invalid or expired",
      });
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

// Health check endpoint (no auth required)
app.get("/health", (req, res) => {
  res.json({
    status: "OK",
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    cors: "Enabled",
  });
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
      "POST /upload",
      "GET /api/profile",
      "PUT /api/profile",
      "GET /api/stats",
    ],
  });
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error("Unhandled error:", error);

  // Handle multer errors specifically
  if (error instanceof multer.MulterError) {
    if (error.code === "LIMIT_FILE_SIZE") {
      return res.status(400).json({
        success: false,
        error: "File too large. Maximum size is 5MB.",
      });
    }
    return res.status(400).json({
      success: false,
      error: "File upload error: " + error.message,
    });
  }

  res.status(500).json({ error: "Internal server error" });
});

const PORT = process.env.PORT || 3000;

// For local development
if (process.env.NODE_ENV !== "production") {
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`CORS enabled for all origins`);
  });
}

module.exports = app;
