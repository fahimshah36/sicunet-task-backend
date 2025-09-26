const express = require("express");
const crypto = require("crypto");
const { Redis } = require("@upstash/redis");
const multer = require("multer");
const FormData = require("form-data");
const fetch = require("node-fetch");

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

// Parse JSON and URL-encoded data
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));

// Initialize Upstash Redis client
const redis = new Redis({
  url: process.env.KV_REST_API_URL,
  token: process.env.KV_REST_API_TOKEN,
});

// Initialize default users in Redis store
async function initializeUsers() {
  try {
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
      uploadImage: "POST /api/upload",
    },
    storage: "Upstash Redis",
  });
});

// Image upload endpoint (public - no auth required)
app.post("/api/upload", upload.single("file"), async (req, res) => {
  try {
    console.log("Upload request received");
    console.log("File:", req.file ? "Present" : "Missing");

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

// Login endpoint
app.post("/auth", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res
        .status(400)
        .json({ error: "Username and password are required" });
    }

    const usersData = await redis.get("users");
    const users = usersData
      ? typeof usersData === "string"
        ? JSON.parse(usersData)
        : usersData
      : {};

    const user = Object.values(users).find(
      (u) => u.username === username && u.password === password
    );

    if (!user) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const accessToken = crypto.randomBytes(32).toString("hex");

    users[user.id] = { ...users[user.id], token: accessToken };
    await redis.set("users", users);

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

// Apply auth middleware to protected routes only
app.use("/api/users", validateToken);
app.use("/api/logout", validateToken);

// GET /api/users with pagination & sorting
app.get("/api/users", async (req, res) => {
  try {
    const usersData = await redis.get("users");
    const users = usersData
      ? typeof usersData === "string"
        ? JSON.parse(usersData)
        : usersData
      : {};

    let usersList = Object.values(users).map(
      ({ password, token, ...user }) => user
    );

    const skip = parseInt(req.query.skip) || 0;
    const limit = Math.min(parseInt(req.query.limit) || 10, 100);

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

    const usersData = await redis.get("users");
    const users = usersData
      ? typeof usersData === "string"
        ? JSON.parse(usersData)
        : usersData
      : {};
    const userCounter = (await redis.get("user_counter")) || 0;

    const existingUser = Object.values(users).find(
      (u) => u.username === username || u.email === email
    );

    if (existingUser) {
      return res.status(409).json({
        error: "User with this username or email already exists",
      });
    }

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

    users[newUserId] = newUser;
    await redis.set("users", users);
    await redis.set("user_counter", newUserId);

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

    const usersData = await redis.get("users");
    const users = usersData
      ? typeof usersData === "string"
        ? JSON.parse(usersData)
        : usersData
      : {};

    if (!users[userId]) {
      return res.status(404).json({ error: "User not found" });
    }

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

    const usersData = await redis.get("users");
    const users = usersData
      ? typeof usersData === "string"
        ? JSON.parse(usersData)
        : usersData
      : {};

    if (!users[userId]) {
      return res.status(404).json({ error: "User not found" });
    }

    if (req.user.id === userId) {
      return res.status(400).json({ error: "Cannot delete your own account" });
    }

    delete users[userId];
    await redis.set("users", users);

    res.json({ message: "User deleted successfully" });
  } catch (error) {
    console.error("Delete user error:", error);
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
      "POST /api/upload",
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

  res.status(500).json({
    success: false,
    error: "Internal server error",
  });
});

const PORT = process.env.PORT || 3000;

if (process.env.NODE_ENV !== "production") {
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
}

module.exports = app;
