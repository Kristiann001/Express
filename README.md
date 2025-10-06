// index.js - Complete Express MVC Implementation in Single File

/**
 * 🎯 LEARNING OBJECTIVES:
 * 1. Understand MVC Architecture in one file
 * 2. See how middleware works
 * 3. Learn database connection setup
 * 4. Understand how to separate concerns later
 */

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 5000;

// ============================================================================
// 🗃️ DATABASE CONNECTION SETUP
// ============================================================================

/**
 * 📝 DATABASE CONCEPT:
 * - mongoose.connect() establishes connection to MongoDB
 * - Connection string format: mongodb://localhost:27017/database-name
 * - We'll move this to config/database.js later
 */
mongoose.connect('mongodb://localhost:27017/express_single_file_demo', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
.then(() => console.log('✅ MongoDB Connected Successfully'))
.catch(err => console.log('❌ MongoDB Connection Error:', err));

// ============================================================================
// 📊 MODELS (Data Layer - M in MVC)
// ============================================================================

/**
 * 📝 MODEL CONCEPT:
 * - Models define your data structure and database schema
 * - They handle data validation, relationships, and business logic
 * - We'll move these to models/ folder later
 */

// User Model
const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: [true, 'Username is required'],
        unique: true,
        trim: true,
        minlength: [3, 'Username must be at least 3 characters']
    },
    email: {
        type: String,
        required: [true, 'Email is required'],
        unique: true,
        lowercase: true
    },
    password: {
        type: String,
        required: [true, 'Password is required'],
        minlength: 6,
        select: false // Don't return password by default
    },
    role: {
        type: String,
        enum: ['user', 'admin'],
        default: 'user'
    }
}, {
    timestamps: true // Adds createdAt and updatedAt automatically
});

// Hash password before saving
userSchema.pre('save', async function(next) {
    if (!this.isModified('password')) return next();
    
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
});

// Compare password method
userSchema.methods.comparePassword = async function(candidatePassword) {
    return await bcrypt.compare(candidatePassword, this.password);
};

const User = mongoose.model('User', userSchema);

// Post Model
const postSchema = new mongoose.Schema({
    title: {
        type: String,
        required: [true, 'Post title is required'],
        trim: true,
        maxlength: [100, 'Title cannot exceed 100 characters']
    },
    content: {
        type: String,
        required: [true, 'Post content is required']
    },
    author: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    status: {
        type: String,
        enum: ['draft', 'published'],
        default: 'draft'
    }
}, {
    timestamps: true
});

const Post = mongoose.model('Post', postSchema);

// ============================================================================
// ⚙️ MIDDLEWARE (Request Processing Layer)
// ============================================================================

/**
 * 📝 MIDDLEWARE CONCEPT:
 * - Functions that have access to request and response objects
 * - Can execute code, modify requests, or end request-response cycle
 * - We'll move these to middleware/ folder later
 */

// 1. Built-in Middleware - Parse incoming JSON
app.use(express.json());

// 2. Custom Middleware - Logging
const requestLogger = (req, res, next) => {
    console.log(`📨 ${req.method} ${req.path} - ${new Date().toISOString()}`);
    next(); // Always call next() to pass to next middleware
};
app.use(requestLogger);

// 3. Authentication Middleware
const authenticateToken = async (req, res, next) => {
    try {
        const token = req.header('Authorization')?.replace('Bearer ', '');
        
        if (!token) {
            return res.status(401).json({
                success: false,
                message: 'Access denied. No token provided.'
            });
        }

        const decoded = jwt.verify(token, 'your-secret-key');
        const user = await User.findById(decoded.id).select('-password');
        
        if (!user) {
            return res.status(401).json({
                success: false,
                message: 'Invalid token.'
            });
        }

        req.user = user; // Attach user to request object
        next();
    } catch (error) {
        res.status(401).json({
            success: false,
            message: 'Invalid token.'
        });
    }
};

// 4. Authorization Middleware
const requireAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({
            success: false,
            message: 'Access denied. Admin role required.'
        });
    }
    next();
};

// ============================================================================
// 🎮 CONTROLLERS (Business Logic Layer - C in MVC)
// ============================================================================

/**
 * 📝 CONTROLLER CONCEPT:
 * - Handle the application logic and request processing
 * - Interact with models and send responses
 * - We'll move these to controllers/ folder later
 */

// Auth Controller
const authController = {
    // Register User
    register: async (req, res) => {
        try {
            const { username, email, password } = req.body;

            // Check if user exists
            const existingUser = await User.findOne({
                $or: [{ email }, { username }]
            });

            if (existingUser) {
                return res.status(400).json({
                    success: false,
                    message: 'User already exists with this email or username'
                });
            }

            // Create user
            const user = await User.create({
                username,
                email,
                password
            });

            // Generate JWT token
            const token = jwt.sign(
                { id: user._id }, 
                'your-secret-key', 
                { expiresIn: '30d' }
            );

            res.status(201).json({
                success: true,
                message: 'User registered successfully',
                data: {
                    user: {
                        id: user._id,
                        username: user.username,
                        email: user.email,
                        role: user.role
                    },
                    token
                }
            });

        } catch (error) {
            res.status(500).json({
                success: false,
                message: 'Error registering user',
                error: error.message
            });
        }
    },

    // Login User
    login: async (req, res) => {
        try {
            const { email, password } = req.body;

            // Find user and include password
            const user = await User.findOne({ email }).select('+password');

            if (!user || !(await user.comparePassword(password))) {
                return res.status(401).json({
                    success: false,
                    message: 'Invalid email or password'
                });
            }

            // Generate JWT token
            const token = jwt.sign(
                { id: user._id }, 
                'your-secret-key', 
                { expiresIn: '30d' }
            );

            res.json({
                success: true,
                message: 'Login successful',
                data: {
                    user: {
                        id: user._id,
                        username: user.username,
                        email: user.email,
                        role: user.role
                    },
                    token
                }
            });

        } catch (error) {
            res.status(500).json({
                success: false,
                message: 'Error logging in',
                error: error.message
            });
        }
    },

    // Get Current User
    getMe: async (req, res) => {
        try {
            res.json({
                success: true,
                data: req.user
            });
        } catch (error) {
            res.status(500).json({
                success: false,
                message: 'Error fetching user data',
                error: error.message
            });
        }
    }
};

// Post Controller
const postController = {
    // Get All Posts
    getPosts: async (req, res) => {
        try {
            const posts = await Post.find({ status: 'published' })
                .populate('author', 'username email')
                .sort({ createdAt: -1 });

            res.json({
                success: true,
                count: posts.length,
                data: posts
            });
        } catch (error) {
            res.status(500).json({
                success: false,
                message: 'Error fetching posts',
                error: error.message
            });
        }
    },

    // Get Single Post
    getPost: async (req, res) => {
        try {
            const post = await Post.findById(req.params.id)
                .populate('author', 'username email');

            if (!post) {
                return res.status(404).json({
                    success: false,
                    message: 'Post not found'
                });
            }

            res.json({
                success: true,
                data: post
            });
        } catch (error) {
            res.status(500).json({
                success: false,
                message: 'Error fetching post',
                error: error.message
            });
        }
    },

    // Create Post
    createPost: async (req, res) => {
        try {
            const { title, content, status } = req.body;

            const post = await Post.create({
                title,
                content,
                author: req.user.id, // From auth middleware
                status: status || 'draft'
            });

            // Populate author details
            await post.populate('author', 'username email');

            res.status(201).json({
                success: true,
                message: 'Post created successfully',
                data: post
            });
        } catch (error) {
            res.status(500).json({
                success: false,
                message: 'Error creating post',
                error: error.message
            });
        }
    },

    // Update Post
    updatePost: async (req, res) => {
        try {
            let post = await Post.findById(req.params.id);

            if (!post) {
                return res.status(404).json({
                    success: false,
                    message: 'Post not found'
                });
            }

            // Check if user owns the post or is admin
            if (post.author.toString() !== req.user.id && req.user.role !== 'admin') {
                return res.status(403).json({
                    success: false,
                    message: 'Not authorized to update this post'
                });
            }

            post = await Post.findByIdAndUpdate(
                req.params.id,
                req.body,
                { new: true, runValidators: true }
            ).populate('author', 'username email');

            res.json({
                success: true,
                message: 'Post updated successfully',
                data: post
            });
        } catch (error) {
            res.status(500).json({
                success: false,
                message: 'Error updating post',
                error: error.message
            });
        }
    },

    // Delete Post
    deletePost: async (req, res) => {
        try {
            const post = await Post.findById(req.params.id);

            if (!post) {
                return res.status(404).json({
                    success: false,
                    message: 'Post not found'
                });
            }

            // Check if user owns the post or is admin
            if (post.author.toString() !== req.user.id && req.user.role !== 'admin') {
                return res.status(403).json({
                    success: false,
                    message: 'Not authorized to delete this post'
                });
            }

            await Post.findByIdAndDelete(req.params.id);

            res.json({
                success: true,
                message: 'Post deleted successfully'
            });
        } catch (error) {
            res.status(500).json({
                success: false,
                message: 'Error deleting post',
                error: error.message
            });
        }
    }
};

// ============================================================================
// 🛣️ ROUTES (Routing Layer - V in MVC for API endpoints)
// ============================================================================

/**
 * 📝 ROUTES CONCEPT:
 * - Define API endpoints and connect them to controllers
 * - Apply middleware to specific routes
 * - We'll move these to routes/ folder later
 */

// Welcome Route
app.get('/', (req, res) => {
    res.json({
        success: true,
        message: 'Welcome to Express MVC Single File Demo!',
        timestamp: new Date().toISOString(),
        endpoints: {
            auth: {
                'POST /api/auth/register': 'Register new user',
                'POST /api/auth/login': 'Login user',
                'GET /api/auth/me': 'Get current user (Protected)'
            },
            posts: {
                'GET /api/posts': 'Get all published posts (Public)',
                'GET /api/posts/:id': 'Get single post (Public)',
                'POST /api/posts': 'Create new post (Protected)',
                'PUT /api/posts/:id': 'Update post (Protected)',
                'DELETE /api/posts/:id': 'Delete post (Protected)'
            }
        }
    });
});

// Auth Routes
app.post('/api/auth/register', authController.register);
app.post('/api/auth/login', authController.login);
app.get('/api/auth/me', authenticateToken, authController.getMe);

// Post Routes
app.get('/api/posts', postController.getPosts);
app.get('/api/posts/:id', postController.getPost);
app.post('/api/posts', authenticateToken, postController.createPost);
app.put('/api/posts/:id', authenticateToken, postController.updatePost);
app.delete('/api/posts/:id', authenticateToken, postController.deletePost);

// Admin-only Route Example
app.get('/api/admin/users', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const users = await User.find().select('-password');
        res.json({
            success: true,
            count: users.length,
            data: users
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Error fetching users',
            error: error.message
        });
    }
});

// ============================================================================
// 🚨 ERROR HANDLING MIDDLEWARE (Always at the end)
// ============================================================================

// 404 Handler - Catch undefined routes
app.use('*', (req, res) => {
    res.status(404).json({
        success: false,
        message: `Route ${req.originalUrl} not found`
    });
});

// Global Error Handler
app.use((err, req, res, next) => {
    console.error('🚨 Global Error Handler:', err.stack);
    
    // Mongoose validation error
    if (err.name === 'ValidationError') {
        const messages = Object.values(err.errors).map(val => val.message);
        return res.status(400).json({
            success: false,
            message: 'Validation Error',
            errors: messages
        });
    }

    // Mongoose duplicate key error
    if (err.code === 11000) {
        return res.status(400).json({
            success: false,
            message: 'Duplicate field value entered'
        });
    }

    // JWT errors
    if (err.name === 'JsonWebTokenError') {
        return res.status(401).json({
            success: false,
            message: 'Invalid token'
        });
    }

    // Default server error
    res.status(500).json({
        success: false,
        message: 'Internal Server Error',
        error: process.env.NODE_ENV === 'development' ? err.message : {}
    });
});

// ============================================================================
// 🚀 START SERVER
// ============================================================================

app.listen(PORT, () => {
    console.log(`
    🚀 Express Server Running!
    📍 Port: ${PORT}
    🌐 Environment: ${process.env.NODE_ENV || 'development'}
    📚 API Documentation: http://localhost:${PORT}
    
    🏗️  Architecture Overview:
    ├── 📊 Models (Data Layer)
    │   ├── User Model
    │   └── Post Model
    ├── ⚙️ Middleware (Request Processing)
    │   ├── JSON Parser
    │   ├── Request Logger
    │   ├── Authentication
    │   └── Authorization
    ├── 🎮 Controllers (Business Logic)
    │   ├── Auth Controller
    │   └── Post Controller
    ├── 🛣️ Routes (API Endpoints)
    │   ├── Auth Routes
    │   └── Post Routes
    └── 🚨 Error Handling
    `);
});

// ============================================================================
// 📁 HOW TO SEPARATE INTO FILES LATER:
// ============================================================================

/**
 * 📁 FUTURE FILE STRUCTURE:
 * 
 * project/
 * ├── index.js (this file - will become thin entry point)
 * ├── package.json
 * ├── config/
 * │   └── database.js (move DB connection here)
 * ├── models/
 * │   ├── User.js (move User model here)
 * │   └── Post.js (move Post model here)
 * ├── middleware/
 * │   ├── auth.js (move authenticateToken, requireAdmin here)
 * │   ├── logger.js (move requestLogger here)
 * │   └── errorHandler.js (move error handlers here)
 * ├── controllers/
 * │   ├── authController.js (move authController here)
 * │   └── postController.js (move postController here)
 * ├── routes/
 * │   ├── authRoutes.js (move auth routes here)
 * │   └── postRoutes.js (move post routes here)
 * └── utils/
 *     └── generateToken.js (move JWT generation here)
 */
