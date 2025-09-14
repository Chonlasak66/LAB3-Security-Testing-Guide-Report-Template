// backend/secure-server.js - SECURE VERSION
const express = require('express');
const sql = require('mssql');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const { body, param, query, validationResult } = require('express-validator');

const app = express();
const PORT = 3001;

// Security middleware
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https:"]
        }
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true
    }
}));

app.use(cors({
    origin: ['http://localhost:8080', 'http://127.0.0.1:8080', 'http://localhost:5500' ,'http://127.0.0.1:5500'],
    credentials: true
}));

// Rate limiting
const generalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 นาที
    max: 100, // จำกัด 100 requests ต่อ IP
    message: { error: 'Too many requests, please try again later.' },
    standardHeaders: true,
    legacyHeaders: false
});

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5, // จำกัด 5 การ login ต่อ IP ใน 15 นาที
    message: { error: 'Too many login attempts, please try again later.' },
    skipSuccessfulRequests: true
});

app.use(generalLimiter);
app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ extended: true }));

// Database configuration
const dbConfig = {
    user: 'sa',
    password: '1',
    server: 'localhost\\SQLEXPRESS',
    database: 'SecurityLab',
    options: {
        encrypt: false,
        trustServerCertificate: true
    }
};

// JWT Secret (ในการใช้งานจริงควรเก็บใน environment variables)
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-key-change-this-in-production';

// Connect to database
async function connectDB() {
    try {
        await sql.connect(dbConfig);
        console.log('✅ Connected to SQL Server (Secure Version)');
    } catch (err) {
        console.error('❌ Database connection failed:', err);
        process.exit(1);
    }
}

connectDB();

// Logging middleware
function logRequest(req, res, next) {
    const timestamp = new Date().toISOString();
    const ip = req.ip || req.connection.remoteAddress;
    const userAgent = req.get('User-Agent') || 'Unknown';
    
    console.log(`[${timestamp}] ${req.method} ${req.url} - IP: ${ip} - User-Agent: ${userAgent.substring(0, 50)}`);
    next();
}

app.use(logRequest);

// Authentication middleware
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ 
            error: 'Access token required',
            code: 'NO_TOKEN'
        });
    }
    
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            console.log(`❌ JWT verification failed: ${err.message}`);
            return res.status(403).json({ 
                error: 'Invalid or expired token',
                code: 'INVALID_TOKEN'
            });
        }
        req.user = user;
        next();
    });
}

// Authorization middleware
function requireAdmin(req, res, next) {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ 
            error: 'Admin access required',
            code: 'INSUFFICIENT_PRIVILEGES'
        });
    }
    next();
}

// HTML encoding function
function htmlEncode(str) {
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;')
        .replace(/\//g, '&#x2F;');
}

// Input sanitization function
function sanitizeInput(input) {
    return input
        .replace(/[<>]/g, '') // Remove angle brackets
        .replace(/javascript:/gi, '') // Remove javascript: protocol
        .replace(/on\w+=/gi, '') // Remove event handlers
        .trim();
}

// ✅ SECURE: Health check endpoint
app.get('/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        timestamp: new Date().toISOString(),
        server: 'Secure Version'
    });
});

// ✅ SECURE: Login with comprehensive security
app.post('/login', 
    loginLimiter,
    [
        body('username')
            .trim()
            .isLength({ min: 1, max: 50 })
            .matches(/^[a-zA-Z0-9_]+$/)
            .withMessage('Username must be 1-50 characters, alphanumeric with underscores only'),
        body('password')
            .isLength({ min: 1, max: 100 })
            .withMessage('Password is required (max 100 characters)')
    ],
    async (req, res) => {
        const startTime = Date.now();
        
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                console.log(`❌ Login validation failed: ${JSON.stringify(errors.array())}`);
                return res.status(400).json({ 
                    success: false, 
                    message: 'Invalid input format',
                    errors: errors.array() 
                });
            }
            
            const { username, password } = req.body;
            
            // Log login attempt
            console.log(`🔐 Login attempt for user: ${username} from IP: ${req.ip}`);
            
            // ✅ Using prepared statement
            const request = new sql.Request();
            request.input('username', sql.NVarChar, username);
            
            const result = await request.query('SELECT * FROM Users WHERE username = @username');
            
            if (result.recordset.length === 0) {
                console.log(`❌ Login failed: User '${username}' not found`);
                // ✅ Generic error message to prevent username enumeration
                return res.status(401).json({ 
                    success: false, 
                    message: 'Invalid credentials',
                    code: 'INVALID_CREDENTIALS'
                });
            }
            
            const user = result.recordset[0];
            
            // ✅ Compare password (ในการใช้งานจริงควรใช้ bcrypt)
            // For this lab, we'll use plain text but show the secure way
            // const isValidPassword = await bcrypt.compare(password, user.password);
            const isValidPassword = password === user.password;
            
            if (!isValidPassword) {
                console.log(`❌ Login failed: Invalid password for user '${username}'`);
                return res.status(401).json({ 
                    success: false, 
                    message: 'Invalid credentials',
                    code: 'INVALID_CREDENTIALS'
                });
            }
            
            // ✅ Generate JWT token with additional claims
            const tokenPayload = {
                userId: user.id,
                username: user.username,
                role: user.role,
                loginTime: Date.now()
            };
            
            const token = jwt.sign(
                tokenPayload,
                JWT_SECRET,
                { 
                    expiresIn: '1h',
                    issuer: 'security-lab',
                    audience: 'security-lab-users'
                }
            );
            
            console.log(`✅ Login successful for user '${username}' (Role: ${user.role})`);
            
            res.json({
                success: true,
                message: 'Login successful',
                token: token,
                user: {
                    id: user.id,
                    username: user.username,
                    email: user.email,
                    role: user.role
                }
            });
            
        } catch (err) {
            console.error('❌ Login error:', err);
            // ✅ Generic error message - ไม่เปิดเผยรายละเอียด
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred during login',
                code: 'INTERNAL_ERROR'
            });
        }
        
        const duration = Date.now() - startTime;
        console.log(`⏱️  Login request completed in ${duration}ms`);
    }
);

// ✅ SECURE: Comments with comprehensive input validation
app.post('/comments',
    authenticateToken,
    [
        body('content')
            .trim()
            .isLength({ min: 1, max: 1000 })
            .withMessage('Comment must be 1-1000 characters')
            .custom(value => {
                // ✅ Additional security validation
                const forbiddenPatterns = [
                    /<script/gi,
                    /javascript:/gi,
                    /vbscript:/gi,
                    /onload/gi,
                    /onerror/gi,
                    /onclick/gi,
                    /onmouseover/gi
                ];
                
                if (forbiddenPatterns.some(pattern => pattern.test(value))) {
                    throw new Error('Content contains potentially dangerous code');
                }
                
                return true;
            })
    ],
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                console.log(`❌ Comment validation failed for user ${req.user.username}:`, errors.array());
                return res.status(400).json({ 
                    success: false, 
                    message: 'Invalid comment content',
                    errors: errors.array() 
                });
            }
            
            const { content } = req.body;
            const userId = req.user.userId;
            
            // ✅ Multiple layers of sanitization
            let sanitizedContent = sanitizeInput(content);
            sanitizedContent = htmlEncode(sanitizedContent);
            
            console.log(`💬 Adding comment from user: ${req.user.username}`);
            
            // ✅ Using prepared statement
            const request = new sql.Request();
            request.input('userId', sql.Int, userId);
            request.input('content', sql.NVarChar, sanitizedContent);
            
            const result = await request.query('INSERT INTO Comments (user_id, content) VALUES (@userId, @content)');
            
            console.log(`✅ Comment added successfully by user: ${req.user.username}`);
            
            res.json({ 
                success: true, 
                message: 'Comment added successfully',
                sanitized: sanitizedContent !== content
            });
            
        } catch (err) {
            console.error('❌ Comment error:', err);
            res.status(500).json({ 
                success: false, 
                message: 'Failed to add comment' 
            });
        }
    }
);

// ✅ SECURE: User profile with comprehensive authorization
app.get('/user/:id',
    authenticateToken,
    [param('id').isInt({ min: 1 }).withMessage('Valid user ID required')],
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ 
                    error: 'Invalid user ID format',
                    details: errors.array() 
                });
            }
            
            const requestedUserId = parseInt(req.params.id);
            const currentUserId = req.user.userId;
            const currentUserRole = req.user.role;
            
            console.log(`👤 Profile request: User ${req.user.username} requesting profile ${requestedUserId}`);
            
            // ✅ Authorization: users can only access their own profile (except admins)
            if (requestedUserId !== currentUserId && currentUserRole !== 'admin') {
                console.log(`❌ Unauthorized profile access attempt by user: ${req.user.username}`);
                return res.status(403).json({ 
                    error: 'Access denied: You can only access your own profile',
                    code: 'INSUFFICIENT_PRIVILEGES'
                });
            }
            
            // ✅ Using prepared statement
            const request = new sql.Request();
            request.input('userId', sql.Int, requestedUserId);
            
            // ✅ Select only safe columns (exclude password)
            const result = await request.query(
                'SELECT id, username, email, role, created_at FROM Users WHERE id = @userId'
            );
            
            if (result.recordset.length === 0) {
                return res.status(404).json({ 
                    error: 'User not found',
                    code: 'USER_NOT_FOUND'
                });
            }
            
            console.log(`✅ Profile data provided for user ID: ${requestedUserId}`);
            res.json(result.recordset[0]);
            
        } catch (err) {
            console.error('❌ Profile error:', err);
            res.status(500).json({ 
                error: 'Failed to retrieve profile',
                code: 'INTERNAL_ERROR'
            });
        }
    }
);

// ✅ SECURE: Search with strict input validation
app.get('/search',
    [
        query('q')
            .trim()
            .isLength({ min: 1, max: 100 })
            .matches(/^[a-zA-Z0-9\s\-_]+$/)
            .withMessage('Search term must be 1-100 characters, alphanumeric with spaces, hyphens, underscores only')
    ],
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                console.log(`❌ Search validation failed:`, errors.array());
                return res.status(400).json({ 
                    error: 'Invalid search term',
                    details: errors.array() 
                });
            }
            
            const searchTerm = req.query.q;
            console.log(`🔍 Search request: "${searchTerm}"`);
            
            // ✅ Using prepared statement with LIKE
            const request = new sql.Request();
            request.input('searchTerm', sql.NVarChar, `%${searchTerm}%`);
            
            const result = await request.query(
                'SELECT id, name, price, description FROM Products WHERE name LIKE @searchTerm'
            );
            
            console.log(`✅ Search completed: ${result.recordset.length} results found`);
            res.json(result.recordset);
            
        } catch (err) {
            console.error('❌ Search error:', err);
            res.status(500).json({ 
                error: 'Search failed',
                code: 'SEARCH_ERROR'
            });
        }
    }
);

// ✅ SECURE: Get comments (public, but with safe output)
app.get('/comments', async (req, res) => {
    try {
        console.log(`💬 Loading all comments`);
        
        // ✅ Safe query without user input
        const query = `
            SELECT c.id, c.content, c.created_at, u.username 
            FROM Comments c 
            JOIN Users u ON c.user_id = u.id 
            ORDER BY c.created_at DESC
        `;
        const result = await sql.query(query);
        
        console.log(`✅ Comments loaded: ${result.recordset.length} comments`);
        res.json(result.recordset);
        
    } catch (err) {
        console.error('❌ Comments fetch error:', err);
        res.status(500).json({ 
            error: 'Failed to load comments',
            code: 'COMMENTS_ERROR'
        });
    }
});

// ✅ SECURE: Admin-only endpoint with role verification
app.get('/admin/users', 
    authenticateToken, 
    requireAdmin,
    async (req, res) => {
        try {
            console.log(`👑 Admin request: Loading all users by ${req.user.username}`);
            
            // ✅ Safe query, admin access only
            const query = `
                SELECT id, username, email, role, created_at 
                FROM Users 
                ORDER BY created_at DESC
            `;
            const result = await sql.query(query);
            
            console.log(`✅ Admin data provided: ${result.recordset.length} users`);
            res.json(result.recordset);
            
        } catch (err) {
            console.error('❌ Admin users error:', err);
            res.status(500).json({ 
                error: 'Failed to load users',
                code: 'ADMIN_ERROR'
            });
        }
    }
);

// ✅ SECURE: Token validation endpoint
app.get('/validate-token', authenticateToken, (req, res) => {
    res.json({
        valid: true,
        user: {
            userId: req.user.userId,
            username: req.user.username,
            role: req.user.role,
            loginTime: req.user.loginTime
        },
        tokenExp: new Date(req.user.exp * 1000)
    });
});

// ✅ SECURE: Logout endpoint (token blacklisting would go here in production)
app.post('/logout', authenticateToken, (req, res) => {
    console.log(`👋 User logout: ${req.user.username}`);
    // In production, you would add the token to a blacklist
    res.json({ 
        success: true, 
        message: 'Logged out successfully' 
    });
});

// ✅ Error handling middleware
app.use((err, req, res, next) => {
    console.error('❌ Unhandled error:', err);
    
    // Don't expose error details in production
    if (process.env.NODE_ENV === 'production') {
        res.status(500).json({ 
            error: 'Internal server error',
            code: 'INTERNAL_ERROR'
        });
    } else {
        res.status(500).json({ 
            error: err.message,
            stack: err.stack
        });
    }
});

// ✅ 404 handler
app.use('*', (req, res) => {
    console.log(`❌ 404: ${req.method} ${req.originalUrl}`);
    res.status(404).json({ 
        error: 'Endpoint not found',
        code: 'NOT_FOUND',
        path: req.originalUrl
    });
});

// Start server
app.listen(PORT, () => {
    console.log(`✅ Secure server running on http://localhost:${PORT}`);
    console.log('🔒 Security features enabled:');
    console.log('   📋 Input validation with express-validator');
    console.log('   🛡️  Helmet security headers');
    console.log('   ⏱️  Rate limiting (100 req/15min, 5 login/15min)');
    console.log('   🔐 JWT authentication with expiry');
    console.log('   🚫 SQL injection prevention (prepared statements)');
    console.log('   🧹 XSS prevention (HTML encoding + sanitization)');
    console.log('   🔑 Authorization checks (IDOR prevention)');
    console.log('   📝 Request logging');
    console.log('   ❌ Generic error messages');
    console.log('');
    console.log('🎯 Ready for security testing!');
});