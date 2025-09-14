// backend/server.js - VULNERABLE VERSION
const express = require('express');
const sql = require('mssql');
const cors = require('cors');
const bodyParser = require('body-parser');

const app = express();
const PORT = 3000;

// Middleware
app.use(cors());
app.use(bodyParser.json());
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

// Connect to database
async function connectDB() {
    try {
        await sql.connect(dbConfig);
        console.log('Connected to SQL Server');
    } catch (err) {
        console.error('Database connection failed:', err);
    }
}

connectDB();

// 🚨 VULNERABLE: SQL Injection
app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        // ❌ String concatenation - SQL Injection vulnerability
        const query = `SELECT * FROM Users WHERE username='${username}' AND password='${password}'`;
        console.log('Query:', query); // For debugging
        
        const result = await sql.query(query);
        
        if (result.recordset.length > 0) {
            const user = result.recordset[0];
            res.json({
                success: true,
                message: 'Login successful',
                user: {
                    id: user.id,
                    username: user.username,
                    email: user.email,
                    role: user.role
                }
            });
        } else {
            res.status(401).json({ success: false, message: 'Invalid credentials' });
        }
    } catch (err) {
        // ❌ Exposing internal errors
        res.status(500).json({ error: err.message });
    }
});

// 🚨 VULNERABLE: XSS in comments
app.post('/comments', async (req, res) => {
    try {
        const { userId, content } = req.body;
        
        // ❌ No input sanitization
        const query = `INSERT INTO Comments (user_id, content) VALUES (${userId}, '${content}')`;
        await sql.query(query);
        
        res.json({ success: true, message: 'Comment added' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 🚨 VULNERABLE: IDOR - Direct object reference
app.get('/user/:id', async (req, res) => {
    try {
        const userId = req.params.id;
        
        // ❌ No authorization check
        const query = `SELECT * FROM Users WHERE id=${userId}`;
        const result = await sql.query(query);
        
        if (result.recordset.length > 0) {
            res.json(result.recordset[0]);
        } else {
            res.status(404).json({ error: 'User not found' });
        }
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 🚨 VULNERABLE: No input validation
app.get('/search', async (req, res) => {
    try {
        const { q } = req.query;
        
        // ❌ SQL Injection in search
        const query = `SELECT * FROM Products WHERE name LIKE '%${q}%'`;
        console.log('Search query:', query);
        
        const result = await sql.query(query);
        res.json(result.recordset);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Get all comments (for display)
app.get('/comments', async (req, res) => {
    try {
        const query = `
            SELECT c.*, u.username 
            FROM Comments c 
            JOIN Users u ON c.user_id = u.id 
            ORDER BY c.created_at DESC
        `;
        const result = await sql.query(query);
        res.json(result.recordset);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.listen(PORT, () => {
    console.log(`🚨 Vulnerable server running on http://localhost:${PORT}`);
    console.log('⚠️  This server has intentional security vulnerabilities for educational purposes');
});