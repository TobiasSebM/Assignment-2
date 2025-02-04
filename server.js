const express = require('express');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = 3000;

// Secrets for signing tokens
const ACCESS_SECRET = 'access_tkn';
const REFRESH_SECRET = 'refresh_tkn';

// In-memory storage for posts and refresh tokens
let posts = [];
const refreshTokens = new Set();

// Mock user database
const users = [
    { id: 1, username: 'admin', password: 'admin123', role: 'admin' },
    { id: 2, username: 'user', password: 'user123', role: 'user' }
];

// Middleware to parse JSON bodies
app.use(express.json());

// Function to generate an access token (short-lived)
const createAccessToken = user => jwt.sign(
    { id: user.id, username: user.username, role: user.role },
    ACCESS_SECRET,
    { expiresIn: '15m' }
);

// Function to generate a refresh token (long-lived)
const createRefreshToken = user => {
    const token = jwt.sign(
        { id: user.id, username: user.username, role: user.role },
        REFRESH_SECRET,
        { expiresIn: '7d' }
    );
    refreshTokens.add(token);
    return token;
};

// Middleware to authenticate a token and check user role if required
const authenticateToken = (role = null) => (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).send('Unauthorized');

    jwt.verify(token, ACCESS_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: err.name === 'TokenExpiredError' ? 'Token expired' : 'Forbidden' });

        if (role && user.role !== role) return res.status(403).send('Insufficient privileges');
        
        req.user = user;
        next();
    });
};

// Login route to authenticate users and provide tokens
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username && u.password === password);
    if (!user) return res.status(401).send('Invalid credentials');

    res.json({
        accessToken: createAccessToken(user),
        refreshToken: createRefreshToken(user)
    });
});

// Refresh token route to issue a new access token
app.post('/refresh-token', (req, res) => {
    const { refreshToken } = req.body;
    if (!refreshToken || !refreshTokens.has(refreshToken)) return res.status(403).send('Invalid Refresh Token');

    jwt.verify(refreshToken, REFRESH_SECRET, (err, user) => {
        if (err) {
            refreshTokens.delete(refreshToken);
            return res.status(403).send('Invalid Refresh Token');
        }
        res.json({ accessToken: createAccessToken(user) });
    });
});

// Logout route to invalidate refresh token
app.post('/logout', (req, res) => {
    refreshTokens.delete(req.body.refreshToken);
    res.sendStatus(204);
});

// Get all posts (accessible to authenticated users)
app.get('/posts', authenticateToken(), (req, res) => res.json(posts));

// Create a new post (only accessible to admin users)
app.post('/posts', authenticateToken('admin'), (req, res) => {
    const { message } = req.body;
    if (!message || typeof message !== 'string') return res.status(400).send('Message is required and must be a string');
    
    posts.push({ id: posts.length + 1, message, author: req.user.username, timestamp: new Date() });
    res.status(201).json({ message: 'Post created successfully' });
});

// Start the Express server
app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));
