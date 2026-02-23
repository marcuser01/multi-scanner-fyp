const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const app = express();

app.use(bodyParser.json());

// CWE-1321: Prototype Pollution
// An attacker can send {"__proto__": {"admin": true}} to pollute the global Object
app.post('/api/update-profile', (req, res) => {
    let user = {};
    let updates = req.body;
    for (let key in updates) {
        user[key] = updates[key]; // Dangerous assignment
    }
    res.send("Profile updated");
});

// CWE-338: Use of Cryptographically Weak PRNG
// Using Math.random() for security-sensitive tokens
app.get('/api/reset-token', (req, res) => {
    const token = Math.random().toString(36).substring(2);
    res.json({ reset_token: token });
});

// CWE-345: Insufficient Verification (JWT None Attack)
app.get('/api/admin', (req, res) => {
    const token = req.headers['authorization'];
    // Insecurely decoding without verifying signature
    const decoded = jwt.decode(token);
    if (decoded && decoded.role === 'admin') {
        res.send("Welcome, Admin");
    } else {
        res.status(403).send("Access Denied");
    }
});

// CWE-79: Cross-Site Scripting (XSS)
app.get('/hello', (req, res) => {
    const name = req.query.name;
    // Directly injecting user input into HTML
    res.send(`<h1>Hello, ${name}</h1>`);
});

app.listen(3000);
