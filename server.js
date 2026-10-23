const express = require('express');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const { pool, initDB } = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret_donzy';

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Initialize TiDB Tables
initDB();

// Middleware: Authenticate Admin Token
function authAdmin(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Access denied. No token provided.' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.admin = decoded;
    next();
  } catch (err) {
    return res.status(403).json({ error: 'Invalid or expired session token.' });
  }
}

// Middleware: Require Super Admin Role
function requireSuperAdmin(req, res, next) {
  if (!req.admin || req.admin.role !== 'super_admin') {
    return res.status(403).json({ error: 'Permission denied. Requires Super Admin privileges.' });
  }
  next();
}

// ==========================================
// API ROUTES
// ==========================================

// 1. Admin Login (super_admin / admin)
app.post('/api/admin/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required.' });
  }

  try {
    const [rows] = await pool.query('SELECT * FROM panel_admins WHERE username = ?', [username]);
    if (rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials.' });
    }

    const admin = rows[0];
    const isMatch = await bcrypt.compare(password, admin.password_hash);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid credentials.' });
    }

    const token = jwt.sign(
      { id: admin.id, username: admin.username, role: admin.role },
      JWT_SECRET,
      { expiresIn: '8h' }
    );

    res.json({
      message: 'Login successful',
      token,
      user: { id: admin.id, username: admin.username, role: admin.role }
    });
  } catch (err) {
    res.status(500).json({ error: 'Server error: ' + err.message });
  }
});

// 2. Client Authentication Validation Endpoint
app.post('/api/validate', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ valid: false, message: 'Username and password required.' });
  }

  try {
    const [rows] = await pool.query('SELECT * FROM panel_users WHERE username = ?', [username]);
    if (rows.length === 0) {
      return res.status(401).json({ valid: false, message: 'Account not found or unauthorized.' });
    }

    const user = rows[0];
    if (user.status !== 'active') {
      return res.status(403).json({ valid: false, message: `Account is ${user.status}.` });
    }

    if (user.expires_at && new Date(user.expires_at) < new Date()) {
      return res.status(403).json({ valid: false, message: 'Account has expired.' });
    }

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      return res.status(401).json({ valid: false, message: 'Invalid credentials.' });
    }

    res.json({
      valid: true,
      message: 'Access granted',
      status: user.status,
      expires_at: user.expires_at
    });
  } catch (err) {
    res.status(500).json({ valid: false, message: 'Verification error' });
  }
});

// 3. User Management (Admins & Super Admins)
app.get('/api/users', authAdmin, async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT id, username, status, created_by, expires_at, created_at FROM panel_users ORDER BY id DESC');
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/users', authAdmin, async (req, res) => {
  const { username, password, expires_days } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required.' });
  }

  try {
    const hash = await bcrypt.hash(password, 10);
    let expiresAt = null;
    if (expires_days && parseInt(expires_days) > 0) {
      const d = new Date();
      d.setDate(d.getDate() + parseInt(expires_days));
      expiresAt = d.toISOString().slice(0, 19).replace('T', ' ');
    }

    await pool.query(
      'INSERT INTO panel_users (username, password_hash, created_by, expires_at) VALUES (?, ?, ?, ?)',
      [username, hash, req.admin.username, expiresAt]
    );

    res.json({ message: 'User created successfully.' });
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ error: 'Username already exists.' });
    }
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/users/:id', authAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM panel_users WHERE id = ?', [req.params.id]);
    res.json({ message: 'User deleted.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/users/:id/status', authAdmin, async (req, res) => {
  const { status } = req.body;
  if (!['active', 'suspended'].includes(status)) {
    return res.status(400).json({ error: 'Invalid status.' });
  }

  try {
    await pool.query('UPDATE panel_users SET status = ? WHERE id = ?', [status, req.params.id]);
    res.json({ message: `Status updated to ${status}.` });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 4. Sub-Admin Management (Super Admin only)
app.get('/api/admins', authAdmin, requireSuperAdmin, async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT id, username, role, created_at FROM panel_admins ORDER BY id ASC');
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/admins', authAdmin, requireSuperAdmin, async (req, res) => {
  const { username, password, role } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required.' });
  }

  const assignedRole = role === 'super_admin' ? 'super_admin' : 'admin';
  try {
    const hash = await bcrypt.hash(password, 10);
    await pool.query(
      'INSERT INTO panel_admins (username, password_hash, role) VALUES (?, ?, ?)',
      [username, hash, assignedRole]
    );
    res.json({ message: `Admin account (${assignedRole}) created.` });
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ error: 'Admin username already exists.' });
    }
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/admins/:id', authAdmin, requireSuperAdmin, async (req, res) => {
  try {
    if (parseInt(req.params.id) === req.admin.id) {
      return res.status(400).json({ error: 'Cannot delete your own account.' });
    }
    await pool.query('DELETE FROM panel_admins WHERE id = ?', [req.params.id]);
    res.json({ message: 'Admin deleted.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// SPA Catch-all
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`[SERVER] Donzy Admin Panel running on http://localhost:${PORT}`);
});
