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

// 2. Client Authentication Validation Handler
// Supports both /api/validate (JSON) and /upload/login-access.php (Form / App)
const handleClientValidate = async (req, res) => {
  const username = req.body.username || req.body['username-activation'];
  const password = req.body.password || req.body['password-activation'];
  const deviceId = req.body.deviceId || req.body['user-device-id'];
  const isPhpAppRoute = req.path.includes('login-access.php');

  if (!username || !password) {
    if (isPhpAppRoute) {
      return res.json([{ status: 'disable', message: 'Username and password required', geo_restricted: false, "check-user": "failed" }]);
    }
    return res.status(400).json({ valid: false, status: 'error', message: 'Username and password required.' });
  }

  try {
    const [rows] = await pool.query('SELECT * FROM panel_users WHERE username = ?', [username]);
    if (rows.length === 0) {
      if (isPhpAppRoute) {
        return res.json([{ status: 'disable', message: 'Account not found or unauthorized', geo_restricted: false, "check-user": "failed" }]);
      }
      return res.status(401).json({ valid: false, status: 'error', message: 'Account not found or unauthorized.' });
    }

    const user = rows[0];
    if (user.status !== 'active') {
      if (isPhpAppRoute) {
        return res.json([{ status: 'disable', message: `Account is ${user.status}`, geo_restricted: false, "check-user": "failed" }]);
      }
      return res.status(403).json({ valid: false, status: user.status, message: `Account is ${user.status}.` });
    }

    if (user.expires_at && new Date(user.expires_at) < new Date()) {
      if (isPhpAppRoute) {
        return res.json([{ status: 'disable', message: 'Account has expired', geo_restricted: false, "check-user": "failed" }]);
      }
      return res.status(403).json({ valid: false, status: 'expired', message: 'Account has expired.' });
    }

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      if (isPhpAppRoute) {
        return res.json([{ status: 'disable', message: 'Invalid credentials', geo_restricted: false, "check-user": "failed" }]);
      }
      return res.status(401).json({ valid: false, status: 'error', message: 'Invalid credentials.' });
    }

    const remainingSeconds = user.expires_at 
      ? Math.max(0, Math.floor((new Date(user.expires_at).getTime() - Date.now()) / 1000))
      : 2592000;

    const payload = {
      status: 'enable',
      valid: true,
      result: 9,
      username: user.username,
      remaining_time: remainingSeconds.toString(),
      remaining_seconds: remainingSeconds,
      geo_restricted: false,
      "check-user": "ok",
      user: {
        username: user.username,
        status: user.status,
        expires_at: user.expires_at
      }
    };

    if (isPhpAppRoute) {
      return res.json([payload]);
    }
    return res.json(payload);
  } catch (err) {
    if (isPhpAppRoute) {
      return res.json([{ status: 'disable', message: 'Verification error', geo_restricted: false, "check-user": "failed" }]);
    }
    res.status(500).json({ valid: false, status: 'error', message: 'Verification error: ' + err.message });
  }
};

app.post('/api/validate', handleClientValidate);
app.post('/upload/login-access.php', handleClientValidate);

// 3. User & License Management
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
    if (expires_days && parseInt(expires_days, 10) > 0) {
      const d = new Date();
      d.setDate(d.getDate() + parseInt(expires_days, 10));
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

app.patch('/api/users/:id/extend', authAdmin, async (req, res) => {
  const { days } = req.body;
  const daysToAdd = parseInt(days || '30', 10);
  try {
    const [rows] = await pool.query('SELECT expires_at FROM panel_users WHERE id = ?', [req.params.id]);
    if (rows.length === 0) return res.status(404).json({ error: 'User not found' });

    let currentExpiry = rows[0].expires_at ? new Date(rows[0].expires_at) : new Date();
    if (currentExpiry < new Date()) currentExpiry = new Date();
    currentExpiry.setDate(currentExpiry.getDate() + daysToAdd);

    const newExpiryStr = currentExpiry.toISOString().slice(0, 19).replace('T', ' ');
    await pool.query('UPDATE panel_users SET expires_at = ?, status = "active" WHERE id = ?', [newExpiryStr, req.params.id]);
    res.json({ message: `License extended by ${daysToAdd} days.`, expires_at: newExpiryStr });
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

// 5. Version check and alert feed for App Home Screen
app.all(['/upload/check-version.php', '/check-version.php'], (req, res) => {
  res.json({
    status: 'success',
    code: 200,
    version: 'v56.32.2',
    game_version: 'v56.32.2',
    update_required: false,
    message: 'Online'
  });
});

app.all(['/upload/alert-feed.php', '/alert-feed.php'], (req, res) => {
  res.json([]);
});

app.all(['/upload/social-info.php', '/social-info.php'], (req, res) => {
  res.json({
    telegram: 'https://t.me/donzy',
    channel: 'https://t.me/donzy'
  });
});

app.all(['/upload/reseller-list.php', '/reseller-list.php'], (req, res) => {
  res.json([]);
});

// SPA Catch-all
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`[SERVER] Donzy Admin Panel running on http://localhost:${PORT}`);
});
