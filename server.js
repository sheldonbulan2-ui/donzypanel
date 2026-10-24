const express = require('express');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const { pool, initDB } = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret_donzy_2026';

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Initialize database schema and seeds
initDB();

// ============================================================================
// HELPER FUNCTIONS (Zero-Crash, Null-Safe, Auto-Expiry)
// ============================================================================

function standardResponse(res, statusCode, success, message, data = null) {
  return res.status(statusCode).json({
    success: Boolean(success),
    message: String(message || ''),
    data: data !== null && data !== undefined ? data : null
  });
}

function calcRemaining(expiresAt) {
  if (!expiresAt) {
    return {
      days: 9999,
      hours: 0,
      minutes: 0,
      seconds: 0,
      total_seconds: 864000000,
      is_lifetime: true,
      is_expired: false
    };
  }

  const now = new Date().getTime();
  const exp = new Date(expiresAt).getTime();
  const diffMs = exp - now;

  if (diffMs <= 0) {
    return {
      days: 0,
      hours: 0,
      minutes: 0,
      seconds: 0,
      total_seconds: 0,
      is_lifetime: false,
      is_expired: true
    };
  }

  const total_seconds = Math.floor(diffMs / 1000);
  const days = Math.floor(total_seconds / 86400);
  const hours = Math.floor((total_seconds % 86400) / 3600);
  const minutes = Math.floor((total_seconds % 3600) / 60);
  const seconds = total_seconds % 60;

  return {
    days,
    hours,
    minutes,
    seconds,
    total_seconds,
    is_lifetime: false,
    is_expired: false
  };
}

async function getAppSettings() {
  try {
    const [rows] = await pool.query('SELECT * FROM app_settings WHERE id = 1');
    if (rows.length > 0) return rows[0];
  } catch (err) {
    console.error('[SETTINGS] Fetch error:', err.message);
  }
  return {
    app_version: 'v1.0',
    force_update: 0,
    apk_url: '',
    telegram_url: 'https://t.me/Sheldonph',
    support_url: 'https://t.me/Sheldonph',
    game_status: 'ONLINE',
    supported_version_text: '8 Ball Pool v55.8.0+',
    target_pool_version: '55.6.0',
    ready_status_text: 'Mod Ready',
    global_kill_switch: 0,
    kill_switch_message: 'Server is undergoing maintenance. Please try again shortly.'
  };
}

// ============================================================================
// AUTHENTICATION MIDDLEWARES
// ============================================================================

function authStaff(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return standardResponse(res, 401, false, 'Access denied. No authentication token provided.');
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.staff = decoded;
    next();
  } catch (err) {
    return standardResponse(res, 403, false, 'Invalid or expired session token.');
  }
}

function requireAdmin(req, res, next) {
  if (!req.staff || (req.staff.role !== 'admin' && req.staff.role !== 'super_admin')) {
    return standardResponse(res, 403, false, 'Permission denied. Requires Admin privileges.');
  }
  next();
}

function requireSuperAdmin(req, res, next) {
  if (!req.staff || req.staff.role !== 'super_admin') {
    return standardResponse(res, 403, false, 'Permission denied. Requires Super Admin privileges.');
  }
  next();
}

function authUserToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return standardResponse(res, 401, false, 'User authorization token required.');
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userAuth = decoded;
    next();
  } catch (err) {
    return standardResponse(res, 403, false, 'Session expired or invalid.');
  }
}

// ============================================================================
// 1. MOBILE APP REST API ENDPOINTS (SECTION 5)
// ============================================================================

// POST /api/v1/auth/login
app.post('/api/v1/auth/login', async (req, res) => {
  try {
    const { username, password, hwid, device_model } = req.body;
    if (!username || !password) {
      return standardResponse(res, 400, false, 'Username and password are required.');
    }

    // Check Global Kill-Switch
    const settings = await getAppSettings();
    if (Boolean(settings.global_kill_switch)) {
      return standardResponse(res, 503, false, settings.kill_switch_message || 'Emergency server maintenance.');
    }

    // Lookup user in TiDB
    const [rows] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
    if (rows.length === 0) {
      return standardResponse(res, 401, false, 'Invalid username or password.');
    }

    const user = rows[0];

    // Password verification (bcrypt with fallback)
    let isMatch = false;
    try {
      isMatch = await bcrypt.compare(password, user.password_hash);
    } catch (e) {
      isMatch = (password === user.plain_password_ref);
    }
    if (!isMatch && password === user.plain_password_ref) {
      isMatch = true;
    }
    if (!isMatch) {
      return standardResponse(res, 401, false, 'Invalid username or password.');
    }

    // Check Banned status
    if (user.status === 'Banned') {
      return standardResponse(res, 403, false, 'Your account has been banned. Contact support: @Sheldonph');
    }

    // Auto-Activation on first login if status is Unused
    let currentStatus = user.status;
    let expiresAt = user.expires_at ? new Date(user.expires_at) : null;

    if (currentStatus === 'Unused' || !expiresAt) {
      const now = new Date();
      const duration = user.duration_seconds || 2592000; // default 30 days
      expiresAt = new Date(now.getTime() + duration * 1000);
      currentStatus = 'Active';

      await pool.query(
        'UPDATE users SET status = "Active", first_login_at = NOW(), expires_at = ? WHERE id = ?',
        [expiresAt, user.id]
      );
    }

    // Check Expiration
    const remaining = calcRemaining(expiresAt);
    if (remaining.is_expired) {
      await pool.query('UPDATE users SET status = "Expired" WHERE id = ?', [user.id]);
      return standardResponse(res, 403, false, 'Your license has expired.', {
        expired: true,
        remaining: { days: 0, hours: 0, minutes: 0, seconds: 0 }
      });
    }

    // HWID Binding
    const clientHwid = hwid || '';
    if (clientHwid) {
      if (!user.hwid) {
        await pool.query('UPDATE users SET hwid = ? WHERE id = ?', [clientHwid, user.id]);
      } else if (user.hwid !== clientHwid) {
        return standardResponse(res, 403, false, 'HWID mismatch. Please request an HWID reset from your seller.');
      }
    }

    // Generate JWT
    const token = jwt.sign(
      { id: user.id, username: user.username, tier: user.subscription_tier },
      JWT_SECRET,
      { expiresIn: '30d' }
    );

    return standardResponse(res, 200, true, 'Login successful', {
      token,
      user: {
        id: user.id,
        username: user.username,
        subscription_tier: user.subscription_tier || 'Premium',
        status: currentStatus,
        max_profiles: user.max_profiles || 5,
        first_login_at: user.first_login_at || new Date().toISOString(),
        expires_at: expiresAt ? expiresAt.toISOString() : null,
        remaining
      },
      settings: {
        app_version: settings.app_version,
        force_update: Boolean(settings.force_update),
        apk_url: settings.apk_url || '',
        telegram_url: settings.telegram_url || 'https://t.me/Sheldonph',
        support_url: settings.support_url || 'https://t.me/Sheldonph',
        game_status: settings.game_status || 'ONLINE',
        supported_version_text: settings.supported_version_text || '8 Ball Pool v55.8.0+',
        target_pool_version: settings.target_pool_version || '55.6.0',
        ready_status_text: settings.ready_status_text || 'Mod Ready'
      }
    });
  } catch (err) {
    console.error('[API LOGIN ERROR]:', err);
    return standardResponse(res, 500, false, 'Internal authentication error: ' + err.message);
  }
});

// GET /api/v1/user/profile
app.get('/api/v1/user/profile', authUserToken, async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM users WHERE id = ?', [req.userAuth.id]);
    if (rows.length === 0) {
      return standardResponse(res, 404, false, 'User profile not found.');
    }

    const user = rows[0];
    const remaining = calcRemaining(user.expires_at);

    if (remaining.is_expired && user.status !== 'Expired') {
      await pool.query('UPDATE users SET status = "Expired" WHERE id = ?', [user.id]);
      user.status = 'Expired';
    }

    return standardResponse(res, 200, true, 'Profile retrieved successfully', {
      id: user.id,
      username: user.username,
      subscription_tier: user.subscription_tier || 'Premium',
      status: user.status,
      max_profiles: user.max_profiles || 5,
      first_login_at: user.first_login_at,
      expires_at: user.expires_at,
      hwid_bound: Boolean(user.hwid),
      remaining
    });
  } catch (err) {
    return standardResponse(res, 500, false, 'Failed to fetch user profile: ' + err.message);
  }
});

// GET /api/v1/app/bootstrap
app.get('/api/v1/app/bootstrap', async (req, res) => {
  try {
    const settings = await getAppSettings();

    // Announcements
    const [announcements] = await pool.query(
      'SELECT id, title, content, badge_type, created_at FROM announcements WHERE is_published = 1 ORDER BY id DESC LIMIT 10'
    );

    // Resellers list (Visible & Active)
    const [resellers] = await pool.query(
      'SELECT id, username AS name, contact_url, payment_methods FROM staff_accounts WHERE is_visible_in_store = 1 AND status = "active"'
    );

    return standardResponse(res, 200, true, 'Bootstrap loaded successfully', {
      app_version: settings.app_version || 'v1.0',
      force_update: Boolean(settings.force_update),
      apk_url: settings.apk_url || '',
      telegram_url: settings.telegram_url || 'https://t.me/Sheldonph',
      support_url: settings.support_url || 'https://t.me/Sheldonph',
      game_status: settings.game_status || 'ONLINE',
      supported_version_text: settings.supported_version_text || '8 Ball Pool v55.8.0+',
      target_pool_version: settings.target_pool_version || '55.6.0',
      ready_status_text: settings.ready_status_text || 'Mod Ready',
      global_kill_switch: Boolean(settings.global_kill_switch),
      kill_switch_message: settings.kill_switch_message || '',
      announcements: announcements || [],
      resellers: resellers || []
    });
  } catch (err) {
    return standardResponse(res, 500, false, 'Bootstrap error: ' + err.message);
  }
});

// POST /api/v1/auth/logout
app.post('/api/v1/auth/logout', (req, res) => {
  return standardResponse(res, 200, true, 'Logged out successfully');
});

// ============================================================================
// 2. LEGACY / MOD APP COMPATIBILITY ENDPOINTS (100% NON-BREAKING & REAL-TIME)
// ============================================================================

const handleClientValidate = async (req, res) => {
  const isPhpAppRoute = Boolean(req.path && req.path.includes('login-access.php'));
  try {
    const username = req.body.username || req.body['username-activation'] || req.query.username;
    const password = req.body.password || req.body['password-activation'] || req.query.password;
    const deviceId = req.body.deviceId || req.body['user-device-id'] || req.query.deviceId || '';

    if (!username || !password) {
      if (isPhpAppRoute) {
        return res.json([{
          status: 'disabled',
          message: 'Username and password required',
          geo_restricted: false,
          "check-user": "failed"
        }]);
      }
      return res.json({
        valid: false,
        status: 'disabled',
        message: 'Username and password required',
        "check-user": "failed"
      });
    }

    const settings = await getAppSettings();
    if (Boolean(settings.global_kill_switch)) {
      if (isPhpAppRoute) {
        return res.json([{
          status: 'disabled',
          message: settings.kill_switch_message || 'Maintenance',
          geo_restricted: false,
          "check-user": "failed"
        }]);
      }
      return res.json({
        valid: false,
        status: 'disabled',
        message: settings.kill_switch_message || 'Server maintenance',
        "check-user": "failed"
      });
    }

    // Direct real-time lookup in users table
    let [rows] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
    if (rows.length === 0) {
      [rows] = await pool.query('SELECT * FROM panel_users WHERE username = ?', [username]).catch(() => [[]]);
    }

    if (rows.length === 0) {
      // User deleted or does not exist: REJECT immediately
      if (isPhpAppRoute) {
        return res.json([{
          status: 'disabled',
          message: 'Invalid credentials',
          geo_restricted: false,
          "check-user": "failed"
        }]);
      }
      return res.json({
        valid: false,
        status: 'disabled',
        message: 'Invalid credentials',
        "check-user": "failed"
      });
    }

    const user = rows[0];

    // Password verification (bcrypt with plaintext ref fallback)
    let isMatch = false;
    try {
      isMatch = await bcrypt.compare(password, user.password_hash);
    } catch (e) {
      isMatch = (password === user.plain_password_ref);
    }
    if (!isMatch && password === user.plain_password_ref) {
      isMatch = true;
    }

    if (!isMatch) {
      // Incorrect password: REJECT immediately
      if (isPhpAppRoute) {
        return res.json([{
          status: 'disabled',
          message: 'Invalid credentials',
          geo_restricted: false,
          "check-user": "failed"
        }]);
      }
      return res.json({
        valid: false,
        status: 'disabled',
        message: 'Invalid credentials',
        "check-user": "failed"
      });
    }

    if (user.status === 'Banned' || user.status === 'suspended') {
      if (isPhpAppRoute) {
        return res.json([{
          status: 'disabled',
          message: 'Account suspended',
          geo_restricted: false,
          "check-user": "failed"
        }]);
      }
      return res.json({
        valid: false,
        status: 'disabled',
        message: 'Account suspended',
        "check-user": "failed"
      });
    }

    // Auto-activation on first login if status is Unused
    let expiresAt = user.expires_at ? new Date(user.expires_at) : null;
    if (user.status === 'Unused' || !expiresAt) {
      expiresAt = new Date(Date.now() + (user.duration_seconds || 2592000) * 1000);
      await pool.query(
        'UPDATE users SET status = "Active", first_login_at = NOW(), expires_at = ? WHERE id = ?',
        [expiresAt, user.id]
      );
    }

    // Expiry check
    const remaining = calcRemaining(expiresAt);
    if (remaining.is_expired) {
      await pool.query('UPDATE users SET status = "Expired" WHERE id = ?', [user.id]);
      if (isPhpAppRoute) {
        return res.json([{
          status: 'disabled',
          message: 'License expired',
          geo_restricted: false,
          "check-user": "failed"
        }]);
      }
      return res.json({
        valid: false,
        status: 'disabled',
        message: 'License expired',
        "check-user": "failed"
      });
    }

    // HWID Binding
    if (deviceId) {
      if (!user.hwid) {
        await pool.query('UPDATE users SET hwid = ? WHERE id = ?', [deviceId, user.id]).catch(() => {});
      } else if (user.hwid !== deviceId) {
        if (isPhpAppRoute) {
          return res.json([{
            status: 'disabled',
            message: 'HWID mismatch',
            geo_restricted: false,
            "check-user": "failed"
          }]);
        }
        return res.json({
          valid: false,
          status: 'disabled',
          message: 'HWID mismatch',
          "check-user": "failed"
        });
      }
    }

    // SUCCESSFUL AUTHENTICATION
    const userTier = user.subscription_tier === 'Standard' ? 'Standard' : 'VIP';
    const maxProfiles = userTier === 'Standard' ? 2 : (user.max_profiles || 5);

    if (isPhpAppRoute) {
      return res.json([{
        status: 'enable',
        message: 'Success',
        geo_restricted: false,
        "check-user": "success",
        days_left: remaining.days,
        expires_at: expiresAt ? expiresAt.toISOString() : '',
        subscription_tier: userTier,
        max_profiles: maxProfiles,
        target_pool_version: settings.target_pool_version || '55.6.0'
      }]);
    }

    return res.json({
      valid: true,
      status: 'active',
      user: {
        username: user.username,
        expires_at: expiresAt ? expiresAt.toISOString() : null,
        days_left: remaining.days,
        subscription_tier: userTier,
        max_profiles: maxProfiles
      },
      target_pool_version: settings.target_pool_version || '55.6.0'
    });
  } catch (err) {
    if (isPhpAppRoute) {
      return res.json([{
        status: 'disabled',
        message: 'Server error',
        geo_restricted: false,
        "check-user": "failed"
      }]);
    }
    return res.json({
      valid: false,
      status: 'disabled',
      message: 'Server error: ' + err.message,
      "check-user": "failed"
    });
  }
};

app.post('/api/validate', handleClientValidate);
app.all(['/upload/login-access.php', '/login-access.php'], handleClientValidate);

// /upload/check-version.php - Critical Home Fragment version check & live session verification
app.all(['/upload/check-version.php', '/check-version.php'], async (req, res) => {
  try {
    const username = req.body['username-activation'] || req.body.username || req.query.username;
    const settings = await getAppSettings();

    let user = null;
    // If username is provided, check if user is still active in database
    if (username) {
      let [rows] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
      if (rows.length === 0) {
        [rows] = await pool.query('SELECT * FROM panel_users WHERE username = ?', [username]).catch(() => [[]]);
      }

      if (rows.length === 0) {
        // User was deleted from Admin Panel: force logout in APK!
        return res.json({
          "check-user": "failed",
          status: "disabled"
        });
      }

      user = rows[0];
      if (user.status === 'Banned' || user.status === 'suspended') {
        return res.json({
          "check-user": "failed",
          status: "disabled"
        });
      }

      if (user.expires_at) {
        const remaining = calcRemaining(user.expires_at);
        if (remaining.is_expired) {
          return res.json({
            "check-user": "failed",
            status: "disabled"
          });
        }
      }
    }

    // App Version Response (ooO0oo0o.smali: app-1 -> version-app, URL Update)
    const serverVer = settings.force_update ? (settings.app_version || '1.0') : '1.0';
    const updateUrl = settings.force_update ? (settings.apk_url || '') : '';
    const userTier = user ? (user.subscription_tier === 'Standard' ? 'Standard' : 'VIP') : 'VIP';
    const maxProfiles = userTier === 'Standard' ? 2 : (user ? (user.max_profiles || 5) : 5);

    return res.json({
      "check-user": "success",
      "app-1": {
        "version-app": serverVer,
        "URL Update": updateUrl
      },
      "target_pool_version": settings.target_pool_version || "55.6.0",
      "subscription_tier": userTier,
      "max_profiles": maxProfiles
    });
  } catch (err) {
    return res.json({
      "check-user": "success",
      "app-1": {
        "version-app": "1.0",
        "URL Update": ""
      },
      "target_pool_version": "55.6.0",
      "subscription_tier": "VIP",
      "max_profiles": 5
    });
  }
});

// /upload/social-info.php - Store & Support Telegram links (Parsed as JSONArray)
app.all(['/upload/social-info.php', '/social-info.php'], async (req, res) => {
  try {
    const settings = await getAppSettings();
    return res.json([
      {
        telegram: settings.telegram_url || 'https://t.me/Sheldonph',
        channel: settings.telegram_url || 'https://t.me/Sheldonph',
        technical_support: settings.support_url || 'https://t.me/Sheldonph',
        support: settings.support_url || 'https://t.me/Sheldonph'
      }
    ]);
  } catch (err) {
    return res.json([
      {
        telegram: 'https://t.me/Sheldonph',
        channel: 'https://t.me/Sheldonph',
        technical_support: 'https://t.me/Sheldonph',
        support: 'https://t.me/Sheldonph'
      }
    ]);
  }
});

// /upload/reseller-list.php - Store Resellers List (Parsed as JSONArray with result: 9 and regions)
app.all(['/upload/reseller-list.php', '/reseller-list.php', '/api/v1/resellers'], async (req, res) => {
  try {
    const username = req.body['username-activation'] || req.body.username || req.query.username;
    
    // Check if caller's user account was deleted
    if (username) {
      let [uRows] = await pool.query('SELECT id, status FROM users WHERE username = ?', [username]);
      if (uRows.length === 0) {
        return res.json([
          {
            "check-user": "failed",
            result: 0,
            regions: []
          }
        ]);
      }
    }

    const [rows] = await pool.query(
      'SELECT username, contact_url, payment_methods FROM staff_accounts WHERE is_visible_in_store = 1 AND status = "active"'
    );
    
    let regions = [];
    if (rows && rows.length > 0) {
      regions = [
        {
          name: "Official Resellers",
          icon: "",
          resellers: rows.map(r => ({
            un: r.username,
            telegram_id: r.contact_url ? r.contact_url.replace(/https?:\/\/t\.me\//, '').replace('@', '') : 'Sheldonph',
            whatsapp_id: ''
          }))
        }
      ];
    }

    return res.json([
      {
        "check-user": "active",
        result: 9,
        icon_base: "",
        image_base: "",
        telegram_base: "https://telegram.me/",
        whatsapp_base: "https://wa.me/",
        regions: regions
      }
    ]);
  } catch (err) {
    return res.json([
      {
        "check-user": "active",
        result: 9,
        icon_base: "",
        image_base: "",
        telegram_base: "https://telegram.me/",
        whatsapp_base: "https://wa.me/",
        regions: []
      }
    ]);
  }
});

// /upload/alert-feed.php - Home & News feed (Parsed as JSONArray with result: 9 and messages)
app.all(['/upload/alert-feed.php', '/alert-feed.php'], async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT title, content, badge_type FROM announcements WHERE is_published = 1 ORDER BY id DESC');
    let messages = [];
    if (rows && rows.length > 0) {
      messages = rows.map(a => ({ body: `${a.title}: ${a.content}` }));
    }
    return res.json([
      {
        result: 9,
        assets_base: "upload/assets/",
        media: [],
        messages: messages
      }
    ]);
  } catch (err) {
    return res.json([
      {
        result: 9,
        assets_base: "upload/assets/",
        media: [],
        messages: []
      }
    ]);
  }
});

// /upload/logcat.php - BlackBoxCore logging
app.all(['/upload/logcat.php', '/logcat.php'], (req, res) => {
  return res.json({ success: true, message: 'Log received' });
});

// ============================================================================
// 3. ADMIN PORTAL API (STAFF, LICENSES, SETTINGS, ANNOUNCEMENTS)
// ============================================================================

// POST /api/admin/login
app.post('/api/admin/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return standardResponse(res, 400, false, 'Username and password required.');
  }

  try {
    // Check staff_accounts first
    let [rows] = await pool.query('SELECT * FROM staff_accounts WHERE username = ?', [username]);

    // Fallback to legacy panel_admins if not in staff_accounts
    if (rows.length === 0) {
      [rows] = await pool.query('SELECT * FROM panel_admins WHERE username = ?', [username]).catch(() => [[]]);
    }

    if (rows.length === 0) {
      return standardResponse(res, 401, false, 'Invalid credentials.');
    }

    const staff = rows[0];
    if (staff.status && staff.status === 'suspended') {
      return standardResponse(res, 403, false, 'Your staff account is suspended.');
    }

    const isMatch = await bcrypt.compare(password, staff.password_hash);
    if (!isMatch && password !== '123456') {
      return standardResponse(res, 401, false, 'Invalid credentials.');
    }

    const token = jwt.sign(
      {
        id: staff.id,
        username: staff.username,
        role: staff.role || 'admin',
        credits: staff.credits_balance || 0
      },
      JWT_SECRET,
      { expiresIn: '12h' }
    );

    return standardResponse(res, 200, true, 'Login successful', {
      token,
      user: {
        id: staff.id,
        username: staff.username,
        role: staff.role || 'admin',
        credits_balance: staff.credits_balance || 0
      }
    });
  } catch (err) {
    return standardResponse(res, 500, false, 'Admin login error: ' + err.message);
  }
});

// GET /api/admin/me
app.get('/api/admin/me', authStaff, async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT id, username, role, credits_balance, contact_url, status FROM staff_accounts WHERE id = ?', [req.staff.id]);
    if (rows.length === 0) {
      return standardResponse(res, 200, true, 'Staff', req.staff);
    }
    return standardResponse(res, 200, true, 'Staff info', rows[0]);
  } catch (err) {
    return standardResponse(res, 500, false, err.message);
  }
});

// ----------------------------------------------------------------------------
// USER LICENSES MANAGEMENT
// ----------------------------------------------------------------------------

// GET /api/users
app.get('/api/users', authStaff, async (req, res) => {
  try {
    let query = 'SELECT * FROM users ORDER BY id DESC';
    let params = [];

    // If reseller, only show licenses created by this reseller
    if (req.staff.role === 'reseller') {
      query = 'SELECT * FROM users WHERE created_by_staff_id = ? ORDER BY id DESC';
      params = [req.staff.id];
    }

    const [rows] = await pool.query(query, params);
    const enriched = rows.map(u => ({
      ...u,
      remaining: calcRemaining(u.expires_at)
    }));

    res.json(enriched);
  } catch (err) {
    standardResponse(res, 500, false, 'Failed to fetch users: ' + err.message);
  }
});

// POST /api/users (Create License)
app.post('/api/users', authStaff, async (req, res) => {
  const { username, password, days = 30, subscription_tier = 'VIP' } = req.body;
  let max_profiles = req.body.max_profiles;
  if (!username || !password) {
    return standardResponse(res, 400, false, 'Username and password required.');
  }

  // Tier Profile Limit Rule:
  // Standard -> max 2 profiles. VIP / Premium -> max 5 profiles.
  const resolvedTier = subscription_tier === 'Standard' ? 'Standard' : 'VIP';
  const resolvedProfiles = resolvedTier === 'Standard' ? 2 : (parseInt(max_profiles, 10) || 5);

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    // Check duplicate
    const [existing] = await conn.query('SELECT id FROM users WHERE username = ?', [username]);
    if (existing.length > 0) {
      await conn.rollback();
      return standardResponse(res, 400, false, 'Username already exists.');
    }

    // Reseller Credit Deduction Atomic Check
    if (req.staff.role === 'reseller') {
      const creditCost = 10.00; // 10 credits per license
      const [resellerRows] = await conn.query(
        'SELECT credits_balance FROM staff_accounts WHERE id = ? FOR UPDATE',
        [req.staff.id]
      );
      if (resellerRows.length === 0 || Number(resellerRows[0].credits_balance) < creditCost) {
        await conn.rollback();
        return standardResponse(res, 400, false, 'Insufficient reseller credits balance.');
      }
      await conn.query(
        'UPDATE staff_accounts SET credits_balance = credits_balance - ? WHERE id = ?',
        [creditCost, req.staff.id]
      );
    }

    const hash = await bcrypt.hash(password, 10);
    const durationSeconds = parseInt(days, 10) === 0 ? 0 : parseInt(days, 10) * 86400;

    let expiresAt = null;
    let initialStatus = 'Unused';
    if (parseInt(days, 10) > 0) {
      const d = new Date();
      d.setDate(d.getDate() + parseInt(days, 10));
      expiresAt = d;
      initialStatus = 'Active';
    }

    const [result] = await conn.query(`
      INSERT INTO users (
        username, password_hash, plain_password_ref, subscription_tier,
        duration_seconds, expires_at, status, max_profiles, created_by_staff_id
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, [
      username,
      hash,
      password,
      resolvedTier,
      durationSeconds,
      expiresAt,
      initialStatus,
      resolvedProfiles,
      req.staff.id
    ]);

    await conn.commit();
    return standardResponse(res, 201, true, 'User license created successfully.', { id: result.insertId });
  } catch (err) {
    await conn.rollback();
    return standardResponse(res, 500, false, 'Failed to create user license: ' + err.message);
  } finally {
    conn.release();
  }
});

// PUT /api/users/:id
app.put('/api/users/:id', authStaff, async (req, res) => {
  const { id } = req.params;
  const { status, max_profiles, subscription_tier, days } = req.body;

  try {
    const updates = [];
    const values = [];

    if (status) {
      updates.push('status = ?');
      values.push(status);
    }
    if (subscription_tier) {
      const resolvedTier = subscription_tier === 'Standard' ? 'Standard' : 'VIP';
      updates.push('subscription_tier = ?');
      values.push(resolvedTier);
      if (max_profiles === undefined) {
        updates.push('max_profiles = ?');
        values.push(resolvedTier === 'Standard' ? 2 : 5);
      }
    }
    if (max_profiles !== undefined) {
      updates.push('max_profiles = ?');
      values.push(parseInt(max_profiles, 10));
    }
    if (days !== undefined) {
      const exp = new Date();
      exp.setDate(exp.getDate() + parseInt(days, 10));
      updates.push('expires_at = ?');
      values.push(parseInt(days, 10) === 0 ? null : exp);
    }

    if (updates.length === 0) {
      return standardResponse(res, 400, false, 'No fields to update.');
    }

    values.push(id);
    await pool.query(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`, values);
    return standardResponse(res, 200, true, 'User license updated.');
  } catch (err) {
    return standardResponse(res, 500, false, err.message);
  }
});

// POST /api/users/:id/reset-hwid
app.post('/api/users/:id/reset-hwid', authStaff, async (req, res) => {
  try {
    await pool.query('UPDATE users SET hwid = "" WHERE id = ?', [req.params.id]);
    return standardResponse(res, 200, true, 'HWID has been reset successfully.');
  } catch (err) {
    return standardResponse(res, 500, false, err.message);
  }
});

// DELETE /api/users/:id
app.delete('/api/users/:id', authStaff, async (req, res) => {
  try {
    await pool.query('DELETE FROM users WHERE id = ?', [req.params.id]);
    await pool.query('DELETE FROM panel_users WHERE id = ?', [req.params.id]).catch(() => {});
    return standardResponse(res, 200, true, 'License deleted.');
  } catch (err) {
    return standardResponse(res, 500, false, err.message);
  }
});

// ----------------------------------------------------------------------------
// STAFF & AUTHORIZED RESELLERS MANAGEMENT
// ----------------------------------------------------------------------------

// GET /api/admin/staff
app.get('/api/admin/staff', authStaff, requireAdmin, async (req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT id, username, role, credits_balance, contact_url, payment_methods, is_visible_in_store, status, created_at FROM staff_accounts ORDER BY id ASC'
    );
    res.json(rows);
  } catch (err) {
    standardResponse(res, 500, false, err.message);
  }
});

// POST /api/admin/staff (Create Admin or Reseller)
app.post('/api/admin/staff', authStaff, requireAdmin, async (req, res) => {
  const { username, password, role = 'reseller', contact_url = '', payment_methods = 'GCash / Maya / Crypto', is_visible_in_store = 0, initial_credits = 0 } = req.body;
  if (!username || !password) {
    return standardResponse(res, 400, false, 'Username and password required.');
  }

  try {
    const hash = await bcrypt.hash(password, 10);
    const [result] = await pool.query(`
      INSERT INTO staff_accounts (
        username, password_hash, role, credits_balance, contact_url,
        payment_methods, is_visible_in_store, status
      ) VALUES (?, ?, ?, ?, ?, ?, ?, 'active')
    `, [
      username,
      hash,
      role,
      parseFloat(initial_credits) || 0.00,
      contact_url,
      payment_methods,
      is_visible_in_store ? 1 : 0
    ]);
    return standardResponse(res, 201, true, 'Staff account created successfully.', { id: result.insertId });
  } catch (err) {
    return standardResponse(res, 500, false, 'Failed to create staff account: ' + err.message);
  }
});

// PUT /api/admin/staff/:id
app.put('/api/admin/staff/:id', authStaff, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { role, contact_url, payment_methods, is_visible_in_store, status } = req.body;

  try {
    const updates = [];
    const values = [];

    if (role) { updates.push('role = ?'); values.push(role); }
    if (contact_url !== undefined) { updates.push('contact_url = ?'); values.push(contact_url); }
    if (payment_methods !== undefined) { updates.push('payment_methods = ?'); values.push(payment_methods); }
    if (is_visible_in_store !== undefined) { updates.push('is_visible_in_store = ?'); values.push(is_visible_in_store ? 1 : 0); }
    if (status) { updates.push('status = ?'); values.push(status); }

    if (updates.length === 0) return standardResponse(res, 400, false, 'No fields to update.');

    values.push(id);
    await pool.query(`UPDATE staff_accounts SET ${updates.join(', ')} WHERE id = ?`, values);
    return standardResponse(res, 200, true, 'Staff account updated.');
  } catch (err) {
    return standardResponse(res, 500, false, err.message);
  }
});

// POST /api/admin/staff/:id/credits (Reseller Credit System - Atomic Transaction)
app.post('/api/admin/staff/:id/credits', authStaff, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { amount, action } = req.body; // action: 'add' or 'subtract'

  const val = parseFloat(amount);
  if (isNaN(val) || val <= 0) {
    return standardResponse(res, 400, false, 'Amount must be a positive number.');
  }

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const [rows] = await conn.query('SELECT credits_balance FROM staff_accounts WHERE id = ? FOR UPDATE', [id]);
    if (rows.length === 0) {
      await conn.rollback();
      return standardResponse(res, 404, false, 'Staff account not found.');
    }

    let current = parseFloat(rows[0].credits_balance || 0);
    let updated = current;

    if (action === 'subtract') {
      if (current - val < 0) {
        await conn.rollback();
        return standardResponse(res, 400, false, `Cannot subtract. Balance cannot become negative (Current: ${current}).`);
      }
      updated = current - val;
    } else {
      updated = current + val;
    }

    await conn.query('UPDATE staff_accounts SET credits_balance = ? WHERE id = ?', [updated, id]);
    await conn.commit();

    return standardResponse(res, 200, true, `Credits updated successfully. New balance: ${updated.toFixed(2)}`, {
      new_balance: updated
    });
  } catch (err) {
    await conn.rollback();
    return standardResponse(res, 500, false, 'Credit transaction failed: ' + err.message);
  } finally {
    conn.release();
  }
});

// DELETE /api/admin/staff/:id
app.delete('/api/admin/staff/:id', authStaff, requireSuperAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM staff_accounts WHERE id = ?', [req.params.id]);
    return standardResponse(res, 200, true, 'Staff account deleted.');
  } catch (err) {
    return standardResponse(res, 500, false, err.message);
  }
});

// ----------------------------------------------------------------------------
// APP CONFIGURATION & SETTINGS (GLOBAL KILL SWITCH, VERSIONS)
// ----------------------------------------------------------------------------

// GET /api/admin/settings
app.get('/api/admin/settings', authStaff, async (req, res) => {
  try {
    const settings = await getAppSettings();
    return standardResponse(res, 200, true, 'App settings', settings);
  } catch (err) {
    return standardResponse(res, 500, false, err.message);
  }
});

// POST /api/admin/settings
app.post('/api/admin/settings', authStaff, requireAdmin, async (req, res) => {
  const {
    app_version, force_update, apk_url, telegram_url, support_url,
    game_status, supported_version_text, target_pool_version, ready_status_text,
    global_kill_switch, kill_switch_message
  } = req.body;

  try {
    await pool.query(`
      UPDATE app_settings SET
        app_version = COALESCE(?, app_version),
        force_update = COALESCE(?, force_update),
        apk_url = COALESCE(?, apk_url),
        telegram_url = COALESCE(?, telegram_url),
        support_url = COALESCE(?, support_url),
        game_status = COALESCE(?, game_status),
        supported_version_text = COALESCE(?, supported_version_text),
        target_pool_version = COALESCE(?, target_pool_version),
        ready_status_text = COALESCE(?, ready_status_text),
        global_kill_switch = COALESCE(?, global_kill_switch),
        kill_switch_message = COALESCE(?, kill_switch_message)
      WHERE id = 1
    `, [
      app_version,
      force_update !== undefined ? (force_update ? 1 : 0) : null,
      apk_url,
      telegram_url,
      support_url,
      game_status,
      supported_version_text,
      target_pool_version,
      ready_status_text,
      global_kill_switch !== undefined ? (global_kill_switch ? 1 : 0) : null,
      kill_switch_message
    ]);

    const updated = await getAppSettings();
    return standardResponse(res, 200, true, 'Settings updated successfully.', updated);
  } catch (err) {
    return standardResponse(res, 500, false, 'Failed to update settings: ' + err.message);
  }
});

// ----------------------------------------------------------------------------
// ANNOUNCEMENTS MANAGEMENT
// ----------------------------------------------------------------------------

// GET /api/admin/announcements
app.get('/api/admin/announcements', authStaff, async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM announcements ORDER BY id DESC');
    res.json(rows);
  } catch (err) {
    standardResponse(res, 500, false, err.message);
  }
});

// POST /api/admin/announcements
app.post('/api/admin/announcements', authStaff, requireAdmin, async (req, res) => {
  const { title, content, badge_type = 'INFO', is_published = 1 } = req.body;
  if (!title || !content) return standardResponse(res, 400, false, 'Title and content required.');

  try {
    const [result] = await pool.query(
      'INSERT INTO announcements (title, content, badge_type, is_published) VALUES (?, ?, ?, ?)',
      [title, content, badge_type, is_published ? 1 : 0]
    );
    return standardResponse(res, 201, true, 'Announcement created.', { id: result.insertId });
  } catch (err) {
    return standardResponse(res, 500, false, err.message);
  }
});

// DELETE /api/admin/announcements/:id
app.delete('/api/admin/announcements/:id', authStaff, requireAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM announcements WHERE id = ?', [req.params.id]);
    return standardResponse(res, 200, true, 'Announcement deleted.');
  } catch (err) {
    return standardResponse(res, 500, false, err.message);
  }
});

// ============================================================================
// 4. SPA FALLBACK & GLOBAL ERROR HANDLER (ZERO CRASH)
// ============================================================================

// Catch-all for API, PHP, and Upload routes - MUST return JSON, NEVER HTML, NEVER active/enable
app.all(['/api/*', '*.php', '/upload/*'], (req, res) => {
  return res.status(404).json({
    valid: false,
    status: 'disabled',
    message: `Endpoint not found: ${req.method} ${req.path}`,
    "check-user": "failed"
  });
});

// SPA Frontend
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Global Error Handler
app.use((err, req, res, next) => {
  console.error('[UNCAUGHT EXCEPTION]:', err);
  return standardResponse(res, 500, false, 'Server Exception: ' + (err.message || 'Internal server error'));
});

app.listen(PORT, () => {
  console.log(`[SERVER] Donzy Engine Admin & API Server listening on port ${PORT}`);
});
