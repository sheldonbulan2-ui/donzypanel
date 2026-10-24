const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: parseInt(process.env.DB_PORT || '4000', 10),
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  ssl: {
    minVersion: 'TLSv1.2',
    rejectUnauthorized: true
  },
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

async function initDB() {
  try {
    const conn = await pool.getConnection();
    console.log('[DB] Connected to TiDB Cloud successfully.');

    // 1. staff_accounts table (Super Admins, Sub-Admins, and Resellers)
    await conn.query(`
      CREATE TABLE IF NOT EXISTS staff_accounts (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        role ENUM('super_admin', 'admin', 'reseller') DEFAULT 'reseller',
        credits_balance DECIMAL(10,2) DEFAULT 0.00,
        contact_url VARCHAR(255) DEFAULT '',
        payment_methods VARCHAR(255) DEFAULT 'GCash / Maya / Crypto / Bank',
        is_visible_in_store TINYINT(1) DEFAULT 0,
        status ENUM('active', 'suspended') DEFAULT 'active',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_role (role),
        INDEX idx_store_visible (is_visible_in_store, status)
      ) ENGINE=InnoDB;
    `);

    // 2. users table (Licenses & Authentication)
    await conn.query(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        plain_password_ref VARCHAR(255) DEFAULT '',
        hwid VARCHAR(255) DEFAULT '',
        subscription_tier VARCHAR(50) DEFAULT 'Premium',
        duration_seconds INT DEFAULT 2592000,
        first_login_at DATETIME NULL,
        expires_at DATETIME NULL,
        status ENUM('Active', 'Unused', 'Banned', 'Expired') DEFAULT 'Unused',
        max_profiles INT DEFAULT 5,
        created_by_staff_id INT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_status (status),
        INDEX idx_expires (expires_at)
      ) ENGINE=InnoDB;
    `);

    // 3. announcements table
    await conn.query(`
      CREATE TABLE IF NOT EXISTS announcements (
        id INT AUTO_INCREMENT PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        content TEXT NOT NULL,
        badge_type VARCHAR(50) DEFAULT 'INFO',
        is_published TINYINT(1) DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB;
    `);

    // 4. app_settings table
    await conn.query(`
      CREATE TABLE IF NOT EXISTS app_settings (
        id INT PRIMARY KEY DEFAULT 1,
        app_version VARCHAR(50) DEFAULT 'v1.0',
        force_update TINYINT(1) DEFAULT 0,
        apk_url VARCHAR(500) DEFAULT '',
        telegram_url VARCHAR(255) DEFAULT 'https://t.me/Sheldonph',
        support_url VARCHAR(255) DEFAULT 'https://t.me/Sheldonph',
        game_status VARCHAR(50) DEFAULT 'ONLINE',
        supported_version_text VARCHAR(255) DEFAULT '8 Ball Pool v55.8.0+',
        target_pool_version VARCHAR(50) DEFAULT '55.6.0',
        ready_status_text VARCHAR(255) DEFAULT 'Mod Ready',
        global_kill_switch TINYINT(1) DEFAULT 0,
        kill_switch_message VARCHAR(500) DEFAULT 'Server is currently undergoing scheduled maintenance. Please try again shortly.',
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      ) ENGINE=InnoDB;
    `);

    // Safe migration: Add target_pool_version to app_settings if not exists
    try {
      await conn.query(`ALTER TABLE app_settings ADD COLUMN target_pool_version VARCHAR(50) DEFAULT '55.6.0'`);
    } catch (ignoreCol) {}

    try {
      await conn.query(`UPDATE app_settings SET apk_url = 'https://donzypanel.onrender.com/Donzy_v1.0.apk' WHERE id = 1 AND (apk_url IS NULL OR apk_url = '')`);
    } catch (ignoreUrl) {}

    // 5. Seed default App Settings (Row 1)
    const [settingsRows] = await conn.query('SELECT id FROM app_settings WHERE id = 1');
    if (settingsRows.length === 0) {
      await conn.query(`
        INSERT INTO app_settings (
          id, app_version, force_update, apk_url, telegram_url, support_url,
          game_status, supported_version_text, ready_status_text, global_kill_switch
        ) VALUES (
          1, 'v1.0', 0, '', 'https://t.me/Sheldonph', 'https://t.me/Sheldonph',
          'ONLINE', '8 Ball Pool v55.8.0+', 'Mod Ready', 0
        )
      `);
      console.log('[DB] Seeded default app_settings row 1.');
    }

    // 6. Seed Super Admin account (superadmin / 123456)
    const [adminRows] = await conn.query('SELECT id FROM staff_accounts WHERE username = ?', ['superadmin']);
    if (adminRows.length === 0) {
      const hash123456 = await bcrypt.hash('123456', 10);
      await conn.query(`
        INSERT INTO staff_accounts (
          username, password_hash, role, credits_balance, contact_url, is_visible_in_store, status
        ) VALUES (?, ?, 'super_admin', 99999.00, 'https://t.me/Sheldonph', 1, 'active')
      `, ['superadmin', hash123456]);
      console.log('[DB] Seeded default superadmin staff account (superadmin / 123456).');
    }

    // 7. Seed Sheldon Reseller in Store
    const [sheldonRows] = await conn.query('SELECT id FROM staff_accounts WHERE username = ?', ['Sheldonph']);
    if (sheldonRows.length === 0) {
      const sheldonHash = await bcrypt.hash('123456', 10);
      await conn.query(`
        INSERT INTO staff_accounts (
          username, password_hash, role, credits_balance, contact_url, payment_methods, is_visible_in_store, status
        ) VALUES (?, ?, 'reseller', 5000.00, 'https://t.me/Sheldonph', 'GCash / Maya / Crypto / Bank Transfer', 1, 'active')
      `, ['Sheldonph', sheldonHash]);
      console.log('[DB] Seeded Sheldonph authorized reseller.');
    }

    // 8. Seed default client user: nonoph / nonoph
    const [userRows] = await conn.query('SELECT id FROM users WHERE username = ?', ['nonoph']);
    if (userRows.length === 0) {
      const nonoHash = await bcrypt.hash('nonoph', 10);
      const expiresAt = new Date();
      expiresAt.setDate(expiresAt.getDate() + 30);
      await conn.query(`
        INSERT INTO users (
          username, password_hash, plain_password_ref, hwid, subscription_tier,
          duration_seconds, expires_at, status, max_profiles
        ) VALUES (?, ?, 'nonoph', '', 'Premium', 2592000, ?, 'Active', 5)
      `, ['nonoph', nonoHash, expiresAt]);
      console.log('[DB] Seeded client license: nonoph / nonoph.');
    }

    // 9. Migrate any legacy panel_users into users table if exists
    try {
      const [legacyUsers] = await conn.query('SELECT * FROM panel_users');
      for (const lu of legacyUsers) {
        const [exists] = await conn.query('SELECT id FROM users WHERE username = ?', [lu.username]);
        if (exists.length === 0) {
          await conn.query(`
            INSERT INTO users (username, password_hash, status, expires_at, created_at)
            VALUES (?, ?, ?, ?, ?)
          `, [
            lu.username,
            lu.password_hash,
            lu.status === 'active' ? 'Active' : (lu.status === 'expired' ? 'Expired' : 'Banned'),
            lu.expires_at,
            lu.created_at || new Date()
          ]);
        }
      }
    } catch (ignoreErr) {
      // panel_users table might not exist
    }

    conn.release();
    console.log('[DB] All tables migrated and ready.');
  } catch (err) {
    console.error('[DB] Connection / Init error:', err.message);
  }
}

module.exports = { pool, initDB };
