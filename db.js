const mysql = require('mysql2/promise');
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

    // Table 1: Admins (super_admin and admin)
    await conn.query(`
      CREATE TABLE IF NOT EXISTS panel_admins (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        role ENUM('super_admin', 'admin') DEFAULT 'admin',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB;
    `);

    // Table 2: Client Access Users / Licenses
    await conn.query(`
      CREATE TABLE IF NOT EXISTS panel_users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        status ENUM('active', 'suspended', 'expired') DEFAULT 'active',
        created_by VARCHAR(50) DEFAULT 'admin',
        expires_at DATETIME NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB;
    `);

    // Seed default super_admin if not exists
    const bcrypt = require('bcryptjs');
    const [rows] = await conn.query('SELECT id FROM panel_admins WHERE username = ?', ['superadmin']);
    if (rows.length === 0) {
      const defaultHash = await bcrypt.hash('admin123', 10);
      await conn.query(
        'INSERT INTO panel_admins (username, password_hash, role) VALUES (?, ?, ?)',
        ['superadmin', defaultHash, 'super_admin']
      );
      console.log('[DB] Seeded default super_admin account: superadmin / admin123');
    }

    conn.release();
  } catch (err) {
    console.error('[DB] Connection / Init error:', err.message);
  }
}

module.exports = { pool, initDB };
