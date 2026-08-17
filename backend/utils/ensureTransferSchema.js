const db = require("../db");

function columnExists(tableName, columnName) {
  return db.promise().query(
    `SELECT COUNT(*) AS count
     FROM INFORMATION_SCHEMA.COLUMNS
     WHERE TABLE_SCHEMA = DATABASE()
       AND TABLE_NAME = ?
       AND COLUMN_NAME = ?`,
    [tableName, columnName]
  ).then(([rows]) => Number(rows?.[0]?.count || 0) > 0);
}

async function addColumnIfMissing(tableName, columnName, definition) {
  if (await columnExists(tableName, columnName)) return;
  await db.promise().query(`ALTER TABLE \`${tableName}\` ADD COLUMN \`${columnName}\` ${definition}`);
}

async function ensureTransferSettings() {
  await db.promise().query(`
    CREATE TABLE IF NOT EXISTS settings (
      key_name VARCHAR(100) NOT NULL PRIMARY KEY,
      value VARCHAR(255) NOT NULL,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )
  `);

  const defaults = [
    ["local_transfer_otp_enabled", "1"],
    ["local_transfer_admin_confirm_enabled", "1"],
    ["wire_transfer_otp_enabled", "1"],
    ["wire_transfer_admin_confirm_enabled", "1"],
  ];

  for (const [key, value] of defaults) {
    await db.promise().query(
      `INSERT IGNORE INTO settings (key_name, value) VALUES (?, ?)`,
      [key, value]
    );
  }
}

async function ensureTransferOtpTable() {
  await db.promise().query(`
    CREATE TABLE IF NOT EXISTS transfer_otps (
      transfer_id INT NOT NULL PRIMARY KEY,
      user_id INT NOT NULL,
      otp_hash VARCHAR(128) NOT NULL,
      expires_at DATETIME NOT NULL,
      last_sent_at DATETIME DEFAULT NULL,
      attempts INT NOT NULL DEFAULT 0,
      max_attempts INT NOT NULL DEFAULT 5,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      INDEX idx_transfer_otps_user_id (user_id)
    )
  `);
}

async function ensureTransferSchema() {
  await addColumnIfMissing("transfers", "total_amount", "DECIMAL(15,2) NOT NULL DEFAULT 0.00");
  await addColumnIfMissing(
    "transfers",
    "otp_status",
    "VARCHAR(20) NOT NULL DEFAULT 'not_required'"
  );
  await addColumnIfMissing("transfers", "otp_verified_at", "DATETIME NULL");
  await addColumnIfMissing("transfers", "confirmed_at", "DATETIME NULL");

  await ensureTransferSettings();
  await ensureTransferOtpTable();
}

module.exports = { ensureTransferSchema };
