// routes/userRoutes.js
const express = require('express');
const multer = require('multer');
const db = require('../db');
const path = require('path');
const moment = require('moment');
const { logActivity } = require('../utils/activityLogger');
const { authenticateToken } = require('../middleware/authMiddleware');
const { sendAtmCardRequestEmail,sendTransferOTPEmail } = require('../utils/mailer'); 
const { notifyAdmins } = require('../services/telegram');


const router = express.Router();

// Multer Config
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    const filename = `user_${Date.now()}${ext}`;
    cb(null, filename);
  }
});
const upload = multer({ storage });

// 🖼️ Multer Config for Proof Upload
const proofstorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    const filename = `deposit_${Date.now()}${ext}`;
    cb(null, filename);
  }
});
const proofupload = multer({ storage: proofstorage });

// otp start 
const crypto = require("crypto");

const OTP_TTL_MINUTES = 5;
const OTP_MAX_ATTEMPTS = 5;
// -------------------- Helper Functions -------------------- //
function generateOtp(len = 6) {
  let s = "";
  for (let i = 0; i < len; i++) s += Math.floor(Math.random() * 10);
  return s;
}

function hashOtp(otp) {
  // add a secret salt so hashes can't be guessed from DB dump
  const secret = process.env.OTP_SECRET || "otp_secret_change_me";
  return crypto.createHash("sha256").update(`${otp}:${secret}`).digest("hex");
}
// otp ends 

// 📄 Get authenticated user's full profile (without is_admin)
router.get('/profile', authenticateToken, (req, res) => {
  const userId = req.user.id;

  const query = `
    SELECT 
      u.id,
      u.username,
      u.full_name,
      u.email,
      u.account_number,
      u.current_balance,
      u.savings_balance,
      u.loan_balance,
      u.acct_status,
      u.email_verified,
      u.currency_sign,
      IFNULL(i.image_url, '') AS profile_image_url,
      a.c_account_number,
      a.s_account_number
    FROM users u
    LEFT JOIN user_images i ON u.id = i.user_id
    LEFT JOIN accounts a ON u.id = a.user_id
    WHERE u.id = ?
  `;

  db.query(query, [userId], (err, results) => {
    if (err) {
      console.error('❌ DB ERROR:', err);
      return res.status(500).json({ error: 'Database error', details: err.message });
    }

    if (results.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    return res.json({ user: results[0] });
  });
});
// 🔁 Update user profile
router.put('/profile/update', authenticateToken, (req, res) => {
  const userId = req.user.id;
  const { full_name, username } = req.body;

  const updateQuery = `
    UPDATE users 
    SET full_name = ?, username = ?
    WHERE id = ?
  `;

  db.query(updateQuery, [full_name, username, userId], async (err, result) => {
    if (err) return res.status(500).json({ error: 'Failed to update user profile' });

    await logActivity(userId, 'profile_update', `Updated profile details`);
    res.json({ message: 'Profile updated successfully' });
  });
});
// 📸 Upload user profile image
router.post('/profile/upload-image', authenticateToken, upload.single('image'), (req, res) => {
  const userId = req.user.id;

  if (!req.file) return res.status(400).json({ error: 'No image uploaded' });

  const imageUrl = `/uploads/${req.file.filename}`;

  // Insert or update profile image
  db.query('SELECT * FROM user_images WHERE user_id = ?', [userId], (err, results) => {
    if (err) return res.status(500).json({ error: 'DB error' });

    if (results.length === 0) {
      // Insert
      db.query('INSERT INTO user_images (user_id, image_url) VALUES (?, ?)', [userId, imageUrl], async (err2) => {
        if (err2) return res.status(500).json({ error: 'Failed to save image' });

        await logActivity(userId, 'image_upload', `Uploaded new profile image`);
        res.json({ message: 'Image uploaded successfully', image_url: imageUrl });
      });
    } else {
      // Update
      db.query('UPDATE user_images SET image_url = ? WHERE user_id = ?', [imageUrl, userId], async (err3) => {
        if (err3) return res.status(500).json({ error: 'Failed to update image' });

        await logActivity(userId, 'image_update', `Updated profile image`);
        res.json({ message: 'Image updated successfully', image_url: imageUrl });
      });
    }
  });
});
// Get authenticated user's account status only
router.get('/profile/status', authenticateToken, (req, res) => {
  const userId = req.user.id;

  const sql = `
    SELECT acct_status
    FROM users
    WHERE id = ?
    LIMIT 1
  `;

  db.query(sql, [userId], (err, rows) => {
    if (err) {
      console.error('❌ DB ERROR [/profile/status]:', err);
      return res.status(500).json({ ok: false, error: 'Database error', details: err.message });
    }

    if (!rows.length) {
      return res.status(404).json({ ok: false, error: 'User not found' });
    }

    return res.json({
      ok: true,
      acct_status: rows[0].acct_status
    });
  });
});


// 🚨 Set or Update User Transaction PIN (not hashed)
router.post('/set-pin', authenticateToken, (req, res) => {
  const userId = req.user.id;
  const { transaction_pin, old_pin, new_pin } = req.body;

  // If user is setting for the first time
  if (transaction_pin) {
    if (!/^\d{6}$/.test(transaction_pin)) {
      return res.status(400).json({ error: 'PIN must be exactly 6 digits' });
    }

    db.query('SELECT transaction_pin FROM users WHERE id = ?', [userId], async (err, results) => {
      if (err) return res.status(500).json({ error: 'DB error' });

      const currentPin = results[0]?.transaction_pin;
      if (currentPin) {
        return res.status(400).json({ error: 'You already have a PIN. Use old_pin and new_pin to update.' });
      }

      db.query('UPDATE users SET transaction_pin = ? WHERE id = ?', [transaction_pin, userId], async (err2) => {
        if (err2) return res.status(500).json({ error: 'Failed to set PIN' });

        await logActivity(userId, 'set_pin', 'User set their transaction PIN for the first time');
        res.json({ message: 'Transaction PIN set successfully' });
      });
    });

  } else if (old_pin && new_pin) {
    if (!/^\d{6}$/.test(old_pin) || !/^\d{6}$/.test(new_pin)) {
      return res.status(400).json({ error: 'Both old and new PINs must be 6 digits' });
    }

    db.query('SELECT transaction_pin FROM users WHERE id = ?', [userId], async (err, results) => {
      if (err) return res.status(500).json({ error: 'DB error' });

      const currentPin = results[0]?.transaction_pin;
      if (!currentPin) return res.status(400).json({ error: 'No PIN set yet. Please set it using transaction_pin.' });
      if (currentPin !== old_pin) return res.status(401).json({ error: 'Old PIN is incorrect' });

      db.query('UPDATE users SET transaction_pin = ? WHERE id = ?', [new_pin, userId], async (err2) => {
        if (err2) return res.status(500).json({ error: 'Failed to update PIN' });

        await logActivity(userId, 'update_pin', 'User updated their transaction PIN');
        res.json({ message: 'Transaction PIN updated successfully' });
      });
    });

  } else {
    return res.status(400).json({ error: 'Missing required fields: provide transaction_pin or old_pin + new_pin' });
  }
});
// ✅ GET: Check if user has a transaction PIN (never returns the PIN itself)
router.get('/pin', authenticateToken, (req, res) => {
  const userId = req.user.id;

  db.query('SELECT transaction_pin FROM users WHERE id = ?', [userId], async (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB error' });

    const pin = rows?.[0]?.transaction_pin || null;
    if (!pin) {
      return res.json({ has_pin: false, message: 'No transaction PIN set.' });
    }

    // Mask all but last 2 digits (e.g., ****12)
    const pin_mask = String(pin).replace(/\d(?=\d{2})/g, '*');

    await logActivity(userId, 'get_pin_status', 'User checked transaction PIN status');
    return res.json({ has_pin: true, pin_mask });
  });
});


// 📊 Get total available balance (current + savings)
router.get('/balance/total', authenticateToken, (req, res) => {
  const userId = req.user.id;

  const balanceQuery = `
    SELECT 
      CAST(current_balance AS DECIMAL(15,2)) AS current_balance, 
      CAST(savings_balance AS DECIMAL(15,2)) AS savings_balance
    FROM users 
    WHERE id = ?
  `;

  db.query(balanceQuery, [userId], (err, results) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (results.length === 0) return res.status(404).json({ error: 'User not found' });

    const { current_balance, savings_balance } = results[0];
    const total_balance = parseFloat(current_balance) + parseFloat(savings_balance);

    res.json({
      current_balance,
      savings_balance,
      total_balance: total_balance.toFixed(2)
    });
  });
});

// 💳 Transfer funds locally (uses user's currency sign)
router.post('/transfer/local', authenticateToken, (req, res) => {
  const userId = req.user.id;
  const {
    from_account,
    bank_name,
    account_name,
    account_number,
    reason,
    amount,
    pin
  } = req.body;

  if (!from_account || !bank_name || !account_name || !account_number || !amount || !pin) {
    return res.status(400).json({ error: 'Missing required fields including PIN' });
  }

  // Step 1: Get User PIN + Currency Sign
  db.query('SELECT transaction_pin, currency_sign FROM users WHERE id = ?', [userId], (err, results) => {
    if (err) return res.status(500).json({ error: 'Failed to fetch PIN' });
    if (!results.length || results[0].transaction_pin !== pin) {
      return res.status(403).json({ error: 'Invalid PIN' });
    }

    const currency = results[0].currency_sign || '$';

    // Step 2: Get Fee for Local Transfer
    db.query('SELECT fee_amount FROM transfer_fees WHERE type = ?', ['local'], (err2, feeResult) => {
      if (err2) return res.status(500).json({ error: 'Fee fetch failed' });

      const fee = parseFloat(feeResult?.[0]?.fee_amount || 0);
      const total = parseFloat(amount) + fee;

      const balanceColumn = from_account === 'savings' ? 'savings_balance' : 'current_balance';

      // Step 3: Check Balance
      db.query(`SELECT ${balanceColumn} FROM users WHERE id = ?`, [userId], (err3, balResult) => {
        if (err3) return res.status(500).json({ error: 'Balance fetch failed' });

        const balance = parseFloat(balResult[0][balanceColumn]);
        if (balance < total) return res.status(400).json({ error: 'Insufficient balance' });

        const newBalance = (balance - total).toFixed(2);

        // Step 4: Deduct balance
        db.query(`UPDATE users SET ${balanceColumn} = ? WHERE id = ?`, [newBalance, userId]);

        // Step 5: Record Transfer (include status = 'processing')
        db.query(
          `INSERT INTO transfers 
           (user_id, transfer_type, from_account, bank_name, account_name, account_number, reason, amount, fee, status) 
           VALUES (?, 'local', ?, ?, ?, ?, ?, ?, ?, 'processing')`,
          [userId, from_account, bank_name, account_name, account_number, reason, amount, fee],
          async (err4) => {
            if (err4) return res.status(500).json({ error: 'Transfer failed' });

            // Step 6: Log Activity
            await logActivity(
              userId,
              'local_transfer',
              `Transferred ${currency}${parseFloat(amount).toFixed(2)} to ${account_name} (${account_number}) [${bank_name}] with fee ${currency}${fee.toFixed(2)}`
            );

            res.json({
              message: `Transfer successful. Fee ${currency}${fee.toFixed(2)} applied.`
            });
          }
        );
      });
    });
  });
});
// ✅ Initiate local transfer => OTP (if enabled) OR skip OTP (if disabled)
router.post("/transfer/local/initiate/old", authenticateToken, (req, res) => {
  const userId = req.user?.id;

  const {
    from_account,
    bank_name,
    account_name,
    account_number,
    reason,
    amount,
    pin,
  } = req.body || {};

  if (!userId) return res.status(401).json({ error: "Unauthorized" });

  if (!from_account || !bank_name || !account_name || !account_number || !amount || !pin) {
    return res.status(400).json({ error: "Missing required fields including PIN" });
  }

  const fromAccount = String(from_account).trim().toLowerCase();
  if (!["savings", "current"].includes(fromAccount)) {
    return res.status(400).json({ error: "from_account must be 'savings' or 'current'" });
  }

  const amt = parseFloat(amount);
  if (!Number.isFinite(amt) || amt <= 0) {
    return res.status(400).json({ error: "Amount must be a valid number > 0" });
  }

  const balanceColumn = fromAccount === "savings" ? "savings_balance" : "current_balance";

  // 0) Check OTP toggle from settings (default ON)
  db.query(
    `SELECT value FROM settings WHERE key_name = 'local_transfer_otp_enabled' LIMIT 1`,
    (sErr, sRows) => {
      if (sErr) return res.status(500).json({ error: "Failed to fetch OTP setting", details: String(sErr) });

      const raw = sRows?.[0]?.value;
      const otpEnabled = raw === undefined || raw === null ? true : String(raw) === "1";

      // A) Fetch user
      db.query(
        `SELECT id, full_name, email, transaction_pin, currency_sign, ${balanceColumn} AS balance
         FROM users WHERE id = ? LIMIT 1`,
        [userId],
        (err, userRows) => {
          if (err) return res.status(500).json({ error: "Failed to fetch user", details: String(err) });
          if (!userRows || userRows.length === 0) return res.status(404).json({ error: "User not found" });

          const user = userRows[0];

          if (String(user.transaction_pin) !== String(pin)) {
            return res.status(403).json({ error: "Invalid PIN" });
          }

          const currency = user.currency_sign || "$";
          const userBalance = parseFloat(user.balance || 0);

          // B) Fetch local fee
          db.query(
            "SELECT fee_amount FROM transfer_fees WHERE type = ? LIMIT 1",
            ["local"],
            (err2, feeRows) => {
              if (err2) return res.status(500).json({ error: "Fee fetch failed", details: String(err2) });

              const fee = parseFloat(feeRows?.[0]?.fee_amount || 0);
              const total = amt + fee;

              if (userBalance < total) return res.status(400).json({ error: "Insufficient balance" });

              // ✅ CASE 1: OTP OFF => deduct immediately + mark verified
              if (!otpEnabled) {
                const newBalance = (userBalance - total).toFixed(2);

                db.query(
                  `UPDATE users SET ${balanceColumn} = ? WHERE id = ?`,
                  [newBalance, userId],
                  (uErr) => {
                    if (uErr) return res.status(500).json({ error: "Failed to deduct balance", details: String(uErr) });

                    db.query(
                      `INSERT INTO transfers
                        (user_id, transfer_type, from_account, bank_name, account_name, account_number, reason,
                         amount, fee, total_amount, status, otp_status, otp_verified_at)
                       VALUES
                        (?, 'local', ?, ?, ?, ?, ?, ?, ?, ?, 'processing', 'verified', NOW())`,
                      [userId, fromAccount, bank_name, account_name, account_number, reason || null, amt, fee, total],
                      async (iErr, result) => {
                        if (iErr) return res.status(500).json({ error: "Transfer initiation failed", details: String(iErr) });

                        const transferId = result.insertId;

                        try {
                          await logActivity?.(
                            userId,
                            "local_transfer_no_otp",
                            `Local transfer processed without OTP. Deducted ${currency}${total.toFixed(2)} to ${account_name} (${account_number}) [${bank_name}] fee ${currency}${fee.toFixed(2)}`
                          );
                        } catch (_) {}

                        return res.json({
                          message: "Transfer initiated (OTP disabled by admin). Now processing.",
                          transfer_id: transferId,
                          status: "processing",
                          otp_enabled: false,
                        });
                      }
                    );
                  }
                );

                return; // stop here
              }

              // ✅ CASE 2: OTP ON => your existing flow (create transfer + pending_otp)
              db.query(
                `INSERT INTO transfers
                  (user_id, transfer_type, from_account, bank_name, account_name, account_number, reason,
                   amount, fee, total_amount, status, otp_status)
                 VALUES
                  (?, 'local', ?, ?, ?, ?, ?, ?, ?, ?, 'processing', 'pending_otp')`,
                [userId, fromAccount, bank_name, account_name, account_number, reason || null, amt, fee, total],
                (err3, insertResult) => {
                  if (err3) {
                    return res.status(500).json({ error: "Transfer initiation failed", details: String(err3) });
                  }

                  const transferId = insertResult.insertId;

                  const otp = generateOtp(6);
                  const otpHash = hashOtp(String(otp).trim());

                  db.query(
                    `INSERT INTO transfer_otps (transfer_id, user_id, otp_hash, expires_at, last_sent_at, attempts, max_attempts)
                     VALUES (?, ?, ?, DATE_ADD(NOW(), INTERVAL ? MINUTE), NOW(), 0, ?)
                     ON DUPLICATE KEY UPDATE
                       otp_hash = VALUES(otp_hash),
                       expires_at = VALUES(expires_at),
                       last_sent_at = NOW(),
                       attempts = 0,
                       max_attempts = VALUES(max_attempts)`,
                    [transferId, userId, otpHash, OTP_TTL_MINUTES, OTP_MAX_ATTEMPTS],
                    async (err4) => {
                      if (err4) {
                        return res.status(500).json({ error: "OTP creation failed", details: String(err4) });
                      }

                      try {
                        await sendTransferOTPEmail(user.email, user.full_name, otp, {
                          amountText: `${currency}${total.toFixed(2)} (incl. fee ${currency}${fee.toFixed(2)})`,
                          beneficiaryText: `${account_name} (${account_number}) - ${bank_name}`,
                        });
                      } catch (mailErr) {
                        return res.status(500).json({ error: "Failed to send OTP email", details: String(mailErr) });
                      }

                      try {
                        await logActivity?.(
                          userId,
                          "local_transfer_initiated",
                          `Transfer initiated ${currency}${amt.toFixed(2)} to ${account_name} (${account_number}) [${bank_name}] fee ${currency}${fee.toFixed(2)} - awaiting OTP`
                        );
                      } catch (_) {}

                      return res.json({
                        message: "OTP sent. Confirm transfer with OTP.",
                        transfer_id: transferId,
                        otp_expires_in_minutes: OTP_TTL_MINUTES,
                        pending: true,
                        otp_status: "pending_otp",
                        otp_enabled: true,
                      });
                    }
                  );
                }
              );
            }
          );
        }
      );
    }
  );
});
// ✅ Initiate local transfer => OTP (if enabled) OR skip OTP (if disabled)
router.post("/transfer/local/initiate", authenticateToken, (req, res) => {
  const userId = req.user?.id;

  const {
    from_account,
    bank_name,
    account_name,
    account_number,
    reason,
    amount,
    pin,
  } = req.body || {};

  if (!userId) return res.status(401).json({ error: "Unauthorized" });

  if (
    !from_account ||
    !bank_name ||
    !account_name ||
    !account_number ||
    !amount ||
    !pin
  ) {
    return res.status(400).json({ error: "Missing required fields including PIN" });
  }

  const fromAccount = String(from_account).trim().toLowerCase();
  if (!["savings", "current"].includes(fromAccount)) {
    return res.status(400).json({ error: "from_account must be 'savings' or 'current'" });
  }

  const amt = parseFloat(amount);
  if (!Number.isFinite(amt) || amt <= 0) {
    return res.status(400).json({ error: "Amount must be a valid number > 0" });
  }

  const balanceColumn = fromAccount === "savings" ? "savings_balance" : "current_balance";

  // Helper: read setting (defaultValue returned if not set)
  function getSetting(keyName, defaultValue, cb) {
    db.query(
      `SELECT value FROM settings WHERE key_name = ? LIMIT 1`,
      [keyName],
      (err, rows) => {
        if (err) return cb(err);
        const raw = rows?.[0]?.value;
        if (raw === undefined || raw === null) return cb(null, defaultValue);
        cb(null, String(raw));
      }
    );
  }

  // 0) Read OTP setting + Admin confirm setting
  getSetting("local_transfer_otp_enabled", "1", (otpErr, otpRaw) => {
    if (otpErr) {
      return res.status(500).json({
        error: "Failed to fetch OTP setting",
        details: String(otpErr),
      });
    }

    const otpEnabled = String(otpRaw) === "1";

    getSetting("local_transfer_admin_confirm_enabled", "1", (acErr, acRaw) => {
      if (acErr) {
        return res.status(500).json({
          error: "Failed to fetch admin-confirm setting",
          details: String(acErr),
        });
      }

      const adminConfirmEnabled = String(acRaw) === "1";

      // A) Fetch user
      db.query(
        `SELECT id, full_name, email, transaction_pin, currency_sign, ${balanceColumn} AS balance
         FROM users WHERE id = ? LIMIT 1`,
        [userId],
        (err, userRows) => {
          if (err) return res.status(500).json({ error: "Failed to fetch user", details: String(err) });
          if (!userRows || userRows.length === 0) return res.status(404).json({ error: "User not found" });

          const user = userRows[0];

          if (String(user.transaction_pin) !== String(pin)) {
            return res.status(403).json({ error: "Invalid PIN" });
          }

          const currency = user.currency_sign || "$";
          const userBalance = parseFloat(user.balance || 0);

          // B) Fetch local fee
          db.query(
            "SELECT fee_amount FROM transfer_fees WHERE type = ? LIMIT 1",
            ["local"],
            (err2, feeRows) => {
              if (err2) return res.status(500).json({ error: "Fee fetch failed", details: String(err2) });

              const fee = parseFloat(feeRows?.[0]?.fee_amount || 0);
              const total = amt + fee;

              if (userBalance < total) return res.status(400).json({ error: "Insufficient balance" });

              // Decide final workflow statuses
              const statusIfNoOtp = adminConfirmEnabled ? "pending_admin" : "completed";

              // ✅ CASE 1: OTP OFF => deduct immediately + insert transfer
              if (!otpEnabled) {
                const newBalance = (userBalance - total).toFixed(2);

                db.query(
                  `UPDATE users SET ${balanceColumn} = ? WHERE id = ?`,
                  [newBalance, userId],
                  (uErr) => {
                    if (uErr) return res.status(500).json({ error: "Failed to deduct balance", details: String(uErr) });

                    db.query(
                      `INSERT INTO transfers
                        (user_id, transfer_type, from_account, bank_name, account_name, account_number, reason,
                         amount, fee, total_amount, status, otp_status, otp_verified_at, confirmed_at)
                       VALUES
                        (?, 'local', ?, ?, ?, ?, ?, ?, ?, ?, ?, 'verified', NOW(), ${statusIfNoOtp === "completed" ? "NOW()" : "NULL"})`,
                      [
                        userId,
                        fromAccount,
                        bank_name,
                        account_name,
                        account_number,
                        reason || null,
                        amt,
                        fee,
                        total,
                        statusIfNoOtp,
                      ],
                      async (iErr, result) => {
                        if (iErr) return res.status(500).json({ error: "Transfer initiation failed", details: String(iErr) });

                        const transferId = result.insertId;

                        try {
                          await logActivity?.(
                            userId,
                            "local_transfer_no_otp",
                            `Local transfer ${statusIfNoOtp}. Deducted ${currency}${total.toFixed(
                              2
                            )} to ${account_name} (${account_number}) [${bank_name}] fee ${currency}${fee.toFixed(2)}`
                          );
                        } catch (_) {}

                        return res.json({
                          message:
                            statusIfNoOtp === "completed"
                              ? "Transfer completed (OTP + admin confirmation disabled)."
                              : "Transfer initiated. Awaiting admin confirmation.",
                          transfer_id: transferId,
                          status: statusIfNoOtp,
                          otp_enabled: false,
                          admin_confirm_enabled: adminConfirmEnabled,
                        });
                      }
                    );
                  }
                );

                return;
              }

              // ✅ CASE 2: OTP ON => create transfer + pending_otp
              // status depends on admin-confirm toggle:
              // - if admin confirm ON => pending_admin (still needs OTP verified + admin confirm)
              // - if admin confirm OFF => processing (OTP verify should finalize to completed)
              const initialStatus = adminConfirmEnabled ? "pending_admin" : "processing";

              db.query(
                `INSERT INTO transfers
                  (user_id, transfer_type, from_account, bank_name, account_name, account_number, reason,
                   amount, fee, total_amount, status, otp_status)
                 VALUES
                  (?, 'local', ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending_otp')`,
                [userId, fromAccount, bank_name, account_name, account_number, reason || null, amt, fee, total, initialStatus],
                (err3, insertResult) => {
                  if (err3) {
                    return res.status(500).json({ error: "Transfer initiation failed", details: String(err3) });
                  }

                  const transferId = insertResult.insertId;

                  const otp = generateOtp(6);
                  const otpHash = hashOtp(String(otp).trim());

                  db.query(
                    `INSERT INTO transfer_otps (transfer_id, user_id, otp_hash, expires_at, last_sent_at, attempts, max_attempts)
                     VALUES (?, ?, ?, DATE_ADD(NOW(), INTERVAL ? MINUTE), NOW(), 0, ?)
                     ON DUPLICATE KEY UPDATE
                       otp_hash = VALUES(otp_hash),
                       expires_at = VALUES(expires_at),
                       last_sent_at = NOW(),
                       attempts = 0,
                       max_attempts = VALUES(max_attempts)`,
                    [transferId, userId, otpHash, OTP_TTL_MINUTES, OTP_MAX_ATTEMPTS],
                    async (err4) => {
                      if (err4) {
                        return res.status(500).json({ error: "OTP creation failed", details: String(err4) });
                      }

                      try {
                        await sendTransferOTPEmail(user.email, user.full_name, otp, {
                          amountText: `${currency}${total.toFixed(2)} (incl. fee ${currency}${fee.toFixed(2)})`,
                          beneficiaryText: `${account_name} (${account_number}) - ${bank_name}`,
                        });
                      } catch (mailErr) {
                        return res.status(500).json({ error: "Failed to send OTP email", details: String(mailErr) });
                      }

                      try {
                        await logActivity?.(
                          userId,
                          "local_transfer_initiated",
                          `Transfer initiated ${currency}${amt.toFixed(2)} to ${account_name} (${account_number}) [${bank_name}] fee ${currency}${fee.toFixed(2)} - awaiting OTP`
                        );
                      } catch (_) {}

                      return res.json({
                        message: "OTP sent. Confirm transfer with OTP.",
                        transfer_id: transferId,
                        otp_expires_in_minutes: OTP_TTL_MINUTES,
                        pending: true,
                        otp_status: "pending_otp",
                        otp_enabled: true,
                        admin_confirm_enabled: adminConfirmEnabled,
                        next_status_after_otp:
                          adminConfirmEnabled ? "pending_admin" : "completed",
                        current_status: initialStatus,
                      });
                    }
                  );
                }
              );
            }
          );
        }
      );
    });
  });
});
// ✅ Verify local transfer OTP
router.post("/transfer/local/verify", authenticateToken, (req, res) => {
  const userId = req.user?.id;
  const { transfer_id, otp } = req.body || {};

  if (!userId) return res.status(401).json({ error: "Unauthorized" });
  if (!transfer_id || !otp) return res.status(400).json({ error: "transfer_id and otp are required" });

  const otpHash = hashOtp(String(otp).trim());

  db.query(
    `SELECT t.id, t.user_id, t.from_account, t.amount, t.fee, t.total_amount, t.status, t.otp_status,
            u.currency_sign, u.savings_balance, u.current_balance,
            o.otp_hash, o.expires_at, o.attempts, o.max_attempts
     FROM transfers t
     JOIN users u ON u.id = t.user_id
     JOIN transfer_otps o ON o.transfer_id = t.id
     WHERE t.id = ? AND t.user_id = ? LIMIT 1`,
    [transfer_id, userId],
    (err, rows) => {
      if (err) return res.status(500).json({ error: "Verification fetch failed", details: String(err) });
      if (!rows || rows.length === 0) return res.status(404).json({ error: "Pending OTP transfer not found" });

      const r = rows[0];

      // ✅ We use otp_status as the pending gate
      if (String(r.otp_status) !== "pending_otp") {
        return res.status(400).json({ error: "Transfer is not awaiting OTP" });
      }

      if (Number(r.attempts) >= Number(r.max_attempts)) {
        return res.status(429).json({ error: "Too many OTP attempts. Start transfer again." });
      }

      const expiresAt = new Date(r.expires_at);
      if (Date.now() > expiresAt.getTime()) {
        return res.status(400).json({ error: "OTP expired. Start transfer again." });
      }

      if (String(r.otp_hash) !== String(otpHash)) {
        db.query(`UPDATE transfer_otps SET attempts = attempts + 1 WHERE transfer_id = ?`, [transfer_id]);
        return res.status(403).json({ error: "Invalid OTP" });
      }

      const currency = r.currency_sign || "$";
      const fromAcc = String(r.from_account).toLowerCase();
      const balanceColumn = fromAcc === "savings" ? "savings_balance" : "current_balance";

      const balance = parseFloat(r[balanceColumn] || 0);
      const total = parseFloat(r.total_amount || (parseFloat(r.amount) + parseFloat(r.fee)));

      if (balance < total) return res.status(400).json({ error: "Insufficient balance (balance changed)" });

      const newBalance = (balance - total).toFixed(2);

      // 1) deduct
      db.query(`UPDATE users SET ${balanceColumn} = ? WHERE id = ?`, [newBalance, userId], (e1) => {
        if (e1) return res.status(500).json({ error: "Failed to deduct balance", details: String(e1) });

        // 2) update transfer otp_status
        db.query(
          `UPDATE transfers
           SET otp_status = 'verified', otp_verified_at = NOW()
           WHERE id = ? AND user_id = ?`,
          [transfer_id, userId],
          (e2) => {
            if (e2) return res.status(500).json({ error: "Failed to update transfer status", details: String(e2) });

            // 3) delete otp record
            db.query(`DELETE FROM transfer_otps WHERE transfer_id = ?`, [transfer_id]);

            return res.json({
              message: `OTP verified. Transfer confirmed. Total ${currency}${total.toFixed(2)} deducted.`,
              transfer_id,
              status: r.status,        // stays whatever your DB expects (processing, etc.)
              otp_status: "verified",
            });
          }
        );
      });
    }
  );
});
// ✅ Get transfer OTP details by transfer ID
router.get("/transfer/otp/:transfer_id", authenticateToken, (req, res) => {
  const userId = req.user?.id;
  const transferId = req.params.transfer_id;

  if (!userId) return res.status(401).json({ error: "Unauthorized" });

  db.query(
    `SELECT
        t.id AS transfer_id,
        t.transfer_type,
        t.from_account,
        t.bank_name,
        t.account_name,
        t.account_number,
        t.amount,
        t.fee,
        t.total_amount,
        t.status,
        t.otp_status,
        t.created_at,

        o.expires_at,
        o.attempts,
        o.max_attempts
     FROM transfers t
     JOIN transfer_otps o ON o.transfer_id = t.id
     WHERE t.id = ? AND t.user_id = ?
     LIMIT 1`,
    [transferId, userId],
    (err, rows) => {
      if (err) {
        return res.status(500).json({ error: "Failed to fetch transfer OTP", details: String(err) });
      }

      if (!rows || rows.length === 0) {
        return res.status(404).json({ error: "Transfer OTP not found or already verified" });
      }

      return res.json({
        success: true,
        transfer: rows[0],
      });
    }
  );
});
// ✅ Get all pending transfers (OTP not verified)
router.get("/transfers/local/pending", authenticateToken, (req, res) => {
  const userId = req.user?.id;

  if (!userId) return res.status(401).json({ error: "Unauthorized" });

  db.query(
    `SELECT
        t.id AS transfer_id,
        t.transfer_type,
        t.from_account,
        t.bank_name,
        t.account_name,
        t.account_number,
        t.amount,
        t.fee,
        t.total_amount,
        t.status,
        t.otp_status,
        t.created_at,

        o.expires_at,
        o.attempts,
        o.max_attempts
     FROM transfers t
     JOIN transfer_otps o ON o.transfer_id = t.id
     WHERE t.user_id = ?
       AND t.otp_status = 'pending_otp'
     ORDER BY t.id DESC`,
    [userId],
    (err, rows) => {
      if (err) {
        return res.status(500).json({ error: "Failed to fetch pending transfers", details: String(err) });
      }

      return res.json({
        success: true,
        count: rows.length,
        pending_transfers: rows,
      });
    }
  );
});
// 🔁 Resend OTP for pending transfer
router.post("/transfer/local/resend-otp", authenticateToken, async (req, res) => {
  const userId = req.user?.id;
  const { transfer_id } = req.body || {};

  if (!userId) return res.status(401).json({ error: "Unauthorized" });
  if (!transfer_id) return res.status(400).json({ error: "transfer_id is required" });

  // 1️⃣ Fetch transfer + OTP
  db.query(
    `SELECT
        t.id,
        t.otp_status,
        t.amount,
        t.fee,
        t.total_amount,
        t.bank_name,
        t.account_name,
        t.account_number,
        u.email,
        u.full_name,
        u.currency_sign,
        o.last_sent_at
     FROM transfers t
     JOIN users u ON u.id = t.user_id
     JOIN transfer_otps o ON o.transfer_id = t.id
     WHERE t.id = ? AND t.user_id = ?
     LIMIT 1`,
    [transfer_id, userId],
    async (err, rows) => {
      if (err) return res.status(500).json({ error: "Failed to fetch transfer", details: String(err) });
      if (!rows || rows.length === 0) {
        return res.status(404).json({ error: "Pending transfer not found" });
      }

      const r = rows[0];

      if (String(r.otp_status) !== "pending_otp") {
        return res.status(400).json({ error: "Transfer is not awaiting OTP" });
      }

      // 2️⃣ Rate limit (60s resend cooldown)
      const COOLDOWN_SECONDS = 60;
      if (r.last_sent_at) {
        const lastSent = new Date(r.last_sent_at).getTime();
        if (Date.now() - lastSent < COOLDOWN_SECONDS * 1000) {
          return res.status(429).json({
            error: "Please wait before requesting another OTP",
            retry_after_seconds: COOLDOWN_SECONDS
          });
        }
      }

      // 3️⃣ Generate new OTP
      const otp = generateOtp(6);
      const otpHash = hashOtp(String(otp).trim());

      // 4️⃣ Update OTP record
      db.query(
        `UPDATE transfer_otps
         SET otp_hash = ?,
             expires_at = DATE_ADD(NOW(), INTERVAL ? MINUTE),
             last_sent_at = NOW(),
             attempts = 0
         WHERE transfer_id = ? AND user_id = ?`,
        [otpHash, OTP_TTL_MINUTES, transfer_id, userId],
        async (err2) => {
          if (err2) {
            return res.status(500).json({ error: "Failed to update OTP", details: String(err2) });
          }

          // 5️⃣ Send OTP email
          try {
            const currency = r.currency_sign || "$";
            await sendTransferOTPEmail(r.email, r.full_name, otp, {
              amountText: `${currency}${Number(r.total_amount).toFixed(2)}`,
              beneficiaryText: `${r.account_name} (${r.account_number}) - ${r.bank_name}`
            });
          } catch (mailErr) {
            return res.status(500).json({ error: "Failed to send OTP email", details: String(mailErr) });
          }

          return res.json({
            message: "OTP resent successfully",
            transfer_id,
            otp_expires_in_minutes: OTP_TTL_MINUTES
          });
        }
      );
    }
  );
});
// 📜 Get transfer history (only local) + entry_type
router.get('/transfer/history/local', authenticateToken, (req, res) => {
  const userId = req.user.id;

  const query = `
    SELECT 
      t.id,
      t.transfer_type,
      t.entry_type,              -- ✅ added
      t.from_account,
      t.bank_name,
      t.account_name,
      t.account_number,
      t.reason,
      t.amount,
      t.fee,
      t.status,
      t.created_at,
      u.currency_sign
    FROM transfers t
    JOIN users u ON t.user_id = u.id
    WHERE t.user_id = ? AND t.transfer_type = 'local'
    ORDER BY t.created_at DESC
    LIMIT 50
  `;

  db.query(query, [userId], (err, results) => {
    if (err) {
      console.error('❌ Local history fetch failed:', err);
      return res.status(500).json({ error: 'Failed to fetch transfer history' });
    }

    const formatted = results.map(t => ({
      id: t.id,
      type: t.transfer_type,
      entry_type: t.entry_type, // ✅ added
      from_account: t.from_account,
      bank_name: t.bank_name,
      account_name: t.account_name,
      account_number: t.account_number,
      reason: t.reason,
      amount: `${t.currency_sign}${parseFloat(t.amount).toFixed(2)}`,
      fee: `${t.currency_sign}${parseFloat(t.fee).toFixed(2)}`,
      status: t.status,
      date: moment(t.created_at).format('YYYY-MM-DD HH:mm:ss')
    }));

    res.json({ history: formatted });
  });
});


// 💸 Wire Transfer (requires PIN; codes depend on admin settings)
router.post('/transfer/wire', authenticateToken, async (req, res) => {
  const userId = req.user.id;
  const {
    from_account,
    bank_name,
    account_name,
    account_number,
    bank_country,
    routine_number,
    reason,
    imf_code,
    cot_code,
    tax_code,
    amount,
    pin
  } = req.body;

  // Basic non-code fields must always be present
  if (
    !from_account || !bank_name || !account_name || !account_number ||
    !bank_country || !routine_number || !amount || !pin || !reason
  ) {
    return res.status(400).json({ error: 'Missing required fields (excluding codes). PIN and reason are required.' });
  }

  try {
    // 0) Read admin settings for code requirements
    const [[settingsRow]] = await db.promise().query(
      'SELECT require_imf, require_cot, require_tax FROM security_settings WHERE id = 1'
    );
    const require_imf = settingsRow ? !!settingsRow.require_imf : true;
    const require_cot = settingsRow ? !!settingsRow.require_cot : true;
    const require_tax = settingsRow ? !!settingsRow.require_tax : true;

    // 1) Validate user PIN
    const [[user]] = await db.promise().query(
      'SELECT transaction_pin, currency_sign FROM users WHERE id = ?',
      [userId]
    );

    if (!user || user.transaction_pin !== pin) {
      return res.status(403).json({ error: 'Invalid PIN' });
    }

    const currency = user.currency_sign || '$';

    // 2) If any code is required, fetch configured codes
    let codes = null;
    if (require_imf || require_cot || require_tax) {
      const [[row]] = await db.promise().query(
        'SELECT imf_code, cot_code, tax_code FROM security_codes LIMIT 1'
      );
      if (!row) {
        return res.status(404).json({ error: 'Security codes not configured' });
      }
      codes = row;
    }

    // Ensure required codes are provided in the request
    if (require_imf && !imf_code) return res.status(400).json({ error: 'IMF code is required' });
    if (require_cot && !cot_code) return res.status(400).json({ error: 'COT code is required' });
    if (require_tax && !tax_code) return res.status(400).json({ error: 'TAX code is required' });

    // Validate only the codes that are enabled
    if (require_imf && codes.imf_code !== imf_code) {
      return res.status(403).json({ error: 'IMF code is expired' });
    }
    if (require_cot && codes.cot_code !== cot_code) {
      return res.status(403).json({ error: 'COT code is expired' });
    }
    if (require_tax && codes.tax_code !== tax_code) {
      return res.status(403).json({ error: 'TAX code is expired' });
    }

    // 3) Fee
    const [[feeRow]] = await db.promise().query(
      'SELECT fee_amount FROM transfer_fees WHERE type = ?',
      ['wire']
    );
    const fee = parseFloat(feeRow?.fee_amount || 0);
    const total = parseFloat(amount) + fee;

    // 4) Balance check & deduct
    const balanceCol = from_account === 'savings' ? 'savings_balance' : 'current_balance';
    const [[balRow]] = await db.promise().query(
      `SELECT ${balanceCol} FROM users WHERE id = ?`,
      [userId]
    );
    const balance = parseFloat(balRow[balanceCol]);
    if (Number.isNaN(balance)) return res.status(500).json({ error: 'Invalid account balance' });
    if (balance < total) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }

    const newBalance = (balance - total).toFixed(2);
    await db.promise().query(
      `UPDATE users SET ${balanceCol} = ? WHERE id = ?`,
      [newBalance, userId]
    );

    // 5) Insert transfer
    await db.promise().query(
      `INSERT INTO transfers 
        (user_id, transfer_type, from_account, bank_name, account_name, account_number, bank_country, routine_number, reason, imf_code, cot_code, tax_code, amount, fee, status) 
       VALUES (?, 'wire', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'processing')`,
      [
        userId,
        from_account,
        bank_name,
        account_name,
        account_number,
        bank_country,
        routine_number,
        reason,
        // Even if disabled, store whatever was provided (or NULL) for audit
        imf_code || null,
        cot_code || null,
        tax_code || null,
        amount,
        fee
      ]
    );

    // 6) Log
    const codesNote = `codes_used: IMF=${require_imf}, COT=${require_cot}, TAX=${require_tax}`;
    await logActivity(
      userId,
      'wire_transfer',
      `Wire transfer of ${currency}${parseFloat(amount).toFixed(2)} to ${account_name} (${account_number}) [${bank_name}] initiated. Fee: ${currency}${fee.toFixed(2)}; ${codesNote}`
    );

    res.json({
      ok: true,
      message: `Wire transfer successful. Fee ${currency}${fee.toFixed(2)} applied.`,
      codes_required: { imf: require_imf, cot: require_cot, tax: require_tax }
    });

  } catch (error) {
    console.error('❌ Wire transfer error:', error);
    res.status(500).json({ error: 'Wire transfer failed' });
  }
});
// ✅ 1) Initiate wire transfer => OTP (if enabled) OR skip OTP (if disabled)
router.post("/transfer/wire/initiate/old", authenticateToken, (req, res) => {
  const userId = req.user?.id;

  const {
    from_account,
    bank_name,
    account_name,
    account_number,
    bank_country,
    routine_number,
    reason,
    imf_code,
    cot_code,
    tax_code,
    amount,
    pin,
  } = req.body || {};

  if (!userId) return res.status(401).json({ error: "Unauthorized" });

  // Basic non-code fields must always be present
  if (
    !from_account || !bank_name || !account_name || !account_number ||
    !bank_country || !routine_number || !amount || !pin || !reason
  ) {
    return res.status(400).json({ error: "Missing required fields (excluding codes). PIN and reason are required." });
  }

  const fromAccount = String(from_account).trim().toLowerCase();
  if (!["savings", "current"].includes(fromAccount)) {
    return res.status(400).json({ error: "from_account must be 'savings' or 'current'" });
  }

  const amt = parseFloat(amount);
  if (!Number.isFinite(amt) || amt <= 0) {
    return res.status(400).json({ error: "Amount must be a valid number > 0" });
  }

  const balanceColumn = fromAccount === "savings" ? "savings_balance" : "current_balance";

  // 0) Check OTP toggle from settings (default ON)
  db.query(
    `SELECT value FROM settings WHERE key_name = 'wire_transfer_otp_enabled' LIMIT 1`,
    (sErr, sRows) => {
      if (sErr) return res.status(500).json({ error: "Failed to fetch OTP setting", details: String(sErr) });

      const raw = sRows?.[0]?.value;
      const otpEnabled = raw === undefined || raw === null ? true : String(raw) === "1";

      // 1) Read admin code requirements
      db.query(
        `SELECT require_imf, require_cot, require_tax FROM security_settings WHERE id = 1 LIMIT 1`,
        (setErr, setRows) => {
          if (setErr) return res.status(500).json({ error: "Failed to fetch security settings", details: String(setErr) });

          const row = setRows?.[0];
          const require_imf = row ? !!row.require_imf : true;
          const require_cot = row ? !!row.require_cot : true;
          const require_tax = row ? !!row.require_tax : true;

          // Ensure required codes are provided
          if (require_imf && !imf_code) return res.status(400).json({ error: "IMF code is required" });
          if (require_cot && !cot_code) return res.status(400).json({ error: "COT code is required" });
          if (require_tax && !tax_code) return res.status(400).json({ error: "TAX code is required" });

          // 2) Fetch user (PIN + email + balance)
          db.query(
            `SELECT id, full_name, email, transaction_pin, currency_sign, ${balanceColumn} AS balance
             FROM users WHERE id = ? LIMIT 1`,
            [userId],
            (uErr, uRows) => {
              if (uErr) return res.status(500).json({ error: "Failed to fetch user", details: String(uErr) });
              if (!uRows || uRows.length === 0) return res.status(404).json({ error: "User not found" });

              const user = uRows[0];

              if (String(user.transaction_pin) !== String(pin)) {
                return res.status(403).json({ error: "Invalid PIN" });
              }

              const currency = user.currency_sign || "$";
              const userBalance = parseFloat(user.balance || 0);

              // 3) If any code is required, fetch configured codes and validate
              const validateCodesAndContinue = (codesRowOrNull) => {
                if (require_imf && String(codesRowOrNull?.imf_code || "") !== String(imf_code || "")) {
                  return res.status(403).json({ error: "IMF code is expired" });
                }
                if (require_cot && String(codesRowOrNull?.cot_code || "") !== String(cot_code || "")) {
                  return res.status(403).json({ error: "COT code is expired" });
                }
                if (require_tax && String(codesRowOrNull?.tax_code || "") !== String(tax_code || "")) {
                  return res.status(403).json({ error: "TAX code is expired" });
                }

                // 4) Fee
                db.query(
                  "SELECT fee_amount FROM transfer_fees WHERE type = ? LIMIT 1",
                  ["wire"],
                  (fErr, fRows) => {
                    if (fErr) return res.status(500).json({ error: "Fee fetch failed", details: String(fErr) });

                    const fee = parseFloat(fRows?.[0]?.fee_amount || 0);
                    const total = amt + fee;

                    if (userBalance < total) return res.status(400).json({ error: "Insufficient balance" });

                    // ✅ CASE 1: OTP OFF => deduct immediately + create transfer with otp_status verified
                    if (!otpEnabled) {
                      const newBalance = (userBalance - total).toFixed(2);

                      db.query(
                        `UPDATE users SET ${balanceColumn} = ? WHERE id = ?`,
                        [newBalance, userId],
                        (balErr) => {
                          if (balErr) return res.status(500).json({ error: "Failed to deduct balance", details: String(balErr) });

                          db.query(
                            `INSERT INTO transfers
                              (user_id, transfer_type, from_account, bank_name, account_name, account_number,
                               bank_country, routine_number, reason, imf_code, cot_code, tax_code,
                               amount, fee, total_amount, status, otp_status, otp_verified_at)
                             VALUES
                              (?, 'wire', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'processing', 'verified', NOW())`,
                            [
                              userId,
                              fromAccount,
                              bank_name,
                              account_name,
                              account_number,
                              bank_country,
                              routine_number,
                              reason,
                              imf_code || null,
                              cot_code || null,
                              tax_code || null,
                              amt,
                              fee,
                              total,
                            ],
                            async (iErr, result) => {
                              if (iErr) return res.status(500).json({ error: "Wire transfer initiation failed", details: String(iErr) });

                              const transferId = result.insertId;

                              try {
                                await logActivity?.(
                                  userId,
                                  "wire_transfer_no_otp",
                                  `Wire transfer processed without OTP. Deducted ${currency}${total.toFixed(2)} to ${account_name} (${account_number}) [${bank_name}] fee ${currency}${fee.toFixed(2)}`
                                );
                              } catch (_) {}

                              return res.json({
                                ok: true,
                                message: "Wire transfer initiated (OTP disabled by admin). Now processing.",
                                transfer_id: transferId,
                                status: "processing",
                                otp_enabled: false,
                                codes_required: { imf: require_imf, cot: require_cot, tax: require_tax },
                              });
                            }
                          );
                        }
                      );

                      return;
                    }

                    // ✅ CASE 2: OTP ON => create transfer + pending_otp (NO deduction yet)
                    db.query(
                      `INSERT INTO transfers
                        (user_id, transfer_type, from_account, bank_name, account_name, account_number,
                         bank_country, routine_number, reason, imf_code, cot_code, tax_code,
                         amount, fee, total_amount, status, otp_status)
                       VALUES
                        (?, 'wire', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'processing', 'pending_otp')`,
                      [
                        userId,
                        fromAccount,
                        bank_name,
                        account_name,
                        account_number,
                        bank_country,
                        routine_number,
                        reason,
                        imf_code || null,
                        cot_code || null,
                        tax_code || null,
                        amt,
                        fee,
                        total,
                      ],
                      (tErr, insertResult) => {
                        if (tErr) return res.status(500).json({ error: "Wire transfer initiation failed", details: String(tErr) });

                        const transferId = insertResult.insertId;

                        const otp = generateOtp(6);
                        const otpHash = hashOtp(String(otp).trim());

                        db.query(
                          `INSERT INTO transfer_otps (transfer_id, user_id, otp_hash, expires_at, last_sent_at, attempts, max_attempts)
                           VALUES (?, ?, ?, DATE_ADD(NOW(), INTERVAL ? MINUTE), NOW(), 0, ?)
                           ON DUPLICATE KEY UPDATE
                             otp_hash = VALUES(otp_hash),
                             expires_at = VALUES(expires_at),
                             last_sent_at = NOW(),
                             attempts = 0,
                             max_attempts = VALUES(max_attempts)`,
                          [transferId, userId, otpHash, OTP_TTL_MINUTES, OTP_MAX_ATTEMPTS],
                          async (oErr) => {
                            if (oErr) return res.status(500).json({ error: "OTP creation failed", details: String(oErr) });

                            try {
                              await sendTransferOTPEmail(user.email, user.full_name, otp, {
                                amountText: `${currency}${total.toFixed(2)} (incl. fee ${currency}${fee.toFixed(2)})`,
                                beneficiaryText: `${account_name} (${account_number}) - ${bank_name}`,
                              });
                            } catch (mailErr) {
                              return res.status(500).json({ error: "Failed to send OTP email", details: String(mailErr) });
                            }

                            try {
                              await logActivity?.(
                                userId,
                                "wire_transfer_initiated",
                                `Wire transfer initiated ${currency}${amt.toFixed(2)} to ${account_name} (${account_number}) [${bank_name}] fee ${currency}${fee.toFixed(2)} - awaiting OTP`
                              );
                            } catch (_) {}

                            return res.json({
                              ok: true,
                              message: "OTP sent. Confirm wire transfer with OTP.",
                              transfer_id: transferId,
                              otp_expires_in_minutes: OTP_TTL_MINUTES,
                              pending: true,
                              otp_status: "pending_otp",
                              otp_enabled: true,
                              codes_required: { imf: require_imf, cot: require_cot, tax: require_tax },
                            });
                          }
                        );
                      }
                    );
                  }
                );
              };

              if (require_imf || require_cot || require_tax) {
                db.query(
                  "SELECT imf_code, cot_code, tax_code FROM security_codes LIMIT 1",
                  (cErr, cRows) => {
                    if (cErr) return res.status(500).json({ error: "Failed to fetch security codes", details: String(cErr) });
                    const codes = cRows?.[0];
                    if (!codes) return res.status(404).json({ error: "Security codes not configured" });
                    return validateCodesAndContinue(codes);
                  }
                );
              } else {
                return validateCodesAndContinue(null);
              }
            }
          );
        }
      );
    }
  );
});
// ✅ 1) Initiate wire transfer => OTP (if enabled) OR skip OTP (if disabled)
router.post("/transfer/wire/initiate", authenticateToken, (req, res) => {
  const userId = req.user?.id;

  const {
    from_account,
    bank_name,
    account_name,
    account_number,
    bank_country,
    routine_number,
    reason,
    imf_code,
    cot_code,
    tax_code,
    amount,
    pin,
  } = req.body || {};

  if (!userId) return res.status(401).json({ error: "Unauthorized" });

  // Basic non-code fields must always be present
  if (
    !from_account ||
    !bank_name ||
    !account_name ||
    !account_number ||
    !bank_country ||
    !routine_number ||
    !amount ||
    !pin ||
    !reason
  ) {
    return res.status(400).json({
      error: "Missing required fields (excluding codes). PIN and reason are required.",
    });
  }

  const fromAccount = String(from_account).trim().toLowerCase();
  if (!["savings", "current"].includes(fromAccount)) {
    return res.status(400).json({ error: "from_account must be 'savings' or 'current'" });
  }

  const amt = parseFloat(amount);
  if (!Number.isFinite(amt) || amt <= 0) {
    return res.status(400).json({ error: "Amount must be a valid number > 0" });
  }

  const balanceColumn = fromAccount === "savings" ? "savings_balance" : "current_balance";

  // Helper: read setting (defaultValue returned if not set)
  function getSetting(keyName, defaultValue, cb) {
    db.query(
      `SELECT value FROM settings WHERE key_name = ? LIMIT 1`,
      [keyName],
      (err, rows) => {
        if (err) return cb(err);
        const raw = rows?.[0]?.value;
        if (raw === undefined || raw === null) return cb(null, defaultValue);
        cb(null, String(raw));
      }
    );
  }

  // 0) OTP toggle + Admin confirm toggle
  getSetting("wire_transfer_otp_enabled", "1", (sErr, otpRaw) => {
    if (sErr)
      return res.status(500).json({ error: "Failed to fetch OTP setting", details: String(sErr) });

    const otpEnabled = String(otpRaw) === "1";

    getSetting("wire_transfer_admin_confirm_enabled", "1", (aErr, acRaw) => {
      if (aErr)
        return res.status(500).json({
          error: "Failed to fetch admin-confirm setting",
          details: String(aErr),
        });

      const adminConfirmEnabled = String(acRaw) === "1";

      // 1) Read admin code requirements
      db.query(
        `SELECT require_imf, require_cot, require_tax FROM security_settings WHERE id = 1 LIMIT 1`,
        (setErr, setRows) => {
          if (setErr)
            return res.status(500).json({
              error: "Failed to fetch security settings",
              details: String(setErr),
            });

          const row = setRows?.[0];
          const require_imf = row ? !!row.require_imf : true;
          const require_cot = row ? !!row.require_cot : true;
          const require_tax = row ? !!row.require_tax : true;

          // Ensure required codes are provided
          if (require_imf && !imf_code) return res.status(400).json({ error: "IMF code is required" });
          if (require_cot && !cot_code) return res.status(400).json({ error: "COT code is required" });
          if (require_tax && !tax_code) return res.status(400).json({ error: "TAX code is required" });

          // 2) Fetch user (PIN + email + balance)
          db.query(
            `SELECT id, full_name, email, transaction_pin, currency_sign, ${balanceColumn} AS balance
             FROM users WHERE id = ? LIMIT 1`,
            [userId],
            (uErr, uRows) => {
              if (uErr) return res.status(500).json({ error: "Failed to fetch user", details: String(uErr) });
              if (!uRows || uRows.length === 0) return res.status(404).json({ error: "User not found" });

              const user = uRows[0];

              if (String(user.transaction_pin) !== String(pin)) {
                return res.status(403).json({ error: "Invalid PIN" });
              }

              const currency = user.currency_sign || "$";
              const userBalance = parseFloat(user.balance || 0);

              // 3) Validate codes then continue
              const validateCodesAndContinue = (codesRowOrNull) => {
                if (require_imf && String(codesRowOrNull?.imf_code || "") !== String(imf_code || "")) {
                  return res.status(403).json({ error: "IMF code is expired" });
                }
                if (require_cot && String(codesRowOrNull?.cot_code || "") !== String(cot_code || "")) {
                  return res.status(403).json({ error: "COT code is expired" });
                }
                if (require_tax && String(codesRowOrNull?.tax_code || "") !== String(tax_code || "")) {
                  return res.status(403).json({ error: "TAX code is expired" });
                }

                // 4) Fee
                db.query(
                  "SELECT fee_amount FROM transfer_fees WHERE type = ? LIMIT 1",
                  ["wire"],
                  (fErr, fRows) => {
                    if (fErr) return res.status(500).json({ error: "Fee fetch failed", details: String(fErr) });

                    const fee = parseFloat(fRows?.[0]?.fee_amount || 0);
                    const total = amt + fee;

                    if (userBalance < total) return res.status(400).json({ error: "Insufficient balance" });

                    // ✅ Decide statuses based on adminConfirmEnabled
                    const statusIfNoOtp = adminConfirmEnabled ? "pending_admin" : "completed";
                    const statusIfOtpOn = adminConfirmEnabled ? "pending_admin" : "processing";

                    // ✅ CASE 1: OTP OFF => deduct immediately + create transfer
                    if (!otpEnabled) {
                      const newBalance = (userBalance - total).toFixed(2);

                      db.query(
                        `UPDATE users SET ${balanceColumn} = ? WHERE id = ?`,
                        [newBalance, userId],
                        (balErr) => {
                          if (balErr)
                            return res.status(500).json({
                              error: "Failed to deduct balance",
                              details: String(balErr),
                            });

                          db.query(
                            `INSERT INTO transfers
                              (user_id, transfer_type, from_account, bank_name, account_name, account_number,
                               bank_country, routine_number, reason, imf_code, cot_code, tax_code,
                               amount, fee, total_amount, status, otp_status, otp_verified_at, confirmed_at)
                             VALUES
                              (?, 'wire', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'verified', NOW(), ${
                                statusIfNoOtp === "completed" ? "NOW()" : "NULL"
                              })`,
                            [
                              userId,
                              fromAccount,
                              bank_name,
                              account_name,
                              account_number,
                              bank_country,
                              routine_number,
                              reason,
                              imf_code || null,
                              cot_code || null,
                              tax_code || null,
                              amt,
                              fee,
                              total,
                              statusIfNoOtp,
                            ],
                            async (iErr, result) => {
                              if (iErr)
                                return res.status(500).json({
                                  error: "Wire transfer initiation failed",
                                  details: String(iErr),
                                });

                              const transferId = result.insertId;

                              try {
                                await logActivity?.(
                                  userId,
                                  "wire_transfer_no_otp",
                                  `Wire transfer ${statusIfNoOtp}. Deducted ${currency}${total.toFixed(
                                    2
                                  )} to ${account_name} (${account_number}) [${bank_name}] fee ${currency}${fee.toFixed(
                                    2
                                  )}`
                                );
                              } catch (_) {}

                              return res.json({
                                ok: true,
                                message:
                                  statusIfNoOtp === "completed"
                                    ? "Wire transfer completed (OTP + admin confirmation disabled)."
                                    : "Wire transfer initiated. Awaiting admin confirmation.",
                                transfer_id: transferId,
                                status: statusIfNoOtp,
                                otp_enabled: false,
                                admin_confirm_enabled: adminConfirmEnabled,
                                codes_required: { imf: require_imf, cot: require_cot, tax: require_tax },
                              });
                            }
                          );
                        }
                      );

                      return;
                    }

                    // ✅ CASE 2: OTP ON => create transfer + pending_otp (NO deduction yet)
                    db.query(
                      `INSERT INTO transfers
                        (user_id, transfer_type, from_account, bank_name, account_name, account_number,
                         bank_country, routine_number, reason, imf_code, cot_code, tax_code,
                         amount, fee, total_amount, status, otp_status)
                       VALUES
                        (?, 'wire', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending_otp')`,
                      [
                        userId,
                        fromAccount,
                        bank_name,
                        account_name,
                        account_number,
                        bank_country,
                        routine_number,
                        reason,
                        imf_code || null,
                        cot_code || null,
                        tax_code || null,
                        amt,
                        fee,
                        total,
                        statusIfOtpOn,
                      ],
                      (tErr, insertResult) => {
                        if (tErr)
                          return res.status(500).json({
                            error: "Wire transfer initiation failed",
                            details: String(tErr),
                          });

                        const transferId = insertResult.insertId;

                        const otp = generateOtp(6);
                        const otpHash = hashOtp(String(otp).trim());

                        db.query(
                          `INSERT INTO transfer_otps (transfer_id, user_id, otp_hash, expires_at, last_sent_at, attempts, max_attempts)
                           VALUES (?, ?, ?, DATE_ADD(NOW(), INTERVAL ? MINUTE), NOW(), 0, ?)
                           ON DUPLICATE KEY UPDATE
                             otp_hash = VALUES(otp_hash),
                             expires_at = VALUES(expires_at),
                             last_sent_at = NOW(),
                             attempts = 0,
                             max_attempts = VALUES(max_attempts)`,
                          [transferId, userId, otpHash, OTP_TTL_MINUTES, OTP_MAX_ATTEMPTS],
                          async (oErr) => {
                            if (oErr)
                              return res.status(500).json({
                                error: "OTP creation failed",
                                details: String(oErr),
                              });

                            try {
                              await sendTransferOTPEmail(user.email, user.full_name, otp, {
                                amountText: `${currency}${total.toFixed(2)} (incl. fee ${currency}${fee.toFixed(2)})`,
                                beneficiaryText: `${account_name} (${account_number}) - ${bank_name}`,
                              });
                            } catch (mailErr) {
                              return res.status(500).json({
                                error: "Failed to send OTP email",
                                details: String(mailErr),
                              });
                            }

                            try {
                              await logActivity?.(
                                userId,
                                "wire_transfer_initiated",
                                `Wire transfer initiated ${currency}${amt.toFixed(2)} to ${account_name} (${account_number}) [${bank_name}] fee ${currency}${fee.toFixed(2)} - awaiting OTP`
                              );
                            } catch (_) {}

                            return res.json({
                              ok: true,
                              message: "OTP sent. Confirm wire transfer with OTP.",
                              transfer_id: transferId,
                              otp_expires_in_minutes: OTP_TTL_MINUTES,
                              pending: true,
                              otp_status: "pending_otp",
                              otp_enabled: true,
                              admin_confirm_enabled: adminConfirmEnabled,
                              current_status: statusIfOtpOn,
                              next_status_after_otp: adminConfirmEnabled ? "pending_admin" : "completed",
                              codes_required: { imf: require_imf, cot: require_cot, tax: require_tax },
                            });
                          }
                        );
                      }
                    );
                  }
                );
              };

              if (require_imf || require_cot || require_tax) {
                db.query(
                  "SELECT imf_code, cot_code, tax_code FROM security_codes LIMIT 1",
                  (cErr, cRows) => {
                    if (cErr) return res.status(500).json({ error: "Failed to fetch security codes", details: String(cErr) });
                    const codes = cRows?.[0];
                    if (!codes) return res.status(404).json({ error: "Security codes not configured" });
                    return validateCodesAndContinue(codes);
                  }
                );
              } else {
                return validateCodesAndContinue(null);
              }
            }
          );
        }
      );
    });
  });
});
// ✅ 2) Verify wire transfer OTP => deduct + mark otp_status verified
router.post("/transfer/wire/verify", authenticateToken, (req, res) => {
  const userId = req.user?.id;
  const { transfer_id, otp } = req.body || {};

  if (!userId) return res.status(401).json({ error: "Unauthorized" });
  if (!transfer_id || !otp) return res.status(400).json({ error: "transfer_id and otp are required" });

  const otpHash = hashOtp(String(otp).trim());

  db.query(
    `SELECT t.id, t.user_id, t.from_account, t.amount, t.fee, t.total_amount, t.status, t.otp_status,
            t.bank_name, t.account_name, t.account_number,
            u.currency_sign, u.savings_balance, u.current_balance,
            o.otp_hash, o.expires_at, o.attempts, o.max_attempts
     FROM transfers t
     JOIN users u ON u.id = t.user_id
     JOIN transfer_otps o ON o.transfer_id = t.id
     WHERE t.id = ? AND t.user_id = ? AND t.transfer_type = 'wire'
     LIMIT 1`,
    [transfer_id, userId],
    (err, rows) => {
      if (err) return res.status(500).json({ error: "Verification fetch failed", details: String(err) });
      if (!rows || rows.length === 0) return res.status(404).json({ error: "Pending OTP wire transfer not found" });

      const r = rows[0];

      if (String(r.otp_status) !== "pending_otp") {
        return res.status(400).json({ error: "Transfer is not awaiting OTP" });
      }

      if (Number(r.attempts) >= Number(r.max_attempts)) {
        return res.status(429).json({ error: "Too many OTP attempts. Start transfer again." });
      }

      const expiresAt = new Date(r.expires_at);
      if (Date.now() > expiresAt.getTime()) {
        return res.status(400).json({ error: "OTP expired. Start transfer again." });
      }

      if (String(r.otp_hash) !== String(otpHash)) {
        db.query(`UPDATE transfer_otps SET attempts = attempts + 1 WHERE transfer_id = ?`, [transfer_id]);
        return res.status(403).json({ error: "Invalid OTP" });
      }

      const currency = r.currency_sign || "$";
      const fromAcc = String(r.from_account).toLowerCase();
      const balanceColumn = fromAcc === "savings" ? "savings_balance" : "current_balance";

      const balance = parseFloat(r[balanceColumn] || 0);
      const total = parseFloat(r.total_amount || (parseFloat(r.amount) + parseFloat(r.fee)));

      if (balance < total) return res.status(400).json({ error: "Insufficient balance (balance changed)" });

      const newBalance = (balance - total).toFixed(2);

      db.query(`UPDATE users SET ${balanceColumn} = ? WHERE id = ?`, [newBalance, userId], (e1) => {
        if (e1) return res.status(500).json({ error: "Failed to deduct balance", details: String(e1) });

        db.query(
          `UPDATE transfers
           SET otp_status = 'verified', otp_verified_at = NOW()
           WHERE id = ? AND user_id = ? AND transfer_type = 'wire'`,
          [transfer_id, userId],
          async (e2) => {
            if (e2) return res.status(500).json({ error: "Failed to update transfer status", details: String(e2) });

            db.query(`DELETE FROM transfer_otps WHERE transfer_id = ?`, [transfer_id]);

            try {
              await logActivity?.(
                userId,
                "wire_transfer_confirmed",
                `Wire transfer confirmed via OTP. Deducted ${currency}${total.toFixed(2)} (incl fee). Transfer ID #${transfer_id}`
              );
            } catch (_) {}

            return res.json({
              ok: true,
              message: `OTP verified. Wire transfer confirmed. Total ${currency}${total.toFixed(2)} deducted.`,
              transfer_id,
              status: r.status, // stays whatever your DB uses (processing)
              otp_status: "verified",
            });
          }
        );
      });
    }
  );
});
// 🔁 3) Resend OTP for pending wire transfer
router.post("/transfer/wire/resend-otp", authenticateToken, (req, res) => {
  const userId = req.user?.id;
  const { transfer_id } = req.body || {};

  if (!userId) return res.status(401).json({ error: "Unauthorized" });
  if (!transfer_id) return res.status(400).json({ error: "transfer_id is required" });

  db.query(
    `SELECT
        t.id,
        t.otp_status,
        t.total_amount,
        t.bank_name,
        t.account_name,
        t.account_number,
        u.email,
        u.full_name,
        u.currency_sign,
        o.last_sent_at
     FROM transfers t
     JOIN users u ON u.id = t.user_id
     JOIN transfer_otps o ON o.transfer_id = t.id
     WHERE t.id = ? AND t.user_id = ? AND t.transfer_type = 'wire'
     LIMIT 1`,
    [transfer_id, userId],
    async (err, rows) => {
      if (err) return res.status(500).json({ error: "Failed to fetch transfer", details: String(err) });
      if (!rows || rows.length === 0) return res.status(404).json({ error: "Pending wire transfer not found" });

      const r = rows[0];

      if (String(r.otp_status) !== "pending_otp") {
        return res.status(400).json({ error: "Transfer is not awaiting OTP" });
      }

      // resend cooldown
      const COOLDOWN_SECONDS = 60;
      if (r.last_sent_at) {
        const lastSent = new Date(r.last_sent_at).getTime();
        if (Date.now() - lastSent < COOLDOWN_SECONDS * 1000) {
          return res.status(429).json({
            error: "Please wait before requesting another OTP",
            retry_after_seconds: COOLDOWN_SECONDS,
          });
        }
      }

      const otp = generateOtp(6);
      const otpHash = hashOtp(String(otp).trim());

      db.query(
        `UPDATE transfer_otps
         SET otp_hash = ?,
             expires_at = DATE_ADD(NOW(), INTERVAL ? MINUTE),
             last_sent_at = NOW(),
             attempts = 0
         WHERE transfer_id = ? AND user_id = ?`,
        [otpHash, OTP_TTL_MINUTES, transfer_id, userId],
        async (err2) => {
          if (err2) return res.status(500).json({ error: "Failed to update OTP", details: String(err2) });

          try {
            const currency = r.currency_sign || "$";
            await sendTransferOTPEmail(r.email, r.full_name, otp, {
              amountText: `${currency}${Number(r.total_amount || 0).toFixed(2)}`,
              beneficiaryText: `${r.account_name} (${r.account_number}) - ${r.bank_name}`,
            });
          } catch (mailErr) {
            return res.status(500).json({ error: "Failed to send OTP email", details: String(mailErr) });
          }

          return res.json({
            ok: true,
            message: "OTP resent successfully",
            transfer_id,
            otp_expires_in_minutes: OTP_TTL_MINUTES,
          });
        }
      );
    }
  );
});

// 📜 Get Wire Transfer History (only wire) + entry_type
router.get('/transfer/history/wire', authenticateToken, async (req, res) => {
  const userId = req.user.id;

  try {
    const [rows] = await db.promise().query(`
      SELECT 
        t.id,
        t.transfer_type,
        t.entry_type,             -- ✅ added
        t.from_account,
        t.bank_name,
        t.account_name,
        t.account_number,
        t.bank_country,
        t.routine_number,
        t.reason,
        t.amount,
        t.fee,
        t.status,
        t.created_at,
        u.currency_sign
      FROM transfers t
      JOIN users u ON t.user_id = u.id
      WHERE t.user_id = ? AND t.transfer_type = 'wire'
      ORDER BY t.created_at DESC
      LIMIT 50
    `, [userId]);

    const result = rows.map(row => ({
      id: row.id,
      type: row.transfer_type,     // keeps it consistent
      entry_type: row.entry_type,  // ✅ added
      from_account: row.from_account,
      bank_name: row.bank_name,
      account_name: row.account_name,
      account_number: row.account_number,
      bank_country: row.bank_country,
      routine_number: row.routine_number,
      reason: row.reason,
      amount: `${row.currency_sign}${parseFloat(row.amount).toFixed(2)}`,
      fee: `${row.currency_sign}${parseFloat(row.fee).toFixed(2)}`,
      status: row.status,
      date: moment(row.created_at).format('YYYY-MM-DD HH:mm:ss')
    }));

    res.json({ wire_history: result });

  } catch (error) {
    console.error('❌ Wire history fetch failed:', error);
    res.status(500).json({ error: 'Failed to fetch wire transfer history' });
  }
});
// 📜 Get Transfer by ID (Local or Wire)
router.get('/transfer/history/:id', authenticateToken, (req, res) => {
  const userId = req.user.id;
  const transferId = req.params.id;

  const query = `
    SELECT 
      t.id, t.transfer_type, t.from_account, t.bank_name, t.account_name,
      t.account_number, t.bank_country, t.routine_number, t.reason,
      t.amount, t.fee, t.status, t.created_at, u.currency_sign
    FROM transfers t
    JOIN users u ON t.user_id = u.id
    WHERE t.id = ? AND t.user_id = ?
    LIMIT 1
  `;

  db.query(query, [transferId, userId], (err, results) => {
    if (err) {
      console.error('❌ Transfer fetch error:', err);
      return res.status(500).json({ error: 'Failed to fetch transfer' });
    }

    if (!results.length) {
      return res.status(404).json({ error: 'Transfer not found' });
    }

    const t = results[0];
    const currency = t.currency_sign || '$';

    // Format base data
    const baseTransfer = {
      id: t.id,
      type: t.transfer_type,
      from_account: t.from_account,
      bank_name: t.bank_name,
      account_name: t.account_name,
      account_number: t.account_number,
      reason: t.reason,
      amount: `${currency}${parseFloat(t.amount).toFixed(2)}`,
      fee: `${currency}${parseFloat(t.fee).toFixed(2)}`,
      status: t.status,
      date: moment(t.created_at).format('YYYY-MM-DD HH:mm:ss')
    };

    // Append wire-specific fields if type is 'wire'
    if (t.transfer_type === 'wire') {
      baseTransfer.bank_country = t.bank_country;
      baseTransfer.routine_number = t.routine_number;
    }

    res.json({ transfer: baseTransfer });
  });
});
// 👤 User: fetch wire transfer requirements & fee (no secrets)
router.get('/security-codes/requirements', authenticateToken, async (req, res) => {
  const userId = req.user.id;
  try {
    // Settings (default to required if row missing)
    const [[settingsRow]] = await db.promise().query(
      'SELECT require_imf, require_cot, require_tax FROM security_settings WHERE id = 1'
    );
    const require_imf = settingsRow ? !!settingsRow.require_imf : true;
    const require_cot = settingsRow ? !!settingsRow.require_cot : true;
    const require_tax = settingsRow ? !!settingsRow.require_tax : true;

    // Fee
    const [[feeRow]] = await db.promise().query(
      'SELECT fee_amount FROM transfer_fees WHERE type = ?', ['wire']
    );
    const fee = Number(feeRow?.fee_amount || 0);

    // Currency (and optionally balances for UX)
    const [[user]] = await db.promise().query(
      'SELECT currency_sign, current_balance, savings_balance FROM users WHERE id = ?',
      [userId]
    );
    const currency_sign = user?.currency_sign || '$';

    res.json({
      ok: true,
      requirements: { imf: require_imf, cot: require_cot, tax: require_tax },
      fee,
      currency_sign,
      // optional, handy for showing available funds
      balances: {
        current: Number(user?.current_balance ?? 0),
        savings: Number(user?.savings_balance ?? 0)
      }
    });
  } catch (e) {
    console.error('❌ GET /security-codes/requirements:', e);
    res.status(500).json({ ok: false, error: 'db_error', details: e.message });
  }
});


// 💳 self Transfer (same user, same bank)
router.post('/transfer/self', authenticateToken, (req, res) => {
  const userId = req.user.id;
  const { from_account, to_account, amount, pin } = req.body;

  if (!from_account || !to_account || !amount || !pin || from_account === to_account) {
    return res.status(400).json({ error: 'Invalid self transfer request' });
  }

  // Step 1: Get and verify user's PIN
  db.query('SELECT transaction_pin FROM users WHERE id = ?', [userId], (err, results) => {
    if (err) return res.status(500).json({ error: 'DB error on PIN' });
    if (!results.length || results[0].transaction_pin !== pin) {
      return res.status(403).json({ error: 'Incorrect PIN' });
    }

    const fromCol = from_account === 'savings' ? 'savings_balance' : 'current_balance';
    const toCol = to_account === 'savings' ? 'savings_balance' : 'current_balance';

    // Step 2: Check balance
    db.query(`SELECT ${fromCol}, ${toCol} FROM users WHERE id = ?`, [userId], (err2, balances) => {
      if (err2) return res.status(500).json({ error: 'DB error on balance check' });

      const fromBal = parseFloat(balances[0][fromCol]);
      const amountNum = parseFloat(amount);

      if (fromBal < amountNum) {
        return res.status(400).json({ error: 'Insufficient balance' });
      }

      const newFrom = (fromBal - amountNum).toFixed(2);
      const newTo = (parseFloat(balances[0][toCol]) + amountNum).toFixed(2);

      // Step 3: Perform update and insert
      db.query(`UPDATE users SET ${fromCol} = ?, ${toCol} = ? WHERE id = ?`, [newFrom, newTo, userId]);
      db.query(
        `INSERT INTO self_transfers (user_id, from_account, to_account, amount) VALUES (?, ?, ?, ?)`,
        [userId, from_account, to_account, amountNum]
      );

      // Step 4: Log activity in USD
      logActivity(
        userId,
        'self_transfer',
        `Transferred $${amountNum.toFixed(2)} from ${from_account} to ${to_account}`
      );

      res.json({ message: 'Self transfer completed successfully' });
    });
  });
});
// 📜 Get self-transfer history (formatted)
router.get('/transfer/self/history', authenticateToken, (req, res) => {
  const userId = req.user.id;

  const query = `
    SELECT id, from_account, to_account, amount, created_at
    FROM self_transfers
    WHERE user_id = ?
    ORDER BY created_at DESC
  `;

  db.query(query, [userId], (err, results) => {
    if (err) return res.status(500).json({ error: 'Failed to fetch transfer history' });

    const formattedResults = results.map((record) => ({
      id: record.id,
      from_account: record.from_account,
      to_account: record.to_account,
      amount: `$${parseFloat(record.amount).toFixed(2)}`,
      created_at: moment(record.created_at).format('MMM D, YYYY h:mm A')
    }));

    res.json({ history: formattedResults });
  });
});


// 🔍 Get last 50 activity logs for the authenticated user
router.get('/logs', authenticateToken, (req, res) => {
  const userId = req.user.id;

  const query = `
    SELECT id, activity_type, description, created_at
    FROM activities
    WHERE user_id = ?
    ORDER BY created_at DESC
    LIMIT 50
  `;

  db.query(query, [userId], (err, results) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to fetch activity logs' });
    }

    const formattedLogs = results.map(log => ({
      ...log,
      formatted_time: moment(log.created_at).format('MMMM Do YYYY, h:mm:ss A') // e.g., August 8th 2025, 2:45:23 PM
    }));

    res.json({ logs: formattedLogs });
  });
});

// 📄 User - Request ATM Card
router.post('/request-atm-card', authenticateToken, async (req, res) => {
  const userId = req.user.id;
  const { account_type } = req.body;

  if (!['savings', 'current'].includes(account_type)) {
    return res.status(400).json({ error: 'Invalid account type' });
  }

  try {
    // 1. Check if card already requested or approved
    const [existing] = await db.promise().query(
      `SELECT * FROM atm_cards WHERE user_id = ? AND account_type = ? AND status IN ('pending', 'approved')`,
      [userId, account_type]
    );
    if (existing.length) {
      return res.status(400).json({ error: 'ATM card already requested or approved' });
    }

    // 2. Get fee for this account type
    const [feeResult] = await db.promise().query(
      'SELECT fee FROM card_fees WHERE account_type = ?',
      [account_type]
    );
    if (!feeResult.length) return res.status(400).json({ error: 'Fee not set for this account type' });

    const fee = parseFloat(feeResult[0].fee);

    // 3. Get user info and balance
    const col = account_type === 'savings' ? 'savings_balance' : 'current_balance';
    const [userRow] = await db.promise().query(
      `SELECT full_name, email, ${col}, currency_sign FROM users WHERE id = ?`, 
      [userId]
    );
    const balance = parseFloat(userRow[0][col]);
    const name = userRow[0].full_name;
    const email = userRow[0].email;
    const currency = userRow[0].currency_sign;

    if (balance < fee) {
      return res.status(400).json({ error: 'Insufficient balance for ATM card fee' });
    }

    // 4. Deduct the fee
    const newBal = (balance - fee).toFixed(2);
    await db.promise().query(`UPDATE users SET ${col} = ? WHERE id = ?`, [newBal, userId]);

    // 5. Generate card details
    const card_number = '5' + Math.floor(100000000000000 + Math.random() * 900000000000000); // MasterCard format
    const expiry_date = moment().add(3, 'years').format('MM/YY');
    const cvv = Math.floor(100 + Math.random() * 900).toString();

    // 6. Save card
    const [insertResult] = await db.promise().query(
      `INSERT INTO atm_cards (user_id, account_type, card_number, card_holder_name, expiry_date, cvv, fee)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [userId, account_type, card_number, name, expiry_date, cvv, fee]
    );

    // 7. Log Activity
    await logActivity(userId, 'atm_card_request', `Requested ATM card for ${account_type} account. Fee: ${currency}${fee.toFixed(2)}`);

    // 8. Email notification
    await sendAtmCardRequestEmail(email, name, account_type, currency, fee.toFixed(2));

    // 9. Return card info to user
    res.json({
      message: `ATM card request submitted successfully. Fee ${currency}${fee.toFixed(2)} deducted.`,
      card: {
        card_number,
        card_holder_name: name,
        expiry_date,
        cvv,
        account_type,
        status: 'pending'
      }
    });

  } catch (error) {
    console.error('ATM Request Error:', error);
    res.status(500).json({ error: 'Failed to request ATM card' });
  }
});
// 📄 Get ATM card info for the authenticated user
router.get('/atm-card-info', authenticateToken, async (req, res) => {
  const userId = req.user.id;

  try {
    const [rows] = await db.promise().query(
      `SELECT account_type, card_number, card_holder_name, expiry_date, cvv, fee, status, requested_at 
       FROM atm_cards 
       WHERE user_id = ?
       ORDER BY requested_at DESC`,
      [userId]
    );

    res.json({ cards: rows });
  } catch (err) {
    console.error('Card fetch error:', err);
    res.status(500).json({ error: 'Failed to fetch card info' });
  }
});

// 🪙 GET all wallets (QR code URLs use server base URL)
router.get('/wallets', authenticateToken, async (req, res) => {
  try {
    const [wallets] = await db.promise().query('SELECT * FROM wallets ORDER BY id DESC');

    const baseUrl = `${req.protocol}://${req.get('host')}`; // ✅ dynamic server URL

    const formattedWallets = wallets.map(w => ({
      id: w.id,
      wallet_name: w.wallet_name,
      wallet_address: w.wallet_address,
      qrcode_url: `${baseUrl}/${w.qrcode_path}`, // full server URL
      created_at: w.created_at
    }));

    res.json({ wallets: formattedWallets });
  } catch (error) {
    console.error('❌ Fetch wallets error:', error);
    res.status(500).json({ error: 'Failed to retrieve wallets' });
  }
});


// 🧾 CREATE TICKET
router.post('/create', authenticateToken, async (req, res) => {
  const { subject, message } = req.body;
  const user_id = req.user.id;

  if (!subject || !message) {
    return res.status(400).json({ error: 'Subject and message are required' });
  }

  try {
    const [[user]] = await db.promise().query(
      'SELECT username, email FROM users WHERE id = ?',
      [user_id]
    );

    const now = moment().format('YYYY-MM-DD HH:mm:ss');

    const [ticketResult] = await db.promise().query(
      `INSERT INTO support_tickets (user_id, subject, status, created_at) 
       VALUES (?, ?, 'open', ?)`,
      [user_id, subject, now]
    );

    await db.promise().query(
      `INSERT INTO support_messages (ticket_id, sender, message, created_at) 
       VALUES (?, 'user', ?, ?)`,
      [ticketResult.insertId, message, now]
    );

    const alertText =
      `<b>🆕 New Support Ticket</b>\n\n` +
      `👤 User: <b>${user?.username || 'Unknown User'}</b>\n` +
      (user?.email ? `📧 Email: <code>${user.email}</code>\n` : '') +
      `🆔 Ticket: <code>#${ticketResult.insertId}</code>\n` +
      `📌 Subject: <b>${subject}</b>\n` +
      `⏱ ${now}\n\n` +
      `💬 Message:\n${message}\n`;

    const keyboard = {
      inline_keyboard: [
        [
          { text: `💬 Reply #${ticketResult.insertId}`, callback_data: `ticket:${ticketResult.insertId}:reply` },
          { text: `📄 View #${ticketResult.insertId}`,  callback_data: `ticket:${ticketResult.insertId}:view` },
          { text: `✅ Close #${ticketResult.insertId}`, callback_data: `ticket:${ticketResult.insertId}:close` }
        ]
      ]
    };

    notifyAdmins(alertText, keyboard).catch(err => {
      console.error('notifyAdmins error (new ticket):', err.message);
    });

    res.status(201).json({
      message: 'Ticket created successfully',
      ticket_id: ticketResult.insertId
    });
  } catch (error) {
    console.error('❌ Error creating ticket:', error);
    res.status(500).json({ error: 'Server error creating ticket' });
  }
});
// 💬 USER REPLY TO TICKET
router.post('/:ticket_id/reply', authenticateToken, async (req, res) => {
  const { ticket_id } = req.params;
  const { message } = req.body;
  const user_id = req.user.id;

  if (!message) {
    return res.status(400).json({ error: 'Message required' });
  }

  try {
    const [[ticket]] = await db.promise().query(
      'SELECT * FROM support_tickets WHERE id = ? AND user_id = ?',
      [ticket_id, user_id]
    );

    if (!ticket) {
      return res.status(404).json({ error: 'Ticket not found' });
    }

    const [[user]] = await db.promise().query(
      'SELECT username, email FROM users WHERE id = ?',
      [user_id]
    );

    const now = moment().format('YYYY-MM-DD HH:mm:ss');

    await db.promise().query(
      `INSERT INTO support_messages (ticket_id, sender, message, created_at) 
       VALUES (?, 'user', ?, ?)`,
      [ticket_id, message, now]
    );

    const alertText =
      `<b>💬 New Reply on Ticket #${ticket_id}</b>\n\n` +
      `👤 User: <b>${user?.username || 'Unknown User'}</b>\n` +
      (user?.email ? `📧 Email: <code>${user.email}</code>\n` : '') +
      `📌 Subject: <b>${ticket.subject}</b>\n` +
      `⏱ ${now}\n\n` +
      `💬 Message:\n${message}\n`;

    const keyboard = {
      inline_keyboard: [
        [
          { text: `📄 View #${ticket_id}`,  callback_data: `ticket:${ticket_id}:view` },
          { text: `💬 Reply #${ticket_id}`, callback_data: `ticket:${ticket_id}:reply` },
          { text: `✅ Close #${ticket_id}`, callback_data: `ticket:${ticket_id}:close` }
        ]
      ]
    };

    notifyAdmins(alertText, keyboard).catch(err => {
      console.error('notifyAdmins error (reply):', err.message);
    });

    res.json({ message: 'Reply sent successfully' });
  } catch (error) {
    console.error('❌ Error replying to ticket:', error);
    res.status(500).json({ error: 'Server error sending reply' });
  }
});
// 📜 GET USER TICKETS
router.get('/my-tickets', authenticateToken, async (req, res) => {
  const user_id = req.user.id;

  try {
    const [tickets] = await db.promise().query(
      'SELECT * FROM support_tickets WHERE user_id = ? ORDER BY created_at DESC',
      [user_id]
    );

    res.json(tickets);
  } catch (error) {
    console.error('❌ Error fetching tickets:', error);
    res.status(500).json({ error: 'Server error fetching tickets' });
  }
});
// 📜 GET all messages for a specific ticket (User)
router.get('/:ticket_id/messages', authenticateToken, async (req, res) => {
  const { ticket_id } = req.params;
  const user_id = req.user.id;

  try {
    // Ensure the ticket belongs to the user
    const [[ticket]] = await db.promise().query(
      'SELECT * FROM support_tickets WHERE id = ? AND user_id = ?',
      [ticket_id, user_id]
    );

    if (!ticket) {
      return res.status(404).json({ error: 'Ticket not found or not yours' });
    }

    // Fetch messages for that ticket
    const [messages] = await db.promise().query(
      'SELECT id, sender, message, created_at FROM support_messages WHERE ticket_id = ? ORDER BY created_at ASC',
      [ticket_id]
    );

    // Format timestamps using moment
    const formattedMessages = messages.map(msg => ({
      ...msg,
      created_at: moment(msg.created_at).format('YYYY-MM-DD HH:mm:ss')
    }));

    res.json({
      ticket: {
        id: ticket.id,
        subject: ticket.subject,
        status: ticket.status,
        created_at: moment(ticket.created_at).format('YYYY-MM-DD HH:mm:ss')
      },
      messages: formattedMessages
    });
  } catch (error) {
    console.error('Error fetching ticket messages:', error);
    res.status(500).json({ error: 'Server error fetching ticket messages' });
  }
});


// User submits a deposit with proof of payment 🧾 POST /user/deposit
router.post('/deposit', authenticateToken, proofupload.single('proof'), async (req, res) => {
  try {
    const { amount, wallet_id } = req.body;
    const user_id = req.user.id;
    const proof_path = req.file ? req.file.path : null;

    if (!amount || !wallet_id || !proof_path) {
      return res.status(400).json({ error: 'Missing fields: amount, wallet_id, proof required' });
    }

    const created_at = moment().format('YYYY-MM-DD HH:mm:ss');

    await db
      .promise()
      .query(
        'INSERT INTO deposits (user_id, wallet_id, amount, proof_path, status, created_at) VALUES (?, ?, ?, ?, ?, ?)',
        [user_id, wallet_id, amount, proof_path, 'pending', created_at]
      );

    res.json({ message: 'Deposit submitted successfully and awaiting admin confirmation' });
  } catch (error) {
    console.error('❌ Deposit upload error:', error);
    res.status(500).json({ error: 'Failed to submit deposit' });
  }
});
// Get all deposits for the logged-in user 👀 GET /user/deposits
router.get('/deposits', authenticateToken, async (req, res) => {
  try {
    const user_id = req.user.id;
    const [deposits] = await db
      .promise()
      .query('SELECT * FROM deposits WHERE user_id = ? ORDER BY id DESC', [user_id]);

    const baseUrl = `${req.protocol}://${req.get('host')}`;
    const formatted = deposits.map(d => ({
      id: d.id,
      amount: d.amount,
      wallet_id: d.wallet_id,
      status: d.status,
      proof_url: `${baseUrl}/${d.proof_path}`,
      created_at: d.created_at
    }));

    res.json({ deposits: formatted });
  } catch (error) {
    console.error('❌ Fetch user deposits error:', error);
    res.status(500).json({ error: 'Failed to fetch deposits' });
  }
});



// Delete user account
router.delete('/delete', authenticateToken, (req, res) => {
  const userId = req.user.id;

  db.query('DELETE FROM users WHERE id = ?', [userId], (err) => {
    if (err) return res.status(500).json({ error: 'Failed to delete account' });
    res.json({ message: 'Account deleted successfully' });
  });
});

module.exports = router;
