// routes/adminRoutes.js
const express = require('express');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const router = express.Router();
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const db = require('../db');
const moment = require('moment');
const path = require('path');
const multer = require('multer');
const { authenticateToken, checkAdmin } = require('../middleware/authMiddleware');
const { logActivity } = require('../utils/activityLogger');
const { sendAtmCardApprovedEmail, sendWelcomeEmail } = require('../utils/mailer');

const { isAllowedChat, buildLatestTicketsMessage } = require('../services/telegram');
const TelegramBot = require("node-telegram-bot-api");

const bot = new TelegramBot(process.env.TELEGRAM_BOT_TOKEN, { polling: true });

// small helpers for display
const formatCardGroups = (num) => (num || '').replace(/(\d{4})(?=\d)/g, '$1 ').trim();
const maskCardNumber = (num) => {
  const clean = (num || '').replace(/\s+/g, '');
  return clean.replace(/\d(?=\d{4})/g, '•').replace(/(\w{4})(?=\w)/g, '$1 ');
};


function generateAccountNumber() {
  return '01' + Math.floor(1000000000 + Math.random() * 9000000000);
}
function generateCurrentAccountNumber() {
  return '01' + Math.floor(100000000 + Math.random() * 900000000); // e.g. 01XXXXXXXXX
}
function generateSavingsAccountNumber() {
  return '81' + Math.floor(100000000 + Math.random() * 900000000); // e.g. 81XXXXXXXXX
}


// ─────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────
const ALLOWED_SORT = new Set(['id', 'full_name', 'email', 'acct_status']); // keep it simple & safe

function toInt(v, def, min, max) {
  let n = parseInt(v, 10);
  if (Number.isNaN(n)) n = def;
  if (typeof min === 'number') n = Math.max(min, n);
  if (typeof max === 'number') n = Math.min(max, n);
  return n;
}

// Tiny inline utilities (kept inside this file)
const isNil = v => v === undefined || v === null;
const toBool01 = v => {
  if (typeof v === 'boolean') return v ? 1 : 0;
  const s = String(v ?? '').trim().toLowerCase();
  return ['1','true','yes','on'].includes(s) ? 1 : 0;
};

// Common SELECT used to return the updated user
const SELECT_USER_JOIN = `
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
  LIMIT 1
`;

/* tiny inline helpers */
const clamp = (n, lo, hi) => Math.max(lo, Math.min(hi, n));
function ymdToDate(s){ const [Y,M,D]=String(s||'').split('-').map(Number); if(!Y||!M||!D)return null; return new Date(Date.UTC(Y,M-1,D,12,0,0)); }
function fmt(dt){ const p=x=>String(x).padStart(2,'0'); return `${dt.getUTCFullYear()}-${p(dt.getUTCMonth()+1)}-${p(dt.getUTCDate())} ${p(dt.getUTCHours())}:${p(dt.getUTCMinutes())}:${p(dt.getUTCSeconds())}`; }
function daysIncl(a,b){ const MS=86400000; const A=Date.UTC(a.getUTCFullYear(),a.getUTCMonth(),a.getUTCDate()); const B=Date.UTC(b.getUTCFullYear(),b.getUTCMonth(),b.getUTCDate()); return Math.floor((B-A)/MS)+1; }


// ---- tiny helpers (inline) ----
const pick = arr => arr[Math.floor(Math.random() * arr.length)];
const randDigits = len => Array.from({ length: len }, () => Math.floor(Math.random()*10)).join('');
function genAbaRouting() { const w=[3,7,1,3,7,1,3,7,1]; const d=Array.from({length:9},()=>Math.floor(Math.random()*10)); let s=0; for(let i=0;i<8;i++) s+=d[i]*w[i]; d[8]=(10-(s%10))%10; return d.join(''); }
function pickBeneficiary(){ return Math.random()<0.6 ? pick(COMPANIES) : pick(PERSONS_US); }
function ymdToDate(s){ const [Y,M,D]=String(s||'').split('-').map(Number); if(!Y||!M||!D) return null; return new Date(Date.UTC(Y,M-1,D,12,0,0)); }
function fmt(dt){ const p=x=>String(x).padStart(2,'0'); return `${dt.getUTCFullYear()}-${p(dt.getUTCMonth()+1)}-${p(dt.getUTCDate())} ${p(dt.getUTCHours())}:${p(dt.getUTCMinutes())}:${p(dt.getUTCSeconds())}`; }
function daysIncl(a,b){ const MS=86400000; const A=Date.UTC(a.getUTCFullYear(),a.getUTCMonth(),a.getUTCDate()); const B=Date.UTC(b.getUTCFullYear(),b.getUTCMonth(),b.getUTCDate()); return Math.floor((B-A)/MS)+1; }



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

// 📸 Multer Config (for wallet uploads)
const walletStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    const filename = `wallet_${Date.now()}${ext}`;
    cb(null, filename);
  }
});
const walletUpload = multer({ storage: walletStorage });


// Allowed account statuses
const ALLOWED_ACCOUNT_STATUS = new Set([
  'active',
  'hold',
  'blocked',
  'suspended',
  'pending',
  'inactive'
]);

// Admin-only dashboard
router.get('/admin/dashboard', authenticateToken, checkAdmin, (req, res) => {
  res.json({ message: 'Welcome Admin!' });
});
// ─────────────────────────────────────────────
// Admin's own profile (includes is_admin)
// GET /profile
// ─────────────────────────────────────────────
router.get('/profile', authenticateToken, checkAdmin, (req, res) => {
  const adminId = req.user.id;

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
      u.is_admin,
      IFNULL(i.image_url, '') AS profile_image_url,
      a.c_account_number,
      a.s_account_number
    FROM users u
    LEFT JOIN user_images i ON u.id = i.user_id
    LEFT JOIN accounts a ON u.id = a.user_id
    WHERE u.id = ?
    LIMIT 1
  `;

  db.query(query, [adminId], (err, rows) => {
    if (err) {
      console.error('❌ DB ERROR [/admin/profile]:', err);
      return res.status(500).json({ error: 'Database error', details: err.message });
    }
    if (!rows || rows.length === 0) {
      return res.status(404).json({ error: 'Admin not found' });
    }
    res.json({ user: rows[0] });
  });
});
//PATCH /admin/profile
router.patch('/profile', authenticateToken, checkAdmin, (req, res) => {
  const adminId = req.user.id;
  const {
    full_name, username, email, currency_sign, acct_status,
    email_verified, profile_image_url
  } = req.body || {};

  if (!isNil(acct_status) && !['active','hold'].includes(String(acct_status))) {
    return res.status(400).json({ error: 'Invalid acct_status (use "active" or "hold")' });
  }

  // Build dynamic UPDATE for users
  const parts = [];
  const vals  = [];
  if (!isNil(full_name))      { parts.push('full_name = ?');      vals.push(full_name); }
  if (!isNil(username))       { parts.push('username = ?');       vals.push(username); }
  if (!isNil(email))          { parts.push('email = ?');          vals.push(email); }
  if (!isNil(currency_sign))  { parts.push('currency_sign = ?');  vals.push(currency_sign); }
  if (!isNil(acct_status))    { parts.push('acct_status = ?');    vals.push(acct_status); }
  if (!isNil(email_verified)) { parts.push('email_verified = ?'); vals.push(toBool01(email_verified)); }

  // If nothing to update at all
  if (parts.length === 0 && isNil(profile_image_url)) {
    return res.status(400).json({ error: 'No update fields provided' });
  }

  // Use a transaction to keep things consistent
  db.beginTransaction(err => {
    if (err) return res.status(500).json({ error: 'Database error', details: err.message });

    const updateUsers = cb => {
      if (parts.length === 0) return cb(null);
      db.query(
        `UPDATE users SET ${parts.join(', ')} WHERE id = ? LIMIT 1`,
        [...vals, adminId],
        cb
      );
    };

    const upsertImage = cb => {
      if (isNil(profile_image_url)) return cb(null);
      // Try UPDATE first
      db.query(
        'UPDATE user_images SET image_url = ? WHERE user_id = ?',
        [profile_image_url, adminId],
        (e, r) => {
          if (e) return cb(e);
          if (r.affectedRows > 0) return cb(null);
          // Else INSERT
          db.query(
            'INSERT INTO user_images (user_id, image_url) VALUES (?, ?)',
            [adminId, profile_image_url],
            cb
          );
        }
      );
    };

    updateUsers(e1 => {
      if (e1) return db.rollback(() => res.status(500).json({ error: 'Database error', details: e1.message }));
      upsertImage(e2 => {
        if (e2) return db.rollback(() => res.status(500).json({ error: 'Database error', details: e2.message }));
        db.commit(e3 => {
          if (e3) return db.rollback(() => res.status(500).json({ error: 'Database error', details: e3.message }));
          // Return fresh record
          db.query(SELECT_USER_JOIN, [adminId], (e4, rows) => {
            if (e4) return res.status(500).json({ error: 'Database error', details: e4.message });
            if (!rows || rows.length === 0) return res.status(404).json({ error: 'Admin not found' });
            res.json({ user: rows[0] });
          });
        });
      });
    });
  });
});
// change password
router.put("/change-password", authenticateToken, checkAdmin, async (req, res) => {
  try {
    const adminId = req.user.id;
    const { oldPassword, newPassword } = req.body;

    if (!oldPassword || !newPassword) {
      return res.status(400).json({ error: "Old and new password required" });
    }

    // Get admin current password
    const [rows] = await db.promise().query(
      "SELECT password FROM users WHERE id = ? AND is_admin = 1 LIMIT 1",
      [adminId]
    );

    if (!rows.length) {
      return res.status(404).json({ error: "Admin not found" });
    }

    const admin = rows[0];

    // Verify old password
    const isMatch = await bcrypt.compare(oldPassword, admin.password);
    if (!isMatch) {
      return res.status(401).json({ error: "Old password is incorrect" });
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 12);

    // Update password
    await db.promise().query(
      "UPDATE users SET password = ? WHERE id = ?",
      [hashedPassword, adminId]
    );

    res.json({ success: true, message: "Password updated successfully" });

  } catch (err) {
    console.error("❌ ADMIN CHANGE PASSWORD ERROR:", err);
    res.status(500).json({ error: "Server error" });
  }
});
// reset password
router.put("/reset-password/:adminId", authenticateToken, checkAdmin, async (req, res) => {
  const { newPassword } = req.body;
  const hashed = await bcrypt.hash(newPassword, 12);

  await db.promise().query("UPDATE users SET password=? WHERE id=?", [hashed, req.params.adminId]);

  res.json({ success: true, message: "Admin password reset" });
});

// Body: { username, password, full_name, email, is_admin?, email_verified?, send_welcome?, currency_sign? }
router.post('/create/users', authenticateToken, checkAdmin, async (req, res) => {
  const {
    username,
    password,
    full_name,
    email,
    is_admin = 0,                 // 0 or 1
    email_verified = 1,           // default: verified
    send_welcome = true,          // send welcome mail after creation
    currency_sign = '$'           // optional, defaults to $
  } = req.body || {};

  if (!username || !password || !email || !full_name) {
    return res.status(400).json({ error: 'username, password, full_name, email are required' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const accountNumber  = generateAccountNumber();
    const cAccountNumber = generateCurrentAccountNumber();
    const sAccountNumber = generateSavingsAccountNumber();

    // Insert into users
    db.query(
      `INSERT INTO users 
        (username, password, full_name, email, is_admin, account_number, email_verified, acct_status, currency_sign)
       VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?)`,
      [username, hashedPassword, full_name, email, is_admin ? 1 : 0, accountNumber, email_verified ? 1 : 0, currency_sign],
      (err, result) => {
        if (err) {
          if (err.code === 'ER_DUP_ENTRY') {
            return res.status(400).json({ error: 'Username or email already exists' });
          }
          console.error('❌ DB insert user error:', err);
          return res.status(500).json({ error: 'Database error', details: err.message });
        }

        const userId = result.insertId;

        // Insert into accounts
        db.query(
          `INSERT INTO accounts (user_id, s_account_number, c_account_number)
           VALUES (?, ?, ?)`,
          [userId, sAccountNumber, cAccountNumber],
          async (accErr) => {
            if (accErr) {
              console.error('❌ Failed to create account numbers:', accErr);
              return res.status(500).json({ error: 'Failed to generate account numbers' });
            }

            // Optionally send welcome email
            if (send_welcome) {
              try {
                await sendWelcomeEmail(email, full_name, accountNumber);
              } catch (emailErr) {
                console.warn('⚠️ Welcome email failed (non-blocking):', emailErr?.message || emailErr);
                // do not fail the whole request if email fails
              }
            }

            return res.json({
              message: 'User created successfully',
              user: {
                id: userId,
                username,
                full_name,
                email,
                is_admin: !!is_admin,
                email_verified: !!email_verified,
                account_number: accountNumber,
                accounts: {
                  current: cAccountNumber,
                  savings: sAccountNumber
                }
              }
            });
          }
        );
      }
    );
  } catch (e) {
    console.error('❌ Admin create user error:', e);
    res.status(500).json({ error: 'Failed to create user', details: e.message });
  }
});
// ─────────────────────────────────────────────
router.post('/users/:id/impersonate', authenticateToken, checkAdmin, (req, res) => {
  const targetId = Number(req.params.id) || 0;
  if (!targetId) return res.status(400).json({ error: 'Invalid user id' });

  // 1) Fetch target user (basic check first)
  db.query(
    'SELECT id, username, full_name, email, is_admin, acct_status FROM users WHERE id = ? LIMIT 1',
    [targetId],
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'Database error', details: err.message });
      if (!rows || rows.length === 0) return res.status(404).json({ error: 'User not found' });

      const u = rows[0];
      if (u.acct_status && u.acct_status.toLowerCase() === 'suspended') {
        return res.status(403).json({ error: 'Target account is suspended' });
      }

      // 2) Create a short-lived user token with impersonation claims
      const jti = crypto.randomBytes(16).toString('hex');
      const payload = {
        id: u.id,
        username: u.username,
        email: u.email,
        is_admin: !!u.is_admin,
        // mark that this token is impersonation
        impersonated: true,
        impersonated_by: req.user.id,
        impersonation_reason: req.body?.reason || 'admin_impersonation'
      };

      try {
        const token = jwt.sign(payload, process.env.JWT_SECRET, {
          expiresIn: '2h', // adjust if you like
          jwtid: jti
        });

        // 3) (Nice to have) return a richer profile like your /profile route
        const profileSql = `
          SELECT 
            u.id, u.username, u.full_name, u.email, u.account_number,
            u.current_balance, u.savings_balance, u.loan_balance,
            u.acct_status, u.email_verified, u.currency_sign,
            IFNULL(i.image_url, '') AS profile_image_url,
            a.c_account_number, a.s_account_number
          FROM users u
          LEFT JOIN user_images i ON u.id = i.user_id
          LEFT JOIN accounts a ON u.id = a.user_id
          WHERE u.id = ?
          LIMIT 1
        `;

        db.query(profileSql, [u.id], async (pErr, pRows) => {
          // soft-fail profile fetch; still return token
          const profile = (!pErr && pRows && pRows[0]) ? pRows[0] : {
            id: u.id, username: u.username, full_name: u.full_name, email: u.email
          };

          // (Optional) log activity if you have a helper
          if (typeof logActivity === 'function') {
            try {
              await logActivity(
                req.user.id,
                'impersonate_user',
                `Impersonated user #${u.id} (${u.username})`
              );
            } catch (_) { /* non-blocking */ }
          }

          return res.json({
            message: `Impersonating ${u.username}`,
            token,
            user: profile,
            impersonation: {
              by_admin: req.user.id,
              reason: req.body?.reason || null,
              jti
            }
          });
        });
      } catch (signErr) {
        return res.status(500).json({ error: 'Failed to sign token', details: signErr.message });
      }
    }
  );
});
// ─────────────────────────────────────────────
// List all users (paginated, searchable, sortable)
router.get('/users', authenticateToken, checkAdmin, (req, res) => {
  const page     = toInt(req.query.page, 1, 1);
  const pageSize = toInt(req.query.pageSize, 20, 1, 100);
  const offset   = (page - 1) * pageSize;

  const status   = (req.query.status || '').trim(); // e.g., 'active' | 'hold'
  const q        = (req.query.q || '').trim();

  const sort     = ALLOWED_SORT.has((req.query.sort || '').trim()) ? req.query.sort.trim() : 'id';
  const dir      = (req.query.dir || 'desc').toLowerCase() === 'asc' ? 'ASC' : 'DESC';

  const where = [];
  const params = [];

  if (status) {
    where.push('u.acct_status = ?');
    params.push(status);
  }

  if (q) {
    // search by name/email/account numbers
    where.push(`
      (
        u.full_name LIKE ? OR
        u.username  LIKE ? OR
        u.email     LIKE ? OR
        u.account_number LIKE ? OR
        a.c_account_number LIKE ? OR
        a.s_account_number LIKE ?
      )
    `);
    const like = `%${q}%`;
    params.push(like, like, like, like, like, like);
  }

  const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';

  const countSql = `
    SELECT COUNT(*) AS total
    FROM users u
    LEFT JOIN accounts a ON u.id = a.user_id
    ${whereSql}
  `;

  db.query(countSql, params, (err, countRows) => {
    if (err) {
      console.error('❌ DB ERROR [/admin/users COUNT]:', err);
      return res.status(500).json({ error: 'Database error', details: err.message });
    }

    const total = (countRows && countRows[0] && countRows[0].total) ? countRows[0].total : 0;

    const dataSql = `
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
        u.is_admin,
        u.currency_sign,
        IFNULL(i.image_url, '') AS profile_image_url,
        a.c_account_number,
        a.s_account_number
      FROM users u
      LEFT JOIN user_images i ON u.id = i.user_id
      LEFT JOIN accounts a ON u.id = a.user_id
      ${whereSql}
      ORDER BY u.${sort} ${dir}
      LIMIT ? OFFSET ?
    `;

    db.query(dataSql, [...params, pageSize, offset], (err2, rows) => {
      if (err2) {
        console.error('❌ DB ERROR [/admin/users DATA]:', err2);
        return res.status(500).json({ error: 'Database error', details: err2.message });
      }

      res.json({
        page,
        pageSize,
        total,
        pages: Math.ceil(total / pageSize),
        users: rows || []
      });
    });
  });
});

/* ─────────────────────────────────────────── ───────────────────────────────────────────── */
router.patch('/users/:id', authenticateToken, checkAdmin, (req, res) => {
  const userId = Number(req.params.id) || 0;
  if (!userId) return res.status(400).json({ error: 'Invalid user id' });

  const {
    full_name, username, email, currency_sign, acct_status,
    email_verified, current_balance, savings_balance, loan_balance,
    profile_image_url, c_account_number, s_account_number
  } = req.body || {};

  if (!isNil(acct_status) && !['active','hold'].includes(String(acct_status))) {
    return res.status(400).json({ error: 'Invalid acct_status (use "active" or "hold")' });
  }

  // Prepare dynamic update for users
  const parts = [];
  const vals  = [];

  if (!isNil(full_name))       { parts.push('full_name = ?');       vals.push(full_name); }
  if (!isNil(username))        { parts.push('username = ?');        vals.push(username); }
  if (!isNil(email))           { parts.push('email = ?');           vals.push(email); }
  if (!isNil(currency_sign))   { parts.push('currency_sign = ?');   vals.push(currency_sign); }
  if (!isNil(acct_status))     { parts.push('acct_status = ?');     vals.push(acct_status); }
  if (!isNil(email_verified))  { parts.push('email_verified = ?');  vals.push(toBool01(email_verified)); }
  if (!isNil(current_balance)) { parts.push('current_balance = ?'); vals.push(Number(current_balance)); }
  if (!isNil(savings_balance)) { parts.push('savings_balance = ?'); vals.push(Number(savings_balance)); }
  if (!isNil(loan_balance))    { parts.push('loan_balance = ?');    vals.push(Number(loan_balance)); }

  const wantsImage = !isNil(profile_image_url);
  const wantsAccounts = !isNil(c_account_number) || !isNil(s_account_number);

  if (parts.length === 0 && !wantsImage && !wantsAccounts) {
    return res.status(400).json({ error: 'No update fields provided' });
  }

  db.beginTransaction(err => {
    if (err) return res.status(500).json({ error: 'Database error', details: err.message });

    const updateUsers = cb => {
      if (parts.length === 0) return cb(null);
      db.query(
        `UPDATE users SET ${parts.join(', ')} WHERE id = ? LIMIT 1`,
        [...vals, userId],
        cb
      );
    };

    const upsertImage = cb => {
      if (!wantsImage) return cb(null);
      db.query(
        'UPDATE user_images SET image_url = ? WHERE user_id = ?',
        [profile_image_url, userId],
        (e, r) => {
          if (e) return cb(e);
          if (r.affectedRows > 0) return cb(null);
          db.query(
            'INSERT INTO user_images (user_id, image_url) VALUES (?, ?)',
            [userId, profile_image_url],
            cb
          );
        }
      );
    };

    const upsertAccounts = cb => {
      if (!wantsAccounts) return cb(null);

      const setParts = [];
      const setVals  = [];
      if (!isNil(c_account_number)) { setParts.push('c_account_number = ?'); setVals.push(c_account_number); }
      if (!isNil(s_account_number)) { setParts.push('s_account_number = ?'); setVals.push(s_account_number); }

      // If somehow neither provided, skip
      if (setParts.length === 0) return cb(null);

      db.query(
        `UPDATE accounts SET ${setParts.join(', ')} WHERE user_id = ?`,
        [...setVals, userId],
        (e, r) => {
          if (e) return cb(e);
          if (r.affectedRows > 0) return cb(null);

          // Insert if missing
          const cols = ['user_id'];
          const qs   = ['?'];
          const ivs  = [userId];
          if (!isNil(c_account_number)) { cols.push('c_account_number'); qs.push('?'); ivs.push(c_account_number); }
          if (!isNil(s_account_number)) { cols.push('s_account_number'); qs.push('?'); ivs.push(s_account_number); }

          db.query(
            `INSERT INTO accounts (${cols.join(',')}) VALUES (${qs.join(',')})`,
            ivs,
            cb
          );
        }
      );
    };

    updateUsers(e1 => {
      if (e1) return db.rollback(() => res.status(500).json({ error: 'Database error', details: e1.message }));

      upsertImage(e2 => {
        if (e2) return db.rollback(() => res.status(500).json({ error: 'Database error', details: e2.message }));

        upsertAccounts(e3 => {
          if (e3) return db.rollback(() => res.status(500).json({ error: 'Database error', details: e3.message }));

          db.commit(e4 => {
            if (e4) return db.rollback(() => res.status(500).json({ error: 'Database error', details: e4.message }));

            // Return fresh record
            db.query(SELECT_USER_JOIN, [userId], (e5, rows) => {
              if (e5) return res.status(500).json({ error: 'Database error', details: e5.message });
              if (!rows || rows.length === 0) return res.status(404).json({ error: 'User not found' });
              res.json({ user: rows[0] });
            });
          });
        });
      });
    });
  });
});

// Delete a user and their related records (admin only)
router.delete('/users/:id', authenticateToken, checkAdmin, async (req, res) => {
  const userId = Number(req.params.id) || 0;
  if (!userId) return res.status(400).json({ error: 'Invalid user id' });
  if (userId === Number(req.user.id)) {
    return res.status(400).json({ error: 'You cannot delete your own admin account' });
  }

  const forceAdminDelete = req.body?.confirm_admin_delete === true;

  try {
    const [[target]] = await db.promise().query(
      'SELECT id, username, full_name, email, is_admin FROM users WHERE id = ? LIMIT 1',
      [userId]
    );

    if (!target) return res.status(404).json({ error: 'User not found' });
    if (target.is_admin && !forceAdminDelete) {
      return res.status(400).json({
        error: 'Refusing to delete an admin account without explicit confirmation'
      });
    }

    const conn = db.promise();

    const runOptional = async (sql, params = []) => {
      try {
        await conn.query(sql, params);
      } catch (error) {
        if (error.code === 'ER_NO_SUCH_TABLE' || error.code === 'ER_BAD_FIELD_ERROR') return;
        throw error;
      }
    };

    try {
      await conn.beginTransaction();

      await runOptional(
        'DELETE FROM support_messages WHERE ticket_id IN (SELECT id FROM support_tickets WHERE user_id = ?)',
        [userId]
      );
      await runOptional(
        'DELETE FROM transfer_otps WHERE user_id = ? OR transfer_id IN (SELECT id FROM transfers WHERE user_id = ?)',
        [userId, userId]
      );

      const relatedDeletes = [
        ['DELETE FROM user_images WHERE user_id = ?', [userId]],
        ['DELETE FROM accounts WHERE user_id = ?', [userId]],
        ['DELETE FROM activities WHERE user_id = ?', [userId]],
        ['DELETE FROM otps WHERE user_id = ?', [userId]],
        ['DELETE FROM login_otps WHERE user_id = ?', [userId]],
        ['DELETE FROM password_resets WHERE user_id = ?', [userId]],
        ['DELETE FROM self_transfers WHERE user_id = ?', [userId]],
        ['DELETE FROM atm_cards WHERE user_id = ?', [userId]],
        ['DELETE FROM deposits WHERE user_id = ?', [userId]],
        ['DELETE FROM transfers WHERE user_id = ?', [userId]],
        ['DELETE FROM support_tickets WHERE user_id = ?', [userId]]
      ];

      for (const [sql, params] of relatedDeletes) {
        await runOptional(sql, params);
      }

      const [result] = await conn.query('DELETE FROM users WHERE id = ? LIMIT 1', [userId]);
      if (result.affectedRows === 0) {
        await conn.rollback();
        return res.status(404).json({ error: 'User not found' });
      }

      await conn.commit();

      try {
        await logActivity(
          req.user.id,
          'admin_delete_user',
          `Deleted user #${target.id} (${target.username || target.email})`
        );
      } catch (_) {
        // non-blocking audit failure
      }

      res.json({
        message: 'User deleted successfully',
        deleted_user: {
          id: target.id,
          username: target.username,
          full_name: target.full_name,
          email: target.email
        }
      });
    } catch (error) {
      await conn.rollback();
      throw error;
    }
  } catch (error) {
    console.error('❌ Admin delete user error:', error);
    res.status(500).json({ error: 'Failed to delete user', details: error.message });
  }
});
// ─────────────────────────────────────────────
// Get a specific user by ID (admin view)
// ─────────────────────────────────────────────
router.get('/users/:id', authenticateToken, checkAdmin, (req, res) => {
  const userId = Number(req.params.id) || 0;
  if (!userId) return res.status(400).json({ error: 'Invalid user id' });

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
    LIMIT 1
  `;

  db.query(query, [userId], (err, rows) => {
    if (err) {
      console.error('❌ DB ERROR [/admin/users/:id]:', err);
      return res.status(500).json({ error: 'Database error', details: err.message });
    }
    if (!rows || rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({ user: rows[0] });
  });
});
// update login OTP setting for a user (userId from body)
router.put('/user/login-otp-toggle', authenticateToken, checkAdmin, (req, res) => {
  const { userId, enabled } = req.body; // expects userId and enabled: true/false

  if (!userId || typeof enabled !== 'boolean') {
    return res.status(400).json({ error: 'userId and enabled (true/false) are required' });
  }

  const value = enabled ? 1 : 0;

  db.query('UPDATE users SET login_otp_enabled = ? WHERE id = ?', [value, userId], (err, result) => {
    if (err) return res.status(500).json({ error: 'Failed to update user login OTP setting' });

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ message: `Login OTP for user ${userId} is now ${enabled ? 'enabled' : 'disabled'}` });
  });
});
// 📸 Admin: Upload/Update a user's profile image by user ID
// POST /users/:id/upload-image
router.post('/users/:id/upload-image', authenticateToken, checkAdmin, upload.single('image'), (req, res) => {
  const targetUserId = Number(req.params.id) || 0;
  if (!targetUserId) return res.status(400).json({ error: 'Invalid user id' });
  if (!req.file) return res.status(400).json({ error: 'No image uploaded' });

  const imageUrl = `/uploads/${req.file.filename}`;

  // Ensure the user exists
  db.query('SELECT id FROM users WHERE id = ? LIMIT 1', [targetUserId], (uErr, uRows) => {
    if (uErr) return res.status(500).json({ error: 'DB error', details: uErr.message });
    if (!uRows || uRows.length === 0) return res.status(404).json({ error: 'User not found' });

    // Insert or update profile image
    db.query('SELECT id FROM user_images WHERE user_id = ? LIMIT 1', [targetUserId], (err, results) => {
      if (err) return res.status(500).json({ error: 'DB error', details: err.message });

      if (!results || results.length === 0) {
        // Insert new row
        db.query(
          'INSERT INTO user_images (user_id, image_url) VALUES (?, ?)',
          [targetUserId, imageUrl],
          async (insErr) => {
            if (insErr) return res.status(500).json({ error: 'Failed to save image', details: insErr.message });

            // Log for the target user (and note which admin did it)
            try { await logActivity(targetUserId, 'image_upload', `Admin #${req.user.id} uploaded profile image`); } catch (_) {}
            return res.json({ message: 'Image uploaded successfully', user_id: targetUserId, image_url: imageUrl });
          }
        );
      } else {
        // Update existing
        db.query(
          'UPDATE user_images SET image_url = ? WHERE user_id = ?',
          [imageUrl, targetUserId],
          async (updErr) => {
            if (updErr) return res.status(500).json({ error: 'Failed to update image', details: updErr.message });

            try { await logActivity(targetUserId, 'image_update', `Admin #${req.user.id} updated profile image`); } catch (_) {}
            return res.json({ message: 'Image updated successfully', user_id: targetUserId, image_url: imageUrl });
          }
        );
      }
    });
  });
});

// Update security codes (admin only)
router.put('/security-codes', authenticateToken, checkAdmin, (req, res) => {
  const { imf_code, cot_code, tax_code } = req.body;
  if (!imf_code || !cot_code || !tax_code) {
    return res.status(400).json({ error: 'All codes are required' });
  }

  db.query('SELECT id FROM security_codes LIMIT 1', (err, results) => {
    if (err) return res.status(500).json({ error: 'Database error' });

    if (results.length === 0) {
      // Insert new
      db.query(
        'INSERT INTO security_codes (imf_code, cot_code, tax_code) VALUES (?, ?, ?)',
        [imf_code, cot_code, tax_code],
        (err2) => {
          if (err2) return res.status(500).json({ error: 'Insert failed' });
          res.json({ message: 'Security codes added' });
        }
      );
    } else {
      // Update existing
      const id = results[0].id;
      db.query(
        'UPDATE security_codes SET imf_code = ?, cot_code = ?, tax_code = ? WHERE id = ?',
        [imf_code, cot_code, tax_code, id],
        (err3) => {
          if (err3) return res.status(500).json({ error: 'Update failed' });
          res.json({ message: 'Security codes updated' });
        }
      );
    }
  });
});
// GET /security-codes
router.get('/security-codes', authenticateToken, checkAdmin, (req, res) => {
  db.query(
    'SELECT imf_code, cot_code, tax_code FROM security_codes LIMIT 1',
    (err, rows) => {
      if (err) {
        console.error('❌ DB ERROR [/security-codes]:', err);
        return res.status(500).json({ error: 'Database error', details: err.message });
      }
      if (!rows || rows.length === 0) {
        return res.status(404).json({ error: 'No security codes found' });
      }
      return res.json({ codes: rows[0] });
    }
  );
});

// [POST or PUT] Admin sets transfer fee
router.post('/set-transfer-fee', authenticateToken, checkAdmin, (req, res) => {
  const { type, fee_amount } = req.body;

  if (!type || !['local', 'wire'].includes(type)) {
    return res.status(400).json({ error: 'Invalid transfer type' });
  }

  if (fee_amount === undefined || isNaN(fee_amount)) {
    return res.status(400).json({ error: 'Invalid fee amount' });
  }

  db.query(
    `INSERT INTO transfer_fees (type, fee_amount)
     VALUES (?, ?)
     ON DUPLICATE KEY UPDATE fee_amount = VALUES(fee_amount)`,
    [type, fee_amount],
    (err) => {
      if (err) return res.status(500).json({ error: 'Failed to set fee' });

      res.json({ message: `${type} transfer fee updated to $${parseFloat(fee_amount).toFixed(2)}` });
    }
  );
});
// Get transfer fee(s) (admin only)
router.get('/transfer-fee', authenticateToken, checkAdmin, (req, res) => {
  const { type } = req.query || {};

  // If a specific type is requested
  if (type) {
    if (!['local', 'wire'].includes(type)) {
      return res.status(400).json({ error: 'Invalid transfer type (use local or wire)' });
    }

    db.query(
      'SELECT fee_amount FROM transfer_fees WHERE type = ? LIMIT 1',
      [type],
      (err, rows) => {
        if (err) {
          console.error('❌ DB ERROR [/transfer-fee?type]:', err);
          return res.status(500).json({ error: 'Database error', details: err.message });
        }
        if (!rows || rows.length === 0) {
          return res.status(404).json({ error: `No fee configured for ${type}` });
        }
        const fee = parseFloat(rows[0].fee_amount);
        return res.json({ type, fee_amount: fee });
      }
    );
    return;
  }

  // Otherwise return all (local + wire) that exist
  db.query(
    "SELECT type, fee_amount FROM transfer_fees WHERE type IN ('local','wire')",
    (err, rows) => {
      if (err) {
        console.error('❌ DB ERROR [/transfer-fee]:', err);
        return res.status(500).json({ error: 'Database error', details: err.message });
      }
      if (!rows || rows.length === 0) {
        return res.status(404).json({ error: 'No transfer fees set' });
      }

      const fees = {};
      rows.forEach(r => { fees[r.type] = parseFloat(r.fee_amount); });
      return res.json({ fees });
    }
  );
});
// ✅ Admin updates status of a transfer
router.put('/update-transfer-status/:transferId', authenticateToken, checkAdmin, (req, res) => {
  const { transferId } = req.params;
  const { status } = req.body;

  const validStatuses = ['processing', 'failed', 'completed'];
  if (!validStatuses.includes(status)) {
    return res.status(400).json({ error: 'Invalid status value' });
  }

  db.query(
    'UPDATE transfers SET status = ? WHERE id = ?',
    [status, transferId],
    (err, result) => {
      if (err) return res.status(500).json({ error: 'Failed to update transfer status' });

      if (result.affectedRows === 0) {
        return res.status(404).json({ error: 'Transfer not found' });
      }

      res.json({ message: `Transfer ID ${transferId} status updated to '${status}'` });
    }
  );
});
// 📄 Admin - Get all transfers (local + wire)
router.get('/all-transfers', authenticateToken, checkAdmin, (req, res) => {
  const query = `
    SELECT 
      t.id, 
      t.user_id, 
      u.full_name, 
      u.email, 
      u.currency_sign,
      t.transfer_type, 
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
      t.created_at
    FROM transfers t
    INNER JOIN users u ON t.user_id = u.id
    ORDER BY t.created_at DESC
  `;

  db.query(query, (err, results) => {
    if (err) return res.status(500).json({ error: 'Failed to fetch transfers' });

    // Format amount and fee with currency symbol
    const formattedTransfers = results.map((t) => ({
      id: t.id,
      user_id: t.user_id,
      full_name: t.full_name,
      email: t.email,
      type: t.transfer_type,
      from_account: t.from_account,
      bank_name: t.bank_name,
      account_name: t.account_name,
      account_number: t.account_number,
      bank_country: t.bank_country,
      routine_number: t.routine_number,
      reason: t.reason,
      amount: `${t.currency_sign}${parseFloat(t.amount).toFixed(2)}`,
      fee: `${t.currency_sign}${parseFloat(t.fee).toFixed(2)}`,
      status: t.status,
      date: moment(t.created_at).format('YYYY-MM-DD HH:mm:ss')
    }));

    res.json({ transfers: formattedTransfers });
  });
});


// Admin sets ATM card fee
router.post('/set-card-fee', authenticateToken, checkAdmin, (req, res) => {
  const { account_type, fee } = req.body;

  if (!['savings', 'current'].includes(account_type) || isNaN(fee)) {
    return res.status(400).json({ error: 'Invalid request' });
  }

  db.query(
    `INSERT INTO card_fees (account_type, fee)
     VALUES (?, ?)
     ON DUPLICATE KEY UPDATE fee = VALUES(fee)`,
    [account_type, fee],
    (err) => {
      if (err) return res.status(500).json({ error: 'Fee update failed' });
      res.json({ message: `ATM card fee set for ${account_type} account: $${fee}` });
    }
  );
});
// Get ATM card fee(s) (admin only)
router.get('/card-fee', authenticateToken, checkAdmin, (req, res) => {
  const { account_type } = req.query || {};

  if (account_type) {
    if (!['savings', 'current'].includes(account_type)) {
      return res.status(400).json({ error: 'Invalid account_type (use savings or current)' });
    }

    db.query(
      'SELECT fee FROM card_fees WHERE account_type = ? LIMIT 1',
      [account_type],
      (err, rows) => {
        if (err) {
          console.error('❌ DB ERROR [/card-fee?account_type]:', err);
          return res.status(500).json({ error: 'Database error', details: err.message });
        }
        if (!rows || rows.length === 0) {
          return res.status(404).json({ error: `No fee configured for ${account_type}` });
        }
        const fee = parseFloat(rows[0].fee);
        return res.json({ account_type, fee });
      }
    );
    return;
  }

  // return all available (savings/current)
  db.query(
    "SELECT account_type, fee FROM card_fees WHERE account_type IN ('savings','current')",
    (err, rows) => {
      if (err) {
        console.error('❌ DB ERROR [/card-fee]:', err);
        return res.status(500).json({ error: 'Database error', details: err.message });
      }
      if (!rows || rows.length === 0) {
        return res.status(404).json({ error: 'No card fees set' });
      }
      const fees = {};
      rows.forEach(r => { fees[r.account_type] = parseFloat(r.fee); });
      return res.json({ fees });
    }
  );
});
// ✅ Admin approves an ATM card
router.put('/atm-cards/:cardId/approve', authenticateToken, checkAdmin, async (req, res) => {
  const { cardId } = req.params;

  try {
    // 1) Fetch card + user
    const [rows] = await db.promise().query(
      `SELECT c.id, c.user_id, c.account_type, c.card_number, c.card_holder_name, c.expiry_date, c.cvv, c.status,
              u.email, u.full_name, u.currency_sign
       FROM atm_cards c
       JOIN users u ON u.id = c.user_id
       WHERE c.id = ?`,
      [cardId]
    );
    if (!rows.length) return res.status(404).json({ error: 'Card not found' });

    const card = rows[0];
    if (card.status === 'approved') {
      return res.status(400).json({ error: 'Card already approved' });
    }

    // 2) Approve
    await db.promise().query(`UPDATE atm_cards SET status = 'approved' WHERE id = ?`, [cardId]);

    // 3) Log activity
    await logActivity(
      card.user_id,
      'atm_card_approved',
      `ATM card approved for ${card.account_type} account`
    );

    // 4) Send fancy email (glass card)
    await sendAtmCardApprovedEmail({
      to: card.email,
      bankCustomerName: card.full_name,
      accountType: card.account_type,
      cardNumberMasked: maskCardNumber(card.card_number),   // •••• •••• •••• 1234
      cardNumberGrouped: formatCardGroups(card.card_number),// 5456 3278 9012 3456
      expiryDate: card.expiry_date,
      // never email a CVV in real life; we’ll mask it for safety
      cvvMasked: '***',
      currency: card.currency_sign || '$'
    });

    res.json({ message: 'ATM card approved and email sent to user.' });
  } catch (err) {
    console.error('Approve ATM card error:', err);
    res.status(500).json({ error: 'Failed to approve ATM card' });
  }
});
// 📄 Admin - Get All ATM Card Requests (uses requested_at)
router.get('/atm-cards', authenticateToken, checkAdmin, async (req, res) => {
  try {
    const [rows] = await db.promise().query(`
      SELECT 
        c.id, 
        c.user_id, 
        u.full_name, 
        u.email,
        u.currency_sign,
        c.account_type, 
        c.card_number, 
        c.card_holder_name, 
        c.expiry_date, 
        c.cvv, 
        c.fee, 
        c.status, 
        c.requested_at
      FROM atm_cards c
      JOIN users u ON u.id = c.user_id
      ORDER BY c.requested_at DESC
    `);

    const formatted = rows.map(card => ({
      id: card.id,
      user_id: card.user_id,
      full_name: card.full_name,
      email: card.email,
      account_type: card.account_type,
      card_number: card.card_number,
      card_holder_name: card.card_holder_name,
      expiry_date: card.expiry_date,
      cvv: card.cvv,
      fee: `${card.currency_sign}${parseFloat(card.fee).toFixed(2)}`,
      status: card.status,
      created_at: card.requested_at ? moment(card.requested_at).format('YYYY-MM-DD HH:mm:ss') : null,
      updated_at: null // not tracked in current schema
    }));

    res.json({ atm_cards: formatted });

  } catch (error) {
    console.error('❌ Failed to fetch ATM cards:', error);
    res.status(500).json({ error: 'Failed to fetch ATM cards' });
  }
});
// 📄 Admin - Delete a User's ATM Card
router.delete('/atm-cards/:id', authenticateToken, checkAdmin, async (req, res) => {
  const { id } = req.params;

  try {
    // 1. Check if card exists
    const [card] = await db.promise().query(
      'SELECT * FROM atm_cards WHERE id = ?',
      [id]
    );

    if (!card.length) {
      return res.status(404).json({ error: 'ATM card not found' });
    }

    // 2. Delete the card
    await db.promise().query(
      'DELETE FROM atm_cards WHERE id = ?',
      [id]
    );

    res.json({ message: 'ATM card deleted successfully' });

  } catch (error) {
    console.error('❌ Failed to delete ATM card:', error);
    res.status(500).json({ error: 'Failed to delete ATM card' });
  }
});

// POST /users/:user_id/simulate/transactions  (admin only)
router.post('/users/:user_id/simulate/transactions', authenticateToken, checkAdmin, async (req, res) => {
  try {
    const userId = Number(req.params.user_id) || 0;
    if (!userId) return res.status(400).json({ error: 'Invalid user_id' });

    const {
      transfer_type = 'local',      // 'local' | 'wire'
      direction,                    // 'credit' | 'debit' (required)
      amount,                       // total across entries (required)
      from_account = 'current',     // 'current' | 'savings'
      start_date, end_date,
      mode = 'single', count,
      apply_to_balance = false,

      // Optional overrides for local/wire fields
      bank_name, account_name, account_number, reason,
      bank_country, routine_number, imf_code, cot_code, tax_code
    } = req.body || {};

    if (!['local','wire'].includes(transfer_type)) return res.status(400).json({ error: 'transfer_type must be "local" or "wire"' });
    if (!direction || isNil(amount) || !start_date) return res.status(400).json({ error: 'direction, amount, start_date are required' });
    if (!['credit','debit'].includes(direction)) return res.status(400).json({ error: 'direction must be "credit" or "debit"' });
    if (!['current','savings'].includes(from_account)) return res.status(400).json({ error: 'from_account must be "current" or "savings"' });

    // window
    const start = ymdToDate(start_date);
    if (!start) return res.status(400).json({ error: 'Invalid start_date (YYYY-MM-DD)' });
    let end = end_date ? ymdToDate(end_date) : start;
    if (!end) return res.status(400).json({ error: 'Invalid end_date (YYYY-MM-DD)' });
    if (end < start) end = start;

    // timestamps
    let entries = 1;
    let stamps = [fmt(start)];
    if (mode === 'daily') {
      entries = daysIncl(start, end);
      stamps = Array.from({ length: entries }, (_, i) => { const d=new Date(start); d.setUTCDate(start.getUTCDate()+i); return fmt(d); });
    } else if (mode === 'count') {
      const c = clamp(parseInt(count || 0, 10), 1, 365);
      entries = c;
      if (entries === 1) stamps = [fmt(start)];
      else {
        const span = end.getTime() - start.getTime();
        stamps = Array.from({ length: entries }, (_, i) => fmt(new Date(start.getTime() + Math.round((span*i)/(entries-1)))));
      }
    }

    // amounts
    const totalAmount = Number(amount);
    if (!Number.isFinite(totalAmount) || totalAmount <= 0) return res.status(400).json({ error: 'amount must be a positive number' });
    const per = Math.floor((totalAmount / entries) * 100) / 100;
    const rows = []; let acc = 0;
    for (let i=0;i<entries;i++){ const part=(i===entries-1)?Number((totalAmount-acc).toFixed(2)):per; acc=Number((acc+part).toFixed(2)); rows.push({ ts: stamps[i], amt: part }); }

    // user
    const [[user]] = await db.promise().query('SELECT id, currency_sign FROM users WHERE id = ? LIMIT 1', [userId]);
    if (!user) return res.status(404).json({ error: 'User not found' });

    // fee per type
    const [[feeRow]] = await db.promise().query('SELECT fee_amount FROM transfer_fees WHERE type = ? LIMIT 1', [transfer_type]);
    const feePerRow = Number(feeRow?.fee_amount || 0);
    const effectiveFee = (direction === 'debit') ? feePerRow : 0; // credits => fee 0

    // random defaults (US-centric)
    const _bank_name      = bank_name      || pick(BANKS);
    const _account_name   = account_name   || pickBeneficiary();
    const _account_number = account_number || randDigits(10);
    const _reason         = reason         || pick(REASONS);

    const defaultCountry  = 'United States';
    const _bank_country   = bank_country   || (transfer_type === 'wire' ? defaultCountry : defaultCountry);
    const _routing        = routine_number || (_bank_country === 'United States' ? genAbaRouting() : randDigits(Math.floor(Math.random()*5)+8));
    const _imf            = imf_code       || `IMF-${randDigits(6)}`;
    const _cot            = cot_code       || `COT-${randDigits(6)}`;
    const _tax            = tax_code       || `TAX-${randDigits(6)}`;

    const simBatch = (typeof crypto.randomUUID === 'function') ? crypto.randomUUID() : crypto.randomBytes(16).toString('hex');

    // single-connection transaction using your `db` (no pool)
    const conn = db.promise();
    try {
      await conn.beginTransaction();

      // optional net balance impact once
      const net = rows.reduce((sum, r) => sum + (direction === 'credit' ? r.amt : -(r.amt + effectiveFee)), 0);
      if (apply_to_balance && net !== 0) {
        const col = from_account === 'savings' ? 'savings_balance' : 'current_balance';
        const [[bal]] = await conn.query(`SELECT ${col} AS bal FROM users WHERE id = ? FOR UPDATE`, [userId]);
        const current = parseFloat(bal?.bal || 0);
        const next = Number((current + net).toFixed(2));
        await conn.query(`UPDATE users SET ${col} = ? WHERE id = ?`, [next, userId]);
      }

      // inserts
      for (const r of rows) {
        if (transfer_type === 'local') {
          await conn.query(
            `INSERT INTO transfers
             (user_id, transfer_type, from_account, bank_name, account_name, account_number, reason,
              amount, fee, entry_type, status, is_simulated, sim_batch_id, created_at)
             VALUES (?, 'local', ?, ?, ?, ?, ?, ?, ?, ?, 'completed', 1, ?, ?)`,
            [userId, from_account, _bank_name, _account_name, _account_number, _reason,
             r.amt, effectiveFee, direction, simBatch, r.ts]
          );
        } else {
          await conn.query(
            `INSERT INTO transfers
             (user_id, transfer_type, from_account, bank_name, account_name, account_number, bank_country, routine_number,
              reason, imf_code, cot_code, tax_code, amount, fee, entry_type, status, is_simulated, sim_batch_id, created_at)
             VALUES (?, 'wire', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'completed', 1, ?, ?)`,
            [userId, from_account, _bank_name, _account_name, _account_number, _bank_country, _routing,
             _reason, _imf, _cot, _tax, r.amt, effectiveFee, direction, simBatch, r.ts]
          );
        }
      }

      await conn.commit();
    } catch (e) {
      await conn.rollback();
      throw e;
    }

    res.json({
      ok: true,
      user_id: userId,
      sim_batch_id: simBatch,
      transfer_type, direction, from_account,
      total_entries: entries,
      total_amount: totalAmount,
      per_entry_fee: effectiveFee,
      applied_to_balance: !!apply_to_balance,
      window: { start: start_date, end: end_date || start_date }
    });
  } catch (err) {
    console.error('❌ simulate error:', err);
    res.status(500).json({ error: 'Simulation failed', details: err.message });
  }
});

// ---------- Random data sources (US + major international; no Nigeria) ----------
const BANKS = [
  'JPMorgan Chase','Bank of America','Wells Fargo','Citibank','U.S. Bank',
  'Capital One','PNC Bank','TD Bank','Truist Bank','Fifth Third Bank',
  'KeyBank','BMO Harris Bank','Regions Bank','Charles Schwab Bank',
  'Goldman Sachs Bank USA','Morgan Stanley Private Bank','Ally Bank',
  'Barclays','HSBC','Deutsche Bank','UBS','BNP Paribas','Santander',
  'Societe Generale','Standard Chartered','ING','Rabobank',
  'Royal Bank of Canada','Scotiabank','Commonwealth Bank of Australia',
  'ANZ','National Australia Bank','Mizuho Bank','MUFG Bank','SMBC','DBS Bank','OCBC'
];

const PERSONS_US = [
  'Olivia Martinez','Liam Johnson','Ava Brown','Noah Williams','Isabella Davis',
  'James Anderson','Sophia Miller','Benjamin Wilson','Mia Taylor','Elijah Moore',
  'Charlotte Thomas','William Jackson','Amelia White','Michael Harris','Harper Martin',
  'Ethan Thompson','Evelyn Garcia','Alexander Clark','Abigail Lewis','Daniel Robinson'
];

const COMPANIES = [
  'Acme Logistics LLC','BlueSky Consulting LLC','Northstar Holdings Inc.',
  'Evergreen Supplies Co.','Sunrise Media Group LLC','Westbridge Construction Co.',
  'Pioneer Healthcare PLLC','Silverline Tech Solutions Inc.','Harborview Imports Ltd.',
  'Lakeside Ventures LP','Redwood Real Estate Partners LLC','Summit Legal Services PLLC',
  'GreenLeaf Foods Co.','Velocity Marketing Group LLC','Atlas Freight & Shipping LLC',
  'Crescent Financial Advisors LLC','Beacon Education Services Inc.',
  'Prime Automotive Parts LLC','Clearwater Cleaners Inc.','Riverton Design Studio LLC'
];

const REASONS = [
  'Payroll','Salary Payment','Invoice Payment','Consulting Services','Subscription Renewal',
  'Loan Repayment','Rent','Utilities','Reimbursement','Refund','Gift',
  'Savings Transfer','Card Settlement','Bill Payment','Bonus','Dividend',
  'Supplier Payment','Expense Reimbursement','Tuition','Insurance Premium'
];

const COUNTRIES = [
  'United States','United Kingdom','Canada','Germany','France','Netherlands',
  'Switzerland','Spain','Italy','Ireland','Australia','New Zealand',
  'Singapore','Japan','United Arab Emirates','Sweden','Norway','Denmark'
];

// POST /users/:user_id/transactions/sim-refresh   (admin only, update-only)
// Uses BANKS / PERSONS_US / COMPANIES / REASONS / COUNTRIES to refresh data.
// Keeps the same bank; changes account_name + account_number per bank per day.
// Also normalizes bank casing; fills wire extras if asked.

router.post('/users/:user_id/transactions/sim-refresh',
  authenticateToken,
  checkAdmin,
  async (req, res) => {
    const userId = Number(req.params.user_id) || 0;
    if (!userId) return res.status(400).json({ error: 'Invalid user_id' });

    // Config (all optional)
    const {
      scope = 'day',                  // 'day' | 'exact' | 'row'  (bucket to assign identities)
      nameset = 'mix',               // 'person' | 'company' | 'mix'
      update_reason = false,         // fill reason if empty
      fill_wire_extras = true,       // set bank_country & routine_number on wire rows
      preserve_existing = true,      // overwrite only if bucket mostly duplicates
      min_bank_count = 1,            // only banks with at least N rows
      dry_run = false
    } = req.body || {};

    // ---------- Data & helpers ----------
    const F_PERSONS   = (typeof PERSONS_US !== 'undefined' && Array.isArray(PERSONS_US) && PERSONS_US.length) ? PERSONS_US
                        : ['John Doe','Ava Brown','Michael Harris','Alexander Clark'];
    const F_COMPANIES = (typeof COMPANIES !== 'undefined' && Array.isArray(COMPANIES) && COMPANIES.length) ? COMPANIES
                        : ['Northstar Holdings Inc.','Acme Logistics LLC','BlueSky Consulting LLC'];
    const F_REASONS   = (typeof REASONS !== 'undefined' && Array.isArray(REASONS) && REASONS.length) ? REASONS
                        : ['Invoice Payment','Savings Transfer','Payroll'];
    const F_COUNTRIES = (typeof COUNTRIES !== 'undefined' && Array.isArray(COUNTRIES) && COUNTRIES.length) ? COUNTRIES
                        : ['United States','United Kingdom','Canada','Germany','France','Singapore','Japan'];

    // Common acronyms stay uppercase; a few special cases
    const ACRONYMS = new Set(['UBS','HSBC','BNP','PNC','ANZ','SMBC','DBS','OCBC','ING','RBC','NAB','MUFG','UBA','GTB']);
    const toTitle = s => s == null ? null
      : String(s).toLowerCase().replace(/(^|\s|-|’|'|,|\.)[a-z]/g, m => m.toUpperCase()).replace(/\s+/g, ' ').trim();
    const normalizeBankName = (name) => {
      if (!name) return name;
      const t = toTitle(name);
      const compact = t.replace(/[^A-Za-z]/g,'').toUpperCase();
      if (ACRONYMS.has(compact)) return compact;                   // UBS, HSBC, etc
      if (/^U\.?S\.?\s*Bank$/i.test(t)) return 'U.S. Bank';        // special-case formatting
      return t;
    };
    const pick   = arr => arr[Math.floor(Math.random()*arr.length)];
    const digits = n => Array.from({length:n}, () => Math.floor(Math.random()*10)).join('');
    const randAccount = () => digits(10);
    const clean  = v => v == null ? null : String(v).trim();
    const nonEmpty = v => v != null && String(v).trim() !== '';
    const chunkIds = (ids, size=500) => { const out=[]; for(let i=0;i<ids.length;i+=size) out.push(ids.slice(i,i+size)); return out; };

    // name generator
    const newName = () => {
      if (nameset === 'person')  return pick(F_PERSONS);
      if (nameset === 'company') return pick(F_COMPANIES);
      return Math.random() < 0.55 ? pick(F_PERSONS) : pick(F_COMPANIES);
    };

    // bank -> country defaults (fall back to COUNTRIES[0] if unknown)
    const BANK_COUNTRY = {
      'JPMorgan Chase': 'United States',
      'Bank of America': 'United States',
      'Wells Fargo': 'United States',
      'Citibank': 'United States',
      'U.S. Bank': 'United States',
      'Capital One': 'United States',
      'PNC Bank': 'United States',
      'TD Bank': 'United States',
      'Truist Bank': 'United States',
      'Fifth Third Bank': 'United States',
      'KeyBank': 'United States',
      'BMO Harris Bank': 'United States',
      'Regions Bank': 'United States',
      'Charles Schwab Bank': 'United States',
      'Goldman Sachs Bank USA': 'United States',
      'Morgan Stanley Private Bank': 'United States',
      'Ally Bank': 'United States',
      'Barclays': 'United Kingdom',
      'HSBC': 'United Kingdom',
      'Deutsche Bank': 'Germany',
      'UBS': 'Switzerland',
      'BNP Paribas': 'France',
      'Santander': 'Spain',
      'Societe Generale': 'France',
      'Standard Chartered': 'United Kingdom',
      'ING': 'Netherlands',
      'Rabobank': 'Netherlands',
      'Royal Bank of Canada': 'Canada',
      'Scotiabank': 'Canada',
      'Commonwealth Bank of Australia': 'Australia',
      'ANZ': 'Australia',
      'National Australia Bank': 'Australia',
      'Mizuho Bank': 'Japan',
      'MUFG Bank': 'Japan',
      'SMBC': 'Japan',
      'DBS Bank': 'Singapore',
      'OCBC': 'Singapore'
    };

    // routing (ABA 9-digit for US; 8–12 digits for intl)
    const genRouting = (country) => {
      if ((country || '').toLowerCase().includes('united states')) return digits(9);
      return digits(8 + Math.floor(Math.random()*5)); // 8..12
    };

    // bucket expr
    const bucketExpr = scope === 'exact' ? 'created_at'
                      : scope === 'row'  ? 'id'
                      : 'DATE(created_at)'; // default 'day'

    const conn = db.promise();

    try {
      await conn.beginTransaction();

      // A) Get all banks for this user that meet threshold
      const [banks] = await conn.query(
        `SELECT bank_name, COUNT(*) AS cnt
         FROM transfers
         WHERE user_id = ? AND bank_name IS NOT NULL AND TRIM(bank_name) <> ''
         GROUP BY bank_name
         HAVING cnt >= ?`,
        [userId, Math.max(1, Number(min_bank_count) || 1)]
      );

      // If nothing to do, exit early
      if (!banks.length) {
        await conn.rollback();
        return res.json({ ok: true, user_id: userId, total_banks: 0, rows_updated: 0, samples: [], dry_run: !!dry_run });
      }

      let totalRowsUpdated = 0;
      const samples = [];

      for (const b of banks) {
        const prettyBank = normalizeBankName(b.bank_name);

        // B) Split rows of this bank into buckets (by day/exact/row)
        const [bins] = await conn.query(
          `SELECT ${bucketExpr} AS bucket, GROUP_CONCAT(id) AS ids, COUNT(*) AS cnt
           FROM transfers
           WHERE user_id = ? AND bank_name = ?
           GROUP BY bucket
           ORDER BY bucket ASC`,
          [userId, b.bank_name]
        );

        // For uniqueness per bank run
        const usedAccts = new Set();

        for (const bin of bins) {
          // C) If preserve_existing, only refresh if the bucket is mostly the same identity (name+acct)
          let shouldUpdate = true;
          if (preserve_existing) {
            const [topRows] = await conn.query(
              `SELECT LOWER(TRIM(account_name)) AS nm, REPLACE(REPLACE(account_number,' ',''),'-','') AS acct, COUNT(*) AS c
               FROM transfers
               WHERE user_id=? AND bank_name=? AND ${bucketExpr} = ?
               GROUP BY nm, acct
               ORDER BY c DESC LIMIT 1`,
              [userId, b.bank_name, bin.bucket]
            );
            const top = topRows && topRows[0];
            shouldUpdate = !!top && Number(top.c || 0) >= Math.ceil(Number(bin.cnt || 1) / 2);
          }
          if (!shouldUpdate) continue;

          // D) New identity for this bucket
          const name = newName();
          let acct = randAccount();
          while (usedAccts.has(acct)) acct = randAccount();
          usedAccts.add(acct);

          const ids = String(bin.ids || '').split(',').map(s => Number(s)).filter(Boolean);
          if (!ids.length) continue;

          // E) Build UPDATE parts
          const updates = [name, acct, prettyBank];
          let extraSql = '';
          if (update_reason) {
            extraSql += ', reason = IFNULL(NULLIF(TRIM(reason), \'\'), ?)';
            updates.push(pick(F_REASONS));
          }

          // Wire extras? (bank_country, routine_number)
          // To avoid clobbering intentional values, only set when empty or NULL
          if (fill_wire_extras) {
            const country = BANK_COUNTRY[prettyBank] || F_COUNTRIES[0] || 'United States';
            extraSql += `, bank_country = IFNULL(NULLIF(TRIM(bank_country), ''), ?)
                         , routine_number = IFNULL(NULLIF(TRIM(routine_number), ''), ?)`;
            updates.push(country, genRouting(country));
          }

          // F) Update by ID chunks (safer & faster)
          for (const chunk of chunkIds(ids)) {
            const [u] = await conn.query(
              `UPDATE transfers
               SET account_name = ?, account_number = ?, bank_name = ?
                   ${extraSql}
               WHERE user_id = ? AND id IN (${chunk.map(()=>' ?').join(',')})`,
              [...updates, userId, ...chunk]
            );
            totalRowsUpdated += (u.changedRows ?? u.affectedRows ?? 0);
          }

          if (samples.length < 20) {
            samples.push({
              bank: prettyBank,
              bucket: String(bin.bucket),
              rows_updated: ids.length,
              new_name: name,
              new_account_number: acct
            });
          }
        }
      }

      if (dry_run) await conn.rollback();
      else await conn.commit();

      res.json({
        ok: true,
        user_id: userId,
        total_banks: banks.length,
        rows_updated: totalRowsUpdated,
        samples,
        scope,
        nameset,
        update_reason: !!update_reason,
        fill_wire_extras: !!fill_wire_extras,
        preserve_existing: !!preserve_existing,
        dry_run: !!dry_run
      });
    } catch (e) {
      try { await conn.rollback(); } catch {}
      console.error('sim-refresh error:', e);
      res.status(500).json({ error: 'sim_refresh_failed', detail: String(e.message || e) });
    }
  }
);




// GET /users/:id/history/local
router.get('/users/:id/history/local', authenticateToken, checkAdmin, async (req, res) => {
  try {
    const userId = Number(req.params.id) || 0;
    if (!userId) return res.status(400).json({ error: 'Invalid user id' });

    const [rows] = await db.promise().query(
      `
      SELECT t.id, t.transfer_type, t.from_account, t.bank_name, t.account_name, t.account_number,
             t.reason, t.amount, t.fee, t.status,
             DATE_FORMAT(t.created_at, '%Y-%m-%d %H:%i:%s') AS created_at_fmt,
             u.currency_sign
      FROM transfers t
      JOIN users u ON t.user_id = u.id
      WHERE t.user_id = ? AND t.transfer_type = 'local'
      ORDER BY t.created_at DESC
      LIMIT 50
      `,
      [userId]
    );

    const formatted = rows.map(t => ({
      id: t.id,
      type: t.transfer_type,
      from_account: t.from_account,
      bank_name: t.bank_name,
      account_name: t.account_name,
      account_number: t.account_number,
      reason: t.reason,
      amount: `${t.currency_sign}${parseFloat(t.amount).toFixed(2)}`,
      fee: `${t.currency_sign}${parseFloat(t.fee).toFixed(2)}`,
      status: t.status,
      date: t.created_at_fmt
    }));

    res.json({ history: formatted });
  } catch (e) {
    console.error('❌ admin local history error:', e);
    res.status(500).json({ error: 'Failed to fetch local transfer history' });
  }
});
// GET /users/:id/history/wire
router.get('/users/:id/history/wire', authenticateToken, checkAdmin, async (req, res) => {
  try {
    const userId = Number(req.params.id) || 0;
    if (!userId) return res.status(400).json({ error: 'Invalid user id' });

    const [rows] = await db.promise().query(
      `
      SELECT t.id, t.from_account, t.bank_name, t.account_name, t.account_number,
             t.bank_country, t.routine_number, t.reason, t.amount, t.fee, t.status,
             DATE_FORMAT(t.created_at, '%Y-%m-%d %H:%i:%s') AS created_at_fmt,
             u.currency_sign
      FROM transfers t
      JOIN users u ON t.user_id = u.id
      WHERE t.user_id = ? AND t.transfer_type = 'wire'
      ORDER BY t.created_at DESC
      LIMIT 50
      `,
      [userId]
    );

    const result = rows.map(row => ({
      id: row.id,
      type: 'wire',
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
      date: row.created_at_fmt
    }));

    res.json({ wire_history: result });
  } catch (e) {
    console.error('❌ admin wire history error:', e);
    res.status(500).json({ error: 'Failed to fetch wire transfer history' });
  }
});
// UPDATE transfer (admin only) - can update everything incl. created_at
router.put("/transfers/:id", authenticateToken, checkAdmin, async (req, res) => {
  try {
    const transferId = Number(req.params.id) || 0;
    if (!transferId) return res.status(400).json({ error: "Invalid transfer id" });

    // Allowed fields admin can update
    // NOTE: "date" maps to created_at so admin can edit date/time
    const allowed = new Set([
      "transfer_type",
      "from_account",
      "bank_name",
      "account_name",
      "account_number",
      "bank_country",
      "routine_number",
      "reason",
      "amount",
      "fee",
      "status",
      "date" // maps to created_at
    ]);

    // Only pick fields from body that are allowed
    const body = req.body || {};
    const update = {};

    for (const key of Object.keys(body)) {
      if (!allowed.has(key)) continue;

      // map date -> created_at
      if (key === "date") {
        update.created_at = String(body.date || "").trim();
      } else {
        update[key] = body[key];
      }
    }

    if (!Object.keys(update).length) {
      return res.status(400).json({ error: "No valid fields provided to update." });
    }

    // Basic validation for created_at format if provided
    // expected: "YYYY-MM-DD HH:mm:ss"
    if (update.created_at) {
      const isValid = /^\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}$/.test(update.created_at);
      if (!isValid) {
        return res.status(400).json({
          error: 'Invalid "date" format. Use "YYYY-MM-DD HH:mm:ss" (e.g., "2026-01-05 12:38:00").'
        });
      }
    }

    // If amount/fee provided, validate numeric
    if (update.amount !== undefined) {
      const n = Number(update.amount);
      if (Number.isNaN(n) || n < 0) return res.status(400).json({ error: "Invalid amount" });
      update.amount = n;
    }

    if (update.fee !== undefined) {
      const n = Number(update.fee);
      if (Number.isNaN(n) || n < 0) return res.status(400).json({ error: "Invalid fee" });
      update.fee = n;
    }

    // Build dynamic SQL
    const setParts = [];
    const values = [];

    for (const [k, v] of Object.entries(update)) {
      setParts.push(`${k} = ?`);
      values.push(v);
    }

    values.push(transferId);

    // Make sure transfer exists
    const [exists] = await db.promise().query(
      `SELECT id FROM transfers WHERE id = ? LIMIT 1`,
      [transferId]
    );
    if (!exists.length) return res.status(404).json({ error: "Transfer not found" });

    const sql = `UPDATE transfers SET ${setParts.join(", ")} WHERE id = ? LIMIT 1`;
    await db.promise().query(sql, values);

    // Return updated row (useful for confirming date/time edits)
    const [updated] = await db.promise().query(
      `
      SELECT id, user_id, transfer_type, from_account, bank_name, account_name, account_number,
             bank_country, routine_number, reason, amount, fee, status,
             DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s') AS created_at_fmt
      FROM transfers
      WHERE id = ?
      LIMIT 1
      `,
      [transferId]
    );

    return res.json({ message: "Transfer updated successfully", transfer: updated[0] });
  } catch (e) {
    console.error("❌ admin transfer update error:", e);
    res.status(500).json({ error: "Failed to update transfer" });
  }
});


// 💰 Admin — Add Wallet Address & QR
router.post('/wallets', authenticateToken, checkAdmin, walletUpload.single('qrcode'), async (req, res) => {
  const { wallet_name, wallet_address } = req.body;

    if (!wallet_name || !wallet_address || !req.file) {
      return res.status(400).json({ error: 'Wallet name, address, and QR code image are required' });
    }

    try {
      const qrcodePath = `uploads/${req.file.filename}`;

      await db.promise().query(
        `INSERT INTO wallets (wallet_name, wallet_address, qrcode_path) VALUES (?, ?, ?)`,
        [wallet_name, wallet_address, qrcodePath]
      );

      res.json({
        message: 'Wallet added successfully',
        data: {
          wallet_name,
          wallet_address,
          qrcode_url: qrcodePath
        }
      });
    } catch (error) {
      console.error('❌ Wallet upload error:', error);
      res.status(500).json({ error: 'Failed to save wallet details' });
    }
  }
);
// 🪙 GET all wallets (QR code URLs use server base URL)
router.get('/wallets', authenticateToken, checkAdmin, async (req, res) => {
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
// ✏️ UPDATE a wallet (name/address and optionally QR)
router.put('/wallets/:id', authenticateToken, checkAdmin, walletUpload.single('qrcode'), async (req, res) => {
  const { id } = req.params;
  const { wallet_name, wallet_address } = req.body;

  try {
    // Check if wallet exists
    const [[existing]] = await db.promise().query('SELECT * FROM wallets WHERE id = ?', [id]);
    if (!existing) {
      return res.status(404).json({ error: 'Wallet not found' });
    }

    let qrcodePath = existing.qrcode_path;

    // If new QR uploaded, replace the old one
    if (req.file) {
      const newPath = `uploads/${req.file.filename}`;

      // Delete old file if exists
      if (existing.qrcode_path && fs.existsSync(existing.qrcode_path)) {
        fs.unlinkSync(existing.qrcode_path);
      }

      qrcodePath = newPath;
    }

    await db.promise().query(
      'UPDATE wallets SET wallet_name = ?, wallet_address = ?, qrcode_path = ? WHERE id = ?',
      [wallet_name || existing.wallet_name, wallet_address || existing.wallet_address, qrcodePath, id]
    );

    const baseUrl = `${req.protocol}://${req.get('host')}`;
    res.json({
      message: 'Wallet updated successfully',
      data: {
        id,
        wallet_name: wallet_name || existing.wallet_name,
        wallet_address: wallet_address || existing.wallet_address,
        qrcode_url: `${baseUrl}/${qrcodePath}`
      }
    });
  } catch (error) {
    console.error('❌ Update wallet error:', error);
    res.status(500).json({ error: 'Failed to update wallet' });
  }
});
// ❌ DELETE a wallet
router.delete('/wallets/:id', authenticateToken, checkAdmin, async (req, res) => {
  const { id } = req.params;

  try {
    // Check if wallet exists
    const [[existing]] = await db.promise().query('SELECT * FROM wallets WHERE id = ?', [id]);
    if (!existing) {
      return res.status(404).json({ error: 'Wallet not found' });
    }

    // Delete image file if exists
    if (existing.qrcode_path && fs.existsSync(existing.qrcode_path)) {
      fs.unlinkSync(existing.qrcode_path);
    }

    await db.promise().query('DELETE FROM wallets WHERE id = ?', [id]);

    res.json({ message: 'Wallet deleted successfully' });
  } catch (error) {
    console.error('❌ Delete wallet error:', error);
    res.status(500).json({ error: 'Failed to delete wallet' });
  }
});


// 📋 GET ALL TICKETS
router.get('/tickets', authenticateToken, checkAdmin, async (req, res) => {
  try {
    const [tickets] = await db.promise().query(
      `
      SELECT 
        st.*,
        u.username AS user_username
      FROM support_tickets st
      LEFT JOIN users u ON st.user_id = u.id
      ORDER BY st.created_at DESC
      `
    );

    res.json(tickets);
  } catch (error) {
    console.error('❌ Error fetching tickets:', error);
    res.status(500).json({ error: 'Server error fetching tickets' });
  }
});
// 💬 ADMIN REPLY
router.post('/tickets/:ticket_id/reply', authenticateToken, checkAdmin, async (req, res) => {
  const { ticket_id } = req.params;
  const { message } = req.body;

  if (!message) return res.status(400).json({ error: 'Message is required' });

  try {
    const [[ticket]] = await db.promise().query(
      'SELECT * FROM support_tickets WHERE id = ?',
      [ticket_id]
    );

    if (!ticket) return res.status(404).json({ error: 'Ticket not found' });

    await db.promise().query(
      `INSERT INTO support_messages (ticket_id, sender, message, created_at) VALUES (?, 'admin', ?, ?)`,
      [ticket_id, message, moment().format('YYYY-MM-DD HH:mm:ss')]
    );

    res.json({ message: 'Reply sent successfully' });
  } catch (error) {
    console.error('❌ Error replying to ticket:', error);
    res.status(500).json({ error: 'Server error sending reply' });
  }
});
// ✅ CLOSE TICKET
router.put('/tickets/:ticket_id/close', authenticateToken, checkAdmin, async (req, res) => {
  const { ticket_id } = req.params;

  try {
    const [[ticket]] = await db.promise().query(
      'SELECT * FROM support_tickets WHERE id = ?',
      [ticket_id]
    );

    if (!ticket) return res.status(404).json({ error: 'Ticket not found' });

    await db.promise().query(
      'UPDATE support_tickets SET status = "closed" WHERE id = ?',
      [ticket_id]
    );

    res.json({ message: 'Ticket closed successfully' });
  } catch (error) {
    console.error('❌ Error closing ticket:', error);
    res.status(500).json({ error: 'Server error closing ticket' });
  }
});
// 📜 GET all messages for a specific ticket (Admin) + usernames
router.get('/tickets/:ticket_id/messages', authenticateToken, checkAdmin, async (req, res) => {
  const { ticket_id } = req.params;

  try {
    // Fetch ticket with user info
    const [[ticket]] = await db.promise().query(
      `
      SELECT 
        st.*,
        u.username AS user_username
      FROM support_tickets st
      LEFT JOIN users u ON st.user_id = u.id
      WHERE st.id = ?
      `,
      [ticket_id]
    );

    if (!ticket) {
      return res.status(404).json({ error: 'Ticket not found' });
    }

    // Fetch messages + username mapping
    const [messages] = await db.promise().query(
      `
      SELECT 
        sm.id,
        sm.sender,
        sm.message,
        sm.created_at,
        CASE 
          WHEN sm.sender = 'admin' THEN 'Admin'
          ELSE u.username
        END AS sender_username
      FROM support_messages sm
      LEFT JOIN users u ON sm.ticket_id = ? AND sm.sender = 'user'
      WHERE sm.ticket_id = ?
      ORDER BY sm.created_at ASC
      `,
      [ticket_id, ticket_id]
    );

    const formattedMessages = messages.map(msg => ({
      ...msg,
      created_at: moment(msg.created_at).format('YYYY-MM-DD HH:mm:ss')
    }));

    res.json({
      ticket: {
        id: ticket.id,
        user_id: ticket.user_id,
        user_username: ticket.user_username,
        subject: ticket.subject,
        status: ticket.status,
        created_at: moment(ticket.created_at).format('YYYY-MM-DD HH:mm:ss')
      },
      messages: formattedMessages
    });

  } catch (error) {
    console.error('Error fetching ticket messages (admin):', error);
    res.status(500).json({ error: 'Server error fetching ticket messages' });
  }
});


// bot for the admin ticket system
/* ================================================================
   TELEGRAM BOT - INLINE ADMIN PANEL
=================================================================*/

const pendingTicketReplies = {}; // chatId → ticketId

// 🔹 Send ticket list with per-ticket buttons + pagination
async function sendTicketsWithButtons(chatId, page = 1) {
  try {
    const pageSize = 5; // how many tickets per page
    if (page < 1) page = 1;

    // Get total count for pagination
    const [[countRow]] = await db
      .promise()
      .query(`SELECT COUNT(*) AS total FROM support_tickets`);
    const total = countRow.total || 0;

    if (!total) {
      return bot.sendMessage(chatId, "📭 No support tickets found yet.");
    }

    const totalPages = Math.max(1, Math.ceil(total / pageSize));
    if (page > totalPages) page = totalPages;

    const offset = (page - 1) * pageSize;

    const [rows] = await db.promise().query(
      `
      SELECT 
        st.id,
        st.user_id,
        st.subject,
        st.status,
        st.created_at,
        u.username AS user_username
      FROM support_tickets st
      LEFT JOIN users u ON st.user_id = u.id
      ORDER BY st.created_at DESC
      LIMIT ? OFFSET ?
      `,
      [pageSize, offset]
    );

    if (!rows.length) {
      return bot.sendMessage(chatId, "📭 No support tickets found on this page.");
    }

    let text =
      "<b>🎫 Support Tickets</b>\n" +
      `Page <b>${page}</b> of <b>${totalPages}</b>\n\n`;

    const keyboard = [];

    rows.forEach((t, index) => {
      const isClosed = String(t.status).toLowerCase() === "closed";
      const statusLabel = isClosed ? "🔴 CLOSED" : "🟢 OPEN";

      text += `<b>${offset + index + 1}.</b> <b>${t.subject}</b>\n`;
      text += `👤 User: <b>${t.user_username || "Unknown"}</b>\n`;
      text += `🆔 Ticket: <code>#${t.id}</code>\n`;
      text += `📍 Status: ${statusLabel}\n`;
      text += `⏱ ${moment(t.created_at).format("YYYY-MM-DD HH:mm:ss")}\n\n`;

      if (isClosed) {
        // Closed → only "View"
        keyboard.push([
          { text: `📄 View #${t.id}`, callback_data: `ticket:${t.id}:view` }
        ]);
      } else {
        // Open → Reply / View / Close
        keyboard.push([
          { text: `💬 Reply #${t.id}`, callback_data: `ticket:${t.id}:reply` },
          { text: `📄 View #${t.id}`,  callback_data: `ticket:${t.id}:view` },
          { text: `✅ Close #${t.id}`, callback_data: `ticket:${t.id}:close` }
        ]);
      }
    });

    // 🔹 Pagination row (Prev / Page info / Next)
    const navRow = [];

    if (page > 1) {
      navRow.push({
        text: `⬅ Page ${page - 1}`,
        callback_data: `tickets_page:${page - 1}`
      });
    }

    navRow.push({
      text: `📄 ${page}/${totalPages}`,
      callback_data: "tickets_page:noop" // no-op
    });

    if (page < totalPages) {
      navRow.push({
        text: `➡ Page ${page + 1}`,
        callback_data: `tickets_page:${page + 1}`
      });
    }

    keyboard.push(navRow);

    return bot.sendMessage(chatId, text, {
      parse_mode: "HTML",
      reply_markup: { inline_keyboard: keyboard }
    });

  } catch (error) {
    console.error("sendTicketsWithButtons:", error.message);
    return bot.sendMessage(chatId, "❌ Server error loading tickets.");
  }
}



/* ──────────── BOT COMMANDS ────────────*/

// /start → main menu
bot.onText(/^\/start$/, async (msg) => {
  const chatId = msg.chat.id;
  if (!isAllowedChat(chatId)) {
    return bot.sendMessage(chatId, "⛔ You are not authorized to use this admin bot.");
  }

  const welcomeMsg =
    "<b>👋 Admin Dashboard Bot</b>\n\n" +
    "I help you manage support tickets directly from Telegram.\n\n" +
    "<b>Made by:</b> c0de8 (Light-Potato)\n\n" +
    "Choose an action below 👇";

  bot.sendMessage(chatId, welcomeMsg, {
    parse_mode: "HTML",
    reply_markup: {
      inline_keyboard: [
        [{ text: "🎫 View Tickets", callback_data: "tickets_action" }],
        [{ text: "ℹ️ Help / Commands", callback_data: "help_action" }],
        [{ text: "🗑 Clear Chat", callback_data: "clear_chat_action" }]
      ]
    }
  });
});
// /tickets → same as pressing “View Tickets”
bot.onText(/^\/tickets$/, async (msg) => {
  const chatId = msg.chat.id;
  if (!isAllowedChat(chatId)) return;
  await sendTicketsWithButtons(chatId, 1);
});
/* ──────────── BUTTON CLICK HANDLER ────────────*/
bot.on("callback_query", async (callbackQuery) => {
  const chatId = callbackQuery.message.chat.id;
  const action = callbackQuery.data;
  const messageId = callbackQuery.message.message_id;

  if (!isAllowedChat(chatId)) return;

  // stop loading spinner
  try {
    await bot.answerCallbackQuery(callbackQuery.id);
  } catch (e) {
    console.error("answerCallbackQuery error:", e.message);
  }

  // Remove the previous menu / card message to keep chat clean
  bot.deleteMessage(chatId, messageId).catch(() => {});

   // Main menu actions
  if (action === "tickets_action") {
    return sendTicketsWithButtons(chatId, 1);
  }

  // Pagination actions: tickets_page:N
  if (action.startsWith("tickets_page:")) {
    const [, pageStr] = action.split(":");
    if (pageStr === "noop") {
      // Just ignore the center page label button
      return;
    }

    const page = parseInt(pageStr, 10) || 1;
    return sendTicketsWithButtons(chatId, page);
  }


  if (action === "help_action") {
    return bot.sendMessage(
      chatId,
      "📌 <b>Commands</b>\n\n" +
        "• <code>/tickets</code> – Show latest tickets\n" +
        "• <code>/start</code> – Show main menu\n",
      { parse_mode: "HTML" }
    );
  }

  if (action === "clear_chat_action") {
    return bot.sendMessage(
      chatId,
      "🧹 Chat visually cleared.\nUse <code>/start</code> anytime to open the menu again.",
      { parse_mode: "HTML" }
    );
  }

  // Ticket actions: ticket:ID:operation
  if (action.startsWith("ticket:")) {
    const [, ticketIdStr, op] = action.split(":");
    const ticketId = parseInt(ticketIdStr, 10);

    if (!ticketId || !op) {
      return bot.sendMessage(chatId, "⚠️ Invalid ticket action.");
    }

    // 💬 Reply → mark this chat as typing for that ticket
    if (op === "reply") {
      pendingTicketReplies[chatId] = ticketId;

      return bot.sendMessage(
        chatId,
        `✍️ Type your reply for <b>Ticket #${ticketId}</b>.\n\n` +
          "Your next message (not a command) will be saved as the admin reply.",
        { parse_mode: "HTML" }
      );
    }

    // 📄 View ticket + messages
    if (op === "view") {
      try {
        const [[ticket]] = await db.promise().query(
          `
          SELECT st.*, u.username AS user_username
          FROM support_tickets st
          LEFT JOIN users u ON st.user_id = u.id
          WHERE st.id = ?
          `,
          [ticketId]
        );

        if (!ticket) {
          return bot.sendMessage(chatId, `⚠️ Ticket #${ticketId} not found.`);
        }

        const [messages] = await db.promise().query(
          `
          SELECT 
            sm.message,
            sm.sender,
            sm.created_at,
            CASE 
              WHEN sm.sender = 'admin' THEN 'Admin'
              ELSE u.username
            END AS sender_username
          FROM support_messages sm
          LEFT JOIN support_tickets st ON sm.ticket_id = st.id
          LEFT JOIN users u ON st.user_id = u.id
          WHERE sm.ticket_id = ?
          ORDER BY sm.created_at ASC
          `,
          [ticketId]
        );

        const isClosed = String(ticket.status).toLowerCase() === "closed";
        const statusLabel = isClosed ? "🔴 CLOSED" : "🟢 OPEN";

        let txt =
          `<b>📄 Ticket #${ticket.id}</b>\n` +
          `🎟 <b>${ticket.subject}</b>\n` +
          `👤 User: <b>${ticket.user_username || "Unknown"}</b>\n` +
          `📍 Status: ${statusLabel}\n` +
          `⏱ ${moment(ticket.created_at).format("YYYY-MM-DD HH:mm:ss")}\n\n`;

        if (!messages.length) {
          txt += "_No messages yet._\n";
        } else {
          txt += "<b>Messages:</b>\n\n";
          messages.forEach((m) => {
            txt += `• <b>${m.sender_username || "User"}</b>: ${m.message} (${moment(
              m.created_at
            ).format("YYYY-MM-DD HH:mm")})\n`;
          });
        }

        // Build buttons for this view
        const inline_keyboard = [];

        // Back button always
        inline_keyboard.push([
          { text: "⬅ Back to Tickets", callback_data: "tickets_action" }
        ]);

        // If ticket is still open, allow Reply & Close from here too
        if (!isClosed) {
          inline_keyboard.push([
            { text: `💬 Reply #${ticket.id}`, callback_data: `ticket:${ticket.id}:reply` },
            { text: `✅ Close #${ticket.id}`, callback_data: `ticket:${ticket.id}:close` }
          ]);
        }

        return bot.sendMessage(chatId, txt, {
          parse_mode: "HTML",
          reply_markup: { inline_keyboard }
        });
      } catch (err) {
        console.error("view ticket error:", err.message);
        return bot.sendMessage(chatId, "❌ Error loading ticket details.");
      }
    }

    // ✅ Close ticket
    if (op === "close") {
      try {
        await db
          .promise()
          .query(`UPDATE support_tickets SET status = "closed" WHERE id = ?`, [ticketId]);

        return bot.sendMessage(
          chatId,
          `✅ Ticket <b>#${ticketId}</b> has been marked as <b>CLOSED</b>.`,
          { parse_mode: "HTML" }
        );
      } catch (err) {
        console.error("close ticket error:", err.message);
        return bot.sendMessage(chatId, "❌ Error closing ticket.");
      }
    }
  }
});
/* ──────────── Handle Admin Reply Text ────────────*/
bot.on("message", async (msg) => {
  const chatId = msg.chat.id;
  const text = msg.text;

  // ignore commands like /start, /tickets
  if (!text || text.startsWith("/")) return;

  const ticketId = pendingTicketReplies[chatId];
  if (!ticketId || !isAllowedChat(chatId)) return;

  try {
    // Save admin reply
    await db.promise().query(
      `
      INSERT INTO support_messages (ticket_id, sender, message, created_at)
      VALUES (?, 'admin', ?, ?)
      `,
      [ticketId, text, moment().format("YYYY-MM-DD HH:mm:ss")]
    );

    delete pendingTicketReplies[chatId];

    // Fetch updated ticket info
    const [[ticket]] = await db.promise().query(`
      SELECT st.*, u.username AS user_username
      FROM support_tickets st
      LEFT JOIN users u ON st.user_id = u.id
      WHERE st.id = ?
    `, [ticketId]);

    const [messages] = await db.promise().query(`
      SELECT 
        sm.message,
        sm.sender,
        sm.created_at,
        CASE 
          WHEN sm.sender='admin' THEN 'Admin'
          ELSE u.username
        END AS sender_username
      FROM support_messages sm
      LEFT JOIN support_tickets st ON sm.ticket_id = st.id
      LEFT JOIN users u ON st.user_id = u.id
      WHERE sm.ticket_id = ?
      ORDER BY sm.created_at ASC
    `, [ticketId]);

    const isClosed = ticket.status.toLowerCase() === "closed";
    const statusLabel = isClosed ? "🔴 CLOSED" : "🟢 OPEN";

    let txt =
      `<b>📄 Ticket #${ticket.id}</b>\n` +
      `🎟 <b>${ticket.subject}</b>\n` +
      `👤 User: <b>${ticket.user_username || "Unknown"}</b>\n` +
      `📍 Status: ${statusLabel}\n` +
      `⏱ ${moment(ticket.created_at).format("YYYY-MM-DD HH:mm:ss")}\n\n` +
      "<b>Messages:</b>\n\n";

    messages.forEach((m) => {
      txt += `• <b>${m.sender_username}</b>: ${m.message} (${moment(
        m.created_at
      ).format("YYYY-MM-DD HH:mm")})\n`;
    });

    const inline_keyboard = [
      [{ text: "⬅ Back to Tickets", callback_data: "tickets_action" }]
    ];

    if (!isClosed) {
      inline_keyboard.push([
        { text: `💬 Reply Again`, callback_data: `ticket:${ticketId}:reply` },
        { text: `❌ Close Ticket`, callback_data: `ticket:${ticketId}:close` }
      ]);
    }

    return bot.sendMessage(chatId, txt, {
      parse_mode: "HTML",
      reply_markup: { inline_keyboard }
    });

  } catch (err) {
    console.error("Reply save error:", err.message);
    bot.sendMessage(chatId, "❌ Error saving reply. Try again.", { parse_mode: "HTML" });
  }
});
/* ──────────── Bot Ping Test ────────────*/
router.get('/telegram-test', async (req, res) => {
  try {
    const me = await bot.getMe();
    res.json({ ok: true, bot: me });
  } catch (err) {
    console.error('Telegram test error:', err.message);
    res.status(500).json({ ok: false, error: err.message });
  }
});




// Admin view all deposits 👀 GET /admin/deposits
router.get('/deposits', authenticateToken, checkAdmin, async (req, res) => {
  try {
    const [rows] = await db.promise().query(
      `SELECT d.*, u.username, w.wallet_name 
       FROM deposits d 
       JOIN users u ON d.user_id = u.id 
       JOIN wallets w ON d.wallet_id = w.id 
       ORDER BY d.id DESC`
    );

    const baseUrl = `${req.protocol}://${req.get('host')}`;
    const formatted = rows.map(d => ({
      id: d.id,
      username: d.username,
      wallet_name: d.wallet_name,
      amount: d.amount,
      status: d.status,
      proof_url: `${baseUrl}/${d.proof_path}`,
      created_at: d.created_at
    }));

    res.json({ deposits: formatted });
  } catch (error) {
    console.error('❌ Admin fetch deposits error:', error);
    res.status(500).json({ error: 'Failed to fetch deposits' });
  }
});
// Admin confirms a deposit ✅ PUT /admin/deposit/:id/confirm
router.put('/deposit/:id/confirm', authenticateToken, checkAdmin, async (req, res) => {
  try {
    const depositId = req.params.id;

    const [result] = await db
      .promise()
      .query('UPDATE deposits SET status = ? WHERE id = ?', ['confirmed', depositId]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Deposit not found' });
    }

    res.json({ message: 'Deposit confirmed successfully' });
  } catch (error) {
    console.error('❌ Confirm deposit error:', error);
    res.status(500).json({ error: 'Failed to confirm deposit' });
  }
});
// Admin rejects a deposit ❌ PUT /admin/deposit/:id/reject
router.put('/deposit/:id/reject', authenticateToken, checkAdmin, async (req, res) => {
  try {
    const depositId = req.params.id;

    const [result] = await db
      .promise()
      .query('UPDATE deposits SET status = ? WHERE id = ?', ['rejected', depositId]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Deposit not found' });
    }

    res.json({ message: 'Deposit rejected successfully' });
  } catch (error) {
    console.error('❌ Reject deposit error:', error);
    res.status(500).json({ error: 'Failed to reject deposit' });
  }
});


// 🔐 Admin: Reset a user's transaction PIN to 000000
router.post('/users/:id/reset-pin', authenticateToken, checkAdmin, (req, res) => {
  const adminId  = req.user.id;
  const targetId = parseInt(req.params.id, 10);

  if (!Number.isInteger(targetId) || targetId <= 0) {
    return res.status(400).json({ error: 'Invalid user id' });
  }

  db.query('UPDATE users SET transaction_pin = ? WHERE id = ?', ['000000', targetId], async (err, result) => {
    if (err) {
      console.error('❌ DB ERROR [/admin/users/:id/reset-pin]:', err);
      return res.status(500).json({ error: 'Database error', details: err.message });
    }

    if (!result || result.affectedRows === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Optional audit logs
    try {
      await logActivity(adminId,  'admin_reset_pin',     `Admin ${adminId} reset PIN for user ${targetId} to default.`);
      await logActivity(targetId, 'pin_reset_by_admin',  'Your transaction PIN was reset by an admin. Default is 000000; please change it immediately.');
    } catch (_) {}

    return res.json({
      ok: true,
      user_id: targetId,
      pin_set_to: '000000',
      message: 'PIN reset to default 000000. User should change it immediately.'
    });
  });
});


// ----- Admin: view current code-requirement settings
router.get('/security-codes/settings', authenticateToken, checkAdmin, async (req, res) => {
  try {
    const [[row]] = await db.promise().query(
      'SELECT require_imf, require_cot, require_tax FROM security_settings WHERE id = 1'
    );
    const settings = row || { require_imf: 1, require_cot: 1, require_tax: 1 };
    res.json({ ok: true, settings: {
      require_imf: !!settings.require_imf,
      require_cot: !!settings.require_cot,
      require_tax: !!settings.require_tax
    }});
  } catch (e) {
    console.error('❌ GET /security-codes/settings:', e);
    res.status(500).json({ ok: false, error: 'db_error', details: e.message });
  }
});
// ----- Admin: toggle codes (all at once via require_codes OR individually)
router.post('/security-codes/settings', authenticateToken, checkAdmin, async (req, res) => {
  const adminId = req.user.id;
  const { require_codes, require_imf, require_cot, require_tax } = req.body;

  // Helper to coerce to boolean (accepts true/false, "true"/"false", 1/0)
  const toBool = (v) => v === true || v === 1 || v === '1' || String(v).toLowerCase() === 'true';

  try {
    // Read current (or defaults)
    const [[current]] = await db.promise().query(
      'SELECT require_imf, require_cot, require_tax FROM security_settings WHERE id = 1'
    );
    let flags = current || { require_imf: 1, require_cot: 1, require_tax: 1 };

    // If require_codes provided, set all three at once
    if (require_codes !== undefined) {
      const all = toBool(require_codes) ? 1 : 0;
      flags.require_imf = all;
      flags.require_cot = all;
      flags.require_tax = all;
    }

    // Individual overrides (optional)
    if (require_imf !== undefined) flags.require_imf = toBool(require_imf) ? 1 : 0;
    if (require_cot !== undefined) flags.require_cot = toBool(require_cot) ? 1 : 0;
    if (require_tax !== undefined) flags.require_tax = toBool(require_tax) ? 1 : 0;

    // Upsert single settings row (id=1)
    await db.promise().query(
      `INSERT INTO security_settings (id, require_imf, require_cot, require_tax)
       VALUES (1, ?, ?, ?)
       ON DUPLICATE KEY UPDATE
         require_imf = VALUES(require_imf),
         require_cot = VALUES(require_cot),
         require_tax = VALUES(require_tax)`,
      [flags.require_imf, flags.require_cot, flags.require_tax]
    );

    try {
      await logActivity(adminId, 'admin_toggle_codes',
        `Admin set require_imf=${!!flags.require_imf}, require_cot=${!!flags.require_cot}, require_tax=${!!flags.require_tax}`);
    } catch (_) {}

    res.json({
      ok: true,
      settings: {
        require_imf: !!flags.require_imf,
        require_cot: !!flags.require_cot,
        require_tax: !!flags.require_tax
      }
    });
  } catch (e) {
    console.error('❌ POST /security-codes/settings:', e);
    res.status(500).json({ ok: false, error: 'db_error', details: e.message });
  }
});


// Update a user's account status (admin only)
router.patch('/users/:id/status', authenticateToken, checkAdmin, (req, res) => {
  const userId = Number(req.params.id);
  const { acct_status } = req.body || {};

  if (!userId || Number.isNaN(userId)) {
    return res.status(400).json({ ok: false, error: 'Invalid user id' });
  }

  const newStatus = (acct_status || '').trim().toLowerCase();

  if (!newStatus) {
    return res.status(400).json({ ok: false, error: 'acct_status is required' });
  }

  if (!ALLOWED_ACCOUNT_STATUS.has(newStatus)) {
    return res.status(400).json({
      ok: false,
      error: 'Invalid acct_status',
      allowed: Array.from(ALLOWED_ACCOUNT_STATUS)
    });
  }

  const sql = `
    UPDATE users
    SET acct_status = ?
    WHERE id = ?
    LIMIT 1
  `;

  db.query(sql, [newStatus, userId], (err, result) => {
    if (err) {
      console.error('❌ DB ERROR [/admin/users/:id/status]:', err);
      return res.status(500).json({ ok: false, error: 'Database error', details: err.message });
    }

    if (!result.affectedRows) {
      return res.status(404).json({ ok: false, error: 'User not found' });
    }

    return res.json({
      ok: true,
      message: `User account status changed to "${newStatus}"`,
      user: { id: userId, acct_status: newStatus }
    });
  });
});


// Admin: get local transfer OTP status
router.get("/settings/otp/local-transfer", authenticateToken, checkAdmin, (req, res) => {
  db.query(
    `SELECT value FROM settings WHERE key_name = 'local_transfer_otp_enabled' LIMIT 1`,
    (err, rows) => {
      if (err) return res.status(500).json({ error: "Failed to fetch setting", details: String(err) });

      // default ON if not found
      const raw = rows?.[0]?.value;
      const enabled = raw === undefined || raw === null ? true : String(raw) === "1";

      return res.json({ key: "local_transfer_otp_enabled", enabled });
    }
  );
});
// Admin: set local transfer OTP status (enabled: true/false)
router.put("/settings/otp/local-transfer", authenticateToken, checkAdmin, (req, res) => {
  const { enabled } = req.body || {};
  const val = enabled ? "1" : "0";

  db.query(
    `INSERT INTO settings (key_name, value)
     VALUES ('local_transfer_otp_enabled', ?)
     ON DUPLICATE KEY UPDATE value = VALUES(value)`,
    [val],
    (err) => {
      if (err) return res.status(500).json({ error: "Failed to update setting", details: String(err) });
      return res.json({ message: "Updated", key: "local_transfer_otp_enabled", enabled: !!enabled });
    }
  );
});
// ✅ Admin: enable/disable OTP for wire transfers
router.put("/settings/wire-transfer-otp",authenticateToken,checkAdmin,
  async (req, res) => {
    try {
      const { enabled } = req.body || {};

      if (enabled === undefined) {
        return res.status(400).json({
          error: "enabled is required (true or false)",
        });
      }

      const value = enabled ? "1" : "0";

      await db.promise().query(
        `INSERT INTO settings (key_name, value)
         VALUES ('wire_transfer_otp_enabled', ?)
         ON DUPLICATE KEY UPDATE value = VALUES(value)`,
        [value]
      );

      return res.json({
        message: `Wire transfer OTP ${enabled ? "ENABLED" : "DISABLED"}`,
        key: "wire_transfer_otp_enabled",
        value: enabled ? 1 : 0,
      });
    } catch (error) {
      console.error("❌ Update wire OTP setting error:", error);
      res.status(500).json({ error: "Failed to update wire OTP setting" });
    }
  }
);
// ✅ Admin: get wire transfer OTP status
router.get("/settings/wire-transfer-otp",authenticateToken,checkAdmin,
  async (req, res) => {
    try {
      const [rows] = await db.promise().query(
        `SELECT value FROM settings WHERE key_name='wire_transfer_otp_enabled' LIMIT 1`
      );

      const enabled =
        rows?.[0]?.value === undefined ? true : String(rows[0].value) === "1";

      res.json({
        key: "wire_transfer_otp_enabled",
        enabled,
      });
    } catch (error) {
      console.error("❌ Fetch wire OTP setting error:", error);
      res.status(500).json({ error: "Failed to fetch wire OTP setting" });
    }
  }
);



// ✅ Admin: enable/disable admin confirmation for local transfers
router.put("/settings/local-transfer-admin-confirm",authenticateToken,checkAdmin,
  async (req, res) => {
    try {
      const { enabled } = req.body || {};

      if (enabled === undefined) {
        return res.status(400).json({
          error: "enabled is required (true or false)",
        });
      }

      const value = enabled ? "1" : "0";

      await db
        .promise()
        .query(
          `INSERT INTO settings (key_name, value)
           VALUES ('local_transfer_admin_confirm_enabled', ?)
           ON DUPLICATE KEY UPDATE value = VALUES(value)`,
          [value]
        );

      return res.json({
        message: `Local transfer admin confirmation ${
          enabled ? "ENABLED" : "DISABLED"
        }`,
        key: "local_transfer_admin_confirm_enabled",
        value: enabled ? 1 : 0,
      });
    } catch (error) {
      console.error("❌ Update admin confirm setting error:", error);
      res.status(500).json({
        error: "Failed to update admin confirmation setting",
      });
    }
  }
);
// ✅ Admin: get local transfer admin confirmation status
router.get("/settings/local-transfer-admin-confirm",authenticateToken,checkAdmin,
  async (req, res) => {
    try {
      const [rows] = await db
        .promise()
        .query(
          `SELECT value FROM settings
           WHERE key_name = 'local_transfer_admin_confirm_enabled'
           LIMIT 1`
        );

      const enabled =
        rows?.[0]?.value === undefined
          ? true
          : String(rows[0].value) === "1";

      res.json({
        key: "local_transfer_admin_confirm_enabled",
        enabled,
      });
    } catch (error) {
      console.error("❌ Fetch admin confirm setting error:", error);
      res.status(500).json({
        error: "Failed to fetch admin confirmation setting",
      });
    }
  }
);
// ✅ Admin: get wire transfer admin confirmation status
router.put("/settings/wire-transfer-admin-confirm",authenticateToken,checkAdmin,
  async (req, res) => {
    try {
      const { enabled } = req.body || {};
      if (enabled === undefined) {
        return res.status(400).json({ error: "enabled is required (true or false)" });
      }

      const value = enabled ? "1" : "0";

      await db.promise().query(
        `INSERT INTO settings (key_name, value)
         VALUES ('wire_transfer_admin_confirm_enabled', ?)
         ON DUPLICATE KEY UPDATE value = VALUES(value)`,
        [value]
      );

      return res.json({
        message: `Wire transfer admin confirmation ${enabled ? "ENABLED" : "DISABLED"}`,
        key: "wire_transfer_admin_confirm_enabled",
        value: enabled ? 1 : 0,
      });
    } catch (error) {
      console.error("❌ Update wire admin confirm setting error:", error);
      res.status(500).json({ error: "Failed to update wire admin confirmation setting" });
    }
  }
);
// ✅ Admin: get wire transfer admin confirmation status
router.get("/settings/wire-transfer-admin-confirm",authenticateToken,checkAdmin,
  async (req, res) => {
    try {
      const [rows] = await db.promise().query(
        `SELECT value FROM settings WHERE key_name='wire_transfer_admin_confirm_enabled' LIMIT 1`
      );
      const enabled = rows?.[0]?.value === undefined ? true : String(rows[0].value) === "1";
      res.json({ key: "wire_transfer_admin_confirm_enabled", enabled });
    } catch (e) {
      res.status(500).json({ error: "Failed to fetch wire admin confirm setting" });
    }
  }
);


module.exports = router;
