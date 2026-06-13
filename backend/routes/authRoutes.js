const express = require('express');
const bcrypt = require('bcrypt');
const db = require('../db');
const { sendOTPEmail, sendWelcomeEmail, sendLoginAlertEmail, sendLoginOTPEmail, sendPasswordResetEmail } = require('../utils/mailer');
const router = express.Router();
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { logActivity } = require('../utils/activityLogger');


function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

function generateAccountNumber() {
  return '01' + Math.floor(1000000000 + Math.random() * 9000000000);
}
function generateCurrentAccountNumber() {
  return '01' + Math.floor(100000000 + Math.random() * 900000000); // e.g. 01XXXXXXXXX
}
function generateSavingsAccountNumber() {
  return '81' + Math.floor(100000000 + Math.random() * 900000000); // e.g. 81XXXXXXXXX
}

// User Registration
router.post('/register', async (req, res) => {
  const { username, password, full_name, email } = req.body;

  if (!username || !password || !email || !full_name) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const accountNumber = generateAccountNumber();
    const cAccountNumber = generateCurrentAccountNumber();
    const sAccountNumber = generateSavingsAccountNumber();

    // Insert into users
    db.query(
      `INSERT INTO users (username, password, full_name, email, is_admin, account_number)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [username, hashedPassword, full_name, email, 0, accountNumber],
      (err, result) => {
        if (err) {
          if (err.code === 'ER_DUP_ENTRY') {
            return res.status(400).json({ error: 'Username or email already exists' });
          }
          return res.status(500).json({ error: 'Database error', details: err });
        }

        const userId = result.insertId;

        // Insert into accounts table
        db.query(
          `INSERT INTO accounts (user_id, s_account_number, c_account_number)
           VALUES (?, ?, ?)`,
          [userId, sAccountNumber, cAccountNumber],
          (accErr) => {
            if (accErr) {
              console.error('❌ Failed to create account numbers:', accErr);
              return res.status(500).json({ error: 'Failed to generate account numbers' });
            }

            const otp = generateOTP();
            const otpExpiresAt = new Date(Date.now() + (parseInt(process.env.OTP_EXPIRY_MINUTES) || 10) * 60000);

            // Store OTP
            db.query(
              'INSERT INTO otps (user_id, otp_code, otp_expires_at) VALUES (?, ?, ?)',
              [userId, otp, otpExpiresAt],
              async (otpErr) => {
                if (otpErr) return res.status(500).json({ error: 'OTP creation failed' });

                try {
                  await sendOTPEmail(email, full_name, otp);
                  res.json({
                    message: 'User registered. OTP sent to email. Please verify to activate account.'
                  });
                } catch (emailError) {
                  console.error('❌ OTP email error:', emailError);
                  res.status(500).json({ error: 'Failed to send OTP email' });
                }
              }
            );
          }
        );
      }
    );
  } catch (error) {
    res.status(500).json({ error: 'Registration failed', details: error.message });
  }
});

// Verify OTP
router.post('/verify-otp', (req, res) => {
  const { email, otp } = req.body;

  if (!email || !otp) {
    return res.status(400).json({ error: 'Email and OTP are required' });
  }

  // Get user ID by email
  db.query('SELECT id, email_verified, full_name, account_number FROM users WHERE email = ?', [email], (err, users) => {
    if (err) return res.status(500).json({ error: 'DB Error' });
    if (users.length === 0) return res.status(404).json({ error: 'User not found' });

    const user = users[0];
    if (user.email_verified) {
      return res.status(400).json({ error: 'Email already verified' });
    }

    // Get matching OTP
    db.query(
      'SELECT * FROM otps WHERE user_id = ? AND otp_code = ? AND otp_expires_at > NOW()',
      [user.id, otp],
      (err2, otps) => {
        if (err2) return res.status(500).json({ error: 'OTP check error' });
        if (otps.length === 0) return res.status(400).json({ error: 'Invalid or expired OTP' });

        // ✅ Update email_verified and cleanup
        db.query('UPDATE users SET email_verified = 1 WHERE id = ?', [user.id], (err3) => {
          if (err3) return res.status(500).json({ error: 'Verification failed' });

          db.query('DELETE FROM otps WHERE user_id = ?', [user.id], async (err4) => {
            if (err4) console.warn('OTP cleanup failed (non-blocking)');

            // ✅ Send Welcome Email AFTER OTP is verified
            try {
              await sendWelcomeEmail(email, user.full_name, user.account_number);
              res.json({ message: 'Email verified and welcome email sent' });
            } catch (emailErr) {
              console.error('❌ Failed to send welcome email:', emailErr);
              res.status(200).json({
                message: 'Email verified, but welcome email failed to send',
                email_verified: true
              });
            }
          });
        });
      }
    );
  });
});

// Resend OTP
router.post('/resend-otp', (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }

  // Step 1: Find user
  db.query('SELECT id, full_name, email_verified FROM users WHERE email = ?', [email], (err, users) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (users.length === 0) return res.status(404).json({ error: 'User not found' });

    const user = users[0];
    if (user.email_verified) {
      return res.status(400).json({ error: 'Email is already verified' });
    }

    const newOtp = generateOTP();
    const newExpiry = new Date(Date.now() + (parseInt(process.env.OTP_EXPIRY_MINUTES) || 10) * 60000);

    // Step 2: Update or insert OTP
    db.query(
      'INSERT INTO otps (user_id, otp_code, otp_expires_at) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE otp_code = VALUES(otp_code), otp_expires_at = VALUES(otp_expires_at)',
      [user.id, newOtp, newExpiry],
      async (err2) => {
        if (err2) return res.status(500).json({ error: 'Failed to save new OTP' });

        // Step 3: Send OTP email
        try {
          await sendOTPEmail(email, user.full_name, newOtp);
          res.json({ message: 'A new OTP has been sent to your email' });
        } catch (emailError) {
          console.error('❌ Failed to send OTP email:', emailError);
          res.status(500).json({ error: 'Failed to send OTP email' });
        }
      }
    );
  });
});

// User Login
router.post('/login', async (req, res) => {
  const { identifier, password } = req.body;

  if (!identifier || !password) {
    return res.status(400).json({ error: 'Email/Account Number and password are required' });
  }

  db.query(
    'SELECT * FROM users WHERE email = ? OR account_number = ?',
    [identifier, identifier],
    async (err, results) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      if (results.length === 0) return res.status(401).json({ error: 'Invalid credentials' });

      const user = results[0];

      if (!user.email_verified) {
        logActivity(user.id, 'login_failed', 'Email not verified');
        return res.status(403).json({ error: 'Email not verified' });
      }

      const passwordMatch = await bcrypt.compare(password, user.password);
      if (!passwordMatch) {
        logActivity(user.id, 'login_failed', 'Incorrect password');
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      try {
        await sendLoginAlertEmail(user.email, user.full_name);
        logActivity(user.id, 'login_alert_sent', 'Login alert email sent');
      } catch (e) {
        console.warn('⚠️ Failed to send login alert email:', e.message);
      }

      const loginOTPEnabled = user.login_otp_enabled === 1;

      if (loginOTPEnabled) {
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const otpExpiresAt = new Date(Date.now() + (parseInt(process.env.OTP_EXPIRY_MINUTES) || 10) * 60000);

        db.query(
          `INSERT INTO login_otps (user_id, otp_code, otp_expires_at)
           VALUES (?, ?, ?)
           ON DUPLICATE KEY UPDATE otp_code = VALUES(otp_code), otp_expires_at = VALUES(otp_expires_at)`,
          [user.id, otp, otpExpiresAt],
          async (err2) => {
            if (err2) {
              logActivity(user.id, 'otp_error', 'Failed to store login OTP');
              return res.status(500).json({ error: 'Failed to save login OTP' });
            }

            try {
              await sendLoginOTPEmail(user.email, user.full_name, otp);
              logActivity(user.id, 'otp_sent', 'Login OTP sent');
              return res.json({
                message: 'Login OTP sent to your email. Please verify to complete login.',
                otp_required: true
              });
            } catch (emailErr) {
              logActivity(user.id, 'otp_email_failed', 'Failed to send OTP email');
              return res.status(500).json({ error: 'Failed to send OTP email' });
            }
          }
        );
      } else {
        // No OTP required
        const token = jwt.sign({ id: user.id, is_admin: user.is_admin }, process.env.JWT_SECRET, {
          expiresIn: '7h'
        });

        logActivity(user.id, 'login', 'Login successful (OTP not required)');
        return res.json({
          message: 'Login successful',
          token,
          user: {
            id: user.id,
            username: user.username,
            full_name: user.full_name,
            account_number: user.account_number,
            is_admin: user.is_admin
          }
        });
      }
    }
  );
});

// ✅ Verify Login OTP
router.post('/login/verify-otp', (req, res) => {
  const { email, otp } = req.body;

  if (!email || !otp) return res.status(400).json({ error: 'Email and OTP required' });

  db.query('SELECT * FROM users WHERE email = ?', [email], (err, users) => {
    if (err || users.length === 0) return res.status(404).json({ error: 'User not found' });

    const user = users[0];

    db.query(
      'SELECT * FROM login_otps WHERE user_id = ? AND otp_code = ? AND otp_expires_at > NOW()',
      [user.id, otp],
      (err2, otps) => {
        if (err2 || otps.length === 0) {
          logActivity(user.id, 'otp_failed', 'Invalid or expired OTP during login');
          return res.status(400).json({ error: 'Invalid or expired OTP' });
        }

        // OTP is valid, delete it and issue token
        db.query('DELETE FROM login_otps WHERE user_id = ?', [user.id]);

        const token = jwt.sign({ id: user.id, is_admin: user.is_admin }, process.env.JWT_SECRET, {
          expiresIn: '7h'
        });

        logActivity(user.id, 'login', 'OTP verified. Login successful');
        return res.json({
          message: 'OTP verified. Login successful',
          token,
          user: {
            id: user.id,
            username: user.username,
            full_name: user.full_name,
            account_number: user.account_number,
            is_admin: user.is_admin
          }
        });
      }
    );
  });
});

// Forgot Password
router.post('/forgot-password', (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email is required' });

  // Find user
  db.query('SELECT id, full_name FROM users WHERE email = ?', [email], (err, users) => {
    if (err) return res.status(500).json({ error: 'DB Error' });
    if (users.length === 0) return res.status(404).json({ error: 'User not found' });

    const user = users[0];
    const token = crypto.randomBytes(32).toString('hex');
    const expires = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes

    // Save token
    db.query(
      `INSERT INTO password_resets (user_id, token, expires_at)
       VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE token = ?, expires_at = ?`,
      [user.id, token, expires, token, expires],
      async (err2) => {
        if (err2) return res.status(500).json({ error: 'Failed to create reset token' });

        try {
          await sendPasswordResetEmail(email, user.full_name, token);
          res.json({ message: 'Password reset email sent' });
        } catch (e) {
          console.error('Email failed:', e.message);
          res.status(500).json({ error: 'Failed to send email' });
        }
      }
    );
  });
});

// Reset Password
router.post('/reset-password', async (req, res) => {
  const { token, new_password } = req.body;
  if (!token || !new_password) {
    return res.status(400).json({ error: 'Token and new password are required' });
  }

  // Check token validity
  db.query(
    `SELECT pr.user_id, u.email FROM password_resets pr
     JOIN users u ON pr.user_id = u.id
     WHERE pr.token = ? AND pr.expires_at > NOW()`,
    [token],
    async (err, results) => {
      if (err) return res.status(500).json({ error: 'DB Error' });
      if (results.length === 0) return res.status(400).json({ error: 'Invalid or expired token' });

      const userId = results[0].user_id;
      const hashedPassword = await bcrypt.hash(new_password, 10);

      // Update password and delete token
      db.query('UPDATE users SET password = ? WHERE id = ?', [hashedPassword, userId], (err2) => {
        if (err2) return res.status(500).json({ error: 'Failed to reset password' });

        db.query('DELETE FROM password_resets WHERE user_id = ?', [userId]);
        res.json({ message: 'Password has been reset successfully' });
      });
    }
  );
});


module.exports = router;
