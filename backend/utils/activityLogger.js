const db = require('../db');

const logActivity = (userId, type, description) => {
  db.query(
    `INSERT INTO activities (user_id, activity_type, description)
     VALUES (?, ?, ?)`,
    [userId, type, description],
    (err) => {
      if (err) console.error('Activity log failed:', err.message);
    }
  );
};

module.exports = { logActivity };
