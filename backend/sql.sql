CREATE TABLE IF NOT EXISTS security_settings (
  id TINYINT PRIMARY KEY,
  require_imf TINYINT(1) NOT NULL DEFAULT 1,
  require_cot TINYINT(1) NOT NULL DEFAULT 1,
  require_tax TINYINT(1) NOT NULL DEFAULT 1,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);
INSERT IGNORE INTO security_settings (id, require_imf, require_cot, require_tax) VALUES (1,1,1,1);


ALTER TABLE users
MODIFY acct_status VARCHAR(20) NOT NULL DEFAULT 'active';
