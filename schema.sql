CREATE DATABASE IF NOT EXISTS exam_reg_db
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;
USE exam_reg_db;

CREATE TABLE IF NOT EXISTS users (
  id INT PRIMARY KEY AUTO_INCREMENT,
  email VARCHAR(255) UNIQUE NOT NULL,
  nshe  VARCHAR(10) NOT NULL,
  full_name VARCHAR(255) NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  role ENUM('student','faculty') NOT NULL DEFAULT 'student',
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uniq_nshe (nshe)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS password_resets (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  token_hash CHAR(64) NOT NULL,
  expires_at DATETIME NOT NULL,
  used TINYINT(1) NOT NULL DEFAULT 0,
  created_at DATETIME NOT NULL DEFAULT NOW(),
  used_at DATETIME NULL,
  INDEX idx_token_hash (token_hash),
  CONSTRAINT fk_reset_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- EXAMS TABLE
CREATE TABLE IF NOT EXISTS exams (
  id INT AUTO_INCREMENT PRIMARY KEY,
  exam_code VARCHAR(255) UNIQUE NOT NULL,
  description VARCHAR(255)
) ENGINE=InnoDB;

-- LOCATIONS TABLE
CREATE TABLE IF NOT EXISTS locations (
  id INT AUTO_INCREMENT PRIMARY KEY,
  campus_name ENUM('Henderson', 'Charleston', 'North Las Vegas') NOT NULL,
  building_name VARCHAR(255) NOT NULL,
  room_number VARCHAR(50) NOT NULL
) ENGINE=InnoDB;

-- EXAM SESSIONS TABLE
CREATE TABLE IF NOT EXISTS exam_sessions (
  id INT AUTO_INCREMENT PRIMARY KEY,
  exam_id INT NOT NULL,
  session_datetime DATETIME NOT NULL,
  location_id INT NOT NULL,
  creator_id INT NOT NULL, -- admin user
  proctor_id INT NOT NULL, -- admin user
  capacity INT DEFAULT 20,
  FOREIGN KEY (exam_id) REFERENCES exams(id),
  FOREIGN KEY (location_id) REFERENCES locations(id),
  FOREIGN KEY (creator_id) REFERENCES users(id),
  FOREIGN KEY (proctor_id) REFERENCES users(id)
) ENGINE=InnoDB;

-- REGISTRATIONS TABLE
CREATE TABLE IF NOT EXISTS registrations (
  id INT AUTO_INCREMENT PRIMARY KEY,
  session_id INT NOT NULL,
  user_id INT NOT NULL, -- student user
  registered_at DATETIME DEFAULT NOW(),
  cancelled BOOLEAN DEFAULT FALSE,
  cancelled_at DATETIME NULL,
  UNIQUE (user_id, session_id),
  FOREIGN KEY (user_id) REFERENCES users(id),
  FOREIGN KEY (session_id) REFERENCES exam_sessions(id)
) ENGINE=InnoDB;
