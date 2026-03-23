-- =========================================================
-- II Design — Database Initialisation
-- Run once: mysql -u root -p < init.sql
-- =========================================================

CREATE DATABASE IF NOT EXISTS ii_design
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE ii_design;

-- Users table for authentication and user management
CREATE TABLE IF NOT EXISTS users (
  id            INT UNSIGNED     NOT NULL AUTO_INCREMENT,
  name          VARCHAR(100)     DEFAULT NULL,
  email         VARCHAR(255)     NOT NULL UNIQUE,
  password_hash VARCHAR(255)     NOT NULL,
  role          ENUM('user','admin') NOT NULL DEFAULT 'user',
  refresh_token TEXT             DEFAULT NULL,
  created_at    DATETIME         NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at    DATETIME         NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  INDEX idx_email (email),
  INDEX idx_role  (role)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Migration: add name and role columns to existing installations
-- ALTER TABLE users ADD COLUMN name VARCHAR(100) DEFAULT NULL AFTER id;
-- ALTER TABLE users ADD COLUMN role ENUM('user','admin') NOT NULL DEFAULT 'user' AFTER email;
-- ALTER TABLE users ADD INDEX idx_role (role);

-- Seed: insert a demo user (password: demo1234)
-- bcrypt hash of "demo1234" with 12 rounds:
-- INSERT INTO users (email, password_hash) VALUES
--   ('demo@iidesign.com', '$2a$12$examplehashgoeshere...');
