CREATE TABLE IF NOT EXISTS users (
                                     id SERIAL PRIMARY KEY,
                                     username VARCHAR(100) UNIQUE NOT NULL,
    email VARCHAR(120) UNIQUE NOT NULL,
    password_hash VARCHAR(255),  -- Made nullable for MS auth users
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    active BOOLEAN DEFAULT FALSE,  -- Default to inactive until approved
    is_admin BOOLEAN DEFAULT FALSE,  -- Default to regular user
    ms_auth BOOLEAN DEFAULT FALSE   -- Track if user authenticated via Microsoft
    );

-- Add indexes on frequently searched columns
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);