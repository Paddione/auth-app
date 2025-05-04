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

INSERT INTO users (username, email, password_hash, active, is_admin, ms_auth)
VALUES ('Patrick', 'patrick@korczewski.de',
        'scrypt:32768:8:1$QSYk3XNSUBCmMcxT$d2112aa584fa5bd165c8b517399306feee42255340d0b3ebc8ce4de66b86fca95e787647f061ebd61d88c444759ace13c8636b409011a1381fd1d0a09ab6db0b',
        TRUE, TRUE, FALSE)
    ON CONFLICT (email) DO NOTHING;