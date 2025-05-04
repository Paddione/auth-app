import psycopg2
import psycopg2.extras
import os
import random
import string
from flask_bcrypt import Bcrypt
import secrets
from datetime import datetime, timedelta
bcrypt = Bcrypt()

class Database:
    def __init__(self):
        self.conn = None

    def connect(self):
        if self.conn is None:
            # Inside Docker network, we use POSTGRES_HOST and default port 5432
            # For external connections, port would be 5433
            self.conn = psycopg2.connect(
                host=os.getenv('POSTGRES_HOST', 'postgres'),
                port=os.getenv('POSTGRES_PORT', 5432),
                database=os.getenv('POSTGRES_DB', 'authdb'),
                user=os.getenv('POSTGRES_USER', 'authuser'),
                password=os.getenv('POSTGRES_PASSWORD', 'authpassword')
            )
            self.conn.autocommit = True

            # Ensure the users table has the required fields
            self._init_schema()

        return self.conn

    def _init_schema(self):
        cursor = self.conn.cursor()
        try:
            # Check if 'active' column exists
            cursor.execute("""
                SELECT column_name
                FROM information_schema.columns
                WHERE table_name='users' AND column_name='active'
            """)

            if cursor.fetchone() is None:
                # Add 'active' column if it doesn't exist
                cursor.execute("ALTER TABLE users ADD COLUMN active BOOLEAN DEFAULT FALSE")

            # Check if 'is_admin' column exists
            cursor.execute("""
                SELECT column_name
                FROM information_schema.columns
                WHERE table_name='users' AND column_name='is_admin'
            """)

            if cursor.fetchone() is None:
                # Add 'is_admin' column if it doesn't exist
                cursor.execute("ALTER TABLE users ADD COLUMN is_admin BOOLEAN DEFAULT FALSE")

            # Check if 'password_reset' column exists
            cursor.execute("""
                SELECT column_name
                FROM information_schema.columns
                WHERE table_name='users' AND column_name='password_reset'
            """)

            if cursor.fetchone() is None:
                # Add 'password_reset' column if it doesn't exist
                cursor.execute("ALTER TABLE users ADD COLUMN password_reset BOOLEAN DEFAULT FALSE")
            cursor.execute("""
                        CREATE TABLE IF NOT EXISTS user_tokens (
                            id SERIAL PRIMARY KEY,
                            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                            token TEXT NOT NULL UNIQUE,
                            token_type TEXT NOT NULL,
                            expires_at TIMESTAMP NOT NULL,
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        )
                    """)
            self.conn.commit()
        except psycopg2.Error as e:
            print(f"Schema initialization error: {e}")
        finally:
            cursor.close()

    def get_cursor(self):
        return self.connect().cursor(cursor_factory=psycopg2.extras.DictCursor)

    def close(self):
        if self.conn is not None:
            self.conn.close()
            self.conn = None

class User:
    @staticmethod
    def create(db, username, email, password, active=False, ms_auth=False, password_reset=False):
        """Create a new user"""
        password_hash = None
        if password:
            password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

        cursor = db.get_cursor()
        try:
            cursor.execute(
                "INSERT INTO users (username, email, password_hash, active, ms_auth, password_reset) VALUES (%s, %s, %s, %s, %s, %s) RETURNING id",
                (username, email, password_hash, active, ms_auth, password_reset)
            )
            user_id = cursor.fetchone()[0]
            return user_id
        except psycopg2.Error as e:
            print(f"Database error: {e}")
            return None
        finally:
            cursor.close()

    @staticmethod
    def get_by_username(db, username):
        """Get user by username"""
        cursor = db.get_cursor()
        try:
            cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
            return cursor.fetchone()
        except psycopg2.Error as e:
            print(f"Database error: {e}")
            return None
        finally:
            cursor.close()

    @staticmethod
    def get_by_email(db, email):
        """Get user by email"""
        cursor = db.get_cursor()
        try:
            cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
            return cursor.fetchone()
        finally:
            cursor.close()

    @staticmethod
    def get_by_id(db, user_id):
        """Get user by ID"""
        cursor = db.get_cursor()
        try:
            cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
            return cursor.fetchone()
        finally:
            cursor.close()

    @staticmethod
    def check_password(user, password):
        """Verify password for user"""
        if not user or not user['password_hash']:
            return False
        return bcrypt.check_password_hash(user['password_hash'], password)

    @staticmethod
    def activate(db, user_id):
        """Activate a user"""
        cursor = db.get_cursor()
        try:
            cursor.execute("UPDATE users SET active = TRUE WHERE id = %s", (user_id,))
            return cursor.rowcount > 0
        except psycopg2.Error as e:
            print(f"Database error: {e}")
            return False
        finally:
            cursor.close()

    @staticmethod
    def deactivate(db, user_id):
        """Deactivate a user"""
        cursor = db.get_cursor()
        try:
            cursor.execute("UPDATE users SET active = FALSE WHERE id = %s", (user_id,))
            return cursor.rowcount > 0
        except psycopg2.Error as e:
            print(f"Database error: {e}")
            return False
        finally:
            cursor.close()

    @staticmethod
    def make_admin(db, user_id):
        """Grant admin privileges to a user"""
        cursor = db.get_cursor()
        try:
            cursor.execute("UPDATE users SET is_admin = TRUE WHERE id = %s", (user_id,))
            return cursor.rowcount > 0
        except psycopg2.Error as e:
            print(f"Database error: {e}")
            return False
        finally:
            cursor.close()

    @staticmethod
    def remove_admin(db, user_id):
        """Remove admin privileges from a user"""
        cursor = db.get_cursor()
        try:
            cursor.execute("UPDATE users SET is_admin = FALSE WHERE id = %s", (user_id,))
            return cursor.rowcount > 0
        except psycopg2.Error as e:
            print(f"Database error: {e}")
            return False
        finally:
            cursor.close()

    @staticmethod
    def get_pending_users(db):
        """Get all pending (inactive) users"""
        cursor = db.get_cursor()
        try:
            cursor.execute("SELECT * FROM users WHERE active = FALSE")
            return cursor.fetchall()
        except psycopg2.Error as e:
            print(f"Database error: {e}")
            return []
        finally:
            cursor.close()

    @staticmethod
    def get_all_users(db):
        """Get all users in the system"""
        cursor = db.get_cursor()
        try:
            cursor.execute("SELECT * FROM users ORDER BY created_at DESC")
            return cursor.fetchall()
        except psycopg2.Error as e:
            print(f"Database error: {e}")
            return []
        finally:
            cursor.close()

    @staticmethod
    def reset_password(db, user_id, new_password, set_reset_flag=True):
        """Reset a user's password and optionally set the password_reset flag"""
        cursor = db.get_cursor()
        try:
            password_hash = bcrypt.generate_password_hash(new_password).decode('utf-8')
            cursor.execute(
                "UPDATE users SET password_hash = %s, password_reset = %s WHERE id = %s",
                (password_hash, set_reset_flag, user_id)
            )
            return cursor.rowcount > 0
        except psycopg2.Error as e:
            print(f"Database error: {e}")
            return False
        finally:
            cursor.close()

    @staticmethod
    def clear_password_reset_flag(db, user_id):
        """Clear the password_reset flag after a user changes their password"""
        cursor = db.get_cursor()
        try:
            cursor.execute("UPDATE users SET password_reset = FALSE WHERE id = %s", (user_id,))
            return cursor.rowcount > 0
        except psycopg2.Error as e:
            print(f"Database error: {e}")
            return False
        finally:
            cursor.close()
    @staticmethod
    def generate_login_token(db, user_id, expires_in_hours=24):
        """Generate a secure login token for the user"""
        token = secrets.token_urlsafe(32)  # Generate a secure random token
        expiry = datetime.utcnow() + timedelta(hours=expires_in_hours)

        cursor = db.get_cursor()
        try:
            # Store the token in the database
            cursor.execute(
                "INSERT INTO user_tokens (user_id, token, expires_at, token_type) VALUES (%s, %s, %s, %s)",
                (user_id, token, expiry, 'login')
            )
            return token
        except Exception as e:
            print(f"Error generating login token: {e}")
            return None
        finally:
            cursor.close()

    @staticmethod
    def verify_login_token(db, token):
        """Verify a login token and return the user_id if valid"""
        cursor = db.get_cursor()
        try:
            # Get the token from the database
            cursor.execute(
                "SELECT user_id, expires_at FROM user_tokens WHERE token = %s AND token_type = %s",
                (token, 'login')
            )
            result = cursor.fetchone()

            if not result:
                return None

            user_id, expires_at = result

            # Check if token has expired
            if expires_at < datetime.utcnow():
                # Delete expired token
                cursor.execute("DELETE FROM user_tokens WHERE token = %s", (token,))
                return None

            # Token is valid - delete it so it can only be used once
            cursor.execute("DELETE FROM user_tokens WHERE token = %s", (token,))

            return user_id
        except Exception as e:
            print(f"Error verifying login token: {e}")
            return None
        finally:
            cursor.close()
    @staticmethod
    def generate_random_password(length=12):
        """Generate a random password for reset purposes"""
        # Include at least one of each: uppercase, lowercase, digit, and special character
        characters = string.ascii_lowercase + string.ascii_uppercase + string.digits + "!@#$%^&*()"

        # Ensure we have at least one of each type
        password = [
            random.choice(string.ascii_lowercase),
            random.choice(string.ascii_uppercase),
            random.choice(string.digits),
            random.choice("!@#$%^&*()")
        ]

        # Fill the rest with random characters
        password.extend(random.choice(characters) for _ in range(length - 4))

        # Shuffle the password characters
        random.shuffle(password)

        return ''.join(password)