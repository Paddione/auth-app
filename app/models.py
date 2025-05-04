import psycopg2
import psycopg2.extras
import os
from flask_bcrypt import Bcrypt

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

            # Ensure the users table has the active field
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
    def create(db, username, email, password, active=False):
        password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        cursor = db.get_cursor()
        try:
            cursor.execute(
                "INSERT INTO users (username, email, password_hash, active) VALUES (%s, %s, %s, %s) RETURNING id",
                (username, email, password_hash, active)
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
        cursor = db.get_cursor()
        try:
            cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
            return cursor.fetchone()
        finally:
            cursor.close()

    @staticmethod
    def get_by_id(db, user_id):
        cursor = db.get_cursor()
        try:
            cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
            return cursor.fetchone()
        finally:
            cursor.close()

    @staticmethod
    def check_password(user, password):
        if not user:
            return False
        return bcrypt.check_password_hash(user['password_hash'], password)

    @staticmethod
    def activate(db, user_id):
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
    def get_pending_users(db):
        cursor = db.get_cursor()
        try:
            cursor.execute("SELECT * FROM users WHERE active = FALSE")
            return cursor.fetchall()
        except psycopg2.Error as e:
            print(f"Database error: {e}")
            return []
        finally:
            cursor.close()