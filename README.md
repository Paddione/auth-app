
**Features**

This code implements a web application with the following core capabilities:

1.  **User Authentication:**
    * **Standard Registration:** Users can create accounts with a username, email, and password. New registrations require administrator approval.
    * **Standard Login:** Registered and approved users can log in using their username and password.
    * **Password Reset:** Users can request a password reset via email. A temporary password is sent, and the user is forced to change it upon the next login.
    * **Password Change:** Logged-in users can change their password (either voluntarily or forced after a reset).
    * **Logout:** Users can securely log out, clearing their session.
2.  **Session Management:**
    * Uses Flask-Session with a Redis backend to manage user sessions securely.
    * Handles session persistence and expiration.
3.  **User Management (Admin Panel):**
    * An administrator dashboard allows viewing all users and pending registrations.
    * Admins can approve newly registered users.
    * Admins can deactivate existing user accounts.
    * Admins can grant or revoke administrator privileges for other users.
4.  **Email Notifications:**
    * Uses Microsoft Graph API to send emails.
    * Notifies administrators about new user registrations requiring approval.
    * Notifies users when their account is approved, including a one-time auto-login link.
    * Notifies users with a temporary password when they request a password reset.
5.  **Database Interaction:**
    * Connects to a PostgreSQL database (`psycopg2`) to store user information (credentials, status, roles).
    * Includes schema initialization/migration logic to add necessary columns if they don't exist.
    * Uses Flask-Bcrypt for secure password hashing.
6.  **Web Framework & Forms:**
    * Built using the Flask web framework.
    * Uses Flask-WTF and WTForms for form creation and validation (registration, login, password reset/change).
    * Uses Flask's `render_template` to display HTML pages and `flash` for user feedback messages.
    * Includes `ProxyFix` middleware to handle deployments behind reverse proxies correctly.
7.  **Configuration:**
    * Uses environment variables for sensitive settings like secret keys, database credentials, and Microsoft API details, promoting secure configuration practices.

**Detailed Analysis**

Let's go through each section and function.

**Part 1: Flask Application Code**

1.  **Imports:**
    * `os`: Used to access environment variables for configuration.
    * `redis`: Used to connect to the Redis server for session storage.
    * `requests`: Used to make HTTP requests to the Microsoft Graph API.
    * `msal`: Microsoft Authentication Library for Python, used for OAuth 2.0 interactions.
    * `datetime.timedelta`: Used to define the session lifetime.
    * `Flask`, `render_template`, `request`, `redirect`, `url_for`, `flash`, `session`: Core components from the Flask framework for building the web application, handling requests, responses, sessions, and user feedback.
    * `flask_session.Session`: Extension for server-side session management.
    * `flask_wtf.FlaskForm`: Base class for creating forms with WTForms.
    * `wtforms`: Fields (`StringField`, `PasswordField`, `SubmitField`, `EmailField`) and validators (`DataRequired`, `Email`, `Length`, `EqualTo`, `ValidationError`) for form handling.
    * `werkzeug.middleware.proxy_fix.ProxyFix`: Middleware to ensure Flask generates correct URLs when behind a reverse proxy.
    * `models.Database`, `models.User`: Imports the custom database connection class and the (presumably defined) User model class.

2.  **`AppConfig` Class:**
    * **Purpose:** Centralizes application configuration settings. Reads values from environment variables with sensible defaults.
    * **Attributes:**
        * `SECRET_KEY`: Crucial for session security and signing.
        * `SESSION_TYPE`, `SESSION_PERMANENT`, `SESSION_USE_SIGNER`, `SESSION_REDIS`: Configure Flask-Session to use Redis.
        * `PERMANENT_SESSION_LIFETIME`: Sets how long a session lasts (1 day).
        * `CLIENT_ID`, `CLIENT_SECRET`, `TENANT_ID`, `AUTHORITY`, `SCOPE`, `REDIRECT_PATH`, `ENDPOINT`: Configuration specific to Microsoft Azure AD application registration for OAuth and Graph API calls.
        * `ADMIN_EMAIL`, `SENDER_EMAIL`: Email addresses used for sending notifications.

3.  **App Initialization:**
    * `app = Flask(__name__)`: Creates the Flask application instance.
    * `app.config.from_object(AppConfig)`: Loads configuration from the `AppConfig` class.
    * `Session(app)`: Initializes the Flask-Session extension.
    * `app.wsgi_app = ProxyFix(...)`: Wraps the app with `ProxyFix` middleware.
    * `db = Database()`: Creates an instance of the custom `Database` class (defined later).

4.  **`MSALAuth` Class:**
    * **Purpose:** Encapsulates the logic for interacting with the Microsoft Authentication Library (MSAL).
    * **`__init__(self, app_config)`:**
        * **Input:** `app_config` (an instance or object with attributes like `CLIENT_ID`, `CLIENT_SECRET`, etc., typically `AppConfig`).
        * **Purpose:** Initializes the MSAL `ConfidentialClientApplication`, which is suitable for web apps with a backend secret. Stores necessary configuration.
    * **`get_auth_url(self, redirect_uri)`:**
        * **Input:** `redirect_uri` (string): The absolute URL within *this* application where Microsoft should redirect the user after authentication.
        * **Purpose:** Generates the Microsoft login URL that the user needs to be redirected to. Includes necessary scopes and the callback URI.
        * **Output:** A string containing the Microsoft authorization URL.
    * **`get_token_from_code(self, auth_code, redirect_uri)`:**
        * **Input:**
            * `auth_code` (string): The authorization code received from Microsoft in the redirect request.
            * `redirect_uri` (string): The same redirect URI used when requesting the code.
        * **Purpose:** Exchanges the received authorization code for an access token (and potentially a refresh token) using the MSAL library. This token is needed to call the Graph API on behalf of the user.
        * **Output:** A dictionary containing the token response from MSAL (includes `access_token`, `refresh_token`, etc.) or an error dictionary.
    * **`get_token_for_client(self)`:**
        * **Purpose:** Acquires an access token using the client credentials flow (application permissions, not user-delegated). This is used for actions the application performs itself, like sending emails from a service account (`SENDER_EMAIL`).
        * **Output:** A string containing the access token if successful, otherwise `None`.
    * **`logout(self)`:**
        * **Purpose:** Generates the URL for logging the user out of their Microsoft session. Redirecting the user here helps ensure they are fully logged out of the Microsoft identity platform.
        * **Output:** A string containing the Microsoft logout URL.
    * **`auth = MSALAuth(AppConfig)`:** Creates an instance of the `MSALAuth` helper using the application's configuration.

5.  **Form Classes (`FlaskForm` subclasses):**
    * **Purpose:** Define the structure and validation rules for HTML forms using Flask-WTF.
    * **`RegistrationForm`:** Fields for username, email, password, and password confirmation. Includes custom validators (`validate_username`, `validate_email`) to check if the username or email is already present in the database by querying the `User` model.
    * **`LoginForm`:** Fields for username and password.
    * **`ResetPasswordRequestForm`:** Field for the user's email address.
    * **`ChangePasswordForm`:** Fields for current password (optional, depending on context), new password, and confirmation.

6.  **Email Notification Functions:**
    * **`send_admin_notification(user_data)`:**
        * **Input:** `user_data` (dict): A dictionary containing the newly registered user's details (id, username, email).
        * **Purpose:** Sends an email to the administrator (`ADMIN_EMAIL`) notifying them of a new user registration that requires approval. Uses the Microsoft Graph API via the `requests` library and an application token obtained via `auth.get_token_for_client()`. Creates and sends the message using the `/users/{sender_email}/messages` and `/send` Graph API endpoints. Includes an "Approve User" link in the email body.
        * **Output:** `True` if the email sending process appears successful (API returns 202 Accepted for send), `False` otherwise. Includes print statements for debugging.
    * **`send_user_approval_notification(user_data)`:**
        * **Input:** `user_data` (dict): A dictionary containing the approved user's details.
        * **Purpose:** Sends an email to the newly approved user. Generates a short-lived, secure auto-login token using `User.generate_login_token()`. Includes a link with this token (`/auto-login/<token>`) in the email body. Uses the Graph API similarly to `send_admin_notification`.
        * **Output:** `True` if the email sending process appears successful, `False` otherwise.
    * **`send_password_reset_email(user_data, new_password)`:**
        * **Input:**
            * `user_data` (dict): The user's details.
            * `new_password` (string): The generated temporary password.
        * **Purpose:** Sends an email to the user containing their temporary password after a reset request. Uses the Graph API.
        * **Output:** `True` if the email sending process appears successful, `False` otherwise.

7.  **Flask Routes (`@app.route(...)`)**
    * **`index()` (Route: `/`)**
        * **Purpose:** Renders the home page.
        * **Input:** None.
        * **Output:** Renders `index.html`.
    * **`register()` (Route: `/register`, Methods: GET, POST)**
        * **Purpose:** Handles user registration. Displays the registration form (GET) and processes submitted data (POST).
        * **Input (POST):** Form data from `RegistrationForm`.
        * **Output:** Renders `register.html`. On successful POST validation: creates a *pending* user in the DB (`User.create` with `active=False`), calls `send_admin_notification`, flashes a message, and redirects to `login`. Redirects to `profile` if already logged in.
    * **`login()` (Route: `/login`, Methods: GET, POST)**
        * **Purpose:** Handles standard username/password login. Displays the login form (GET) and processes credentials (POST).
        * **Input (POST):** Form data from `LoginForm`.
        * **Output:** Renders `login.html`. On successful POST validation: fetches user (`User.get_by_username`), checks password (`User.check_password`), checks if `active`, checks if `password_reset` flag is set. If all checks pass, stores `user_id`, `username`, `is_admin` in the session, flashes a message, and redirects to `profile` (or `change_password` if reset is needed). Redirects to `profile` if already logged in.
    * **`reset_password_request()` (Route: `/reset-password`, Methods: GET, POST)**
        * **Purpose:** Handles the request to reset a password. Displays the email request form (GET) and processes the email (POST).
        * **Input (POST):** Form data from `ResetPasswordRequestForm`.
        * **Output:** Renders `reset_password.html`. On successful POST validation: fetches user by email (`User.get_by_email`), generates a random password (`User.generate_random_password`), updates the user's password hash and sets the `password_reset` flag (`User.reset_password`), calls `send_password_reset_email`, flashes a message, and redirects to `login`. Redirects to `profile` if already logged in.
    * **`change_password()` (Route: `/change-password`, Methods: GET, POST)**
        * **Purpose:** Allows a logged-in user to change their password. Displays the form (GET) and processes the change (POST). Handles both voluntary changes and forced changes after a reset.
        * **Input:** Reads `user_id` from session. Reads `password_reset` flag from session. (POST) Form data from `ChangePasswordForm`.
        * **Output:** Renders `change_password.html`. Redirects to `login` if not logged in. Modifies the `ChangePasswordForm` to not require the current password if `password_reset` is true in the session. On successful POST validation: checks the current password (if not forced change), updates the password hash and clears the `password_reset` flag (`User.reset_password`), removes `password_reset` from session, flashes success, redirects to `profile`.
    * **`ms_login()` (Route: `/ms-login`)**
        * **Purpose:** Initiates the Microsoft OAuth login flow.
        * **Input:** None.
        * **Output:** Generates the Microsoft authorization URL using `auth.get_auth_url` (including the callback URL for `auth_redirect`) and redirects the user's browser to it.
    * **`auth_redirect()` (Route: `/auth/redirect`)**
        * **Purpose:** Handles the callback from Microsoft after the user authenticates. Exchanges the code for a token and logs in or registers the user.
        * **Input:** Reads query parameters from the URL (`code`, `error`, `error_description`).
        * **Output:** Redirects to `login` on error. If successful: exchanges code for token (`auth.get_token_from_code`), fetches user profile from Graph API (`requests.get(AppConfig.ENDPOINT)`), checks if user exists by email (`User.get_by_email`). If user exists, logs them in (sets session). If not, creates a new, active user (`User.create` with `active=True`, `ms_auth=True`) and logs them in. Redirects to `profile`.
    * **`logout()` (Route: `/logout`)**
        * **Purpose:** Logs the user out.
        * **Input:** Reads session.
        * **Output:** Clears the session (`session.clear()`), flashes a message, redirects to `index`. (Note: It doesn't redirect to the Microsoft logout URL, meaning the user might still be signed into Microsoft).
    * **`profile()` (Route: `/profile`)**
        * **Purpose:** Displays the user's profile page.
        * **Input:** Reads `user_id` from session.
        * **Output:** Renders `profile.html`, passing user data fetched via `User.get_by_id`. Redirects to `login` if not logged in or user not found.
    * **`admin_dashboard()` (Route: `/admin`)**
        * **Purpose:** Displays the administrator dashboard with lists of pending and all users.
        * **Input:** Reads `user_id` and `is_admin` from session.
        * **Output:** Renders `admin_dashboard.html`, passing lists of users obtained via `User.get_pending_users` and `User.get_all_users`. Redirects to `login` if not logged in or not an admin.
    * **`approve_user(user_id)` (Route: `/admin/approve/<int:user_id>`)**
        * **Purpose:** Endpoint (likely linked from admin dashboard or email) for an admin to approve a pending user.
        * **Input:** `user_id` (integer from URL path). Reads admin status from session.
        * **Output:** Redirects to `login` if not admin. Fetches user (`User.get_by_id`), activates the user (`User.activate`), sends approval email (`send_user_approval_notification`), flashes message, redirects back to `admin_dashboard`.
    * **`deactivate_user(user_id)` (Route: `/admin/deactivate/<int:user_id>`)**
        * **Purpose:** Endpoint for an admin to deactivate an active user.
        * **Input:** `user_id` (integer from URL path). Reads admin status and own `user_id` from session.
        * **Output:** Redirects to `login` if not admin. Prevents self-deactivation. Deactivates the user (`User.deactivate`), flashes message, redirects back to `admin_dashboard`.
    * **`auto_login(token)` (Route: `/auto-login/<token>`)**
        * **Purpose:** Handles the one-time login link sent in the approval email.
        * **Input:** `token` (string from URL path).
        * **Output:** Verifies the token (`User.verify_login_token`). If valid, fetches the user (`User.get_by_id`), checks if active, logs the user in (sets session), flashes message, and redirects to `profile`. If token invalid/expired or user not found/inactive, flashes error and redirects to `login`. Handles edge case where user might need to set initial password.
    * **`make_admin(user_id)` (Route: `/admin/make-admin/<int:user_id>`)**
        * **Purpose:** Endpoint for an admin to grant admin privileges to another user.
        * **Input:** `user_id` (integer from URL path). Reads admin status from session.
        * **Output:** Redirects to `login` if not admin. Updates user's `is_admin` flag in DB (`User.make_admin`), flashes message, redirects to `admin_dashboard`.
    * **`remove_admin(user_id)` (Route: `/admin/remove-admin/<int:user_id>`)**
        * **Purpose:** Endpoint for an admin to revoke admin privileges from another user.
        * **Input:** `user_id` (integer from URL path). Reads admin status and own `user_id` from session.
        * **Output:** Redirects to `login` if not admin. Prevents self-revocation. Updates user's `is_admin` flag in DB (`User.remove_admin`), flashes message, redirects to `admin_dashboard`.

8.  **Main Execution Block (`if __name__ == '__main__':`)**
    * **Purpose:** Runs the Flask development server if the script is executed directly.
    * **Input:** None.
    * **Output:** Starts the web server, listening on all interfaces (`0.0.0.0`) on the default Flask port (5000), with debugging enabled (`debug=True`).

**Part 2: Database Model Code (`models.py` equivalent)**

1.  **Imports:**
    * `psycopg2`, `psycopg2.extras`: PostgreSQL adapter for Python. `extras` likely used for `DictCursor`.
    * `os`: To get database connection details from environment variables.
    * `random`, `string`: Used by `User.generate_random_password`.
    * `flask_bcrypt.Bcrypt`: Used for password hashing (`User.create`, `User.check_password`, `User.reset_password`).
    * `secrets`: Used for generating cryptographically secure tokens (`User.generate_login_token`).
    * `datetime`, `timedelta`: Used for setting token expiry (`User.generate_login_token`).
    * `bcrypt = Bcrypt()`: Initializes the Bcrypt object. *Note: It's generally better practice to initialize extensions within the Flask app context if they depend on app config, but here it seems standalone.*

2.  **`Database` Class:**
    * **Purpose:** Manages the connection to the PostgreSQL database.
    * **`__init__(self)`:** Initializes `self.conn` to `None`.
    * **`connect(self)`:**
        * **Purpose:** Establishes a connection to the database if one doesn't exist. Reads connection parameters (host, port, dbname, user, password) from environment variables. Sets `autocommit=True` (meaning each SQL statement is executed in its own transaction). Calls `_init_schema` after connecting.
        * **Output:** Returns the active `psycopg2` connection object.
    * **`_init_schema(self)`:**
        * **Purpose:** Ensures the necessary database schema (tables and columns) exists. It checks for the existence of `active`, `is_admin`, and `password_reset` columns in the `users` table and adds them if missing (`ALTER TABLE`). It also creates the `user_tokens` table if it doesn't exist. This makes the application somewhat self-migrating for these specific changes.
        * **Input:** Uses `self.conn`.
        * **Output:** Modifies the database schema if necessary. Catches and prints `psycopg2.Error`.
    * **`get_cursor(self)`:**
        * **Purpose:** Convenience method to get a database cursor, ensuring a connection is established first. Uses `DictCursor`, which allows accessing query results like dictionaries (e.g., `row['username']`).
        * **Output:** A `psycopg2.extras.DictCursor` object.
    * **`close(self)`:**
        * **Purpose:** Closes the database connection if it's open. *(Note: The implementation provided is incomplete, it should have `self.conn.close()` inside the `if` block)*. In a web app, connections are often managed per-request or using a pool, rather than a single persistent connection like this might imply.

3.  **`User` Class (Inferred Functionality):**
    * *(This class is not defined in the provided code, but its methods are called. The descriptions below are based on how these methods are used in the Flask app.)*
    * **Purpose:** Represents the User model and encapsulates all database operations related to users. Likely contains static methods that take the `db` (Database instance) as an argument.
    * **`create(db, username, email, password, active=False, ms_auth=False)`:**
        * **Input:** `db` instance, user details (`username`, `email`), `password` (or `None` for MS auth), `active` status, `ms_auth` flag.
        * **Purpose:** Inserts a new user record into the `users` table. Hashes the password using `bcrypt.generate_password_hash()` if provided. Sets the `active` status (default `False` for standard registration, `True` for MS auth). Sets `ms_auth` flag.
        * **Output:** Returns the new user's ID, or `None` on failure.
    * **`get_by_id(db, user_id)`:**
        * **Input:** `db` instance, `user_id`.
        * **Purpose:** Fetches a user record from the `users` table by their primary key ID.
        * **Output:** A dictionary-like object (from `DictCursor`) representing the user row, or `None` if not found.
    * **`get_by_username(db, username)`:**
        * **Input:** `db` instance, `username`.
        * **Purpose:** Fetches a user record by username.
        * **Output:** User row dictionary or `None`.
    * **`get_by_email(db, email)`:**
        * **Input:** `db` instance, `email`.
        * **Purpose:** Fetches a user record by email address.
        * **Output:** User row dictionary or `None`.
    * **`check_password(user, password)`:**
        * **Input:** `user` (user data dictionary), `password` (plain text password to check).
        * **Purpose:** Verifies if the provided `password` matches the stored hash (`user['password_hash']`) using `bcrypt.check_password_hash()`.
        * **Output:** `True` if the password matches, `False` otherwise.
    * **`activate(db, user_id)`:**
        * **Input:** `db` instance, `user_id`.
        * **Purpose:** Updates the user's record to set `active = TRUE`.
        * **Output:** `True` on success, `False` on failure.
    * **`deactivate(db, user_id)`:**
        * **Input:** `db` instance, `user_id`.
        * **Purpose:** Updates the user's record to set `active = FALSE`.
        * **Output:** `True` on success, `False` on failure.
    * **`get_pending_users(db)`:**
        * **Input:** `db` instance.
        * **Purpose:** Fetches all user records where `active = FALSE`.
        * **Output:** A list of user row dictionaries.
    * **`get_all_users(db)`:**
        * **Input:** `db` instance.
        * **Purpose:** Fetches all user records.
        * **Output:** A list of user row dictionaries.
    * **`reset_password(db, user_id, new_password, needs_reset_flag)`:**
        * **Input:** `db` instance, `user_id`, `new_password` (plain text), `needs_reset_flag` (boolean).
        * **Purpose:** Updates the user's `password_hash` with the hash of `new_password`. Sets the `password_reset` boolean column based on `needs_reset_flag`.
        * **Output:** `True` on success, `False` on failure.
    * **`generate_random_password(length=12)`:**
        * **Input:** Optional `length`.
        * **Purpose:** Generates a cryptographically secure random string suitable for a temporary password. Uses `random` and `string`.
        * **Output:** A random password string.
    * **`generate_login_token(db, user_id, expires_in=86400)`:**
        * **Input:** `db` instance, `user_id`, optional expiry time in seconds (default 1 day).
        * **Purpose:** Generates a secure, unique, time-limited token (using `secrets.token_urlsafe`). Stores the token, its type ('login'), user ID, and expiry timestamp in the `user_tokens` table.
        * **Output:** The generated token string, or `None` on failure.
    * **`verify_login_token(db, token)`:**
        * **Input:** `db` instance, `token` string.
        * **Purpose:** Looks up the token in the `user_tokens` table. Checks if it exists, is of type 'login', and has not expired. If valid, deletes the token (to make it single-use).
        * **Output:** The associated `user_id` if the token is valid and verified, otherwise `None`.
    * **`make_admin(db, user_id)`:**
        * **Input:** `db` instance, `user_id`.
        * **Purpose:** Updates the user's record to set `is_admin = TRUE`.
        * **Output:** `True` on success, `False` on failure.
    * **`remove_admin(db, user_id)`:**
        * **Input:** `db` instance, `user_id`.
        * **Purpose:** Updates the user's record to set `is_admin = FALSE`.
        * **Output:** `True` on success, `False` on failure.

**Class Diagram (Textual Representation)**

```
+-----------------+      +--------------------+      +-------------------+
|      Flask      |----->|    AppConfig       |      |      Redis        |
| (Application)   |      | (Configuration)    |      | (Session Backend) |
+-----------------+      +--------------------+      +-------------------+
       | 1
       | Uses 1..*
       v
+-----------------+      +--------------------+      +-------------------+
| FlaskForm       |<-----| RegistrationForm   |      |      MSALAuth     |
| (WTForms Base)  |      | LoginForm          |----->| (MSAL Wrapper)    |
+-----------------+      | ResetPassword...   |      +-------------------+
                         | ChangePasswordForm |             | 1
                         +--------------------+             | Uses
                                                            v
                                                     +-----------------+
                                                     |      msal       |
                                                     | (MS Library)    |
                                                     +-----------------+

+-----------------+      +--------------------+      +-------------------+
|      Flask      |----->|      Session       |      |      Requests     |
| (Routes/Views)  |      | (User State)       |      | (HTTP Client)     |
+-----------------+      +--------------------+      +-------------------+
   |                          ^                             |
   | Uses                     | Reads/Writes                | Calls MS Graph API
   v                          |                             v
+-----------------+           |                  +----------------------+
|      User       |<----------+------------------| send_..._notification|
| (Model Logic)   |                              | (Email Functions)    |
+-----------------+                              +----------------------+
   | 1                                                  |
   | Uses 1                                             | Uses
   v                                                    v
+-----------------+                              +-----------------+
|    Database     |----------------------------->|    psycopg2     |
| (DB Connection) |                              | (PostgreSQL Driver)|
+-----------------+                              +-----------------+
   |                                                    ^
   | Uses                                               |
   v                                                    |
+-----------------+                                     |
|     Bcrypt      |-------------------------------------+
| (Hashing)       |
+-----------------+
```

**Explanation of Diagram:**

* Arrows indicate dependencies or usage (`-->` "uses" or "depends on", `<--` inheritance/implementation).
* The `Flask` application object is central.
* It uses `AppConfig` for settings.
* It interacts with `FlaskForm` subclasses for handling web forms.
* It uses `MSALAuth` (which wraps the `msal` library) for Microsoft login.
* Routes within `Flask` call methods on the `User` model (logic).
* Email functions also use `MSALAuth` (for app tokens) and `requests` to call the Graph API.
* The `User` model uses the `Database` class to get connections/cursors.
* The `Database` class uses `psycopg2` to talk to PostgreSQL.
* `Bcrypt` is used by the `User` model (likely) and `psycopg2` for password handling.
* `Flask` uses `Session` (configured for `Redis`) to store user state between requests.

This detailed breakdown covers the features, configuration, components, and flow of the provided Flask application code.
