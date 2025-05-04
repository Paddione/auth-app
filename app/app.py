import os
import redis
import requests
import msal
from datetime import timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_session import Session
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, EmailField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError
from werkzeug.middleware.proxy_fix import ProxyFix

# Import your existing database model
from models import Database, User

# Configuration
class AppConfig:
    SECRET_KEY = os.getenv('SECRET_KEY', 'default_secret_key')
    SESSION_TYPE = 'redis'
    SESSION_PERMANENT = False
    SESSION_USE_SIGNER = True
    SESSION_REDIS = redis.Redis(
        host=os.getenv('REDIS_HOST', 'redis'),
        port=6379
    )
    PERMANENT_SESSION_LIFETIME = timedelta(days=1)

    # Microsoft Authentication settings
    CLIENT_ID = os.getenv('MS_CLIENT_ID')
    CLIENT_SECRET = os.getenv('MS_CLIENT_SECRET')
    TENANT_ID = os.getenv('MS_TENANT_ID')
    AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
    SCOPE = ['https://graph.microsoft.com/.default']
    REDIRECT_PATH = "/auth/redirect"
    ENDPOINT = "https://graph.microsoft.com/v1.0/me"

    # Email notification settings
    ADMIN_EMAIL = os.getenv('NOTIFICATION_EMAIL', 'patrick@korczewski.de')
    SENDER_EMAIL = os.getenv('SENDER_EMAIL', 'automailer@korczewski.de')

# Initialize app
app = Flask(__name__)
app.config.from_object(AppConfig)
Session(app)

# Fix for proxies - helps with URL generation when behind a reverse proxy
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Initialize database
db = Database()

# MSAL authentication helper
class MSALAuth:
    def __init__(self, app_config):
        self.client_id = app_config.CLIENT_ID
        self.client_secret = app_config.CLIENT_SECRET
        self.authority = app_config.AUTHORITY
        self.scope = app_config.SCOPE
        self.redirect_path = app_config.REDIRECT_PATH

        # Initialize MSAL app
        self.msal_app = msal.ConfidentialClientApplication(
            self.client_id,
            authority=self.authority,
            client_credential=self.client_secret
        )

    def get_auth_url(self, redirect_uri):
        """Generate authorization URL for user login"""
        return self.msal_app.get_authorization_request_url(
            self.scope,
            redirect_uri=redirect_uri,
            prompt="select_account"
        )

    def get_token_from_code(self, auth_code, redirect_uri):
        """Exchange authorization code for tokens"""
        return self.msal_app.acquire_token_by_authorization_code(
            auth_code,
            scopes=self.scope,
            redirect_uri=redirect_uri
        )

    def get_token_for_client(self):
        """Get token for application permissions (client credentials flow)"""
        result = self.msal_app.acquire_token_for_client(scopes=self.scope)
        if 'access_token' in result:
            return result['access_token']
        return None

    def logout(self):
        """Generate logout URL"""
        return f"{self.authority}/oauth2/v2.0/logout"

# Initialize auth helper
auth = MSALAuth(AppConfig)

# Form classes
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=50)])
    email = EmailField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.get_by_username(db, username.data)
        if user:
            raise ValidationError('Username already taken. Please choose a different one.')

    def validate_email(self, email):
        user = User.get_by_email(db, email.data)
        if user:
            raise ValidationError('Email already registered. Please use a different one.')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class ResetPasswordRequestForm(FlaskForm):
    email = EmailField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')

class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[])
    new_password = PasswordField('New Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('new_password')])
    submit = SubmitField('Change Password')

# Function to send email notification
def send_admin_notification(user_data):
    token = auth.get_token_for_client()
    if not token:
        print("Failed to obtain token for email notification")
        return False

    print(f"Attempting to get token for email notification")
    print(f"Token acquisition result: {{'token_type': 'Bearer', 'expires_in': 3599, 'access_token': '[REDACTED]'}}")
    print(f"Successfully obtained token, sending email notification")

    # For client credentials flow (application permissions), we need to use
    # /users/{sender_user_id} instead of /me
    # Create message as a draft first, then send it
    message_data = {
        'subject': 'New User Registration - Approval Required',
        'body': {
            'contentType': 'HTML',
            'content': f'''
            <h2>New User Registration</h2>
            <p>A new user has registered and requires approval:</p>
            <ul>
                <li><strong>Username:</strong> {user_data['username']}</li>
                <li><strong>Email:</strong> {user_data['email']}</li>
                <li><strong>User ID:</strong> {user_data['id']}</li>
            </ul>
            <p>Please log in to the admin dashboard to approve or reject this registration.</p>
            <p><a href="{request.host_url}admin/approve/{user_data['id']}">Approve User</a></p>
            '''
        },
        'toRecipients': [
            {
                'emailAddress': {
                    'address': AppConfig.ADMIN_EMAIL
                }
            }
        ]
    }

    try:
        # Extract the username from sender email (everything before @)
        sender_name = AppConfig.SENDER_EMAIL.split('@')[0]

        # First, create the message
        print(f"Creating draft message using sender: {sender_name}")
        create_response = requests.post(
            f'https://graph.microsoft.com/v1.0/users/{AppConfig.SENDER_EMAIL}/messages',
            headers={
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json'
            },
            json=message_data,
            timeout=10
        )

        print(f"Create message response: Status {create_response.status_code}")
        if create_response.status_code != 201:
            print(f"Failed to create message: {create_response.text}")
            return False

        # Get the message ID
        message_id = create_response.json().get('id')
        if not message_id:
            print("No message ID returned")
            return False

        # Send the created message
        print(f"Sending message with ID: {message_id}")
        send_response = requests.post(
            f'https://graph.microsoft.com/v1.0/users/{AppConfig.SENDER_EMAIL}/messages/{message_id}/send',
            headers={
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json'
            },
            timeout=10
        )

        print(f"Send message response: Status {send_response.status_code}")
        if send_response.status_code != 202:
            print(f"Failed to send message: {send_response.text}")

        return send_response.status_code == 202
    except Exception as e:
        print(f"Exception sending email: {str(e)}")
        return False

# Function to send user approval notification email
def send_user_approval_notification(user_data):
    token = auth.get_token_for_client()
    if not token:
        print("Failed to obtain token for approval notification email")
        return False

    # Generate a secure login token for this user
    login_token = User.generate_login_token(db, user_data['id'])
    if not login_token:
        print("Failed to generate login token")
        # Continue with regular email without the auto-login link
        auto_login_url = f"https://game.korczewski.de"
    else:
        auto_login_url = f"https://game.korczewski.de/auto-login/{login_token}"

    message_data = {
        'subject': 'Your Account Has Been Approved',
        'body': {
            'contentType': 'HTML',
            'content': f'''
            <h2>Account Approval Notification</h2>
            <p>Hello {user_data['username']},</p>
            <p>We're pleased to inform you that your account has been approved!</p>
            <p>You can now access our platform using the link below, which will automatically log you in:</p>
            <p><a href="{auto_login_url}" style="display: inline-block; background-color: #4CAF50; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; font-weight: bold;">Click here to log in automatically</a></p>
            <p>This auto-login link will expire in 24 hours for security reasons.</p>
            <p>If the link doesn't work, you can still log in manually at <a href="https://game.korczewski.de">game.korczewski.de</a> using your username and password.</p>
            <p>Thank you for joining us!</p>
            '''
        },
        'toRecipients': [
            {
                'emailAddress': {
                    'address': user_data['email']
                }
            }
        ]
    }

    try:
        # First, create the message
        create_response = requests.post(
            f'https://graph.microsoft.com/v1.0/users/{AppConfig.SENDER_EMAIL}/messages',
            headers={
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json'
            },
            json=message_data,
            timeout=10
        )

        print(f"Create message response: Status {create_response.status_code}")
        if create_response.status_code != 201:
            print(f"Failed to create message: {create_response.text}")
            return False

        # Get the message ID
        message_id = create_response.json().get('id')
        if not message_id:
            print("No message ID returned")
            return False

        # Send the created message
        print(f"Sending message with ID: {message_id}")
        send_response = requests.post(
            f'https://graph.microsoft.com/v1.0/users/{AppConfig.SENDER_EMAIL}/messages/{message_id}/send',
            headers={
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json'
            },
            timeout=10
        )

        print(f"Send message response: Status {send_response.status_code}")
        if send_response.status_code != 202:
            print(f"Failed to send message: {send_response.text}")
            return False

        return send_response.status_code == 202
    except Exception as e:
        print(f"Exception sending approval email: {str(e)}")
        return False

# Function to send password reset email
def send_password_reset_email(user_data, new_password):
    token = auth.get_token_for_client()
    if not token:
        print("Failed to obtain token for password reset email")
        return False

    print(f"Attempting to get token for password reset email")
    print(f"Successfully obtained token, sending password reset email")

    message_data = {
        'subject': 'Your Password Has Been Reset',
        'body': {
            'contentType': 'HTML',
            'content': f'''
            <h2>Password Reset</h2>
            <p>Hello {user_data['username']},</p>
            <p>Your password has been reset as requested. Your temporary password is:</p>
            <p><strong>{new_password}</strong></p>
            <p>Please log in with this temporary password. You will be required to change it immediately upon login.</p>
            <p>If you did not request this password reset, please contact the administrator immediately.</p>
            <p><a href="{request.host_url}login">Login to your account</a></p>
            '''
        },
        'toRecipients': [
            {
                'emailAddress': {
                    'address': user_data['email']
                }
            }
        ]
    }

    try:
        # First, create the message
        create_response = requests.post(
            f'https://graph.microsoft.com/v1.0/users/{AppConfig.SENDER_EMAIL}/messages',
            headers={
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json'
            },
            json=message_data,
            timeout=10
        )

        print(f"Create message response: Status {create_response.status_code}")
        if create_response.status_code != 201:
            print(f"Failed to create message: {create_response.text}")
            return False

        # Get the message ID
        message_id = create_response.json().get('id')
        if not message_id:
            print("No message ID returned")
            return False

        # Send the created message
        print(f"Sending message with ID: {message_id}")
        send_response = requests.post(
            f'https://graph.microsoft.com/v1.0/users/{AppConfig.SENDER_EMAIL}/messages/{message_id}/send',
            headers={
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json'
            },
            timeout=10
        )

        print(f"Send message response: Status {send_response.status_code}")
        if send_response.status_code != 202:
            print(f"Failed to send message: {send_response.text}")
            return False

        return send_response.status_code == 202
    except Exception as e:
        print(f"Exception sending password reset email: {str(e)}")
        return False

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    # If user is already logged in, redirect to profile
    if 'user_id' in session:
        return redirect(url_for('profile'))

    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data

        # Create user with status pending (not activated)
        user_id = User.create(db, username, email, password, active=False)
        if user_id:
            # Get the user data for email notification
            user_data = User.get_by_id(db, user_id)

            # Send notification email to admin
            email_sent = send_admin_notification(user_data)

            if email_sent:
                flash('Your account has been created! An administrator will approve your account soon.', 'success')
            else:
                flash('Your account has been created, but admin notification failed. Please contact support.', 'warning')

            return redirect(url_for('login'))
        else:
            flash('Registration failed. Please try again.', 'danger')

    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    # If user is already logged in, redirect to profile
    if 'user_id' in session:
        return redirect(url_for('profile'))

    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        user = User.get_by_username(db, username)

        if user and User.check_password(user, password):
            # Check if user is active/approved
            if not user['active']:
                flash('Your account has not been activated yet. Please wait for administrator approval.', 'warning')
                return render_template('login.html', form=form)

            # Set session data
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_admin'] = user.get('is_admin', False)

            # Check if this is a reset password that needs to be changed
            if user['password_reset']:
                session['password_reset'] = True
                flash('You must change your temporary password before continuing.', 'warning')
                return redirect(url_for('change_password'))

            flash('You have successfully logged in!', 'success')
            return redirect(url_for('profile'))
        else:
            flash('Login unsuccessful. Please check your username and password.', 'danger')

    return render_template('login.html', form=form)

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password_request():
    # If user is already logged in, redirect to profile
    if 'user_id' in session:
        return redirect(url_for('profile'))

    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        email = form.email.data
        user = User.get_by_email(db, email)

        if user:
            # Generate a random password
            new_password = User.generate_random_password()

            # Update the user's password in the database with reset flag
            if User.reset_password(db, user['id'], new_password, True):
                # Send the password reset email
                if send_password_reset_email(user, new_password):
                    flash('A password reset email has been sent with your temporary password.', 'success')
                else:
                    flash('Failed to send password reset email. Please contact support.', 'danger')
            else:
                flash('Failed to reset password. Please try again later.', 'danger')
        else:
            # Don't reveal that email doesn't exist for security reasons
            flash('A password reset email has been sent if the email exists in our system.', 'info')

        return redirect(url_for('login'))

    return render_template('reset_password.html', form=form)

@app.route('/change-password', methods=['GET', 'POST'])
def change_password():
    # Check if user is logged in
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('login'))

    user = User.get_by_id(db, session['user_id'])
    if not user:
        # If user not found, clear session and redirect to login
        session.clear()
        flash('User not found. Please log in again.', 'warning')
        return redirect(url_for('login'))

    # Check if this is a forced password change
    force_change = session.get('password_reset', False)

    form = ChangePasswordForm()

    # If it's a forced change after reset, we don't need current password
    if force_change:
        form.current_password.validators = []
    else:
        form.current_password.validators = [DataRequired()]

    if form.validate_on_submit():
        # Verify current password if not a forced change
        valid_current = True
        if not force_change:
            current_password = form.current_password.data
            valid_current = User.check_password(user, current_password)

        if valid_current:
            new_password = form.new_password.data

            # Update the password and clear the reset flag
            if User.reset_password(db, user['id'], new_password, False):
                # Clear the password_reset session flag if it exists
                if 'password_reset' in session:
                    session.pop('password_reset')

                flash('Your password has been updated successfully.', 'success')
                return redirect(url_for('profile'))
            else:
                flash('Failed to update password. Please try again.', 'danger')
        else:
            flash('Current password is incorrect.', 'danger')

    return render_template('change_password.html', form=form, force_change=force_change)

@app.route('/ms-login')
def ms_login():
    """Microsoft OAuth login route"""
    redirect_uri = url_for('auth_redirect', _external=True)
    auth_url = auth.get_auth_url(redirect_uri)
    return redirect(auth_url)

@app.route('/auth/redirect')
def auth_redirect():
    """Handle redirect from Microsoft OAuth"""
    if 'error' in request.args:
        flash(f"Login error: {request.args.get('error_description', 'Unknown error')}", 'danger')
        return redirect(url_for('login'))

    # Get auth code from query parameters
    code = request.args.get('code')
    if not code:
        flash('Authentication failed. No code received.', 'danger')
        return redirect(url_for('login'))

    # Exchange code for tokens
    redirect_uri = url_for('auth_redirect', _external=True)
    result = auth.get_token_from_code(code, redirect_uri)

    if 'access_token' not in result:
        flash('Failed to obtain access token.', 'danger')
        return redirect(url_for('login'))

    # Get user info from Microsoft Graph
    graph_data = requests.get(
        AppConfig.ENDPOINT,
        headers={'Authorization': f"Bearer {result['access_token']}"},
        timeout=10
    ).json()

    if 'error' in graph_data:
        flash(f"Error getting user data: {graph_data.get('error_description', 'Unknown error')}", 'danger')
        return redirect(url_for('login'))

    # Check if user exists by email
    email = graph_data.get('mail') or graph_data.get('userPrincipalName')
    if not email:
        flash('Could not retrieve email from Microsoft account.', 'danger')
        return redirect(url_for('login'))

    user = User.get_by_email(db, email)

    if user:
        # User exists, log them in
        session['user_id'] = user['id']
        session['username'] = user['username']
        session['is_admin'] = user.get('is_admin', False)
        flash('You have successfully logged in with Microsoft!', 'success')
    else:
        # User doesn't exist, create a new account
        # Use display name or email as username (could be customized)
        username = graph_data.get('displayName') or email.split('@')[0]

        # Create user with Microsoft auth
        user_id = User.create(db, username, email, None, active=True, ms_auth=True)
        if user_id:
            session['user_id'] = user_id
            session['username'] = username
            session['is_admin'] = False
            flash('Account created successfully with Microsoft authentication!', 'success')
        else:
            flash('Failed to create account. Please try again later.', 'danger')
            return redirect(url_for('login'))

    return redirect(url_for('profile'))

@app.route('/logout')
def logout():
    """Logout user"""
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))

@app.route('/profile')
def profile():
    """User profile page"""
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('login'))

    user = User.get_by_id(db, session['user_id'])
    if not user:
        session.clear()
        flash('User not found. Please log in again.', 'warning')
        return redirect(url_for('login'))

    return render_template('profile.html', user=user)

@app.route('/admin')
def admin_dashboard():
    """Admin dashboard page"""
    if 'user_id' not in session or not session.get('is_admin', False):
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('login'))

    pending_users = User.get_pending_users(db)
    all_users = User.get_all_users(db)

    return render_template('admin_dashboard.html', pending_users=pending_users, all_users=all_users)

@app.route('/admin/approve/<int:user_id>')
def approve_user(user_id):
    """Approve a user account"""
    if 'user_id' not in session or not session.get('is_admin', False):
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('login'))

    # Get the user to be approved
    user = User.get_by_id(db, user_id)
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('admin_dashboard'))

    # Activate the user
    if User.activate(db, user_id):
        # Send approval notification email to the user
        email_sent = send_user_approval_notification(user)

        if email_sent:
            flash(f'User {user["username"]} has been approved and notified.', 'success')
        else:
            flash(f'User {user["username"]} has been approved, but email notification failed.', 'warning')
    else:
        flash('Failed to approve user. Please try again.', 'danger')

    return redirect(url_for('admin_dashboard'))

@app.route('/admin/deactivate/<int:user_id>')
def deactivate_user(user_id):
    """Deactivate a user account"""
    if 'user_id' not in session or not session.get('is_admin', False):
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('login'))

    # Prevent self-deactivation
    if user_id == session['user_id']:
        flash('You cannot deactivate your own account.', 'warning')
        return redirect(url_for('admin_dashboard'))

    if User.deactivate(db, user_id):
        flash('User has been deactivated.', 'success')
    else:
        flash('Failed to deactivate user. Please try again.', 'danger')

    return redirect(url_for('admin_dashboard'))

@app.route('/auto-login/<token>')
def auto_login(token):
    """Handle auto-login with tokens"""
    # Verify the token and get the user ID
    user_id = User.verify_login_token(db, token)

    if not user_id:
        flash('Invalid or expired login link. Please log in manually.', 'danger')
        return redirect(url_for('login'))

    # Get the user
    user = User.get_by_id(db, user_id)
    if not user:
        flash('User not found. Please log in manually.', 'danger')
        return redirect(url_for('login'))

    # Check if user is active
    if not user['active']:
        flash('Your account has not been activated yet.', 'warning')
        return redirect(url_for('login'))

    # Set session data
    session['user_id'] = user['id']
    session['username'] = user['username']
    session['is_admin'] = user.get('is_admin', False)

    # If this is a first-time login, send them to change password
    if not user['password_hash'] or user['password_reset']:
        session['password_reset'] = True
        flash('Please set your password to continue.', 'info')
        return redirect(url_for('change_password'))

    flash('You have been automatically logged in!', 'success')
    return redirect(url_for('profile'))

@app.route('/admin/make-admin/<int:user_id>')
def make_admin(user_id):
    """Make a user an admin"""
    if 'user_id' not in session or not session.get('is_admin', False):
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('login'))

    if User.make_admin(db, user_id):
        flash('User has been granted admin privileges.', 'success')
    else:
        flash('Failed to grant admin privileges. Please try again.', 'danger')

    return redirect(url_for('admin_dashboard'))

@app.route('/admin/remove-admin/<int:user_id>')
def remove_admin(user_id):
    """Remove admin privileges from a user"""
    if 'user_id' not in session or not session.get('is_admin', False):
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('login'))

    # Prevent removing own admin privileges
    if user_id == session['user_id']:
        flash('You cannot remove your own admin privileges.', 'warning')
        return redirect(url_for('admin_dashboard'))

    if User.remove_admin(db, user_id):
        flash('Admin privileges have been removed from user.', 'success')
    else:
        flash('Failed to remove admin privileges. Please try again.', 'danger')

    return redirect(url_for('admin_dashboard'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)