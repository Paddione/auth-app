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
    REDIRECT_PATH = "/ms-login"
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
        print("Token acquisition result:", result)  # Add this for debugging
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

# Function to send email notification
def send_admin_notification(user_data):
    print("Attempting to get token for email notification")
    token = auth.get_token_for_client()
    if not token:
        print("Failed to obtain token for email notification")
        print("Auth object state:", vars(auth))  # Print auth object details
        return False

    print("Successfully obtained token, sending email notification")

    # Email content
    email_data = {
        'message': {
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
            'from': {
                'emailAddress': {
                    'address': AppConfig.SENDER_EMAIL
                }
            },
            'toRecipients': [
                {
                    'emailAddress': {
                        'address': AppConfig.ADMIN_EMAIL
                    }
                }
            ]
        }
    }

    # Send email using Microsoft Graph API
    response = requests.post(
        'https://graph.microsoft.com/v1.0/users/me/sendMail',
        headers={
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        },
        json=email_data
    )

    return response.status_code == 202

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

            flash('You have successfully logged in!', 'success')
            return redirect(url_for('profile'))
        else:
            flash('Login unsuccessful. Please check your username and password.', 'danger')

    return render_template('login.html', form=form)

@app.route('/ms-login')
def ms_login():
    """Microsoft OAuth login route"""
    redirect_uri = url_for('auth_redirect', _external=True)
    auth_url = auth.get_auth_url(redirect_uri)
    return redirect(auth_url)

@app.route(AppConfig.REDIRECT_PATH)
def auth_redirect():
    """Handle Microsoft OAuth redirect"""
    redirect_uri = url_for('auth_redirect', _external=True)
    token_result = auth.get_token_from_code(request.args.get('code'), redirect_uri)

    if 'error' in token_result:
        flash(f"Authentication error: {token_result.get('error_description', 'Unknown error')}", 'danger')
        return redirect(url_for('login'))

    # Get user info from Microsoft Graph
    user_info = requests.get(
        AppConfig.ENDPOINT,
        headers={'Authorization': f"Bearer {token_result['access_token']}"},
        timeout=30
    ).json()

    # Check if user exists in our database
    email = user_info.get('mail') or user_info.get('userPrincipalName')
    user = User.get_by_email(db, email)

    if not user:
        # Automatically register the user
        username = user_info.get('displayName', '').replace(' ', '_').lower()
        base_username = username
        counter = 1

        # Ensure username is unique
        while User.get_by_username(db, username):
            username = f"{base_username}_{counter}"
            counter += 1

        # Create user with Microsoft login and auto-activated
        user_id = User.create(db, username, email, None, active=True, ms_auth=True)
        user = User.get_by_id(db, user_id)
    elif not user['active']:
        # Activate user if they were pending
        User.activate(db, user['id'])
        user['active'] = True

    # Set session data
    session['user_id'] = user['id']
    session['username'] = user['username']
    session['is_admin'] = user.get('is_admin', False)
    session['ms_auth'] = True

    flash('You have successfully logged in with Microsoft!', 'success')
    return redirect(url_for('profile'))

@app.route('/profile')
def profile():
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

    return render_template('profile.html', user=user)

@app.route('/admin/approve/<int:user_id>', methods=['GET'])
def approve_user(user_id):
    # Check if user is logged in and is admin
    if 'user_id' not in session or not session.get('is_admin', False):
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('login'))

    if User.activate(db, user_id):
        flash('User has been approved and activated.', 'success')
    else:
        flash('Failed to activate user.', 'danger')

    return redirect(url_for('admin_dashboard'))

@app.route('/admin/dashboard')
def admin_dashboard():
    # Check if user is logged in and is admin
    if 'user_id' not in session or not session.get('is_admin', False):
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('login'))

    # Get all pending users
    pending_users = User.get_pending_users(db)

    return render_template('admin_dashboard.html', pending_users=pending_users)

@app.route('/logout')
def logout():
    # Check if user was logged in with Microsoft
    ms_auth = session.get('ms_auth', False)

    # Clear session
    session.clear()
    flash('You have been logged out.', 'info')

    # If Microsoft auth was used, redirect to Microsoft logout
    if ms_auth:
        logout_url = auth.logout()
        return_url = url_for('login', _external=True)
        return redirect(f"{logout_url}?post_logout_redirect_uri={return_url}")

    return redirect(url_for('login'))

@app.teardown_appcontext
def close_db(error):
    db.close()

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)