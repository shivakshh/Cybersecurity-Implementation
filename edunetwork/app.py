from flask import Flask, render_template, redirect, url_for, session, request, jsonify, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from authlib.integrations.flask_client import OAuth
import os
import sqlite3
import requests
import pyotp
import qrcode
import io
import base64
from datetime import datetime, timedelta
import hashlib
import json

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')

# Database path configuration
DB_DIR = os.environ.get("DB_DIR", ".")  # On Render: /opt/render/project/data
DB_PATH = os.path.join(DB_DIR, "edunetwork.db")


# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# OAuth Configuration
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET')
GITHUB_CLIENT_ID = os.environ.get('GITHUB_CLIENT_ID')
GITHUB_CLIENT_SECRET = os.environ.get('GITHUB_CLIENT_SECRET')

# Initialize OAuth
oauth = OAuth(app)

# Configure Google OAuth
google = oauth.register(
    name='google',
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile'
    }
)

# Configure GitHub OAuth
github = oauth.register(
    name='github',
    client_id=GITHUB_CLIENT_ID,
    client_secret=GITHUB_CLIENT_SECRET,
    access_token_url='https://github.com/login/oauth/access_token',
    authorize_url='https://github.com/login/oauth/authorize',
    api_base_url='https://api.github.com/',
    client_kwargs={'scope': 'user:email'},
)

class User:
    def __init__(self, id, oauth_provider, oauth_id, email, name, totp_secret=None, mfa_enabled=False, created_at=None, last_login=None):
        self.id = id
        self.oauth_provider = oauth_provider
        self.oauth_id = oauth_id
        self.email = email
        self.name = name
        self.totp_secret = totp_secret
        self.mfa_enabled = mfa_enabled
        self.created_at = created_at
        self.last_login = last_login
    
    def is_authenticated(self):
        return True
    
    def is_active(self):
        return True
    
    def is_anonymous(self):
        return False
    
    def get_id(self):
        return str(self.id)

@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user_data = cursor.fetchone()
    conn.close()
    
    if user_data:
        return User(*user_data)
    return None

def init_database():
    """Initialize the database with required tables"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            oauth_provider VARCHAR(20) NOT NULL,
            oauth_id VARCHAR(100) NOT NULL,
            email VARCHAR(120) UNIQUE NOT NULL,
            name VARCHAR(100) NOT NULL,
            totp_secret VARCHAR(32),
            mfa_enabled BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )
    ''')
    
    # Login history table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS login_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            ip_address VARCHAR(45) NOT NULL,
            location VARCHAR(100),
            country VARCHAR(2),
            login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            mfa_required BOOLEAN DEFAULT 0,
            success BOOLEAN DEFAULT 1,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Courses table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS courses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title VARCHAR(200) NOT NULL,
            description TEXT,
            content TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # User activity table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_activity (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            course_id INTEGER,
            activity_type VARCHAR(50),
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (course_id) REFERENCES courses (id)
        )
    ''')
    
    # Insert sample courses
    cursor.execute('SELECT COUNT(*) FROM courses')
    if cursor.fetchone()[0] == 0:
        sample_courses = [
            ("Introduction to Web Development", "Learn HTML, CSS, and JavaScript basics", "Welcome to web development! This course covers the fundamentals of creating websites and web applications. You'll learn HTML for structure, CSS for styling, and JavaScript for interactivity."),
            ("Python Programming Fundamentals", "Master Python from basics to advanced concepts", "Python is a versatile programming language used in web development, data science, automation, and more. This comprehensive course takes you from beginner to advanced Python programmer."),
            ("Cybersecurity Essentials", "Understanding modern security practices", "In today's digital world, security is paramount. Learn about threats, vulnerabilities, secure coding practices, and how to protect systems and data from cyber attacks.")
        ]
        cursor.executemany('INSERT INTO courses (title, description, content) VALUES (?, ?, ?)', sample_courses)
    
    conn.commit()
    conn.close()

def get_location_from_ip(ip_address):
    """Get location information from IP address"""
    try:
        # Using a free IP geolocation service
        response = requests.get(f'https://ipapi.co/{ip_address}/json/', timeout=5)
        if response.status_code == 200:
            data = response.json()
            return {
                'country': data.get('country_code', 'Unknown'),
                'city': data.get('city', 'Unknown'),
                'region': data.get('region', 'Unknown')
            }
    except:
        pass
    return {'country': 'Unknown', 'city': 'Unknown', 'region': 'Unknown'}

def is_risky_login(user_id, current_ip):
    if not current_ip:
        return True  # unknown IP → require MFA

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT DISTINCT ip_address, country FROM login_history
        WHERE user_id = ? AND success = 1
    ''', (user_id,))
    history = cursor.fetchall()
    conn.close()

    # Get current location
    current_location = get_location_from_ip(current_ip)
    current_country = current_location.get('country', 'Unknown')
    
    # If no history → first login → require MFA
    if not history:
        return True

    # Check if country or IP is new → risky
    known_countries = [row[1] for row in history if row[1] and row[1] != 'Unknown']
    known_ips = [row[0] for row in history if row[0]]

    if current_country not in known_countries:
        print(f"New country detected: {current_country}")  # Debug log
        return True  # Trigger MFA

    if current_ip not in known_ips:
        print(f"New IP detected: {current_ip}")  # Debug log
        return True  # Trigger MFA

    return False



def log_login_attempt(user_id, ip_address, success=True, mfa_required=False):
    """Log login attempt to database"""
    location_data = get_location_from_ip(ip_address)
    city = location_data.get('city') or 'N/A'
    region = location_data.get('region') or 'N/A'
    country = location_data.get('country') or 'N/A'

    location_str = f"{city}, {region}, {country}"
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO login_history (user_id, ip_address, location, country, mfa_required, success)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (user_id, ip_address, location_str, location_data['country'], mfa_required, success))
    conn.commit()
    conn.close()

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('base.html')

@app.route('/login')
def login():
    return render_template('base.html')

@app.route('/auth/<provider>')
def oauth_login(provider):
    """Initiate OAuth login with specified provider"""
    if provider == 'google':
        redirect_uri = url_for('oauth_callback', provider='google', _external=True)
        return google.authorize_redirect(redirect_uri)
    elif provider == 'github':
        redirect_uri = url_for('oauth_callback', provider='github', _external=True)
        return github.authorize_redirect(redirect_uri)
    else:
        flash('Invalid OAuth provider', 'error')
        return redirect(url_for('login'))

@app.route('/callback/<provider>')
def oauth_callback(provider):
    """Handle OAuth callback"""
    try:
        if provider == 'google':
            token = google.authorize_access_token()
            user_info = token.get('userinfo')
            if user_info:
                user_data = {
                    'id': user_info['sub'],
                    'email': user_info['email'],
                    'name': user_info['name']
                }
            else:
                raise Exception("Failed to get user info from Google")
                
        elif provider == 'github':
            token = github.authorize_access_token()
            resp = github.get('user', token=token)
            user_info = resp.json()
            
            # Get user email (GitHub might not provide it in the user endpoint)
            email_resp = github.get('user/emails', token=token)
            emails = email_resp.json()
            primary_email = next((email['email'] for email in emails if email['primary']), user_info.get('email'))
            
            user_data = {
                'id': str(user_info['id']),
                'email': primary_email,
                'name': user_info.get('name') or user_info.get('login')
            }
        else:
            flash('Invalid OAuth provider', 'error')
            return redirect(url_for('login'))
    
    except Exception as e:
        flash(f'OAuth authentication failed: {str(e)}', 'error')
        return redirect(url_for('login'))
    
    # Check if user exists or create new user
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE oauth_provider = ? AND oauth_id = ?', 
                  (provider, user_data['id']))
    existing_user = cursor.fetchone()
    
    if not existing_user:
        # Create new user
        cursor.execute('''
            INSERT INTO users (oauth_provider, oauth_id, email, name)
            VALUES (?, ?, ?, ?)
        ''', (provider, user_data['id'], user_data['email'], user_data['name']))
        conn.commit()
        user_id = cursor.lastrowid
    else:
        user_id = existing_user[0]
    
    conn.close()
    
    # Check if MFA is required
    if request.headers.get('X-Forwarded-For'):
        client_ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
    else:
        client_ip = request.remote_addr
    
    mfa_required = is_risky_login(user_id, client_ip)
    
    user = load_user(user_id)
    
    # Fixed logic: Check if MFA setup is needed
    if mfa_required or user.mfa_enabled:
        session['pending_user_id'] = user_id
        session['mfa_required'] = True
        log_login_attempt(user_id, client_ip, success=False, mfa_required=True)
        
        # NEW: Check if user has TOTP secret set up
        if not user.totp_secret:
            # User needs to set up MFA first
            return redirect(url_for('mfa_setup'))
        else:
            # User has MFA set up, go to verification
            return redirect(url_for('mfa_verify'))
    else:
        login_user(user)
        log_login_attempt(user_id, client_ip, success=True, mfa_required=False)
        return redirect(url_for('dashboard'))



@app.route('/mfa/setup', methods=['GET', 'POST'])
def mfa_setup():
    """Setup MFA for user"""
    # Handle both logged-in users and pending OAuth users
    if current_user.is_authenticated:
        user = current_user
    elif 'pending_user_id' in session:
        user = load_user(session['pending_user_id'])
        if not user:
            flash('Session expired. Please log in again.', 'error')
            return redirect(url_for('login'))
    else:
        flash('Please log in first.', 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        # Handle MFA setup completion
        token = request.form.get('token')
        if not token:
            flash('Please enter the verification code.', 'error')
            return render_template('base.html', qr_code=session.get('qr_code'), secret=user.totp_secret)
        
        # Verify the token
        totp = pyotp.TOTP(user.totp_secret)
        if totp.verify(token):
            # Enable MFA and complete setup
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute('UPDATE users SET mfa_enabled = 1 WHERE id = ?', (user.id,))
            conn.commit()
            conn.close()
            
            # If this was during OAuth flow, complete the login
            if 'pending_user_id' in session:
                login_user(user)
                client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
                log_login_attempt(user.id, client_ip, success=True, mfa_required=True)
                del session['pending_user_id']
                del session['mfa_required']
                if 'qr_code' in session:
                    del session['qr_code']
            
            flash('MFA has been successfully enabled!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid verification code. Please try again.', 'error')
            return render_template('base.html', qr_code=session.get('qr_code'), secret=user.totp_secret)
    
    # GET request - show setup page
    if not user.totp_secret:
        secret = pyotp.random_base32()
        
        # Update user with TOTP secret
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET totp_secret = ? WHERE id = ?', 
                      (secret, user.id))
        conn.commit()
        conn.close()
        
        user.totp_secret = secret
    
    # Generate QR code
    totp_uri = pyotp.totp.TOTP(user.totp_secret).provisioning_uri(
        user.email,
        issuer_name="EduNetwork"
    )
    
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(totp_uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    buffered = io.BytesIO()
    img.save(buffered)
    img_str = base64.b64encode(buffered.getvalue()).decode()
    
    # Store QR code in session for POST request
    session['qr_code'] = img_str
    
    return render_template('base.html', qr_code=img_str, secret=user.totp_secret)

@app.route('/dashboard')
@login_required
def dashboard():
    """User dashboard"""
    # Get courses
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM courses')
    courses = cursor.fetchall()
    
    # Get recent login history
    cursor.execute('''
        SELECT ip_address, location, login_time, mfa_required 
        FROM login_history 
        WHERE user_id = ? AND success = 1
        ORDER BY login_time DESC LIMIT 5
    ''', (current_user.id,))
    login_history = cursor.fetchall()
    
    conn.close()
    
    return render_template('base.html', courses=courses, login_history=login_history)

@app.route('/course/<int:course_id>')
@login_required  
def view_course(course_id):
    """View course content"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM courses WHERE id = ?', (course_id,))
    course = cursor.fetchone()
    
    if course:
        # Log course view activity
        cursor.execute('''
            INSERT INTO user_activity (user_id, course_id, activity_type)
            VALUES (?, ?, ?)
        ''', (current_user.id, course_id, 'course_view'))
        conn.commit()
    
    conn.close()
    
    if not course:
        flash('Course not found', 'error')
        return redirect(url_for('dashboard'))
    
    return render_template('base.html', course=course)
@app.route('/mfa/verify', methods=['GET', 'POST'])
def mfa_verify():
    """Verify MFA token after login attempt"""
    # User should be pending MFA at this stage
    if 'pending_user_id' not in session:
        flash('Session expired. Please log in again.', 'error')
        return redirect(url_for('login'))

    user = load_user(session['pending_user_id'])
    if not user:
        flash('User not found. Please log in again.', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        token = request.form.get('token')
        if not token:
            flash('Please enter your authentication code.', 'error')
            return render_template('base.html')

        totp = pyotp.TOTP(user.totp_secret)
        if totp.verify(token):
            # ✅ Success
            login_user(user)
            client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
            log_login_attempt(user.id, client_ip, success=True, mfa_required=True)

            # Clear session keys
            session.pop('pending_user_id', None)
            session.pop('mfa_required', None)

            flash('MFA verification successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid or expired code. Please try again.', 'error')
            return render_template('base.html')

    # GET → render verification page
    return render_template('base.html')

@app.route('/logout')
@login_required
def logout():
    """Logout user"""
    logout_user()
    flash('You have been logged out successfully', 'info')
    return redirect(url_for('login'))

# Ensure DB initialized on Render (Gunicorn won't hit __main__)
if os.environ.get("RENDER", "false").lower() == "true":
    init_database()

if __name__ == '__main__':
    init_database()
    app.run(debug=True)
