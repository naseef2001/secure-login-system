"""
Project Setup Script for Secure Login System
Run this to create all necessary files
"""

import os

# Create directories
os.makedirs('app/models', exist_ok=True)
os.makedirs('app/routes', exist_ok=True)
os.makedirs('app/templates', exist_ok=True)
os.makedirs('app/static/css', exist_ok=True)
os.makedirs('app/static/js', exist_ok=True)
os.makedirs('screenshots', exist_ok=True)
os.makedirs('.github/workflows', exist_ok=True)

print("✓ Directories created")

# ============ app/__init__.py ============
with open('app/__init__.py', 'w', encoding='utf-8') as f:
    f.write("""from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
import os
from dotenv import load_dotenv

load_dotenv()

db = SQLAlchemy()
bcrypt = Bcrypt()
login_manager = LoginManager()

def create_app():
    app = Flask(__name__)
    
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-12345')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///secure_login.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['MAX_LOGIN_ATTEMPTS'] = 5
    app.config['ACCOUNT_LOCKOUT_DURATION'] = 30
    
    db.init_app(app)
    bcrypt.init_app(app)
    login_manager.init_app(app)
    
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access this page.'
    
    from app.routes import auth, admin
    app.register_blueprint(auth.bp)
    app.register_blueprint(admin.bp)
    
    with app.app_context():
        db.create_all()
        print("Database tables created successfully!")
    
    return app
""")

# ============ app/models/user.py ============
with open('app/models/user.py', 'w', encoding='utf-8') as f:
    f.write("""from datetime import datetime, timedelta
from flask_login import UserMixin
from app import db, login_manager
from werkzeug.security import generate_password_hash, check_password_hash

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='user')
    is_active = db.Column(db.Boolean, default=True)
    is_approved = db.Column(db.Boolean, default=False)
    approved_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    approved_at = db.Column(db.DateTime, nullable=True)
    login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    last_failed_attempt = db.Column(db.DateTime, nullable=True)
    
    approver = db.relationship('User', remote_side=[id], foreign_keys=[approved_by])
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def is_locked(self):
        if self.locked_until and datetime.utcnow() < self.locked_until:
            return True
        return False
    
    def increment_login_attempts(self):
        self.login_attempts += 1
        self.last_failed_attempt = datetime.utcnow()
        if self.login_attempts >= 5:
            self.locked_until = datetime.utcnow() + timedelta(minutes=30)
            return True
        return False
    
    def reset_login_attempts(self):
        self.login_attempts = 0
        self.locked_until = None
        self.last_failed_attempt = None
    
    def get_remaining_attempts(self):
        return max(0, 5 - self.login_attempts)
    
    def get_lockout_remaining_time(self):
        if self.locked_until and datetime.utcnow() < self.locked_until:
            remaining = (self.locked_until - datetime.utcnow()).total_seconds() / 60
            return int(remaining)
        return 0
    
    def is_admin(self):
        return self.role == 'admin' and self.is_approved
    
    def is_user(self):
        return self.role == 'user' and self.is_approved
    
    def is_pending(self):
        return not self.is_approved
    
    def can_login(self):
        return self.is_approved and self.is_active

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
""")

# ============ app/routes/auth.py ============
with open('app/routes/auth.py', 'w', encoding='utf-8') as f:
    f.write("""from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from flask_login import login_user, logout_user, login_required, current_user
from datetime import datetime
from app import db
from app.models.user import User
import re
import random
import string

bp = Blueprint('auth', __name__)

def generate_captcha():
    captcha = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    session['captcha'] = captcha
    return captcha

def validate_input(data):
    if data:
        dangerous_patterns = ['--', ';', '/*', '*/', 'select', 'insert', 'delete', 'update', 'drop', 'union', 'exec']
        for pattern in dangerous_patterns:
            if pattern in data.lower():
                return False
    return True

@bp.route('/')
def index():
    return redirect(url_for('auth.login'))

@bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if current_user.is_admin():
            return redirect(url_for('admin.dashboard'))
        return redirect(url_for('auth.dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        captcha_input = request.form.get('captcha')
        captcha_session = session.get('captcha', '')
        
        if not email or not password:
            flash('Please fill in all fields', 'danger')
            return render_template('login.html', captcha=generate_captcha())
        
        if not captcha_input or captcha_input.upper() != captcha_session.upper():
            flash('Invalid verification code', 'danger')
            return render_template('login.html', captcha=generate_captcha())
        
        if not validate_input(email) or not validate_input(password):
            flash('Invalid input detected', 'danger')
            return render_template('login.html', captcha=generate_captcha())
        
        user = User.query.filter_by(email=email).first()
        
        if user:
            if not user.is_active:
                flash('Your account has been deactivated. Contact administrator.', 'danger')
                return render_template('login.html', captcha=generate_captcha())
            
            if not user.is_approved and user.role == 'admin':
                flash('Your administrator account is pending approval. You will be notified once approved.', 'warning')
                return render_template('login.html', captcha=generate_captcha())
            
            if user.is_locked():
                remaining = user.get_lockout_remaining_time()
                flash(f'Account locked due to multiple failed attempts. Try again in {remaining} minutes.', 'danger')
                return render_template('login.html', captcha=generate_captcha())
            
            if user.check_password(password):
                user.reset_login_attempts()
                user.last_login = datetime.utcnow()
                db.session.commit()
                login_user(user, remember=True)
                session.pop('captcha', None)
                
                flash(f'Welcome back, {user.username}!', 'success')
                
                if user.is_admin():
                    return redirect(url_for('admin.dashboard'))
                return redirect(url_for('auth.dashboard'))
            else:
                was_locked = user.increment_login_attempts()
                db.session.commit()
                remaining = user.get_remaining_attempts()
                
                if was_locked:
                    flash(f'Account locked due to 5 failed attempts. Try again after 30 minutes.', 'danger')
                else:
                    flash(f'Invalid password. {remaining} attempts remaining.', 'danger')
        else:
            flash('Invalid email or password', 'danger')
    
    return render_template('login.html', captcha=generate_captcha())

@bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('auth.dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        requested_role = request.form.get('role', 'user')
        
        if not all([username, email, password, confirm_password]):
            flash('Please fill in all fields', 'danger')
            return render_template('register.html')
        
        if not validate_input(username) or not validate_input(email) or not validate_input(password):
            flash('Invalid characters detected', 'danger')
            return render_template('register.html')
        
        if not re.match(r'^[a-zA-Z0-9_]{3,50}$', username):
            flash('Username must be 3-50 characters and contain only letters, numbers, and underscore', 'danger')
            return render_template('register.html')
        
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            flash('Please enter a valid email address', 'danger')
            return render_template('register.html')
        
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return render_template('register.html')
        
        if len(password) < 8:
            flash('Password must be at least 8 characters long', 'danger')
            return render_template('register.html')
        
        if not re.search(r'[A-Z]', password):
            flash('Password must contain at least one uppercase letter', 'danger')
            return render_template('register.html')
        
        if not re.search(r'[a-z]', password):
            flash('Password must contain at least one lowercase letter', 'danger')
            return render_template('register.html')
        
        if not re.search(r'[0-9]', password):
            flash('Password must contain at least one number', 'danger')
            return render_template('register.html')
        
        existing_user = User.query.filter(
            (User.username == username) | (User.email == email)
        ).first()
        
        if existing_user:
            flash('Username or email already exists', 'danger')
            return render_template('register.html')
        
        if requested_role == 'admin':
            user = User(
                username=username, 
                email=email, 
                role='admin',
                is_approved=False,
                is_active=True
            )
            user.set_password(password)
            
            try:
                db.session.add(user)
                db.session.commit()
                flash('Registration successful. Your administrator account is pending approval. You will be notified once approved.', 'success')
                return redirect(url_for('auth.login'))
            except Exception as e:
                db.session.rollback()
                flash('An error occurred during registration. Please try again.', 'danger')
                return render_template('register.html')
        else:
            user = User(
                username=username, 
                email=email, 
                role='user',
                is_approved=True,
                is_active=True,
                approved_by=1,
                approved_at=datetime.utcnow()
            )
            user.set_password(password)
            
            try:
                db.session.add(user)
                db.session.commit()
                flash('Registration successful. You can now login with your credentials.', 'success')
                return redirect(url_for('auth.login'))
            except Exception as e:
                db.session.rollback()
                flash('An error occurred during registration. Please try again.', 'danger')
                return render_template('register.html')
    
    return render_template('register.html')

@bp.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', user=current_user, datetime=datetime)

@bp.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('captcha', None)
    flash('You have been signed out.', 'info')
    return redirect(url_for('auth.login'))
""")

# ============ app/routes/admin.py ============
with open('app/routes/admin.py', 'w', encoding='utf-8') as f:
    f.write("""from flask import Blueprint, render_template, flash, redirect, url_for, request
from flask_login import login_required, current_user
from app import db
from app.models.user import User
from datetime import datetime
from functools import wraps

bp = Blueprint('admin', __name__, url_prefix='/admin')

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Please login to access this page.', 'danger')
            return redirect(url_for('auth.login'))
        if not current_user.is_admin():
            flash('Access denied. Administrator privileges required.', 'danger')
            return redirect(url_for('auth.dashboard'))
        return f(*args, **kwargs)
    return decorated_function

@bp.route('/dashboard')
@login_required
@admin_required
def dashboard():
    users = User.query.all()
    
    stats = {
        'total_users': len(users),
        'admin_users': len([u for u in users if u.is_admin()]),
        'active_users': len([u for u in users if u.is_active]),
        'locked_users': len([u for u in users if u.is_locked()]),
        'pending_users': len([u for u in users if not u.is_approved and u.role == 'admin']),
    }
    
    return render_template('admin.html', users=users, stats=stats)

@bp.route('/user/<int:user_id>/approve', methods=['POST'])
@login_required
@admin_required
def approve_user(user_id):
    user = User.query.get_or_404(user_id)
    
    if user.is_approved:
        flash(f'User {user.username} is already approved', 'warning')
        return redirect(url_for('admin.dashboard'))
    
    user.is_approved = True
    user.approved_by = current_user.id
    user.approved_at = datetime.utcnow()
    
    db.session.commit()
    
    flash(f'User {user.username} has been approved as {user.role.upper()}', 'success')
    return redirect(url_for('admin.dashboard'))

@bp.route('/user/<int:user_id>/reject', methods=['POST'])
@login_required
@admin_required
def reject_user(user_id):
    user = User.query.get_or_404(user_id)
    
    if user.is_approved:
        flash(f'Cannot reject approved user. Deactivate or delete instead.', 'danger')
        return redirect(url_for('admin.dashboard'))
    
    username = user.username
    db.session.delete(user)
    db.session.commit()
    
    flash(f'User {username} has been rejected and removed.', 'success')
    return redirect(url_for('admin.dashboard'))

@bp.route('/user/<int:user_id>/change-role', methods=['POST'])
@login_required
@admin_required
def change_user_role(user_id):
    user = User.query.get_or_404(user_id)
    new_role = request.form.get('new_role')
    
    if user.id == current_user.id:
        flash('You cannot change your own role', 'danger')
        return redirect(url_for('admin.dashboard'))
    
    if new_role not in ['user', 'admin']:
        flash('Invalid role', 'danger')
        return redirect(url_for('admin.dashboard'))
    
    user.role = new_role
    db.session.commit()
    
    flash(f'User {user.username} role changed to {new_role.upper()}', 'success')
    return redirect(url_for('admin.dashboard'))

@bp.route('/user/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    
    if user.id == current_user.id:
        flash('You cannot delete your own account', 'danger')
        return redirect(url_for('admin.dashboard'))
    
    try:
        username = user.username
        db.session.delete(user)
        db.session.commit()
        flash(f'User {username} has been deleted successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error deleting user', 'danger')
    
    return redirect(url_for('admin.dashboard'))

@bp.route('/user/<int:user_id>/toggle', methods=['POST'])
@login_required
@admin_required
def toggle_user_status(user_id):
    user = User.query.get_or_404(user_id)
    
    if user.id == current_user.id:
        flash('You cannot modify your own account status', 'danger')
        return redirect(url_for('admin.dashboard'))
    
    user.is_active = not user.is_active
    db.session.commit()
    status = 'activated' if user.is_active else 'deactivated'
    flash(f'User {user.username} has been {status}', 'success')
    return redirect(url_for('admin.dashboard'))

@bp.route('/user/<int:user_id>/reset-attempts', methods=['POST'])
@login_required
@admin_required
def reset_login_attempts(user_id):
    user = User.query.get_or_404(user_id)
    user.reset_login_attempts()
    db.session.commit()
    flash(f'Login attempts reset for {user.username}', 'success')
    return redirect(url_for('admin.dashboard'))
""")

# ============ HTML Templates ============

# login.html
with open('app/templates/login.html', 'w', encoding='utf-8') as f:
    f.write("""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - Secure Login System</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='css/dark-theme.css') }}">
</head>
<body>
    <div class="container">
        <div class="form-container">
            <h2>Secure Login</h2>
            {% with messages = get_flashed_messages(with_categories=true) %}
                {% if messages %}
                    {% for category, message in messages %}
                        <div class="alert alert-{{ category }}">{{ message }}</div>
                    {% endfor %}
                {% endif %}
            {% endwith %}
            <form method="POST" id="loginForm">
                <div class="form-group">
                    <label for="email">Email Address</label>
                    <input type="email" id="email" name="email" required placeholder="Enter your email">
                </div>
                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" id="password" name="password" required placeholder="Enter your password">
                </div>
                <div class="form-group">
                    <label>Verification Code</label>
                    <div class="captcha-container">
                        <span class="captcha-text">{{ captcha }}</span>
                        <button type="button" class="captcha-refresh" onclick="refreshCaptcha()">⟳</button>
                    </div>
                    <input type="text" id="captcha" name="captcha" required placeholder="Enter verification code">
                </div>
                <button type="submit" class="btn">Sign In</button>
            </form>
            <p class="text-center">
                Don't have an account? <a href="{{ url_for('auth.register') }}">Create Account</a>
            </p>
        </div>
    </div>
    <script src="{{ url_for('static', filename='js/validation.js') }}"></script>
</body>
</html>""")

# register.html
with open('app/templates/register.html', 'w', encoding='utf-8') as f:
    f.write("""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register - Secure Login System</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='css/dark-theme.css') }}">
</head>
<body>
    <div class="container">
        <div class="form-container">
            <h2>Create Account</h2>
            {% with messages = get_flashed_messages(with_categories=true) %}
                {% if messages %}
                    {% for category, message in messages %}
                        <div class="alert alert-{{ category }}">{{ message }}</div>
                    {% endfor %}
                {% endif %}
            {% endwith %}
            <form method="POST" id="registerForm">
                <div class="form-group">
                    <label for="username">Username</label>
                    <input type="text" id="username" name="username" required placeholder="Choose a username (3-50 characters)">
                    <small style="color: #6c757d; font-size: 11px;">Letters, numbers, and underscore only</small>
                </div>
                <div class="form-group">
                    <label for="email">Email Address</label>
                    <input type="email" id="email" name="email" required placeholder="Enter your email">
                </div>
                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" id="password" name="password" required placeholder="Create a strong password">
                    <div id="passwordStrength" class="password-strength"></div>
                    <small style="color: #6c757d; font-size: 11px;">Minimum 8 characters, uppercase, lowercase, and number required</small>
                </div>
                <div class="form-group">
                    <label for="confirm_password">Confirm Password</label>
                    <input type="password" id="confirm_password" name="confirm_password" required placeholder="Confirm your password">
                </div>
                <div class="form-group">
                    <label for="role">Account Type</label>
                    <select id="role" name="role">
                        <option value="user">Standard User</option>
                        <option value="admin">Administrator</option>
                    </select>
                    <small style="color: #6c757d; font-size: 11px;">Administrator accounts require approval</small>
                </div>
                <button type="submit" class="btn">Register</button>
            </form>
            <p class="text-center">
                Already have an account? <a href="{{ url_for('auth.login') }}">Sign In</a>
            </p>
        </div>
    </div>
    <script src="{{ url_for('static', filename='js/validation.js') }}"></script>
</body>
</html>""")

# dashboard.html
with open('app/templates/dashboard.html', 'w', encoding='utf-8') as f:
    f.write("""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - Secure Login System</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='css/dark-theme.css') }}">
</head>
<body>
    <div class="dashboard">
        <div class="dashboard-header">
            <h1>Welcome, {{ user.username }}</h1>
            <div class="nav-links">
                {% if user.is_admin() %}
                    <a href="{{ url_for('admin.dashboard') }}">Admin Panel</a>
                {% endif %}
                <a href="{{ url_for('auth.logout') }}">Sign Out</a>
            </div>
        </div>
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ category }}">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        <div class="dashboard-content">
            <div class="info-card">
                <h3>Account Information</h3>
                <div class="info-row"><strong>Username:</strong> <span>{{ user.username }}</span></div>
                <div class="info-row"><strong>Email:</strong> <span>{{ user.email }}</span></div>
                <div class="info-row"><strong>Role:</strong> <span class="role-badge {{ user.role }}">{{ user.role|title }}</span></div>
                <div class="info-row"><strong>Approval Status:</strong> 
                    {% if user.role == 'admin' %}
                        {% if user.is_approved %}<span class="status-badge active">Approved</span>{% else %}<span class="status-badge pending">Pending Approval</span>{% endif %}
                    {% else %}<span class="status-badge active">Approved</span>{% endif %}
                </div>
                <div class="info-row"><strong>Account Status:</strong> <span class="status-badge {{ 'active' if user.is_active else 'inactive' }}">{{ 'Active' if user.is_active else 'Inactive' }}</span></div>
                <div class="info-row"><strong>Account Created:</strong> <span>{{ user.created_at.strftime('%Y-%m-%d %H:%M') }}</span></div>
                <div class="info-row"><strong>Last Login:</strong> <span>{{ user.last_login.strftime('%Y-%m-%d %H:%M') if user.last_login else 'First login' }}</span></div>
                <div class="info-row"><strong>Failed Login Attempts:</strong> <span>{{ user.login_attempts }}/5</span></div>
            </div>
            <div class="info-card">
                <h3>Security Features</h3>
                <ul>
                    <li>Password hashing with bcrypt</li>
                    <li>Account lockout after 5 failed attempts</li>
                    <li>CAPTCHA protection</li>
                    <li>SQL injection prevention</li>
                    <li>Role-based access control</li>
                </ul>
            </div>
        </div>
    </div>
</body>
</html>""")

# admin.html
with open('app/templates/admin.html', 'w', encoding='utf-8') as f:
    f.write("""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Panel - Secure Login System</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='css/dark-theme.css') }}">
</head>
<body>
    <div class="dashboard">
        <div class="dashboard-header">
            <h1>Admin Dashboard</h1>
            <div class="nav-links">
                <a href="{{ url_for('auth.dashboard') }}">User Dashboard</a>
                <a href="{{ url_for('auth.logout') }}">Sign Out</a>
            </div>
        </div>
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ category }}">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        <div class="stats-cards">
            <div class="stat-card"><h3>Total Users</h3><div class="stat-number">{{ stats.total_users }}</div></div>
            <div class="stat-card"><h3>Administrators</h3><div class="stat-number">{{ stats.admin_users }}</div></div>
            <div class="stat-card"><h3>Active Users</h3><div class="stat-number">{{ stats.active_users }}</div></div>
            <div class="stat-card"><h3>Pending Approval</h3><div class="stat-number">{{ stats.pending_users }}</div></div>
            <div class="stat-card"><h3>Locked Users</h3><div class="stat-number">{{ stats.locked_users }}</div></div>
        </div>
        <div class="user-table">
            <h3>User Management</h3>
            <div class="table-responsive">
                 <table>
                    <thead>
                        <tr><th>ID</th><th>Username</th><th>Email</th><th>Role</th><th>Status</th><th>Approved</th><th>Login Attempts</th><th>Actions</th></tr>
                    </thead>
                    <tbody>
                        {% for user in users %}
                        <tr>
                            <td>{{ user.id }}</td>
                            <td>{{ user.username }}</td>
                            <td>{{ user.email }}</td>
                            <td><span class="role-badge {{ user.role }}">{{ user.role|title }}</span></td>
                            <td><span class="status-badge {{ 'active' if user.is_active else 'inactive' }}">{{ 'Active' if user.is_active else 'Inactive' }}</span></td>
                            <td>{% if user.is_approved %}<span style="color: #28a745;">Approved</span>{% else %}<span style="color: #ffc107;">Pending</span>{% endif %}</td>
                            <td>{{ user.login_attempts }}/5</td>
                            <td class="actions">
                                {% if user.id != current_user.id %}
                                    {% if not user.is_approved and user.role == 'admin' %}
                                        <form action="{{ url_for('admin.approve_user', user_id=user.id) }}" method="POST" style="display:inline;"><button type="submit" class="btn-small btn-success">Approve</button></form>
                                        <form action="{{ url_for('admin.reject_user', user_id=user.id) }}" method="POST" style="display:inline;"><button type="submit" class="btn-small btn-danger">Reject</button></form>
                                    {% else %}
                                        {% if user.is_locked() %}<form action="{{ url_for('admin.reset_login_attempts', user_id=user.id) }}" method="POST" style="display:inline;"><button type="submit" class="btn-small btn-unlock">Unlock</button></form>{% endif %}
                                        <form action="{{ url_for('admin.toggle_user_status', user_id=user.id) }}" method="POST" style="display:inline;"><button type="submit" class="btn-small btn-toggle">{{ 'Deactivate' if user.is_active else 'Activate' }}</button></form>
                                        <form action="{{ url_for('admin.change_user_role', user_id=user.id) }}" method="POST" style="display:inline;"><select name="new_role"><option value="user">User</option><option value="admin">Admin</option></select><button type="submit" class="btn-small btn-toggle">Change</button></form>
                                        <form action="{{ url_for('admin.delete_user', user_id=user.id) }}" method="POST" style="display:inline;"><button type="submit" class="btn-small btn-danger">Delete</button></form>
                                    {% endif %}
                                {% else %}<span class="current-user-badge">Current User</span>{% endif %}
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</body>
</html>""")

# ============ CSS and JS ============
with open('app/static/css/dark-theme.css', 'w', encoding='utf-8') as f:
    f.write("""* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: linear-gradient(135deg, #1a2c3e 0%, #0f1a24 100%); min-height: 100vh; display: flex; align-items: center; justify-content: center; color: #212529; }
.container { width: 100%; max-width: 450px; padding: 20px; animation: fadeInUp 0.4s ease-out; }
@keyframes fadeInUp { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
.form-container { background: #ffffff; padding: 40px; border-radius: 12px; box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1); border: 1px solid #dee2e6; }
h2 { text-align: center; margin-bottom: 30px; font-size: 28px; font-weight: 600; color: #212529; }
.form-group { margin-bottom: 20px; }
label { display: block; margin-bottom: 8px; color: #212529; font-weight: 500; font-size: 14px; }
input, select { width: 100%; padding: 10px 12px; background: #ffffff; border: 1px solid #dee2e6; border-radius: 6px; font-size: 14px; color: #212529; transition: all 0.2s ease; }
input:focus, select:focus { outline: none; border-color: #0052cc; box-shadow: 0 0 0 3px rgba(0, 82, 204, 0.1); }
.btn { width: 100%; padding: 12px; background: #0052cc; color: white; border: none; border-radius: 6px; font-size: 14px; font-weight: 500; cursor: pointer; transition: all 0.2s ease; }
.btn:hover { background: #0047b3; transform: translateY(-1px); }
.alert { padding: 12px; border-radius: 6px; margin-bottom: 20px; font-size: 14px; }
.alert-success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
.alert-danger { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
.alert-warning { background: #fff3cd; color: #856404; border: 1px solid #ffeaa7; }
.captcha-container { background: #f8f9fa; padding: 15px; border-radius: 6px; text-align: center; margin-bottom: 15px; border: 1px solid #dee2e6; display: flex; justify-content: center; align-items: center; gap: 15px; }
.captcha-text { font-family: 'Courier New', monospace; font-size: 24px; font-weight: bold; letter-spacing: 4px; color: #0052cc; }
.captcha-refresh { background: none; border: none; color: #0052cc; cursor: pointer; font-size: 18px; padding: 5px 10px; border-radius: 4px; }
.text-center { text-align: center; margin-top: 20px; }
.text-center a { color: #0052cc; text-decoration: none; font-weight: 500; }
.text-center a:hover { text-decoration: underline; }
.dashboard { width: 100%; max-width: 1200px; margin: 20px auto; padding: 20px; }
.dashboard-header { background: #ffffff; padding: 20px 30px; border-radius: 12px; margin-bottom: 25px; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 1px 3px rgba(0,0,0,0.1); border: 1px solid #dee2e6; }
.nav-links { display: flex; gap: 15px; }
.nav-links a { padding: 8px 16px; border-radius: 6px; text-decoration: none; font-weight: 500; font-size: 14px; }
.nav-links a:first-child { background: #0052cc; color: white; }
.nav-links a:last-child { background: #f8f9fa; color: #dc3545; border: 1px solid #dee2e6; }
.dashboard-content { display: grid; grid-template-columns: repeat(auto-fit, minmax(350px, 1fr)); gap: 25px; }
.info-card { background: #ffffff; padding: 25px; border-radius: 12px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); border: 1px solid #dee2e6; }
.info-row { padding: 12px 0; border-bottom: 1px solid #dee2e6; display: flex; justify-content: space-between; font-size: 14px; }
.role-badge { display: inline-block; padding: 4px 10px; border-radius: 4px; font-size: 12px; font-weight: 600; text-transform: uppercase; }
.role-badge.admin { background: #0052cc; color: white; }
.role-badge.user { background: #28a745; color: white; }
.status-badge { display: inline-block; padding: 4px 10px; border-radius: 4px; font-size: 12px; font-weight: 600; }
.status-badge.active { background: #28a745; color: white; }
.status-badge.inactive { background: #dc3545; color: white; }
.status-badge.pending { background: #ffc107; color: #212529; }
.stats-cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
.stat-card { background: #ffffff; padding: 20px; border-radius: 12px; text-align: center; border: 1px solid #dee2e6; }
.stat-number { font-size: 32px; font-weight: 700; color: #0052cc; }
.user-table { background: #ffffff; border-radius: 12px; padding: 20px; border: 1px solid #dee2e6; }
.table-responsive { overflow-x: auto; }
.user-table table { width: 100%; border-collapse: collapse; }
.user-table th { background: #f8f9fa; padding: 12px; text-align: left; font-weight: 600; border-bottom: 2px solid #dee2e6; }
.user-table td { padding: 12px; border-bottom: 1px solid #dee2e6; color: #6c757d; }
.btn-small { padding: 4px 8px; font-size: 12px; margin: 0 2px; border: none; border-radius: 4px; cursor: pointer; }
.btn-toggle { background: #ffc107; color: #212529; }
.btn-danger { background: #dc3545; color: white; }
.btn-unlock { background: #17a2b8; color: white; }
.btn-success { background: #28a745; color: white; }
.current-user-badge { display: inline-block; padding: 4px 8px; background: #e9ecef; border-radius: 4px; font-size: 11px; }
@media (max-width: 768px) { .form-container { padding: 25px; } .dashboard-header { flex-direction: column; gap: 15px; text-align: center; } }
""")

with open('app/static/js/validation.js', 'w', encoding='utf-8') as f:
    f.write("""function checkPasswordStrength(password) {
    let strength = 0;
    if (password.length >= 8) strength++;
    if (password.match(/[a-z]/)) strength++;
    if (password.match(/[A-Z]/)) strength++;
    if (password.match(/[0-9]/)) strength++;
    return strength;
}
function validateEmail(email) {
    return /^[^\\s@]+@([^\\s@]+\\.)+[^\\s@]+$/.test(email);
}
document.addEventListener('DOMContentLoaded', function() {
    const registerForm = document.getElementById('registerForm');
    if (registerForm) {
        const passwordInput = document.getElementById('password');
        const strengthIndicator = document.getElementById('passwordStrength');
        if (passwordInput) {
            passwordInput.addEventListener('input', function() {
                const strength = checkPasswordStrength(this.value);
                let text = '', className = '';
                if (this.value.length === 0) text = '';
                else if (strength <= 2) { text = 'Weak'; className = 'strength-weak'; }
                else if (strength <= 3) { text = 'Medium'; className = 'strength-medium'; }
                else { text = 'Strong'; className = 'strength-strong'; }
                strengthIndicator.textContent = text;
                strengthIndicator.className = className;
            });
        }
        registerForm.addEventListener('submit', function(e) {
            const password = document.getElementById('password').value;
            const confirm = document.getElementById('confirm_password');
            if (confirm && password !== confirm.value) {
                alert('Passwords do not match');
                e.preventDefault();
            }
        });
    }
});
function refreshCaptcha() { location.reload(); }
""")

# ============ Configuration Files ============
with open('config.py', 'w', encoding='utf-8') as f:
    f.write("""import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-12345')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///secure_login.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    MAX_LOGIN_ATTEMPTS = 5
    ACCOUNT_LOCKOUT_DURATION = 30
""")

with open('run.py', 'w', encoding='utf-8') as f:
    f.write("""from app import create_app

app = create_app()

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)
""")

with open('.env', 'w', encoding='utf-8') as f:
    f.write("""SECRET_KEY=your-super-secret-key-change-in-production-12345
DATABASE_URL=sqlite:///secure_login.db
""")

with open('requirements.txt', 'w', encoding='utf-8') as f:
    f.write("""Flask==2.3.2
Flask-SQLAlchemy==3.0.5
Flask-Login==0.6.2
Flask-Bcrypt==1.0.1
python-dotenv==1.0.0
email-validator==2.0.0
""")

with open('database_setup.py', 'w', encoding='utf-8') as f:
    f.write("""from app import create_app, db
from app.models.user import User
from datetime import datetime

app = create_app()

with app.app_context():
    db.drop_all()
    db.create_all()
    print("Database tables created successfully!")
    
    admin = User(username='admin', email='admin@example.com', role='admin', is_approved=True, is_active=True, approved_by=1, approved_at=datetime.utcnow())
    admin.set_password('Admin12345')
    db.session.add(admin)
    
    user = User(username='testuser', email='test@example.com', role='user', is_approved=True, is_active=True)
    user.set_password('Test12345')
    db.session.add(user)
    
    pending = User(username='pendinguser', email='pending@example.com', role='admin', is_approved=False, is_active=True)
    pending.set_password('Pending123')
    db.session.add(pending)
    
    db.session.commit()
    
    print("Default users created:")
    print("  - Admin: admin@example.com / Admin12345")
    print("  - User: test@example.com / Test12345")
    print("  - Pending: pending@example.com / Pending123")
""")

# ============ Empty init files ============
with open('app/models/__init__.py', 'w', encoding='utf-8') as f:
    f.write("")
with open('app/routes/__init__.py', 'w', encoding='utf-8') as f:
    f.write("")

print("\n" + "="*50)
print("✓ All files created successfully!")
print("="*50)
print("\nNext steps:")
print("1. Run: python database_setup.py")
print("2. Run: python run.py")
print("3. Open: http://127.0.0.1:5000")