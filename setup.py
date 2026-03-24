import os

# Create directories
os.makedirs('app/models', exist_ok=True)
os.makedirs('app/routes', exist_ok=True)
os.makedirs('app/templates', exist_ok=True)

# Create app/__init__.py
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

# Create app/models/user.py
with open('app/models/user.py', 'w', encoding='utf-8') as f:
    f.write("""from datetime import datetime
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
    login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    last_failed_attempt = db.Column(db.DateTime, nullable=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def is_locked(self):
        if self.locked_until and datetime.utcnow() < self.locked_until:
            return True
        return False
    
    def increment_login_attempts(self):
        from config import Config
        self.login_attempts += 1
        self.last_failed_attempt = datetime.utcnow()
        if self.login_attempts >= Config.MAX_LOGIN_ATTEMPTS:
            from datetime import timedelta
            self.locked_until = datetime.utcnow() + timedelta(minutes=Config.ACCOUNT_LOCKOUT_DURATION)
            return True
        return False
    
    def reset_login_attempts(self):
        self.login_attempts = 0
        self.locked_until = None
        self.last_failed_attempt = None
    
    def get_remaining_attempts(self):
        from config import Config
        return max(0, Config.MAX_LOGIN_ATTEMPTS - self.login_attempts)
    
    def get_lockout_remaining_time(self):
        if self.locked_until and datetime.utcnow() < self.locked_until:
            remaining = (self.locked_until - datetime.utcnow()).total_seconds() / 60
            return int(remaining)
        return 0
    
    def is_admin(self):
        return self.role == 'admin'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
""")

# Create app/routes/auth.py
with open('app/routes/auth.py', 'w', encoding='utf-8') as f:
    f.write("""from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
from datetime import datetime
from app import db
from app.models.user import User

bp = Blueprint('auth', __name__)

@bp.route('/')
def index():
    return redirect(url_for('auth.login'))

@bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('auth.dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        if not email or not password:
            flash('Please fill in all fields', 'danger')
            return render_template('login.html')
        
        user = User.query.filter_by(email=email).first()
        
        if user:
            if not user.is_active:
                flash('Your account has been deactivated. Contact admin.', 'danger')
                return render_template('login.html')
            
            if user.is_locked():
                remaining = user.get_lockout_remaining_time()
                flash(f'Account locked. Try again in {remaining} minutes.', 'danger')
                return render_template('login.html')
            
            if user.check_password(password):
                user.reset_login_attempts()
                user.last_login = datetime.utcnow()
                db.session.commit()
                login_user(user)
                flash(f'Welcome back, {user.username}!', 'success')
                return redirect(url_for('auth.dashboard'))
            else:
                user.increment_login_attempts()
                db.session.commit()
                remaining = user.get_remaining_attempts()
                flash(f'Invalid password. {remaining} attempts remaining.', 'danger')
        else:
            flash('Invalid email or password', 'danger')
    
    return render_template('login.html')

@bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role', 'user')
        
        if not all([username, email, password]):
            flash('Please fill in all fields', 'danger')
            return render_template('register.html')
        
        if len(password) < 8:
            flash('Password must be at least 8 characters', 'danger')
            return render_template('register.html')
        
        existing = User.query.filter(
            (User.username == username) | (User.email == email)
        ).first()
        
        if existing:
            flash('Username or email already exists', 'danger')
            return render_template('register.html')
        
        user = User(username=username, email=email, role=role)
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('auth.login'))
    
    return render_template('register.html')

@bp.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', user=current_user)

@bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))
""")

# Create app/routes/admin.py
with open('app/routes/admin.py', 'w', encoding='utf-8') as f:
    f.write("""from flask import Blueprint, render_template, flash, redirect, url_for, request
from flask_login import login_required, current_user
from app import db
from app.models.user import User

bp = Blueprint('admin', __name__, url_prefix='/admin')

@bp.route('/dashboard')
@login_required
def dashboard():
    if not current_user.is_admin():
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('auth.dashboard'))
    
    users = User.query.all()
    stats = {
        'total_users': len(users),
        'admin_users': len([u for u in users if u.is_admin()]),
        'active_users': len([u for u in users if u.is_active]),
        'locked_users': len([u for u in users if u.is_locked()])
    }
    return render_template('admin.html', users=users, stats=stats)

@bp.route('/user/<int:user_id>/delete', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin():
        flash('Access denied', 'danger')
        return redirect(url_for('auth.dashboard'))
    
    user = User.query.get_or_404(user_id)
    
    if user.id == current_user.id:
        flash('You cannot delete your own account', 'danger')
        return redirect(url_for('admin.dashboard'))
    
    username = user.username
    db.session.delete(user)
    db.session.commit()
    flash(f'User {username} has been deleted', 'success')
    return redirect(url_for('admin.dashboard'))

@bp.route('/user/<int:user_id>/toggle', methods=['POST'])
@login_required
def toggle_user_status(user_id):
    if not current_user.is_admin():
        flash('Access denied', 'danger')
        return redirect(url_for('auth.dashboard'))
    
    user = User.query.get_or_404(user_id)
    
    if user.id == current_user.id:
        flash('You cannot modify your own account', 'danger')
        return redirect(url_for('admin.dashboard'))
    
    user.is_active = not user.is_active
    db.session.commit()
    status = 'activated' if user.is_active else 'deactivated'
    flash(f'User {user.username} {status}', 'success')
    return redirect(url_for('admin.dashboard'))

@bp.route('/user/<int:user_id>/reset-attempts', methods=['POST'])
@login_required
def reset_login_attempts(user_id):
    if not current_user.is_admin():
        flash('Access denied', 'danger')
        return redirect(url_for('auth.dashboard'))
    
    user = User.query.get_or_404(user_id)
    user.reset_login_attempts()
    db.session.commit()
    flash(f'Login attempts reset for {user.username}', 'success')
    return redirect(url_for('admin.dashboard'))
""")

# Create empty __init__.py files
with open('app/models/__init__.py', 'w', encoding='utf-8') as f:
    f.write("")

with open('app/routes/__init__.py', 'w', encoding='utf-8') as f:
    f.write("")

print("All files created successfully!")