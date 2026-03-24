from flask import Blueprint, render_template, request, redirect, url_for, flash, session
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
