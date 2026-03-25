from datetime import datetime, timedelta
from flask_login import UserMixin
from app import db, login_manager
from flask_bcrypt import Bcrypt

bcrypt = Bcrypt()

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
        """Hash password using bcrypt"""
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    
    def check_password(self, password):
        """Verify password using bcrypt"""
        return bcrypt.check_password_hash(self.password_hash, password)
    
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