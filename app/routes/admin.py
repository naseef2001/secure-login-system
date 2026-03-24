from flask import Blueprint, render_template, flash, redirect, url_for, request
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
