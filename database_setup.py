from app import create_app, db
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
