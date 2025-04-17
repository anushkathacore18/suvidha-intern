from app import app, db, User
from werkzeug.security import generate_password_hash

def create_database():
    with app.app_context():
        # Create all tables
        db.create_all()
        print("Database tables created successfully")
        
        # Create super admin if it doesn't exist
        if not User.query.filter_by(user_type='super_admin').first():
            super_admin = User(
                username='admin',
                email='admin@example.com',
                user_type='super_admin',
                first_name='Super',
                last_name='Admin',
                is_active=True,
                is_verified=True
            )
            super_admin.set_password('admin123')
            db.session.add(super_admin)
            db.session.commit()
            print("Super admin account created. Username: admin, Password: admin123")

if __name__ == "__main__":
    create_database() 