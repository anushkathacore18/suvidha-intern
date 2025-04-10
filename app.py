from flask import Flask, request, jsonify, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
import os
from dotenv import load_dotenv
from datetime import timedelta, datetime

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-here')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'your-jwt-secret-key-here')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)

db = SQLAlchemy(app)
jwt = JWTManager(app)

# User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    user_type = db.Column(db.String(20), nullable=False)  # 'student', 'employer', or 'tpo'

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Job Model
class Job(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    company = db.Column(db.String(100), nullable=False)
    position = db.Column(db.String(100), nullable=False)
    requirements = db.Column(db.Text, nullable=False)
    employer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='active')  # 'active' or 'closed'

# Job Application Model
class JobApplication(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    job_id = db.Column(db.Integer, db.ForeignKey('job.id'), nullable=False)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')  # 'pending', 'accepted', 'rejected'
    date_applied = db.Column(db.DateTime, default=datetime.utcnow)

# Frontend Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login')
def login_page():
    return render_template('login.html')

@app.route('/register')
def register_page():
    return render_template('register.html')

@app.route('/register/student')
def register_student_page():
    return render_template('register_student.html')

@app.route('/register/employee')
def register_employee_page():
    return render_template('register_employee.html')

@app.route('/register/tpo')
def register_tpo_page():
    return render_template('register_tpo.html')

@app.route('/dashboard')
def dashboard_page():
    return render_template('dashboard.html')

@app.route('/dashboard/student')
def student_dashboard_page():
    return render_template('student_dashboard.html')

@app.route('/dashboard/employee')
def employee_dashboard_page():
    return render_template('employee_dashboard.html')

@app.route('/dashboard/tpo')
def tpo_dashboard_page():
    return render_template('tpo_dashboard.html')

# API Routes
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    user_type = data.get('user_type')
    
    user = User.query.filter_by(username=username, user_type=user_type).first()
    
    if user and user.check_password(password):
        access_token = create_access_token(identity={
            'user_id': user.id,
            'username': user.username,
            'user_type': user.user_type
        })
        return jsonify({
            'status': 'success',
            'message': 'Login successful',
            'access_token': access_token,
            'user': {
                'id': user.id,
                'username': user.username,
                'user_type': user.user_type
            }
        }), 200
    else:
        return jsonify({
            'status': 'error',
            'message': 'Invalid username, password, or user type'
        }), 401

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    user_type = data.get('user_type')
    
    if User.query.filter_by(username=username).first():
        return jsonify({
            'status': 'error',
            'message': 'Username already exists'
        }), 400
    
    user = User(username=username, user_type=user_type)
    user.set_password(password)
    
    db.session.add(user)
    db.session.commit()
    
    return jsonify({
        'status': 'success',
        'message': 'Registration successful'
    }), 201

@app.route('/api/profile', methods=['GET'])
@jwt_required()
def get_profile():
    current_user = get_jwt_identity()
    user = User.query.get(current_user['user_id'])
    
    return jsonify({
        'status': 'success',
        'user': {
            'id': user.id,
            'username': user.username,
            'user_type': user.user_type
        }
    }), 200

# Job-related API endpoints
@app.route('/api/jobs', methods=['POST'])
@jwt_required()
def create_job():
    current_user = get_jwt_identity()
    if current_user['user_type'] != 'employer':
        return jsonify({
            'status': 'error',
            'message': 'Only employers can create jobs'
        }), 403
    
    data = request.get_json()
    job = Job(
        company=data.get('company'),
        position=data.get('position'),
        requirements=data.get('requirements'),
        employer_id=current_user['user_id']
    )
    
    db.session.add(job)
    db.session.commit()
    
    return jsonify({
        'status': 'success',
        'message': 'Job created successfully',
        'job_id': job.id
    }), 201

@app.route('/api/jobs/available', methods=['GET'])
@jwt_required()
def get_available_jobs():
    jobs = Job.query.filter_by(status='active').all()
    return jsonify({
        'status': 'success',
        'jobs': [{
            'id': job.id,
            'company': job.company,
            'position': job.position,
            'requirements': job.requirements
        } for job in jobs]
    }), 200

@app.route('/api/jobs/applied', methods=['GET'])
@jwt_required()
def get_applied_jobs():
    current_user = get_jwt_identity()
    if current_user['user_type'] != 'student':
        return jsonify({
            'status': 'error',
            'message': 'Only students can view applied jobs'
        }), 403
    
    applications = JobApplication.query.filter_by(student_id=current_user['user_id']).all()
    return jsonify({
        'status': 'success',
        'applications': [{
            'id': app.id,
            'job': {
                'company': app.job.company,
                'position': app.job.position
            },
            'status': app.status,
            'date_applied': app.date_applied.isoformat()
        } for app in applications]
    }), 200

@app.route('/api/jobs/<int:job_id>/apply', methods=['POST'])
@jwt_required()
def apply_for_job(job_id):
    current_user = get_jwt_identity()
    if current_user['user_type'] != 'student':
        return jsonify({
            'status': 'error',
            'message': 'Only students can apply for jobs'
        }), 403
    
    job = Job.query.get_or_404(job_id)
    if job.status != 'active':
        return jsonify({
            'status': 'error',
            'message': 'This job is no longer accepting applications'
        }), 400
    
    # Check if already applied
    existing_application = JobApplication.query.filter_by(
        job_id=job_id,
        student_id=current_user['user_id']
    ).first()
    
    if existing_application:
        return jsonify({
            'status': 'error',
            'message': 'You have already applied for this job'
        }), 400
    
    application = JobApplication(
        job_id=job_id,
        student_id=current_user['user_id']
    )
    
    db.session.add(application)
    db.session.commit()
    
    return jsonify({
        'status': 'success',
        'message': 'Application submitted successfully'
    }), 201

# Admin API route to create TPO accounts
@app.route('/api/admin/create-tpo', methods=['POST'])
@jwt_required()
def create_tpo():
    current_user = get_jwt_identity()
    if current_user['user_type'] not in ['admin', 'tpo']:
        return jsonify({
            'status': 'error',
            'message': 'You do not have permission to access this endpoint'
        }), 403
    
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if User.query.filter_by(username=username).first():
        return jsonify({
            'status': 'error',
            'message': 'Username already exists'
        }), 400
    
    tpo_user = User(username=username, user_type='tpo')
    tpo_user.set_password(password)
    
    db.session.add(tpo_user)
    db.session.commit()
    
    return jsonify({
        'status': 'success',
        'message': 'TPO account created successfully'
    }), 201

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        
        # Create initial TPO account if none exists
        if not User.query.filter_by(user_type='tpo').first():
            default_tpo = User(username='admin_tpo', user_type='tpo')
            default_tpo.set_password('admin123')  # Change this to a secure password
            db.session.add(default_tpo)
            db.session.commit()
            print("Initial TPO account created. Username: admin_tpo, Password: admin123")
            print("Please change this password immediately after first login!")
    
    app.run(debug=True) 