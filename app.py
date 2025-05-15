from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
import os
from dotenv import load_dotenv
from datetime import timedelta, datetime

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Generate a secure random key
app.permanent_session_lifetime = timedelta(days=7)  # Set session lifetime

# Validate and set database configuration
database_url = os.getenv('DATABASE_URL')
if not database_url:
    raise ValueError("DATABASE_URL environment variable is not set")

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-here')
app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'your-jwt-secret-key-here')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=1)  # Extend token expiration to 1 day
app.config['JWT_TOKEN_LOCATION'] = ['headers']
app.config['JWT_HEADER_NAME'] = 'Authorization'
app.config['JWT_HEADER_TYPE'] = 'Bearer'

db = SQLAlchemy(app)
jwt = JWTManager(app)

# JWT error handlers
@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    print("Token expired")
    return jsonify({
        'status': 'error',
        'message': 'Token has expired'
    }), 401

@jwt.invalid_token_loader
def invalid_token_callback(error):
    print(f"Invalid token: {error}")
    return jsonify({
        'status': 'error',
        'message': 'Invalid token'
    }), 401

@jwt.unauthorized_loader
def unauthorized_callback(error):
    print(f"Missing token: {error}")
    return jsonify({
        'status': 'error',
        'message': 'Authorization header missing'
    }), 401

# User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    user_type = db.Column(db.String(20), nullable=False)  # 'student', 'employer', 'tpo', 'super_admin'
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))
    institute = db.Column(db.String(100))  # For TPOs
    department = db.Column(db.String(100))  # For TPOs
    company_name = db.Column(db.String(100))  # For employers
    company_website = db.Column(db.String(200))  # For employers
    is_active = db.Column(db.Boolean, default=True)
    is_verified = db.Column(db.Boolean, default=False)
    requires_password_reset = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))  # For TPOs, tracks who created them

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

@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if request.method == 'POST':
        user_type = request.form.get('userType')
        email = request.form.get('email')
        password = request.form.get('password')
        print(f"[LOGIN DEBUG] userType: {user_type}, email: {email}, password: {password}")

        user = User.query.filter_by(email=email, user_type=user_type).first()
        print(f"[LOGIN DEBUG] User found: {user}")
        if user and user.check_password(password):
            print(f"[LOGIN DEBUG] Password correct for {email}")
            session['user_id'] = user.id
            session['user_name'] = user.first_name
            session['user_type'] = user.user_type
            # Redirect to the correct dashboard
            if user_type == 'student':
                print("[LOGIN DEBUG] Redirecting to student_dashboard")
                return redirect(url_for('student_dashboard'))
            elif user_type == 'employee':
                print("[LOGIN DEBUG] Redirecting to employee_dashboard_page")
                return redirect(url_for('employee_dashboard_page'))
            elif user_type == 'tpo':
                print("[LOGIN DEBUG] Redirecting to tpo_dashboard_page")
                return redirect(url_for('tpo_dashboard_page'))
        else:
            print(f"[LOGIN DEBUG] Invalid credentials for {email}")
            return render_template('login.html', error='Invalid credentials. Please try again.')
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
def dashboard():
    # This route just renders the dashboard template
    # No authentication required here
    return render_template('dashboard.html')

@app.route('/dashboard/student')
def student_dashboard_page():
    return render_template('student_dashboard.html')

@app.route('/dashboard/employee')
def employee_dashboard_page():
    if 'user_id' not in session or session.get('user_type') != 'employee':
        return redirect(url_for('login_page'))
    return render_template('employee_dash.html')

@app.route('/dashboard/tpo')
def tpo_dashboard_page():
    if 'user_id' not in session or session.get('user_type') != 'tpo':
        return redirect(url_for('login_page'))
    return render_template('tpo.html')

@app.route('/dashboard/super-admin')
def super_admin_dashboard_page():
    return render_template('super_admin_dashboard.html')

@app.route('/reset-password')
def reset_password_page():
    return render_template('reset_password.html')

# API Routes
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    user_type = data.get('user_type')
    
    print(f"Login attempt: username={username}, user_type={user_type}")
    
    user = User.query.filter_by(username=username, user_type=user_type).first()
    
    if user and user.check_password(password):
        if not user.is_active:
            return jsonify({
                'status': 'error',
                'message': 'Account is deactivated'
            }), 403
        
        if user.requires_password_reset:
            return jsonify({
                'status': 'error',
                'message': 'Password reset required',
                'requires_reset': True
            }), 403
        
        # Create JWT token
        access_token = create_access_token(identity={
            'user_id': user.id,
            'username': user.username,
            'user_type': user.user_type
        })
        
        print(f"Login successful: username={username}, user_type={user_type}")
        
        return jsonify({
            'status': 'success',
            'message': 'Login successful',
            'access_token': access_token,
            'user': {
                'id': user.id,
                'username': user.username,
                'user_type': user.user_type,
                'first_name': user.first_name,
                'last_name': user.last_name
            }
        }), 200
    else:
        print(f"Login failed: username={username}, user_type={user_type}")
        return jsonify({
            'status': 'error',
            'message': 'Invalid username, password, or user type'
        }), 401

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    user_type = data.get('user_type')
    first_name = data.get('first_name')
    last_name = data.get('last_name')
    
    # Only allow student and employer registration
    if user_type not in ['student', 'employer']:
        return jsonify({
            'status': 'error',
            'message': 'Invalid user type for registration'
        }), 400
    
    if User.query.filter_by(username=username).first():
        return jsonify({
            'status': 'error',
            'message': 'Username already exists'
        }), 400
    
    if User.query.filter_by(email=email).first():
        return jsonify({
            'status': 'error',
            'message': 'Email already exists'
        }), 400
    
    user = User(
        username=username,
        email=email,
        user_type=user_type,
        first_name=first_name,
        last_name=last_name
    )
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
    try:
        current_user = get_jwt_identity()
        print(f"Profile request for user: {current_user}")
        
        if not current_user or 'user_id' not in current_user:
            print("Invalid JWT payload")
            return jsonify({
                'status': 'error',
                'message': 'Invalid authentication token'
            }), 401
        
        user = User.query.get(current_user['user_id'])
        
        if not user:
            print(f"User not found: {current_user['user_id']}")
            return jsonify({
                'status': 'error',
                'message': 'User not found'
            }), 404
        
        print(f"Profile found for: {user.username}, type: {user.user_type}")
        
        return jsonify({
            'status': 'success',
            'user': {
                'id': user.id,
                'username': user.username,
                'user_type': user.user_type,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'email': user.email,
                'company_name': user.company_name if user.user_type == 'employer' else None,
                'company_website': user.company_website if user.user_type == 'employer' else None
            }
        }), 200
    except Exception as e:
        print(f"Error in profile endpoint: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Internal server error'
        }), 500

@app.route('/api/profile/update', methods=['PUT'])
@jwt_required()
def update_profile():
    try:
        current_user = get_jwt_identity()
        
        if not current_user or 'user_id' not in current_user:
            return jsonify({
                'status': 'error',
                'message': 'Invalid authentication token'
            }), 401
        
        user = User.query.get(current_user['user_id'])
        
        if not user:
            return jsonify({
                'status': 'error',
                'message': 'User not found'
            }), 404
        
        data = request.get_json()
        if not data:
            return jsonify({
                'status': 'error',
                'message': 'No data provided'
            }), 400
        
        # Update allowed fields
        if 'first_name' in data:
            user.first_name = data['first_name']
        if 'last_name' in data:
            user.last_name = data['last_name']
        if 'email' in data:
            # Check if email is already in use by another user
            existing_user = User.query.filter_by(email=data['email']).first()
            if existing_user and existing_user.id != user.id:
                return jsonify({
                    'status': 'error',
                    'message': 'Email already in use'
                }), 400
            user.email = data['email']
        
        # Update employer-specific fields
        if user.user_type == 'employer':
            if 'company_name' in data:
                user.company_name = data['company_name']
            if 'company_website' in data:
                user.company_website = data['company_website']
        
        # Update TPO-specific fields
        if user.user_type == 'tpo':
            if 'institute' in data:
                user.institute = data['institute']
            if 'department' in data:
                user.department = data['department']
        
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Profile updated successfully',
            'user': {
                'id': user.id,
                'username': user.username,
                'user_type': user.user_type,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'email': user.email,
                'company_name': user.company_name if user.user_type == 'employer' else None,
                'company_website': user.company_website if user.user_type == 'employer' else None,
                'institute': user.institute if user.user_type == 'tpo' else None,
                'department': user.department if user.user_type == 'tpo' else None
            }
        }), 200
    except Exception as e:
        print(f"Error in update profile endpoint: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Internal server error: {str(e)}'
        }), 500

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

# Super Admin Routes
@app.route('/api/admin/create-tpo', methods=['POST'])
@jwt_required()
def create_tpo():
    current_user = get_jwt_identity()
    if current_user['user_type'] != 'super_admin':
        return jsonify({
            'status': 'error',
            'message': 'Only super admin can create TPO accounts'
        }), 403
    
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    first_name = data.get('first_name')
    last_name = data.get('last_name')
    institute = data.get('institute')
    department = data.get('department')
    
    if User.query.filter_by(username=username).first():
        return jsonify({
            'status': 'error',
            'message': 'Username already exists'
        }), 400
    
    if User.query.filter_by(email=email).first():
        return jsonify({
            'status': 'error',
            'message': 'Email already exists'
        }), 400
    
    tpo = User(
        username=username,
        email=email,
        user_type='tpo',
        first_name=first_name,
        last_name=last_name,
        institute=institute,
        department=department,
        created_by=current_user['user_id'],
        requires_password_reset=True
    )
    tpo.set_password(password)
    
    db.session.add(tpo)
    db.session.commit()
    
    return jsonify({
        'status': 'success',
        'message': 'TPO account created successfully'
    }), 201

@app.route('/api/admin/tpos', methods=['GET'])
@jwt_required()
def get_tpos():
    current_user = get_jwt_identity()
    if current_user['user_type'] != 'super_admin':
        return jsonify({
            'status': 'error',
            'message': 'Only super admin can view TPO accounts'
        }), 403
    
    tpos = User.query.filter_by(user_type='tpo').all()
    return jsonify({
        'status': 'success',
        'tpos': [{
            'id': tpo.id,
            'username': tpo.username,
            'email': tpo.email,
            'first_name': tpo.first_name,
            'last_name': tpo.last_name,
            'institute': tpo.institute,
            'department': tpo.department,
            'is_active': tpo.is_active,
            'is_verified': tpo.is_verified,
            'created_at': tpo.created_at.isoformat()
        } for tpo in tpos]
    }), 200

@app.route('/api/admin/tpo/<int:tpo_id>', methods=['PUT'])
@jwt_required()
def update_tpo(tpo_id):
    current_user = get_jwt_identity()
    if current_user['user_type'] != 'super_admin':
        return jsonify({
            'status': 'error',
            'message': 'Only super admin can update TPO accounts'
        }), 403
    
    tpo = User.query.get_or_404(tpo_id)
    if tpo.user_type != 'tpo':
        return jsonify({
            'status': 'error',
            'message': 'User is not a TPO'
        }), 400
    
    data = request.get_json()
    if 'is_active' in data:
        tpo.is_active = data['is_active']
    if 'is_verified' in data:
        tpo.is_verified = data['is_verified']
    if 'requires_password_reset' in data:
        tpo.requires_password_reset = data['requires_password_reset']
    
    db.session.commit()
    
    return jsonify({
        'status': 'success',
        'message': 'TPO account updated successfully'
    }), 200

# Password Reset Route
@app.route('/api/reset-password', methods=['POST'])
@jwt_required()
def reset_password():
    current_user = get_jwt_identity()
    user = User.query.get(current_user['user_id'])
    
    if not user.requires_password_reset:
        return jsonify({
            'status': 'error',
            'message': 'Password reset not required'
        }), 400
    
    data = request.get_json()
    new_password = data.get('new_password')
    
    user.set_password(new_password)
    user.requires_password_reset = False
    
    db.session.commit()
    
    return jsonify({
        'status': 'success',
        'message': 'Password reset successful'
    }), 200

@app.route('/student/login', methods=['GET', 'POST'])
def student_login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        remember = request.form.get('remember')

        print(f"[LOGIN] Attempt for email: {email}")
        user = User.query.filter_by(email=email, user_type='student').first()
        print(f"[LOGIN] User found: {user}")
        if user and user.check_password(password):
            print(f"[LOGIN] Success for {email}")
            session['user_id'] = user.id
            session['user_name'] = user.first_name
            session['user_type'] = 'student'
            if remember:
                session.permanent = True
            return redirect(url_for('student_dashboard'))
        else:
            print(f"[LOGIN] Failed for {email}")
            return render_template('stu_login.html', error='Invalid email or password')

    return render_template('stu_login.html')

@app.route('/student/signup', methods=['GET', 'POST'])
def student_signup():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        terms = request.form.get('terms')

        print(f"[SIGNUP] Attempt for email: {email}")
        if User.query.filter_by(email=email, user_type='student').first():
            print(f"[SIGNUP] Email already registered: {email}")
            return render_template('stu_signup.html', error='Email already registered')

        if password != confirm_password:
            print(f"[SIGNUP] Passwords do not match for {email}")
            return render_template('stu_signup.html', error='Passwords do not match')

        if not terms:
            print(f"[SIGNUP] Terms not accepted for {email}")
            return render_template('stu_signup.html', error='Please accept terms and conditions')

        new_user = User(
            username=email,
            email=email,
            user_type='student',
            first_name=first_name,
            last_name=last_name
        )
        new_user.set_password(password)
        try:
            db.session.add(new_user)
            db.session.commit()
            print(f"[SIGNUP] Success for {email}")
            return redirect(url_for('login_page'))
        except Exception as e:
            db.session.rollback()
            print(f"[SIGNUP] Registration failed for {email}: {e}")
            return render_template('stu_signup.html', error='Registration failed. Please try again.')

    return render_template('stu_signup.html')

@app.route('/student/registration', methods=['GET', 'POST'])
def student_registration():
    if request.method == 'POST':
        full_name = request.form.get('full_name', '').strip()
        email = request.form.get('email', '').strip()
        contact = request.form.get('contact', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        college = request.form.get('college', '').strip()
        branch = request.form.get('branch', '').strip()
        year = request.form.get('year', '').strip()
        agree = request.form.get('agree')

        # Split full name
        first_name, last_name = '', ''
        if full_name:
            parts = full_name.split()
            first_name = parts[0]
            last_name = ' '.join(parts[1:]) if len(parts) > 1 else ''

        # Validation
        if User.query.filter_by(email=email, user_type='student').first():
            return render_template('student_registration.html', error='Email already registered')
        if password != confirm_password:
            return render_template('student_registration.html', error='Passwords do not match')
        if not agree:
            return render_template('student_registration.html', error='Please accept terms and conditions')
        if not all([first_name, email, password, college, branch, year]):
            return render_template('student_registration.html', error='Please fill all required fields')

        new_user = User(
            username=email,
            email=email,
            user_type='student',
            first_name=first_name,
            last_name=last_name,
            institute=college,
            department=branch
        )
        new_user.set_password(password)
        try:
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('login_page'))
        except Exception as e:
            db.session.rollback()
            return render_template('student_registration.html', error='Registration failed. Please try again.')
    return render_template('student_registration.html')

@app.route('/student/dashboard')
def student_dashboard():
    if 'user_id' not in session or session.get('user_type') != 'student':
        return redirect(url_for('login_page'))
    return render_template('stu_dash.html')

@app.route('/student/logout')
def student_logout():
    session.clear()
    return redirect(url_for('student_login'))

@app.route('/check-session')
def check_session():
    return jsonify({'valid': 'user_id' in session})

@app.route('/forgot-password')
def forgot_password():
    # Implement password reset functionality
    return "Password reset functionality coming soon"

# Placeholder routes for navigation
@app.route('/internships')
def internships():
    return "Internships page coming soon"

@app.route('/courses')
def courses():
    return "Courses page coming soon"

@app.route('/offers')
def offers():
    return "Offers page coming soon"

@app.route('/jobs')
def jobs():
    return "Jobs page coming soon"

@app.route('/profile')
def profile():
    return "Profile page coming soon"

@app.route('/settings')
def settings():
    return "Settings page coming soon"

@app.route('/download-app')
def download_app():
    return "App download page coming soon"

@app.route('/edit-resume')
def edit_resume():
    return "Resume editor coming soon"

@app.route('/employee/signup', methods=['GET', 'POST'])
def employee_signup():
    if request.method == 'POST':
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()
        email = request.form.get('email', '').strip()
        phone = request.form.get('phone', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        company_name = request.form.get('company_name', '').strip()
        company_website = request.form.get('company_website', '').strip()
        designation = request.form.get('designation', '').strip()
        department = request.form.get('department', '').strip()
        terms = request.form.get('terms')
        # Placeholder for file upload
        # verification_doc = request.files.get('verification_doc')

        if User.query.filter_by(email=email, user_type='employee').first():
            return render_template('employee_registration.html', error='Email already registered')
        if password != confirm_password:
            return render_template('employee_registration.html', error='Passwords do not match')
        if not terms:
            return render_template('employee_registration.html', error='Please accept terms and conditions')
        if not all([first_name, last_name, email, password, company_name, department]):
            return render_template('employee_registration.html', error='Please fill all required fields')

        new_user = User(
            username=email,
            email=email,
            user_type='employee',
            first_name=first_name,
            last_name=last_name,
            company_name=company_name,
            company_website=company_website,
            department=department
        )
        new_user.set_password(password)
        try:
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('login_page'))
        except Exception as e:
            db.session.rollback()
            return render_template('employee_registration.html', error='Registration failed. Please try again.')
    return render_template('employee_registration.html')

@app.route('/employee/login', methods=['GET', 'POST'])
def employee_login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        remember = request.form.get('remember')

        print(f"[EMPLOYEE LOGIN] Attempt for email: {email}")
        user = User.query.filter_by(email=email, user_type='employee').first()
        print(f"[EMPLOYEE LOGIN] User found: {user}")
        if user and user.check_password(password):
            print(f"[EMPLOYEE LOGIN] Success for {email}")
            session['user_id'] = user.id
            session['user_name'] = user.first_name
            session['user_type'] = 'employee'
            if remember:
                session.permanent = True
            return redirect(url_for('employee_dashboard_page'))
        else:
            print(f"[EMPLOYEE LOGIN] Failed for {email}")
            return render_template('employee_registration.html', error='Invalid email or password')

    return render_template('employee_registration.html')

@app.route('/tpo/signup', methods=['GET', 'POST'])
def tpo_signup():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        terms = request.form.get('terms')

        print(f"[TPO SIGNUP] Attempt for email: {email}")
        if User.query.filter_by(email=email, user_type='tpo').first():
            print(f"[TPO SIGNUP] Email already registered: {email}")
            return render_template('TPO_Signup.html', error='Email already registered')

        if password != confirm_password:
            print(f"[TPO SIGNUP] Passwords do not match for {email}")
            return render_template('TPO_Signup.html', error='Passwords do not match')

        if not terms:
            print(f"[TPO SIGNUP] Terms not accepted for {email}")
            return render_template('TPO_Signup.html', error='Please accept terms and conditions')

        new_user = User(
            username=email,
            email=email,
            user_type='tpo',
            first_name=first_name,
            last_name=last_name
        )
        new_user.set_password(password)
        try:
            db.session.add(new_user)
            db.session.commit()
            print(f"[TPO SIGNUP] Success for {email}")
            return redirect(url_for('login_page'))
        except Exception as e:
            db.session.rollback()
            print(f"[TPO SIGNUP] Registration failed for {email}: {e}")
            return render_template('TPO_Signup.html', error='Registration failed. Please try again.')

    return render_template('TPO_Signup.html')

@app.route('/tpo/login', methods=['GET', 'POST'])
def tpo_login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        remember = request.form.get('remember')

        print(f"[TPO LOGIN] Attempt for email: {email}")
        user = User.query.filter_by(email=email, user_type='tpo').first()
        print(f"[TPO LOGIN] User found: {user}")
        if user and user.check_password(password):
            print(f"[TPO LOGIN] Success for {email}")
            session['user_id'] = user.id
            session['user_name'] = user.first_name
            session['user_type'] = 'tpo'
            if remember:
                session.permanent = True
            return redirect(url_for('tpo_dashboard_page'))
        else:
            print(f"[TPO LOGIN] Failed for {email}")
            return render_template('TPO_Signup.html', error='Invalid email or password')

    return render_template('TPO_Signup.html')

@app.route('/employee/logout')
def employee_logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/tpo/registration', methods=['GET', 'POST'])
def tpo_registration():
    if request.method == 'POST':
        full_name = request.form.get('full_name', '').strip()
        email = request.form.get('email', '').strip()
        contact = request.form.get('contact', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        college = request.form.get('college', '').strip()
        designation = request.form.get('designation', '').strip()
        agree = request.form.get('agree')

        print(f"[TPO REG DEBUG] full_name: {full_name}, email: {email}, contact: {contact}, password: {password}, confirm_password: {confirm_password}, college: {college}, designation: {designation}, agree: {agree}")

        # Split full name
        first_name, last_name = '', ''
        if full_name:
            parts = full_name.split()
            first_name = parts[0]
            last_name = ' '.join(parts[1:]) if len(parts) > 1 else ''

        # Validation
        if User.query.filter_by(email=email, user_type='tpo').first():
            print("[TPO REG DEBUG] Email already registered")
            return render_template('tpo_registration.html', error='Email already registered')
        if password != confirm_password:
            print("[TPO REG DEBUG] Passwords do not match")
            return render_template('tpo_registration.html', error='Passwords do not match')
        if not agree:
            print("[TPO REG DEBUG] Terms not accepted")
            return render_template('tpo_registration.html', error='Please accept terms and conditions')
        if not all([first_name, email, password, college, designation]):
            print("[TPO REG DEBUG] Missing required fields")
            return render_template('tpo_registration.html', error='Please fill all required fields')

        new_user = User(
            username=email,
            email=email,
            user_type='tpo',
            first_name=first_name,
            last_name=last_name,
            institute=college,
            department=designation
        )
        new_user.set_password(password)
        try:
            db.session.add(new_user)
            db.session.commit()
            print("[TPO REG DEBUG] Registration successful, redirecting to login page")
            return redirect(url_for('login_page'))
        except Exception as e:
            db.session.rollback()
            print(f"[TPO REG DEBUG] Registration failed: {e}")
            return render_template('tpo_registration.html', error='Registration failed. Please try again.')
    return render_template('tpo_registration.html')

@app.route('/tpo/logout')
def tpo_logout():
    session.clear()
    return redirect(url_for('index'))

# Initialize the database with a super admin account
def init_db():
    with app.app_context():
        db.create_all()
        
        # Check if super admin exists
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

if __name__ == '__main__':
    try:
        # Make sure database exists first
        from init_mysql import create_database
        create_database()
        print("MySQL database initialized")
        
        # Then initialize Flask-SQLAlchemy models
        init_db()
        app.run(debug=True)
    except Exception as e:
        print(f"Error starting application: {e}") 