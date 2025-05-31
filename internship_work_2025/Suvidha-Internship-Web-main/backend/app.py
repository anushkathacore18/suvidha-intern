import os
from flask import Flask, render_template, request, redirect, session, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import or_
from sqlalchemy.sql import text
from dotenv import load_dotenv


load_dotenv()
print("DB URL:", os.getenv("MYSQL_DB_URL"))

app = Flask(__name__)
app.secret_key = 'suvidha-802'
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('MYSQL_DB_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'Uploads'
ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx'}

# Ensure upload directory exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

db = SQLAlchemy(app)

# ------------------ Models ------------------ #
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)  # Matches updated schema
    password_hash = db.Column(db.String(128), nullable=False)  # Matches updated schema
    role = db.Column(db.String(20), nullable=False)  # student, employee, or tpo

    __table_args__ = (
        db.UniqueConstraint('username', name='unique_username'),
        db.UniqueConstraint('email', name='unique_email'),
    )

    def set_password(self, password):
        """Hash and store the password."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Verify the password against the stored hash."""
        return check_password_hash(self.password_hash, password)

class Profile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), unique=True, nullable=False)
    resume_path = db.Column(db.String(255))
    profile_photo = db.Column(db.String(255))  # New field for profile photo
    full_name = db.Column(db.String(100))
    course_year = db.Column(db.String(100))
    email = db.Column(db.String(100))
    phone = db.Column(db.String(20))
    address = db.Column(db.Text)  # New field
    city = db.Column(db.String(100))  # New field
    state = db.Column(db.String(100))  # New field
    pincode = db.Column(db.String(20))  # New field
    country = db.Column(db.String(100))  # New field
    college = db.Column(db.String(100))
    branch = db.Column(db.String(100))
    graduation_year = db.Column(db.Integer)  # New field
    linkedin_url = db.Column(db.String(255))  # New field
    github_url = db.Column(db.String(255))  # New field
    about = db.Column(db.Text)  # New field
    designation = db.Column(db.String(100))
    company_website = db.Column(db.String(255))
    department = db.Column(db.String(100))
    user = db.relationship('User', backref=db.backref('profile', uselist=False))

class Rating(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    from_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    to_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.Text)
    from_user = db.relationship('User', foreign_keys=[from_id])
    to_user = db.relationship('User', foreign_keys=[to_id])

class Certificate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    certification_name = db.Column(db.String(100))  # Matches schema
    issuer = db.Column(db.String(100))
    duration = db.Column(db.String(50))
    credential_id = db.Column(db.String(100))
    filename = db.Column(db.String(255))  # For file path

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    project_name = db.Column(db.String(255))  # Matches schema
    project_type = db.Column(db.String(100))
    duration = db.Column(db.String(50))
    description = db.Column(db.Text)
    github_link = db.Column(db.String(200))

class Education(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    degree = db.Column(db.String(100))
    institution = db.Column(db.String(100))
    duration = db.Column(db.String(50))
    grade = db.Column(db.String(20))

class Experience(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    position = db.Column(db.String(100))
    company = db.Column(db.String(100))
    duration = db.Column(db.String(50))
    description = db.Column(db.Text)

class Skill(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    skill_name = db.Column(db.String(100))

class Application(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    internship_id = db.Column(db.Integer, nullable=False)
    applied_on = db.Column(db.DateTime, server_default=text('CURRENT_TIMESTAMP'))

class Internship(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    company_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    posted_on = db.Column(db.DateTime, server_default=text('CURRENT_TIMESTAMP'))
    company = db.relationship('User', backref='internships')

# ------------------ Database Initialization ------------------ #
def init_db():
    with app.app_context():
        db.create_all()

# Initialize database during app setup
init_db()

# ------------------ Helper Functions ------------------ #
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ------------------ Routes ------------------ #
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register/<role>', methods=['GET', 'POST'])
def register(role='student'):
    if role not in ['student', 'employee', 'tpo']:
        return render_template('login.html', error="Invalid role")

    template_map = {
        'student': 'student_registration.html',
        'employee': 'employee_registration.html',
        'tpo': 'tpo_registration.html'
    }

    if request.method == 'POST':
        try:
            username = request.form.get('username')
            email = request.form.get('email')
            password = request.form.get('password')
            confirm_password = request.form.get('confirm_password')
            full_name = request.form.get('full_name')
            phone = request.form.get('phone')

            # Validate input
            if not all([username, email, password, confirm_password, full_name, phone]):
                return render_template(template_map[role], error="All fields are required")
            if password != confirm_password:
                return render_template(template_map[role], error="Passwords do not match")
            if len(password) < 8:
                return render_template(template_map[role], error="Password must be at least 8 characters")

            # Check if username or email exists
            if User.query.filter(or_(User.username == username, User.email == email)).first():
                return render_template(template_map[role], error="Username or email already taken")

            # Create new user
            user = User(username=username, email=email, role=role)
            user.set_password(password)
            db.session.add(user)
            db.session.flush()  # Get user.id

            # Create profile
            profile_data = {
                'user_id': user.id,
                'full_name': full_name,
                'email': email,
                'phone': phone
            }

            if role == 'student':
                profile_data.update({
                    'course_year': request.form.get('course_year'),
                    'college': request.form.get('college'),
                    'branch': request.form.get('branch')
                })
            elif role == 'tpo':
                verification_doc = request.files.get('verification_doc')
                if verification_doc and allowed_file(verification_doc.filename):
                    filename = secure_filename(verification_doc.filename)
                    verification_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    verification_doc.save(verification_path)
                    profile_data['resume_path'] = verification_path
                profile_data.update({
                    'college': request.form.get('college'),
                    'designation': request.form.get('designation')
                })
            elif role == 'employee':
                verification_doc = request.files.get('verification_doc')
                if verification_doc and allowed_file(verification_doc.filename):
                    filename = secure_filename(verification_doc.filename)
                    verification_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    verification_doc.save(verification_path)
                    profile_data['resume_path'] = verification_path
                profile_data.update({
                    'location': request.form.get('company_name'),
                    'company_website': request.form.get('company_website'),
                    'designation': request.form.get('designation'),
                    'department': request.form.get('department')
                })

            profile = Profile(**profile_data)
            db.session.add(profile)
            db.session.commit()
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            return render_template(template_map[role], error=f"Registration failed: {str(e)}")
    
    return render_template(template_map[role])

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            role = request.form.get('role', 'student')
            identifier = request.form.get('username')  # Could be username or email
            password = request.form.get('password')

            # Query user by username or email, and role
            user = User.query.filter(
                or_(User.username == identifier, User.email == identifier),
                User.role == role
            ).first()

            # Check if user exists and password matches
            if user and user.check_password(password):
                session['user_id'] = user.id
                session['role'] = user.role
                return redirect(url_for('dashboard'))
            else:
                return render_template('login.html', error="Invalid username/email, password, or role")
        except Exception as e:
            return render_template('login.html', error=f"Login failed: {str(e)}")
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session or 'role' not in session:
        return redirect(url_for('login'))
    try:
        user = db.session.get(User, session['user_id'])
        if not user:
            session.clear()
            return redirect(url_for('login'))
        
        dashboard_map = {
            'student': 'stu_dash.html',
            'employee': 'employee_dash.html',
            'tpo': 'tpo_dash.html'
        }
        
        template = dashboard_map.get(user.role, 'stu_dash.html')
        
        if user.role == 'student':
            try:
                others = User.query.filter(User.id != user.id).all()
                received = Rating.query.filter_by(to_id=user.id).all()
                internships = Internship.query.order_by(Internship.posted_on.desc()).all()
                return render_template(template, user=user, others=others, received=received, internships=internships)
            except Exception as e:
                print(f"Error in student dashboard: {str(e)}")
                return render_template(template, user=user, others=[], received=[], internships=[])
                
        elif user.role == 'employee':
            try:
                students_count = User.query.filter_by(role='student').count()
                internships_count = Internship.query.filter_by(company_id=user.id).count()
                
                # Fixed the filter syntax here
                applications = Application.query.join(Internship).filter(Internship.company_id == user.id).all()
                applications_count = len(applications) if applications else 0
                
                return render_template(template, user=user, students_count=students_count, 
                                     internships_count=internships_count, applications_count=applications_count, 
                                     applications=applications)
            except Exception as e:
                print(f"Error in employee dashboard: {str(e)}")
                return render_template(template, user=user, students_count=0, 
                                     internships_count=0, applications_count=0, applications=[])
                
        elif user.role == 'tpo':
            try:
                students = User.query.filter_by(role='student').all()
                students_count = len(students) if students else 0
                internships_count = Internship.query.count()
                applications_count = Application.query.count()
                
                return render_template(template, user=user, students_count=students_count, 
                                     internships_count=internships_count, applications_count=applications_count, 
                                     students=students)
            except Exception as e:
                print(f"Error in tpo dashboard: {str(e)}")
                return render_template(template, user=user, students_count=0, 
                                     internships_count=0, applications_count=0, students=[])
    
    except Exception as e:
        print(f"General dashboard error: {str(e)}")
        return render_template('login.html', error=f"Error loading dashboard: {str(e)}")


ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx'}

def allowed_file(filename, file_type='image'):
    ALLOWED_EXTENSIONS = {
        'image': {'png', 'jpg', 'jpeg', 'gif'},
        'document': {'pdf', 'doc', 'docx'}
    }
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS.get(file_type, set())

app.config['UPLOAD_FOLDER'] = 'static/Uploads'

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session or 'role' not in session:
        return redirect(url_for('login'))
    
    user = db.session.get(User, session['user_id'])
    if not user:
        session.clear()
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        try:
            # Initialize or update profile
            if not user.profile:
                profile = Profile(user_id=user.id)
                db.session.add(profile)
            
            # Update profile fields
            profile_data = {
                'full_name': request.form.get('full_name'),
                'email': request.form.get('email'),
                'phone': request.form.get('phone'),
                'address': request.form.get('address'),
                'city': request.form.get('city'),
                'state': request.form.get('state'),
                'pincode': request.form.get('pincode'),
                'country': request.form.get('country'),
                'college': request.form.get('college'),
                'branch': request.form.get('branch'),
                'course_year': request.form.get('course_year'),
                'graduation_year': request.form.get('graduation_year'),
                'linkedin_url': request.form.get('linkedin_url'),
                'github_url': request.form.get('github_url'),
                'about': request.form.get('about')
            }
            
            for key, value in profile_data.items():
                setattr(user.profile, key, value)
            
            # Update username
            if request.form.get('username'):
                user.username = request.form.get('username')
            
            # Handle profile photo upload
            profile_photo = request.files.get('profile_photo')
            if profile_photo and allowed_file(profile_photo.filename):
                filename = secure_filename(profile_photo.filename)
                photo_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                profile_photo.save(photo_path)
                user.profile.profile_photo = f'Uploads/{filename}'  # Store relative path
            
            # Handle resume upload (for resume builder compatibility)
            resume = request.files.get('resume')
            if resume and allowed_file(resume.filename):
                filename = secure_filename(resume.filename)
                resume_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                resume.save(resume_path)
                user.profile.resume_path = f'Uploads/{filename}'
            
            # Handle skills
            skills = request.form.getlist('skills[]')
            if skills:
                Skill.query.filter_by(user_id=user.id).delete()
                for skill in skills:
                    if skill.strip():
                        db.session.add(Skill(user_id=user.id, skill_name=skill.strip()))
            
            # Handle projects
            project_names = request.form.getlist('project_name[]')
            project_types = request.form.getlist('project_type[]')
            durations = request.form.getlist('duration[]')
            descriptions = request.form.getlist('description[]')
            github_links = request.form.getlist('github_link[]')
            
            if project_names:
                Project.query.filter_by(user_id=user.id).delete()
                for name, p_type, dur, desc, link in zip(project_names, project_types, durations, descriptions, github_links):
                    if name.strip():
                        db.session.add(Project(
                            user_id=user.id,
                            project_name=name.strip(),
                            project_type=p_type.strip(),
                            duration=dur.strip(),
                            description=desc.strip(),
                            github_link=link.strip()
                        ))
            
            # Handle certificates
            cert_names = request.form.getlist('certification_name[]')
            issuers = request.form.getlist('issuer[]')
            cert_durations = request.form.getlist('cert_duration[]')
            credential_ids = request.form.getlist('credential_id[]')
            cert_files = request.files.getlist('certificate_file[]')
            
            if cert_names:
                Certificate.query.filter_by(user_id=user.id).delete()
                for i, (name, issuer, dur, cred_id) in enumerate(zip(cert_names, issuers, cert_durations, credential_ids)):
                    if name.strip():
                        cert = Certificate(
                            user_id=user.id,
                            certification_name=name.strip(),
                            issuer=issuer.strip(),
                            duration=dur.strip(),
                            credential_id=cred_id.strip()
                        )
                        if i < len(cert_files) and cert_files[i] and allowed_file(cert_files[i].filename):
                            filename = secure_filename(cert_files[i].filename)
                            cert_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                            cert_files[i].save(cert_path)
                            cert.filename = f'Uploads/{filename}'
                        db.session.add(cert)
            
            db.session.commit()
            
            # Return JSON for AJAX requests (from resume builder)
            if 'X-Requested-With' in request.headers:
                return jsonify({'success': True})
            
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            if 'X-Requested-With' in request.headers:
                return jsonify({'success': False, 'error': str(e)}), 500
            flash(f'Error updating profile: {str(e)}', 'error')
            return redirect(url_for('profile'))
    
    skills = Skill.query.filter_by(user_id=user.id).all()
    projects = Project.query.filter_by(user_id=user.id).all()
    certificates = Certificate.query.filter_by(user_id=user.id).all()
    return render_template('profile.html', user=user, skills=skills, projects=projects, certificates=certificates)

@app.route('/post_internship', methods=['GET', 'POST'])
def post_internship():
    if 'user_id' not in session or session['role'] not in ['employee', 'tpo']:
        return redirect(url_for('login'))
    if request.method == 'POST':
        try:
            title = request.form.get('title')
            description = request.form.get('description')
            if not title or not description:
                flash('Title and description are required', 'error')
                return redirect(url_for('post_internship'))
            internship = Internship(title=title, description=description, company_id=session['user_id'])
            db.session.add(internship)
            db.session.commit()
            flash('Internship posted successfully!', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error posting internship: {str(e)}', 'error')
            return redirect(url_for('post_internship'))
    return render_template('post_internship.html')

@app.route('/apply/<int:internship_id>', methods=['GET'])
def apply_to_internship(internship_id):
    if 'user_id' not in session or session['role'] != 'student':
        return redirect(url_for('login'))
    try:
        existing = Application.query.filter_by(user_id=session['user_id'], internship_id=internship_id).first()
        if existing:
            flash('You have already applied to this internship!', 'warning')
            return redirect(url_for('dashboard'))
        application = Application(user_id=session['user_id'], internship_id=internship_id)
        db.session.add(application)
        db.session.commit()
        flash('Application submitted successfully!', 'success')
        return redirect(url_for('dashboard'))
    except Exception as e:
        db.session.rollback()
        flash(f'Application failed: {str(e)}', 'error')
        return redirect(url_for('dashboard'))

@app.route('/applications')
def applications():
    if 'user_id' not in session or session['role'] not in ['employee', 'tpo']:
        return redirect(url_for('login'))
    user = db.session.get(User, session['user_id'])
    applications = Application.query.join(Internship).filter(Internship.company_id == user.id).all()
    return render_template('applications.html', applications=applications)

@app.route('/students')
def students():
    if 'user_id' not in session or session['role'] != 'tpo':
        return redirect(url_for('login'))
    students = User.query.filter_by(role='student').all()
    return render_template('students.html', students=students)

@app.route('/internships')
def internships():
    location = request.args.get('location')
    stream = request.args.get('stream')
    query = Internship.query
    if location:
        query = query.filter(Internship.description.contains(location))
    if stream:
        query = query.filter(Internship.description.contains(stream))
    internships = query.order_by(Internship.posted_on.desc()).all()
    return render_template('internship_listing.html', internships=internships)

@app.route('/resume_edit')
def resume_edit():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = db.session.get(User, session['user_id'])
    if not user:
        session.clear()
        return redirect(url_for('login'))
    
    skills = Skill.query.filter_by(user_id=user.id).all()
    projects = Project.query.filter_by(user_id=user.id).all()
    certificates = Certificate.query.filter_by(user_id=user.id).all()
    
    return render_template('Resume_edit.html', user=user, skills=skills, projects=projects, certificates=certificates)

@app.route('/help')
def help():
    return render_template('help.html')

@app.route('/rate/<int:to_id>', methods=['GET', 'POST'])
def rate(to_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        try:
            rating_value = int(request.form['rating'])
            comment_text = request.form['comment']
            existing = Rating.query.filter_by(from_id=session['user_id'], to_id=to_id).first()
            if existing:
                existing.rating = rating_value
                existing.comment = comment_text
            else:
                rating = Rating(
                    from_id=session['user_id'],
                    to_id=to_id,
                    rating=rating_value,
                    comment=comment_text
                )
                db.session.add(rating)
            db.session.commit()
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            to_user = User.query.get(to_id)
            return render_template('rate.html', to_user=to_user, error=f"Rating failed: {str(e)}")
    try:
        to_user = User.query.get(to_id)
        return render_template('rate.html', to_user=to_user)
    except Exception as e:
        return redirect(url_for('dashboard'), error=f"Error loading rate page: {str(e)}")

@app.route('/application_page')
def application_page():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    try:
        user = User.query.get(session['user_id'])
        applications = Application.query.filter_by(user_id=user.id).all()
        return render_template('application_page.html', user=user, applications=applications)
    except Exception as e:
        return render_template('login.html', error=f"Error loading application page: {str(e)}")

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

@app.route('/initdb')
def initdb():
    init_db()
    return "Database initialized!"

# ------------------ Main ------------------ #
if __name__ == '__main__':
    app.run(debug=True)