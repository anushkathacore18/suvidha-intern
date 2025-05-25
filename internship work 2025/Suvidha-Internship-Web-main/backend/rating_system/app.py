import os
from flask import Flask, render_template, request, redirect, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from sqlalchemy.sql import text


from dotenv import load_dotenv
load_dotenv()
print("DB URL:", os.getenv("MYSQL_DB_URL"))

app = Flask(__name__)
app.secret_key = 'suvidha-802'
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('MYSQL_DB_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# ------------------ Models ------------------ #
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # student, employee, or company

class Rating(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    from_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    to_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.Text)


    from_user = db.relationship('User', foreign_keys=[from_id])
    to_user = db.relationship('User', foreign_keys=[to_id])


class Profile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), unique=True, nullable=False)
    resume_path = db.Column(db.String(200))
    user = db.relationship('User', backref=db.backref('profile', uselist=False))
   
class Education(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    degree = db.Column(db.String(100))  # Degree/Qualification
    institution = db.Column(db.String(100))  # Institution Name
    duration = db.Column(db.String(50))  # Year - Year
    grade = db.Column(db.String(20))  # Grade/Score

class Experience(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    position = db.Column(db.String(100))  # Position/Role
    company = db.Column(db.String(100))  # Company/Organization
    duration = db.Column(db.String(50))  # Month Year - Month Year
    description = db.Column(db.Text)  # Description of role and responsibilities

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    project_name = db.Column(db.String(100))  # Project Title
    project_type = db.Column(db.String(100))  # Project Type
    duration = db.Column(db.String(50))  # Month Year - Month Year
    description = db.Column(db.Text)  # Description of project, technologies, role

class Skill(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    skill_name = db.Column(db.String(100))  # Skill Name

class Certification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    certification_name = db.Column(db.String(100))  # Certification Name
    issuer = db.Column(db.String(100))  # Issuing Organization
    duration = db.Column(db.String(50))  # Month Year - Month Year (or No Expiry)
    credential_id = db.Column(db.String(100))  # Credential ID

class Application(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    internship_id = db.Column(db.Integer, nullable=False)
    applied_on = db.Column(db.TIMESTAMP, server_default=text('CURRENT_TIMESTAMP'))


# ------------------ Database Initialization ------------------ #
def init_db():
    with app.app_context():
        db.create_all()

# Initialize database during app setup
init_db()

# ------------------ Routes ------------------ #
@app.route('/')
def home():
    return redirect('/login')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        try:
            existing_user = User.query.filter_by(username=username).first()
            if existing_user:
                return render_template('register.html', error="Username already exists!")
            new_user = User(
                username=username,
                password=request.form['password'],
                role=request.form['role']
            )
            db.session.add(new_user)
            db.session.commit()
            return redirect('/login')
        except Exception as e:
            db.session.rollback()
            return render_template('register.html', error=f"Registration failed: {str(e)}")
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            user = User.query.filter_by(
                username=request.form['username'],
                password=request.form['password']
            ).first()
            if user:
                session['user_id'] = user.id
                return redirect('/dashboard')
            else:
                return render_template('login.html', error="Invalid credentials")
        except Exception as e:
            return render_template('login.html', error=f"Login failed: {str(e)}")
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/login')
    try:
        user = User.query.get(session['user_id'])
        others = User.query.filter(User.id != user.id).all()
        received = Rating.query.filter_by(to_id=user.id).all()
        return render_template('dashboard.html', user=user, others=others, received=received)
    except Exception as e:
        return render_template('login.html', error=f"Error loading dashboard: {str(e)}")


# ------------------ Resume page------------------ #
@app.route('/resume', methods=['GET', 'POST'])
def resume():
    if 'user_id' not in session:
        return redirect('/login')
    user_id = session['user_id']

    if request.method == 'POST':
        try:
            # Handle resume data saving
            data = request.form.get('resume_data')
            if data:
                resume_data = json.loads(data)
                
                # Update Profile
                profile = Profile.query.filter_by(user_id=user_id).first()
                if not profile:
                    profile = Profile(user_id=user_id)
                    db.session.add(profile)
                profile.full_name = resume_data.get('full_name')
                profile.course_year = resume_data.get('course_year')
                profile.email = resume_data.get('email')
                profile.phone = resume_data.get('phone')
                profile.location = resume_data.get('location')

                # Update Education
                Education.query.filter_by(user_id=user_id).delete()
                for edu in resume_data.get('education', []):
                    new_edu = Education(
                        user_id=user_id,
                        degree=edu.get('degree'),
                        institution=edu.get('institution'),
                        duration=edu.get('duration'),
                        grade=edu.get('grade')
                    )
                    db.session.add(new_edu)

                # Update Experience
                Experience.query.filter_by(user_id=user_id).delete()
                for exp in resume_data.get('experience', []):
                    new_exp = Experience(
                        user_id=user_id,
                        position=exp.get('position'),
                        company=exp.get('company'),
                        duration=exp.get('duration'),
                        description=exp.get('description')
                    )
                    db.session.add(new_exp)

                # Update Projects
                Project.query.filter_by(user_id=user_id).delete()
                for proj in resume_data.get('projects', []):
                    new_proj = Project(
                        user_id=user_id,
                        project_name=proj.get('project_name'),
                        project_type=proj.get('project_type'),
                        duration=proj.get('duration'),
                        description=proj.get('description')
                    )
                    db.session.add(new_proj)

                # Update Skills
                Skill.query.filter_by(user_id=user_id).delete()
                for skill in resume_data.get('skills', []):
                    new_skill = Skill(user_id=user_id, skill_name=skill)
                    db.session.add(new_skill)

                # Update Certifications
                Certification.query.filter_by(user_id=user_id).delete()
                for cert in resume_data.get('certifications', []):
                    new_cert = Certification(
                        user_id=user_id,
                        certification_name=cert.get('certification_name'),
                        issuer=cert.get('issuer'),
                        duration=cert.get('duration'),
                        credential_id=cert.get('credential_id')
                    )
                    db.session.add(new_cert)

                # Handle resume file upload
                resume_file = request.files.get('resume_file')
                if resume_file and allowed_file(resume_file.filename):
                    filename = secure_filename(resume_file.filename)
                    resume_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    resume_file.save(resume_path)
                    profile.resume_path = resume_path

                db.session.commit()
                return jsonify({'status': 'success', 'message': 'Resume saved successfully'})

            return jsonify({'status': 'error', 'message': 'No valid data provided'})
        except Exception as e:
            db.session.rollback()
            return jsonify({'status': 'error', 'message': f"Error: {str(e)}"})

    # GET: Render resume edit page with existing data
    profile = Profile.query.filter_by(user_id=user_id).first()
    educations = Education.query.filter_by(user_id=user_id).all()
    experiences = Experience.query.filter_by(user_id=user_id).all()
    projects = Project.query.filter_by(user_id=user_id).all()
    skills = Skill.query.filter_by(user_id=user_id).all()
    certifications = Certification.query.filter_by(user_id=user_id).all()
    
    resume_data = {
        'full_name': profile.full_name if profile else '',
        'course_year': profile.course_year if profile else '',
        'email': profile.email if profile else '',
        'phone': profile.phone if profile else '',
        'location': profile.location if profile else '',
        'education': [{
            'degree': edu.degree,
            'institution': edu.institution,
            'duration': edu.duration,
            'grade': edu.grade
        } for edu in educations],
        'experience': [{
            'position': exp.position,
            'company': exp.company,
            'duration': exp.duration,
            'description': exp.description
        } for exp in experiences],
        'projects': [{
            'project_name': proj.project_name,
            'project_type': proj.project_type,
            'duration': proj.duration,
            'description': proj.description
        } for proj in projects],
        'skills': [skill.skill_name for skill in skills],
        'certifications': [{
            'certification_name': cert.certification_name,
            'issuer': cert.issuer,
            'duration': cert.duration,
            'credential_id': cert.credential_id
        } for cert in certifications]
    }
    
    return render_template('Resume_edit.html', resume_data=resume_data)


# -- Apply internship route -- #
@app.route('/apply/<int:internship_id>', methods=['GET'])
def apply_to_internship(internship_id):
    if 'user_id' not in session:
        return redirect('/login')

    user_id = session['user_id']

    # Check if already applied
    existing = Application.query.filter_by(user_id=user_id, internship_id=internship_id).first()
    if existing:
        return "Already applied!"

    # Store application
    new_app = Application(user_id=user_id, internship_id=internship_id)
    db.session.add(new_app)
    db.session.commit()
    return "Application submitted successfully!"


@app.route('/internships')
def internships():
    return render_template('internship_listing.html')



@app.route('/rate/<int:to_id>', methods=['GET', 'POST'])
def rate(to_id):
    if 'user_id' not in session:
        return redirect('/login')
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
            return redirect('/dashboard')
        except Exception as e:
            db.session.rollback()
            to_user = User.query.get(to_id)
            return render_template('rate.html', to_user=to_user, error=f"Rating failed: {str(e)}")
    try:
        to_user = User.query.get(to_id)
        return render_template('rate.html', to_user=to_user)
    except Exception as e:
        return redirect('/dashboard', error=f"Error loading rate page: {str(e)}")

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

@app.route('/initdb')
def initdb():
    init_db()
    return "Database initialized!"

# ------------------ Main ------------------ #
if __name__ == '__main__':
    app.run(debug=True)