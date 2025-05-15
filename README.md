# Suvidha Student Portal

A web application for student login, registration, and dashboard functionality.

## Setup Instructions

1. Create a virtual environment:
```bash
python -m venv venv
```

2. Activate the virtual environment:
- Windows:
```bash
venv\Scripts\activate
```
- Unix/MacOS:
```bash
source venv/bin/activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Run the application:
```bash
python app.py
```

The application will be available at `http://localhost:5000`

## Features

- Student Login
- Student Registration
- Dashboard with session management
- Remember Me functionality
- Password reset (coming soon)
- Profile management (coming soon)

## Directory Structure

```
.
├── app.py              # Main Flask application
├── requirements.txt    # Python dependencies
├── static/            # Static files (CSS, JS, images)
└── templates/         # HTML templates
    ├── stu_login.html
    ├── stu_signup.html
    └── stu_dash.html
```

## Security Features

- Password hashing
- Session management
- CSRF protection
- Input validation
- Secure password reset (coming soon)

## Note

This is a development version. For production:
1. Use a proper database instead of in-memory storage
2. Set up proper email functionality for password reset
3. Configure proper security headers
4. Use environment variables for sensitive data 