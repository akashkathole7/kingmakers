# Standard library imports
import os
from datetime import datetime, timedelta
from functools import wraps
import logging
from logging.handlers import RotatingFileHandler
import json
import secrets
from datetime import datetime, timedelta
from pathlib import Path
from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash
import jwt
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash

# Third-party imports
from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from flask_cors import CORS
from flask_mail import Mail, Message
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from bson import ObjectId
import pymongo
import redis
import jwt
import bleach

# Initialize Flask app
app = Flask(__name__, 
    static_folder='static',
    template_folder='templates'
)
CORS(app, supports_credentials=True)

# Configuration
app.config.update(
    # Basic Flask Configuration
    SECRET_KEY='fallback_secret_key',
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,  # 16MB max file size
    
    # Mail Configuration
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USERNAME='schoolofinspirationalai@gmail.com',
    MAIL_PASSWORD='tyer niyw eofr qcxn',
    MAIL_DEFAULT_SENDER='schoolofinspirationalai@gmail.com',
    
    # Upload Configuration
    UPLOAD_FOLDER=Path('uploads'),
    ALLOWED_EXTENSIONS={'png', 'jpg', 'jpeg', 'gif', 'pdf', 'doc', 'docx'},
    
    # API Configuration
    API_RATE_LIMIT=100,
    API_RATE_LIMIT_PERIOD=60,
    
    # Redis Configuration
    REDIS_URL="redis://localhost:6379/0"
)

# Initialize extensions
mail = Mail(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Initialize Redis
redis_client = redis.from_url(app.config['REDIS_URL'])

# Setup logging
if not os.path.exists('logs'):
    os.mkdir('logs')
    
file_handler = RotatingFileHandler(
    'logs/app.log',
    maxBytes=10240,
    backupCount=10
)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
file_handler.setLevel(logging.INFO)
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)
app.logger.info('Application startup')

# MongoDB setup
try:
    mongo_client = pymongo.MongoClient(
        "mongodb+srv://schoolofinspirationalai:OAFqDazeUOpnBBzQ@contact.qabnx.mongodb.net/?retryWrites=true&w=majority&appName=contact",
        tlsAllowInvalidCertificates=True
    )
    db = mongo_client.ai_website
    mongo_client.server_info()
    
    # Create indexes
    db.users.create_index([('email', pymongo.ASCENDING)], unique=True)
    db.contacts.create_index([('created_at', pymongo.ASCENDING)])
    
except Exception as e:
    app.logger.error(f"MongoDB Connection Error: {e}")
    raise

# User Model
class User(UserMixin):
    def __init__(self, user_data):
        self.id = str(user_data['_id'])
        self.email = user_data['email']
        self.name = user_data.get('name', '')
        self.role = user_data.get('role', 'user')
        self.is_active = user_data.get('is_active', True)

    def get_token(self, expires_in=3600):
        token = jwt.encode(
            {
                'user_id': self.id,
                'exp': datetime.utcnow() + timedelta(seconds=expires_in)
            },
            app.config['SECRET_KEY'],
            algorithm='HS256'
        )
        return token

@login_manager.user_loader
def load_user(user_id):
    user_data = db.users.find_one({'_id': ObjectId(user_id)})
    return User(user_data) if user_data else None

# Frontend Routes
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/services')
def services():
    return render_template('services.html')

# Enhanced password reset functionality
@app.route('/api/auth/reset-password', methods=['POST'])
def request_password_reset():
    try:
        data = request.get_json()
        email = data.get('email')
        
        if not email:
            return jsonify({'error': 'Email is required'}), 400
            
        # Check if user exists but don't reveal this information
        user = db.users.find_one({'email': email})
        
        # Generate reset token
        reset_token = secrets.token_urlsafe(32)
        expiration = datetime.utcnow() + timedelta(hours=1)
        
        # Store reset token
        db.password_resets.update_one(
            {'email': email},
            {
                '$set': {
                    'token': reset_token,
                    'expires': expiration
                }
            },
            upsert=True
        )
        
        # Create reset link
        reset_link = f"{request.host_url}reset-password/{reset_token}"
        
        # Send email only if user exists (but don't reveal this in response)
        if user:
            try:
                msg = Message(
                    'Reset Your Password - Kingmaker AI',
                    recipients=[email],
                    html=render_template(
                        'email/reset_password.html',
                        reset_link=reset_link,
                        user_name=user.get('name', '').split()[0]
                    )
                )
                mail.send(msg)
            except Exception as e:
                app.logger.error(f"Password reset email error: {str(e)}")
        
        # Always return success to prevent email enumeration
        return jsonify({
            'message': 'If an account exists with this email, you will receive password reset instructions.'
        }), 200
        
    except Exception as e:
        app.logger.error(f"Password reset error: {str(e)}")
        return jsonify({'error': 'An unexpected error occurred'}), 500
    
def mask_email(email):
    """Helper function to partially mask email address"""
    parts = email.split('@')
    username = parts[0]
    domain = parts[1]
    masked_username = username[:2] + '*' * (len(username) - 2)
    return f"{masked_username}@{domain}"

def get_location_from_ip(ip_address):
    """Helper function to get approximate location from IP (for security awareness)"""
    try:
        # Implement IP geolocation service here
        return "approximate location"
    except:
        return "unknown location"
    
@app.route('/api/auth/verify-reset-token/<token>', methods=['GET'])
def verify_reset_token(token):
    reset_request = db.password_resets.find_one({
        'token': token,
        'expires': {'$gt': datetime.utcnow()},
        'attempted': False
    })
    
    if not reset_request:
        return jsonify({'valid': False}), 400
        
    return jsonify({'valid': True}), 200


@app.route('/reset-password/<token>')
def reset_password_page(token):
    # Verify token is valid and not expired
    reset_request = db.password_resets.find_one({
        'token': token,
        'expires': {'$gt': datetime.utcnow()}
    })
    
    if not reset_request:
        return render_template('404.html'), 404
        
    return render_template('reset-password.html', token=token)

@app.route('/api/auth/reset-password/<token>', methods=['POST'])
def reset_password(token):
    try:
        data = request.get_json()
        new_password = data.get('password')
        
        if not new_password:
            return jsonify({'error': 'New password is required'}), 400
            
        # Comprehensive password validation
        if not is_strong_password(new_password):
            return jsonify({
                'error': 'Password does not meet security requirements',
                'requirements': get_password_requirements()
            }), 400
            
        # Verify token and get reset request
        reset_request = db.password_resets.find_one_and_update(
            {
                'token': token,
                'expires': {'$gt': datetime.utcnow()},
                'attempted': False
            },
            {'$set': {'attempted': True}},
            return_document=True
        )
        
        if not reset_request:
            return jsonify({'error': 'Invalid or expired reset token'}), 400
            
        # Update password with additional security measures
        user = db.users.find_one_and_update(
            {'email': reset_request['email']},
            {
                '$set': {
                    'password': generate_password_hash(new_password),
                    'password_changed_at': datetime.utcnow()
                },
                '$push': {
                    'password_history': {
                        'hash': generate_password_hash(new_password),
                        'changed_at': datetime.utcnow()
                    }
                }
            }
        )
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
            
        # Invalidate all active sessions for this user
        db.sessions.delete_many({'user_id': user['_id']})
        
        # Send confirmation email
        send_password_change_confirmation(user['email'])
        
        # Log successful password reset
        db.security_logs.insert_one({
            'type': 'password_reset_complete',
            'user_id': user['_id'],
            'timestamp': datetime.utcnow(),
            'ip_address': request.remote_addr,
            'user_agent': request.headers.get('User-Agent')
        })
        
        return jsonify({
            'message': 'Password successfully reset',
            'next_steps': [
                'Log in with your new password',
                'Review your recent account activity',
                'Set up two-factor authentication for enhanced security'
            ]
        }), 200
        
    except Exception as e:
        app.logger.error(f"Password reset error: {str(e)}")
        return jsonify({'error': 'Failed to reset password'}), 500

def is_strong_password(password):
    """Enhanced password strength validation"""
    criteria = {
        'length': len(password) >= 12,
        'uppercase': bool(re.search(r'[A-Z]', password)),
        'lowercase': bool(re.search(r'[a-z]', password)),
        'numbers': bool(re.search(r'\d', password)),
        'special': bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password)),
        'not_common': not is_common_password(password)
    }
    return all(criteria.values())

def get_password_requirements():
    """Return password requirements with psychological framing"""
    return {
        'min_length': 'At least 12 characters (longer passwords are stronger)',
        'complexity': 'Mix of uppercase, lowercase, numbers, and special characters',
        'uniqueness': 'Different from previously used passwords',
        'strength_tips': [
            'Use a memorable phrase',
            'Add personal meaning only you would know',
            'Consider using a password manager'
        ]
    }

def send_password_change_confirmation(email):
    """Send confirmation email after password change"""
    try:
        msg = Message(
            'Your password has been successfully reset',
            recipients=[email],
            html=render_template('email/password_changed.html',
                timestamp=datetime.utcnow(),
                ip_address=request.remote_addr,
                location=get_location_from_ip(request.remote_addr)
            )
        )
        mail.send(msg)
    except Exception as e:
        app.logger.error(f"Password change confirmation email error: {str(e)}")

# Add MongoDB index for password resets
def setup_password_reset_indexes():
    try:
        db.password_resets.create_index([("expires", pymongo.ASCENDING)])
        db.password_resets.create_index([("token", pymongo.ASCENDING)], unique=True)
    except Exception as e:
        app.logger.error(f"Error creating password reset indexes: {str(e)}")

# Call this during app initialization
setup_password_reset_indexes()

# Cleanup expired tokens periodically
def cleanup_expired_tokens():
    try:
        db.password_resets.delete_many({
            'expires': {'$lt': datetime.utcnow()}
        })
    except Exception as e:
        app.logger.error(f"Error cleaning up expired tokens: {str(e)}")
                         
@app.route('/portfolio')
def portfolio():
    return render_template('portfolio.html')

@app.route('/contact')
def contact_page():
    return render_template('contact.html')

@app.route('/blog')
def blog():
    # Fetch latest blog posts from database
    posts = list(db.blog_posts.find().sort('created_at', -1).limit(10))
    for post in posts:
        post['_id'] = str(post['_id'])
    return render_template('blog.html', posts=posts)

@app.route('/careers')
def careers():
    # Fetch active job listings
    jobs = list(db.jobs.find({'active': True}).sort('posted_date', -1))
    for job in jobs:
        job['_id'] = str(job['_id'])
    return render_template('careers.html', jobs=jobs)

@app.route('/testimonials')
def testimonials():
    testimonials = list(db.testimonials.find())
    for testimonial in testimonials:
        testimonial['_id'] = str(testimonial['_id'])
    return render_template('testimonials.html', testimonials=testimonials)

@app.route('/login')
def login_page():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/register')
def register_page():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

# API Routes
@app.route('/api/auth/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['email', 'password', 'name']
        if not all(field in data for field in required_fields):
            return jsonify({'error': 'Missing required fields'}), 400
            
        # Check if user exists
        if db.users.find_one({'email': data['email']}):
            return jsonify({'error': 'Email already registered'}), 400
            
        # Create user
        user_data = {
            'email': data['email'],
            'password': generate_password_hash(data['password']),
            'name': data['name'],
            'role': 'user',
            'created_at': datetime.utcnow(),
            'is_active': True
        }
        
        result = db.users.insert_one(user_data)
        
        # Send welcome email
        try:
            msg = Message(
                'Welcome to kingmaker',
                recipients=[data['email']],
                body=f"Welcome {data['name']}! Thank you for registering."
            )
            mail.send(msg)
        except Exception as e:
            app.logger.error(f"Welcome email error: {e}")
        
        return jsonify({
            'message': 'Registration successful',
            'user_id': str(result.inserted_id)
        }), 201
        
    except Exception as e:
        app.logger.error(f"Registration error: {str(e)}")
        return jsonify({'error': 'Registration failed'}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        
        user_data = db.users.find_one({'email': data['email']})
        if user_data and check_password_hash(user_data['password'], data['password']):
            user = User(user_data)
            if not user.is_active:
                return jsonify({'error': 'Account is deactivated'}), 403
                
            login_user(user)
            
            # Update last login
            db.users.update_one(
                {'_id': user_data['_id']},
                {'$set': {'last_login': datetime.utcnow()}}
            )
            
            return jsonify({
                'token': user.get_token(),
                'user': {
                    'id': user.id,
                    'email': user.email,
                    'name': user.name,
                    'role': user.role
                }
            })
            
        return jsonify({'error': 'Invalid credentials'}), 401
        
    except Exception as e:
        app.logger.error(f"Login error: {str(e)}")
        return jsonify({'error': 'Login failed'}), 500

@app.route('/api/contact', methods=['POST'])
def contact():
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['name', 'email', 'message']
        if not all(field in data for field in required_fields):
            return jsonify({'error': 'Missing required fields'}), 400
            
        # Store contact message
        contact_data = {
            'name': bleach.clean(data['name']),
            'email': bleach.clean(data['email']),
            'message': bleach.clean(data['message']),
            'created_at': datetime.utcnow()
        }
        
        db.contacts.insert_one(contact_data)
        
        # Send email notification
        msg = Message(
            'New Contact Form Submission',
            recipients=[app.config['MAIL_USERNAME']],
            body=f"Name: {contact_data['name']}\nEmail: {contact_data['email']}\n\nMessage:\n{contact_data['message']}"
        )
        mail.send(msg)
        
        return jsonify({'message': 'Message sent successfully'})
        
    except Exception as e:
        app.logger.error(f"Error processing contact form: {str(e)}")
        return jsonify({'error': 'Failed to send message'}), 500

@app.route('/api/subscribe', methods=['POST'])
def subscribe_newsletter():
    try:
        data = request.get_json()
        email = data.get('email')
        
        if not email:
            return jsonify({'error': 'Email is required'}), 400
            
        if db.subscribers.find_one({'email': email}):
            return jsonify({'error': 'Already subscribed'}), 400
            
        db.subscribers.insert_one({
            'email': email,
            'subscribed_at': datetime.utcnow(),
            'active': True
        })
        
        return jsonify({'message': 'Subscribed successfully'})
        
    except Exception as e:
        app.logger.error(f"Newsletter subscription error: {str(e)}")
        return jsonify({'error': 'Subscription failed'}), 500

@app.route('/api/job-application', methods=['POST'])
def job_application():
    try:
        data = request.form
        
        # Validate required fields
        required_fields = ['name', 'email', 'position']
        if not all(field in data for field in required_fields):
            return jsonify({'error': 'Missing required fields'}), 400
            
        # Handle resume upload
        resume = request.files.get('resume')
        if not resume:
            return jsonify({'error': 'Resume is required'}), 400
            
        # Save application
        application_data = {
            'name': data['name'],
            'email': data['email'],
            'position': data['position'],
            'message': data.get('message', ''),
            'created_at': datetime.utcnow()
        }
        
        result = db.job_applications.insert_one(application_data)
        
        return jsonify({'message': 'Application submitted successfully'})
        
    except Exception as e:
        app.logger.error(f"Job application error: {str(e)}")
        return jsonify({'error': 'Application submission failed'}), 500

# Error Handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    app.logger.error(f"Server Error: {error}")
    return render_template('500.html'), 500

# Run the application
if __name__ == '__main__':
    app.run(
        host='0.0.0.0',
        port=int(os.environ.get('PORT', 5000)),
        debug=True
    )