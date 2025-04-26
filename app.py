from flask import Flask, render_template, jsonify, abort, request, redirect, url_for, flash, session
from datetime import datetime, timedelta
from functools import wraps
import json
import os
import csv
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import re
from cryptography.fernet import Fernet
from base64 import b64encode
import bcrypt
from flask_sqlalchemy import SQLAlchemy
from enum import Enum
from werkzeug.utils import secure_filename
from sqlalchemy.sql import func
import random
from bs4.element import Tag # Added import
import math # Import math module for ceil
import requests
from bs4 import BeautifulSoup
# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY') or os.urandom(24)
# Use environment variable for database URI if available, otherwise default to SQLite
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///cars.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=1)
# Use environment variable to determine secure cookies (True for production)
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV') == 'production'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Add upload folder configuration
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True) # Ensure upload folder exists

db = SQLAlchemy(app)

MANUAL_BRAND_LIST = sorted([
    "Mercedes", "Land Rover", "BMW", "Jeep", "Toyota", "Volkswagen", "Nissan",
    "Audi", "Honda", "Hyundai", "Chevrolet", "Kia", "Porsche", "Mazda", "MINI",
    "Mitsubishi", "Renault", "Infiniti", "Peugeot", "Ford", "GMC", "Jaguar",
    "Suzuki", "Subaru", "Cadillac", "Smart", "Fiat", "Dodge", "Maserati",
    "Citroen", "Other make", "Volvo", "Seat", "Opel", "Ferrari", "Lexus",
    "Bentley", "Dacia", "Hummer", "MG", "BYD", "Alfa Romeo", "Lada", "Geely",
    "Buick", "Changan", "Lamborghini", "Daihatsu", "Chrysler", "Daewoo",
    "Chery", "Avatr", "Datsun", "Saab", "JAC", "Tesla", "Rolls Royce", "Skoda",
    "Lotus", "Aston Martin", "DFSK", "Wuling", "Jetour", "GAC", "Isuzu",
    "Pontiac", "DongFeng", "Zeekr"
])

FUEL_TYPE_OPTIONS = ["Benzine", "Diesel", "Electric", "Hybrid"]

# Role-Permission Association Table
role_permissions = db.Table('role_permissions',
    db.Column('role_id', db.Integer, db.ForeignKey('role.id'), primary_key=True),
    db.Column('permission_id', db.Integer, db.ForeignKey('permission.id'), primary_key=True)
)

class Permission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    description = db.Column(db.String(255))

class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    description = db.Column(db.String(255))
    permissions = db.relationship('Permission', secondary=role_permissions,
                                backref=db.backref('roles', lazy='dynamic'))

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    name = db.Column(db.String(120), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'))
    failed_login_attempts = db.Column(db.Integer, default=0)
    last_failed_login = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    role = db.relationship('Role', backref=db.backref('users', lazy=True))

    # Additional profile fields
    phone = db.Column(db.String(20))
    address = db.Column(db.String(255))
    profile_picture = db.Column(db.String(255), default='images/default-profile.png')
    bio = db.Column(db.Text)
    date_of_birth = db.Column(db.Date)
    last_login = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)
    preferences = db.Column(db.JSON)  # For storing user preferences as JSON

class Vehicle(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    price = db.Column(db.Float, nullable=False)
    rental_price_per_day = db.Column(db.Float, nullable=False)
    mileage = db.Column(db.Integer)
    year = db.Column(db.Integer, nullable=False)
    transmission = db.Column(db.String(50))
    fuel_type = db.Column(db.String(50))
    description = db.Column(db.Text)
    location = db.Column(db.String(200))
    features = db.Column(db.Text)  # Stored as JSON
    status = db.Column(db.String(50), default='available')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    source_url = db.Column(db.String(500), unique=True)  # URL where the vehicle was scraped from

class VehicleImage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    vehicle_id = db.Column(db.Integer, db.ForeignKey('vehicle.id'), nullable=False)
    image_path = db.Column(db.String(255), nullable=False)
    is_primary = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    vehicle = db.relationship('Vehicle', backref=db.backref('images', lazy=True))

class UserActivity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(100), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    details = db.Column(db.JSON)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(255))

# Initialize default roles and permissions
def init_db():
    # Drop all tables and recreate them
    db.drop_all()
    db.create_all()

    # Create default permissions if they don't exist
    permissions = {
        'view_dashboard': 'Access admin dashboard',
        'manage_vehicles': 'Create, edit, and delete vehicles',
        'manage_users': 'Manage user accounts',
        'manage_bookings': 'Manage booking requests',
        'view_reports': 'View analytics and reports'
    }

    for perm_name, perm_desc in permissions.items():
        permission = Permission.query.filter_by(name=perm_name).first()
        if not permission:
            permission = Permission()
            permission.name = perm_name
            permission.description = perm_desc
            db.session.add(permission)
            app.logger.info(f"Added permission: {perm_name}")
    db.session.commit() # Commit permissions first

    # Create default roles if they don't exist
    admin_role = Role.query.filter_by(name='admin').first()
    if not admin_role:
        admin_role = Role()
        admin_role.name = 'admin'
        admin_role.description = 'Administrator with full access'
        db.session.add(admin_role)
        app.logger.info("Added role: admin")

    staff_role = Role.query.filter_by(name='staff').first()
    if not staff_role:
        staff_role = Role()
        staff_role.name = 'staff'
        staff_role.description = 'Staff member with limited access'
        db.session.add(staff_role)
        app.logger.info("Added role: staff")

    user_role = Role.query.filter_by(name='user').first()
    if not user_role:
        user_role = Role()
        user_role.name = 'user'
        user_role.description = 'Regular user'
        db.session.add(user_role)
        app.logger.info("Added role: user")

    db.session.commit()
    app.logger.info("Default roles committed.")

    # Assign permissions to roles (ensure roles and permissions exist)
    admin_role = Role.query.filter_by(name='admin').first()
    if admin_role:
        admin_role.permissions = Permission.query.all() # Reset permissions for admin

    staff_role = Role.query.filter_by(name='staff').first()
    if staff_role:
        staff_permissions = Permission.query.filter(
            Permission.name.in_(['view_dashboard', 'manage_vehicles', 'manage_bookings'])
        ).all()
        staff_role.permissions = staff_permissions # Reset permissions for staff

    db.session.commit()
    app.logger.info("Default roles and permissions assigned and committed.")

# Create admin user if it doesn't exist
def create_admin_user():
    admin_email = os.environ.get('ADMIN_EMAIL', 'admin@example.com')
    admin_password = os.environ.get('ADMIN_PASSWORD', 'Admin123!')

    admin_user = User.query.filter_by(email=admin_email).first()
    if not admin_user:
        admin_role = Role.query.filter_by(name='admin').first()
        if not admin_role:
            app.logger.error("Admin role not found, cannot create admin user.")
            return
        admin_user = User()
        admin_user.email = admin_email
        admin_user.password = generate_password_hash(admin_password)
        admin_user.name = 'Admin User'
        admin_user.role_id = admin_role.id # Assign role_id instead of role object
        admin_user.preferences = {
            'language': 'en',
            'notifications': True,
            'newsletter': False
        }
        db.session.add(admin_user)
        db.session.commit()
        app.logger.info(f"Created admin user: {admin_email}")
    else:
        # Ensure existing admin has the role
        admin_role = Role.query.filter_by(name='admin').first()
        if admin_role and admin_user.role_id != admin_role.id:
            admin_user.role_id = admin_role.id
            db.session.commit()
            app.logger.info(f"Updated role for admin user: {admin_email}")


def create_specific_admin():
    admin_email = 'charbel@example.com'
    admin_password = 'Charbel'

    admin_user = User.query.filter_by(email=admin_email).first()
    admin_role = Role.query.filter_by(name='admin').first()
    if not admin_role:
        app.logger.error("Admin role not found, cannot create specific admin user.")
        return

    if not admin_user:
        hashed_password = generate_password_hash(admin_password, method='pbkdf2:sha256')
        admin_user = User()
        admin_user.email = admin_email
        admin_user.password = hashed_password
        admin_user.name = 'Charbel'
        admin_user.role_id = admin_role.id
        admin_user.preferences = {
            'language': 'en',
            'notifications': True,
            'newsletter': False
        }
        db.session.add(admin_user)
        db.session.commit()
        app.logger.info(f"Created specific admin user: {admin_email}")
    else:
        # Optionally update existing specific admin user
        if admin_user.role_id != admin_role.id:
             admin_user.role_id = admin_role.id
        # Optionally update password if needed
        # if not check_password_hash(admin_user.password, admin_password):
        #    admin_user.password = generate_password_hash(admin_password, method='pbkdf2:sha256')
        db.session.commit()
        app.logger.info(f"Checked/Updated specific admin user: {admin_email}")

    print(f"Specific Admin password hash: {admin_user.password}")


def create_sample_user():
    user_email = 'charbel@user.com'
    user_password = 'Charbel'

    user = User.query.filter_by(email=user_email).first()
    user_role = Role.query.filter_by(name='user').first()
    if not user_role:
        app.logger.error("User role not found, cannot create sample user.")
        return

    if not user:
        hashed_password = generate_password_hash(user_password, method='pbkdf2:sha256')
        user = User()
        user.email = user_email
        user.password = hashed_password
        user.name = 'Charbel User'
        user.role_id = user_role.id
        user.preferences = {
            'language': 'en',
            'notifications': True,
            'newsletter': False
        }
        db.session.add(user)
        db.session.commit()
        app.logger.info(f"Created sample user: {user_email}")
    else:
        # Optionally update existing sample user
        if user.role_id != user_role.id:
             user.role_id = user_role.id
        # Optionally update password if needed
        # if not check_password_hash(user.password, user_password):
        #     user.password = generate_password_hash(user_password, method='pbkdf2:sha256')
        db.session.commit()
        app.logger.info(f"Checked/Updated sample user: {user_email}")

    print(f"Sample User password hash: {user.password}")

# Initialize DB and users within app context
with app.app_context():
    # Check if tables exist before initializing
    inspector = db.inspect(db.engine)
    if not inspector.has_table('user'):
        app.logger.info("Database tables not found, initializing...")
        init_db()
        create_admin_user()
        create_specific_admin()
        create_sample_user()
        app.logger.info("Database initialization complete.")
    else:
        app.logger.info("Database tables already exist.")
        # Optionally ensure roles/permissions/users exist even if tables do
        # init_db() # This would drop data, be careful
        # create_admin_user()
        # create_specific_admin()
        # create_sample_user()


# Security headers
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://kit.fontawesome.com; " # Added fontawesome
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; " # Added fonts and fontawesome css
        "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; " # Added fonts and fontawesome fonts
        "img-src 'self' images.dubizzle.com.lb data:;" # Allow images from self, dubizzle, and data URIs
        "connect-src 'self' https://api.openai.com;" # Allow connections to OpenAI if needed by chatbot JS
    )
    return response

# Mock user database (replace with real database in production) - REMOVED, using DB now

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            flash('Please log in to access this page', 'error')
            return redirect(url_for('login', next=request.url))
        # Check if user is active
        user = User.query.get(session['user']['id'])
        if not user or not user.is_active:
            session.pop('user', None) # Log out inactive user
            flash('Your account is inactive. Please contact support.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["400 per day", "200 per hour"]
)

# Initialize limiter within app context
with app.app_context():
    limiter.init_app(app)

def validate_password(password):
    """
    Validate password complexity:
    - At least 8 characters long
    - Contains at least one uppercase letter
    - Contains at least one lowercase letter
    - Contains at least one number
    - Contains at least one special character
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"\d", password):
        return False, "Password must contain at least one number."
    if not re.search(r"[ !@#$%&'()*+,-./[\\\]^_`{|}~"+r'"]', password):
        return False, "Password must contain at least one special character."
    return True, ""

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute") # Limit login attempts
def login():
    if request.method == 'GET':
        return render_template('login.html')

    email = request.form.get('email')
    password = request.form.get('password')
    remember = request.form.get('remember', False)

    if not email or not password:
        flash('Please provide both email and password', 'error')
        return redirect(url_for('login'))

    try:
        user = User.query.filter_by(email=email).first()

        # Lockout check
        lockout_duration = timedelta(minutes=15)
        max_attempts = 5
        if user and user.failed_login_attempts >= max_attempts and \
           user.last_failed_login and datetime.utcnow() < user.last_failed_login + lockout_duration:
            flash(f'Account locked due to too many failed attempts. Try again later.', 'error')
            app.logger.warning(f"Locked out login attempt for user: {email}")
            return redirect(url_for('login'))

        if user and user.is_active and check_password_hash(user.password, password):
            app.logger.info(f"Successful login for user: {email}")
            # Update user's last login time and reset failed attempts
            user.last_login = datetime.utcnow()
            user.failed_login_attempts = 0
            user.last_failed_login = None
            db.session.commit()

            # Set up the session
            session.permanent = remember # Use remember me value
            session['user'] = {
                'id': user.id,
                'email': user.email,
                'name': user.name,
                'role': user.role.name if user.role else 'user'
            }
            track_user_activity(user.id, 'login') # Track successful login
            flash('Successfully logged in!', 'success')
            next_page = request.args.get('next')
            # Basic validation to prevent open redirect
            if next_page and (next_page.startswith('/') or url_for('index') in next_page):
                 return redirect(next_page)
            return redirect(url_for('index'))
        elif user and not user.is_active:
             flash('Your account is inactive. Please contact support.', 'error')
             app.logger.warning(f"Login attempt for inactive user: {email}")
             return redirect(url_for('login'))
        else:
            if user:
                user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
                user.last_failed_login = datetime.utcnow()
                db.session.commit()
                remaining_attempts = max_attempts - user.failed_login_attempts
                if remaining_attempts <= 0:
                     flash('Invalid email or password. Account locked for 15 minutes.', 'error')
                     app.logger.warning(f"Failed login attempt locking account for user: {email}.")
                else:
                     flash(f'Invalid email or password. {remaining_attempts} attempts remaining.', 'error')
                     app.logger.warning(f"Failed login attempt for user: {email}. Attempts: {user.failed_login_attempts}")
            else:
                app.logger.warning(f"Failed login attempt for non-existent user: {email}")
                flash('Invalid email or password', 'error')

            return redirect(url_for('login'))

    except Exception as e:
        app.logger.error(f"Login error for {email}: {str(e)}", exc_info=True)
        flash('An error occurred during login. Please try again.', 'error')
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    user_id = session.get('user', {}).get('id')
    if user_id:
        track_user_activity(user_id, 'logout') # Track logout
    session.pop('user', None)
    flash('Logged out successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')

    email = request.form.get('email', '').strip()
    password = request.form.get('password', '').strip()
    name = request.form.get('name', '').strip()

    if not all([email, password, name]):
        flash('All fields are required', 'error')
        return render_template('register.html', email=email, name=name)

    # Simple email format check
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        flash('Invalid email format', 'error')
        return render_template('register.html', email=email, name=name)

    is_valid, message = validate_password(password)
    if not is_valid:
        flash(message, 'error')
        return render_template('register.html', email=email, name=name)

    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        flash('Email already registered', 'error')
        return render_template('register.html', email=email, name=name)

    user_role = Role.query.filter_by(name='user').first()
    if not user_role:
        flash('User role configuration error. Please contact support.', 'error')
        return render_template('register.html')

    try:
        new_user = User()
        new_user.email = email
        new_user.password = generate_password_hash(password, method='pbkdf2:sha256') # Use stronger hashing
        new_user.name = name
        new_user.role_id = user_role.id
        new_user.preferences = {
            'language': 'en',
            'notifications': True,
            'newsletter': False
        }

        db.session.add(new_user)
        db.session.commit()
        track_user_activity(new_user.id, 'register') # Track registration

        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Registration error for {email}: {str(e)}", exc_info=True)
        flash('An error occurred during registration. Please try again.', 'error')
        return render_template('register.html', email=email, name=name)


import openai

# Load OpenAI API key from environment variable
openai_api_key = os.environ.get('OPENAI_API_KEY')

# Initialize OpenAI client globally if key exists
openai_client = None
if openai_api_key:
    try:
        openai_client = openai.OpenAI(api_key=openai_api_key)
        openai_client.models.list()  # Validate the API key
        print("OpenAI API key loaded and valid.")
    except openai.AuthenticationError as e:
        print(f"Error: Invalid OpenAI API key from environment variable. Please check your .env file. {e}")
        openai_client = None # Ensure client is None if key is invalid
    except Exception as e:
        print(f"An error occurred while initializing OpenAI: {e}")
        openai_client = None # Ensure client is None on other errors
else:
    print("Warning: OPENAI_API_KEY not found in environment variables.")

def search_cars_in_csv(query):
    """Search for cars in the CSV based on a query, including image and link.""" 

    cars_found = []
    csv_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'database', 'dubizzle.csv')
    query_lower = query.lower()
    keywords = [kw for kw in query_lower.split() if len(kw) > 2]
    try:
        with open(csv_path, 'r', encoding='utf-8') as file:
            reader = csv.DictReader(file)
            match_count = 0 # Count only the cars that MATCH
            # --- Iterate through ALL rows ---
            for row in reader:
                searchable_text = f"{row.get('Car Name', '')} {row.get('Year', '')} {row.get('Fuel Type', '')} {row.get('Location', '')}".lower()

                # Check keywords if they exist
                if keywords and not any(keyword in searchable_text for keyword in keywords):
                    continue # Skip row if keywords provided but none match

                # --- If keywords match (or if no keywords were given and you want to match all) ---
                # Process the matched row
                price_str = row.get('Price', '0').replace('USD ', '').replace(',', '').strip()
                try: price_float = float(price_str); formatted_price = f"USD {price_float:,.0f}"
                except ValueError: formatted_price = "N/A"; price_float = None

                ad_link_path = row.get('AD Link'); link_url = f"https://www.dubizzle.com.lb{ad_link_path}" if ad_link_path else '#'
                image_url = row.get('image_url', None)

                cars_found.append({
                    'name': row.get('Car Name', 'N/A'), 'year': row.get('Year', 'N/A'),
                    'price': formatted_price, 'price_float': price_float,
                    'mileage': row.get('KM Run', 'N/A'), 'fuel': row.get('Fuel Type', 'N/A'),
                    'location': row.get('Location', 'N/A').replace('•', '').strip(),
                    'link': link_url, 'image_url': image_url
                })

                match_count += 1 # Increment match count
                # Apply limit based on MATCHES found
                if match_count >= 5: # Limit to 5 *matching* cars for chatbot
                    app.logger.info(f"Chatbot search limit ({match_count}) reached for query '{query}'.")
                    break # Stop reading CSV once limit is hit
            # --- End loop through all rows ---

    except FileNotFoundError: app.logger.error(f"Chatbot search CSV not found: {csv_path}")
    except Exception as e: app.logger.error(f"Chatbot search error: {e}", exc_info=True)

    app.logger.info(f"Chatbot search for '{query}' found {len(cars_found)} keyword matches after checking full CSV (limit 5).")
    return cars_found # Return the list of matched cars (up to the limit)

# In app.py - Modify the /deals route

@app.route('/deals')
def deals():
    # Fetch vehicles with special deals (e.g., discounted or featured)
    # For now, just gets random cars from CSV
    try:
        # --- Call get_cars and unpack the tuple ---
        # Fetch a larger number of cars to sample from for deals
        all_cars_dict, _ = get_cars(per_page=1000) # Unpack, ignore pagination info (_)

        # --- Get the list of car dictionaries ---
        all_cars_list = list(all_cars_dict.values()) # Get values from the dictionary

        # --- Shuffle and select deals ---
        random.shuffle(all_cars_list)
        deals_list = all_cars_list[:10] # Get 10 random cars as deals

        app.logger.info(f"Displaying {len(deals_list)} deals.")
        return render_template('deals.html', deals=deals_list)

    except Exception as e:
         # Handle potential errors during car fetching/processing
         app.logger.error(f"Error fetching data for /deals route: {e}", exc_info=True)
         flash("Could not load deals at this time.", "error")
         # Render the deals template with an empty list or redirect
         return render_template('deals.html', deals=[])

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        subject = request.form.get('subject', '').strip()
        message = request.form.get('message', '').strip()
        errors = []
        if not name: errors.append('Name is required.')
        if not email or not re.match(r"[^@]+@[^@]+\.[^@]+", email): errors.append('A valid email is required.')
        if not subject: errors.append('Subject is required.')
        if not message: errors.append('Message is required.')

        if errors:
            for error in errors: flash(error, 'danger')
            return render_template('contact.html', name=name, email=email, subject=subject, message=message)

        # Here you could save the message to the database or send an email
        app.logger.info(f"Contact form submitted: Name={name}, Email={email}, Subject={subject}")
        flash('Thank you for contacting us! We have received your message and will get back to you soon.', 'success')
        return redirect(url_for('contact'))

    return render_template('contact.html')


# --- Helper function for chatbot price extraction ---
def extract_price_constraints(text):
    min_price = None; max_price = None
    text = text.lower().replace(',', '')
    match_max = re.search(r'(under|less than|max|up to|below)\s*\$?(\d+)', text)
    if match_max: max_price = int(match_max.group(2))
    match_min = re.search(r'(over|more than|min|minimum|starting at|above)\s*\$?(\d+)', text)
    if match_min: min_price = int(match_min.group(2))
    match_between = re.search(r'(between|from)\s*\$?(\d+)\s*(and|to|-)\s*\$?(\d+)', text)
    if match_between: min_price = int(match_between.group(2)); max_price = int(match_between.group(4))
    else:
        match_range = re.search(r'\$?(\d+)\s*(to|-)\s*\$?(\d+)', text)
        if match_range:
             if min_price is None: min_price = int(match_range.group(1))
             if max_price is None: max_price = int(match_range.group(3))
    match_around = re.search(r'around\s*\$?(\d+)', text)
    if match_around:
        target_price = int(match_around.group(1))
        if min_price is None: min_price = int(target_price * 0.85)
        if max_price is None: max_price = int(target_price * 1.15)
    if min_price is None and max_price is None:
         match_single = re.search(r'(for|about)\s*\$?(\d{3,})\b', text)
         if match_single: max_price = int(match_single.group(2))
    app.logger.info(f"Extracted Price Constraints: Min={min_price}, Max={max_price}")
    return min_price, max_price

# --- Main Chatbot Route ---
@app.route('/chatbot', methods=['POST'])
def chatbot():
    """Handle chatbot requests using OpenAI API, incorporating car data"""
    try:
        data = request.get_json()
        message = data.get('message', '').strip()
        if not message: return jsonify({'error': 'No message provided'}), 400
        if not openai_client: return jsonify({'response': "Chatbot unavailable."}), 503

        system_prompt = "You are Careology, a friendly and knowledgeable car dealership assistant..." # Keep your prompt

        keyword_matched_cars = search_cars_in_csv(message)

                # --- 4. Build Context for OpenAI using KEYWORD-MATCHED list ---
        car_context_for_ai = "\n\n"
        # Use keyword_matched_cars directly now
        if keyword_matched_cars:
            car_context_for_ai += "Based on the user's query keywords, here are relevant cars found in inventory:\n"
            for car in keyword_matched_cars: # <-- Use keyword_matched_cars
                 car_context_for_ai += (
                     f"- {car.get('name', 'N/A')} ({car.get('year', 'N/A')}) - "
                     f"Price: {car.get('price', 'N/A')}, "
                     # f"Link: {car.get('link', '#')}\n"
                     f"Mileage: {car.get('mileage', 'N/A')}\n" # Keep other details + newline
                 )
            car_context_for_ai += "\nYou can present these options. If the user mentioned a price, you can compare the listed price to their request."
        else: # No cars found even by keyword
            car_context_for_ai = "\n\nI couldn't find specific cars matching that query in the inventory."
        # --- End Context Build Modification ---

        # Add explicit budget info for AI

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"{message}\n{car_context_for_ai}"} #<-- Send only message + car context
        ]

        try:
            response = openai_client.chat.completions.create(model="gpt-4o-mini", messages=messages, max_tokens=250) # Increased tokens slightly
            ai_reply_text = response.choices[0].message.content.strip()
            app.logger.info(f"OpenAI reply generated for: '{message}'")
        except openai.OpenAIError as e: app.logger.error(f"OpenAI API error: {e}"); return jsonify({'response': "Error communicating with AI assistant."}), 500
        except Exception as e: app.logger.error(f"Error during OpenAI call: {e}", exc_info=True); return jsonify({'response': "Error processing request with AI."}), 500

        final_html_response = ai_reply_text
        if keyword_matched_cars: # <-- Check keyword_matched_cars
            final_html_response += "<br><br><b>Here are the cars I found based on your keywords:</b><br>" # Adjusted title
            for car in keyword_matched_cars: # <-- Use keyword_matched_cars
                final_html_response += '<div style="border: 1px solid #eee; margin-bottom: 10px; padding: 10px; border-radius: 5px; display: flex; align-items: center;">'
                img_html = '<span style="flex-shrink: 0; width: 100px; height: 75px; background: #f0f0f0; display: flex; align-items: center; justify-content: center; color: #ccc; margin-right: 10px; border-radius: 3px;">No Img</span>'
                if car.get('image_url') and car['image_url'].startswith('http'):
                    img_html = f'<img src="{car["image_url"]}" alt="{car.get("name", "Car")}" style="flex-shrink: 0; width: 100px; height: 75px; object-fit: cover; margin-right: 10px; border-radius: 3px;">'
                final_html_response += img_html
                final_html_response += '<div style="flex-grow: 1;">'
                final_html_response += f"<b>{car.get('name', 'N/A')}</b> ({car.get('year', 'N/A')})<br>"
                final_html_response += f"Price: {car.get('price', 'N/A')}<br>"
                if car.get('link') and car['link'] != '#':
                     final_html_response += f'<a href="{car["link"]}" target="_blank" rel="noopener noreferrer" style="font-size: 0.9em; color: #007bff;">View Source</a>'
                final_html_response += '</div></div>'

        return jsonify({'response': final_html_response})

    except Exception as e:
        app.logger.error(f"Chatbot general error: {str(e)}", exc_info=True)
        return jsonify({'error': 'An internal error occurred'}), 500

# Enable debugging based on environment variable
app.debug = os.environ.get('FLASK_ENV') == 'development'

# Custom filter for number formatting
@app.template_filter('number_format')
def number_format_filter(value):
    try:
        # Remove any existing formatting (like $, USD, or ,)
        if isinstance(value, str):
            value = re.sub(r'[^\d.]', '', value) # Keep only digits and decimal point
        # Convert to float and format with commas, handle None or empty string
        return "{:,.0f}".format(float(value)) if value else '0'
    except (ValueError, TypeError):
        return value # Return original value if conversion fails

# In app.py - Update the get_cars function

def get_cars(search_query=None, page=1, per_page=12): # Default per_page
    import csv
    import os
    from math import ceil

    # csv_path should be defined relative to the app's root or using an absolute path
    csv_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'database', 'dubizzle.csv')
    app.logger.info(f"Attempting to read CSV from: {csv_path}") # Log path

    all_cars_list = [] # Read all into a list first
    try:
        with open(csv_path, 'r', encoding='utf-8') as file:
            reader = csv.DictReader(file)
            for idx, row in enumerate(reader, 1):
                # Skip rows with missing essential data like Car Name or Year
                if not row.get('Car Name') or not row.get('Year'):
                    app.logger.debug(f"Skipping row {idx+1}: Missing Car Name or Year")
                    continue

                # Clean and format the price
                price_str = row.get('Price', '0').replace('USD ', '').replace(',', '').strip()
                price_float = None
                formatted_price = 'N/A'
                try:
                    price_float = float(price_str)
                    if price_float <= 0:
                        app.logger.debug(f"Skipping row {idx+1}: Invalid price {price_str}")
                        continue # Skip cars with zero or negative price
                    formatted_price = "{:,.0f}".format(price_float)
                except (ValueError, AttributeError):
                    app.logger.debug(f"Skipping row {idx+1}: Could not parse price {row.get('Price', '')}")
                    continue # Skip if price is unparseable

                # Calculate rental price
                rental_price = max(10, round(price_float * 0.001)) if price_float else 10

                # Format the full AD Link URL
                ad_link = f"https://www.dubizzle.com.lb{row.get('AD Link', '')}" if row.get('AD Link') else '#'

                # --- Process Mileage - Store as int or None ---
                mileage_str = row.get('KM Run', '').replace(' km', '').replace(',', '').strip()
                mileage_int = None
                if mileage_str.isdigit():
                    try:
                        mileage_int = int(mileage_str)
                    except ValueError:
                        pass # Keep as None if conversion fails somehow
                # --- End Process Mileage ---

                # Get other fields
                car_name = row.get('Car Name', 'N/A')
                year = row.get('Year', 'N/A')
                # Clean fuel type - strip spaces and handle potential inconsistencies
                fuel_type = str(row.get('Fuel Type', 'N/A')).strip().capitalize() # Capitalize for consistency
                location = row.get('Location', 'N/A').replace('•', '').strip()
                image_url = row.get('image_url', None) # Read image URL directly

                # Create a detailed description (simplified)
                description = f"{car_name} ({year}) located in {location}. Fuel: {fuel_type}."
                if mileage_int is not None:
                    description += f" Mileage: {mileage_int:,} km."

                car_data = {
                    'id': idx,
                    'Car Name': car_name,
                    'price': formatted_price, # Already formatted string '11,500' etc
                    'price_float': price_float, # Store float for filtering
                    'rental_price_per_day': str(rental_price),
                    'mileage': mileage_int, # Store as integer or None
                    'Year': year,
                    'transmission': 'Automatic', # Default
                    'Fuel Type': fuel_type, # Store cleaned fuel type
                    'description': description,
                    'Location': location,
                    'features': ['Contact seller for details'],
                    'source_url': ad_link,
                    'image_url': image_url,
                    'Range': None, # Placeholder for Range - ADD ACTUAL DATA HERE LATER
                    'availability': { 'status': 'available', 'booked_dates': [] }
                }
                all_cars_list.append(car_data)

    except FileNotFoundError:
        app.logger.error(f"CSV file not found at {csv_path}")
        return {}, {'total_cars': 0, 'total_pages': 1, 'current_page': 1, 'per_page': per_page}
    except Exception as e:
        app.logger.error(f"Error reading CSV file: {e}", exc_info=True)
        return {}, {'total_cars': 0, 'total_pages': 1, 'current_page': 1, 'per_page': per_page}

    # Apply search filter if provided (do this *before* returning, affects pagination)
    if search_query:
        search_query_lower = search_query.lower()
        filtered_after_search = []
        for car in all_cars_list:
            # More comprehensive search text
            searchable_text = f"{car['Car Name']} {car['Year']} {car['Location']} {car['Fuel Type']} {car['description']}".lower()
            if search_query_lower in searchable_text:
                filtered_after_search.append(car)
        # Use the search-filtered list for subsequent steps
        list_to_paginate = filtered_after_search
        app.logger.info(f"Search '{search_query}' yielded {len(list_to_paginate)} results from {len(all_cars_list)} total.")
    else:
        # No search query, use all cars read from CSV
        list_to_paginate = all_cars_list
        app.logger.info(f"No search query, using {len(list_to_paginate)} total cars.")


    # Calculate pagination based on the (potentially search-filtered) list
    total_cars = len(list_to_paginate)
    total_pages = ceil(total_cars / per_page) if per_page > 0 else 1
    current_page = max(1, min(page, total_pages if total_pages > 0 else 1)) # Use 'page' from request args
    start_idx = (current_page - 1) * per_page
    end_idx = start_idx + per_page

    # Get cars for the current page slice
    paginated_cars_list = list_to_paginate[start_idx:end_idx]

    # Convert list slice back to dictionary for return (optional, depends on usage)
    cars_on_page_dict = {car['id']: car for car in paginated_cars_list}

    pagination_info = {
        'total_cars': total_cars, # Total AFTER search filter
        'total_pages': total_pages,
        'current_page': current_page,
        'per_page': per_page
    }
    # Return dict of cars for the page, and pagination info based on filtered total
    return cars_on_page_dict, pagination_info

  #  except FileNotFoundError:
   #     app.logger.error(f"CSV file not found at {csv_path}")
    #    return {}, {'total_cars': 0, 'total_pages': 1, 'current_page': 1, 'per_page': per_page}
   # except Exception as e:
    #    app.logger.error(f"Error reading CSV file: {e}", exc_info=True)
        # Return empty dict if there's an error
     #   return {}, {'total_cars': 0, 'total_pages': 1, 'current_page': 1, 'per_page': per_page}


# Booking data storage (in-memory for demonstration)
bookings = {}

# Initialize encryption key
def get_encryption_key():
    key = os.environ.get('ENCRYPTION_KEY')
    if not key:
        app.logger.warning("ENCRYPTION_KEY not set, generating a temporary one. Set it in .env for persistence.")
        key = Fernet.generate_key()
        # Avoid writing to .env automatically in production/shared environments
        # with open('.env', 'a') as f:
        #     f.write(f'\nENCRYPTION_KEY={key.decode()}')
    return key if isinstance(key, bytes) else key.encode()

fernet = Fernet(get_encryption_key())

def encrypt_data(data):
    """Encrypt sensitive data"""
    if not data: return None
    try:
        return fernet.encrypt(data.encode()).decode()
    except Exception as e:
        app.logger.error(f"Encryption failed: {e}")
        return None

def decrypt_data(encrypted_data):
    """Decrypt sensitive data"""
    if not encrypted_data: return None
    try:
        return fernet.decrypt(encrypted_data.encode()).decode()
    except Exception as e:
        app.logger.error(f"Decryption failed: {e}")
        return None # Return None or a placeholder on failure
    
    # In app.py - Update the index route

@app.route('/')
def index():
    # 1. Get filter parameters (Keep as is, including new range params)
    search_query = request.args.get('search', '').strip()
    min_price_str = request.args.get('min_price', '').strip()
    max_price_str = request.args.get('max_price', '').strip()
    selected_brands = [b.strip() for b in request.args.get('brands', '').split(',') if b.strip()]
    selected_locations = [loc.strip() for loc in request.args.get('locations', '').split(',') if loc.strip()]
    selected_year = request.args.get('year', '').strip()
    selected_fuel_type = request.args.get('fuel_type', '').strip().capitalize() # Capitalize to match data
    min_mileage_str = request.args.get('min_mileage', '').strip()
    max_mileage_str = request.args.get('max_mileage', '').strip()
    min_range_str = request.args.get('min_range', '').strip()
    max_range_str = request.args.get('max_range', '').strip()
    page = request.args.get('page', 1, type=int)
    per_page = 12

    # 2. Get ALL cars potentially matching the search query
    # NOTE: Passing per_page=9999 can be slow. Consider database if possible.
    all_matching_cars_dict, _ = get_cars(search_query=search_query, page=1, per_page=9999)
    all_matching_cars_list = list(all_matching_cars_dict.values())
    app.logger.debug(f"Initial car count after search (if any): {len(all_matching_cars_list)}")


    # 3. Populate Filter Dropdown Options (Keep as is)
    all_brands_options = MANUAL_BRAND_LIST
    all_locations_options = set()
    all_years_options = set()
    all_fuel_types_options = FUEL_TYPE_OPTIONS # Use predefined

    # Collect dynamic options from the *search-filtered* list for relevance
    for car_data in all_matching_cars_list:
        if isinstance(car_data, dict):
            location_str = car_data.get('Location')
            if location_str and location_str != 'N/A': all_locations_options.add(location_str)
            year_str = str(car_data.get('Year', ''))
            if year_str.isdigit() and 1900 < int(year_str) <= datetime.now().year + 1: all_years_options.add(int(year_str))
            # Don't need to collect fuel types if using predefined

    # 4. Apply additional filters (Price, Mileage, Range, Brand, Location, Year, Fuel Type)
    final_filtered_cars = []
    app.logger.debug(f"Applying filters: Price=({min_price_str}-{max_price_str}), Mileage=({min_mileage_str}-{max_mileage_str}), Brands={selected_brands}, Locs={selected_locations}, Year={selected_year}, Fuel={selected_fuel_type}")

    for car in all_matching_cars_list: # Filter the results from get_cars
        if not isinstance(car, dict): continue

        # --- Price Filter ---
        # Use the pre-calculated float value for efficiency
        car_price_float = car.get('price_float') # Get float price from get_cars
        if min_price_str:
            try:
                min_price = float(min_price_str)
                if car_price_float is None or car_price_float < min_price:
                    # app.logger.debug(f"Car {car.get('id')} failed min price: {car_price_float} < {min_price}")
                    continue
            except ValueError: pass
        if max_price_str:
            try:
                max_price = float(max_price_str)
                if car_price_float is None or car_price_float > max_price:
                    # app.logger.debug(f"Car {car.get('id')} failed max price: {car_price_float} > {max_price}")
                    continue
            except ValueError: pass

        # --- Mileage Filter ---
        car_mileage_int = car.get('mileage') # Get int/None mileage from get_cars
        if min_mileage_str:
            try:
                min_mileage = int(min_mileage_str)
                if car_mileage_int is None or car_mileage_int < min_mileage:
                    # app.logger.debug(f"Car {car.get('id')} failed min mileage: {car_mileage_int} < {min_mileage}")
                    continue
            except ValueError: pass
        if max_mileage_str:
            try:
                max_mileage = int(max_mileage_str)
                if car_mileage_int is None or car_mileage_int > max_mileage:
                    # app.logger.debug(f"Car {car.get('id')} failed max mileage: {car_mileage_int} > {max_mileage}")
                    continue
            except ValueError: pass

        # --- Fuel Range Filter (Still placeholder until data exists) ---
        car_range = car.get('Range') # Get Range (currently None) from get_cars
        if min_range_str:
            try:
                min_range = int(min_range_str)
                if car_range is None or car_range < min_range: continue
            except ValueError: pass
        if max_range_str:
            try:
                max_range = int(max_range_str)
                if car_range is None or car_range > max_range: continue
            except ValueError: pass

        # --- Brand Filter ---
        if selected_brands:
            car_name_lower = str(car.get('Car Name', '')).lower()
            # Simple substring match based on previous logic
            if not any(brand.lower() in car_name_lower for brand in selected_brands):
                # app.logger.debug(f"Car {car.get('id')} failed brand filter: '{car.get('Car Name')}' vs {selected_brands}")
                continue

        # --- Location Filter ---
        if selected_locations:
            car_location_lower = str(car.get('Location', '')).lower()
            if not any(loc.lower() in car_location_lower for loc in selected_locations):
                # app.logger.debug(f"Car {car.get('id')} failed location filter: '{car.get('Location')}' vs {selected_locations}")
                continue

        # --- Year Filter ---
        if selected_year:
             car_year_str = str(car.get('Year', ''))
             if car_year_str != selected_year:
                 # app.logger.debug(f"Car {car.get('id')} failed year filter: '{car_year_str}' != '{selected_year}'")
                 continue

        # --- Fuel Type Filter ---
        if selected_fuel_type:
             # Use the cleaned, capitalized fuel type from get_cars
             car_fuel_type = car.get('Fuel Type', '')
             # Compare directly (both should be capitalized now)
             if car_fuel_type != selected_fuel_type:
                 # app.logger.debug(f"Car {car.get('id')} failed fuel filter: '{car_fuel_type}' != '{selected_fuel_type}'")
                 continue

        # If car passed all filters
        final_filtered_cars.append(car)

    app.logger.debug(f"Car count after all filters: {len(final_filtered_cars)}")

    # 5. Apply Pagination
    total_cars_after_all_filters = len(final_filtered_cars)
    total_pages = math.ceil(total_cars_after_all_filters / per_page) if per_page > 0 else 1
    page = max(1, min(page, total_pages if total_pages > 0 else 1))
    start_idx = (page - 1) * per_page
    end_idx = start_idx + per_page
    cars_to_display_on_page = final_filtered_cars[start_idx:end_idx]

    pagination_info = {
        'total_cars': total_cars_after_all_filters,
        'total_pages': total_pages,
        'current_page': page,
        'per_page': per_page
    }

    # 6. Prepare data for template
    sorted_brands = all_brands_options # Use manual list
    sorted_locations = sorted(list(all_locations_options))
    sorted_years = sorted(list(all_years_options), reverse=True)
    sorted_fuel_types = all_fuel_types_options # Use manual list
    colors = ['Black', 'White', 'Silver', 'Gray', 'Red', 'Blue']

    # 7. Render the template
    return render_template('index.html',
                         cars=cars_to_display_on_page,
                         pagination=pagination_info,
                         search_query=search_query,
                         min_price=min_price_str,
                         max_price=max_price_str,
                         selected_brands=selected_brands,
                         selected_locations=selected_locations,
                         selected_year=selected_year,
                         selected_fuel_type=selected_fuel_type, # Pass back capitalized version
                         min_mileage=min_mileage_str,
                         max_mileage=max_mileage_str,
                         min_range=min_range_str,
                         max_range=max_range_str,
                         brands=sorted_brands,
                         locations=sorted_locations,
                         years=sorted_years,
                         fuel_types=sorted_fuel_types,
                         colors=colors)

# (Keep rest of app.py: helpers, context processors, main run block)
# ...


@app.route('/car/<car_id>')
def car_details(car_id):
    # Fetch all cars first (inefficient for large datasets)
    # Consider a way to fetch only one car if possible
    all_cars, _ = get_cars(per_page=10000) # Get all cars

    car = None
    try:
        # Find the car by ID (assuming 'id' key exists and is usable)
        car = all_cars.get(int(car_id)) # Convert car_id to int for lookup
    except (ValueError, TypeError):
        pass # Handle cases where car_id is not a valid integer

    if car is None:
        app.logger.warning(f"Car with ID {car_id} not found in get_cars result.")
        abort(404) # Car not found

    # Get saved cars from session
    saved_cars = session.get('saved_cars', [])

    # Check if user is logged in
    is_authenticated = 'user' in session

    return render_template('car_details.html',
                         car=car,
                         is_authenticated=is_authenticated,
                         saved_cars=saved_cars)


@app.route('/car/<int:car_id>/rent', methods=['GET'])
@login_required
def rent_car(car_id):
     # Fetch all cars first (inefficient for large datasets)
    all_cars, _ = get_cars(per_page=10000) # Get all cars
    car = all_cars.get(car_id) # Fetch car by integer ID

    if car is None:
        app.logger.warning(f"Rent request for non-existent car ID {car_id}.")
        abort(404)

    today_date = datetime.utcnow().strftime('%Y-%m-%d')
    return render_template('rent_car.html', car=car, today=today_date)


@app.route('/car/<int:car_id>/check-availability', methods=['POST'])
def check_availability(car_id):
     # Fetch all cars first (inefficient for large datasets)
    all_cars, _ = get_cars(per_page=10000) # Get all cars
    car = all_cars.get(car_id) # Fetch car by integer ID

    if car is None:
        return jsonify({'error': 'Car not found'}), 404

    data = request.get_json()
    if not data or 'start_date' not in data or 'end_date' not in data:
         return jsonify({'error': 'Missing start or end date'}), 400

    try:
        start_date = datetime.strptime(data['start_date'], '%Y-%m-%d').date() # Use date objects
        end_date = datetime.strptime(data['end_date'], '%Y-%m-%d').date()
        if start_date > end_date:
            return jsonify({'available': False, 'message': 'End date must be after start date'})
        if start_date < datetime.utcnow().date():
             return jsonify({'available': False, 'message': 'Start date cannot be in the past'})

    except ValueError:
        return jsonify({'error': 'Invalid date format'}), 400

    # Check if dates are already booked (using in-memory bookings dict)
    # This check might not align perfectly if car['availability'] isn't updated
    for booking in bookings.values():
        if booking['car_id'] == car_id and booking['status'] in ['pending', 'confirmed']:
            booked_start = datetime.strptime(booking['start_date'], '%Y-%m-%d').date()
            booked_end = datetime.strptime(booking['end_date'], '%Y-%m-%d').date()
            # Check for overlap: (StartA <= EndB) and (EndA >= StartB)
            if start_date <= booked_end and end_date >= booked_start:
                return jsonify({'available': False, 'message': 'Car is not available for the selected dates'})

    # Calculate total price
    try:
        # Extract numeric part of rental price
        rental_price_str = re.sub(r'[^\d.]', '', str(car.get('rental_price_per_day', '0')))
        rental_price_float = float(rental_price_str) if rental_price_str else 0.0
        days = (end_date - start_date).days + 1
        total_price = rental_price_float * days
    except (ValueError, TypeError) as e:
         app.logger.error(f"Error calculating rental price for car {car_id}: {e}")
         return jsonify({'error': 'Could not calculate rental price'}), 500


    return jsonify({
        'available': True,
        'total_price': round(total_price, 2),
        'days': days
    })


@app.route('/car/<int:car_id>/book', methods=['POST'])
@login_required
def book_car(car_id):
    # Fetch all cars first (inefficient for large datasets)
    all_cars, _ = get_cars(per_page=10000) # Get all cars
    car = all_cars.get(car_id) # Fetch car by integer ID

    if car is None:
        return jsonify({'error': 'Car not found'}), 404

    data = request.get_json()
    if not data or not all(k in data for k in ['start_date', 'end_date', 'total_price', 'customer_name', 'customer_email', 'customer_phone']):
         return jsonify({'error': 'Missing booking information'}), 400

    # **Re-validate availability server-side before booking**
    try:
        start_date = datetime.strptime(data['start_date'], '%Y-%m-%d').date()
        end_date = datetime.strptime(data['end_date'], '%Y-%m-%d').date()
        if start_date > end_date or start_date < datetime.utcnow().date():
            return jsonify({'error': 'Invalid booking dates selected.'}), 400

        for booking in bookings.values():
            if booking['car_id'] == car_id and booking['status'] in ['pending', 'confirmed']:
                booked_start = datetime.strptime(booking['start_date'], '%Y-%m-%d').date()
                booked_end = datetime.strptime(booking['end_date'], '%Y-%m-%d').date()
                if start_date <= booked_end and end_date >= booked_start:
                    return jsonify({'error': 'Sorry, the car became unavailable for the selected dates.'}), 409 # Conflict
    except ValueError:
        return jsonify({'error': 'Invalid date format in request'}), 400

    # --- Proceed with booking ---
    booking_id = len(bookings) + 1 # Simple incremental ID for demo

    # Encrypt sensitive data
    customer_name_enc = encrypt_data(data['customer_name'])
    customer_email_enc = encrypt_data(data['customer_email'])
    customer_phone_enc = encrypt_data(data['customer_phone'])

    if not all([customer_name_enc, customer_email_enc, customer_phone_enc]):
         app.logger.error(f"Encryption failed for booking data, car_id {car_id}")
         return jsonify({'error': 'Failed to secure booking data'}), 500

    booking_data = {
        'id': booking_id,
        'car_id': car_id,
        'user_id': session['user']['id'], # Link booking to user
        'start_date': data['start_date'],
        'end_date': data['end_date'],
        'total_price': data['total_price'],
        'customer_name': customer_name_enc,
        'customer_email': customer_email_enc,
        'customer_phone': customer_phone_enc,
        'status': 'pending', # Start as pending until payment
        'payment_status': 'pending',
        'created_at': datetime.utcnow().isoformat()
    }

    bookings[booking_id] = booking_data

    # Track booking attempt
    track_user_activity(session['user']['id'], 'create_booking', details={'booking_id': booking_id, 'car_id': car_id})

    # When returning booking info, decrypt sensitive data
    return jsonify({
        'success': True,
        'booking_id': booking_id,
        'booking': {
            'id': booking_id,
            'car_id': car_id,
            'start_date': data['start_date'],
            'end_date': data['end_date'],
            'total_price': data['total_price'],
            'customer_name': data['customer_name'], # Return plain text initially
            'customer_email': data['customer_email'],
            'customer_phone': data['customer_phone'],
            'status': 'pending'
        },
        'message': 'Booking initiated successfully. Proceed to payment.'
    })

@app.route('/booking/<int:booking_id>', methods=['GET'])
@login_required
def get_booking(booking_id):
    booking = bookings.get(booking_id)
    if booking is None or booking['user_id'] != session['user']['id']: # Check ownership
        app.logger.warning(f"User {session['user']['id']} attempted to access booking {booking_id} they don't own.")
        return jsonify({'error': 'Booking not found or access denied'}), 404

    # Decrypt sensitive data for display
    decrypted_booking = {
        'id': booking['id'],
        'car_id': booking['car_id'],
        'start_date': booking['start_date'],
        'end_date': booking['end_date'],
        'total_price': booking['total_price'],
        'customer_name': decrypt_data(booking['customer_name']),
        'customer_email': decrypt_data(booking['customer_email']),
        'customer_phone': decrypt_data(booking['customer_phone']),
        'status': booking['status'],
        'payment_status': booking['payment_status'],
        'created_at': booking['created_at']
    }

    return jsonify(decrypted_booking)

@app.route('/booking/<int:booking_id>/confirm', methods=['POST'])
@login_required # Ensure user is logged in
def confirm_booking(booking_id):
    booking = bookings.get(booking_id)
    if booking is None or booking['user_id'] != session['user']['id']: # Check ownership
        return jsonify({'error': 'Booking not found or access denied'}), 404

    if booking['status'] == 'confirmed':
        return jsonify({'success': True, 'message': 'Booking already confirmed'})
    if booking['status'] == 'cancelled':
        return jsonify({'error': 'Cannot confirm a cancelled booking'}), 400

    # Process payment (mock implementation)
    payment_data = request.get_json()
    # Add validation for payment_data here (card number format, expiry, cvv)

    if process_payment(payment_data, booking['total_price']): # Pass amount for validation
        booking['status'] = 'confirmed'
        booking['payment_status'] = 'paid'
        # Optionally, update the actual car's availability data if stored elsewhere
        track_user_activity(session['user']['id'], 'confirm_booking', details={'booking_id': booking_id})
        app.logger.info(f"Booking {booking_id} confirmed for user {session['user']['id']}.")
        return jsonify({
            'success': True,
            'message': 'Booking confirmed and payment processed successfully'
        })
    else:
        app.logger.warning(f"Payment processing failed for booking {booking_id}.")
        return jsonify({
            'error': 'Payment processing failed. Please check your card details.'
        }), 400

@app.route('/booking/<int:booking_id>/cancel', methods=['POST'])
@login_required # Ensure user is logged in
def cancel_booking(booking_id):
    booking = bookings.get(booking_id)
    if booking is None or booking['user_id'] != session['user']['id']: # Check ownership
        return jsonify({'error': 'Booking not found or access denied'}), 404

    if booking['status'] == 'cancelled':
        return jsonify({'success': True, 'message': 'Booking already cancelled'})

    # Add cancellation logic (e.g., check if cancellation is allowed based on time)
    # Add refund logic if payment was already processed

    booking['status'] = 'cancelled'
    # Optionally, update the actual car's availability data if stored elsewhere
    track_user_activity(session['user']['id'], 'cancel_booking', details={'booking_id': booking_id})
    app.logger.info(f"Booking {booking_id} cancelled by user {session['user']['id']}.")
    return jsonify({
        'success': True,
        'message': 'Booking cancelled successfully'
    })

def process_payment(payment_data, expected_amount):
    # Mock payment processing - IN A REAL APP, INTEGRATE WITH A PAYMENT GATEWAY (Stripe, etc.)
    # Add validation for payment_data fields
    # Compare payment amount with expected_amount
    app.logger.info(f"Mock payment processing for amount: {expected_amount} with data: {payment_data}")
    # Simulate success/failure
    return random.choice([True, True, False]) # Simulate occasional failure

@app.errorhandler(404)
def page_not_found(e):
     # Fetch some cars for the 404 page footer or suggestions
    cars_data, _ = get_cars(per_page=4)
    return render_template('404.html', cars=list(cars_data.values())), 404

@app.errorhandler(500)
def internal_server_error(e):
    app.logger.error(f"Internal Server Error: {e}", exc_info=True)
    return render_template('500.html'), 500 # Generic 500 error page

def role_required(permission):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user' not in session:
                flash('Please log in to access this page', 'error')
                return redirect(url_for('login', next=request.url))

            user = User.query.get(session['user']['id']) # Fetch user by ID
            if not user or not user.role or not user.is_active:
                flash('Access denied or account inactive', 'error')
                return redirect(url_for('index'))

            # Check permissions via the relationship
            user_permissions = [p.name for p in user.role.permissions]
            # Admin role bypasses specific permission check
            if user.role.name == 'admin' or permission in user_permissions:
                return f(*args, **kwargs)
            else:
                flash('You do not have permission to access this resource.', 'error')
                app.logger.warning(f"Permission denied for user {user.email} attempting to access resource requiring '{permission}'")
                return redirect(url_for('admin_dashboard' if 'view_dashboard' in user_permissions else 'index')) # Redirect appropriately
        return decorated_function
    return decorator

@app.route('/admin')
@login_required
@role_required('view_dashboard')
def admin_dashboard():
    # Basic statistics from DB
    stats = {
        'total_vehicles': Vehicle.query.count(),
        'available_vehicles': Vehicle.query.filter_by(status='available').count(),
        'total_bookings': len(bookings), # Still using in-memory bookings
        'total_users': User.query.count(),
        'active_users': User.query.filter_by(is_active=True).count(),
        'pending_bookings': sum(1 for b in bookings.values() if b['status'] == 'pending'),
        'confirmed_bookings': sum(1 for b in bookings.values() if b['status'] == 'confirmed')
    }

    # User activity analytics
    recent_activities = UserActivity.query.order_by(UserActivity.timestamp.desc()).limit(10).all()

    # User registration trends (last 7 days)
    seven_days_ago = datetime.utcnow() - timedelta(days=7)
    registration_trend_query = db.session.query(
        func.date(User.created_at).label('date'), # Use func.date for grouping
        func.count(User.id).label('count')
    ).filter(User.created_at >= seven_days_ago)\
     .group_by(func.date(User.created_at))\
     .order_by(func.date(User.created_at))
    registration_trend = registration_trend_query.all()
    # Format for chart libraries (e.g., Chart.js)
    registration_chart_data = {
        'labels': [d.date.strftime('%Y-%m-%d') for d in registration_trend],
        'data': [d.count for d in registration_trend]
    }


    # Login activity by hour (last 24 hours)
    day_ago = datetime.utcnow() - timedelta(days=1)
    login_activity_query = db.session.query(
        func.strftime('%H', UserActivity.timestamp).label('hour'),
        func.count(UserActivity.id).label('count')
    ).filter(
        UserActivity.action == 'login',
        UserActivity.timestamp >= day_ago
    ).group_by(func.strftime('%H', UserActivity.timestamp))\
     .order_by(func.strftime('%H', UserActivity.timestamp))
    login_activity = login_activity_query.all()
     # Format for chart libraries
    login_chart_data = {
        'labels': [f"{int(h.hour):02d}:00" for h in login_activity], # Format hour
        'data': [h.count for h in login_activity]
    }


    # Get recent bookings for dashboard
    recent_bookings_list = []
    # Fetch cars for bookings more efficiently if possible, or handle missing cars
    all_cars_data_for_bookings, _ = get_cars(per_page=10000) # Inefficient
    for booking_id, booking in sorted(bookings.items(), key=lambda x: x[1]['created_at'], reverse=True)[:5]:
        car_id = booking['car_id']
        car = all_cars_data_for_bookings.get(car_id, {}) # Get car info from cache/dict

        recent_bookings_list.append({
            'id': booking_id,
            'vehicle_name': car.get('Car Name', 'Unknown Vehicle'), # Use car name
            'customer_name': decrypt_data(booking['customer_name']) or "Error",
            'status': booking['status'],
            'created_at': datetime.fromisoformat(booking['created_at'])
        })

    return render_template(
        'admin/dashboard.html',
        stats=stats,
        recent_activities=recent_activities,
        registration_chart_data=json.dumps(registration_chart_data), # Pass as JSON for JS
        login_chart_data=json.dumps(login_chart_data), # Pass as JSON for JS
        recent_bookings=recent_bookings_list # Use the list
    )


@app.route('/admin/analytics')
@login_required
@role_required('view_reports') # Changed permission to view_reports
def admin_analytics():
    # Date range for analytics
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=30)

    # User growth over time
    user_growth_query = db.session.query(
        func.date(User.created_at).label('date'), # Use func.date
        func.count(User.id).label('count')
    ).filter(User.created_at >= start_date)\
     .group_by(func.date(User.created_at))\
     .order_by(func.date(User.created_at))
    user_growth = user_growth_query.all()
    user_growth_chart_data = {
        'labels': [d.date.strftime('%Y-%m-%d') for d in user_growth],
        'data': [d.count for d in user_growth]
    }

    # Activity distribution
    activity_distribution_query = db.session.query(
        UserActivity.action,
        func.count(UserActivity.id).label('count')
    ).group_by(UserActivity.action)
    activity_distribution = activity_distribution_query.all()
    activity_chart_data = {
         'labels': [a.action for a in activity_distribution],
         'data': [a.count for a in activity_distribution]
    }


    # User engagement metrics
    # Note: distinct() on user_id might be DB-specific or less efficient.
    # Consider alternative approaches for large datasets.
    try:
        daily_active = db.session.query(func.count(func.distinct(UserActivity.user_id))).\
            filter(UserActivity.timestamp >= datetime.utcnow() - timedelta(days=1)).scalar()
        weekly_active = db.session.query(func.count(func.distinct(UserActivity.user_id))).\
            filter(UserActivity.timestamp >= datetime.utcnow() - timedelta(days=7)).scalar()
        monthly_active = db.session.query(func.count(func.distinct(UserActivity.user_id))).\
            filter(UserActivity.timestamp >= datetime.utcnow() - timedelta(days=30)).scalar()
    except Exception as e:
        app.logger.error(f"Error calculating active users: {e}")
        daily_active, weekly_active, monthly_active = 0, 0, 0

    engagement_metrics = {
        'daily_active_users': daily_active or 0,
        'weekly_active_users': weekly_active or 0,
        'monthly_active_users': monthly_active or 0
    }


    return render_template(
        'admin/analytics.html',
        user_growth_chart_data=json.dumps(user_growth_chart_data),
        activity_chart_data=json.dumps(activity_chart_data),
        engagement_metrics=engagement_metrics
    )


@app.route('/admin/reports')
@login_required
@role_required('view_reports')
def admin_reports():
    # Generate various reports (mock data for now)
    reports = {
        'user_activity': generate_user_activity_report(), # Use mock data functions
        'platform_performance': generate_platform_performance_report(),
        'user_trends': generate_user_trends_report()
    }
    return render_template('admin/reports.html', reports=reports)

# --- Mock Report Generation Functions ---
def generate_user_activity_report():
    # Replace with actual data fetching later
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=30)
    try:
        most_common_actions = db.session.query(
                UserActivity.action, func.count(UserActivity.id).label('count')
            ).group_by(UserActivity.action).order_by(func.count(UserActivity.id).desc()).limit(5).all()
        activity_by_day = db.session.query(
                func.date(UserActivity.timestamp).label('date'), func.count(UserActivity.id).label('count')
            ).filter(UserActivity.timestamp >= start_date)\
             .group_by(func.date(UserActivity.timestamp)).order_by(func.date(UserActivity.timestamp)).all()

        return {
            'total_actions': UserActivity.query.count(),
            'unique_users': db.session.query(func.count(func.distinct(UserActivity.user_id))).scalar() or 0,
            'most_common_actions': [(a.action, a.count) for a in most_common_actions],
            'activity_by_day': [(d.date.strftime('%Y-%m-%d'), d.count) for d in activity_by_day]
        }
    except Exception as e:
         app.logger.error(f"Error generating user activity report: {e}")
         return {}

def generate_platform_performance_report():
    # Mock data - replace with actual monitoring if available
    return {
        'average_response_time': f"{calculate_average_response_time()} ms",
        'error_rate': f"{calculate_error_rate()} %",
        'uptime_percentage': f"{calculate_uptime_percentage()} %"
    }

def generate_user_trends_report():
     # Mock data - replace with actual calculations if available
    return {
        'user_growth_rate': f"{calculate_user_growth_rate()} %",
        'retention_rate': f"{calculate_retention_rate()} %",
        'engagement_score': f"{calculate_engagement_score()} / 100"
    }
# --- End Mock Report Functions ---

def track_user_activity(user_id, action, details=None):
    try:
        activity = UserActivity()
        activity.user_id = user_id
        activity.action = action
        activity.details = details
        activity.ip_address = get_remote_address() # Use limiter's function
        activity.user_agent = request.user_agent.string[:255] # Truncate if needed
        db.session.add(activity)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Failed to track user activity for user {user_id}, action {action}: {e}")

# --- Vehicle Admin Routes (Using DB Models) ---
@app.route('/admin/vehicles')
@login_required
@role_required('manage_vehicles')
def admin_vehicles():
    vehicles = Vehicle.query.order_by(Vehicle.created_at.desc()).all()
    return render_template('admin/vehicles.html', vehicles=vehicles)

@app.route('/admin/vehicles/add', methods=['GET', 'POST'])
@login_required
@role_required('manage_vehicles')
def admin_add_vehicle():
    if request.method == 'POST':
        try:
            features = request.form.getlist('features[]') # Get features as list
            vehicle = Vehicle()
            vehicle.title = request.form['title']
            vehicle.price = float(request.form['price'])
            vehicle.rental_price_per_day = float(request.form['rental_price_per_day'])
            vehicle.mileage = int(request.form['mileage'])
            vehicle.year = int(request.form['year'])
            vehicle.transmission = request.form['transmission']
            vehicle.fuel_type = request.form['fuel_type']
            vehicle.description = request.form['description']
            vehicle.location = request.form['location']
            vehicle.features = json.dumps(features) # Store features as JSON string
            vehicle.source_url = request.form.get('source_url')
            vehicle.status = request.form.get('status', 'available') # Get status

            db.session.add(vehicle)
            db.session.commit() # Commit to get vehicle.id

            # Handle image uploads
            images = request.files.getlist('images[]')
            primary_image_set = False
            for i, image in enumerate(images):
                if image and image.filename and allowed_file(image.filename):
                    filename = secure_filename(f"{vehicle.id}_{i}_{image.filename}") # Make filename unique
                    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    image.save(filepath)

                    vehicle_image = VehicleImage()
                    vehicle_image.vehicle_id = vehicle.id
                    # Store relative path from 'static' folder
                    vehicle_image.image_path = os.path.join('uploads', filename).replace("\\", "/")
                    # Set first uploaded image as primary if none explicitly marked
                    vehicle_image.is_primary = (i == 0 and not primary_image_set)
                    if vehicle_image.is_primary: primary_image_set = True

                    db.session.add(vehicle_image)

            db.session.commit() # Commit images
            track_user_activity(session['user']['id'], 'add_vehicle', details={'vehicle_id': vehicle.id, 'title': vehicle.title})
            flash('Vehicle added successfully', 'success')
            return redirect(url_for('admin_vehicles'))

        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error adding vehicle: {e}", exc_info=True)
            flash(f'Error adding vehicle: {str(e)}', 'error')

    # Pass empty vehicle object for form structure in GET request
    return render_template('admin/vehicle_form.html', vehicle={})


@app.route('/admin/vehicles/<int:vehicle_id>/edit', methods=['GET', 'POST'])
@login_required
@role_required('manage_vehicles')
def admin_edit_vehicle(vehicle_id):
    vehicle = Vehicle.query.get_or_404(vehicle_id)
    # Load features from JSON string for form display
    try:
        vehicle_features = json.loads(vehicle.features) if vehicle.features else []
    except json.JSONDecodeError:
        vehicle_features = []

    if request.method == 'POST':
        try:
            vehicle.title = request.form['title']
            vehicle.price = float(request.form['price'])
            vehicle.rental_price_per_day = float(request.form['rental_price_per_day'])
            vehicle.mileage = int(request.form['mileage'])
            vehicle.year = int(request.form['year'])
            vehicle.transmission = request.form['transmission']
            vehicle.fuel_type = request.form['fuel_type']
            vehicle.description = request.form['description']
            vehicle.location = request.form['location']
            vehicle.features = json.dumps(request.form.getlist('features[]')) # Save updated features
            vehicle.source_url = request.form.get('source_url')
            vehicle.status = request.form.get('status', 'available')

            # Handle new image uploads
            images = request.files.getlist('images[]')
            for i, image in enumerate(images):
                 if image and image.filename and allowed_file(image.filename):
                    # Create more unique filename
                    timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S')
                    filename = secure_filename(f"{vehicle.id}_{timestamp}_{i}_{image.filename}")
                    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    image.save(filepath)

                    vehicle_image = VehicleImage()
                    vehicle_image.vehicle_id = vehicle.id
                    vehicle_image.image_path = os.path.join('uploads', filename).replace("\\", "/")
                    db.session.add(vehicle_image)
                    # Logic for setting primary image if needed should be added here

            # Handle image deletion
            images_to_delete = request.form.getlist('delete_images[]')
            for img_id_str in images_to_delete:
                 try:
                    img_id = int(img_id_str)
                    img_to_delete = VehicleImage.query.filter_by(id=img_id, vehicle_id=vehicle.id).first()
                    if img_to_delete:
                        # Attempt to delete file from filesystem
                        try:
                            file_path_to_delete = os.path.join(app.root_path, 'static', img_to_delete.image_path)
                            if os.path.exists(file_path_to_delete):
                                os.remove(file_path_to_delete)
                                app.logger.info(f"Deleted image file: {file_path_to_delete}")
                            else:
                                app.logger.warning(f"Image file not found for deletion: {file_path_to_delete}")
                        except OSError as oe:
                             app.logger.error(f"Error deleting image file {file_path_to_delete}: {oe}")
                        # Delete DB record regardless of file deletion success
                        db.session.delete(img_to_delete)
                 except ValueError:
                     app.logger.warning(f"Invalid image ID for deletion: {img_id_str}")


            db.session.commit()
            track_user_activity(session['user']['id'], 'edit_vehicle', details={'vehicle_id': vehicle.id, 'title': vehicle.title})
            flash('Vehicle updated successfully', 'success')
            return redirect(url_for('admin_vehicles'))

        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error updating vehicle {vehicle_id}: {e}", exc_info=True)
            flash(f'Error updating vehicle: {str(e)}', 'error')

    # Pass vehicle and its features/images for form display in GET request
    return render_template('admin/vehicle_form.html', vehicle=vehicle, features=vehicle_features, images=vehicle.images)


@app.route('/admin/vehicles/<int:vehicle_id>/delete', methods=['POST'])
@login_required
@role_required('manage_vehicles')
def admin_delete_vehicle(vehicle_id):
    vehicle = Vehicle.query.get_or_404(vehicle_id)
    title = vehicle.title # Get title for logging before deleting
    try:
        # Delete associated images first (from filesystem and DB)
        for image in vehicle.images:
            try:
                 file_path_to_delete = os.path.join(app.root_path, 'static', image.image_path)
                 if os.path.exists(file_path_to_delete):
                     os.remove(file_path_to_delete)
                     app.logger.info(f"Deleted image file during vehicle delete: {file_path_to_delete}")
                 else:
                      app.logger.warning(f"Image file not found for deletion during vehicle delete: {file_path_to_delete}")
            except OSError as oe:
                 app.logger.error(f"Error deleting image file {file_path_to_delete} during vehicle delete: {oe}")
            # DB record deleted via cascade or explicitly if needed: db.session.delete(image)
        # Now delete the vehicle itself
        db.session.delete(vehicle)
        db.session.commit()
        track_user_activity(session['user']['id'], 'delete_vehicle', details={'vehicle_id': vehicle_id, 'title': title})
        flash('Vehicle deleted successfully', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error deleting vehicle {vehicle_id}: {e}", exc_info=True)
        flash(f'Error deleting vehicle: {str(e)}', 'error')

    return redirect(url_for('admin_vehicles'))


@app.route('/admin/users')
@login_required
@role_required('manage_users')
def admin_users():
    users = User.query.order_by(User.created_at.desc()).all()
    roles = Role.query.all()
    return render_template('admin/users.html', users=users, roles=roles)


@app.route('/admin/bookings')
@login_required
@role_required('manage_bookings')
def admin_bookings():
    # Convert bookings dictionary to a list and sort by created_at
    booking_list = []
    # Fetch cars for bookings more efficiently if possible
    all_cars_data_for_bookings, _ = get_cars(per_page=10000) # Inefficient
    for booking_id, booking in bookings.items():
        # Decrypt sensitive data for display
        car_id = booking['car_id']
        car = all_cars_data_for_bookings.get(car_id, {})

        booking_data = {
            'id': booking_id,
            'car_id': car_id,
            'user_id': booking.get('user_id', 'N/A'), # Add user ID if available
            'vehicle_name': car.get('Car Name', 'Unknown Vehicle'),
            'customer_name': decrypt_data(booking['customer_name']) or "Error",
            'customer_email': decrypt_data(booking['customer_email']) or "Error",
            'customer_phone': decrypt_data(booking['customer_phone']) or "Error",
            'start_date': booking['start_date'],
            'end_date': booking['end_date'],
            'total_price': booking['total_price'],
            'status': booking['status'],
            'payment_status': booking['payment_status'],
             # Parse safely
            'created_at': datetime.fromisoformat(booking['created_at']) if isinstance(booking.get('created_at'), str) else None
        }
        booking_list.append(booking_data)

    # Sort bookings by created_at in descending order (handle None dates)
    booking_list.sort(key=lambda x: x['created_at'] or datetime.min, reverse=True)

    return render_template('admin/bookings.html', bookings=booking_list)


@app.route('/admin/users/<int:user_id>/role', methods=['POST'])
@login_required
@role_required('manage_users')
def admin_update_user_role(user_id):
    user = User.query.get_or_404(user_id)
    role_id = request.form.get('role_id')

    # Prevent admin from changing their own role? Or add specific checks
    if user.id == session['user']['id']:
         flash('Administrators cannot change their own role.', 'warning')
         return redirect(url_for('admin_users'))

    if role_id:
        try:
            role_id_int = int(role_id)
            role = Role.query.get(role_id_int)
            if role:
                user.role_id = role.id
                db.session.commit()
                track_user_activity(session['user']['id'], 'update_user_role', details={'target_user_id': user_id, 'new_role_id': role.id})
                flash('User role updated successfully', 'success')
            else:
                flash('Invalid role selected', 'error')
        except ValueError:
             flash('Invalid role ID format', 'error')
        except Exception as e:
             db.session.rollback()
             app.logger.error(f"Error updating role for user {user_id}: {e}", exc_info=True)
             flash('Error updating user role', 'error')

    return redirect(url_for('admin_users'))

# --- User Profile Routes ---
@app.route('/profile')
@login_required
def profile():
    user = User.query.get_or_404(session['user']['id'])
    # Basic profile data
    user_data = {
        'id': user.id,
        'name': user.name,
        'email': user.email,
        'profile_picture': user.profile_picture or url_for('static', filename='images/default-profile.png'),
        'phone': user.phone or 'Not provided',
        'address': user.address or 'Not provided',
        'bio': user.bio or 'No bio yet.',
        'date_of_birth': user.date_of_birth.strftime('%B %d, %Y') if user.date_of_birth else 'Not provided',
        'member_since': user.created_at.strftime('%B %Y'),
        'last_login': user.last_login.strftime('%Y-%m-%d %H:%M') if user.last_login else 'Never',
        'role': user.role.name.capitalize() if user.role else 'User'
    }
    # Fetch user's saved cars (from session for now)
    saved_car_ids = session.get('saved_cars', [])
    user_data['saved_cars_count'] = len(saved_car_ids)

    # Fetch user's bookings (from in-memory dict for now)
    user_bookings = [b for b in bookings.values() if b.get('user_id') == user.id]
    user_bookings.sort(key=lambda x: x['created_at'], reverse=True)

    return render_template('profile.html', user_profile=user_data, bookings=user_bookings)

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    user = User.query.get_or_404(session['user']['id'])
    if request.method == 'POST':
        action = request.form.get('action')

        try:
            if action == 'update_profile':
                user.name = request.form.get('name', user.name).strip()
                user.phone = request.form.get('phone', user.phone).strip()
                user.address = request.form.get('address', user.address).strip()
                user.bio = request.form.get('bio', user.bio).strip()
                dob_str = request.form.get('date_of_birth')
                if dob_str:
                    try: user.date_of_birth = datetime.strptime(dob_str, '%Y-%m-%d').date()
                    except ValueError: flash('Invalid date format (YYYY-MM-DD)', 'error')
                else: user.date_of_birth = None

                db.session.commit()
                # Update name in session if changed
                session['user']['name'] = user.name
                session.modified = True
                track_user_activity(user.id, 'update_profile')
                flash('Profile updated successfully!', 'success')

            elif action == 'change_password':
                current_password = request.form.get('current_password')
                new_password = request.form.get('new_password')
                confirm_password = request.form.get('confirm_password')

                if not all([current_password, new_password, confirm_password]):
                    flash('Please fill in all password fields.', 'error')
                elif not check_password_hash(user.password, current_password):
                    flash('Current password is incorrect.', 'error')
                elif new_password != confirm_password:
                    flash('New passwords do not match.', 'error')
                else:
                    is_valid, message = validate_password(new_password)
                    if not is_valid:
                         flash(message, 'error')
                    else:
                        user.password = generate_password_hash(new_password, method='pbkdf2:sha256')
                        db.session.commit()
                        track_user_activity(user.id, 'change_password')
                        flash('Password updated successfully.', 'success')

            elif action == 'update_preferences':
                if not isinstance(user.preferences, dict): user.preferences = {} # Ensure it's a dict
                user.preferences['notifications'] = request.form.get('notifications') == 'on'
                user.preferences['newsletter'] = request.form.get('newsletter') == 'on'
                # Force SQLAlchemy to detect JSON change
                db.session.flag_modified(user, 'preferences')
                db.session.commit()
                track_user_activity(user.id, 'update_preferences')
                flash('Preferences updated successfully.', 'success')

            elif action == 'upload_picture':
                 if 'profile_picture' in request.files:
                    file = request.files['profile_picture']
                    if file and file.filename and allowed_file(file.filename):
                        # Create unique filename
                        timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S')
                        ext = file.filename.rsplit('.', 1)[1].lower()
                        filename = secure_filename(f"profile_{user.id}_{timestamp}.{ext}")
                        # Define profiles subdirectory
                        profile_upload_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'profiles')
                        os.makedirs(profile_upload_dir, exist_ok=True) # Ensure directory exists
                        filepath = os.path.join(profile_upload_dir, filename)

                        # Delete old picture if exists and is not default
                        if user.profile_picture and user.profile_picture != 'images/default-profile.png':
                             try:
                                old_filepath = os.path.join(app.root_path, 'static', user.profile_picture)
                                if os.path.exists(old_filepath): os.remove(old_filepath)
                             except OSError as oe: app.logger.error(f"Error deleting old profile pic {old_filepath}: {oe}")

                        file.save(filepath)
                        # Save relative path from 'static'
                        user.profile_picture = os.path.join('uploads', 'profiles', filename).replace("\\", "/")
                        db.session.commit()
                        track_user_activity(user.id, 'upload_profile_picture')
                        flash('Profile picture updated successfully.', 'success')
                    elif file.filename: # File selected but not allowed
                         flash('Invalid file type. Allowed types: png, jpg, jpeg, gif', 'error')

            else:
                flash('Invalid action.', 'error')

        except Exception as e:
             db.session.rollback()
             app.logger.error(f"Error updating settings for user {user.id}: {e}", exc_info=True)
             flash('An error occurred while updating settings.', 'error')

        return redirect(url_for('settings')) # Redirect after POST to prevent re-submission

    # GET request: Prepare data for the form
    user_data = {
        'name': user.name or '',
        'email': user.email, # Usually not editable
        'phone': user.phone or '',
        'address': user.address or '',
        'bio': user.bio or '',
        'date_of_birth': user.date_of_birth.strftime('%Y-%m-%d') if user.date_of_birth else '',
        'profile_picture': user.profile_picture or url_for('static', filename='images/default-profile.png'),
        'preferences': user.preferences if isinstance(user.preferences, dict) else {'notifications': True, 'newsletter': False}
    }
    return render_template('settings.html', user_settings=user_data)

# --- Saved Cars Routes (Using Session) ---
@app.route('/saved-cars')
@login_required
def saved_cars():
    saved_car_ids = session.get('saved_cars', [])
    # Fetch car details (inefficient - should ideally query DB if cars were stored there)
    all_cars, _ = get_cars(per_page=10000)
    saved_cars_list = []
    for car_id_str in saved_car_ids:
        try:
            car = all_cars.get(int(car_id_str))
            if car: saved_cars_list.append(car)
        except (ValueError, TypeError): continue # Skip if ID is invalid

    return render_template('saved_cars.html', cars=saved_cars_list)


@app.route('/car/<car_id>/save', methods=['POST'])
@login_required
def save_car(car_id):
    if 'saved_cars' not in session: session['saved_cars'] = []
    # Ensure car_id is string for consistency in session list
    car_id_str = str(car_id)

    if car_id_str not in session['saved_cars']:
        session['saved_cars'].append(car_id_str)
        session.modified = True # IMPORTANT: Mark session as modified
        track_user_activity(session['user']['id'], 'save_car', details={'car_id': car_id_str})
        return jsonify({'status': 'success', 'message': 'Car saved successfully'})
    else:
        return jsonify({'status': 'error', 'message': 'Car already saved'})

@app.route('/car/<car_id>/unsave', methods=['POST'])
@login_required
def unsave_car(car_id):
    car_id_str = str(car_id)
    if 'saved_cars' in session and car_id_str in session['saved_cars']:
        session['saved_cars'].remove(car_id_str)
        session.modified = True # IMPORTANT: Mark session as modified
        track_user_activity(session['user']['id'], 'unsave_car', details={'car_id': car_id_str})
        return jsonify({'status': 'success', 'message': 'Car removed from saved list'})
    else:
        return jsonify({'status': 'error', 'message': 'Car was not in saved list'})

# --- Helper Functions ---
def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Custom template filter for datetime formatting
@app.template_filter('datetime')
def format_datetime_filter(value, format='%Y-%m-%d %H:%M:%S'):
    if isinstance(value, str):
        try: value = datetime.fromisoformat(value)
        except ValueError: return value # Return original string if parse fails
    if isinstance(value, datetime):
        return value.strftime(format)
    return value # Return original value if not datetime

# --- Mock Calculation Functions (for Reports) ---
def calculate_average_response_time(): return round(random.uniform(100, 500), 2)
def calculate_error_rate(): return round(random.uniform(0.1, 2.0), 2)
def calculate_uptime_percentage(): return round(random.uniform(98.5, 99.99), 2)
def calculate_user_growth_rate(): return round(random.uniform(-5, 15), 2)
def calculate_retention_rate(): return round(random.uniform(20, 60), 2)
def calculate_engagement_score(): return round(random.uniform(30, 80), 2)
# --- End Mock Calculations ---

# Add context processor to make 'now' available in templates
@app.context_processor
def inject_now():
    return {'now': datetime.utcnow()} # Use UTC time

@app.route('/signup', methods=['GET']) # Only GET for signup page display
def signup():
     # Registration logic is handled by /register POST route
    return render_template('register.html') # Reuse register template for signup page


if __name__ == '__main__':
    # Consider using environment variables for host and port in production
    host = os.environ.get('FLASK_RUN_HOST', '127.0.0.1')
    port = int(os.environ.get('FLASK_RUN_PORT', 5000))
    debug_mode = app.debug # Use debug setting from app config
    app.run(host=host, port=port, debug=debug_mode)