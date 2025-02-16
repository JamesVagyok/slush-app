from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
import os
from werkzeug.utils import secure_filename
from models import db, User, UserProfile, Document
import time
from flask import send_file
import pandas as pd
import logging
import boto3
import uuid
from dotenv import load_dotenv



# Explicitly load .env file
load_dotenv(dotenv_path=".env", override=True)





# Flask App Initialization
app = Flask(__name__)





#Load configurations
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default_secret_key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')





# Ensure UPLOAD_FOLDER is defined before using it
app.config['UPLOAD_FOLDER'] = "uploads"
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)





S3_BUCKET=os.getenv("S3_BUCKET")
S3_ACCESS_KEY=os.getenv("S3_ACCESS_KEY")
S3_SECRET_KEY=os.getenv("S3_SECRET_KEY")
S3_REGION=os.getenv("S3_REGION")

s3 = boto3.client(
    "s3",
    aws_access_key_id=S3_ACCESS_KEY,
    aws_secret_access_key=S3_SECRET_KEY,
    region_name=S3_REGION
)

def upload_to_s3(file):
    """Upload file to AWS S3 and return its URL."""
    file.filename = f"{uuid.uuid4()}-{secure_filename(file.filename)}"  # Unique filename
    s3.upload_fileobj(file, S3_BUCKET, file.filename)
    return f"https://{S3_BUCKET}.s3.{S3_REGION}.amazonaws.com/{file.filename}"





#Login configurations
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)





# Initialize database and migrations
db.init_app(app)
migrate = Migrate(app, db)





# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'



@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))





# Allowed file types and max size
ALLOWED_EXTENSIONS = {'pdf', 'jpg', 'jpeg', 'png'}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB





def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS






# Home Page
@app.route('/')
def index():
    return render_template('index.html')





# User Registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        #Admin logic
        admin_emails = ["slushtest001@gmail.com"]  # Admin accounts
        is_admin = email in admin_emails  

        #prevent duplicate emails
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'danger')
            return redirect(url_for('register'))
        
        #save user
        new_user = User(name=name, email=email, is_admin=is_admin)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')





# User Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            login_user(user)

            # If user is admin, send them directly to admin dashboard (skip profile check)
            if user.is_admin:
                return redirect(url_for('admin_dashboard'))

            # If user is NOT admin and has no profile, redirect to create profile
            if not UserProfile.query.filter_by(user_id=user.id).first():
                return redirect(url_for('create_profile'))

            # Otherwise, send regular users to their dashboard
            return redirect(url_for('dashboard'))

        
        flash('Invalid email or password', 'danger')
    return render_template('login.html')





# Create Profile
@app.route('/create_profile', methods=['GET', 'POST'])
@login_required
def create_profile():
    if UserProfile.query.filter_by(user_id=current_user.id).first():
        flash("Profile already exists. Redirecting to Dashboard.", "info")
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        try:
        
            profile = UserProfile(
                user_id=current_user.id,
                date_of_birth=request.form['date_of_birth'],
                university=request.form['university'],
                city_of_residence=request.form['city_of_residence'],
                phone_number=request.form['phone_number'],
                bank_name=request.form['bank_name'],
                bank_swift_code=request.form['bank_swift_code'],
                bank_iban=request.form['bank_iban'],
                passport_number=request.form['passport_number']
            )
            db.session.add(profile)
            db.session.commit()
            flash('Profile created successfully!', 'success')
            return redirect(url_for('dashboard'))

        except Exception as e:
            db.session.rollback()
            flash(f"Error creating profile: {e}", "danger")

    return render_template('create_profile.html')





# Edit Profile
@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    profile = UserProfile.query.filter_by(user_id=current_user.id).first()
    if not profile:
        flash("Profile not found. Please create one.", "danger")
        return redirect(url_for('create_profile'))
    
    logger.info(f"Before Edit -> Passport Number in DB: {profile.passport_number}")


    if request.method == 'POST':
        try:

            profile.date_of_birth = request.form['date_of_birth']
            profile.university = request.form['university']
            profile.city_of_residence = request.form['city_of_residence']
            profile.phone_number = request.form['phone_number']
            profile.bank_name = request.form['bank_name']
            profile.bank_swift_code = request.form['bank_swift_code']
            profile.bank_iban = request.form['bank_iban']
            profile.passport_number = request.form['passport_number']

            db.session.commit()
            flash('Profile updated successfully!', 'success')
            logger.info(f"Profile updated for user {current_user.email}")  #LOGGING ADDED
            return redirect(url_for('dashboard'))
        
        except Exception as e:

            db.session.rollback()
            logger.error(f"Error updating profile for user {current_user.email}: {e}")  #LOGGING ERROR
            flash(f"Error updating profile: {e}", 'danger')

    return render_template('edit_profile.html', profile=profile)





# User Dashboard
@app.route('/dashboard')
@login_required
def dashboard():
    uploaded_files = Document.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', files=uploaded_files)





@app.route('/uploads', methods=['POST'])
@login_required
def upload_file():
    if 'files' not in request.files:
        flash('No files uploaded', 'danger')
        return redirect(url_for('dashboard'))

    files = request.files.getlist('files')
    file_type = request.form.get('file_type')

    allowed_types = ["Transcript", "ID Card", "Scholarship Letter", "Other"]
    if file_type not in allowed_types:
        flash("Invalid file category!", "danger")
        return redirect(url_for('dashboard'))

    for file in files:
        if file and allowed_file(file.filename):
            file.seek(0, os.SEEK_END)  # Move cursor to end of file
            file_size = file.tell()  # Get file size
            file.seek(0)  # Reset cursor

            if file_size > MAX_FILE_SIZE:
                flash(f"File {file.filename} exceeds the 5MB limit.", "danger")
                continue  # Skip this file and move to the next one

            try:
                file_url = upload_to_s3(file)  # Upload to AWS S3 and get URL

                # Save file details to the database
                new_document = Document(
                    user_id=current_user.id,
                    filename=file.filename,
                    file_path=file_url,  # Store S3 URL instead of local path
                    file_type=file_type
                )
                db.session.add(new_document)
            except Exception as e:
                flash(f"Error uploading file to S3: {e}", "danger")
                continue

    db.session.commit()
    flash("Files uploaded successfully!", "success")
    return redirect(url_for('dashboard'))




# Logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))





# Admin Dashboard
@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash("Access denied! You are not an admin.", "danger")
        return redirect(url_for('dashboard'))

    users = db.session.query(User, UserProfile).join(UserProfile).all()
    return render_template('admin_dashboard.html', users=users)





#Download excel
@app.route('/download_users_excel')
@login_required
def download_users_excel():
    if not current_user.is_admin:
        flash("Access denied! You are not an admin.", "danger")
        return redirect(url_for('dashboard'))

    users = db.session.query(User, UserProfile).join(UserProfile).all()

    # Create a DataFrame
    data = []
    for user, profile in users:
        data.append([
            user.name, user.email, profile.date_of_birth, profile.university,
            profile.city_of_residence, profile.phone_number, profile.bank_name,
            profile.bank_swift_code, profile.bank_iban, profile.passport_number
        ])

    columns = ["Name", "Email", "Date of Birth", "University", "City of Residence",
               "Phone Number", "Bank Name", "Swift Code", "IBAN", "Passport Number"]
    
    df = pd.DataFrame(data, columns=columns)

    # Save to an Excel file
    excel_filename = "users_list.xlsx"
    excel_path = os.path.join(app.config['UPLOAD_FOLDER'], excel_filename)
    df.to_excel(excel_path, index=False, engine='openpyxl')

    # Send file for download
    return send_file(excel_path, as_attachment=True, download_name=excel_filename, mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")





if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
