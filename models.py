from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

# User model
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)  
    
    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

#  UserProfile model
class UserProfile(db.Model):
    __tablename__ = "user_profiles"  # Add a table name for clarity
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, unique=True)
    date_of_birth = db.Column(db.String(10), nullable=False)
    university = db.Column(db.String(255), nullable=False)
    city_of_residence = db.Column(db.String(100), nullable=False)
    phone_number = db.Column(db.String(20), nullable=False)
    bank_name = db.Column(db.String(255), nullable=False)
    bank_swift_code = db.Column(db.String(20), nullable=False)
    bank_iban = db.Column(db.String(34), nullable=False)
    passport_number = db.Column(db.String(20), nullable=False) 
    
    user = db.relationship('User', backref=db.backref('profile', uselist=False))

#  Document model
class Document(db.Model):
    __tablename__ = "documents"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(255), nullable=False)
    file_type = db.Column(db.String(50), nullable=False)  # NEW: Store file category (e.g., 'Transcript', 'ID')
    uploaded_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    user = db.relationship('User', backref=db.backref('documents', lazy=True))
