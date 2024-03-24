from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from . import db  # Assuming db is defined in __init__.py of Admin package

# Initialize SQLAlchemy and Bcrypt instances
db = SQLAlchemy()
bcrypt = Bcrypt()

class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    profile_pic = db.Column(db.String(100))  # Assuming storing profile picture URL
    about_us = db.Column(db.Text)
    business_location = db.Column(db.String(100))
    operational_hours = db.Column(db.String(100))
    delivery_services = db.Column(db.Text)
    is_admin = db.Column(db.Boolean, default=True)  # Flag to indicate if the user is an admin

    def __repr__(self):
        return f'<Admin {self.username}>'

from . import db  # Assuming db is defined in __init__.py of Admin package

class Client(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    # Add additional fields for account updates
    bio = db.Column(db.Text)  # Example field for storing user bio
    profile_picture = db.Column(db.String(255))  # Example field for storing profile picture URL
    
    def __repr__(self):
        return f"Client('{self.username}', '{self.email}')"

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    description = db.Column(db.Text)
    image = db.Column(db.String(255))  # Assuming image URLs or file paths will not exceed 255 characters

    def __repr__(self):
        return f'<Product {self.name}>'
