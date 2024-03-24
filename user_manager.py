from flask_bcrypt import Bcrypt
from Admin.models import db, Admin, Client
from flask import flash

bcrypt = Bcrypt()

class UserManager:
    def register_user(self, username, email, password, account_type='client'):
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        if account_type == 'admin':
            user = Admin(username=username, email=email, password=hashed_password)
        else:
            user = Client(username=username, email=email, password=hashed_password)
        db.session.add(user)
        db.session.commit()

    def check_user_exists(self, email, account_type='client'):
        if account_type == 'admin':
            return Admin.query.filter_by(email=email).first() is not None
        else:
            return Client.query.filter_by(email=email).first() is not None

    def check_password(self, email, password, account_type='client'):
        if account_type == 'admin':
            user = Admin.query.filter_by(email=email).first()
        else:
            user = Client.query.filter_by(email=email).first()
        if user:
            return bcrypt.check_password_hash(user.password, password)
        return False

    def is_admin_registration(self, email):
        # Check if the provided email corresponds to an admin account
        user = Admin.query.filter_by(email=email).first()
        return user is not None
    def update_email(self, current_email, new_email):
        # Query the database to retrieve the user by email
        user = Client.query.filter_by(email=current_email).first()
        if user:
            # Update the user's email
            user.email = new_email
            db.session.commit()
            flash('Email updated successfully!', 'success')
        else:
            flash('User not found!', 'error')
            

    @staticmethod
    def is_user_logged_in(session):
        return 'email' in session

    @staticmethod
    def get_logged_in_user_email(session):
        return session.get('email', None)
