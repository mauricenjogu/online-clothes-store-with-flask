from flask import Flask, redirect, render_template, request, session, flash, url_for
from flask_bcrypt import Bcrypt
from datetime import timedelta
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from Admin.admin import admin_blueprint  # Importing admin_blueprint from the admin package
from Admin.models import db, Admin, Product, Client  # Importing models from the admin package
from user_manager import UserManager
from flask import request, flash, redirect, url_for, render_template
from werkzeug.utils import secure_filename
import os


app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Set a secret key for session encryption
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.sqlite3'  # Replace 'example.db' with your database URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.register_blueprint(admin_blueprint)

# Initialize SQLAlchemy and migrate instances
db.init_app(app)
migrate = Migrate(app, db)

# Set session timeout to 12 hours
app.permanent_session_lifetime = timedelta(hours=12)

# Define your routes and other application logic here

@app.route('/business')
def business_page():
    return render_template('simoshop.html')

@app.route('/')
def home():
    return render_template('home_page.html')

@app.route('/products')
def products():
    # Retrieve all products from the database
    products = Product.query.all()
    return render_template('products.html', products=products)

@app.route('/about')
def get_about_us_info():
    # Query the database to fetch the "About Us" information for the admin
    admin = Admin.query.first()  # Assuming there is only one admin in the database
    about_us_info = admin.about_us if admin else None
    return render_template('about.html', about_us_info=about_us_info)

@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('query')
    if query:
        # Query the database for products matching the search query
        search_results = Product.query.filter(Product.name.ilike(f'%{query}%')).all()
    else:
        search_results = []
    return render_template('search_results.html', search_results=search_results)

@app.route('/account')
def account():
    if UserManager.is_user_logged_in(session):
        email = UserManager.get_logged_in_user_email(session)
        return render_template('user_account.html', email=email)
    else:
        return render_template('user_account_guest.html')
    
@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if request.method == 'POST':
        # Extract form data
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_new_password = request.form['confirm_new_password']
        
        # Retrieve the current user's email from the session
        email = session.get('email')

        # Perform validation checks
        if not all((current_password, new_password, confirm_new_password)):
            flash('All fields are required.', 'error')
            return redirect(url_for('change_password'))  # Redirect to the change password page
        elif new_password != confirm_new_password:
            flash('New passwords do not match.', 'error')
            return redirect(url_for('change_password'))  # Redirect to the change password page
        else:
            # Query the database to retrieve the user by email
            user = Client.query.filter_by(email=email).first()

            # Verify the current password
            if user and bcrypt.check_password_hash(user.password, current_password):
                # Check if the new password is the same as the old password
                if bcrypt.check_password_hash(user.password, new_password):
                    flash('New password cannot be the same as the old password.', 'error')
                    return redirect(url_for('change_password'))  # Redirect to the change password page with an error message

                # Update the password with the new one
                user.password = bcrypt.generate_password_hash(new_password).decode('utf-8')
                db.session.commit()
                flash('Password changed successfully!', 'success')
                return redirect(url_for('account'))  # Redirect to the user account page after changing password
            else:
                flash('Invalid current password.', 'error')
                return redirect(url_for('change_password'))  # Redirect to the change password page with an error message
    else:
        return render_template('change_password.html')   

@app.route('/update_email', methods=['POST'])
def update_email():
    current_email = request.form['current_email']
    new_email = request.form['new_email']
    UserManager.update_email(current_email, new_email)
    return render_template('update_email.html')

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
UPLOAD_FOLDER = 'path/to/upload/folder'

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/edit_profile_picture', methods=['GET', 'POST'])
def edit_profile_picture():
    if request.method == 'POST':
        # Check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part', 'error')
            return redirect(request.url)
        
        file = request.files['file']
        
        # If the user does not select a file, the browser submits an empty file without a filename
        if file.filename == '':
            flash('No selected file', 'error')
            return redirect(request.url)

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            # Save the file to the upload folder
            file_path = os.path.join(UPLOAD_FOLDER, filename)
            file.save(file_path)
            
            # Retrieve the current user's email from the session
            email = session.get('email')

            # Query the database to retrieve the user by email
            user = Client.query.filter_by(email=email).first()

            # Update the profile picture path in the database
            if user:
                user.profile_picture = file_path
                db.session.commit()
                flash('Profile picture updated successfully!', 'success')
                return redirect(url_for('edit_profile_picture'))
            else:
                flash('User not found.', 'error')
                return redirect(url_for('edit_profile_picture'))

    return render_template('edit_profile_picture.html')


@app.route('/contact')
def contact():
    # Assuming you have a function to fetch the admin's information from the database
    admin = Admin.query.first()  # Example query to fetch the first admin record
    return render_template('contact.html', admin=admin)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Extract form data
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        # Perform validation checks
        if not all((username, email, password, confirm_password)):
            # Handle case where any field is empty
            flash('All fields are required.', 'error')
            return render_template('register.html')
        elif password != confirm_password:
            # Handle case where passwords don't match
            flash('Passwords do not match.', 'error')
            return render_template('register.html')
        elif UserManager().check_user_exists(email):
            # Handle case where email is already registered
            flash('Email is already registered. Please login instead.', 'error')
            return redirect('/login')
        else:
            # Registration successful, determine account type and register user accordingly
            if UserManager().is_admin_registration(email):
                UserManager().register_user(username, email, password, account_type='admin')
                return render_template('register_admin.html')  # Render admin registration template
            else:
                UserManager().register_user(username, email, password)
                flash('Registration successful! Please login.', 'success')
                return redirect('/login')
    else:
        # If it's a GET request, simply render the registration form template
        return render_template('register.html')

@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        # Extract form data
        email = request.form['email']
        password = request.form['password']
        
        # Check if user exists in the database
        if UserManager().check_user_exists(email):
            # Verify password
            if UserManager().check_password(email, password):
                # Password is correct, set session and redirect to home page
                session.permanent = True  # Make session persistent
                session['email'] = email  # Store user's email in session
                return redirect('/')
            else:
                # Password is incorrect, render login page with error message
                flash('Incorrect password. Please try again.', 'error')
                return render_template('login.html')
        else:
            # Email not found in database, render login page with error message
            flash('Email not found. Please register or try again with a different email.', 'error')
            return render_template('login.html', show_register=True)
    else:
        # If it's a GET request, simply render the login form template
        return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('email', None)  # Clear the session
    flash('You have been logged out.', 'success')
    return redirect(url_for('business_page'))

if __name__ == '__main__':
    app.run(debug=True)
