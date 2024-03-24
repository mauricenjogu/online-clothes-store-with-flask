from functools import wraps
from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from .models import Admin, Product, db

# Define Blueprint for admin-related routes
admin_blueprint = Blueprint('admin', __name__)

# Custom decorator to check if user is logged in
def login_required(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if 'email' not in session:  # Assuming you store the user's email in session
            flash('You need to log in to access this page.', 'error')
            return redirect(url_for('login'))  # Redirect to your login route
        return func(*args, **kwargs)
    return decorated_function

# Define routes for admin panel
@admin_blueprint.route('/admin/dashboard')
@login_required
def admin_dashboard():
    # Only authenticated users can access this route
    if session.get('is_admin'):  # Assuming you have a key to indicate admin status
        products = Product.query.all()
        return render_template('admin/dashboard.html', products=products)
    else:
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('home'))  # Redirect to home or login page

@admin_blueprint.route('/admin/products', methods=['GET', 'POST'])
@login_required
def manage_products():
    if request.method == 'POST':
        # Handle form submission to add a new product
        # Ensure only admin can add products (if needed)
        if session.get('is_admin'):
            name = request.form['name']
            price = request.form['price']
            description = request.form['description']
            image = request.files['image'] if 'image' in request.files else None
            product = Product(name=name, price=price, description=description, image=image)
            db.session.add(product)
            db.session.commit()
            flash('Product added successfully.', 'success')
        else:
            flash('You do not have permission to add products.', 'error')
        return redirect(url_for('admin.manage_products'))
    else:
        # Display form to add a new product
        return render_template('admin/manage_products.html')

# Other admin routes...
