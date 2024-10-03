from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_migrate import Migrate
from datetime import datetime
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email
import os
from flask_mail import Mail, Message
import traceback
import fitz 

app = Flask(__name__)

# Set the secret key directly or use the environment variable
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', '1dc848e676509123293d611f5bd2d178')

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://username:admin1234@localhost/salon_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
migrate = Migrate(app, db)

# Email configuration
app.config['MAIL_SERVER'] = 'smtp.example.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'mathipa@gmail.com'
app.config['MAIL_PASSWORD'] = 'mabitsela#1'
app.config['MAIL_DEFAULT_SENDER'] = 'mathipa@gmail.com'

mail = Mail(app)

# User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    full_name = db.Column(db.String(100))
    phone_number = db.Column(db.String(20))
    created_at = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp())

    def __repr__(self):
        return f"User('{self.username}', '{self.email}')"

    def get_id(self):
        return str(self.id)

# Admin model
class Admin(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

    def __repr__(self):
        return f"Admin('{self.username}', '{self.email}')"

    def get_id(self):
        return str(self.id)

# Appointment model
class Appointment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('appointments', lazy=True))
    appointment_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    appointment_time = db.Column(db.String(20), nullable=False)
    description = db.Column(db.Text)

    def __repr__(self):
        return f"Appointment('{self.appointment_date}', '{self.appointment_time}')"

# Appointment model and other models definitions

@app.route('/appointments', methods=['GET', 'POST'])
@login_required
def appointments():
    try:
        if request.method == 'POST':
            appointment_date = request.form.get('appointment_date')
            appointment_time = request.form.get('appointment_time')
            description = request.form.get('description')

            # Parse the date and time
            try:
                appointment_date = datetime.strptime(appointment_date, '%Y-%m-%d')
            except ValueError as e:
                app.logger.error(f"Error parsing appointment date: {str(e)}")
                flash('Invalid date format. Please use YYYY-MM-DD.', 'danger')
                return redirect(url_for('appointments'))

            new_appointment = Appointment(
                user_id=current_user.id,
                appointment_date=appointment_date,
                appointment_time=appointment_time,
                description=description
            )
            db.session.add(new_appointment)
            db.session.commit()
            flash('Appointment scheduled successfully!', 'success')

            # Send confirmation email
            msg = Message('Appointment Confirmation', recipients=[current_user.email])
            msg.body = f'Your appointment is scheduled for {appointment_date.strftime("%Y-%m-%d")} at {appointment_time}. Description: {description}'
            mail.send(msg)

            app.logger.info(f"New appointment created for user {current_user.id}: {new_appointment}")

            return redirect(url_for('appointments'))

        # Fetch appointments for the current user
        appointments = Appointment.query.filter_by(user_id=current_user.id).all()
        app.logger.info(f"Fetched {len(appointments)} appointments for user {current_user.id}: {appointments}")

        return render_template('appointments.html', appointments=appointments)
    
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error in /appointments route: {str(e)}")
        flash('An error occurred. Please try again.', 'danger')
        return render_template('appointments.html', appointments=[])

# Hairstyle model
class Hairstyle(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    image_file = db.Column(db.String(100), nullable=False)

class Nail(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    image_file = db.Column(db.String(100), nullable=False)

class Skincare(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    image_file = db.Column(db.String(100), nullable=False)

@app.route('/hairstyles')
def display_services():
    hairstyles = Hairstyle.query.all()
    nails = Nail.query.all()
    skincares = Skincare.query.all()
    return render_template('hairstyles.html', hairstyles=hairstyles, nails=nails, skincares=skincares)

@app.cli.command('add_hairstyles')
def add_hairstyles():
    hairstyles_data = [
        {'name': 'Male Cut', 'price': 35.0, 'image_file': 'hair1.jpeg'},
        {'name': 'Male Cut', 'price': 50.0, 'image_file': 'hair2.jpeg'},
        {'name': 'Male Cut', 'price': 25.0, 'image_file': 'hair3.jpeg'},
        {'name': 'Male Cut', 'price': 35.0, 'image_file': 'hair4.jpeg'},
        {'name': 'Male Cut', 'price': 35.0, 'image_file': 'hair5.jpeg'},
        {'name': 'Male Cut', 'price': 35.0, 'image_file': 'hair6.jpeg'},
        {'name': 'Male Cut', 'price': 35.0, 'image_file': 'hair7.jpeg'},
        {'name': 'Male Cut', 'price': 35.0, 'image_file': 'hair8.jpeg'},
        {'name': 'Male Cut', 'price': 35.0, 'image_file': 'hair9.jpeg'},
        {'name': 'Male Cut', 'price': 35.0, 'image_file': 'hair10.jpeg'},
        {'name': 'Male Cut', 'price': 35.0, 'image_file': 'hair11.jpeg'},
        {'name': 'Male Cut', 'price': 400.0, 'image_file': 'hair12.jpeg'},
        {'name': 'Male Cut', 'price': 35.0, 'image_file': 'hair13.jpeg'},
        {'name': 'Male Cut', 'price': 35.0, 'image_file': 'hair14.jpeg'},
        {'name': 'Male Cut', 'price': 35.0, 'image_file': 'hair15.jpeg'},
        {'name': 'Male Cut', 'price': 35.0, 'image_file': 'hair16.jpeg'},
        {'name': 'Male Cut', 'price': 35.0, 'image_file': 'hair17.jpeg'},
        {'name': 'Male Cut', 'price': 35.0, 'image_file': 'hair18.jpeg'},
        {'name': 'Male Cut', 'price': 35.0, 'image_file': 'hair19.jpeg'},
        {'name': 'Male Cut', 'price': 35.0, 'image_file': 'hair20.jpeg'},
        {'name': 'Male Cut', 'price': 35.0, 'image_file': 'hair21.jpeg'},
        {'name': 'Male Cut', 'price': 35.0, 'image_file': 'hair22.jpeg'},
        {'name': 'Cut Material', 'image_file': 'set_material.jpeg'},
        
        # Add more as needed
    ]

    for hairstyle_data in hairstyles_data:
        hairstyle = Hairstyle(
            name=hairstyle_data['name'],
            price=hairstyle_data['price'],
            image_file=hairstyle_data['image_file']
        )
        db.session.add(hairstyle)

    try:
        db.session.commit()
        print('Hairstyles added successfully.')
    except Exception as e:
        db.session.rollback()
        print(f'Error adding hairstyles: {str(e)}')

@app.cli.command('add_nails')
def add_nails():
    nails_data = [
        {'name': 'Manicure', 'price': 60.0, 'image_file': 'nail1.jpeg'},
        {'name': 'Nail Art', 'price': 70.0, 'image_file': 'nail2.jpeg'},
        {'name': 'Manicure', 'price': 60.0, 'image_file': 'nail3.jpeg'},
        {'name': 'Manicure', 'price': 60.0, 'image_file': 'nail4.jpeg'},
        {'name': 'Manicure', 'price': 60.0, 'image_file': 'nail4.jpeg'},
        {'name': 'Manicure', 'price': 60.0, 'image_file': 'nail5.jpeg'},
        {'name': 'Manicure', 'price': 60.0, 'image_file': 'nail6.jpeg'},
        {'name': 'Pedicure', 'price': 50.0, 'image_file': 'nail7.jpeg'},
        {'name': 'Manicure', 'price': 60.0, 'image_file': 'nail8.jpeg'},
        {'name': 'Nail Art', 'price': 70.0, 'image_file': 'nail9.jpeg'},
        # Add more as needed
    ]

    for nail_data in nails_data:
        nail = Nail(
            name=nail_data['name'],
            price=nail_data['price'],
            image_file=nail_data['image_file']
        )
        db.session.add(nail)

    try:
        db.session.commit()
        print('Nails added successfully.')
    except Exception as e:
        db.session.rollback()
        print(f'Error adding nails: {str(e)}')

@app.cli.command('add_skincare')
def add_skincare():
    skincare_data = [
        {'name': 'Facial', 'price': 80.0, 'image_file': 'skincare1.jpeg'},
        {'name': 'Facial', 'price': 80.0, 'image_file': 'skincare2.jpeg'},
        {'name': 'Facial', 'price': 80.0, 'image_file': 'skincare3.jpeg'},
        {'name': 'Facial', 'price': 80.0, 'image_file': 'skincare4.jpeg'},
        {'name': 'Facial', 'price': 80.0, 'image_file': 'skincare5.jpeg'},
        {'name': 'Facial', 'price': 80.0, 'image_file': 'skincare6.jpeg'},
        {'name': 'Facial', 'price': 80.0, 'image_file': 'skincare7.jpeg'},
        {'name': 'Facial', 'price': 80.0, 'image_file': 'skincare8.jpeg'},
        {'name': 'Facial', 'price': 80.0, 'image_file': 'skincare9.jpeg'},
        {'name': 'Facial', 'price': 80.0, 'image_file': 'skincare10.jpeg'},
        {'name': 'Massage', 'price': 90.0, 'image_file': 'skincare11.jpeg'},
        {'name': 'Massage', 'price': 90.0, 'image_file': 'skincare12.jpeg'},
        # Add more as needed
    ]

    for skincare_data in skincare_data:
        skincare = Skincare(
            name=skincare_data['name'],
            price=skincare_data['price'],
            image_file=skincare_data['image_file']
        )
        db.session.add(skincare)

    try:
        db.session.commit()
        print('Skincare added successfully.')
    except Exception as e:
        db.session.rollback()
        print(f'Error adding skincare: {str(e)}')
# Form classes
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

@login_manager.user_loader
def load_user(user_id):
    # Check if user is a regular user
    user = User.query.get(int(user_id))
    if not user:
        # If not a regular user, check if user is an admin
        user = Admin.query.get(int(user_id))
    return user

# CLI command to create admin user
@app.cli.command('create_admin')
def create_admin():
    admin = Admin.query.filter_by(email='admin@gmail.com').first()
    if not admin:
        admin = Admin(username='admin', email='admin@gmail.com', password=bcrypt.generate_password_hash('admin1234').decode('utf-8'))
        db.session.add(admin)
        db.session.commit()
        print('Admin user created.')
    else:
        print('Admin user already exists.')

# Routes
@app.route('/')
def index():
    return render_template('index.html')


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign Up')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)

        try:
            db.session.commit()
            flash('Account created successfully!', 'success')
            
            # Send a confirmation email
            msg = Message('Welcome to Salon', recipients=[email])
            msg.body = f'Thank you for signing up, {username}!'
            mail.send(msg)

            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('Error creating account. Please try again.', 'danger')
            print(str(e))

    return render_template('signup.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        print(f"Attempting login for email: {email}")
        user = User.query.filter_by(email=email).first()
        if user:
            print("User found")
        else:
            print("User not found")

        if user and bcrypt.check_password_hash(user.password, password):
            print("Password matched")
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('profile'))
        else:
            print("Password did not match or user not found")
            flash('Login unsuccessful. Please check email and password', 'danger')

    return render_template('login.html', form=form)

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        current_user.full_name = request.form.get('full_name')
        current_user.phone_number = request.form.get('phone_number')

        try:
            db.session.commit()
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('profile'))
        except Exception as e:
            db.session.rollback()
            flash('Error updating profile. Please try again.', 'danger')
            print(str(e))  # Print the specific error for debugging

    return render_template('profile.html', user=current_user)

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out!', 'info')
    return redirect(url_for('login'))

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        admin = Admin.query.filter_by(email=email).first()

        if admin:
            if bcrypt.check_password_hash(admin.password, password):
                login_user(admin)
                flash('Admin login successful!', 'success')
                return redirect(url_for('admin_dashboard'))
            else:
                flash('Incorrect password for admin account.', 'danger')
        else:
            flash('Admin account not found. Please check email.', 'danger')

    return render_template('admin_login.html', form=form)

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not isinstance(current_user, Admin):
        flash('Access denied.', 'danger')
        return redirect(url_for('admin_login'))

    appointments = Appointment.query.all()
    return render_template('admin_dashboard.html', appointments=appointments)

@app.route('/admin/logout')
@login_required
def admin_logout():
    if not isinstance(current_user, Admin):
        flash('Access denied.', 'danger')
        return redirect(url_for('admin_login'))

    logout_user()
    flash('Admin logged out successfully.', 'info')
    return redirect(url_for('admin_login'))

from flask import jsonify

# Extract text from PDF function
def extract_text_from_pdf(pdf_path):
    pdf_document = fitz.open(pdf_path)
    text = ""
    for page_num in range(len(pdf_document)):
        page = pdf_document.load_page(page_num)
        text += page.get_text()
    return text

# Search PDF content function
def search_pdf_content(text, keyword):
    results = []
    lines = text.split('\n')
    for line in lines:
        if keyword.lower() in line.lower():
            results.append(line)
    return results

# Route to handle chatbot responses
@app.route('/chatbot-response', methods=['POST'])
def chatbot_response():
    data = request.get_json()
    user_message = data['message']
    
    # Replace 'path_to_your_pdf.pdf' with your actual PDF path
    pdf_path = "C:/Users/USER/Desktop/My System/Salon_App/Salon_Application.pdf"
    pdf_text = extract_text_from_pdf(pdf_path)
    
    # Search the PDF content
    search_results = search_pdf_content(pdf_text, user_message)
    
    if search_results:
        bot_response = "Here are the relevant information I found:\n" + "\n".join(search_results)
    else:
        bot_response = "I couldn't find any information related to your query in the PDF."

    return jsonify({'response': bot_response})

# Route to render chatbot interface
@app.route('/chatbot', methods=['GET'])
def chatbot():
    return render_template('chatbot.html')


if __name__ == '__main__':
    app.run(debug=True)

import secrets
