from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
import os
import datetime
import re
import secrets

app = Flask(__name__)

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', secrets.token_hex(16))
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')

mail = Mail(app)
db = SQLAlchemy(app)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    reset_token = db.Column(db.String(100), unique=True, nullable=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256')

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class ConsciousnessScore(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date = db.Column(db.Date, default=datetime.date.today)
    score = db.Column(db.Integer, nullable=False)

# Helper functions
def is_valid_email(email):
    return re.match(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', email)

def is_valid_password(password):
    return len(password) >= 8 and any(char.isdigit() for char in password) and any(char.isupper() for char in password)

# Ensure tables are created
with app.app_context():
    db.create_all()

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        if not is_valid_email(email):
            flash("Invalid email format.", 'danger')
            return redirect(url_for('signup'))
        
        if not is_valid_password(password):
            flash("Password must be at least 8 characters long, contain at least one number, and one uppercase letter.", 'danger')
            return redirect(url_for('signup'))
        
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash("Email already registered.", 'danger')
            return redirect(url_for('signup'))
        
        user = User(username=username, email=email)
        user.set_password(password)
        try:
            db.session.add(user)
            db.session.commit()
            flash("Account created successfully. Please log in.", 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash("An error occurred.", 'danger')
            return redirect(url_for('signup'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            session['user_id'] = user.id
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid email or password.", 'danger')
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html')

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    return render_template('profile.html', user=user)

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            token = secrets.token_urlsafe(32)
            user.reset_token = token
            db.session.commit()
            msg = Message('Password Reset', sender=app.config['MAIL_USERNAME'], recipients=[email])
            msg.body = f"Use this link to reset your password: {url_for('reset_token', token=token, _external=True)}"
            mail.send(msg)
            flash("Password reset link sent.", 'info')
        else:
            flash("Email not found.", 'danger')
    return render_template('reset_password.html')

@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset_token(token):
    user = User.query.filter_by(reset_token=token).first()
    if not user:
        flash("Invalid or expired token.", 'danger')
        return redirect(url_for('reset_password'))
    if request.method == 'POST':
        new_password = request.form['password']
        if not is_valid_password(new_password):
            flash("Password must be strong.", 'danger')
            return redirect(url_for('reset_token', token=token))
        user.set_password(new_password)
        user.reset_token = None
        db.session.commit()
        flash("Password reset successful. Please log in.", 'success')
        return redirect(url_for('login'))
    return render_template('new_password.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('index'))

# Run the app
if __name__ == '__main__':
    app.run(debug=True)
