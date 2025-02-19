from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
import os
import datetime
import re
import secrets

app = Flask(__name__)

# === CONFIGURATION ===
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', secrets.token_hex(16))

# Email Configuration (Set these in Render Environment Variables)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')

mail = Mail(app)
db = SQLAlchemy(app)

# === DATABASE MODELS ===
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

# === HELPER FUNCTIONS ===
def is_valid_email(email):
    """Validate email format."""
    return re.match(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', email)

def is_valid_password(password):
    """Ensure password is strong."""
    return len(password) >= 8 and any(char.isdigit() for char in password) and any(char.isupper() for char in password)

# Ensure tables exist
with app.app_context():
    db.create_all()

# === ROUTES ===
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        if not username or not email or not password:
            flash("All fields are required.", "danger")
            return redirect(url_for('signup'))

        if not is_valid_email(email):
            flash("Invalid email format.", "danger")
            return redirect(url_for('signup'))

        if not is_valid_password(password):
            flash("Password must be at least 8 characters, contain a number and an uppercase letter.", "danger")
            return redirect(url_for('signup'))

        if User.query.filter_by(email=email).first():
            flash("Email is already registered.", "danger")
            return redirect(url_for('signup'))

        new_user = User(username=username, email=email)
        new_user.set_password(password)

        try:
            db.session.add(new_user)
            db.session.commit()
            flash("Signup successful! Please log in.", "success")
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash("An error occurred. Try again.", "danger")
            return redirect(url_for('signup'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            session['user_id'] = user.id
            flash("Login successful!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid credentials. Try again.", "danger")

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    scores = ConsciousnessScore.query.filter_by(user_id=user.id).all()
    return render_template('dashboard.html', user=user, scores=scores)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash("Logged out successfully.", "info")
    return redirect(url_for('index'))

# === PASSWORD RESET ===
@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()

        if user:
            token = secrets.token_urlsafe(32)
            user.reset_token = token
            db.session.commit()

            msg = Message('Password Reset', sender=app.config['MAIL_USERNAME'], recipients=[email])
            msg.body = f"Click this link to reset your password: {url_for('reset_token', token=token, _external=True)}"
            mail.send(msg)

            flash("Password reset link sent.", "info")
            return redirect(url_for('login'))
        else:
            flash("Email not found.", "danger")

    return render_template('reset_password.html')

@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset_token(token):
    user = User.query.filter_by(reset_token=token).first()

    if not user:
        flash("Invalid or expired token.", "danger")
        return redirect(url_for('reset_password'))

    if request.method == 'POST':
        new_password = request.form.get('password')

        if not is_valid_password(new_password):
            flash("Password must be strong.", "danger")
            return redirect(url_for('reset_token', token=token))

        user.set_password(new_password)
        user.reset_token = None
        db.session.commit()

        flash("Password reset successful. Please log in.", "success")
        return redirect(url_for('login'))

    return render_template('new_password.html')

# === CONSCIOUSNESS TEST ===
@app.route('/test', methods=['GET', 'POST'])
def test():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        score = sum(int(request.form.get(f'q{i}', 0)) for i in range(1, 21))
        new_score = ConsciousnessScore(user_id=session['user_id'], score=score)
        db.session.add(new_score)
        db.session.commit()
        flash("Test submitted successfully!", "success")
        return redirect(url_for('dashboard'))

    return render_template('test.html')

# === PROFILE SECTION ===
@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    return render_template('profile.html', user=user)

# === RUN APPLICATION ===
if __name__ == '__main__':
    app.run(debug=True)
