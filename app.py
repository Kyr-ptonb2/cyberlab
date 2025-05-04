from flask import Flask, render_template, request, redirect, session, url_for, flash
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'
bcrypt = Bcrypt(app)

# Configure SQLite database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cyberlab.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Configure Flask-Mail (Gmail)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'goodwinmaina36@gmail.com'  # Replace with your Gmail
app.config['MAIL_PASSWORD'] = 'ljbi bodc vsdy ieth '     # Replace with your App Password
app.config['MAIL_DEFAULT_SENDER'] = 'goodwinmaina36@gmail.com'

mail = Mail(app)
serializer = URLSafeTimedSerializer(app.secret_key)

db = SQLAlchemy(app)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(150), nullable=False)
    middle_name = db.Column(db.String(150), nullable=True)
    last_name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    is_confirmed = db.Column(db.Boolean, default=False)

# Home route
@app.route('/')
def home():
    return render_template('home.html')

# Signup
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        first_name = request.form['first_name'].strip()
        middle_name = request.form.get('middle_name')
        last_name = request.form['last_name'].strip()
        email = request.form['email'].strip()
        username = request.form['username'].strip()
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        if User.query.filter_by(username=username).first():
            flash("Username already exists. Please choose a different one!", "error")
            return render_template('signup.html', error=True)

        if User.query.filter_by(email=email).first():
            flash("Email already exists. Please input a different email!", "error")
            return render_template('signup.html', error=True)

        if password1 != password2:
            flash("Passwords don't match, try again!", "error")
            return redirect(url_for('signup'))

        if len(password1) < 8:
            flash('Password must be at least 8 characters long.', 'error')
            return render_template('signup.html', error=True)

        hashed_password = bcrypt.generate_password_hash(password1).decode('utf-8')

        new_user = User(
            first_name=first_name,
            middle_name=middle_name,
            last_name=last_name,
            email=email,
            username=username,
            password=hashed_password
        )

        db.session.add(new_user)
        db.session.commit()

        #Email confirmation setup
        s = URLSafeTimedSerializer(app.secret_key)
        token = s.dumps(email, salt='email-confirmation-salt')
        confirm_url = url_for('confirm_email', token=token, _external=True)
        
        #Send confirmation email
        msg = Message('Confirm Your Email - CyberLab', sender='goodwinmaina36@gmail.com', recipients=[email])
        msg.body = f'Please click the link to confirm your email: {confirm_url}'
        try:
            mail.send(msg)
        
        except Exception as e:
            flash("Failed to send confirmation email. please cheque your SMPT settings.","error!")
            print("Email send error:", e)

        flash("Account created! Check your email to confirm your address.", "success")
        return redirect(url_for('login'))

    return render_template('signup.html', error=False)

# Confirm Email
@app.route('/confirm/<token>')
def confirm_email(token):
    try:
        email = serializer.loads(token, salt='email-confirmation-salt', max_age=3600)
    except:
        flash('The confirmation link is invalid or has expired.', 'danger')
        return redirect(url_for('login'))

    user = User.query.filter_by(email=email).first_or_404()
    if user.is_confirmed:
        flash('Account already confirmed. Please log in.', 'info')
    else:
        user.is_confirmed = True
        db.session.commit()
        flash('You have confirmed your account. Thanks!', 'success')
    return redirect(url_for('login'))

# Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()

        if not user:
            flash("Username does not exist!", "danger")
            return redirect(url_for('signup'))

        if not bcrypt.check_password_hash(user.password, password):
            flash("Password is incorrect", "danger")
            return redirect(url_for('login'))

        if not user.is_confirmed:
            flash("Please confirm your email address before logging in.", "warning")
            return redirect(url_for('login'))

        session['user_id'] = user.id
        session['username'] = username
        flash("Logged in successfully!", "success")
        return redirect(url_for('home'))
    return render_template('login.html')

# Logout
@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out", "info")
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        if not os.path.exists('cyberlab.db'):
            db.create_all()
    app.run(debug=True)

    

# import socket

# @app.route('/port-scanner', methods=['GET', 'POST'])
# def port_scanner():
#     results = []
#     target = ''
#     if request.method == 'POST':
#         target = request.form['target']
#         common_ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389]
#         for port in common_ports:
#             try:
#                 s = socket.socket()
#                 s.settimeout(0.5)
#                 s.connect((target, port))
#                 results.append(f"Port {port} is OPEN")
#                 s.close()
#             except:
#                 results.append(f"Port {port} is CLOSED")
#     return render_template('port_scanner.html', results=results, target=target)
