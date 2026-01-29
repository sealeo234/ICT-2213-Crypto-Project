from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
from werkzeug.utils import secure_filename
from flask import send_from_directory

# Ensure the upload folder exists
UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'REDACTED'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['UPLOAD_FOLDER'] = 'uploads'

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# User Model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# Routes
@app.route('/')
def index():
    files = []
    if current_user.is_authenticated:
        # Check if directory exists, if not, create it
        if not os.path.exists(app.config['UPLOAD_FOLDER']):
            os.makedirs(app.config['UPLOAD_FOLDER'])
        
        # Get list of files in the directory
        files = os.listdir(app.config['UPLOAD_FOLDER'])
    
    return render_template('index.html', files=files)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Retrieve form data
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Check if user already exists
        user_exists = User.query.filter_by(username=username).first()
        if user_exists:
            flash('Username is already registered in the system.')
            return redirect(url_for('register'))

        # Securely hash password and save
        hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_pw)
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Vault successfully created. Please login.')
        return redirect(url_for('login'))
        
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and check_password_hash(user.password, request.form['password']):
            login_user(user)
            return redirect(url_for('index'))
        flash('Login Unsuccessful. Check username and password')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        flash('System Error: No file stream detected.')
        return redirect(url_for('index'))
    
    file = request.files['file']
    
    if file.filename == '':
        flash('Selection Error: No file selected.')
        return redirect(url_for('index'))

    if file:
        filename = secure_filename(file.filename)
        # Ensure the directory exists
        if not os.path.exists(app.config['UPLOAD_FOLDER']):
            os.makedirs(app.config['UPLOAD_FOLDER'])
            
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        flash(f'Asset "{filename}" has been successfully vaulted.')
        return redirect(url_for('index'))

@app.route('/download/<filename>')
@login_required
def download_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/delete/<filename>')
@login_required
def delete_file(filename):
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if os.path.exists(file_path):
        os.remove(file_path)
        flash(f'Asset {filename} has been scrubbed from the vault.')
    return redirect(url_for('index'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)