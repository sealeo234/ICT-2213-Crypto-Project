from flask import Flask, render_template, redirect, url_for, request, flash, jsonify, send_from_directory, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import json

app = Flask(__name__)

EXTENSION_DIR = os.path.join(os.path.dirname(__file__), "extension")
EXTENSION_FILENAME = "extension.zip"

# --- CONFIG ---
UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['SECRET_KEY'] = 'REDACTED_SECRET_KEY'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024

# Ensure CORS allows the extension to send cookies
CORS(app, supports_credentials=True, resources={r"/*": {"origins": "*"}})

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    public_key = db.Column(db.Text, nullable=True)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# --- WEB UI ROUTES ---

@app.route('/')
def index():
    files = os.listdir(app.config['UPLOAD_FOLDER']) if current_user.is_authenticated else []
    return render_template('index.html', files=files)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if User.query.filter_by(username=username).first():
            flash('Username already registered.')
            return redirect(url_for('register'))
        new_user = User(username=username, password=generate_password_hash(password, method='pbkdf2:sha256'))
        db.session.add(new_user)
        db.session.commit()
        flash('Vault created.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and check_password_hash(user.password, request.form['password']):
            login_user(user)
            return redirect(url_for('index'))
        flash('Login failed.')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# --- EXTENSION API ROUTES ---

@app.route('/api/me', methods=['GET'])
def api_me():
    """Checks if the session cookie is valid and returns user info"""
    if current_user.is_authenticated:
        return jsonify({
            "authenticated": True,
            "username": current_user.username,
            "has_key": current_user.public_key is not None
        }), 200
    return jsonify({"authenticated": False}), 401

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    user = User.query.filter_by(username=data.get('username')).first()
    if user and check_password_hash(user.password, data.get('password')):
        login_user(user, remember=True)
        return jsonify({"status": "success", "user": user.username}), 200
    return jsonify({"status": "error", "message": "Invalid credentials"}), 401

@app.route('/api/logout', methods=['POST'])
@login_required
def api_logout():
    """Handles logout for the browser extension"""
    logout_user()
    return jsonify({"status": "success", "message": "Logged out"}), 200

@app.route('/public-key', methods=['POST'])
@login_required
def receive_public_key():
    data = request.get_json()
    if not data or 'publicKey' not in data:
        return jsonify({"error": "Missing key"}), 400
    current_user.public_key = data['publicKey']
    db.session.commit()
    return jsonify({"status": "success", "message": "Key linked."}), 200

# --- FILE OPERATIONS ---

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    # Force=True makes Flask try to parse it even if the header is slightly off
    data = request.get_json(force=True, silent=True)
    
    if not data or 'payload' not in data:
        # Check if it was accidentally sent as a traditional file instead of JSON
        if 'file' in request.files:
            return jsonify({"error": "Server requires encrypted JSON from the extension, not raw files."}), 415
        return jsonify({"error": "No JSON payload detected."}), 400

    filename = secure_filename(data['filename'])
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    # Save the encrypted JSON payload to disk
    try:
        with open(file_path, 'w') as f:
            json.dump(data['payload'], f)
        return jsonify({"status": "success", "message": "Asset vaulted"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

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
        flash(f'Asset {filename} scrubbed.')
    return redirect(url_for('index'))

@app.route("/download/extension", methods=["GET"])
def download_extension():
    file_path = os.path.join(EXTENSION_DIR, EXTENSION_FILENAME)

    if not os.path.exists(file_path):
        abort(404, description="Extension not found")

    return send_from_directory(
        EXTENSION_DIR,
        EXTENSION_FILENAME,
        as_attachment=True
    )

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5000)