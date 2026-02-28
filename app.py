from flask import Flask, render_template, redirect, url_for, request, flash, send_from_directory, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import uuid
import json
import base64
from datetime import datetime
from sqlalchemy import text


UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'REDACTED'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


def ensure_schema():
    with db.engine.begin() as conn:
        user_cols = [row[1] for row in conn.execute(text("PRAGMA table_info(user)")).fetchall()]
        if "signing_public_key" not in user_cols:
            conn.execute(text("ALTER TABLE user ADD COLUMN signing_public_key TEXT"))

        file_cols = [row[1] for row in conn.execute(text("PRAGMA table_info(vault_file)")).fetchall()]
        if "signature" not in file_cols:
            conn.execute(text("ALTER TABLE vault_file ADD COLUMN signature TEXT"))
        if "signature_alg" not in file_cols:
            conn.execute(text("ALTER TABLE vault_file ADD COLUMN signature_alg TEXT"))
        if "signer_public_key" not in file_cols:
            conn.execute(text("ALTER TABLE vault_file ADD COLUMN signer_public_key TEXT"))


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    signing_public_key = db.Column(db.Text)
    iv = db.Column(db.String(32), nullable=False)


class VaultFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner_uuid = db.Column(db.String(36), db.ForeignKey('user.uuid'))
    filename = db.Column(db.String(120))
    iv = db.Column(db.Text)
    signature = db.Column(db.Text)
    signature_alg = db.Column(db.String(32))
    signer_public_key = db.Column(db.Text)
    size = db.Column(db.Integer)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class FileKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('vault_file.id'))
    recipient_uuid = db.Column(db.String(36))
    wrapped_key = db.Column(db.Text)


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


@app.route('/')
def index():
    files = []
    if current_user.is_authenticated:
        user_dir = os.path.join(app.config['UPLOAD_FOLDER'], current_user.uuid)
        os.makedirs(user_dir, exist_ok=True)

        # Files I own
        owned_files = VaultFile.query.filter_by(owner_uuid=current_user.uuid)

        # Files shared with me
        shared_file_ids = [fk.file_id for fk in FileKey.query.filter_by(recipient_uuid=current_user.uuid).all()]
        shared_files = VaultFile.query.filter(VaultFile.id.in_(shared_file_ids))

        # Combine
        files = owned_files.union(shared_files).all()

        return render_template(
            'index.html',
            files=files,
            user_uuid=current_user.uuid,
            public_key=current_user.public_key
        )

    return render_template('index.html', files=[])

@app.route("/check_username", methods=["POST"])
def check_username():
    data = request.json
    username = data.get("username", "").strip()
    if not username:
        return {"available": False, "error": "No username provided"}, 400

    exists = User.query.filter_by(username=username).first() is not None
    return {"available": not exists}


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        public_key = request.form.get('public_key')
        signing_public_key = request.form.get('signing_public_key')
        iv = request.form.get('iv')

        if not public_key or not signing_public_key or not iv:
            flash('Missing public key material.')
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash('Username already exists.')
            return redirect(url_for('register'))

        new_user = User(
            username=username,
            password=generate_password_hash(password),
            public_key=public_key,
            signing_public_key=signing_public_key,
            iv=iv
        )
        db.session.add(new_user)
        db.session.commit()
        flash('Vault user initialized.')
        return redirect(url_for('index'))

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
    file = request.files.get('file')

    if not file:
        return "No file", 400

    file.seek(0, os.SEEK_END)
    size = file.tell()
    file.seek(0)

    filename = secure_filename(file.filename)
    user_dir = os.path.join(app.config['UPLOAD_FOLDER'], current_user.uuid)
    os.makedirs(user_dir, exist_ok=True)

    existing_names = {
        f.filename
        for f in VaultFile.query.with_entities(VaultFile.filename).all()
    }


    if filename in existing_names:
        name, ext = os.path.splitext(filename)
        counter = 1
        while f"{name} ({counter}){ext}" in existing_names:
            counter += 1
        filename = f"{name} ({counter}){ext}"

    path = os.path.join(user_dir, filename)
    file.save(path)

    iv = request.form.get("iv")
    wrapped_keys = request.form.get("wrapped_keys")
    signature = request.form.get("signature")
    signature_alg = request.form.get("signature_alg")
    signer_public_key = request.form.get("signer_public_key")

    if not signature or not signature_alg or not signer_public_key:
        return "Missing signature metadata", 400

    if not current_user.signing_public_key:
        return "Signing key not registered", 400

    if signer_public_key != current_user.signing_public_key:
        return "Signing key mismatch", 400

    vault_file = VaultFile(
        owner_uuid=current_user.uuid,
        filename=filename,
        iv=iv,
        signature=signature,
        signature_alg=signature_alg,
        signer_public_key=signer_public_key,
        size=size
    )

    db.session.add(vault_file)
    db.session.commit()

    wrapped_keys = json.loads(wrapped_keys)

    for recipient_uuid, wrapped_key in wrapped_keys.items():
        db.session.add(FileKey(
            file_id=vault_file.id,
            recipient_uuid=recipient_uuid,
            wrapped_key=wrapped_key
        ))

    db.session.commit()

    flash("File encrypted and uploaded successfully.")
    return redirect(url_for("index"))



@app.route('/download/<int:file_id>')
@login_required
def download_file(file_id):
    record = VaultFile.query.filter_by(id=file_id).first()
    if not record:
        return "Not found", 404

    allowed = (
        record.owner_uuid == current_user.uuid or
        FileKey.query.filter_by(
            file_id=file_id,
            recipient_uuid=current_user.uuid
        ).first()
    )

    if not allowed:
        return "Forbidden", 403

    owner_dir = os.path.join(app.config['UPLOAD_FOLDER'], record.owner_uuid)
    return send_from_directory(owner_dir, record.filename, as_attachment=True)



@app.route('/file_iv/<int:file_id>')
@login_required
def file_iv(file_id):
    record = VaultFile.query.filter_by(id=file_id).first()
    if not record:
        return {"error": "not found"}, 404

    # Check if current user is owner or has a wrapped key
    allowed = (
        record.owner_uuid == current_user.uuid or
        FileKey.query.filter_by(file_id=file_id, recipient_uuid=current_user.uuid).first()
    )

    if not allowed:
        return {"error": "access denied"}, 403

    return {"iv": record.iv}


@app.route('/file_signature/<int:file_id>')
@login_required
def file_signature(file_id):
    record = VaultFile.query.filter_by(id=file_id).first()
    if not record:
        return {"error": "not found"}, 404

    allowed = (
        record.owner_uuid == current_user.uuid or
        FileKey.query.filter_by(file_id=file_id, recipient_uuid=current_user.uuid).first()
    )

    if not allowed:
        return {"error": "access denied"}, 403

    return {
        "signature": record.signature,
        "signature_alg": record.signature_alg,
        "signer_public_key": record.signer_public_key,
    }



@app.route('/delete/<file_id>')
@login_required
def delete_file(file_id):
    record = VaultFile.query.filter_by(id=file_id, owner_uuid=current_user.uuid).first()
    if record:
        user_dir = os.path.join(app.config['UPLOAD_FOLDER'], current_user.uuid)
        path = os.path.join(user_dir, record.filename)
        if os.path.exists(path):
            os.remove(path)
        db.session.delete(record)
        db.session.commit()
        flash(f'Asset {record.filename} has been deleted.')
    return redirect(url_for('index'))


@app.route("/share_candidates")
@login_required
def share_candidates():
    users = User.query.with_entities(User.uuid, User.username).all()
    return jsonify([
        {"uuid": u.uuid, "username": u.username}
        for u in users if u.uuid != current_user.uuid
    ])


@app.route("/recipient_keys", methods=["POST"])
@login_required
def recipient_keys():
    uuids = request.json.get("recipients", [])
    users = User.query.filter(User.uuid.in_(uuids)).all()
    return jsonify({
        u.uuid: u.public_key
        for u in users
    })

@app.route("/file_key/<int:file_id>")
@login_required
def file_key(file_id):
    all_keys = request.args.get("all") == "true"
    
    if all_keys:
        keys = FileKey.query.filter_by(file_id=file_id).order_by(FileKey.id.desc()).all()
        latest_by_recipient = {}
        for key in keys:
            if key.recipient_uuid not in latest_by_recipient:
                latest_by_recipient[key.recipient_uuid] = key.wrapped_key
        return jsonify(latest_by_recipient)
    
    key = FileKey.query.filter_by(
        file_id=file_id,
        recipient_uuid=current_user.uuid
    ).order_by(FileKey.id.desc()).first()
    if not key:
        return {"error": "access denied"}, 403
    return {"wrapped_key": key.wrapped_key}

@app.route("/my_files")
@login_required
def my_files():
    # Files owned
    owned = VaultFile.query.filter_by(owner_uuid=current_user.uuid).all()

    # Files shared with user
    shared_ids = [
        fk.file_id for fk in
        FileKey.query.filter_by(recipient_uuid=current_user.uuid).all()
    ]
    shared = VaultFile.query.filter(VaultFile.id.in_(shared_ids)).all()

    files = {f.id for f in owned + shared}
    return jsonify(list(files))

@app.route("/rewrap_self/<int:file_id>", methods=["POST"])
@login_required
def rewrap_self(file_id):
    rows = FileKey.query.filter_by(
        file_id=file_id,
        recipient_uuid=current_user.uuid
    ).order_by(FileKey.id.desc()).all()

    if not rows:
        return {"error": "access denied"}, 403

    new_wrapped = request.json.get("wrapped_key")
    rows[0].wrapped_key = new_wrapped

    for duplicate in rows[1:]:
        db.session.delete(duplicate)

    db.session.commit()
    return {"status": "ok"}

@app.route("/rotate_key", methods=["POST"])
@login_required
def rotate_key():
    public_key = request.json.get("public_key")
    signing_public_key = request.json.get("signing_public_key")
    iv = request.json.get("iv")

    if not public_key or not iv:
        return {"error": "invalid payload"}, 400

    current_user.public_key = public_key
    if signing_public_key:
        current_user.signing_public_key = signing_public_key
    current_user.iv = iv
    db.session.commit()

    return {"status": "ok"}

@app.route('/edit_access/<int:file_id>', methods=['GET', 'POST'])
@login_required
def edit_access(file_id):
    file = VaultFile.query.get_or_404(file_id)

    # Only owner can edit access
    if file.owner_uuid != current_user.uuid:
        return "Forbidden", 403

    # All users except the owner
    all_users = User.query.filter(User.uuid != current_user.uuid).all()

    # Current access uuids
    current_keys = FileKey.query.filter_by(file_id=file.id).all()
    current_access_uuids = [fk.recipient_uuid for fk in current_keys]

    if request.method == 'POST':
        submitted_uuids = request.form.getlist('recipients')

        # Remove access for users no longer checked
        for fk in current_keys:
            if fk.recipient_uuid not in submitted_uuids:
                db.session.delete(fk)

        # Add access for newly checked users
        for uuid_ in submitted_uuids:
            if uuid_ not in current_access_uuids:
                db.session.add(FileKey(file_id=file.id, recipient_uuid=uuid_, wrapped_key="PLACEHOLDER"))

        db.session.commit()
        flash('Access updated successfully.')
        return redirect(url_for('index'))

    return render_template(
        'edit_access.html',
        file=file,
        all_users=all_users,
        current_access_uuids=current_access_uuids
    )

@app.route("/rewrap_keys/<int:file_id>", methods=["POST"])
@login_required
def rewrap_keys(file_id):
    file = VaultFile.query.get_or_404(file_id)

    if file.owner_uuid != current_user.uuid:
        return {"error": "forbidden"}, 403

    wrapped_keys = request.json.get("wrapped_keys")
    if not wrapped_keys:
        return {"error": "missing keys"}, 400

    # Owner key must always exist
    if file.owner_uuid not in wrapped_keys:
        return {"error": "owner key missing"}, 400

    # Remove only the keys that are in the submitted wrapped_keys
    # (so old recipients not in the new list are removed)
    FileKey.query.filter_by(file_id=file.id).delete()

    for recipient_uuid, wrapped_key in wrapped_keys.items():
        db.session.add(FileKey(
            file_id=file.id,
            recipient_uuid=recipient_uuid,
            wrapped_key=wrapped_key
        ))

    db.session.commit()
    return {"status": "ok"}

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        ensure_schema()
    app.run(debug=True)