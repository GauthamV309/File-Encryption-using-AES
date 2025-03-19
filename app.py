from flask import Flask, request, render_template, redirect, url_for, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['UPLOAD_FOLDER'] = 'uploads'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

class FileRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(150), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def encrypt_file(file_data, password):
    key = password.encode('utf-8').ljust(32)[:32]
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(file_data) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encrypted_data

def decrypt_file(file_data, password):
    key = password.encode('utf-8').ljust(32)[:32]
    iv = file_data[:16]
    encrypted_data = file_data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
    return decrypted_data

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password, method='scrypt')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    user_files = FileRecord.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', files=user_files)

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    file = request.files['file']
    if file:
        filename = secure_filename(file.filename)
        file_data = file.read()
        password = current_user.username  # Using username as the encryption password
        encrypted_data = encrypt_file(file_data, password)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        with open(filepath, 'wb') as f:
            f.write(encrypted_data)
        new_file_record = FileRecord(filename=filename, user_id=current_user.id)
        db.session.add(new_file_record)
        db.session.commit()
        flash('File uploaded and encrypted successfully', 'success')
    return redirect(url_for('dashboard'))

@app.route('/download/<int:file_id>', methods=['GET', 'POST'])
@login_required
def download_file(file_id):
    file_record = FileRecord.query.get_or_404(file_id)
    if file_record.user_id != current_user.id:
        flash('You do not have permission to access this file', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        password = request.form['password']
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_record.filename)
        with open(file_path, 'rb') as f:
            file_data = f.read()
        try:
            decrypted_data = decrypt_file(file_data, password)
            output_filename = 'decrypted_' + file_record.filename
            output_filepath = os.path.join(app.config['UPLOAD_FOLDER'], output_filename)
            with open(output_filepath, 'wb') as f:
                f.write(decrypted_data)
            return send_file(output_filepath, as_attachment=True)
        except Exception as e:
            flash('Incorrect password or decryption error', 'danger')
    return render_template('download.html', file_id=file_id)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
