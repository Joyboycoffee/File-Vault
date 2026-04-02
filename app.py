"""
File Vault - Secure File Encryption/Decryption Web App
A Flask-based web application for encrypting and decrypting files securely.
"""

from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import base64
import hashlib
import secrets
from datetime import datetime

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# Configuration
UPLOAD_FOLDER = 'uploads'
ENCRYPTED_FOLDER = 'encrypted'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'xls', 'xlsx', 'zip', 'mp4', 'mp3', 'json', 'xml', 'csv'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['ENCRYPTED_FOLDER'] = ENCRYPTED_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size

# Ensure directories exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(ENCRYPTED_FOLDER, exist_ok=True)

# In-memory user storage (in production, use a database)
users = {}
file_log = []

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_key_from_password(password, salt=None):
    """Generate encryption key from password using PBKDF2."""
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt

def hash_password(password):
    """Hash password for storage."""
    return hashlib.sha256(password.encode()).hexdigest()

def log_action(action, filename, user):
    """Log file operations."""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    file_log.append({
        'action': action,
        'filename': filename,
        'user': user,
        'timestamp': timestamp
    })

@app.route('/')
def index():
    """Home page - redirect to dashboard if logged in."""
    if 'user' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login page."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username in users and users[username]['password'] == hash_password(password):
            session['user'] = username
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration page."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if username in users:
            flash('Username already exists', 'error')
        elif password != confirm_password:
            flash('Passwords do not match', 'error')
        elif len(password) < 6:
            flash('Password must be at least 6 characters', 'error')
        else:
            users[username] = {
                'password': hash_password(password),
                'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    """Main dashboard for file operations."""
    if 'user' not in session:
        return redirect(url_for('login'))

    # Get user's files
    user_files = []
    for filename in os.listdir(app.config['ENCRYPTED_FOLDER']):
        if filename.startswith(f"{session['user']}_") or filename.startswith("shared_"):
            file_path = os.path.join(app.config['ENCRYPTED_FOLDER'], filename)
            file_info = {
                'name': filename,
                'size': os.path.getsize(file_path),
                'modified': datetime.fromtimestamp(os.path.getmtime(file_path)).strftime('%Y-%m-%d %H:%M:%S')
            }
            user_files.append(file_info)

    return render_template('dashboard.html', user=session['user'], files=user_files)

@app.route('/encrypt', methods=['POST'])
def encrypt_file():
    """Encrypt uploaded file."""
    if 'user' not in session:
        return redirect(url_for('login'))

    if 'file' not in request.files:
        flash('No file selected', 'error')
        return redirect(url_for('dashboard'))

    file = request.files['file']
    password = request.form.get('password', '')

    if file.filename == '':
        flash('No file selected', 'error')
        return redirect(url_for('dashboard'))

    if not password:
        flash('Encryption password is required', 'error')
        return redirect(url_for('dashboard'))

    if file and allowed_file(file.filename):
        try:
            filename = secure_filename(file.filename)
            file_content = file.read()

            # Generate key from password
            key, salt = generate_key_from_password(password)
            f = Fernet(key)

            # Encrypt content
            encrypted_content = f.encrypt(file_content)

            # Save encrypted file
            encrypted_filename = f"{session['user']}_{filename}.encrypted"
            encrypted_path = os.path.join(app.config['ENCRYPTED_FOLDER'], encrypted_filename)

            with open(encrypted_path, 'wb') as enc_file:
                enc_file.write(salt + encrypted_content)  # Prepend salt for decryption

            log_action('ENCRYPT', filename, session['user'])
            flash(f'File "{filename}" encrypted successfully!', 'success')

        except Exception as e:
            flash(f'Encryption failed: {str(e)}', 'error')
    else:
        flash('File type not allowed', 'error')

    return redirect(url_for('dashboard'))

@app.route('/decrypt', methods=['POST'])
def decrypt_file():
    """Decrypt selected file."""
    if 'user' not in session:
        return redirect(url_for('login'))

    filename = request.form.get('filename', '')
    password = request.form.get('password', '')

    if not filename or not password:
        flash('Please select a file and enter password', 'error')
        return redirect(url_for('dashboard'))

    try:
        encrypted_path = os.path.join(app.config['ENCRYPTED_FOLDER'], filename)

        if not os.path.exists(encrypted_path):
            flash('File not found', 'error')
            return redirect(url_for('dashboard'))

        with open(encrypted_path, 'rb') as enc_file:
            content = enc_file.read()

        # Extract salt (first 16 bytes) and encrypted content
        salt = content[:16]
        encrypted_content = content[16:]

        # Generate key from password and salt
        key, _ = generate_key_from_password(password, salt)
        f = Fernet(key)

        # Decrypt content
        decrypted_content = f.decrypt(encrypted_content)

        # Create download filename
        original_filename = filename.replace(f"{session['user']}_", "").replace('.encrypted', '')
        download_path = os.path.join(app.config['UPLOAD_FOLDER'], original_filename)

        with open(download_path, 'wb') as dec_file:
            dec_file.write(decrypted_content)

        log_action('DECRYPT', filename, session['user'])

        return send_file(download_path, as_attachment=True, download_name=original_filename)

    except Exception as e:
        flash(f'Decryption failed: Invalid password or corrupted file', 'error')
        return redirect(url_for('dashboard'))

@app.route('/delete', methods=['POST'])
def delete_file():
    """Delete encrypted file."""
    if 'user' not in session:
        return redirect(url_for('login'))

    filename = request.form.get('filename', '')

    if not filename:
        flash('No file selected', 'error')
        return redirect(url_for('dashboard'))

    try:
        file_path = os.path.join(app.config['ENCRYPTED_FOLDER'], filename)
        if os.path.exists(file_path) and filename.startswith(session['user']):
            os.remove(file_path)
            log_action('DELETE', filename, session['user'])
            flash('File deleted successfully', 'success')
        else:
            flash('File not found or access denied', 'error')
    except Exception as e:
        flash(f'Delete failed: {str(e)}', 'error')

    return redirect(url_for('dashboard'))

@app.route('/logs')
def logs():
    """View operation logs."""
    if 'user' not in session:
        return redirect(url_for('login'))

    user_logs = [log for log in file_log if log['user'] == session['user']]
    return render_template('logs.html', user=session['user'], logs=user_logs)

@app.route('/logout')
def logout():
    """Logout user."""
    session.pop('user', None)
    flash('Logged out successfully', 'success')
    return redirect(url_for('index'))

@app.route('/about')
def about():
    """About page."""
    return render_template('about.html')

@app.route('/contact')
def contact():
    """Contact page."""
    return render_template('contact.html')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
