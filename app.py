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
import string
from datetime import datetime
import re

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
password_reset_tokens = {}  # Store reset tokens temporarily

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

def is_valid_email(email):
    """Validate email format."""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def generate_reset_token():
    """Generate a secure reset token."""
    return secrets.token_urlsafe(32)

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
        email = request.form['email']
        full_name = request.form['full_name']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if username in users:
            flash('Username already exists', 'error')
        elif not is_valid_email(email):
            flash('Invalid email format', 'error')
        elif any(user['email'] == email for user in users.values()):
            flash('Email already registered', 'error')
        elif password != confirm_password:
            flash('Passwords do not match', 'error')
        elif len(password) < 6:
            flash('Password must be at least 6 characters', 'error')
        elif len(full_name.strip()) < 2:
            flash('Please enter your full name', 'error')
        else:
            users[username] = {
                'password': hash_password(password),
                'email': email,
                'full_name': full_name,
                'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'profile_image': None
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

    user_info = users.get(session['user'], {})
    return render_template('dashboard.html', user=session['user'], full_name=user_info.get('full_name', session['user']), files=user_files)

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    """User profile management page."""
    if 'user' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'update_profile':
            full_name = request.form.get('full_name')
            email = request.form.get('email')

            if len(full_name.strip()) < 2:
                flash('Please enter a valid full name', 'error')
            elif not is_valid_email(email):
                flash('Invalid email format', 'error')
            elif email != users[session['user']]['email'] and any(user['email'] == email for user in users.values()):
                flash('Email is already in use', 'error')
            else:
                users[session['user']]['full_name'] = full_name
                users[session['user']]['email'] = email
                flash('Profile updated successfully!', 'success')
                return redirect(url_for('profile'))

        elif action == 'change_password':
            current_password = request.form.get('current_password')
            new_password = request.form.get('new_password')
            confirm_password = request.form.get('confirm_password')

            if hash_password(current_password) != users[session['user']]['password']:
                flash('Current password is incorrect', 'error')
            elif new_password != confirm_password:
                flash('New passwords do not match', 'error')
            elif len(new_password) < 6:
                flash('Password must be at least 6 characters', 'error')
            else:
                users[session['user']]['password'] = hash_password(new_password)
                flash('Password changed successfully!', 'success')
                return redirect(url_for('profile'))

    user_info = users.get(session['user'], {})
    return render_template('profile.html', user=session['user'], user_info=user_info)

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    """Forgot password page - send reset code."""
    if request.method == 'POST':
        email = request.form.get('email')

        # Find user by email
        user = None
        for username, user_data in users.items():
            if user_data['email'] == email:
                user = username
                break

        if user:
            reset_token = generate_reset_token()
            password_reset_tokens[reset_token] = {
                'username': user,
                'created_at': datetime.now()
            }
            flash(f'Login the account with username "{user}" and use the link provided in your browser URL bar', 'info')
            return redirect(url_for('reset_password', token=reset_token))
        else:
            flash('Email not found in our system', 'error')

    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """Reset password with token."""
    if token not in password_reset_tokens:
        flash('Invalid or expired reset link', 'error')
        return redirect(url_for('forgot_password'))

    reset_data = password_reset_tokens[token]
    username = reset_data['username']

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if new_password != confirm_password:
            flash('Passwords do not match', 'error')
        elif len(new_password) < 6:
            flash('Password must be at least 6 characters', 'error')
        else:
            users[username]['password'] = hash_password(new_password)
            del password_reset_tokens[token]  # Remove used token
            flash('Password reset successfully! Please login with your new password.', 'success')
            return redirect(url_for('login'))

    return render_template('reset_password.html', username=username, token=token)

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

#nice