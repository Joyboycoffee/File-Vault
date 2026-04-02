# FileVault - Secure File Encryption Web App

A modern, responsive web application for encrypting and decrypting files using military-grade AES-256 encryption with PBKDF2 key derivation.

![FileVault Screenshot](https://via.placeholder.com/800x400/6366f1/ffffff?text=FileVault)

## Features

- **AES-256 Encryption** - Industry-standard encryption algorithm
- **PBKDF2 Key Derivation** - 100,000 iterations for secure password-based keys
- **User Authentication** - Secure login with password hashing (SHA-256)
- **Drag & Drop Upload** - Easy file upload with visual feedback
- **Activity Logging** - Track all encryption/decryption operations
- **Responsive Design** - Works on desktop, tablet, and mobile devices
- **Modern UI** - Dark theme with smooth animations and gradients

## Supported File Types

- Documents: PDF, DOC, DOCX, TXT, JSON, XML, CSV
- Images: PNG, JPG, JPEG, GIF
- Archives: ZIP
- Media: MP4, MP3
- And more...

## Installation

1. **Navigate to the project directory:**
   ```bash
   cd Documents/python-projects/file-vault
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application:**
   ```bash
   python run.py
   ```

4. **Open your browser:**
   Navigate to `http://localhost:5000`

## Usage

### Registration
1. Visit the home page and click "Get Started"
2. Create an account with username and password
3. Login to access your secure vault

### Encrypting Files
1. Go to the Dashboard
2. Drag and drop a file or click "Browse Files"
3. Set a strong encryption password
4. Click "Encrypt File"
5. Your encrypted file is securely stored

### Decrypting Files
1. Go to the Dashboard or click "Decrypt File"
2. Select the encrypted file from the dropdown
3. Enter the encryption password
4. Click "Decrypt & Download"
5. The original file is downloaded to your device

### Viewing Activity Logs
1. Click on "Activity Log" in the sidebar
2. View a history of all your encryption/decryption activities

## Security Notes

- **Important**: Remember your encryption passwords! They are not stored and cannot be recovered.
- Files are encrypted using AES-256 with a unique salt for each file
- Passwords are hashed using SHA-256 for secure storage
- PBKDF2 key derivation uses 100,000 iterations to prevent brute-force attacks
- Session management keeps your account secure

## Project Structure

```
file-vault/
├── app.py                 # Main Flask application
├── run.py                # Launcher script
├── requirements.txt      # Python dependencies
├── README.md            # This file
├── uploads/             # Temporary decrypted files
├── encrypted/           # Encrypted file storage
├── templates/           # HTML templates
│   ├── base.html
│   ├── index.html
│   ├── login.html
│   ├── register.html
│   ├── dashboard.html
│   ├── logs.html
│   ├── about.html
│   └── contact.html
└── static/              # Static assets
    ├── css/
    │   └── style.css    # Main stylesheet
    └── js/
        └── main.js      # Main JavaScript file
```

## Technologies Used

- **Backend**: Python, Flask
- **Frontend**: HTML5, CSS3, JavaScript
- **Encryption**: cryptography library (Fernet, PBKDF2)
- **Icons**: Font Awesome
- **Fonts**: Inter, JetBrains Mono (Google Fonts)

## Browser Support

- Chrome/Edge (latest)
- Firefox (latest)
- Safari (latest)
- Mobile browsers (iOS Safari, Chrome Mobile)

## Development

To run in development mode with auto-reload:

```bash
export FLASK_APP=app.py
export FLASK_ENV=development
flask run
```

On Windows:
```cmd
set FLASK_APP=app.py
set FLASK_ENV=development
flask run
```

## License

This project is for educational purposes.

## Author

Built with Claude Code
