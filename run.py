#!/usr/bin/env python3
"""
FileVault Launcher Script
Starts the Flask development server.
"""

import os
import sys
import webbrowser
from threading import Timer

def open_browser():
    """Open the default browser after a short delay."""
    webbrowser.open('http://localhost:5000')

def main():
    """Main entry point."""
    print("=" * 60)
    print(" " * 15 + "FILEVAULT - Secure File Encryption")
    print("=" * 60)
    print()
    print("Starting FileVault server...")
    print()
    print("Features:")
    print("  - AES-256 Encryption with PBKDF2 Key Derivation")
    print("  - User Authentication with Password Hashing")
    print("  - Responsive Modern UI with Animations")
    print("  - Activity Logging")
    print()
    print("Opening http://localhost:5000 in your browser...")
    print("Press Ctrl+C to stop the server")
    print("=" * 60)
    print()

    # Open browser after 1.5 seconds
    Timer(1.5, open_browser).start()

    # Import and run the Flask app
    from app import app
    app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False)

if __name__ == '__main__':
    main()
