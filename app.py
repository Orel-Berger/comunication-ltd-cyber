"""
Comunication_LTD - Main Application Entrypoint
Cyber Security Final Project - Part A (Secure Development Principles) & System Core
"""
import os
import sys

# Ensure UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

# Ensure project root is in sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from secure_version.app import app
from secure_version.database.init_db import init_database

if __name__ == "__main__":
    print("=" * 70)
    print("   Comunication_LTD - מערכת מידע מאובטחת (פרויקט סיום - חלק א')")
    print("=" * 70)
    print("[*] מאתחל את מסד הנתונים הרלציוני...")
    init_database()
    print("[*] שרת המערכת מופעל כעת:")
    print("    קישור לכניסה בדפדפן: http://127.0.0.1:5000")
    print("=" * 70)
    app.run(host="127.0.0.1", port=5000, debug=True)
