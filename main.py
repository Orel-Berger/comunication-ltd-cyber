"""
Comunication_LTD - Interactive Launcher
"""
import os
import sys

# Ensure UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

def show_menu():
    print("=" * 70)
    print("      Comunication_LTD - תפריט ראשי לפרויקט סיום בסייבר")
    print("=" * 70)
    print("  1. הפעלת המערכת המאובטחת (חלק א' - Secure App) [Port 5000 / 5002]")
    print("  2. הפעלת המערכת הפגיעה (חלק ב' - Vulnerable App) [Port 5001]")
    print("  3. הרצת כל 15 בדיקות האבטחה האוטומטיות (Audit Tests)")
    print("  4. אתחול מסדי הנתונים מחדש (Reset DBs)")
    print("  5. יציאה")
    print("=" * 70)

def main():
    if len(sys.argv) > 1:
        choice = sys.argv[1]
    else:
        show_menu()
        choice = input("בחר אפשרות (1-5): ").strip()

    if choice == "1":
        from secure_version.app import app
        from secure_version.database.init_db import init_database
        init_database()
        print("\n[*] המערכת המאובטחת רצה בכתובת: http://127.0.0.1:5000\n")
        app.run(host="127.0.0.1", port=5000, debug=True)
    elif choice == "2":
        from vulnerable_version.app import app
        from vulnerable_version.database.init_db import init_database
        init_database()
        print("\n[*] המערכת הפגיעה רצה בכתובת: http://127.0.0.1:5001\n")
        app.run(host="127.0.0.1", port=5001, debug=True)
    elif choice == "3":
        from tests.run_all_tests import run_cyber_project_audit
        run_cyber_project_audit()
    elif choice == "4":
        from secure_version.database.init_db import init_database as init_sec
        from vulnerable_version.database.init_db import init_database as init_vuln
        init_vuln()
        init_sec()
        print("[+] שני מסדי הנתונים אותחלו בהצלחה!")
    else:
        print("יציאה.")

if __name__ == "__main__":
    main()
