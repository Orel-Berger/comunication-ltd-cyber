import os
import sqlite3
import sys

# Ensure parent directory is in python path to import utils
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from utils.auth_helpers import hash_password, generate_salt

DB_FILE = os.path.join(current_dir, "comunication_ltd.db")
SCHEMA_FILE = os.path.join(current_dir, "schema.sql")

def init_database():
    print(f"[*] Initializing secure database at: {DB_FILE}")
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    # Read schema
    with open(SCHEMA_FILE, "r", encoding="utf-8") as f:
        schema_script = f.read()
    cursor.executescript(schema_script)

    # Seed Sectors
    sectors = [
        ("פרטי (Private)", "חבילות גלישה ביתיות למשפחות וצרכנים פרטיים"),
        ("עסקי (Business)", "פתרונות אינטרנט מתקדמים לעסקים קטנים ובינוניים"),
        ("אקדמי (Academic)", "מוסדות מחקר, מכללות ואוניברסיטאות"),
        ("ביטחוני (Security & Defense)", "תשתיות תקשורת מוצפנות ומאובטחות"),
        ("ציבורי (Public Sector)", "משרדי ממשלה, בתי חולים ורשויות מקומיות")
    ]
    cursor.executemany("INSERT INTO sectors (name, description) VALUES (?, ?)", sectors)

    # Seed Browsing Packages
    packages = [
        ("בסיסי 100Mb", 100, 49.90, "אינטרנט בסיסי לגלישה קלה ודוא״ל"),
        ("מתקדם 500Mb", 500, 79.90, "אינטרנט מהיר לצפייה ב-4K וגיימינג"),
        ("סיבים אופטיים 1Gb", 1000, 99.90, "סיבים סימטריים במהירות שיא והשהייה נמוכה"),
        ("עסקי פרימיום 2.5Gb", 2500, 199.90, "חבילה עסקית עם IP קבוע ושירות 24/7"),
        ("ביטחוני מאובטח 5Gb", 5000, 399.90, "קו ייעודי מוצפן עם SLA של 99.999%")
    ]
    cursor.executemany("INSERT INTO packages (name, speed_mbps, price, description) VALUES (?, ?, ?, ?)", packages)

    # Seed Default Admin User with HMAC + Salt
    # Password: "Cyber@2026Admin!"
    admin_salt = generate_salt()
    admin_pwd_hash = hash_password("Cyber@2026Admin!", admin_salt)
    cursor.execute(
        "INSERT INTO users (username, email, salt, password_hash) VALUES (?, ?, ?, ?)",
        ("admin_cyber", "admin@comunication-ltd.co.il", admin_salt, admin_pwd_hash)
    )
    admin_id = cursor.lastrowid
    cursor.execute(
        "INSERT INTO password_history (user_id, salt, password_hash) VALUES (?, ?, ?)",
        (admin_id, admin_salt, admin_pwd_hash)
    )

    # Seed a standard user
    # Password: "P@ssw0rdSecure!"
    user_salt = generate_salt()
    user_pwd_hash = hash_password("P@ssw0rdSecure!", user_salt)
    cursor.execute(
        "INSERT INTO users (username, email, salt, password_hash) VALUES (?, ?, ?, ?)",
        ("user_israel", "israel@comunication-ltd.co.il", user_salt, user_pwd_hash)
    )
    user_id = cursor.lastrowid
    cursor.execute(
        "INSERT INTO password_history (user_id, salt, password_hash) VALUES (?, ?, ?)",
        (user_id, user_salt, user_pwd_hash)
    )

    # Seed initial Customers for Comunication_LTD
    customers = [
        ("ישראל ישראלי", "012345678", "israel.israeli@gmail.com", "050-1234567", 1, 3, "לקוח ביתי - מחובר לסיבים אופטיים"),
        ("חברת אלפא טק בע״מ", "514567890", "it@alphatech.co.il", "03-9876543", 2, 4, "עסק בהייטק - נדרש IP קבוע ותמיכת VIP"),
        ("המכללה האקדמית לטכנולוגיה", "580123456", "sysadmin@college.ac.il", "08-6543210", 3, 2, "קמפוס לימודים מרכזי"),
        ("מערך הביטחון האזורי", "901234567", "sec@defense-network.gov.il", "02-5551234", 4, 5, "קו נתונים מאובטח עם הצפנה כפולה")
    ]
    cursor.executemany(
        "INSERT INTO customers (full_name, identity_number, email, phone, sector_id, package_id, notes) VALUES (?, ?, ?, ?, ?, ?, ?)",
        customers
    )

    conn.commit()
    conn.close()
    print("[+] Secure database initialized and seeded successfully!")

if __name__ == "__main__":
    init_database()
