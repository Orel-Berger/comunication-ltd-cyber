import os
import sys
import sqlite3
import html
import re
from datetime import datetime, timezone, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, session

current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from utils.auth_helpers import (
    hash_password,
    verify_password,
    generate_salt,
    generate_sha1_reset_token,
    validate_password_complexity,
    load_password_policy
)
from utils.mailer import send_password_reset_email, get_all_emails, clear_mailbox

app = Flask(__name__)
app.secret_key = "secure_production_secret_key_comunication_ltd_2026"
DB_PATH = os.path.join(current_dir, "database", "comunication_ltd.db")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

@app.after_request
def apply_security_headers(response):
    """Apply defensive HTTP headers including Content-Security-Policy."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' https://cdn.jsdelivr.net; "
        "style-src 'self' https://cdn.jsdelivr.net; "
        "font-src 'self' https://cdn.jsdelivr.net;"
    )
    return response

@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

# =========================================================================
# 1. REGISTER SCREEN (Section 1) - SECURE (Special Char Encoding + Parameters)
# =========================================================================
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        raw_username = request.form.get("username", "").strip()
        raw_email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not raw_username or not raw_email or not password:
            flash("נא למלא את כל השדות.", "danger")
            return render_template("register.html")

        # DEFENSE PART B (סעיף 3): Input validation and encoding of special characters
        # Validate that username contains only safe alphanumeric/underscore characters
        if not re.match(r"^[a-zA-Z0-9_\u0590-\u05fe]{3,30}$", raw_username):
            flash("שם המשתמש חייב להכיל 3-30 תווים (אותיות, מספרים או קו תחתון בלבד). תווים מיוחדים נדחו.", "warning")
            return render_template("register.html")

        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", raw_email):
            flash("כתובת דוא״ל אינה תקינה.", "warning")
            return render_template("register.html")

        # HTML Entity Encoding for defense in depth
        clean_username = html.escape(raw_username)
        clean_email = html.escape(raw_email)

        if password != confirm_password:
            flash("הסיסמאות אינן תואמות.", "danger")
            return render_template("register.html")

        # Validate password complexity from config
        valid, msg = validate_password_complexity(password)
        if not valid:
            flash(msg, "warning")
            return render_template("register.html")

        conn = get_db()
        cursor = conn.cursor()

        # DEFENSE PART B (סעיף 4): Parameterized Query preventing SQLi
        cursor.execute(
            "SELECT id FROM users WHERE username = ? OR email = ?",
            (clean_username, clean_email)
        )
        if cursor.fetchone():
            flash("שם המשתמש או כתובת הדוא״ל כבר קיימים במערכת.", "danger")
            conn.close()
            return render_template("register.html")

        # Cryptographic storage: HMAC + Salt
        salt = generate_salt()
        pwd_hash = hash_password(password, salt)

        # DEFENSE PART B (סעיף 4): Parameterized INSERT
        cursor.execute(
            "INSERT INTO users (username, email, salt, password_hash) VALUES (?, ?, ?, ?)",
            (clean_username, clean_email, salt, pwd_hash)
        )
        new_user_id = cursor.lastrowid

        # Save initial password history for history_count checking
        cursor.execute(
            "INSERT INTO password_history (user_id, salt, password_hash) VALUES (?, ?, ?)",
            (new_user_id, salt, pwd_hash)
        )
        conn.commit()
        conn.close()

        flash("ההרשמה הושלמה בהצלחה! הסיסמה אובטחה ב-HMAC+Salt. כעת ניתן להתחבר.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")

# =========================================================================
# 3. LOGIN SCREEN (Section 3) - SECURE (Parameterized Queries + Brute-force Lock)
# =========================================================================
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        raw_username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # Clean/sanitize username
        username = html.escape(raw_username)

        conn = get_db()
        cursor = conn.cursor()

        # DEFENSE PART B (סעיף 4): Parameterized Query preventing Login SQLi Bypass!
        # Payloads like "admin_cyber' --" are treated purely as a literal string
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()

        if not user:
            conn.close()
            flash("שם משתמש או סיסמה שגויים.", "danger")
            return render_template("login.html")

        # Check account lockout from policy
        policy = load_password_policy()
        max_attempts = policy.get("max_login_attempts", 3)

        if user["failed_attempts"] >= max_attempts and user["locked_until"]:
            try:
                locked_time = datetime.fromisoformat(user["locked_until"])
                now_utc = datetime.now(timezone.utc)
                if locked_time.tzinfo is None:
                    locked_time = locked_time.replace(tzinfo=timezone.utc)
                if now_utc < locked_time:
                    remaining = int((locked_time - now_utc).total_seconds() / 60)
                    conn.close()
                    flash(f"חשבון זה נעול זמנית עקב {max_attempts} ניסיונות כושלים. נסה שוב בעוד {remaining + 1} דקות.", "danger")
                    return render_template("login.html")
            except Exception:
                pass

        # Verify password using HMAC + Salt
        if verify_password(password, user["salt"], user["password_hash"]):
            # Reset failed attempts
            cursor.execute("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?", (user["id"],))
            conn.commit()
            conn.close()

            session["user_id"] = user["id"]
            session["username"] = user["username"]
            flash(f"התחברת בהצלחה למערכת Comunication_LTD, {user['username']}!", "success")
            return redirect(url_for("dashboard"))
        else:
            # Increment failed attempts securely
            new_attempts = user["failed_attempts"] + 1
            if new_attempts >= max_attempts:
                lockout_duration = policy.get("lockout_duration_minutes", 15)
                lock_time = (datetime.now(timezone.utc) + timedelta(minutes=lockout_duration)).isoformat()
                cursor.execute(
                    "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                    (new_attempts, lock_time, user["id"])
                )
                conn.commit()
                conn.close()
                flash(f"סיסמה שגויה! החשבון ננעל לאחר {max_attempts} ניסיונות כושלים (לפי הגדרת הקונפיגורציה).", "danger")
            else:
                cursor.execute(
                    "UPDATE users SET failed_attempts = ? WHERE id = ?",
                    (new_attempts, user["id"])
                )
                conn.commit()
                conn.close()
                flash(f"סיסמה שגויה. נותרו לך {max_attempts - new_attempts} ניסיונות לפני נעילת החשבון.", "warning")

            return render_template("login.html")

    return render_template("login.html")

# =========================================================================
# 2. CHANGE PASSWORD SCREEN (Section 2) - SECURE
# =========================================================================
@app.route("/change-password", methods=["GET", "POST"])
def change_password():
    if "user_id" not in session:
        flash("יש להתחבר כדי לשנות סיסמה.", "warning")
        return redirect(url_for("login"))

    if request.method == "POST":
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not current_password or not new_password:
            flash("נא למלא את כל השדות.", "danger")
            return render_template("change_password.html")

        if new_password != confirm_password:
            flash("אימות הסיסמה החדשה אינו תואם.", "danger")
            return render_template("change_password.html")

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],))
        user = cursor.fetchone()

        if not user or not verify_password(current_password, user["salt"], user["password_hash"]):
            conn.close()
            flash("הסיסמה הנוכחית שגויה.", "danger")
            return render_template("change_password.html")

        # Fetch password history to enforce history_count from config
        cursor.execute(
            "SELECT salt, password_hash FROM password_history WHERE user_id = ? ORDER BY id DESC",
            (user["id"],)
        )
        history_rows = cursor.fetchall()
        history_tuples = [(row["salt"], row["password_hash"]) for row in history_rows]

        # Validate against policy and history
        valid, msg = validate_password_complexity(new_password, history_tuples)
        if not valid:
            conn.close()
            flash(msg, "warning")
            return render_template("change_password.html")

        # Generate new salt and compute new HMAC
        new_salt = generate_salt()
        new_pwd_hash = hash_password(new_password, new_salt)

        cursor.execute(
            "UPDATE users SET salt = ?, password_hash = ? WHERE id = ?",
            (new_salt, new_pwd_hash, user["id"])
        )
        cursor.execute(
            "INSERT INTO password_history (user_id, salt, password_hash) VALUES (?, ?, ?)",
            (user["id"], new_salt, new_pwd_hash)
        )
        conn.commit()
        conn.close()

        flash("הסיסמה שונתה בהצלחה בהתאם לכללי המדיניות וההיסטוריה!", "success")
        return redirect(url_for("dashboard"))

    return render_template("change_password.html")

# =========================================================================
# 5. FORGOT PASSWORD (Section 5) - SHA-1 Token - SECURE
# =========================================================================
@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        raw_identity = request.form.get("identity", "").strip()
        if not raw_identity:
            flash("נא להזין שם משתמש או כתובת דוא״ל.", "warning")
            return render_template("forgot_password.html", step="request_token")

        clean_identity = html.escape(raw_identity)

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM users WHERE username = ? OR email = ?",
            (clean_identity, clean_identity)
        )
        user = cursor.fetchone()

        if not user:
            conn.close()
            # Generic message to prevent user enumeration
            flash("אם המשתמש קיים במערכת, נשלח אליו ערך אימות (SHA-1) לתיבת המייל.", "info")
            return render_template("forgot_password.html", step="request_token")

        # Generate random SHA-1 token as explicitly requested
        token_sha1 = generate_sha1_reset_token()
        expires_at = (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat()

        cursor.execute(
            "INSERT INTO password_resets (user_id, token_sha1, expires_at) VALUES (?, ?, ?)",
            (user["id"], token_sha1, expires_at)
        )
        conn.commit()
        conn.close()

        # Send simulated email
        send_password_reset_email(user["email"], user["username"], token_sha1, request.host_url.rstrip("/"))

        return render_template(
            "forgot_password.html",
            step="enter_token",
            simulated_token=token_sha1
        )

    return render_template("forgot_password.html", step="request_token")

@app.route("/verify-reset-token", methods=["POST"])
def verify_reset_token():
    raw_token = request.form.get("token", "").strip()
    if not raw_token:
        flash("נא להזין ערך אימות (SHA-1 Token).", "danger")
        return redirect(url_for("forgot_password"))

    clean_token = html.escape(raw_token)

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM password_resets WHERE token_sha1 = ? AND used = 0",
        (clean_token,)
    )
    reset_record = cursor.fetchone()
    conn.close()

    if not reset_record:
        flash("טוקן אימות שגוי או שכבר נוצל.", "danger")
        return redirect(url_for("forgot_password"))

    # Check expiration
    expires_at = datetime.fromisoformat(reset_record["expires_at"])
    now_utc = datetime.now(timezone.utc)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if now_utc > expires_at:
        flash("פג תוקף טוקן האימות. בקש טוקן חדש.", "danger")
        return redirect(url_for("forgot_password"))

    return redirect(url_for("reset_password", token=clean_token))

@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    raw_token = request.args.get("token") or request.form.get("token")
    if not raw_token:
        flash("חסר טוקן אימות.", "danger")
        return redirect(url_for("forgot_password"))

    clean_token = html.escape(raw_token.strip())

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM password_resets WHERE token_sha1 = ? AND used = 0",
        (clean_token,)
    )
    reset_record = cursor.fetchone()

    if not reset_record:
        conn.close()
        flash("טוקן אימות אינו תקף.", "danger")
        return redirect(url_for("forgot_password"))

    user_id = reset_record["user_id"]

    if request.method == "POST":
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not new_password or new_password != confirm_password:
            flash("הסיסמאות אינן תואמות או ריקות.", "danger")
            return render_template("reset_password.html", token=clean_token)

        # Check history
        cursor.execute(
            "SELECT salt, password_hash FROM password_history WHERE user_id = ? ORDER BY id DESC",
            (user_id,)
        )
        history_rows = cursor.fetchall()
        history_tuples = [(row["salt"], row["password_hash"]) for row in history_rows]

        valid, msg = validate_password_complexity(new_password, history_tuples)
        if not valid:
            flash(msg, "warning")
            return render_template("reset_password.html", token=clean_token)

        # Update password with HMAC+Salt
        new_salt = generate_salt()
        new_pwd_hash = hash_password(new_password, new_salt)

        cursor.execute(
            "UPDATE users SET salt = ?, password_hash = ?, failed_attempts = 0, locked_until = NULL WHERE id = ?",
            (new_salt, new_pwd_hash, user_id)
        )
        cursor.execute(
            "INSERT INTO password_history (user_id, salt, password_hash) VALUES (?, ?, ?)",
            (user_id, new_salt, new_pwd_hash)
        )
        cursor.execute(
            "UPDATE password_resets SET used = 1 WHERE id = ?",
            (reset_record["id"],)
        )
        conn.commit()
        conn.close()

        flash("הסיסמה אופסה בהצלחה! כעת תוכל להתחבר עם הסיסמה החדשה.", "success")
        return redirect(url_for("login"))

    conn.close()
    return render_template("reset_password.html", token=clean_token)

# =========================================================================
# 4. SYSTEM SCREEN (Section 4) - SECURE (Anti-XSS + Parameterized SQL)
# =========================================================================
@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))

    raw_search = request.args.get("q", "").strip()
    search_query = html.escape(raw_search)
    new_customer_name = session.pop("new_customer_name", None)

    conn = get_db()
    cursor = conn.cursor()

    # Load sectors & packages securely
    cursor.execute("SELECT id, name, description FROM sectors")
    sectors = cursor.fetchall()

    cursor.execute("SELECT id, name, speed_mbps, price FROM packages")
    packages = cursor.fetchall()

    # DEFENSE PART B (סעיף 4): Parameterized Search Query preventing SQLi
    if search_query:
        param = f"%{search_query}%"
        cursor.execute(
            "SELECT c.id, c.full_name, c.identity_number, c.email, c.phone, "
            "s.name as sector, p.name as package, c.notes "
            "FROM customers c "
            "LEFT JOIN sectors s ON c.sector_id = s.id "
            "LEFT JOIN packages p ON c.package_id = p.id "
            "WHERE c.full_name LIKE ? OR c.identity_number LIKE ? "
            "ORDER BY c.id DESC",
            (param, param)
        )
    else:
        cursor.execute(
            "SELECT c.id, c.full_name, c.identity_number, c.email, c.phone, "
            "s.name as sector, p.name as package, c.notes "
            "FROM customers c "
            "LEFT JOIN sectors s ON c.sector_id = s.id "
            "LEFT JOIN packages p ON c.package_id = p.id "
            "ORDER BY c.id DESC"
        )
    customers = cursor.fetchall()
    conn.close()

    return render_template(
        "dashboard.html",
        sectors=sectors,
        packages=packages,
        customers=customers,
        search_query=search_query,
        new_customer_name=new_customer_name
    )

@app.route("/add-customer", methods=["POST"])
def add_customer():
    if "user_id" not in session:
        return redirect(url_for("login"))

    raw_name = request.form.get("full_name", "").strip()
    raw_id = request.form.get("identity_number", "").strip()
    raw_email = request.form.get("email", "").strip()
    raw_phone = request.form.get("phone", "").strip()
    sector_id = request.form.get("sector_id", "")
    package_id = request.form.get("package_id", "")
    raw_notes = request.form.get("notes", "").strip()

    # DEFENSE PART B (סעיף 1 + 4):
    # 1. HTML Escaping to prevent Stored XSS
    clean_name = html.escape(raw_name)
    clean_id = html.escape(raw_id)
    clean_email = html.escape(raw_email)
    clean_phone = html.escape(raw_phone)
    clean_notes = html.escape(raw_notes)

    # 2. Strict ID/Phone validation
    if not re.match(r"^\d{8,10}$", clean_id):
        flash("תעודת זהות / ח.פ חייבת להכיל בין 8 ל-10 ספרות.", "warning")
        return redirect(url_for("dashboard"))

    try:
        sec_id = int(sector_id)
        pkg_id = int(package_id)
    except ValueError:
        flash("שגיאה בבחירת סקטור או חבילת גלישה.", "danger")
        return redirect(url_for("dashboard"))

    # DEFENSE PART B (סעיף 4): Parameterized Query preventing SQLi
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO customers (full_name, identity_number, email, phone, sector_id, package_id, notes) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (clean_name, clean_id, clean_email, clean_phone, sec_id, pkg_id, clean_notes)
        )
        conn.commit()
    except Exception as e:
        conn.close()
        flash(f"שגיאה בהכנסת לקוח: {str(e)}", "danger")
        return redirect(url_for("dashboard"))

    conn.close()

    # Safely saved - template will render with auto-escaping, preventing XSS
    session["new_customer_name"] = clean_name
    return redirect(url_for("dashboard"))

@app.route("/mailbox")
def mailbox():
    emails = get_all_emails()
    return render_template("mailbox.html", emails=emails)

@app.route("/clear-emails")
def clear_emails():
    clear_mailbox()
    flash("תיבת הדואר רוקנה בהצלחה.", "info")
    return redirect(url_for("mailbox"))

@app.route("/logout")
def logout():
    session.clear()
    flash("התנתקת מהמערכת בהצלחה.", "info")
    return redirect(url_for("login"))

if __name__ == "__main__":
    print("[*] Starting Secure Comunication_LTD Server on port 5002...")
    app.run(host="127.0.0.1", port=5002, debug=True)
