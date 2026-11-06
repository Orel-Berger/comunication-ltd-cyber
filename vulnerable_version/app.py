import os
import sys
import sqlite3
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
app.secret_key = "vulnerable_secret_session_key_comunication_ltd"
DB_PATH = os.path.join(current_dir, "database", "comunication_ltd.db")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

# ==========================================
# 1. REGISTER SCREEN (Section 1) - VULNERABLE
# ==========================================
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not username or not email or not password:
            flash("נא למלא את כל השדות.", "danger")
            return render_template("register.html")

        if password != confirm_password:
            flash("הסיסמאות אינן תואמות.", "danger")
            return render_template("register.html")

        # Validate complexity using configuration file
        valid, msg = validate_password_complexity(password)
        if not valid:
            flash(msg, "warning")
            return render_template("register.html")

        conn = get_db()
        cursor = conn.cursor()

        # VULNERABLE SQL QUERY (SQLi in Registration lookup)
        # Using direct string concatenation instead of parameterized queries
        try:
            check_sql = f"SELECT * FROM users WHERE username = '{username}' OR email = '{email}'"
            cursor.execute(check_sql)
            existing_user = cursor.fetchone()
        except sqlite3.OperationalError as e:
            flash(f"שגיאת מסד נתונים (SQL Injection triggered): {str(e)}", "danger")
            conn.close()
            return render_template("register.html")

        if existing_user:
            flash("שם המשתמש או כתובת הדוא״ל כבר קיימים במערכת.", "danger")
            conn.close()
            return render_template("register.html")

        # Cryptographic storage: HMAC + Salt (Required by Part A)
        salt = generate_salt()
        pwd_hash = hash_password(password, salt)

        # VULNERABLE INSERT (String formatting)
        try:
            insert_sql = (
                f"INSERT INTO users (username, email, salt, password_hash) "
                f"VALUES ('{username}', '{email}', '{salt}', '{pwd_hash}')"
            )
            cursor.execute(insert_sql)
            new_user_id = cursor.lastrowid

            # Save initial password history for history_count checking
            cursor.execute(
                f"INSERT INTO password_history (user_id, salt, password_hash) "
                f"VALUES ({new_user_id}, '{salt}', '{pwd_hash}')"
            )
            conn.commit()
            conn.close()
            flash("ההרשמה בוצעה בהצלחה! הסיסמה הוצפנה ב-HMAC+Salt. כעת ניתן להתחבר.", "success")
            return redirect(url_for("login"))
        except sqlite3.OperationalError as e:
            flash(f"שגיאת מסד נתונים בהכנסה: {str(e)}", "danger")
            conn.close()
            return render_template("register.html")

    return render_template("register.html")

# ==========================================
# 3. LOGIN SCREEN (Section 3) - VULNERABLE TO SQLi
# ==========================================
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = get_db()
        cursor = conn.cursor()

        # VULNERABLE SQL QUERY (Authentication bypass via SQLi)
        # Directly interpolating username into SQL
        try:
            sql = f"SELECT * FROM users WHERE username = '{username}'"
            cursor.execute(sql)
            user = cursor.fetchone()
        except sqlite3.OperationalError as e:
            conn.close()
            flash(f"שגיאת מסד נתונים (SQL Injection Error): {str(e)}", "danger")
            return render_template("login.html")

        if not user:
            conn.close()
            flash("שם משתמש אינו קיים במערכת Comunication_LTD.", "danger")
            return render_template("login.html")

        # If SQLi comment bypass was injected (e.g. admin' -- or ' OR 1=1 --)
        # Attacker bypassed password checking
        if "'" in username and ("--" in username or "OR" in username.upper()):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            conn.close()
            flash(f"התחברות הצליחה באמצעות עקיפת SQL Injection! מחובר בתור: {user['username']}", "warning")
            return redirect(url_for("dashboard"))

        # Check account lockout
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
                    flash(f"חשבון זה נעול עקב {max_attempts} ניסיונות כושלים. נסה שוב בעוד {remaining + 1} דקות.", "danger")
                    return render_template("login.html")
            except Exception:
                pass

        # Verify password using HMAC + Salt
        if verify_password(password, user["salt"], user["password_hash"]):
            # Reset failed attempts
            cursor.execute(f"UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = {user['id']}")
            conn.commit()
            conn.close()

            session["user_id"] = user["id"]
            session["username"] = user["username"]
            flash(f"ברוך הבא למערכת Comunication_LTD, {user['username']}!", "success")
            return redirect(url_for("dashboard"))
        else:
            # Increment failed attempts
            new_attempts = user["failed_attempts"] + 1
            locked_until_val = "NULL"
            if new_attempts >= max_attempts:
                lockout_duration = policy.get("lockout_duration_minutes", 15)
                lock_time = (datetime.now(timezone.utc) + timedelta(minutes=lockout_duration)).isoformat()
                cursor.execute(f"UPDATE users SET failed_attempts = {new_attempts}, locked_until = '{lock_time}' WHERE id = {user['id']}")
                conn.commit()
                conn.close()
                flash(f"סיסמה שגויה! החשבון ננעל לאחר {max_attempts} ניסיונות כושלים (לפי הקונפיגורציה).", "danger")
            else:
                cursor.execute(f"UPDATE users SET failed_attempts = {new_attempts} WHERE id = {user['id']}")
                conn.commit()
                conn.close()
                flash(f"סיסמה שגויה. נותרו לך {max_attempts - new_attempts} ניסיונות לפני נעילת החשבון.", "warning")

            return render_template("login.html")

    return render_template("login.html")

# ==========================================
# 2. CHANGE PASSWORD SCREEN (Section 2)
# ==========================================
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
        cursor.execute(f"SELECT * FROM users WHERE id = {session['user_id']}")
        user = cursor.fetchone()

        if not user or not verify_password(current_password, user["salt"], user["password_hash"]):
            conn.close()
            flash("הסיסמה הנוכחית שגויה.", "danger")
            return render_template("change_password.html")

        # Fetch password history to enforce history_count from config
        cursor.execute(f"SELECT salt, password_hash FROM password_history WHERE user_id = {user['id']} ORDER BY id DESC")
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
            f"UPDATE users SET salt = '{new_salt}', password_hash = '{new_pwd_hash}' WHERE id = {user['id']}"
        )
        cursor.execute(
            f"INSERT INTO password_history (user_id, salt, password_hash) VALUES ({user['id']}, '{new_salt}', '{new_pwd_hash}')"
        )
        conn.commit()
        conn.close()

        flash("הסיסמה שונתה בהצלחה בהתאם לכללי המדיניות!", "success")
        return redirect(url_for("dashboard"))

    return render_template("change_password.html")

# ==========================================
# 5. FORGOT PASSWORD (Section 5) - SHA-1 Token
# ==========================================
@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        identity = request.form.get("identity", "").strip()
        if not identity:
            flash("נא להזין שם משתמש או כתובת דוא״ל.", "warning")
            return render_template("forgot_password.html", step="request_token")

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(f"SELECT * FROM users WHERE username = '{identity}' OR email = '{identity}'")
        user = cursor.fetchone()

        if not user:
            conn.close()
            flash("המשתמש לא נמצא במערכת Comunication_LTD.", "danger")
            return render_template("forgot_password.html", step="request_token")

        # Generate random SHA-1 token as explicitly requested
        token_sha1 = generate_sha1_reset_token()
        expires_at = (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat()

        cursor.execute(
            f"INSERT INTO password_resets (user_id, token_sha1, expires_at) "
            f"VALUES ({user['id']}, '{token_sha1}', '{expires_at}')"
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
    token = request.form.get("token", "").strip()
    if not token:
        flash("נא להזין ערך אימות (SHA-1 Token).", "danger")
        return redirect(url_for("forgot_password"))

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM password_resets WHERE token_sha1 = '{token}' AND used = 0")
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

    return redirect(url_for("reset_password", token=token))

@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    token = request.args.get("token") or request.form.get("token")
    if not token:
        flash("חסר טוקן אימות.", "danger")
        return redirect(url_for("forgot_password"))

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM password_resets WHERE token_sha1 = '{token}' AND used = 0")
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
            return render_template("reset_password.html", token=token)

        # Check history
        cursor.execute(f"SELECT salt, password_hash FROM password_history WHERE user_id = {user_id} ORDER BY id DESC")
        history_rows = cursor.fetchall()
        history_tuples = [(row["salt"], row["password_hash"]) for row in history_rows]

        valid, msg = validate_password_complexity(new_password, history_tuples)
        if not valid:
            flash(msg, "warning")
            return render_template("reset_password.html", token=token)

        # Update password with HMAC+Salt
        new_salt = generate_salt()
        new_pwd_hash = hash_password(new_password, new_salt)

        cursor.execute(f"UPDATE users SET salt = '{new_salt}', password_hash = '{new_pwd_hash}', failed_attempts = 0, locked_until = NULL WHERE id = {user_id}")
        cursor.execute(f"INSERT INTO password_history (user_id, salt, password_hash) VALUES ({user_id}, '{new_salt}', '{new_pwd_hash}')")
        cursor.execute(f"UPDATE password_resets SET used = 1 WHERE id = {reset_record['id']}")
        conn.commit()
        conn.close()

        flash("הסיסמה אופסה בהצלחה! כעת תוכל להתחבר עם הסיסמה החדשה.", "success")
        return redirect(url_for("login"))

    conn.close()
    return render_template("reset_password.html", token=token)

# ==========================================
# 4. SYSTEM SCREEN (Section 4) - VULNERABLE
# ==========================================
@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))

    search_query = request.args.get("q", "").strip()
    new_customer_name = session.pop("new_customer_name", None)

    conn = get_db()
    cursor = conn.cursor()

    # Load sectors & packages
    cursor.execute("SELECT id, name, description FROM sectors")
    sectors = cursor.fetchall()

    cursor.execute("SELECT id, name, speed_mbps, price FROM packages")
    packages = cursor.fetchall()

    # VULNERABLE SQL QUERY (SQLi in Customer Search - Section 4)
    # Allows UNION-based SQL Injection
    try:
        if search_query:
            query_sql = (
                f"SELECT c.id, c.full_name, c.identity_number, c.email, c.phone, "
                f"s.name as sector, p.name as package, c.notes "
                f"FROM customers c "
                f"LEFT JOIN sectors s ON c.sector_id = s.id "
                f"LEFT JOIN packages p ON c.package_id = p.id "
                f"WHERE c.full_name LIKE '%{search_query}%' OR c.identity_number LIKE '%{search_query}%' "
                f"ORDER BY c.id DESC"
            )
        else:
            query_sql = (
                "SELECT c.id, c.full_name, c.identity_number, c.email, c.phone, "
                "s.name as sector, p.name as package, c.notes "
                "FROM customers c "
                "LEFT JOIN sectors s ON c.sector_id = s.id "
                "LEFT JOIN packages p ON c.package_id = p.id "
                "ORDER BY c.id DESC"
            )
        cursor.execute(query_sql)
        customers = cursor.fetchall()
    except sqlite3.OperationalError as e:
        customers = []
        flash(f"שגיאת SQL Injection בחיפוש: {str(e)}", "danger")

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

    full_name = request.form.get("full_name", "")
    identity_number = request.form.get("identity_number", "")
    email = request.form.get("email", "")
    phone = request.form.get("phone", "")
    sector_id = request.form.get("sector_id", "")
    package_id = request.form.get("package_id", "")
    notes = request.form.get("notes", "")

    # VULNERABLE INSERT: Raw strings directly in SQL + No HTML Sanitization
    conn = get_db()
    cursor = conn.cursor()
    try:
        insert_sql = (
            f"INSERT INTO customers (full_name, identity_number, email, phone, sector_id, package_id, notes) "
            f"VALUES ('{full_name}', '{identity_number}', '{email}', '{phone}', {sector_id}, {package_id}, '{notes}')"
        )
        cursor.execute(insert_sql)
        conn.commit()
    except Exception as e:
        conn.close()
        flash(f"שגיאה בהכנסת לקוח: {str(e)}", "danger")
        return redirect(url_for("dashboard"))

    conn.close()

    # VULNERABILITY: Stored XSS stored and saved in session to be rendered via | safe!
    session["new_customer_name"] = full_name
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
    print("[*] Starting Vulnerable Comunication_LTD Server on port 5001...")
    app.run(host="127.0.0.1", port=5001, debug=True)
