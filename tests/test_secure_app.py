import unittest
import os
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

# Add BASE_DIR to sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from secure_version.app import app, get_db
from secure_version.database.init_db import init_database
from secure_version.utils.auth_helpers import hash_password, verify_password, load_password_policy

class TestSecureApp(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Reset and seed database before running tests
        init_database()
        app.config["TESTING"] = True
        cls.client = app.test_client()

    def test_01_registration_with_input_validation_and_parameters(self):
        """Test Part B Section 3 & 4: Special characters rejected/encoded and parameterized registration."""
        # 1. Registration with malicious SQLi characters in username is rejected by validation
        resp = self.client.post("/register", data={
            "username": "user' OR '1'='1",
            "email": "sqli@test.com",
            "password": "ValidStrongKey#2026",
            "confirm_password": "ValidStrongKey#2026"
        }, follow_redirects=True)
        self.assertIn("תווים מיוחדים נדחו".encode("utf-8"), resp.data)

        # 2. Valid user registers properly with HMAC + Salt and Parameterized Query
        resp = self.client.post("/register", data={
            "username": "secure_user_1",
            "email": "secure1@test.com",
            "password": "ValidStrongKey#2026",
            "confirm_password": "ValidStrongKey#2026"
        }, follow_redirects=True)
        self.assertIn("ההרשמה הושלמה בהצלחה".encode("utf-8"), resp.data)

        # Verify in DB
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", ("secure_user_1",))
        user = cursor.fetchone()
        conn.close()

        self.assertIsNotNone(user)
        self.assertTrue(verify_password("ValidStrongKey#2026", user["salt"], user["password_hash"]))

    def test_02_sqli_login_bypass_blocked(self):
        """Test Part B Section 4 & Part A Section 3: SQLi Login bypass is completely blocked."""
        # The exact payload that bypassed the vulnerable version: admin_cyber' --
        resp = self.client.post("/login", data={
            "username": "admin_cyber' --",
            "password": ""
        }, follow_redirects=True)

        self.assertEqual(resp.status_code, 200)
        # MUST NOT be authenticated; should show error message
        self.assertNotIn("ברוך הבא למערכת".encode("utf-8"), resp.data)
        self.assertIn("שם משתמש או סיסמה שגויים".encode("utf-8"), resp.data)

    def test_03_login_lockout_policy(self):
        """Test Part A Section 3: Brute force lockout after 3 attempts."""
        policy = load_password_policy()
        max_attempts = policy.get("max_login_attempts", 3)

        # Fail 3 times on user_israel
        for i in range(max_attempts):
            resp = self.client.post("/login", data={
                "username": "user_israel",
                "password": f"WrongPass{i}!"
            }, follow_redirects=True)

        # 4th attempt should be locked out
        resp = self.client.post("/login", data={
            "username": "user_israel",
            "password": "P@ssw0rdSecure!"
        }, follow_redirects=True)
        self.assertIn("חשבון זה נעול זמנית".encode("utf-8"), resp.data)

    def test_04_change_password_history_check(self):
        """Test Part A Section 2: Change password enforces history count of 3."""
        with self.client.session_transaction() as sess:
            sess["user_id"] = 1
            sess["username"] = "admin_cyber"

        # Try changing to current password ("Cyber@2026Admin!") - must be rejected
        resp = self.client.post("/change-password", data={
            "current_password": "Cyber@2026Admin!",
            "new_password": "Cyber@2026Admin!",
            "confirm_password": "Cyber@2026Admin!"
        }, follow_redirects=True)
        self.assertIn("הייתה בשימוש ב-3 הסיסמאות האחרונות".encode("utf-8"), resp.data)

        # Change to valid new password
        resp = self.client.post("/change-password", data={
            "current_password": "Cyber@2026Admin!",
            "new_password": "NewSecureAdmin#2026",
            "confirm_password": "NewSecureAdmin#2026"
        }, follow_redirects=True)
        self.assertIn("הסיסמה שונתה בהצלחה".encode("utf-8"), resp.data)

    def test_05_forgot_password_sha1_token(self):
        """Test Part A Section 5: Forgot password generates random SHA-1 token."""
        resp = self.client.post("/forgot-password", data={
            "identity": "admin_cyber"
        }, follow_redirects=True)

        self.assertEqual(resp.status_code, 200)
        self.assertIn("נשלח ערך אימות SHA-1 למייל שלך".encode("utf-8"), resp.data)

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT token_sha1 FROM password_resets WHERE user_id = 1 ORDER BY id DESC LIMIT 1")
        row = cursor.fetchone()
        conn.close()

        self.assertIsNotNone(row)
        token = row["token_sha1"]
        self.assertEqual(len(token), 40, "SHA-1 token must be 40 hex characters")

        # Verify token and reset password
        resp = self.client.post("/verify-reset-token", data={"token": token}, follow_redirects=True)
        self.assertIn("קביעת סיסמה חדשה".encode("utf-8"), resp.data)

        resp = self.client.post("/reset-password", data={
            "token": token,
            "new_password": "ResetPassOk#2026!",
            "confirm_password": "ResetPassOk#2026!"
        }, follow_redirects=True)
        self.assertIn("הסיסמה אופסה בהצלחה".encode("utf-8"), resp.data)

    def test_06_stored_xss_mitigated(self):
        """Test Part B Section 1 & Part A Section 4: Stored XSS is completely neutralized."""
        with self.client.session_transaction() as sess:
            sess["user_id"] = 1
            sess["username"] = "admin_cyber"

        # Attempt to inject Stored XSS payload in customer name
        xss_attempt = '<script>alert("Hacked XSS");</script>'
        resp = self.client.post("/add-customer", data={
            "full_name": xss_attempt,
            "identity_number": "112233445",
            "email": "secure_cust@test.com",
            "phone": "054-1111222",
            "sector_id": "1",
            "package_id": "3",
            "notes": "Safe customer creation"
        }, follow_redirects=True)

        self.assertEqual(resp.status_code, 200)
        # CRITICAL VERIFICATION:
        # 1. Raw unescaped script tag MUST NOT appear in response!
        self.assertNotIn(b'<script>alert("Hacked XSS");</script>', resp.data, "Raw script tag must NOT be executed in secure version")
        # 2. XSS is neutralized safely by HTML entity encoding (no live execution)
        self.assertTrue(b"&lt;script&gt;" in resp.data or b"&amp;lt;script&amp;gt;" in resp.data)

    def test_07_sqli_in_section_4_blocked(self):
        """Test Part B Section 4: SQLi in customer search is blocked by Parameterized Query."""
        with self.client.session_transaction() as sess:
            sess["user_id"] = 1
            sess["username"] = "admin_cyber"

        sqli_payload = "' UNION SELECT u.id, u.username, u.email, u.salt, u.password_hash, 'LEAK_SEC', 'LEAK_PKG', 'LEAK_NOTES' FROM users u --"
        resp = self.client.get(f"/dashboard?q={sqli_payload}")

        self.assertEqual(resp.status_code, 200)
        # In the results table, no row with leaked user credentials should be rendered
        self.assertNotIn(b"<td>LEAK_SEC</td>", resp.data, "UNION SQLi must not leak user rows into the table")
        self.assertIn("לא נמצאו לקוחות במאגר".encode("utf-8"), resp.data)

    def test_08_security_headers(self):
        """Test that defensive HTTP headers (CSP, nosniff, DENY) are sent."""
        resp = self.client.get("/login")
        self.assertIn("Content-Security-Policy", resp.headers)
        self.assertEqual(resp.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(resp.headers.get("X-Frame-Options"), "DENY")

if __name__ == "__main__":
    unittest.main()
