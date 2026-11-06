import os
import json
from datetime import datetime, timezone

SIMULATED_INBOX_FILE = "simulated_emails.json"

def send_password_reset_email(to_email: str, username: str, reset_token: str, base_url: str = ""):
    """
    Simulates sending an email with the SHA-1 reset token.
    Persists sent emails so the tester or examiner can easily inspect the tokens.
    """
    email_entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "to": to_email,
        "username": username,
        "subject": "Comunication_LTD - Password Reset Token",
        "reset_token": reset_token,
        "reset_link": f"{base_url}/reset-password?token={reset_token}" if base_url else f"/reset-password?token={reset_token}",
        "body": f"שלום {username},\n\nהתקבלה בקשה לאיפוס סיסמתך במערכת Comunication_LTD.\nקוד האימות החד-פעמי שלך (SHA-1 Token) הוא:\n{reset_token}\n\nהזן קוד זה במסך איפוס הסיסמה.\nבברכה,\nצוות אבטחת מידע - Comunication_LTD"
    }

    print(f"\n[EMAIL DISPATCH] To: {to_email} | SHA-1 Token: {reset_token}\n")

    # Save to JSON log file
    emails = []
    if os.path.exists(SIMULATED_INBOX_FILE):
        try:
            with open(SIMULATED_INBOX_FILE, "r", encoding="utf-8") as f:
                emails = json.load(f)
        except Exception:
            emails = []

    emails.append(email_entry)
    with open(SIMULATED_INBOX_FILE, "w", encoding="utf-8") as f:
        json.dump(emails, f, ensure_ascii=False, indent=2)

    return email_entry

def get_latest_email(to_email: str = None):
    """Retrieve the latest sent email (useful for automated testing)."""
    if not os.path.exists(SIMULATED_INBOX_FILE):
        return None
    try:
        with open(SIMULATED_INBOX_FILE, "r", encoding="utf-8") as f:
            emails = json.load(f)
            if not emails:
                return None
            if to_email:
                filtered = [e for e in emails if e["to"].lower() == to_email.lower()]
                return filtered[-1] if filtered else None
            return emails[-1]
    except Exception:
        return None
