import os
import json
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timezone

SIMULATED_INBOX_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "simulated_emails.json")

def send_password_reset_email(to_email: str, username: str, reset_token: str, base_url: str = ""):
    """
    Sends an email with the SHA-1 reset token.
    1. If SMTP server settings are provided via environment variables, sends via real SMTP.
    2. Stores the email in the simulated inbox for Web Mailbox viewing and automated tests.
    """
    reset_url = f"{base_url}/reset-password?token={reset_token}" if base_url else f"/reset-password?token={reset_token}"
    timestamp_now = datetime.now(timezone.utc).isoformat()

    subject = "Comunication_LTD - קוד אימות לאיפוס סיסמה (SHA-1 Token)"
    text_content = (
        f"שלום {username},\n\n"
        f"התקבלה בקשה לאיפוס סיסמתך במערכת Comunication_LTD.\n"
        f"קוד האימות החד-פעמי שלך (מוגדר באמצעות SHA-1) הוא:\n"
        f"{reset_token}\n\n"
        f"להמשך וקביעת סיסמה חדשה, לחץ על הקישור הבא או הזן את הקוד באתר:\n"
        f"{reset_url}\n\n"
        f"בברכה,\nצוות אבטחת מידע - Comunication_LTD"
    )

    html_content = f"""
    <div dir="rtl" style="font-family: Arial, sans-serif; background-color: #f8f9fa; padding: 25px; border-radius: 8px; border: 1px solid #dee2e6;">
        <h2 style="color: #0d6efd; margin-top: 0;">📡 Comunication_LTD</h2>
        <h3 style="color: #333;">בקשה לאיפוס סיסמה</h3>
        <p>שלום <strong>{username}</strong>,</p>
        <p>התקבלה בקשה לשחזור סיסמה עבור חשבונך במערכת המידע של <strong>Comunication_LTD</strong>.</p>
        <div style="background-color: #e7f1ff; border-right: 4px solid #0d6efd; padding: 15px; margin: 20px 0; border-radius: 4px;">
            <p style="margin: 0 0 8px 0; font-weight: bold; color: #084298;">קוד האימות החד-פעמי שלך (SHA-1 Token):</p>
            <code style="font-family: monospace; font-size: 16px; background: #fff; padding: 6px 12px; border: 1px solid #b6d4fe; border-radius: 4px; display: inline-block; color: #000;">{reset_token}</code>
        </div>
        <p>
            <a href="{reset_url}" style="background-color: #0d6efd; color: #ffffff; padding: 10px 20px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block;">
                לחץ כאן לאיפוס הסיסמה
            </a>
        </p>
        <p style="font-size: 12px; color: #6c757d; margin-top: 25px;">
            תוקף הקוד: 15 דקות. אם לא ביקשת איפוס זה, אנא התעלם מהודעה זו.<br>
            Comunication_LTD &copy; 2026 - שיווק חבילות גלישה, לקוחות וסקטורים.
        </p>
    </div>
    """

    email_entry = {
        "timestamp": timestamp_now,
        "to": to_email,
        "username": username,
        "subject": subject,
        "reset_token": reset_token,
        "reset_link": reset_url,
        "body": text_content,
        "html": html_content
    }

    # Optional Real SMTP Dispatch if configured
    smtp_host = os.environ.get("SMTP_HOST")
    smtp_port = os.environ.get("SMTP_PORT", 587)
    smtp_user = os.environ.get("SMTP_USER")
    smtp_pass = os.environ.get("SMTP_PASS")

    if smtp_host and smtp_user and smtp_pass:
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = smtp_user
            msg["To"] = to_email
            msg.attach(MIMEText(text_content, "plain", "utf-8"))
            msg.attach(MIMEText(html_content, "html", "utf-8"))

            with smtplib.SMTP(smtp_host, int(smtp_port), timeout=5) as server:
                server.starttls()
                server.login(smtp_user, smtp_pass)
                server.sendmail(smtp_user, to_email, msg.as_string())
            print(f"[REAL SMTP SENT] Email successfully dispatched to {to_email}")
        except Exception as e:
            print(f"[SMTP WARNING] Could not send via live SMTP ({e}). Fallback to Simulated Mailbox active.")

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

def get_all_emails():
    """Retrieve all simulated emails."""
    if not os.path.exists(SIMULATED_INBOX_FILE):
        return []
    try:
        with open(SIMULATED_INBOX_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []

def get_latest_email(to_email: str = None):
    """Retrieve the latest sent email."""
    emails = get_all_emails()
    if not emails:
        return None
    if to_email:
        filtered = [e for e in emails if e["to"].lower() == to_email.lower()]
        return filtered[-1] if filtered else None
    return emails[-1]

def clear_mailbox():
    """Clear all stored simulated emails."""
    with open(SIMULATED_INBOX_FILE, "w", encoding="utf-8") as f:
        json.dump([], f)
