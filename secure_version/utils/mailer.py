import os
import json
import smtplib
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timezone

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SIMULATED_INBOX_FILE = os.path.join(PROJECT_ROOT, "simulated_emails.json")


def get_email_config_paths():
    return [
        os.path.join(PROJECT_ROOT, "secure_version", "config", "email_config.json"),
        os.path.join(PROJECT_ROOT, "vulnerable_version", "config", "email_config.json"),
    ]


def load_email_config() -> dict:
    current_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(os.path.dirname(current_dir), "config", "email_config.json")
    default_cfg = {
        "provider": "resend",
        "override_recipient_email": "",
        "resend": {
            "api_key": "",
            "from_email": "Comunication_LTD <onboarding@resend.dev>"
        },
        "brevo": {
            "api_key": "",
            "sender_email": "",
            "sender_name": "Comunication_LTD Security"
        },
        "smtp": {
            "host": "smtp.gmail.com",
            "port": 587,
            "user": "",
            "password": ""
        }
    }
    if os.path.exists(config_path):
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                data = json.load(f).get("email_settings", {})
                default_cfg.update(data)
        except Exception:
            pass
    return default_cfg


def save_email_config(new_settings: dict):
    """Save email settings across both versions so configuration is unified."""
    payload = {"email_settings": new_settings}
    for path in get_email_config_paths():
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False, indent=2)
        except Exception:
            pass


def send_via_resend(api_key: str, from_email: str, to_email: str, subject: str, html_content: str, text_content: str) -> tuple[bool, str]:
    """Send transactional email via Resend REST API (https://api.resend.com/emails)."""
    url = "https://api.resend.com/emails"
    headers = {
        "Authorization": f"Bearer {api_key.strip()}",
        "Content-Type": "application/json"
    }
    payload = {
        "from": from_email.strip() or "Comunication_LTD <onboarding@resend.dev>",
        "to": [to_email.strip()],
        "subject": subject,
        "html": html_content,
        "text": text_content
    }
    try:
        resp = requests.post(url, json=payload, headers=headers, timeout=8)
        if resp.status_code in (200, 201):
            res_id = resp.json().get("id", "")
            return True, f"נשלח מייל אמיתי דרך Resend API אל {to_email} (ID: {res_id})"
        return False, f"שגיאת Resend ({resp.status_code}): {resp.text}"
    except Exception as e:
        return False, f"שגיאת תקשורת מול Resend: {str(e)}"


def send_via_brevo(api_key: str, sender_email: str, sender_name: str, to_email: str, subject: str, html_content: str, text_content: str) -> tuple[bool, str]:
    """Send transactional email via Brevo REST API (https://api.brevo.com/v3/smtp/email)."""
    url = "https://api.brevo.com/v3/smtp/email"
    headers = {
        "api-key": api_key.strip(),
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    payload = {
        "sender": {"name": sender_name or "Comunication_LTD", "email": sender_email.strip()},
        "to": [{"email": to_email.strip()}],
        "subject": subject,
        "htmlContent": html_content,
        "textContent": text_content
    }
    try:
        resp = requests.post(url, json=payload, headers=headers, timeout=8)
        if resp.status_code in (200, 201):
            return True, f"נשלח מייל אמיתי דרך Brevo API אל {to_email}"
        return False, f"שגיאת Brevo ({resp.status_code}): {resp.text}"
    except Exception as e:
        return False, f"שגיאת תקשורת מול Brevo: {str(e)}"


def send_via_smtp(host: str, port: int, user: str, password: str, to_email: str, subject: str, html_content: str, text_content: str) -> tuple[bool, str]:
    """Send email via standard SMTP (e.g. Gmail App Password)."""
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = user
        msg["To"] = to_email
        msg.attach(MIMEText(text_content, "plain", "utf-8"))
        msg.attach(MIMEText(html_content, "html", "utf-8"))

        with smtplib.SMTP(host, int(port), timeout=8) as server:
            server.starttls()
            server.login(user, password)
            server.sendmail(user, to_email, msg.as_string())
        return True, f"נשלח מייל אמיתי דרך שרת SMTP אל {to_email}"
    except Exception as e:
        return False, f"שגיאת SMTP: {str(e)}"


def send_password_reset_email(to_email: str, username: str, reset_token: str, base_url: str = ""):
    """
    Dispatches an email containing the SHA-1 reset token:
    1. Uses configured provider (Resend API / Brevo API / SMTP) if credentials are set.
    2. Always saves a copy to the local Web Mailbox (/mailbox) for instant verification.
    """
    cfg = load_email_config()
    override_email = os.environ.get("OVERRIDE_RECIPIENT_EMAIL") or cfg.get("override_recipient_email", "").strip()
    actual_recipient = override_email if override_email else to_email

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
        <p>שלום <strong>{username}</strong> (חשבון: <code>{to_email}</code>),</p>
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

    provider = cfg.get("provider", "resend").lower()
    external_sent = False
    delivery_message = "נשמר בתיבת הדואר המקומית (Web Mailbox) - טרם הוגדר מפתח API חיצוני"

    # 1. Try Resend API
    resend_cfg = cfg.get("resend", {})
    resend_key = os.environ.get("RESEND_API_KEY") or resend_cfg.get("api_key", "").strip()
    if provider == "resend" and resend_key and not resend_key.startswith("re_YOUR"):
        from_email = resend_cfg.get("from_email", "Comunication_LTD <onboarding@resend.dev>")
        external_sent, delivery_message = send_via_resend(
            resend_key, from_email, actual_recipient, subject, html_content, text_content
        )

    # 2. Try Brevo API
    brevo_cfg = cfg.get("brevo", {})
    brevo_key = os.environ.get("BREVO_API_KEY") or brevo_cfg.get("api_key", "").strip()
    if not external_sent and provider == "brevo" and brevo_key and not brevo_key.startswith("xkeysib_YOUR"):
        sender_email = brevo_cfg.get("sender_email", "")
        sender_name = brevo_cfg.get("sender_name", "Comunication_LTD Security")
        external_sent, delivery_message = send_via_brevo(
            brevo_key, sender_email, sender_name, actual_recipient, subject, html_content, text_content
        )

    # 3. Try SMTP
    smtp_cfg = cfg.get("smtp", {})
    smtp_host = os.environ.get("SMTP_HOST") or smtp_cfg.get("host", "smtp.gmail.com")
    smtp_port = os.environ.get("SMTP_PORT") or smtp_cfg.get("port", 587)
    smtp_user = os.environ.get("SMTP_USER") or smtp_cfg.get("user", "").strip()
    smtp_pass = os.environ.get("SMTP_PASS") or smtp_cfg.get("password", "").strip()
    if not external_sent and provider == "smtp" and smtp_host and smtp_user and smtp_pass:
        external_sent, delivery_message = send_via_smtp(
            smtp_host, int(smtp_port), smtp_user, smtp_pass, actual_recipient, subject, html_content, text_content
        )

    print(f"\n[EMAIL DISPATCH] To: {actual_recipient} (User: {to_email}) | Status: {delivery_message} | SHA-1 Token: {reset_token}\n")

    email_entry = {
        "timestamp": timestamp_now,
        "to": to_email,
        "actual_recipient": actual_recipient,
        "username": username,
        "subject": subject,
        "reset_token": reset_token,
        "reset_link": reset_url,
        "body": text_content,
        "html": html_content,
        "external_sent": external_sent,
        "provider": provider.upper(),
        "delivery_message": delivery_message
    }

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


def clear_mailbox():
    """Clear all stored simulated emails."""
    with open(SIMULATED_INBOX_FILE, "w", encoding="utf-8") as f:
        json.dump([], f)
