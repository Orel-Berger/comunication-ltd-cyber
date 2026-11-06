import os
import json
import hmac
import hashlib
from datetime import datetime, timezone, timedelta

HMAC_SECRET_KEY = b"Comunication_LTD_Secure_HMAC_Secret_Key_2026_Project"

def get_config_path():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(os.path.dirname(current_dir), "config", "password_policy.json")

def load_password_policy():
    path = get_config_path()
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f).get("password_policy", {})
    except Exception as e:
        # Fallback defaults if file read fails
        return {
            "min_length": 10,
            "require_uppercase": True,
            "require_lowercase": True,
            "require_digits": True,
            "require_special_characters": True,
            "special_characters_allowed": "!@#$%^&*()_+-=[]{}|;:,.<>?",
            "history_count": 3,
            "max_login_attempts": 3,
            "lockout_duration_minutes": 15,
            "dictionary_blacklist": ["password", "1234567890", "comunication", "qwertyuiop"]
        }

def generate_salt(length: int = 16) -> str:
    """Generate cryptographically secure salt."""
    return os.urandom(length).hex()

def hash_password(password: str, salt: str) -> str:
    """Compute HMAC-SHA256 with Salt and system secret key."""
    msg = (salt + password).encode("utf-8")
    return hmac.new(HMAC_SECRET_KEY, msg, hashlib.sha256).hexdigest()

def verify_password(password: str, salt: str, expected_hash: str) -> bool:
    """Safely verify HMAC hash."""
    computed_hash = hash_password(password, salt)
    return hmac.compare_digest(computed_hash, expected_hash)

def generate_sha1_reset_token() -> str:
    """
    Requirements explicitly dictate:
    'המערכת מייצרת ערך אקראי ושולחת אותו למייל של המשתמש.
     הערך האקראי חייב להיות מוגדר באמצעות SHA-1'
    """
    random_entropy = os.urandom(32) + str(datetime.now(timezone.utc).timestamp()).encode("utf-8")
    return hashlib.sha1(random_entropy).hexdigest()

def validate_password_complexity(password: str, user_history_records=None) -> tuple[bool, str]:
    """
    Validates password against configuration file rules:
    - Min length
    - Complexity (uppercase, lowercase, digits, special characters)
    - Dictionary blacklist
    - Password history
    """
    policy = load_password_policy()
    min_length = policy.get("min_length", 10)
    req_upper = policy.get("require_uppercase", True)
    req_lower = policy.get("require_lowercase", True)
    req_digits = policy.get("require_digits", True)
    req_special = policy.get("require_special_characters", True)
    special_chars = policy.get("special_characters_allowed", "!@#$%^&*()_+-=[]{}|;:,.<>?")
    blacklist = policy.get("dictionary_blacklist", [])
    history_count = policy.get("history_count", 3)

    if len(password) < min_length:
        return False, f"הסיסמה קצרה מדי. נדרש אורך של לפחות {min_length} תווים (לפי הגדרת הקונפיגורציה)."

    if req_upper and not any(c.isupper() for c in password):
        return False, "הסיסמה חייבת לכלול לפחות אות גדולה אחת באנגלית (A-Z)."

    if req_lower and not any(c.islower() for c in password):
        return False, "הסיסמה חייבת לכלול לפחות אות קטנה אחת באנגלית (a-z)."

    if req_digits and not any(c.isdigit() for c in password):
        return False, "הסיסמה חייבת לכלול לפחות ספרה אחת (0-9)."

    if req_special and not any(c in special_chars for c in password):
        return False, f"הסיסמה חייבת לכלול לפחות תו מיוחד אחד מתוך: {special_chars}"

    # Dictionary check
    lower_pwd = password.lower()
    for bad_word in blacklist:
        if bad_word.lower() in lower_pwd:
            return False, f"הסיסמה מכילה מילה או רצף אסור מתוך מילון המערכת ('{bad_word}')."

    # Password History check
    if user_history_records:
        # Check against the last 'history_count' passwords
        recent_history = user_history_records[:history_count]
        for past_salt, past_hash in recent_history:
            if verify_password(password, past_salt, past_hash):
                return False, f"הסיסמה הזו הייתה בשימוש ב-{history_count} הסיסמאות האחרונות שלך. בחר סיסמה חדשה."

    return True, "הסיסמה עומדת בכל דרישות המורכבות."
