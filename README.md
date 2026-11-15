# 📡 Comunication_LTD - פרויקט סיום בסייבר (Cyber Security Final Project)

פרויקט זה מממש מערכת מידע ווב מלאה ומסד נתונים רלציוני עבור חברת התקשורת הדמיונית **Comunication_LTD**, העוסקת בשיווק חבילות גלישה באינטרנט, ניהול לקוחות ושיוכם לסקטורים שיווקיים שונים (פרטי, עסקי, אקדמי, ביטחוני וציבורי).

המערכת פותחה בשפת **Python (Flask)** עם מסד נתונים רלציוני **SQLite3** וממשק **Bootstrap 5 RTL**, ומוגשת בשתי גרסאות נפרדות ומלאות בהתאם לדרישות הפרויקט:
1. 🔴 **גרסה פגיעה (`vulnerable_version` - Port 5001)**: מדגימה הלכה למעשה חולשות **SQL Injection (SQLi)** ו-**Stored Cross-Site Scripting (XSS)** כולל כפתורי הזרקה והעתקת פיילודים מובנים.
2. 🟢 **גרסה מאובטחת (`secure_version` - Port 5002 / Port 5000)**: מתקנת וחוסמת הרמטית את כל החולשות באמצעות **Parameterized Queries (Prepared Statements)**, **קידוד תווים מיוחדים (`html.escape` & Jinja2 Auto-Escaping)**, **אימות קלט קפדני (Regex Whitelisting)**, וכותרות אבטחה (**Content-Security-Policy**).

---

## 📂 ארכיטקטורה ומבנה הפרויקט

```text
comunication-ltd-cyber/
├── secure_version/                  # 🟢 גרסה 2: קוד מאובטח ומוגן (Port 5002 / 5000)
│   ├── config/
│   │   ├── password_policy.json     # קובץ קונפיגורציה חיצוני לניהול מדיניות סיסמאות ונעילת חשבון
│   │   └── email_config.json        # קובץ קונפיגורציה לשליחת מיילים (Resend API / Brevo / SMTP)
│   ├── database/
│   │   ├── schema.sql               # סכמת מסד הנתונים הרלציוני (5 טבלאות מקושרות)
│   │   ├── init_db.py               # סקריפט אתחול מסד הנתונים והזנת נתוני ברירת מחדל (Seed)
│   │   └── comunication_ltd.db      # קובץ מסד הנתונים SQLite של הגרסה המאובטחת
│   ├── static/css/style.css         # עיצוב RTL מותאם לגרסה המאובטחת
│   ├── templates/                   # תבניות HTML מאובטחות (קידוד פלט אוטומטי ללא | safe)
│   ├── utils/
│   │   ├── auth_helpers.py          # מנוע קריפטוגרפי: HMAC-SHA256 + Salt, טוקן SHA-1, ואימות מדיניות
│   │   └── mailer.py                # מנגנון שליחת מיילים היברידי (Resend API / Brevo / SMTP + Web Mailbox)
│   └── app.py                       # שרת Flask מאובטח (Parameterized Queries + Anti-XSS + CSP)
│
├── vulnerable_version/              # 🔴 גרסה 1: קוד פגיע להדגמת מתקפות (Port 5001)
│   ├── config/
│   │   ├── password_policy.json     # קובץ קונפיגורציה לניהול מדיניות סיסמאות
│   │   └── email_config.json        # קובץ קונפיגורציה לשליחת מיילים
│   ├── database/
│   │   ├── schema.sql               # סכמת מסד הנתונים הרלציוני
│   │   ├── init_db.py               # סקריפט אתחול מסד הנתונים של הגרסה הפגיעה
│   │   └── comunication_ltd.db      # קובץ מסד הנתונים SQLite של הגרסה הפגיעה
│   ├── static/css/style.css         # עיצוב RTL מותאם לגרסה הפגיעה
│   ├── templates/                   # תבניות HTML (כוללות | safe ופאנלי מעבדת תקיפה אינטראקטיביים)
│   ├── utils/
│   │   ├── auth_helpers.py          # מנוע קריפטוגרפי (HMAC-SHA256 + Salt, טוקן SHA-1)
│   │   └── mailer.py                # מנגנון שליחת מיילים היברידי
│   └── app.py                       # שרת Flask פגיע (שרשור מחרוזות SQL ישיר וללא סינון XSS)
│
├── app.py                           # נקודת כניסה ראשית להרצת המערכת המאובטחת בפורט 5000
├── run_secure.bat                   # סקריפט הפעלה מהירה בלחיצה לגרסה המאובטחת (Port 5002)
├── run_vulnerable.bat               # סקריפט הפעלה מהירה בלחיצה לגרסה הפגיעה (Port 5001)
├── CYBER_SECURITY_REPORT.md         # דו"ח הגשה אקדמי מלא של הפרויקט (חלק א' + חלק ב')
└── README.md                        # מסמך תיעוד זה
```

---

## 🚀 הוראות התקנה והרצה

### דרישות קדם
* **Python 3.10+**
* ספריות נדרשות: `flask`, `requests`
  ```bash
  pip install flask requests
  ```

### אפשרויות הרצה
1. **הפעלת הגרסה המאובטחת (`secure_version`)**:
   * באמצעות קובץ האצווה (מאתחל את מסד הנתונים ומרים שרת בפורט `5002`):
     ```cmd
     run_secure.bat
     ```
     כתובת בדפדפן: **`http://127.0.0.1:5002`**
   * או ישירות מתיקיית השורש (מרים שרת בפורט `5000`):
     ```cmd
     python app.py
     ```
     כתובת בדפדפן: **`http://127.0.0.1:5000`**

2. **הפעלת הגרסה הפגיעה (`vulnerable_version`)**:
   * באמצעות קובץ האצווה (מאתחל את מסד הנתונים ומרים שרת בפורט `5001`):
     ```cmd
     run_vulnerable.bat
     ```
     כתובת בדפדפן: **`http://127.0.0.1:5001`**

> 💡 **טיפ להדגמה השוואתית:** ניתן להריץ את `run_vulnerable.bat` (פורט `5001`) ואת `run_secure.bat` (פורט `5002`) **במקביל** בשתי לשוניות בדפדפן כדי להדגים בזמן אמת כיצד אותה מתקפה בדיוק מצליחה בגרסה הפגיעה ונחסמת בגרסה המאובטחת.

---

## 🔑 משתמשי ברירת מחדל (Default Credentials)

בעת אתחול מסד הנתונים (`init_db.py`), מוזנים אוטומטית שני משתמשים שסיסמאותיהם מוצפנות ב-`HMAC-SHA256 + Salt` ועומדות בכל דרישות המורכבות:

| תפקיד | שם משתמש (`username`) | כתובת אימייל (`email`) | סיסמה (`password`) |
| :--- | :--- | :--- | :--- |
| **מנהל אבטחה (Admin)** | `admin_cyber` | `admin@comunication-ltd.co.il` | `Cyber@2026Admin!` |
| **משתמש רגיל** | `user_israel` | `israel@comunication-ltd.co.il` | `P@ssw0rdSecure!` |

* במסך ההתחברות (`/login`) בשתי הגרסאות קיים כפתור **"מלא אוטומטית"** וכפתור **"העתק סיסמה"** לנוחות הבודק.

---

## 🛠️ פירוט מעמיק של המימושים הטכניים

### 1. מסד הנתונים הרלציוני (`database/schema.sql`)
מסד הנתונים בנוי מ-5 טבלאות רלציוניות עם מפתחות זרים (`FOREIGN KEY`):
* **`users`**: שומרת את פרטי המשתמשים (`id`, `username`, `email`, `salt`, `password_hash`, `failed_attempts`, `locked_until`, `created_at`). **לעולם לא נשמרת סיסמה בטקסט גלוי (Plaintext).**
* **`password_history`**: מתעדת את היסטוריית הסיסמאות (`user_id`, `salt`, `password_hash`) כדי למנוע שימוש חוזר ב-$N$ הסיסמאות האחרונות.
* **`password_resets`**: שומרת את טוקני האיפוס החד-פעמיים שמחושבים באמצעות **SHA-1** (`user_id`, `token_sha1`, `expires_at`, `used`).
* **`sectors`**: טבלת הסקטורים השיווקיים של החברה (פרטי, עסקי, אקדמי, ביטחוני, ציבורי).
* **`packages`**: טבלת חבילות הגלישה באינטרנט (מהירות ב-Mbps, מחיר ותיאור).
* **`customers`**: טבלת הלקוחות המקושרת ב-`LEFT JOIN` לטבלאות `sectors` ו-`packages`.

---

### 2. חלק א' – עקרונות פיתוח מאובטח (Secure Development Principles)

#### א. שמירת סיסמאות באמצעות `HMAC + Salt` (`utils/auth_helpers.py`)
* **יצירת ה-Salt**: בעת הרשמה או שינוי סיסמה, הפונקציה `generate_salt()` מייצרת Salt אקראי קריפטוגרפי באורך 16 בתים (32 תווים הקסדצימליים) באמצעות `os.urandom(16).hex()`.
* **חישוב ה-HMAC**: הפונקציה `hash_password(password, salt)` משלבת את ה-Salt עם הסיסמה ומחשבת חתימת **HMAC-SHA256** מול מפתח סודי של השרת (`HMAC_SECRET_KEY`):
  ```python
  msg = (salt + password).encode("utf-8")
  hmac.new(HMAC_SECRET_KEY, msg, hashlib.sha256).hexdigest()
  ```
* **אימות עמיד להתקפות תזמון (Timing Attacks)**: הפונקציה `verify_password()` משווה את החתימות באמצעות `hmac.compare_digest(computed_hash, expected_hash)` בזמן קבוע.

#### ב. ניהול מדיניות סיסמאות דינמית בקובץ קונפיגורציה (`config/password_policy.json`)
כל כללי הסיסמה נקראים בזמן אמת מקובץ ה-JSON ללא קידוד קשיח (Hardcoding):
* **`min_length`: `10`** – אורך מינימלי של 10 תווים.
* **`require_uppercase` / `require_lowercase` / `require_digits` / `require_special_characters`** – חיוב שילוב של אותיות גדולות, אותיות קטנות, ספרות ותווים מיוחדים.
* **`dictionary_blacklist`** – מניעת בחירת סיסמאות המכילות מילים נפוצות מתוך מילון חסום (`password`, `1234567890`, `comunication`, `qwertyuiop` וכו').
* **`history_count`: `3`** – בעת שינוי סיסמה (`/change-password`) או איפוס סיסמה (`/reset-password`), המערכת שולפת את 3 הסיסמאות האחרונות של המשתמש מטבלת `password_history` ומוודאת שהסיסמה החדשה אינה זהה לאף אחת מהן.
* **`max_login_attempts`: `3` & `lockout_duration_minutes`: `15`** – הגנה מפני Brute-Force במסך ה-Login: לאחר 3 ניסיונות כושלים החשבון ננעל אוטומטית ל-15 דקות (`locked_until`).

#### ג. מנגנון "שכח סיסמה" וטוקן **SHA-1** (`utils/auth_helpers.py` & `utils/mailer.py`)
* בהתאם לדרישת ההנחיות המפורשת (*"המערכת מייצרת ערך אקראי ושולחת אותו למייל של המשתמש. הערך האקראי חייב להיות מוגדר באמצעות SHA-1"*), הפונקציה `generate_sha1_reset_token()` מייצרת אנטרופיה קריפטוגרפית (`os.urandom(32)`) יחד עם חותמת זמן ומפיקה טוקן של 40 תווים באמצעות `hashlib.sha1().hexdigest()`.
* הטוקן נשמר בטבלת `password_resets` עם תוקף של 15 דקות ודגל `used = 0` (חד-פעמי).

---

### 3. מנגנון שליחת המיילים ההיברידי (`Resend API` / `Brevo` / `SMTP` + `Web Mailbox`)

המערכת מממשת מנגנון שליחת מיילים כפול (Hybrid Dispatch) בקובץ `utils/mailer.py`:
1. **שמירה אוטומטית ב-Web Mailbox (`/mailbox`)**:
   * בכל בקשת איפוס סיסמה, המייל המלא (כולל קוד ה-`SHA-1` וקישור ישיר לאיפוס) נשמר ומוצג מיד בממשק **תיבת הדואר המובנית (`/mailbox`)** בסרגל הניווט העליון. כך הבודק יכול לבדוק את המערכת מיד וללא תלות בהגדרות חיצוניות.
2. **שליחת מייל אמיתי דרך `Resend API` (מומלץ) / `Brevo API` / `SMTP`**:
   * בעמוד `/mailbox` קיים כפתור **"⚙️ הגדרת שליחת מייל אמיתי (Resend / Brevo / SMTP)"** המאפשר להזין מפתח API ישירות מהדפדפן (נשמר אוטומטית ב-`config/email_config.json` של שתי הגרסאות).
   * **הגדרת Resend API ב-30 שניות**:
     1. נרשמים בחינם ב-[resend.com](https://resend.com) ומייצרים מפתח API (`re_...`).
     2. מדביקים את המפתח בפאנל ההגדרות בעמוד `/mailbox`.
     3. מזינים בשדה **`Override Recipient Email`** את כתובת המייל האישית שאיתה נרשמתם ל-Resend.
     4. מעתה, גם כשמבקשים איפוס סיסמה עבור משתמש הדמו `admin_cyber` (`admin@comunication-ltd.co.il`), המערכת תנתב אוטומטית את המייל האמיתי עם טוקן ה-`SHA-1` ישירות לתיבת הדואר האישית שלכם!

---

### 4. חלק ב' – השוואת הגרסה הפגיעה מול הגרסה המאובטחת (XSS & SQLi)

בגרסה הפגיעה (`vulnerable_version`) שולבו בכל מסך **פאנלים אינטראקטיביים של מעבדת תקיפה** עם כפתורי **"העתק פיילוד"** ו-**"הזרק לטופס"** להדגמה מיידית של החולשות:

| מסך / רכיב | 🔴 מימוש בגרסה הפגיעה (`vulnerable_version`) | פיילוד תקיפה להדגמה | 🟢 תיקון בגרסה המאובטחת (`secure_version`) |
| :--- | :--- | :--- | :--- |
| **1. מסך התחברות (`/login`) – SQLi Bypass** | שרשור מחרוזת ישיר בשאילתה:<br>`f"SELECT * FROM users WHERE username = '{username}'"` | `admin_cyber' --` (ללא הזנת סיסמה כלל – עוקף אימות ומתחבר כ-Admin!) | **Parameterized Query**:<br>`cursor.execute("SELECT * FROM users WHERE username = ?", (username,))` + אימות HMAC מלא. |
| **2. חיפוש לקוחות (`/dashboard`) – UNION SQLi** | שרשור פרמטר החיפוש ישירות ל-`LIKE`:<br>`f"... WHERE c.full_name LIKE '%{search_query}%'"` | `' UNION SELECT u.id, u.username, u.email, u.salt, u.password_hash, 'סקטור', 'חבילה', 'סיסמה מוצפנת ב-HMAC' FROM users u --` (מדליף את כל טבלת המשתמשים והסיסמאות למסך!) | **Parameterized Query**:<br>`WHERE c.full_name LIKE ? OR c.identity_number LIKE ?` עם `("%" + search_query + "%",)`. |
| **3. מסך הרשמה (`/register`) – SQLi** | בדיקת קיום משתמש בשרשור ישיר:<br>`f"SELECT * FROM users WHERE username = '{username}'..."` | `test' OR '1'='1` | **Parameterized Query** + **Regex Whitelisting** (`^[a-zA-Z0-9_\u0590-\u05fe]{3,30}$`) + `html.escape()`. |
| **4. הוספת לקוח (`/dashboard`) – Stored XSS** | שמירת שם הלקוח והערות ללא סינון והצגתם בתבנית עם הפילטר העוקף קידוד:<br>`{{ new_customer_name \| safe }}` ו-`{{ c[1] \| safe }}` | `<script>alert('Stored XSS - Comunication_LTD!');</script>` (נשמר ב-DB ומקפיץ חלון JS בכל טעינת דף!) | 1. קידוד ישויות HTML בצד השרת: `html.escape(raw_name)`.<br>2. הסרת `\| safe` בתבנית `dashboard.html`.<br>3. הזרקת כותרת HTTP **`Content-Security-Policy (CSP)`** החוסמת הרצת Inline Scripts זדוניים. |
