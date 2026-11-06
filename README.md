# Comunication_LTD - פרויקט סיום בסייבר (Cyber Security Final Project)

פרויקט זה מציג מערכת מידע ווב ומסד נתונים רלציוני עבור חברת התקשורת הדמיונית **Comunication_LTD**, המשווקת חבילות גלישה באינטרנט ללקוחות במגוון סקטורים.

הפרויקט בנוי בהתאם לכל דרישות מסמך ההנחיות ומוגש ב-**2 גרסאות מלאות**:
1. **גרסה פגיעה (`vulnerable_version`)**: קוד המכיל חולשות אבטחה מובְנות להדגמת מתקפות **Stored XSS** ו-**SQL Injection (SQLi)**.
2. **גרסה מאובטחת (`secure_version`)**: קוד מתוקן ומאובטח באופן הרמטי באמצעות **Parameterized Queries**, **קידוד תווים מיוחדים (Sanitization & HTML Entity Encoding)**, **Content-Security-Policy**, ואימות קלט קפדני.

---

## 📂 מבנה התיקיות בפרויקט

```
c:\project security\
├── vulnerable_version\              # גרסה 1: קוד פגיע להדגמת מתקפות (Port 5001)
│   ├── config\
│   │   └── password_policy.json     # קובץ קונפיגורציית סיסמאות הניתן לשינוי
│   ├── database\
│   │   ├── schema.sql               # סכמת מסד הנתונים הרלציוני
│   │   ├── init_db.py               # סקריפט אתחול והזנת נתונים ראשוניים
│   │   └── comunication_ltd.db      # מסד נתונים SQLite
│   ├── static\css\style.css
│   ├── templates\                   # תבניות HTML (מציגות פרצות בגרסה זו)
│   ├── utils\
│   │   ├── auth_helpers.py          # מימוש HMAC + Salt, טוקן SHA-1, ואימות מורכבות
│   │   └── mailer.py                # סימולטור שליחת מיילים עם תיבת דואר ייעודית
│   └── app.py                       # שרת Flask של הגרסה הפגיעה
│
├── secure_version\                  # גרסה 2: קוד מוגן ומאובטח (Port 5002)
│   ├── config\
│   │   └── password_policy.json
│   ├── database\
│   │   ├── schema.sql
│   │   ├── init_db.py
│   │   └── comunication_ltd.db
│   ├── static\css\style.css
│   ├── templates\                   # תבניות מאובטחות (ללא | safe, עם קידוד)
│   ├── utils\
│   │   ├── auth_helpers.py
│   │   └── mailer.py
│   └── app.py                       # שרת Flask מאובטח (Parameters + Anti-XSS)
│
├── run_vulnerable.bat               # הפעלה בלחיצה של הגרסה הפגיעה
├── run_secure.bat                   # הפעלה בלחיצה של הגרסה המאובטחת
├── README.md                        # מדריך זה
└── CYBER_SECURITY_REPORT.md         # דו"ח הגשה אקדמי מפורט עם צילומי פיילודים
```

---

## 🚀 הוראות הרצה מהירה

### 1. הפעלת המערכת הראשית (חלק א' - גרסה מאובטחת)
להרצה ישירה דרך PowerShell / Command Prompt:
```cmd
python app.py
```
* השרת יעלה ישירות בכתובת: **`http://127.0.0.1:5000`**

### 2. הפעלת הגרסה הפגיעה (Vulnerable App)
```cmd
run_vulnerable.bat
```
* השרת יעלה בכתובת: **`http://127.0.0.1:5001`**
* בגרסה זו ניתן לבצע הדגמת עקיפת התחברות (SQLi Bypass), הדלפת נתונים באמצעות UNION SQLi, והזרקת Stored XSS.

### 3. הפעלת הגרסה המאובטחת (Secure App)
```cmd
run_secure.bat
```
* השרת יעלה בכתובת: **`http://127.0.0.1:5002`**
* בגרסה זו כל המתקפות נחסמות: שאילתות מפורמטות (Parameters), סינון תווים, קידוד HTML Entities, וכותרות Content-Security-Policy.

---

## 🔑 פרטי התחברות ראשוניים (Default Credentials)

| תפקיד | שם משתמש | סיסמה (עומדת בדרישות המורכבות) |
|---|---|---|
| מנהל אבטחה (Admin) | `admin_cyber` | `Cyber@2026Admin!` |
| משתמש רגיל | `user_israel` | `P@ssw0rdSecure!` |

---

## ⚙️ קובץ קונפיגורציה לניהול מדיניות סיסמאות (`password_policy.json`)

קובץ זה ממוקם ב-`config/password_policy.json` בכל גרסה, וערכיו נקראים דינמית:
```json
{
  "password_policy": {
    "min_length": 10,
    "require_uppercase": true,
    "require_lowercase": true,
    "require_digits": true,
    "require_special_characters": true,
    "special_characters_allowed": "!@#$%^&*()_+-=[]{}|;:,.<>?",
    "history_count": 3,
    "max_login_attempts": 3,
    "lockout_duration_minutes": 15,
    "dictionary_blacklist": [
      "password",
      "1234567890",
      "comunication",
      "communication",
      "qwertyuiop",
      "admin12345",
      "iloveyou123",
      "welcome123"
    ]
  }
}
```

---

## 🛡️ פירוט מימוש הדרישות

### חלק א' – עקרונות פיתוח מאובטח
1. **מסך Register:**
   * הגדרת משתמשים חדשים עם אימות מייל תקין.
   * אכיפת סיסמה מורכבת מול הקונפיגורציה (אורך 10+, אותיות גדולות, קטנות, ספרות, תווים מיוחדים, ומניעת מילון).
   * **שמירת סיסמה באמצעות פונקציית HMAC + Salt:** לכל משתמש מופק Salt אקראי קריפטוגרפי (`os.urandom(16).hex()`), והסיסמה נשמרת כ-`HMAC-SHA256(secret_key, salt + password)`.
2. **מסך שינוי סיסמה:**
   * אימות סיסמה נוכחית.
   * אכיפת היסטוריית סיסמאות: בדיקה מול 3 הסיסמאות האחרונות (`history_count`) ומניעת שימוש חוזר בהן.
3. **מסך Login:**
   * הזנת יוזר וסיסמה ואימות מול ה-DB.
   * הגבלת 3 ניסיונות כושלים ונעילת חשבון ל-15 דקות.
4. **מסך מערכת (Dashboard):**
   * הכנסת לקוח חדש עם שיוך לסקטור שיווקי וחבילת גלישה.
   * הצגת שם הלקוח החדש שהוזן על גבי המסך, לצד טבלת לקוחות מלאה.
5. **מסך שכח סיסמה:**
   * הפקת ערך אקראי **המוגדר באמצעות SHA-1** (`hashlib.sha1(random_bytes).hexdigest()`).
   * שליחת הערך למייל (או סימולטור תיבת דואר), אימות הטוקן ומעבר לקביעת סיסמה חדשה.

### חלק ב' – תרחישי תקיפה והגנה (XSS + SQLi)
* **Stored XSS במסך מערכת (סעיף 4):**
  * *פגיע:* קליטת שם הלקוח והצגתו ללא סינון באמצעות `| safe`. פיילוד כגון `<script>alert("Stored XSS");</script>` נשמר ב-DB ומורץ בכל כניסה.
  * *מאובטח:* שימוש בקידוד ישויות HTML (`html.escape`) ורינדור ברירת מחדל ב-Jinja2 ללא `| safe`.
* **SQL Injection (סעיפים 1, 3, 4):**
  * *פגיע:* שרשור מחרוזות ישיר בשאילתות SQL. ב-Login הזנת `admin_cyber' --` עוקפת אימות לחלוטין! בחיפוש לקוחות הזנת UNION SELECT מדליפה את כל משתמשי המערכת והסיסמאות.
  * *מאובטח:* שימוש ב-**Parameterized Queries (Prepared Statements)** בכל השאילתות + קידוד וסינון תווים מיוחדים.
