# Project Structure

```
CodeAlpha_Secure-Coding-Review-main/
├── README.md                          # Original project README
├── CodeReview.pdf                     # PDF review document
│
├── WORKING CODE FILES (Ready to Run)
├── app_xss.py                         # XSS vulnerability Flask app
├── app_csrf.py                        # CSRF vulnerability Flask app
├── app_login.py                       # Login security Flask app
├── test_offline.py                    # Offline test runner
│
├── DOCUMENTATION
├── QUICKSTART.md                      # Quick start guide
├── PROJECT_SUMMARY.md                 # This file
├── secure-coding-examples.md          # JavaScript/Node.js examples
├── secure-coding-python.md            # Python code examples
│
├── CONFIGURATION
├── requirements.txt                   # Python dependencies
│
└── TEMPLATES (HTML)
    └── templates/
        ├── transfer_form.html         # CSRF protected form
        └── user_profile.html          # XSS safe template
```

## File Descriptions

### 📱 Flask Applications

| File | Purpose | Port | Features |
|------|---------|------|----------|
| `app_xss.py` | XSS vulnerability tests | 5001 | Vulnerable & secure versions, HTML escaping, Bleach sanitization |
| `app_csrf.py` | CSRF protection tests | 5002 | Flask-WTF tokens, manual tokens, API protection |
| `app_login.py` | Login security tests | 5003 | Rate limiting, account lockout, password validation, registration |
| `test_offline.py` | Offline tests | N/A | Unit tests, no server needed |

### 📚 Documentation

| File | Contains |
|------|----------|
| `QUICKSTART.md` | How to install, run, and test the code |
| `PROJECT_SUMMARY.md` | Overview of all vulnerabilities and implementations |
| `secure-coding-python.md` | Detailed Python code examples for all 5 vulnerabilities |
| `secure-coding-examples.md` | Detailed JavaScript/Node.js code examples |
| `README.md` | Original project information |

### 📋 Configuration

| File | Purpose |
|------|---------|
| `requirements.txt` | Lists all Python package dependencies |

### 🎨 Templates

| File | Used By | Purpose |
|------|---------|---------|
| `transfer_form.html` | app_csrf.py | CSRF-protected form template |
| `user_profile.html` | app_xss.py | Jinja2 template with auto-escaping |

---

## 🚀 Getting Started

### Quick Install (3 steps)

1. **Navigate to project:**
   ```bash
   cd CodeAlpha_Secure-Coding-Review-main
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run tests:**
   ```bash
   python test_offline.py
   ```

Or run interactive web tests:
```bash
python app_login.py    # Open http://localhost:5003/test/login
```

---

## 📊 What's Covered

### 5 Major Vulnerabilities

1. **XSS (Cross-Site Scripting)**
   - File: `app_xss.py`
   - Docs: `secure-coding-python.md` Section 1
   - Protection: Output escaping, HTML sanitization

2. **CSRF (Cross-Site Request Forgery)**
   - File: `app_csrf.py`
   - Docs: `secure-coding-python.md` Section 2
   - Protection: CSRF tokens, token validation

3. **NoSQL Injection**
   - File: `secure-coding-python.md` Section 3
   - Protection: Input validation, parameterized queries

4. **Brute Force Login**
   - File: `app_login.py`
   - Docs: `secure-coding-python.md` Section 4
   - Protection: Rate limiting, account lockout

5. **Weak Passwords**
   - File: `app_login.py`
   - Docs: `secure-coding-python.md` Section 5
   - Protection: Password validation, bcrypt hashing

---

## 🧪 Testing Guide

### XSS Tests
```bash
python app_xss.py
# Visit http://localhost:5001/test/xss
```

**Test:** Try user ID `2` in both vulnerable and secure versions

### CSRF Tests
```bash
python app_csrf.py
# Visit http://localhost:5002/test/csrf
```

**Test:** Submit vulnerable and secure forms, check token requirements

### Login Tests
```bash
python app_login.py
# Visit http://localhost:5003/test/login
```

**Credentials:** `john` / `SecurePassword123!`

**Tests:**
- Try 10 wrong passwords → account locks
- Try weak password → registration fails
- Use strong password → registration succeeds

---

## 🔐 Security Features Demonstrated

| Feature | Implementation | File |
|---------|----------------|------|
| Output Escaping | Flask escape(), Jinja2 | app_xss.py |
| HTML Sanitization | Bleach library | app_xss.py |
| CSRF Protection | Flask-WTF tokens | app_csrf.py |
| Rate Limiting | Manual tracking, Redis | app_login.py |
| Account Lockout | Failed attempt counter | app_login.py |
| Password Hashing | Bcrypt with 12 rounds | app_login.py |
| Password Validation | Regex + strength rules | app_login.py |
| Input Validation | Type & length checks | All apps |

---

## 📦 Dependencies

### Core Framework
- `flask` - Web framework
- `flask-limiter` - Rate limiting
- `flask-wtf` - CSRF protection

### Security
- `bcrypt` - Password hashing
- `password-validator` - Password strength checking
- `bleach` - HTML sanitization
- `markupsafe` - Safe HTML escaping

### Database
- `redis` - Cache/rate limiter storage
- `pymongo` - MongoDB driver
- `mongoengine` - MongoDB ORM

---

## 🎯 Learning Outcomes

After using this project, you'll understand:

✅ How XSS attacks work and how to prevent them  
✅ How CSRF attacks work and how to prevent them  
✅ How injection attacks work and how to prevent them  
✅ How brute force attacks work and how to prevent them  
✅ Password security best practices  
✅ Industry standards (OWASP, CWE, NIST)  
✅ Secure coding principles and patterns  
✅ Testing security vulnerabilities  

---

## 🔗 References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [NIST 800-218](https://csrc.nist.gov/publications/detail/sp/800-218/final)

---

## ✨ Summary

**Complete, runnable secure coding review project with:**
- 3 interactive Flask applications
- 5 vulnerable & secure code pairs
- Comprehensive documentation
- Ready-to-use security patterns
- Test cases for all vulnerabilities

**Status: ✅ Ready to use and test!**
