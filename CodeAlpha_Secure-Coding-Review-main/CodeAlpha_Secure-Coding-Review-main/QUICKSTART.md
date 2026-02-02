# Secure Coding Review - Quick Start Guide

## Installation

### 1. Install Python Dependencies
```bash
pip install -r requirements.txt
```

Or install individually:
```bash
pip install flask flask-limiter flask-wtf redis bcrypt password-validator bleach markupsafe
```

## Running the Tests

### Option 1: Run Offline Tests
```bash
python test_offline.py
```

This will show you:
- Password validation tests
- Summary of test cases
- Quick start instructions

### Option 2: Interactive Web Tests

**Terminal 1 - XSS Tests:**
```bash
python app_xss.py
```
Then open: `http://localhost:5001/test/xss`

**Terminal 2 - CSRF Tests:**
```bash
python app_csrf.py
```
Then open: `http://localhost:5002/test/csrf`

**Terminal 3 - Login Security Tests:**
```bash
python app_login.py
```
Then open: `http://localhost:5003/test/login`

## Test Credentials

| Field | Value |
|-------|-------|
| Username | john |
| Password | SecurePassword123! |

## What Each Test Does

### 1. XSS (Cross-Site Scripting) - `app_xss.py`

Tests different ways to prevent JavaScript injection:

- **Vulnerable**: Shows how malicious scripts execute
- **Secure (escape)**: Escapes HTML entities
- **Secure (template)**: Uses Jinja2 auto-escaping
- **Secure (bleach)**: Sanitizes HTML tags

Try with user ID `2` to see the vulnerable version.

### 2. CSRF (Cross-Site Request Forgery) - `app_csrf.py`

Tests CSRF token protection:

- **Vulnerable Transfer**: No token protection (can be attacked)
- **Secure Transfer**: Uses Flask-WTF CSRF token
- **API Transfer**: CSRF token in HTTP header

Try submitting forms from the test page to see the difference.

### 3. Login Security - `app_login.py`

Tests brute force protection and password requirements:

#### Rate Limiting:
- Try logging in with wrong password 6+ times
- After 5 failed attempts, account locks for 30 minutes
- Shows remaining attempts after each try

#### Password Requirements:
- Minimum 12 characters
- At least one uppercase letter
- At least one lowercase letter  
- At least one digit
- At least one special character

Example strong password: `MySecurePass123!`

#### Test Scenarios:
1. **Correct Login**: Use the credentials above
2. **Brute Force Protection**: Try 10 wrong passwords in a row
3. **Registration**: Try weak passwords, then strong ones

## Expected Results

### XSS Tests
- ❌ Vulnerable version: Shows `<script>alert("XSS")</script>` as HTML
- ✅ Secure versions: Show the script as plain text (properly escaped)

### CSRF Tests
- ❌ Vulnerable form: Submits without any token check
- ✅ Secure form: Includes hidden CSRF token in the form

### Login Tests
- ❌ Vulnerable: Can try unlimited password attempts
- ✅ Secure: Locks after 5 failed attempts
- ✅ Weak passwords rejected on registration
- ✅ Strong passwords accepted and bcrypt-hashed

## Troubleshooting

### Port Already in Use
If you get "Address already in use" error:

```bash
# Change the port in the code:
# Change: app.run(debug=True, port=5001)
# To:     app.run(debug=True, port=5004)
```

### Module Not Found
If you get "ModuleNotFoundError":

```bash
pip install -r requirements.txt
```

### Flask Not Starting
Make sure Python 3.7+ is installed:

```bash
python --version
```

## Files Included

| File | Purpose |
|------|---------|
| `app_xss.py` | XSS vulnerability demonstrations |
| `app_csrf.py` | CSRF token protection tests |
| `app_login.py` | Login security and brute force tests |
| `test_offline.py` | Offline test runner |
| `requirements.txt` | Python dependencies |
| `templates/transfer_form.html` | CSRF protected form template |
| `templates/user_profile.html` | XSS test template |
| `secure-coding-examples.md` | JavaScript code examples |
| `secure-coding-python.md` | Python code examples |

## Key Security Concepts Demonstrated

### 1. Input Validation
- Check data type and length
- Use regex for format validation
- Reject invalid input early

### 2. Output Escaping
- Escape HTML entities: `<` → `&lt;`
- Use template engines with auto-escaping
- Use sanitization libraries (Bleach)

### 3. CSRF Protection
- Generate unique tokens per session
- Include token in forms and API headers
- Validate token before processing state-changing requests

### 4. Authentication Security
- Hash passwords with bcrypt (not SHA256)
- Implement rate limiting
- Lock accounts after failed attempts
- Require strong passwords

### 5. Password Policy
- Minimum length (12+ characters)
- Mix of character types
- No common passwords
- Secure hashing algorithm (bcrypt)

## Next Steps

1. **Understand the code**: Read the vulnerable vs. secure versions
2. **Test thoroughly**: Try to break the secure versions
3. **Learn more**: Check OWASP and CWE references
4. **Implement**: Apply these patterns in your own projects

## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [NIST 800-218](https://csrc.nist.gov/publications/detail/sp/800-218/final)

## Contact

**Project**: CodeAlpha Secure Coding Review  
**Author**: Satvik Hatulkar  
**Email**: satwikhatulkar@gmail.com  
**GitHub**: [github.com/satvikhatulkar](https://github.com/SatvikHatulkar)
