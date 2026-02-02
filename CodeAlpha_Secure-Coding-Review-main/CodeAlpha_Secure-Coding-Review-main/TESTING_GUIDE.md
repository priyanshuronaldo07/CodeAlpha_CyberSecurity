# Secure Coding Review - Testing Guide

## 📖 How to Run and Test

---

## Method 1: Offline Testing (Quickest)

### Run without installing any packages first:
```bash
python test_offline.py
```

### Expected Output:
```
╔═══════════════════════════════════════════════════════════╗
║     SECURE CODING REVIEW - TEST SUITE                    ║
║     CodeAlpha Internship Project                         ║
╚═══════════════════════════════════════════════════════════╝

Checking dependencies...
✅ All dependencies found!

============================================================
QUICK START GUIDE
============================================================

To run the interactive tests, start the Flask servers...

============================================================
Running Offline Tests...
============================================================

Password Validation Tests:

  WEAK: password
  ❌ Invalid
    - At least 12 characters
    - At least one uppercase letter
    - At least one digit
    - At least one special character

  MEDIUM: Password123
  ❌ Invalid
    - At least 12 characters
    - At least one special character

  STRONG: SecurePassword123!
  ✅ Valid
```

---

## Method 2: Run Flask Apps (Interactive Testing)

### Start Each App in Separate Terminals:

#### Terminal 1 - XSS Tests
```bash
python app_xss.py
```

Output:
```
XSS Test Server running on http://localhost:5001
Visit http://localhost:5001/test/xss to run tests
 * Running on http://localhost:5001
```

Then open browser: `http://localhost:5001/test/xss`

---

#### Terminal 2 - CSRF Tests  
```bash
python app_csrf.py
```

Output:
```
CSRF Test Server running on http://localhost:5002
Visit http://localhost:5002/test/csrf to run tests
 * Running on http://localhost:5002
```

Then open browser: `http://localhost:5002/test/csrf`

---

#### Terminal 3 - Login Tests
```bash
python app_login.py
```

Output:
```
Login Security Test Server running on http://localhost:5003
Visit http://localhost:5003/test/login to run tests

Test Credentials:
  Username: john
  Password: SecurePassword123!
  
 * Running on http://localhost:5003
```

Then open browser: `http://localhost:5003/test/login`

---

## Test Case 1: XSS Vulnerability

### What to test:
1. Go to: `http://localhost:5001/test/xss`
2. Click each test button to see how XSS is prevented

### Expected Results:

**Vulnerable Version:**
- URL: `/vulnerable?id=2`
- Result: Shows `<script>alert("XSS")</script>` as HTML (script may try to run)
- Status: ❌ UNSAFE

**Secure with Escape:**
- URL: `/secure/escape?id=2`
- Result: Shows script text: `<script>alert("XSS")</script>`
- Status: ✅ SAFE

**Secure with Templates:**
- URL: `/secure/template?id=2`
- Result: Shows plain text, properly escaped by Jinja2
- Status: ✅ SAFE

**Secure with Bleach:**
- URL: `/secure/bleach?id=1`
- Result: Shows HTML with only safe tags allowed
- Status: ✅ SAFE

### What's Happening:
- XSS exploits: User input `<script>` gets rendered as code
- Protection: Escaping converts `<` to `&lt;` so it displays as text
- Result: Script can't execute, malicious code is neutralized

---

## Test Case 2: CSRF Attack

### What to test:
1. Go to: `http://localhost:5002/test/csrf`
2. Try vulnerable and secure forms

### Expected Results:

**Vulnerable Transfer:**
- Submits without CSRF token
- Form accepts request directly
- Status: ❌ UNSAFE - Can be attacked from external sites

**Secure Transfer:**
- Form includes hidden CSRF token
- Token must match server session
- Status: ✅ SAFE - Token validates origin

**API Transfer:**
- Click "Test API Transfer with CSRF" button
- Gets token first, then makes request with token in header
- Status: ✅ SAFE - API protected by token

### What's Happening:
- CSRF exploits: External site tricks you into making requests
- Protection: Unique token proves request came from your browser
- Result: Can't forge requests from external sites

---

## Test Case 3: Brute Force Attack & Password Security

### What to test:
1. Go to: `http://localhost:5003/test/login`
2. Test different scenarios

### Scenario A: Successful Login
**Steps:**
1. Enter username: `john`
2. Enter password: `SecurePassword123!`
3. Click "Login (Protected)"

**Expected Result:**
```json
{
  "success": true,
  "message": "Logged in securely",
  "user_id": 1
}
```

### Scenario B: Simulate Brute Force Attack
**Steps:**
1. Click "Simulate 10 Failed Attempts"
2. Watch the login attempts counter

**Expected Results:**
```
Attempt 1: Invalid credentials. 4 attempts remaining
Attempt 2: Invalid credentials. 3 attempts remaining
Attempt 3: Invalid credentials. 2 attempts remaining
Attempt 4: Invalid credentials. 1 attempts remaining
Attempt 5: Invalid credentials. 0 attempts remaining
Attempt 6: Account locked due to too many failed attempts
Attempt 7: Account locked due to too many failed attempts
...
```

**Status:** ✅ SAFE - Account locked after 5 failed attempts

### Scenario C: Weak Password Registration
**Steps:**
1. Go to "Register New User" section
2. Enter username: `testuser`
3. Enter email: `test@example.com`
4. Enter password: `password`
5. Click "Register"

**Expected Result:**
```json
{
  "error": "Password does not meet requirements",
  "requirements": [
    "At least 12 characters",
    "At least one uppercase letter",
    "At least one digit",
    "At least one special character"
  ]
}
```

**Status:** ❌ REJECTED - Password too weak

### Scenario D: Strong Password Registration
**Steps:**
1. Enter username: `newuser`
2. Enter email: `newuser@example.com`
3. Enter password: `MyPassword123!`
4. Click "Register"

**Expected Result:**
```json
{
  "success": true,
  "message": "Registration successful"
}
```

**Status:** ✅ ACCEPTED - Password meets all requirements

---

## Test Results Summary

### XSS Protection
- ✅ Vulnerable version shows the danger
- ✅ Secure versions properly escape output
- ✅ No JavaScript execution in secure versions

### CSRF Protection
- ✅ Vulnerable form allows direct submission
- ✅ Secure forms require valid token
- ✅ Tokens prevent cross-site attacks

### Brute Force Protection
- ✅ Rate limiting prevents unlimited attempts
- ✅ Account lockout triggers after 5 failures
- ✅ 30-minute timeout before retry possible

### Password Security
- ✅ Weak passwords rejected
- ✅ Strong passwords required
- ✅ Passwords hashed with bcrypt (not plain text)

---

## Troubleshooting

### Problem: "ModuleNotFoundError"
**Solution:**
```bash
pip install -r requirements.txt
```

### Problem: "Address already in use"
**Solution:** Port is already taken, try:
```bash
# Change port in code:
# From: app.run(debug=True, port=5001)
# To:   app.run(debug=True, port=5004)
```

### Problem: "Connection refused"
**Solution:** Make sure the Flask app is running in terminal before visiting URL

### Problem: CSRF form shows error
**Solution:** Clear browser cookies and restart the Flask app

---

## Code Analysis

### XSS Vulnerable Code:
```python
# ❌ BAD
html = f"<h1>Welcome {user_input}</h1>"
```

### XSS Secure Code:
```python
# ✅ GOOD
html = f"<h1>Welcome {escape(user_input)}</h1>"
```

---

### CSRF Vulnerable Code:
```python
# ❌ BAD
@app.route('/transfer', methods=['POST'])
def transfer():
    amount = request.form.get('amount')
    db.transfer_money(amount)  # No token check!
```

### CSRF Secure Code:
```python
# ✅ GOOD
@app.route('/transfer', methods=['POST'])
@csrf.protect  # Requires valid token
def transfer():
    amount = request.form.get('amount')
    db.transfer_money(amount)
```

---

### Brute Force Vulnerable Code:
```python
# ❌ BAD
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    user = db.find_user(username)
    if user and verify_password(password, user['hash']):
        return success()
    # No rate limiting!
```

### Brute Force Secure Code:
```python
# ✅ GOOD
@app.route('/login', methods=['POST'])
@limiter.limit("5 per 15 minutes")  # Max 5 attempts
def login():
    username = request.form.get('username')
    
    # Check if account locked
    if is_account_locked(username):
        return {'error': 'Account locked'}, 403
    
    password = request.form.get('password')
    user = db.find_user(username)
    
    if user and verify_password(password, user['hash']):
        return success()
    
    # Lock account after 5 failed attempts
    increment_failed_attempts(username)
```

---

## Performance Notes

- **Offline tests:** Run in < 1 second
- **Flask startup:** ~2-3 seconds
- **First page load:** ~1 second
- **Login test:** ~0.5 seconds per attempt

---

## Security Verification

✅ All code uses secure practices  
✅ No hardcoded secrets (except test credentials)  
✅ No SQL injection vulnerabilities  
✅ Passwords properly hashed with bcrypt  
✅ CSRF tokens properly generated and validated  
✅ Output properly escaped and sanitized  
✅ Input properly validated and sanitized  
✅ Rate limiting implemented  
✅ Account lockout implemented  

---

## Next Steps

1. **Study the code:** Read both vulnerable and secure versions
2. **Understand the patterns:** Learn why each protection works
3. **Apply to your projects:** Use these patterns in real applications
4. **Read the references:** Check OWASP and CWE documentation
5. **Build secure:** Make security a habit in all your coding

---

## References

- OWASP Top 10: https://owasp.org/www-project-top-ten/
- CWE Top 25: https://cwe.mitre.org/top25/
- NIST 800-218: https://csrc.nist.gov/publications/detail/sp/800-218/final
- Flask Security: https://flask.palletsprojects.com/security/

---

## Success Checklist

- [ ] Installed dependencies (`pip install -r requirements.txt`)
- [ ] Ran offline tests (`python test_offline.py`)
- [ ] Started XSS Flask app (`python app_xss.py`)
- [ ] Started CSRF Flask app (`python app_csrf.py`)
- [ ] Started Login Flask app (`python app_login.py`)
- [ ] Tested XSS vulnerabilities
- [ ] Tested CSRF protection
- [ ] Tested brute force protection
- [ ] Tested password validation
- [ ] Reviewed code examples
- [ ] Understood security principles
- [ ] Ready to apply to your projects ✅

---

**Happy secure coding! 🔒**
