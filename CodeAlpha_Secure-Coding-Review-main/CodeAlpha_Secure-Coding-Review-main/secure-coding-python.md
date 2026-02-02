# Secure Coding Review - Python Code Examples & Fixes

## 1. Cross-Site Scripting (XSS) - CVE-2024-6531

### ❌ VULNERABLE CODE
```python
# Flask - No sanitization
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/profile')
def profile():
    user_id = request.args.get('id')
    user_data = db.get_user_data(user_id)
    
    # Directly rendering user input - VULNERABLE!
    html = f"<h1>Welcome {user_data['name']}</h1>"
    return render_template_string(html)

# Jinja2 template without escaping
@app.route('/user/<name>')
def greet(name):
    return f"<div>Hello {name}</div>"
```

### ✅ SECURE CODE
```python
# Flask - With proper sanitization
from flask import Flask, request, render_template, escape
from markupsafe import Markup
import bleach

app = Flask(__name__)

# Method 1: Using Flask's escape
@app.route('/profile')
def profile():
    user_id = request.args.get('id')
    user_data = db.get_user_data(user_id)
    
    # Flask auto-escapes in templates, but explicitly escape if needed
    safe_name = escape(user_data['name'])
    html = f"<h1>Welcome {safe_name}</h1>"
    return html

# Method 2: Using Jinja2 templates (auto-escapes by default)
@app.route('/user/<name>')
def greet(name):
    return render_template('greet.html', name=name)
# Template: <div>Hello {{ name }}</div> - automatically escaped

# Method 3: Using Bleach for HTML sanitization
@app.route('/comment')
def add_comment():
    user_comment = request.form.get('comment')
    
    # Allow only specific HTML tags
    allowed_tags = ['b', 'i', 'u', 'p', 'br']
    sanitized = bleach.clean(user_comment, tags=allowed_tags)
    
    return render_template('comment.html', comment=sanitized)

# Method 4: HTML sanitization with more control
from html import escape as html_escape

@app.route('/post', methods=['POST'])
def create_post():
    title = request.form.get('title', '')
    content = request.form.get('content', '')
    
    # Escape HTML entities
    safe_title = html_escape(title)
    safe_content = html_escape(content)
    
    db.save_post(safe_title, safe_content)
    return render_template('post.html', title=safe_title, content=safe_content)
```

---

## 2. Cross-Site Request Forgery (CSRF)

### ❌ VULNERABLE CODE
```python
# Flask - No CSRF protection
from flask import Flask, request

app = Flask(__name__)

@app.route('/transfer-money', methods=['POST'])
def transfer_money():
    amount = request.form.get('amount')
    recipient_id = request.form.get('recipient_id')
    user_id = session.get('user_id')
    
    # No CSRF token validation - VULNERABLE!
    db.transfer_money(user_id, recipient_id, amount)
    return {'success': True}
```

### ✅ SECURE CODE
```python
# Flask - With CSRF protection
from flask import Flask, request, session, render_template
from flask_wtf.csrf import CSRFProtect
import secrets

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)
csrf = CSRFProtect(app)

# Method 1: Using Flask-WTF (Recommended)
@app.route('/transfer-form')
def transfer_form():
    return render_template('transfer.html')

@app.route('/transfer-money', methods=['POST'])
@csrf.protect
def transfer_money():
    amount = request.form.get('amount')
    recipient_id = request.form.get('recipient_id')
    user_id = session.get('user_id')
    
    # CSRF token is automatically validated by decorator
    db.transfer_money(user_id, recipient_id, amount)
    return {'success': True}

# transfer.html template
"""
<form method="POST" action="/transfer-money">
    {{ csrf_token() }}
    <input type="number" name="amount" required>
    <input type="text" name="recipient_id" required>
    <button type="submit">Transfer</button>
</form>
"""

# Method 2: Manual CSRF token generation and validation
import hashlib
import os

@app.route('/transfer-form')
def transfer_form():
    # Generate CSRF token
    csrf_token = hashlib.sha256(os.urandom(1024)).hexdigest()
    session['csrf_token'] = csrf_token
    return render_template('transfer.html', csrf_token=csrf_token)

@app.route('/transfer-money', methods=['POST'])
def transfer_money():
    # Validate CSRF token
    token_received = request.form.get('csrf_token')
    token_stored = session.get('csrf_token')
    
    if not token_received or token_received != token_stored:
        return {'error': 'CSRF token validation failed'}, 403
    
    amount = request.form.get('amount')
    recipient_id = request.form.get('recipient_id')
    user_id = session.get('user_id')
    
    db.transfer_money(user_id, recipient_id, amount)
    
    # Generate new token for next request
    session['csrf_token'] = hashlib.sha256(os.urandom(1024)).hexdigest()
    
    return {'success': True}

# Method 3: For AJAX requests
@app.route('/api/transfer', methods=['POST'])
def api_transfer():
    # Get CSRF token from header
    csrf_token = request.headers.get('X-CSRF-Token')
    
    if not csrf_token or csrf_token != session.get('csrf_token'):
        return {'error': 'CSRF token validation failed'}, 403
    
    data = request.get_json()
    user_id = session.get('user_id')
    
    db.transfer_money(user_id, data['recipient_id'], data['amount'])
    return {'success': True}
```

---

## 3. NoSQL Injection (MongoDB)

### ❌ VULNERABLE CODE
```python
# Flask + PyMongo - Vulnerable to NoSQL injection
from flask import Flask, request
from pymongo import MongoClient

app = Flask(__name__)
client = MongoClient('mongodb://localhost:27017/')
db = client['myapp']

@app.route('/search', methods=['POST'])
def search():
    query = request.form.get('query')
    
    # Directly using user input - VULNERABLE!
    # User can inject: {"$ne": ""} to bypass filters
    users = db.users.find({"name": query})
    
    return {'users': list(users)}

# Login vulnerable to NoSQL injection
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    
    # User can inject: {"$ne": null}
    user = db.users.find_one({
        "username": username,
        "password": password
    })
    
    if user:
        session['user_id'] = str(user['_id'])
        return {'success': True}
    return {'error': 'Invalid credentials'}, 401
```

### ✅ SECURE CODE
```python
# Flask + PyMongo - Secure implementation
from flask import Flask, request, session
from pymongo import MongoClient
from bson.errors import InvalidId
from bson.objectid import ObjectId
import re

app = Flask(__name__)
client = MongoClient('mongodb://localhost:27017/')
db = client['myapp']

# Method 1: Input validation and type checking
@app.route('/search', methods=['POST'])
def search():
    query = request.form.get('query', '').strip()
    
    # Validate input type and length
    if not isinstance(query, str) or len(query) > 100:
        return {'error': 'Invalid query'}, 400
    
    # Only allow alphanumeric and basic characters
    if not re.match(r'^[a-zA-Z0-9\s\-_.]*$', query):
        return {'error': 'Invalid characters in query'}, 400
    
    # Use regex with $regex operator safely
    users = list(db.users.find({
        "name": {"$regex": query, "$options": "i"}
    }).limit(10))
    
    # Remove sensitive data before returning
    for user in users:
        user.pop('_id', None)
        user.pop('password', None)
    
    return {'users': users}

# Method 2: Secure login with parameterized queries
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    
    # Validate input types
    if not isinstance(username, str) or not isinstance(password, str):
        return {'error': 'Invalid credentials'}, 401
    
    # Never store plain passwords - use hashing
    import hashlib
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    
    # Use typed query to prevent injection
    user = db.users.find_one({
        "username": {"$eq": username},  # Explicit equality operator
        "password_hash": {"$eq": password_hash}
    })
    
    if user:
        session['user_id'] = str(user['_id'])
        return {'success': True}
    
    return {'error': 'Invalid credentials'}, 401

# Method 3: Using Mongoengine with schema validation
from mongoengine import Document, StringField, EmailField, connect

connect('myapp')

class User(Document):
    username = StringField(required=True, unique=True, min_length=3, max_length=50)
    email = EmailField(required=True, unique=True)
    password_hash = StringField(required=True)
    
    meta = {'collection': 'users'}

@app.route('/search/safe', methods=['POST'])
def search_safe():
    query = request.form.get('query', '').strip()
    
    # Validate input
    if not isinstance(query, str) or len(query) > 100:
        return {'error': 'Invalid query'}, 400
    
    # Mongoengine handles parameterization automatically
    users = User.objects(username__icontains=query).limit(10)
    
    return {'users': [{'username': u.username, 'email': u.email} for u in users]}

# Method 4: Whitelist-based approach
@app.route('/filter', methods=['POST'])
def filter_users():
    filter_type = request.form.get('filter_type')
    filter_value = request.form.get('filter_value')
    
    # Whitelist allowed filter types
    allowed_filters = ['username', 'email', 'status']
    
    if filter_type not in allowed_filters:
        return {'error': 'Invalid filter'}, 400
    
    if not isinstance(filter_value, str) or len(filter_value) > 50:
        return {'error': 'Invalid filter value'}, 400
    
    # Build query safely
    query_dict = {filter_type: {"$regex": filter_value, "$options": "i"}}
    users = list(db.users.find(query_dict).limit(10))
    
    return {'users': users}
```

---

## 4. Brute Force Login Vulnerability

### ❌ VULNERABLE CODE
```python
# Flask - No rate limiting or account lockout
from flask import Flask, request, session
import hashlib

app = Flask(__name__)

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    user = db.find_user(username)
    
    if not user or user['password_hash'] != password_hash:
        return {'error': 'Invalid credentials'}, 401  # No rate limiting!
    
    session['user_id'] = user['id']
    return {'success': True}
```

### ✅ SECURE CODE
```python
# Flask - With rate limiting and account lockout
from flask import Flask, request, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime, timedelta
import hashlib
import redis

app = Flask(__name__)

# Rate limiting setup
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    storage_uri="redis://localhost:6379"
)

# Redis connection for tracking failed attempts
redis_client = redis.Redis(host='localhost', port=6379, db=0)

# Method 1: Using Flask-Limiter
@app.route('/login', methods=['POST'])
@limiter.limit("5 per 15 minutes")  # 5 attempts per 15 minutes
def login():
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    
    # Validate input
    if not username or not password:
        return {'error': 'Missing credentials'}, 400
    
    user = db.find_user(username)
    
    if not user:
        return {'error': 'Invalid credentials'}, 401
    
    # Verify password
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    
    if user['password_hash'] != password_hash:
        return {'error': 'Invalid credentials'}, 401
    
    session['user_id'] = user['id']
    return {'success': True}

# Method 2: Manual account lockout implementation
@app.route('/login/secure', methods=['POST'])
def login_secure():
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    
    if not username or not password:
        return {'error': 'Missing credentials'}, 400
    
    # Check if account is locked
    lock_key = f"login_lock:{username}"
    if redis_client.exists(lock_key):
        return {'error': 'Account temporarily locked. Try again later.'}, 403
    
    # Get failed attempts count
    attempts_key = f"login_attempts:{username}"
    failed_attempts = int(redis_client.get(attempts_key) or 0)
    
    if failed_attempts >= 5:
        # Lock account for 30 minutes
        redis_client.setex(lock_key, 30 * 60, "locked")
        return {'error': 'Account locked due to multiple failed attempts'}, 403
    
    user = db.find_user(username)
    
    if not user:
        # Increment failed attempts
        redis_client.incr(attempts_key)
        redis_client.expire(attempts_key, 15 * 60)  # Expire after 15 minutes
        return {'error': 'Invalid credentials'}, 401
    
    # Verify password using bcrypt (better than SHA256)
    import bcrypt
    if not bcrypt.checkpw(password.encode(), user['password_hash'].encode()):
        redis_client.incr(attempts_key)
        redis_client.expire(attempts_key, 15 * 60)
        return {'error': 'Invalid credentials'}, 401
    
    # Successful login - clear failed attempts
    redis_client.delete(attempts_key)
    redis_client.delete(lock_key)
    
    # Update last login
    db.update_user(user['id'], {
        'last_login': datetime.now(),
        'failed_attempts': 0,
        'locked': False
    })
    
    session['user_id'] = user['id']
    return {'success': True}

# Method 3: Database-based account lockout
@app.route('/login/database', methods=['POST'])
def login_with_db_lockout():
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    
    user = db.find_user(username)
    
    if not user:
        return {'error': 'Invalid credentials'}, 401
    
    # Check if account is locked
    if user.get('locked') and user.get('lock_until'):
        if datetime.now() < datetime.fromisoformat(user['lock_until']):
            return {'error': 'Account temporarily locked'}, 403
        else:
            # Unlock account after timeout
            db.update_user(user['id'], {'locked': False, 'lock_until': None})
    
    # Verify password
    import bcrypt
    if not bcrypt.checkpw(password.encode(), user['password_hash'].encode()):
        # Increment failed attempts
        failed_attempts = user.get('failed_attempts', 0) + 1
        
        update_data = {'failed_attempts': failed_attempts}
        
        # Lock account after 5 failed attempts
        if failed_attempts >= 5:
            update_data['locked'] = True
            update_data['lock_until'] = (datetime.now() + timedelta(minutes=30)).isoformat()
        
        db.update_user(user['id'], update_data)
        return {'error': 'Invalid credentials'}, 401
    
    # Successful login
    db.update_user(user['id'], {
        'failed_attempts': 0,
        'locked': False,
        'lock_until': None,
        'last_login': datetime.now()
    })
    
    session['user_id'] = user['id']
    return {'success': True}

# Method 4: IP-based rate limiting
from functools import wraps

def ip_rate_limit(max_attempts=10, window_minutes=60):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            ip = get_remote_address()
            key = f"ip_attempts:{ip}"
            
            attempts = int(redis_client.get(key) or 0)
            
            if attempts >= max_attempts:
                return {'error': 'Too many attempts from your IP'}, 429
            
            redis_client.incr(key)
            redis_client.expire(key, window_minutes * 60)
            
            return f(*args, **kwargs)
        return wrapper
    return decorator

@app.route('/login/ip-limit', methods=['POST'])
@ip_rate_limit(max_attempts=20, window_minutes=60)
def login_with_ip_limit():
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    
    user = db.find_user(username)
    if not user or not verify_password(password, user['password_hash']):
        return {'error': 'Invalid credentials'}, 401
    
    session['user_id'] = user['id']
    return {'success': True}
```

---

## 5. Weak Password Policy

### ❌ VULNERABLE CODE
```python
# Flask - No password validation
from flask import Flask, request
import hashlib

app = Flask(__name__)

@app.route('/register', methods=['POST'])
def register():
    username = request.form.get('username')
    password = request.form.get('password')
    
    # No password requirements!
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    
    db.create_user({
        'username': username,
        'password_hash': password_hash
    })
    
    return {'success': True}
```

### ✅ SECURE CODE
```python
# Flask - With strong password policy
from flask import Flask, request
import re
import bcrypt
from datetime import datetime

app = Flask(__name__)

# Method 1: Custom password validator
def validate_password(password):
    """
    Validate password meets security requirements:
    - At least 12 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character
    """
    errors = []
    
    if len(password) < 12:
        errors.append("Password must be at least 12 characters long")
    
    if not re.search(r'[A-Z]', password):
        errors.append("Password must contain at least one uppercase letter")
    
    if not re.search(r'[a-z]', password):
        errors.append("Password must contain at least one lowercase letter")
    
    if not re.search(r'[0-9]', password):
        errors.append("Password must contain at least one digit")
    
    if not re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]', password):
        errors.append("Password must contain at least one special character")
    
    if ' ' in password:
        errors.append("Password cannot contain spaces")
    
    # Check against common passwords
    common_passwords = [
        'password123', 'admin123', '12345678', 'qwerty123',
        'letmein', 'welcome123', 'monkey123', 'dragon123'
    ]
    
    if password.lower() in common_passwords:
        errors.append("Password is too common")
    
    return len(errors) == 0, errors

@app.route('/register', methods=['POST'])
def register():
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    email = request.form.get('email', '').strip()
    
    # Validate inputs
    if not username or not password or not email:
        return {'error': 'Missing required fields'}, 400
    
    if len(username) < 3 or len(username) > 50:
        return {'error': 'Username must be 3-50 characters'}, 400
    
    if not re.match(r'^[a-zA-Z0-9_-]+$', username):
        return {'error': 'Username contains invalid characters'}, 400
    
    # Validate password
    is_valid, errors = validate_password(password)
    if not is_valid:
        return {'errors': errors}, 400
    
    # Validate email
    if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
        return {'error': 'Invalid email format'}, 400
    
    # Check if user already exists
    if db.find_user(username):
        return {'error': 'Username already exists'}, 409
    
    if db.find_user_by_email(email):
        return {'error': 'Email already registered'}, 409
    
    # Hash password with bcrypt
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
    
    db.create_user({
        'username': username,
        'email': email,
        'password_hash': password_hash,
        'created_at': datetime.now(),
        'password_changed_at': datetime.now()
    })
    
    return {'success': True, 'message': 'Registration successful'}, 201

# Method 2: Using password-validator library
from password_validator import PasswordValidator

schema = PasswordValidator()
schema.min(12).max(128).uppercase().lowercase().digits().symbols().no().spaces()

@app.route('/register/validator', methods=['POST'])
def register_with_validator():
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    email = request.form.get('email', '').strip()
    
    # Validate password strength
    if not schema.validate(password):
        return {
            'error': 'Password does not meet security requirements',
            'requirements': [
                'At least 12 characters',
                'At least one uppercase letter',
                'At least one lowercase letter',
                'At least one digit',
                'At least one special character',
                'No spaces'
            ]
        }, 400
    
    # Hash and save
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
    
    db.create_user({
        'username': username,
        'email': email,
        'password_hash': password_hash,
        'created_at': datetime.now()
    })
    
    return {'success': True}, 201

# Method 3: Password history check
@app.route('/change-password', methods=['POST'])
def change_password():
    user_id = session.get('user_id')
    old_password = request.form.get('old_password', '')
    new_password = request.form.get('new_password', '')
    
    user = db.find_user_by_id(user_id)
    
    # Verify old password
    if not bcrypt.checkpw(old_password.encode(), user['password_hash'].encode()):
        return {'error': 'Current password is incorrect'}, 401
    
    # Validate new password
    is_valid, errors = validate_password(new_password)
    if not is_valid:
        return {'errors': errors}, 400
    
    # Ensure new password is different from old
    if old_password == new_password:
        return {'error': 'New password must be different from current password'}, 400
    
    # Check password history (don't allow reuse of last 5 passwords)
    password_history = user.get('password_history', [])
    
    for old_hash in password_history[-5:]:
        if bcrypt.checkpw(new_password.encode(), old_hash.encode()):
            return {'error': 'Cannot reuse recent passwords'}, 400
    
    # Add current password to history
    new_history = password_history + [user['password_hash']]
    if len(new_history) > 5:
        new_history = new_history[-5:]
    
    # Hash new password
    new_password_hash = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt(rounds=12))
    
    db.update_user(user_id, {
        'password_hash': new_password_hash,
        'password_history': new_history,
        'password_changed_at': datetime.now()
    })
    
    return {'success': True, 'message': 'Password changed successfully'}, 200
```

---

## Best Practices Summary

| Vulnerability | Prevention Method |
|---|---|
| **XSS** | Use `escape()`, Jinja2 auto-escaping, Bleach, markupsafe |
| **CSRF** | Flask-WTF, CSRF tokens, SameSite cookies |
| **NoSQL Injection** | Input validation, type checking, Mongoengine, parameterized queries |
| **Brute Force** | Flask-Limiter, Redis rate limiting, account lockout, bcrypt |
| **Weak Passwords** | password-validator, regex validation, bcrypt with high rounds, entropy checks |

---

## Required Python Dependencies

```bash
pip install flask
pip install flask-limiter
pip install flask-wtf
pip install redis
pip install bcrypt
pip install password-validator
pip install pymongo
pip install mongoengine
pip install bleach
pip install markupsafe
```

---

## Installation & Setup

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Start Redis (for rate limiting)
# On Windows: Download from https://github.com/microsoftarchive/redis/releases
# On Linux/Mac: brew install redis or apt-get install redis-server
redis-server
```

---

## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [NIST 800-218](https://csrc.nist.gov/publications/detail/sp/800-218/final)
- [Python Security Best Practices](https://python.readthedocs.io/en/latest/library/security_warnings.html)
- [Flask Security](https://flask.palletsprojects.com/en/2.3.x/security/)
