"""
Login Security - Rate Limiting & Account Lockout
Test file to demonstrate brute force protection
"""

from flask import Flask, request, session, jsonify, render_template
from datetime import datetime, timedelta
import bcrypt
import re

app = Flask(__name__)
app.config['SECRET_KEY'] = 'test-secret-key'

# In-memory user database
users_db = {
    'john': {
        'id': 1,
        'email': 'john@example.com',
        'password_hash': bcrypt.hashpw(b'SecurePassword123!', bcrypt.gensalt(rounds=12)),
        'failed_attempts': 0,
        'locked': False,
        'lock_until': None,
        'created_at': datetime.now()
    }
}

# In-memory login attempts tracker
login_attempts = {}

def get_attempts_key(username):
    return f"attempts_{username}"

def get_lock_key(username):
    return f"lock_{username}"

# ❌ VULNERABLE - No rate limiting
@app.route('/vulnerable/login', methods=['POST'])
def vulnerable_login():
    """VULNERABLE: Anyone can brute force this endpoint"""
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    
    user = users_db.get(username)
    
    if not user or not bcrypt.checkpw(password.encode(), user['password_hash']):
        return {'error': 'Invalid credentials'}, 401
    
    session['user_id'] = user['id']
    return {'success': True, 'message': 'Logged in (UNSAFE!)'}

# ✅ SECURE - With rate limiting and account lockout
@app.route('/secure/login', methods=['POST'])
def secure_login():
    """SECURE: Protected against brute force attacks"""
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    
    # Validate input
    if not username or not password:
        return {'error': 'Username and password required'}, 400
    
    # Check if account is locked
    lock_key = get_lock_key(username)
    if lock_key in login_attempts:
        lock_data = login_attempts[lock_key]
        if datetime.now() < lock_data['until']:
            remaining = (lock_data['until'] - datetime.now()).seconds
            return {
                'error': f'Account locked. Try again in {remaining} seconds'
            }, 403
        else:
            # Unlock expired lock
            del login_attempts[lock_key]
    
    # Get failed attempts count
    attempts_key = get_attempts_key(username)
    if attempts_key in login_attempts:
        attempt_data = login_attempts[attempts_key]
        
        # Reset if time window expired (15 minutes)
        if datetime.now() > attempt_data['reset_at']:
            attempt_data['count'] = 0
            attempt_data['reset_at'] = datetime.now() + timedelta(minutes=15)
        
        if attempt_data['count'] >= 5:
            # Lock account for 30 minutes
            login_attempts[lock_key] = {
                'until': datetime.now() + timedelta(minutes=30)
            }
            del login_attempts[attempts_key]
            
            return {
                'error': 'Account locked due to too many failed attempts'
            }, 403
    else:
        # Initialize tracking
        login_attempts[attempts_key] = {
            'count': 0,
            'reset_at': datetime.now() + timedelta(minutes=15)
        }
    
    # Verify credentials
    user = users_db.get(username)
    
    if not user or not bcrypt.checkpw(password.encode(), user['password_hash']):
        # Increment failed attempts
        login_attempts[attempts_key]['count'] += 1
        remaining_attempts = 5 - login_attempts[attempts_key]['count']
        
        return {
            'error': f'Invalid credentials. {remaining_attempts} attempts remaining'
        }, 401
    
    # Successful login - reset failed attempts
    if attempts_key in login_attempts:
        del login_attempts[attempts_key]
    
    session['user_id'] = user['id']
    user['last_login'] = datetime.now()
    
    return {
        'success': True,
        'message': 'Logged in securely',
        'user_id': user['id']
    }

# ✅ SECURE - Password validation on registration
def validate_password(password):
    """Validate password strength"""
    errors = []
    
    if len(password) < 12:
        errors.append("At least 12 characters")
    if not re.search(r'[A-Z]', password):
        errors.append("At least one uppercase letter")
    if not re.search(r'[a-z]', password):
        errors.append("At least one lowercase letter")
    if not re.search(r'[0-9]', password):
        errors.append("At least one digit")
    if not re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",./<>?\\|`~]', password):
        errors.append("At least one special character")
    
    return len(errors) == 0, errors

@app.route('/secure/register', methods=['POST'])
def secure_register():
    """Register with strong password requirements"""
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    email = request.form.get('email', '').strip()
    
    # Validate inputs
    if not username or not password or not email:
        return {'error': 'All fields required'}, 400
    
    if len(username) < 3 or len(username) > 50:
        return {'error': 'Username must be 3-50 characters'}, 400
    
    # Check for valid characters
    if not re.match(r'^[a-zA-Z0-9_-]+$', username):
        return {'error': 'Username can only contain letters, numbers, dashes, underscores'}, 400
    
    # Validate password strength
    is_valid, errors = validate_password(password)
    if not is_valid:
        return {
            'error': 'Password does not meet requirements',
            'requirements': errors
        }, 400
    
    if username in users_db:
        return {'error': 'Username already exists'}, 409
    
    # Hash password with bcrypt (12 rounds)
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
    
    # Create user
    users_db[username] = {
        'id': len(users_db) + 1,
        'email': email,
        'password_hash': password_hash,
        'failed_attempts': 0,
        'locked': False,
        'created_at': datetime.now()
    }
    
    return {'success': True, 'message': 'Registration successful'}, 201

# Test page
@app.route('/test/login')
def test_login():
    return """
    <html>
    <head>
        <style>
            body { font-family: Arial; margin: 20px; }
            .section { margin-bottom: 30px; border: 1px solid #ccc; padding: 15px; }
            button { padding: 10px 20px; margin: 5px; cursor: pointer; }
            .vulnerable { background-color: #ffcccc; }
            .secure { background-color: #ccffcc; }
            input { padding: 8px; margin: 5px; width: 200px; }
            .result { margin-top: 10px; padding: 10px; background-color: #f0f0f0; }
        </style>
    </head>
    <body>
    <h1>Login Security Test</h1>
    
    <div class="section vulnerable">
        <h3>1. Vulnerable Login ❌</h3>
        <p>No rate limiting - can be brute forced!</p>
        <form action="/vulnerable/login" method="POST">
            Username: <input type="text" name="username" placeholder="john"><br>
            Password: <input type="password" name="password" placeholder="any"><br>
            <button type="submit">Login (Unprotected)</button>
        </form>
    </div>
    
    <div class="section secure">
        <h3>2. Secure Login ✅</h3>
        <p>Protected with rate limiting and account lockout</p>
        <p><strong>Credentials:</strong> username: john, password: SecurePassword123!</p>
        <form id="secure-form">
            Username: <input type="text" id="username" placeholder="john"><br>
            Password: <input type="password" id="password" placeholder="SecurePassword123!"><br>
            <button type="button" onclick="testSecureLogin()">Login (Protected)</button>
        </form>
        <div id="secure-result" class="result"></div>
    </div>
    
    <div class="section secure">
        <h3>3. Test Brute Force Protection</h3>
        <p>Try logging in with wrong password 6+ times to trigger lockout</p>
        <button onclick="testBruteForce()">Simulate 10 Failed Attempts</button>
        <div id="bruteforce-result" class="result"></div>
    </div>
    
    <div class="section secure">
        <h3>4. Register New User (Strong Password Required)</h3>
        <p>Password must have: 12+ chars, uppercase, lowercase, number, special char</p>
        <form id="register-form">
            Username: <input type="text" id="reg-username" placeholder="newuser"><br>
            Email: <input type="email" id="reg-email" placeholder="user@example.com"><br>
            Password: <input type="password" id="reg-password" 
                           placeholder="MyPassword123!"><br>
            <button type="button" onclick="testRegister()">Register</button>
        </form>
        <div id="register-result" class="result"></div>
    </div>
    
    <script>
    async function testSecureLogin() {
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        
        const response = await fetch('/secure/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: `username=${username}&password=${password}`
        });
        
        const result = await response.json();
        document.getElementById('secure-result').innerHTML = 
            '<pre>' + JSON.stringify(result, null, 2) + '</pre>';
    }
    
    async function testBruteForce() {
        let results = [];
        
        for (let i = 0; i < 10; i++) {
            const response = await fetch('/secure/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: 'username=john&password=wrongpassword'
            });
            
            const result = await response.json();
            results.push(`Attempt ${i+1}: ${result.error || result.success}`);
            
            if (response.status === 403) {
                break;
            }
        }
        
        document.getElementById('bruteforce-result').innerHTML = 
            '<pre>' + results.join('\\n') + '</pre>';
    }
    
    async function testRegister() {
        const username = document.getElementById('reg-username').value;
        const email = document.getElementById('reg-email').value;
        const password = document.getElementById('reg-password').value;
        
        const response = await fetch('/secure/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: `username=${username}&email=${email}&password=${password}`
        });
        
        const result = await response.json();
        document.getElementById('register-result').innerHTML = 
            '<pre>' + JSON.stringify(result, null, 2) + '</pre>';
    }
    </script>
    </body>
    </html>
    """

if __name__ == '__main__':
    print("Login Security Test Server running on http://localhost:5003")
    print("Visit http://localhost:5003/test/login to run tests")
    print()
    print("Test Credentials:")
    print("  Username: john")
    print("  Password: SecurePassword123!")
    app.run(debug=True, port=5003)
