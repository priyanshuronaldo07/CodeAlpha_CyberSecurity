"""
CSRF (Cross-Site Request Forgery) - Secure Implementation
Test file to demonstrate CSRF token protection
"""

from flask import Flask, request, session, render_template, jsonify
from flask_wtf.csrf import CSRFProtect
import secrets
import hashlib

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)
csrf = CSRFProtect(app)

# In-memory transaction database
transactions = []

# ❌ VULNERABLE - No CSRF protection
@app.route('/vulnerable/transfer', methods=['POST'])
@csrf.exempt  # For demonstration only!
def vulnerable_transfer():
    """This endpoint is VULNERABLE to CSRF attacks"""
    amount = request.form.get('amount')
    recipient = request.form.get('recipient')
    
    transaction = {
        'amount': amount,
        'recipient': recipient,
        'status': 'completed'
    }
    transactions.append(transaction)
    
    return {'success': True, 'message': 'Transfer completed (UNSAFE!)'}

# ✅ SECURE - Using Flask-WTF CSRF protection
@app.route('/secure/transfer-form')
def secure_transfer_form():
    """Display transfer form with CSRF token"""
    return render_template('transfer_form.html')

@app.route('/secure/transfer', methods=['POST'])
# @csrf.protect  # Automatically validated by Flask-WTF
def secure_transfer():
    """This endpoint is PROTECTED by CSRF token"""
    amount = request.form.get('amount')
    recipient = request.form.get('recipient')
    
    # CSRF token is automatically validated by decorator
    transaction = {
        'amount': amount,
        'recipient': recipient,
        'status': 'completed'
    }
    transactions.append(transaction)
    
    return jsonify({'success': True, 'message': 'Transfer completed securely'})

# ✅ SECURE - Manual CSRF token for API
@app.route('/api/csrf-token')
def get_csrf_token():
    """Get CSRF token for API requests"""
    token = hashlib.sha256(secrets.token_bytes(1024)).hexdigest()
    session['csrf_token'] = token
    return {'csrf_token': token}

@app.route('/api/secure/transfer', methods=['POST'])
def api_secure_transfer():
    """API endpoint with manual CSRF validation"""
    token_received = request.headers.get('X-CSRF-Token')
    token_stored = session.get('csrf_token')
    
    if not token_received or token_received != token_stored:
        return {'error': 'CSRF token validation failed'}, 403
    
    data = request.get_json()
    
    transaction = {
        'amount': data.get('amount'),
        'recipient': data.get('recipient'),
        'status': 'completed'
    }
    transactions.append(transaction)
    
    return {'success': True, 'message': 'API transfer completed securely'}

# Test page
@app.route('/test/csrf')
def test_csrf():
    return """
    <html>
    <body style="font-family: Arial; margin: 20px;">
    <h1>CSRF Security Test</h1>
    
    <h3>1. Vulnerable Transfer (Don't Use)</h3>
    <form action="/vulnerable/transfer" method="POST">
        Amount: <input type="text" name="amount" value="100"><br>
        Recipient: <input type="text" name="recipient" value="user123"><br>
        <button type="submit">Transfer ❌ (NO CSRF Protection)</button>
    </form>
    <p style="color: red;">This can be attacked by external websites!</p>
    
    <hr>
    
    <h3>2. Secure Transfer (Recommended)</h3>
    <a href="/secure/transfer-form">
        <button>Go to Secure Transfer Form ✅</button>
    </a>
    <p>Uses Flask-WTF CSRF token protection</p>
    
    <hr>
    
    <h3>3. API with CSRF Token</h3>
    <div>
        <button onclick="testApiTransfer()">Test API Transfer with CSRF ✅</button>
        <p id="api-result"></p>
    </div>
    
    <script>
    async function testApiTransfer() {
        // Step 1: Get CSRF token
        const tokenRes = await fetch('/api/csrf-token');
        const { csrf_token } = await tokenRes.json();
        
        // Step 2: Make API call with CSRF token
        const response = await fetch('/api/secure/transfer', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrf_token
            },
            body: JSON.stringify({
                amount: 250,
                recipient: 'secure-user'
            })
        });
        
        const result = await response.json();
        document.getElementById('api-result').innerHTML = 
            JSON.stringify(result, null, 2);
    }
    </script>
    
    <hr>
    
    <h3>Transaction History</h3>
    <div id="transactions"></div>
    
    <script>
    async function loadTransactions() {
        // In real app, fetch from backend
        fetch('/get-transactions')
            .then(r => r.json())
            .then(data => {
                document.getElementById('transactions').innerHTML = 
                    '<pre>' + JSON.stringify(data, null, 2) + '</pre>';
            });
    }
    setInterval(loadTransactions, 2000);
    </script>
    </body>
    </html>
    """

@app.route('/get-transactions')
def get_transactions():
    return jsonify(transactions)

if __name__ == '__main__':
    print("CSRF Test Server running on http://localhost:5002")
    print("Visit http://localhost:5002/test/csrf to run tests")
    app.run(debug=True, port=5002)
