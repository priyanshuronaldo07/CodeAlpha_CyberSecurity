"""
XSS (Cross-Site Scripting) - Secure Implementation
Test file to demonstrate secure output escaping
"""

from flask import Flask, request, render_template, escape
from markupsafe import Markup
import bleach

app = Flask(__name__)
app.config['SECRET_KEY'] = 'test-secret-key'

# Sample user database (in-memory)
users_db = {
    '1': {'id': '1', 'name': 'John Doe', 'bio': '<b>Software Developer</b>'},
    '2': {'id': '2', 'name': '<script>alert("XSS")</script>', 'bio': 'Hacker attempt'}
}

# ❌ VULNERABLE - Demonstrates the problem
@app.route('/vulnerable')
def vulnerable():
    user_id = request.args.get('id', '1')
    user = users_db.get(user_id, {})
    
    # This is VULNERABLE - no sanitization
    html = f"<h1>Welcome {user.get('name', 'Guest')}</h1>"
    return html

# ✅ SECURE - Using escape()
@app.route('/secure/escape')
def secure_escape():
    user_id = request.args.get('id', '1')
    user = users_db.get(user_id, {})
    
    # Properly escape output
    safe_name = escape(user.get('name', 'Guest'))
    html = f"<h1>Welcome {safe_name}</h1>"
    return html

# ✅ SECURE - Using Jinja2 templates (auto-escapes by default)
@app.route('/secure/template')
def secure_template():
    user_id = request.args.get('id', '1')
    user = users_db.get(user_id, {})
    return render_template('user_profile.html', user=user)

# ✅ SECURE - Using Bleach for HTML sanitization
@app.route('/secure/bleach')
def secure_bleach():
    user_id = request.args.get('id', '1')
    user = users_db.get(user_id, {})
    
    # Allow only safe HTML tags
    allowed_tags = ['b', 'i', 'u', 'p', 'br', 'strong', 'em']
    bio = user.get('bio', '')
    sanitized_bio = bleach.clean(bio, tags=allowed_tags, strip=True)
    
    return f"""
    <h2>{escape(user.get('name', 'Guest'))}</h2>
    <p>{sanitized_bio}</p>
    """

# Test endpoint
@app.route('/test/xss')
def test_xss():
    return """
    <html>
    <body>
    <h1>XSS Security Test</h1>
    
    <h3>1. Vulnerable Version (Don't Use)</h3>
    <a href="/vulnerable?id=2">Test Vulnerable ❌</a>
    <p>Should show JavaScript - UNSAFE!</p>
    
    <h3>2. Secure with Escape</h3>
    <a href="/secure/escape?id=2">Test Secure Escape ✅</a>
    <p>JavaScript will be displayed as text</p>
    
    <h3>3. Secure with Templates</h3>
    <a href="/secure/template?id=2">Test Secure Template ✅</a>
    <p>Uses Jinja2 auto-escaping</p>
    
    <h3>4. Secure with Bleach</h3>
    <a href="/secure/bleach?id=1">Test Bleach (Safe HTML) ✅</a>
    <p>Allows some HTML tags but removes dangerous ones</p>
    </body>
    </html>
    """

if __name__ == '__main__':
    print("XSS Test Server running on http://localhost:5001")
    print("Visit http://localhost:5001/test/xss to run tests")
    app.run(debug=True, port=5001)
