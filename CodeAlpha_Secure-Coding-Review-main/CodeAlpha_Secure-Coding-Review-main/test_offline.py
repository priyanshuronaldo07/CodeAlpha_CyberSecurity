"""
Simple test script to demonstrate all vulnerabilities
Run this to test all the security examples
"""

import subprocess
import sys
import time

def check_dependencies():
    """Check if all required packages are installed"""
    print("Checking dependencies...")
    try:
        import flask
        import bcrypt
        print("✅ All dependencies found!")
        return True
    except ImportError as e:
        print(f"❌ Missing package: {e}")
        print("\nRun this to install dependencies:")
        print("  pip install -r requirements.txt")
        return False

def run_xss_tests():
    """Run XSS security tests"""
    print("\n" + "="*60)
    print("XSS SECURITY TESTS")
    print("="*60)
    
    print("""
Test Case 1: XSS Vulnerability
User input: <script>alert('XSS')</script>
Expected: Script should NOT execute in secure versions
    """)
    
    test_cases = {
        "Vulnerable": "http://localhost:5001/vulnerable?id=2",
        "Secure (escape)": "http://localhost:5001/secure/escape?id=2",
        "Secure (template)": "http://localhost:5001/secure/template?id=2",
        "Secure (bleach)": "http://localhost:5001/secure/bleach?id=1",
    }
    
    for method, url in test_cases.items():
        print(f"\n{method}:")
        print(f"  URL: {url}")
        print(f"  Check browser to see if JavaScript executes")

def run_csrf_tests():
    """Run CSRF security tests"""
    print("\n" + "="*60)
    print("CSRF SECURITY TESTS")
    print("="*60)
    
    print("""
Test Case 1: CSRF Token Validation
- Vulnerable endpoint allows transfers without token
- Secure endpoint requires valid CSRF token

Test the endpoints:
    """)
    
    endpoints = {
        "Vulnerable Transfer": "/vulnerable/transfer",
        "Secure Transfer Form": "/secure/transfer-form",
        "Secure API Transfer": "/api/secure/transfer",
    }
    
    for name, endpoint in endpoints.items():
        print(f"\n{name}:")
        print(f"  Endpoint: {endpoint}")

def run_login_tests():
    """Run login security tests"""
    print("\n" + "="*60)
    print("LOGIN SECURITY TESTS")
    print("="*60)
    
    print("""
Test Credentials:
  Username: john
  Password: SecurePassword123!

Test Cases:

1. RATE LIMITING TEST:
   - Try logging in with wrong password 6+ times
   - After 5 failed attempts, account should lock for 30 minutes
   - Expected: Account locked message

2. STRONG PASSWORD TEST:
   - Try registering with weak passwords (123456, password)
   - Try registering with strong password (MyPassword123!)
   - Expected: Weak passwords rejected, strong passwords accepted

3. PASSWORD REQUIREMENTS:
   - Minimum 12 characters
   - At least one uppercase letter
   - At least one lowercase letter
   - At least one digit
   - At least one special character
    """)

def run_unit_tests():
    """Run simple unit tests"""
    print("\n" + "="*60)
    print("UNIT TESTS")
    print("="*60)
    
    # Test password validation
    print("\nPassword Validation Tests:")
    from app_login import validate_password
    
    test_passwords = {
        "weak": "password",
        "medium": "Password123",
        "strong": "SecurePassword123!"
    }
    
    for level, pwd in test_passwords.items():
        is_valid, errors = validate_password(pwd)
        status = "✅ Valid" if is_valid else "❌ Invalid"
        print(f"\n  {level.upper()}: {pwd}")
        print(f"  {status}")
        if errors:
            for error in errors:
                print(f"    - {error}")

def main():
    """Main test runner"""
    print("""
╔═══════════════════════════════════════════════════════════╗
║     SECURE CODING REVIEW - TEST SUITE                    ║
║     CodeAlpha Internship Project                         ║
╚═══════════════════════════════════════════════════════════╝
    """)
    
    # Check dependencies
    if not check_dependencies():
        return
    
    print("\n" + "="*60)
    print("QUICK START GUIDE")
    print("="*60)
    
    print("""
To run the interactive tests, start the Flask servers in separate terminals:

1. XSS Tests:
   python app_xss.py
   Then visit: http://localhost:5001/test/xss

2. CSRF Tests:
   python app_csrf.py
   Then visit: http://localhost:5002/test/csrf

3. Login & Password Tests:
   python app_login.py
   Then visit: http://localhost:5003/test/login

4. Run this script for offline tests:
   python test_offline.py
    """)
    
    # Run offline tests
    print("\n" + "="*60)
    print("Running Offline Tests...")
    print("="*60)
    
    try:
        run_unit_tests()
        print("\n✅ All offline tests completed!")
    except Exception as e:
        print(f"\n❌ Test error: {e}")
    
    # Show test endpoints
    run_xss_tests()
    run_csrf_tests()
    run_login_tests()
    
    print("\n" + "="*60)
    print("SUMMARY")
    print("="*60)
    print("""
Files created:
  ✅ app_xss.py          - XSS vulnerability tests
  ✅ app_csrf.py         - CSRF vulnerability tests
  ✅ app_login.py        - Login security tests
  ✅ requirements.txt    - Python dependencies
  ✅ test_offline.py     - This test file

To start testing:
  1. Install dependencies: pip install -r requirements.txt
  2. Run any of the Flask apps: python app_*.py
  3. Visit the test URLs in your browser
  4. Try the vulnerable vs secure versions

References:
  - OWASP Top 10: https://owasp.org/www-project-top-ten/
  - CWE Top 25: https://cwe.mitre.org/top25/
  - NIST 800-218: https://csrc.nist.gov/publications/detail/sp/800-218/final
    """)

if __name__ == '__main__':
    main()
