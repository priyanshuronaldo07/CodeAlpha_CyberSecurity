# Secure Coding Review - Code Examples & Fixes

## 1. Cross-Site Scripting (XSS) - CVE-2024-6531

### ❌ VULNERABLE CODE
```javascript
// Backend - Express.js
app.get('/profile', (req, res) => {
    const userId = req.query.id;
    const userData = db.getUserData(userId);
    // Directly inserting user input without sanitization
    res.send(`<h1>Welcome ${userData.name}</h1>`);
});

// Frontend - React (without sanitization)
function UserProfile({ name }) {
    return <div dangerouslySetInnerHTML={{ __html: name }} />;
}
```

### ✅ SECURE CODE
```javascript
// Backend - Express.js with DOMPurify
const DOMPurify = require('isomorphic-dompurify');
const xss = require('xss');

app.get('/profile', (req, res) => {
    const userId = req.query.id;
    const userData = db.getUserData(userId);
    // Sanitize output
    const safeName = xss(userData.name, {
        whiteList: {},
        stripIgnoredTag: true
    });
    res.send(`<h1>Welcome ${safeName}</h1>`);
});

// Frontend - React (safe rendering)
function UserProfile({ name }) {
    return <div>{name}</div>; // React auto-escapes by default
}

// Or use DOMPurify for sanitization
import DOMPurify from 'dompurify';

function UserProfile({ htmlContent }) {
    const sanitized = DOMPurify.sanitize(htmlContent);
    return <div dangerouslySetInnerHTML={{ __html: sanitized }} />;
}
```

---

## 2. Cross-Site Request Forgery (CSRF)

### ❌ VULNERABLE CODE
```javascript
// Backend - No CSRF protection
app.post('/transfer-money', (req, res) => {
    const { amount, recipientId } = req.body;
    const userId = req.session.userId;
    
    // No CSRF token validation
    db.transferMoney(userId, recipientId, amount);
    res.json({ success: true });
});

// Frontend - Form without CSRF token
function TransferForm() {
    const handleSubmit = async (e) => {
        e.preventDefault();
        const response = await fetch('/transfer-money', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ amount: 500, recipientId: 'user123' })
        });
    };
    return <form onSubmit={handleSubmit}>...</form>;
}
```

### ✅ SECURE CODE
```javascript
// Backend - With CSRF protection
const csrf = require('csurf');
const cookieParser = require('cookie-parser');

app.use(cookieParser());
app.use(csrf({ cookie: false }));

// Generate CSRF token
app.get('/transfer-form', (req, res) => {
    res.json({ csrfToken: req.csrfToken() });
});

// Validate CSRF token on POST
app.post('/transfer-money', (req, res) => {
    const { amount, recipientId } = req.body;
    const userId = req.session.userId;
    
    // CSRF token is automatically validated by middleware
    db.transferMoney(userId, recipientId, amount);
    res.json({ success: true });
});

// Frontend - Include CSRF token
function TransferForm() {
    const [csrfToken, setCsrfToken] = useState('');
    
    useEffect(() => {
        fetch('/transfer-form')
            .then(res => res.json())
            .then(data => setCsrfToken(data.csrfToken));
    }, []);
    
    const handleSubmit = async (e) => {
        e.preventDefault();
        const response = await fetch('/transfer-money', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken
            },
            body: JSON.stringify({ amount: 500, recipientId: 'user123' })
        });
    };
    
    return <form onSubmit={handleSubmit}>...</form>;
}
```

---

## 3. NoSQL Injection

### ❌ VULNERABLE CODE
```javascript
// Backend - MongoDB with vulnerable query
app.post('/search', (req, res) => {
    const searchQuery = req.body.query;
    
    // Directly concatenating user input - VULNERABLE!
    db.collection('users').find({ name: searchQuery }).toArray((err, users) => {
        res.json(users);
    });
});

// Form input from frontend
function SearchUsers() {
    const handleSearch = async (query) => {
        // User can inject: { "$ne": "" } to bypass authentication
        const response = await fetch('/search', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ query: query })
        });
    };
}
```

### ✅ SECURE CODE
```javascript
// Backend - Sanitized NoSQL queries
const mongoSanitize = require('express-mongo-sanitize');

app.use(mongoSanitize());

app.post('/search', (req, res) => {
    const searchQuery = req.body.query;
    
    // Sanitize and validate input
    const sanitized = String(searchQuery).trim();
    
    if (typeof sanitized !== 'string' || sanitized.length > 100) {
        return res.status(400).json({ error: 'Invalid query' });
    }
    
    // Use parameterized queries with proper escaping
    db.collection('users').find({ name: { $regex: sanitized, $options: 'i' } })
        .toArray((err, users) => {
            if (err) return res.status(500).json({ error: 'Database error' });
            res.json(users);
        });
});

// Alternative: Use schema validation with Mongoose
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true }
});

app.post('/search', async (req, res) => {
    try {
        const searchQuery = req.body.query;
        
        // Validate input type
        if (typeof searchQuery !== 'string') {
            return res.status(400).json({ error: 'Invalid query' });
        }
        
        // Use Mongoose with type safety
        const users = await User.find({ name: { $regex: searchQuery } });
        res.json(users);
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});
```

---

## 4. Brute Force Login Vulnerability

### ❌ VULNERABLE CODE
```javascript
// Backend - No rate limiting
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    
    const user = await db.findUser(username);
    if (!user || !await bcrypt.compare(password, user.passwordHash)) {
        return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    req.session.userId = user.id;
    res.json({ success: true });
});
```

### ✅ SECURE CODE
```javascript
// Backend - With rate limiting and account lockout
const rateLimit = require('express-rate-limit');

// Rate limiter for login attempts
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // Max 5 attempts
    message: 'Too many login attempts, please try again later',
    standardHeaders: true,
    legacyHeaders: false,
    // Store in Redis for distributed systems
    store: new RedisStore({
        client: redisClient,
        prefix: 'login_attempts:'
    })
});

app.post('/login', loginLimiter, async (req, res) => {
    try {
        const { username, password } = req.body;
        
        // Check if account is locked
        const user = await db.findUser(username);
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        if (user.isLocked && Date.now() < user.lockUntil) {
            return res.status(403).json({ error: 'Account temporarily locked' });
        }
        
        // Verify password
        const isValidPassword = await bcrypt.compare(password, user.passwordHash);
        
        if (!isValidPassword) {
            // Increment failed attempts
            user.failedLoginAttempts = (user.failedLoginAttempts || 0) + 1;
            
            // Lock account after 5 failed attempts
            if (user.failedLoginAttempts >= 5) {
                user.isLocked = true;
                user.lockUntil = Date.now() + (30 * 60 * 1000); // 30 minute lockout
            }
            
            await db.updateUser(user.id, user);
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        // Successful login - reset failed attempts
        await db.updateUser(user.id, {
            failedLoginAttempts: 0,
            isLocked: false,
            lockUntil: null,
            lastLogin: Date.now()
        });
        
        req.session.userId = user.id;
        res.json({ success: true });
        
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Optional: Additional IP-based rate limiting
const ipLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 100, // Max 100 requests per hour
    keyGenerator: (req) => req.ip
});

app.use(ipLimiter);
```

---

## 5. Weak Password Policy

### ❌ VULNERABLE CODE
```javascript
// Backend - No password validation
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    
    // No password requirements!
    const hashedPassword = await bcrypt.hash(password, 10);
    
    await db.createUser({ username, passwordHash: hashedPassword });
    res.json({ success: true });
});
```

### ✅ SECURE CODE
```javascript
// Backend - Strong password policy
const passwordValidator = require('password-validator');

// Define password schema
const schema = new passwordValidator();
schema
    .isLength({ min: 12 })
    .has().uppercase()
    .has().lowercase()
    .has().digits()
    .has().symbols()
    .not().spaces();

app.post('/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        // Validate password strength
        if (!schema.validate(password)) {
            return res.status(400).json({
                error: 'Password must be at least 12 characters with uppercase, lowercase, numbers, and symbols'
            });
        }
        
        // Check for common passwords
        const commonPasswords = ['password123', 'admin123', '12345678'];
        if (commonPasswords.includes(password.toLowerCase())) {
            return res.status(400).json({ error: 'Password is too common' });
        }
        
        // Hash password with strong salt rounds
        const hashedPassword = await bcrypt.hash(password, 12);
        
        await db.createUser({ username, passwordHash: hashedPassword });
        res.json({ success: true });
        
    } catch (err) {
        res.status(500).json({ error: 'Registration failed' });
    }
});

// Frontend - Password validation feedback
function PasswordInput({ value, onChange }) {
    const getStrength = (password) => {
        let strength = 0;
        if (password.length >= 12) strength++;
        if (/[A-Z]/.test(password)) strength++;
        if (/[a-z]/.test(password)) strength++;
        if (/[0-9]/.test(password)) strength++;
        if (/[^A-Za-z0-9]/.test(password)) strength++;
        return strength;
    };
    
    const strength = getStrength(value);
    
    return (
        <div>
            <input 
                type="password" 
                value={value}
                onChange={onChange}
                placeholder="Password (min 12 chars, uppercase, lowercase, number, symbol)"
            />
            <div className={`strength strength-${strength}`}>
                Strength: {['Very Weak', 'Weak', 'Fair', 'Good', 'Strong', 'Very Strong'][strength]}
            </div>
        </div>
    );
}
```

---

## Best Practices Summary

| Vulnerability | Prevention Method |
|---|---|
| **XSS** | Use DOMPurify, escape output, Content Security Policy (CSP) |
| **CSRF** | CSRF tokens, SameSite cookies, double-submit cookies |
| **NoSQL Injection** | Input validation, parameterized queries, mongoSanitize |
| **Brute Force** | Rate limiting, account lockout, CAPTCHA, 2FA |
| **Weak Passwords** | Password validator, entropy checks, breach database checks |

---

## Dependencies to Install

```bash
npm install express-rate-limit
npm install bcryptjs
npm install csurf
npm install cookie-parser
npm install xss
npm install dompurify
npm install isomorphic-dompurify
npm install express-mongo-sanitize
npm install password-validator
npm install redis
```

---

## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [NIST 800-218](https://csrc.nist.gov/publications/detail/sp/800-218/final)
