import os
import re
import sqlite3
from datetime import timedelta
from flask import (
    Flask, request, render_template_string, redirect, 
    url_for, session, flash, abort
)
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import pyotp

# ==========================================
# 1. APP CONFIGURATION & SECURITY HEADERS
# ==========================================

app = Flask(__name__)
# Cryptographically strong session key
app.config['SECRET_KEY'] = os.urandom(32)

# Session Hardening
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,   # Mitigates XSS-based cookie theft
    SESSION_COOKIE_SAMESITE='Lax',  # Mitigates Cross-Site Request Forgery (CSRF)
    SESSION_COOKIE_SECURE=False,    # Set to True in production over HTTPS
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30)
)

ph = PasswordHasher()
DB_FILE = "secure_auth.db"

# ==========================================
# 2. DATABASE INITIALIZATION & ACCESS
# ==========================================

def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                totp_secret TEXT,
                is_totp_enabled INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()

init_db()

# Apply Security Headers
@app.after_request
def apply_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

# ==========================================
# 3. INPUT VALIDATION HELPERS
# ==========================================

def validate_registration(username, email, password):
    if not (3 <= len(username) <= 30 and re.match(r"^[a-zA-Z0-9_-]+$", username)):
        return False, "Username must be 3-30 characters (alphanumeric, dashes, underscores)."
    
    email_regex = r"^[\w\.-]+@[\w\.-]+\.\w+$"
    if not (len(email) <= 254 and re.match(email_regex, email)):
        return False, "Invalid email address format."

    if len(password) < 10:
        return False, "Password must be at least 10 characters long."
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter."
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one number."
    if not any(c in "!@#$%^&*()-_=+" for c in password):
        return False, "Password must contain at least one special character (!@#$%^&*()-_=+)."

    return True, None

# ==========================================
# 4. HTML TEMPLATES (In-Memory)
# ==========================================

BASE_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>{{ title }} - Secure App</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f4f6f8; margin: 0; padding: 40px 20px; }
        .container { max-width: 450px; margin: auto; background: #fff; padding: 30px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); }
        h2 { margin-top: 0; color: #222; }
        input[type="text"], input[type="email"], input[type="password"] { width: 100%; padding: 10px; margin: 8px 0 16px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }
        button { width: 100%; padding: 10px; background: #0066cc; color: white; border: none; border-radius: 4px; font-size: 16px; cursor: pointer; }
        button:hover { background: #0052a3; }
        .flash { padding: 10px; border-radius: 4px; margin-bottom: 15px; font-size: 14px; }
        .flash.error { background: #fee2e2; color: #991b1b; }
        .flash.success { background: #dcfce7; color: #166534; }
        .footer-links { margin-top: 15px; font-size: 14px; text-align: center; }
        .secret-box { background: #eef2ff; border: 1px dashed #6366f1; padding: 12px; font-family: monospace; word-break: break-all; margin-bottom: 15px; }
    </style>
</head>
<body>
    <div class="container">
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="flash {{ category }}">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        {% block content %}{% endblock %}
    </div>
</body>
</html>
"""

# ==========================================
# 5. ROUTES & AUTHENTICATION LOGIC
# ==========================================

@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        # 1. Input Validation
        is_valid, err_msg = validate_registration(username, email, password)
        if not is_valid:
            flash(err_msg, "error")
            return render_template_string(BASE_HTML + """
                {% block content %}
                <h2>Create Account</h2>
                <form method="POST">
                    <label>Username</label><input type="text" name="username" value="{{ username }}" required>
                    <label>Email</label><input type="email" name="email" value="{{ email }}" required>
                    <label>Password</label><input type="password" name="password" required>
                    <button type="submit">Register</button>
                </form>
                <div class="footer-links"><a href="{{ url_for('login') }}">Already registered? Login</a></div>
                {% endblock %}
            """, title="Register", username=username, email=email)

        # 2. Hash Password using Argon2
        pwd_hash = ph.hash(password)

        # 3. Parameterized Query (SQL Injection Prevention)
        try:
            with get_db() as conn:
                conn.execute(
                    "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                    (username, email, pwd_hash)
                )
                conn.commit()
            flash("Account created successfully! Please log in.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Username or Email is already registered.", "error")

    return render_template_string(BASE_HTML + """
        {% block content %}
        <h2>Create Account</h2>
        <form method="POST">
            <label>Username</label><input type="text" name="username" required>
            <label>Email</label><input type="email" name="email" required>
            <label>Password</label><input type="password" name="password" required>
            <button type="submit">Register</button>
        </form>
        <div class="footer-links"><a href="{{ url_for('login') }}">Already registered? Login</a></div>
        {% endblock %}
    """, title="Register")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        identifier = request.form.get("identifier", "").strip()
        password = request.form.get("password", "")

        # Parameterized query to fetch user by username or email
        with get_db() as conn:
            user = conn.execute(
                "SELECT * FROM users WHERE username = ? OR email = ?",
                (identifier, identifier)
            ).fetchone()

        # Constant-time password verification via Argon2
        valid_password = False
        if user:
            try:
                valid_password = ph.verify(user["password_hash"], password)
            except VerifyMismatchError:
                valid_password = False

        if not valid_password or not user:
            # Generic error prevents username enumeration attacks
            flash("Invalid username/email or password.", "error")
            return redirect(url_for("login"))

        # Check if 2FA is active
        if user["is_totp_enabled"]:
            session["pre_auth_user_id"] = user["id"]
            return redirect(url_for("verify_2fa"))

        # Session Regeneration (Prevents Session Fixation)
        session.clear()
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        flash(f"Welcome back, {user['username']}!", "success")
        return redirect(url_for("dashboard"))

    return render_template_string(BASE_HTML + """
        {% block content %}
        <h2>Secure Login</h2>
        <form method="POST">
            <label>Username or Email</label><input type="text" name="identifier" required>
            <label>Password</label><input type="password" name="password" required>
            <button type="submit">Sign In</button>
        </form>
        <div class="footer-links"><a href="{{ url_for('register') }}">Create an account</a></div>
        {% endblock %}
    """, title="Login")


@app.route("/2fa/verify", methods=["GET", "POST"])
def verify_2fa():
    user_id = session.get("pre_auth_user_id")
    if not user_id:
        return redirect(url_for("login"))

    if request.method == "POST":
        token = request.form.get("otp_token", "").strip()
        with get_db() as conn:
            user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

        totp = pyotp.TOTP(user["totp_secret"])
        # Validates token within a 30s drift window
        if totp.verify(token, valid_window=1):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            flash("2FA verification successful.", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid or expired 2FA passcode.", "error")

    return render_template_string(BASE_HTML + """
        {% block content %}
        <h2>Two-Factor Authentication</h2>
        <p>Enter the 6-digit passcode from your authenticator app.</p>
        <form method="POST">
            <label>6-Digit Passcode</label>
            <input type="text" name="otp_token" pattern="[0-9]{6}" maxlength="6" autofocus required>
            <button type="submit">Verify Code</button>
        </form>
        <div class="footer-links"><a href="{{ url_for('logout') }}">Cancel</a></div>
        {% endblock %}
    """, title="Verify 2FA")


@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        flash("You must be logged in to view this page.", "error")
        return redirect(url_for("login"))

    with get_db() as conn:
        user = conn.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()

    return render_template_string(BASE_HTML + """
        {% block content %}
        <h2>Dashboard</h2>
        <p>Logged in as: <strong>{{ user['username'] }}</strong></p>
        <p>Email: <code>{{ user['email'] }}</code></p>
        <p>Two-Factor Auth: 
            {% if user['is_totp_enabled'] %}
                <span style="color: green; font-weight: bold;">Enabled</span>
            {% else %}
                <span style="color: red; font-weight: bold;">Disabled</span>
            {% endif %}
        </p>
        
        <hr style="margin: 20px 0; border: none; border-top: 1px solid #eee;">
        
        {% if not user['is_totp_enabled'] %}
            <a href="{{ url_for('setup_2fa') }}"><button style="background: #10b981; margin-bottom: 10px;">Enable 2FA</button></a>
        {% endif %}
        
        <a href="{{ url_for('logout') }}"><button style="background: #ef4444;">Log Out</button></a>
        {% endblock %}
    """, title="Dashboard", user=user)


@app.route("/2fa/setup", methods=["GET", "POST"])
def setup_2fa():
    if "user_id" not in session:
        return redirect(url_for("login"))

    with get_db() as conn:
        user = conn.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()

    if user["is_totp_enabled"]:
        flash("2FA is already configured.", "info")
        return redirect(url_for("dashboard"))

    # Generate or reuse session pending secret
    secret = session.get("pending_totp_secret")
    if not secret:
        secret = pyotp.random_base32()
        session["pending_totp_secret"] = secret

    if request.method == "POST":
        token = request.form.get("otp_token", "").strip()
        totp = pyotp.TOTP(secret)
        if totp.verify(token, valid_window=1):
            with get_db() as conn:
                conn.execute(
                    "UPDATE users SET totp_secret = ?, is_totp_enabled = 1 WHERE id = ?",
                    (secret, session["user_id"])
                )
                conn.commit()
            session.pop("pending_totp_secret", None)
            flash("Two-Factor Authentication successfully activated!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid code. Verification failed.", "error")

    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(name=user["email"], issuer_name="SecureWebApp")

    return render_template_string(BASE_HTML + """
        {% block content %}
        <h2>Setup 2FA</h2>
        <p>1. Add this key into your Authenticator app (e.g., Google Authenticator, Bitwarden):</p>
        <div class="secret-box">{{ secret }}</div>
        <p>Provisioning URI: <code style="font-size: 11px;">{{ totp_uri }}</code></p>
        <p>2. Enter the 6-digit code generated by the app to verify:</p>
        <form method="POST">
            <input type="text" name="otp_token" pattern="[0-9]{6}" maxlength="6" placeholder="123456" required>
            <button type="submit">Enable 2FA</button>
        </form>
        <div class="footer-links"><a href="{{ url_for('dashboard') }}">Back to Dashboard</a></div>
        {% endblock %}
    """, title="Setup 2FA", secret=secret, totp_uri=totp_uri)


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out securely.", "info")
    return redirect(url_for("login"))


if __name__ == "__main__":
    # In production: run via gunicorn/uvicorn with TLS termination
    app.run(debug=True, port=5000)
