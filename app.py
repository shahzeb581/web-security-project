from flask import Flask, request, render_template, redirect, url_for, session, make_response, send_file, jsonify, flash, abort
from flask_talisman import Talisman          # Security headers + CSP + HSTS
from flask_limiter import Limiter            # Rate limiting (brute-force protection)
from flask_limiter.util import get_remote_address
from flask_cors import CORS                  # CORS configuration
import base64
import subprocess
import random
import sqlite3
import pickle
import os
import re
import logging
import datetime
from werkzeug.utils import secure_filename

# ============================================================
# APP SETUP
# ============================================================
app = Flask(__name__)
app.secret_key = 'your_secret_key'

DATABASE = 'sql_injection_demo.db'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
STATIC_FOLDER = 'static'

# ============================================================
# TASK 3: SECURITY HEADERS & CSP IMPLEMENTATION
# Flask-Talisman adds:
#   - Content Security Policy (CSP) → blocks XSS / script injections
#   - HSTS (Strict-Transport-Security) → enforces HTTPS
#   - X-Frame-Options, X-Content-Type-Options, etc.
# ============================================================
csp = {
    'default-src': ["'self'"],           # Only load resources from same origin
    'script-src':  ["'self'"],           # No inline scripts, no external scripts
    'style-src':   ["'self'", "'unsafe-inline'"],  # Allow inline styles (needed for basic HTML)
    'img-src':     ["'self'", 'data:'],  # Images from same origin or data URIs
    'font-src':    ["'self'"],
    'object-src':  ["'none'"],           # Block <object>, <embed>, <applet>
    'frame-src':   ["'none'"],           # Block iframes (clickjacking protection)
}

talisman = Talisman(
    app,
    content_security_policy=csp,
    force_https=False,
    strict_transport_security=True,
    strict_transport_security_max_age=31536000,
    strict_transport_security_include_subdomains=True,
    referrer_policy='strict-origin-when-cross-origin'
)

# ============================================================
# TASK 2a: CORS CONFIGURATION
# Restrict which origins (domains) can call your API.
# Change 'http://localhost:5000' to your actual frontend URL in production.
# ============================================================
CORS(app, resources={
    r"/*": {
        "origins": ["http://localhost:80", "http://localhost"],
        "methods": ["GET", "POST"],
        "allow_headers": ["Content-Type", "X-API-Key"]
    }
})

# ============================================================
# TASK 2b: RATE LIMITING
# Prevents brute-force and DoS attacks by limiting request count.
# ============================================================
from flask_limiter.util import get_remote_address
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# ============================================================
# TASK 1: LOGGING SETUP FOR INTRUSION DETECTION
# All login events are written to security.log
# monitor.py reads this file to detect threats in real-time
# ============================================================
logging.basicConfig(
    filename='security.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
security_logger = logging.getLogger('security')

# ============================================================
# TASK 2c: API KEY AUTHENTICATION
# Protect sensitive API endpoints with a secret key.
# Client must send header:  X-API-Key: mysecretapikey123
# ============================================================
VALID_API_KEYS = {
    "mysecretapikey123": "internal_service",   # key: owner_name
    "anotherkey456":     "monitoring_tool",
}

def require_api_key(f):
    """Decorator — protects any route with API key check."""
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if not api_key or api_key not in VALID_API_KEYS:
            security_logger.warning(
                f"UNAUTHORIZED API ACCESS | IP: {request.remote_addr} | "
                f"Endpoint: {request.path} | Key: {api_key}"
            )
            return jsonify({"error": "Unauthorized. Valid API key required."}), 401
        return f(*args, **kwargs)
    return decorated

# ============================================================
# DATABASE HELPERS
# ============================================================
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

PROFILE_PIC_FOLDER = os.path.join(app.root_path, 'static', 'profile_pics')
if not os.path.exists(PROFILE_PIC_FOLDER):
    os.makedirs(PROFILE_PIC_FOLDER)

app.config['PROFILE_PIC_FOLDER'] = PROFILE_PIC_FOLDER
app.config['SESSION_COOKIE_HTTPONLY'] = True    # FIXED: was False (vulnerability)
app.config['SESSION_COOKIE_SECURE'] = False     # Set True in production with HTTPS

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

chat_messages = []

def init_db():
    db = get_db()
    db.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            email TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            profile_picture TEXT
        )
    ''')
    db.execute('''
        CREATE TABLE IF NOT EXISTS contacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL
        )
    ''')
    db.execute("INSERT OR IGNORE INTO users (username, password, email, role) VALUES ('developer', 'devs-rule', 'devin@dev4U.com', 'dev')")
    db.execute("INSERT OR IGNORE INTO users (username, password, email, role) VALUES ('admin', 'adminpassword', 'admin@example.com', 'admin')")
    db.execute("INSERT OR IGNORE INTO users (username, password, email, role) VALUES ('jim', 'batman', 'jim@dm-scranton.com', 'user')")
    db.execute("INSERT OR IGNORE INTO users (username, password, email, role) VALUES ('dwight', 'spiderman', 'dwight@dm-scranton.com', 'user')")
    db.execute("INSERT OR IGNORE INTO contacts (name, email) VALUES ('micheal', 'bigMike@hotmail.com')")
    db.execute("INSERT OR IGNORE INTO contacts (name, email) VALUES ('pam', 'pamcake@aol.com')")
    db.execute("INSERT OR IGNORE INTO contacts (name, email) VALUES ('ryan', 'ry-guy@gmail.com')")
    db.commit()

init_db()

# ============================================================
# ROUTES
# ============================================================

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")   # RATE LIMIT: max 10 login attempts per minute per IP
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Intentionally kept vulnerable (SQL injection for demo)
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"

        try:
            db = get_db()
            user = db.execute(query).fetchone()

            if user:
                # ✅ Log successful login
                security_logger.info(
                    f"LOGIN_SUCCESS | IP: {request.remote_addr} | User: {username}"
                )
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['role'] = user['role']
                return redirect(url_for('account'))
            else:
                # ⚠️ Log failed login — monitor.py watches for repeated failures
                security_logger.warning(
                    f"LOGIN_FAILED | IP: {request.remote_addr} | User: {username}"
                )
                return 'Invalid credentials, try again!'

        except sqlite3.OperationalError:
            security_logger.error(
                f"LOGIN_ERROR | IP: {request.remote_addr} | Query: {query}"
            )
            return render_template("404.html", image_number=random.randint(1, 5)), 404

    return render_template('login.html')


@app.before_request
def check_session():
    if request.endpoint and request.endpoint.startswith('static'):
        return None
    if 'username' not in session and request.endpoint not in ['login', 'register', 'index', 'diagnostics', 'system_info', 'os_info']:
        return redirect(url_for('login'))


@app.errorhandler(404)
def page_not_found(e):
    image_number = random.randint(1, 6)
    return render_template("404.html", image_number=image_number), 404


# Handle rate limit exceeded errors gracefully
@app.errorhandler(429)
def rate_limit_exceeded(e):
    security_logger.warning(
        f"RATE_LIMIT_EXCEEDED | IP: {request.remote_addr} | Endpoint: {request.path}"
    )
    return jsonify({
        "error": "Too many requests. You have been temporarily blocked.",
        "retry_after": "60 seconds"
    }), 429


@app.route('/chat', methods=['GET', 'POST'])
@limiter.limit("30 per minute")
def chat():
    if 'username' not in session:
        return redirect(url_for('login'))

    blacklist = ['script', 'javascript']

    if request.method == "POST":
        message = request.form.get("message")
        for word in blacklist:
            if word.lower() in message.lower():
                image_number = random.randint(1, 6)
                return render_template('blacklist.html', image_number=image_number)
        message = re.sub(r'<img[^>]*>', '', message)
        message = re.sub(r'alert', '', message)
        chat_messages.append(message)

    return render_template('chat.html', messages=chat_messages)


@app.route('/clear_messages', methods=['POST'])
def clear_messages():
    chat_messages.clear()
    return redirect(url_for('chat'))


@app.route('/admin/download/<int:file_id>', methods=['GET'])
def download(file_id):
    file_mapping = {
        1: "top-secret-company-strategy-2024.doc",
        2: "admin_notes.txt",
        3: "payroll.csv",
    }
    filename = file_mapping.get(file_id)
    if filename:
        safe_filename = secure_filename(filename)
        return send_file(f"fake_reports/{safe_filename}", as_attachment=True, mimetype="text/plain")
    else:
        return "Invalid file ID", 404


@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per hour")   # Limit registrations to prevent spam
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        role = request.form['role']

        decoded_role = base64.b64decode(role).decode('utf-8')

        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        existing_user = cursor.fetchone()

        if existing_user:
            flash("Username already exists. Please choose a different one.", "danger")
            return redirect(url_for('register'))

        cursor.execute("INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)",
                       (username, password, email, decoded_role))
        db.commit()

        security_logger.info(f"NEW_USER_REGISTERED | IP: {request.remote_addr} | User: {username}")
        flash("Registration successful! You can now log in.", "success")
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/account', methods=['GET', 'POST'])
def account():
    if 'username' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    db = get_db()
    user = db.execute("SELECT username, role, profile_picture FROM users WHERE id = ?", (user_id,)).fetchone()

    if not user:
        return redirect(url_for('login'))

    if request.method == 'POST':
        file = request.files['profile_picture']
        if file:
            filename = file.filename
            file_path = os.path.join(app.config['PROFILE_PIC_FOLDER'], filename)
            file.save(file_path)

            if filename.endswith('.py'):
                try:
                    result = subprocess.run(['python', file_path], capture_output=True, text=True)
                    if result.returncode == 0:
                        print("Python script executed successfully.")
                        print(result.stdout)
                    else:
                        print("Python script execution failed.")
                        print(result.stderr)
                except Exception as e:
                    print(f"Error executing Python script: {e}")

            db.execute("UPDATE users SET profile_picture = ? WHERE id = ?", (filename, user_id))
            db.commit()
            session['profile_picture'] = filename
            return redirect(url_for('account'))

    profile_picture_url = None
    if user['profile_picture']:
        profile_picture_url = url_for('static', filename=os.path.join('profile_pics', user['profile_picture']))

    return render_template('account.html', username=user['username'], role=user['role'], profile_picture_url=profile_picture_url)


@app.route('/diagnostics', methods=['GET'])
def diagnostics():
    return render_template('diagnostics.html')


# ============================================================
# SECURED API ENDPOINTS (require API key)
# These were previously open — now protected.
# ============================================================

@app.route('/system_info', methods=['GET'])
@require_api_key           # 🔑 Must send X-API-Key header
@limiter.limit("10 per minute")
def system_info():
    cmd = request.args.get('cmd', '')
    if not cmd:
        return jsonify({"output": "No command provided"}), 400
    try:
        result = os.popen(cmd).read()
    except Exception as e:
        result = f"Error: {str(e)}"
    return jsonify({"output": result})


@app.route('/os_info', methods=['GET'])
@require_api_key           # 🔑 Must send X-API-Key header
@limiter.limit("10 per minute")
def os_info():
    filename = request.args.get('filename', 'testing.txt')
    file_path = os.path.join(STATIC_FOLDER, filename)
    try:
        with open(file_path, 'r') as file:
            content = file.read()
    except Exception as e:
        content = f"Error: {str(e)}"
    return jsonify({"file_content": content})


@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        user_id = session.get('user_id')
        new_password = request.form.get('new_password')

        if user_id and new_password:
            db = get_db()
            query = "UPDATE users SET password = ? WHERE id = ?"
            db.execute(query, (new_password, user_id))
            db.commit()
            flash('Password changed successfully!', 'success')
            return redirect(url_for('account'))


@app.route('/admin')
def admin():
    if 'username' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))

    db = get_db()
    page = request.args.get('page', 1, type=int)
    per_page = 5
    offset = (page - 1) * per_page
    users = db.execute("SELECT id, username, email FROM users WHERE username != 'admin' LIMIT ? OFFSET ?", (per_page, offset)).fetchall()
    total_users = db.execute("SELECT COUNT(*) FROM users WHERE username != 'admin'").fetchone()[0]
    total_pages = (total_users // per_page) + (1 if total_users % per_page > 0 else 0)
    return render_template('admin.html', users=users, page=page, total_pages=total_pages)


@app.route('/admin/reset_password/<int:user_id>', methods=['POST'])
def reset_password(user_id):
    if 'username' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
    db = get_db()
    db.execute("UPDATE users SET password = ? WHERE id = ?", ('qwerty', user_id))
    db.commit()
    return redirect(url_for('admin'))


@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if 'username' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
    db = get_db()
    db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.commit()
    return redirect(url_for('admin'))


@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('user_id', None)
    session.pop('role', None)
    return redirect(url_for('index'))


@app.route('/search', methods=['GET', 'POST'])
@limiter.limit("20 per minute")
def search():
    if request.method == 'POST':
        query = request.form.get('query')
        if query:
            db = get_db()
            result = db.execute(f"SELECT username, email FROM users WHERE username LIKE '%{query}%'").fetchall()
            if result:
                return render_template('search_results.html', results=result)
            else:
                return 'No results found.'
        else:
            return 'No parameter provided', 400
    return render_template('search.html')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3000, debug=True)