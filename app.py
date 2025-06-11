from flask import Flask, request, jsonify, session
from flask_cors import CORS
import psycopg2
import hashlib
from functools import wraps
import os
import secrets
from itsdangerous import URLSafeTimedSerializer
from sqlalchemy.exc import IntegrityError
import smtplib
from email.mime.text import MIMEText

# For sending emails
from flask_mail import Mail, Message

app = Flask(__name__)
origins = [
    "https://front-rsif.vercel.app",  # Your Vercel production domain
    "http://localhost:3000",         # For local development
    "http://localhost:5173"
]

# This is the key change. We are now allowing more methods and headers.
# We also changed the resource path to r"/*" to cover ALL routes, including /login.
CORS(
    app,
    resources={r"/*": {"origins": origins}}, # Apply CORS to all routes
    methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"], # Allow these methods
    allow_headers=["Content-Type", "Authorization"], # Allow these headers
    supports_credentials=True
)
app.secret_key = os.environ.get('SECRET_KEY', 'alifaliali24100')

DATABASE_URL = os.environ.get('DATABASE_URL')
if not DATABASE_URL:
   DATABASE_URL = "postgresql://postgres.hxacfxidjsphycxywajx:1qaz1WSX%40%23@aws-0-eu-central-1.pooler.supabase.com:6543/postgres"
conn = psycopg2.connect(DATABASE_URL)
cur = conn.cursor()

# --- Ensure users table has a 'class', 'owner_id', and 'email' column ---
cur.execute("""
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    role TEXT NOT NULL,
    password TEXT,
    class TEXT,
    owner_id INTEGER,
    email TEXT UNIQUE
);
""")
cur.execute("""
CREATE TABLE IF NOT EXISTS attendance (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    date DATE,
    status TEXT
);
""")
conn.commit()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def home():
    return "Attendance Backend Running!"

# --- Email Setup (Gmail example, use app password for Gmail) ---
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', 'alifakiali24@gmail.com')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', 'ftfa egqv fiiw llbg')
mail = Mail(app)

# --- In-memory reset tokens (for demo; use DB for production) ---
reset_tokens = {}

# --- AUTH ---
@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    name = data.get('name')
    role = data.get('role', '')  # role is not used in frontend, but DB expects it
    password = data.get('password')
    email = data.get('email')
    if not all([name, password, email]):
        return jsonify({'error': 'All fields are required'}), 400
    try:
        hashed_pw = hash_password(password)
        cur.execute("INSERT INTO users (name, role, password, email) VALUES (%s, %s, %s, %s) RETURNING id, name, role, email", (name, role, hashed_pw, email))
        user = cur.fetchone()
        # Set owner_id to their own id
        cur.execute("UPDATE users SET owner_id=%s WHERE id=%s", (user[0], user[0]))
        conn.commit()
        return jsonify({'id': user[0], 'name': user[1], 'role': user[2], 'email': user[3]})
    except psycopg2.IntegrityError as e:
        conn.rollback()  # 💥 rollback to fix aborted transaction
        return jsonify({'error': 'Email already exists'}), 400
    except Exception as e:
        conn.rollback()  # 💥 important for any other DB error
        return jsonify({'error': str(e)}), 400

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    name = data.get('name')
    password = data.get('password')
    if not all([name, password]):
        return jsonify({'error': 'All fields are required'}), 400
    hashed_pw = hash_password(password)
    # Only allow login for admin users
    cur.execute("SELECT id, name, role, email FROM users WHERE name=%s AND password=%s AND role='admin'", (name, hashed_pw))
    user = cur.fetchone()
    if user:
        session['user_id'] = user[0]
        return jsonify({'id': user[0], 'name': user[1], 'role': user[2], 'email': user[3]})
    else:
        return jsonify({'error': 'Invalid credentials or not an admin'}), 401

@app.route('/api/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)
    return jsonify({'message': 'Logged out'})

# --- Password Reset ---
@app.route('/api/request-reset', methods=['POST'])
def request_reset():
    email = request.json.get('email')
    cur.execute("SELECT id FROM users WHERE email=%s", (email,))
    user = cur.fetchone()
    if not user:
        return jsonify({'error': 'Email not found'}), 404
    token = secrets.token_urlsafe(16)
    reset_tokens[token] = user[0]
    # Send email
    msg = Message('Password Reset', sender=app.config['MAIL_USERNAME'], recipients=[email])
    msg.body = f"Use this token to reset your password: {token}"
    try:
        mail.send(msg)
    except Exception as e:
        return jsonify({'error': f'Failed to send email: {str(e)}'}), 500
    return jsonify({'message': 'Reset email sent'})

@app.route('/api/reset-password', methods=['POST'])
def reset_password():
    token = request.json.get('token')
    new_password = request.json.get('new_password')
    user_id = reset_tokens.get(token)
    if not user_id:
        return jsonify({'error': 'Invalid or expired token'}), 400
    hashed_pw = hash_password(new_password)
    cur.execute("UPDATE users SET password=%s WHERE id=%s", (hashed_pw, user_id))
    conn.commit()
    del reset_tokens[token]
    return jsonify({'message': 'Password updated'})

# --- USERS ---
@app.route('/api/users', methods=['POST'])
@login_required
def add_user():
    data = request.json
    name = data.get('name')
    role = data.get('role', '')  # role is not used in frontend, but DB expects it
    user_class = data.get('class')
    owner_id = session['user_id']
    if not all([name, user_class]):
        return jsonify({'error': 'All fields are required'}), 400
    cur.execute("INSERT INTO users (name, role, class, owner_id) VALUES (%s, %s, %s, %s) RETURNING id, name, role, class", (name, role, user_class, owner_id))
    user = cur.fetchone()
    conn.commit()
    return jsonify({'id': user[0], 'name': user[1], 'role': user[2], 'class': user[3]})

@app.route('/api/users', methods=['GET'])
@login_required
def get_users():
    class_filter = request.args.get('class')
    owner_id = session['user_id']
    if class_filter:
        cur.execute("SELECT id, name, role, class FROM users WHERE class = %s AND owner_id = %s", (class_filter, owner_id))
    else:
        cur.execute("SELECT id, name, role, class FROM users WHERE owner_id = %s", (owner_id,))
    users = cur.fetchall()
    return jsonify([{'id': u[0], 'name': u[1], 'role': u[2], 'class': u[3]} for u in users])

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@login_required
def delete_user(user_id):
    owner_id = session['user_id']
    # Only delete if this user belongs to the owner
    cur.execute("SELECT id FROM users WHERE id = %s AND owner_id = %s", (user_id, owner_id))
    if not cur.fetchone():
        return jsonify({'error': 'Not allowed'}), 403
    cur.execute("DELETE FROM attendance WHERE user_id = %s", (user_id,))
    cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
    conn.commit()
    return jsonify({'message': 'User deleted'})

# --- ATTENDANCE ---
@app.route('/api/attendance', methods=['POST'])
@login_required
def mark_attendance():
    data = request.json
    user_id = data.get('user_id')
    date = data.get('date')
    status = data.get('status')
    owner_id = session['user_id']
    # Only allow marking attendance for users owned by this user
    cur.execute("SELECT id FROM users WHERE id = %s AND owner_id = %s", (user_id, owner_id))
    if not cur.fetchone():
        return jsonify({'error': 'Not allowed'}), 403
    if not all([user_id, date, status]):
        return jsonify({'error': 'All fields are required'}), 400
    cur.execute("INSERT INTO attendance (user_id, date, status) VALUES (%s, %s, %s) RETURNING id", (user_id, date, status))
    att_id = cur.fetchone()[0]
    conn.commit()
    return jsonify({'id': att_id, 'user_id': user_id, 'date': date, 'status': status})

@app.route('/api/attendance', methods=['GET'])
@login_required
def get_attendance():
    class_filter = request.args.get('class')
    owner_id = session['user_id']
    if class_filter:
        cur.execute("""
            SELECT a.id, u.name, u.class, a.date, a.status
            FROM attendance a
            JOIN users u ON a.user_id = u.id
            WHERE u.class = %s AND u.owner_id = %s
        """, (class_filter, owner_id))
    else:
        cur.execute("""
            SELECT a.id, u.name, u.class, a.date, a.status
            FROM attendance a
            JOIN users u ON a.user_id = u.id
            WHERE u.owner_id = %s
        """, (owner_id,))
    records = cur.fetchall()
    return jsonify([{'id': r[0], 'name': r[1], 'class': r[2], 'date': str(r[3]), 'status': r[4]} for r in records])

@app.route('/api/attendance/<int:att_id>', methods=['PUT'])
@login_required
def edit_attendance(att_id):
    data = request.json
    status = data.get('status')
    date = data.get('date')
    owner_id = session['user_id']
    # Only allow editing attendance for users owned by this user
    cur.execute("""
        SELECT a.id FROM attendance a
        JOIN users u ON a.user_id = u.id
        WHERE a.id = %s AND u.owner_id = %s
    """, (att_id, owner_id))
    if not cur.fetchone():
        return jsonify({'error': 'Not allowed'}), 403
    if not all([status, date]):
        return jsonify({'error': 'All fields are required'}), 400
    cur.execute("UPDATE attendance SET status=%s, date=%s WHERE id=%s", (status, date, att_id))
    conn.commit()
    return jsonify({'message': 'Attendance updated'})

# --- BULK ATTENDANCE (optional, for future) ---
@app.route('/api/attendance/bulk', methods=['POST'])
@login_required
def bulk_attendance():
    data = request.json
    user_ids = data.get('user_ids', [])
    date = data.get('date')
    status = data.get('status')
    owner_id = session['user_id']
    # Only allow marking attendance for users owned by this user
    for user_id in user_ids:
        cur.execute("SELECT id FROM users WHERE id = %s AND owner_id = %s", (user_id, owner_id))
        if cur.fetchone():
            cur.execute("INSERT INTO attendance (user_id, date, status) VALUES (%s, %s, %s)", (user_id, date, status))
    conn.commit()
    return jsonify({'message': 'Bulk attendance marked'})

# --- ATTENDANCE REPORT ---
@app.route('/api/attendance/report', methods=['GET'])
@login_required
def attendance_report():
    class_filter = request.args.get('class')
    owner_id = session['user_id']
    if class_filter:
        cur.execute("""
            SELECT u.id, u.name, u.role, u.class,
                COALESCE(SUM(CASE WHEN a.status = 'Present' THEN 1 ELSE 0 END), 0) AS presents,
                COALESCE(SUM(CASE WHEN a.status = 'Absent' THEN 1 ELSE 0 END), 0) AS absents,
                COALESCE(SUM(CASE WHEN a.status = 'Late' THEN 1 ELSE 0 END), 0) AS lates
            FROM users u
            LEFT JOIN attendance a ON u.id = a.user_id
            WHERE u.class = %s AND u.owner_id = %s
            GROUP BY u.id, u.name, u.role, u.class
            ORDER BY u.name
        """, (class_filter, owner_id))
    else:
        cur.execute("""
            SELECT u.id, u.name, u.role, u.class,
                COALESCE(SUM(CASE WHEN a.status = 'Present' THEN 1 ELSE 0 END), 0) AS presents,
                COALESCE(SUM(CASE WHEN a.status = 'Absent' THEN 1 ELSE 0 END), 0) AS absents,
                COALESCE(SUM(CASE WHEN a.status = 'Late' THEN 1 ELSE 0 END), 0) AS lates
            FROM users u
            LEFT JOIN attendance a ON u.id = a.user_id
            WHERE u.owner_id = %s
            GROUP BY u.id, u.name, u.role, u.class
            ORDER BY u.name
        """, (owner_id,))
    report = cur.fetchall()
    return jsonify([
        {
            'id': r[0],
            'name': r[1],
            'role': r[2],
            'class': r[3],
            'present': r[4],
            'absent': r[5],
            'late': r[6]
        } for r in report
    ])

# --- CLASS MANAGEMENT ---
@app.route('/api/class/<old_class>', methods=['PUT'])
@login_required
def rename_class(old_class):
    data = request.json
    new_name = data.get('newName')
    owner_id = session['user_id']
    if not new_name:
        return jsonify({'error': 'New class name required'}), 400
    cur.execute("UPDATE users SET class=%s WHERE class=%s AND owner_id=%s", (new_name, old_class, owner_id))
    conn.commit()
    return jsonify({'message': 'Class renamed'})

@app.route('/api/class/<class_name>', methods=['DELETE'])
@login_required
def delete_class(class_name):
    owner_id = session['user_id']
    # Delete attendance for users in this class and owner
    cur.execute("SELECT id FROM users WHERE class=%s AND owner_id=%s", (class_name, owner_id))
    user_ids = [row[0] for row in cur.fetchall()]
    if user_ids:
        cur.execute("DELETE FROM attendance WHERE user_id = ANY(%s)", (user_ids,))
    # Delete users in this class and owner
    cur.execute("DELETE FROM users WHERE class=%s AND owner_id=%s", (class_name, owner_id))
    conn.commit()
    return jsonify({'message': 'Class deleted'})

# --- GET CLASSES FOR USER ---
@app.route('/api/classes', methods=['GET'])
@login_required
def get_classes():
    owner_id = session['user_id']
    cur.execute("SELECT DISTINCT class FROM users WHERE owner_id=%s", (owner_id,))
    classes = [row[0] for row in cur.fetchall() if row[0]]
    return jsonify(classes)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
