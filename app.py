from dotenv import load_dotenv
load_dotenv()
import os
import psycopg2
import secrets
import smtplib
from flask import Flask, request, jsonify, session
from flask_cors import CORS
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# --- CONFIGURATION ---
CORS(app,
     supports_credentials=True,
     origins=[
         "https://data-wg78.onrender.com",
         "http://localhost:3000",
         "http://localhost:5173"
     ])

app.secret_key = os.environ.get('SECRET_KEY')
if not app.secret_key:
    raise ValueError("FATAL: SECRET_KEY environment variable is not set.")

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'alifakiali24@gmail.com'
app.config['MAIL_PASSWORD'] = 'ozyzxpcntlvxalgf'  # not your Gmail password
app.config['MAIL_DEFAULT_SENDER'] = 'alifakiali24@gmail.com'

reset_tokens = {}
mail = Mail(app)


def get_db_connection():
    db_url = os.environ.get('DATABASE_URL')
    if not db_url:
        raise ValueError("FATAL: DATABASE_URL environment variable is not set.")
    conn = psycopg2.connect(db_url)
    return conn

def init_db():
    conn = get_db_connection()
    with conn.cursor() as cur:
        cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY, name TEXT NOT NULL, role TEXT, password TEXT,
            class TEXT, owner_id INTEGER, email TEXT UNIQUE
        );""")
        cur.execute("""
        CREATE TABLE IF NOT EXISTS attendance (
            id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            date DATE, status TEXT
        );""")
    conn.commit()
    conn.close()

def get_current_user_id():
    return session.get('user_id')

@app.route('/')
def home():
    return "Attendance Backend Running!"

# --- AUTH ROUTES ---
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    name, password, email = data.get('name'), data.get('password'), data.get('email')
    if not all([name, password, email]):
        return jsonify({'error': 'Name, password, and email are required'}), 400

    hashed_pw = generate_password_hash(password)
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO users (name, role, password, email) VALUES (%s, %s, %s, %s) RETURNING id",
                (name, 'admin', hashed_pw, email)
            )
            user_id = cur.fetchone()[0]
            cur.execute("UPDATE users SET owner_id=%s WHERE id=%s", (user_id, user_id))
            conn.commit()
            return jsonify({'id': user_id, 'name': name, 'role': 'admin', 'email': email}), 201
    except psycopg2.IntegrityError:
        return jsonify({'error': 'Email already exists'}), 409
    finally:
        conn.close()

@app.route('/login', methods=['POST', 'OPTIONS'])
def login():
    if request.method == 'OPTIONS': return '', 204
    data = request.json
    name, password = data.get('name'), data.get('password')
    if not all([name, password]):
        return jsonify({'error': 'Name and password are required'}), 400

    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id, name, role, email, password FROM users WHERE name=%s", (name,))
            user = cur.fetchone()
            if user and check_password_hash(user[4], password):
                session['user_id'] = user[0]
                return jsonify({'id': user[0], 'name': user[1], 'role': user[2], 'email': user[3]})
            return jsonify({'error': 'Invalid credentials'}), 401
    finally:
        conn.close()

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)
    return jsonify({'message': 'Logged out successfully'})

# --- PASSWORD RESET ROUTES ---
@app.route('/request-reset', methods=['POST'])
def request_reset():
    email = request.json.get('email')
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM users WHERE email=%s", (email,))
            user = cur.fetchone()
            if not user: return jsonify({'error': 'Email not found'}), 404
            token = secrets.token_urlsafe(16)
            reset_tokens[token] = user[0]
            msg = Message('Password Reset', sender=app.config['MAIL_USERNAME'], recipients=[email])
            msg.body = f"Use this token to reset your password: {token}"
            mail.send(msg)
            return jsonify({'message': 'Reset email sent'})
    except Exception as e:
        return jsonify({'error': f'Failed to send email: {str(e)}'}), 500
    finally:
        conn.close()

@app.route('/reset-password', methods=['POST'])
def reset_password():
    token, new_password = request.json.get('token'), request.json.get('new_password')
    user_id = reset_tokens.get(token)
    if not user_id: return jsonify({'error': 'Invalid or expired token'}), 400

    hashed_pw = generate_password_hash(new_password)
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("UPDATE users SET password=%s WHERE id=%s", (hashed_pw, user_id))
            conn.commit()
            del reset_tokens[token]
            return jsonify({'message': 'Password updated successfully'})
    finally:
        conn.close()

# --- USER MANAGEMENT ROUTES ---
@app.route('/users', methods=['POST'])
def add_user():
    owner_id = get_current_user_id()
    if not owner_id:
        return jsonify({'error': 'Not logged in'}), 401
    data = request.json
    name, user_class, role = data.get('name'), data.get('class'), data.get('role', 'student')
    if not all([name, user_class]): return jsonify({'error': 'Name and class are required'}), 400

    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO users (name, role, class, owner_id) VALUES (%s, %s, %s, %s) RETURNING id, name, role, class",
                (name, role, user_class, owner_id)
            )
            user = cur.fetchone()
            conn.commit()
            return jsonify({'id': user[0], 'name': user[1], 'role': user[2], 'class': user[3]}), 201
    finally:
        conn.close()

@app.route('/users', methods=['GET'])
def get_users():
    owner_id = get_current_user_id()
    if not owner_id:
        return jsonify({'error': 'Not logged in'}), 401
    class_filter = request.args.get('class')

    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            sql = "SELECT id, name, role, class FROM users WHERE owner_id = %s"
            params = [owner_id]
            if class_filter:
                sql += " AND class = %s"
                params.append(class_filter)
            cur.execute(sql, params)
            users = cur.fetchall()
            return jsonify([{'id': u[0], 'name': u[1], 'role': u[2], 'class': u[3]} for u in users])
    finally:
        conn.close()

@app.route('/users/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    owner_id = get_current_user_id()
    if not owner_id:
        return jsonify({'error': 'Not logged in'}), 401
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM users WHERE id = %s AND owner_id = %s RETURNING id", (user_id, owner_id))
            if cur.fetchone() is None:
                return jsonify({'error': 'User not found or permission denied'}), 404
            conn.commit()
            return jsonify({'message': 'User deleted successfully'})
    finally:
        conn.close()

# --- ATTENDANCE ROUTES ---
@app.route('/attendance', methods=['POST'])
def mark_attendance():
    owner_id = get_current_user_id()
    if not owner_id:
        return jsonify({'error': 'Not logged in'}), 401
    data = request.json
    user_id, date, status = data.get('user_id'), data.get('date'), data.get('status')
    if not all([user_id, date, status]):
        return jsonify({'error': 'User ID, date, and status are required'}), 400

    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            # Only allow marking attendance for users owned by this admin
            cur.execute("SELECT id FROM users WHERE id = %s AND owner_id = %s", (user_id, owner_id))
            if not cur.fetchone():
                return jsonify({'error': 'Permission denied'}), 403
            cur.execute(
                "INSERT INTO attendance (user_id, date, status) VALUES (%s, %s, %s) RETURNING id",
                (user_id, date, status)
            )
            att_id = cur.fetchone()[0]
            conn.commit()
            return jsonify({'id': att_id, 'user_id': user_id, 'date': date, 'status': status}), 201
    finally:
        conn.close()

@app.route('/attendance', methods=['GET'])
def get_attendance():
    owner_id = get_current_user_id()
    if not owner_id:
        return jsonify({'error': 'Not logged in'}), 401
    class_filter = request.args.get('class')

    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            sql = """
                SELECT a.id, u.name, u.class, a.date, a.status
                FROM attendance a JOIN users u ON a.user_id = u.id
                WHERE u.owner_id = %s
            """
            params = [owner_id]
            if class_filter:
                sql += " AND u.class = %s"
                params.append(class_filter)
            cur.execute(sql, params)
            records = cur.fetchall()
            return jsonify([{'id': r[0], 'name': r[1], 'class': r[2], 'date': str(r[3]), 'status': r[4]} for r in records])
    finally:
        conn.close()

@app.route('/attendance/<int:att_id>', methods=['PUT'])
def edit_attendance(att_id):
    owner_id = get_current_user_id()
    if not owner_id:
        return jsonify({'error': 'Not logged in'}), 401
    data = request.json
    status, date = data.get('status'), data.get('date')
    if not all([status, date]):
        return jsonify({'error': 'Status and date are required'}), 400

    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            # Only allow editing attendance for users owned by this admin
            cur.execute("""
                UPDATE attendance a SET status=%s, date=%s
                FROM users u WHERE a.user_id = u.id AND a.id = %s AND u.owner_id = %s
                RETURNING a.id
            """, (status, date, att_id, owner_id))
            if cur.fetchone() is None:
                return jsonify({'error': 'Attendance record not found or permission denied'}), 404
            conn.commit()
            return jsonify({'message': 'Attendance updated'})
    finally:
        conn.close()

# --- REPORTING ROUTE ---
@app.route('/attendance/report', methods=['GET'])
def attendance_report():
    owner_id = get_current_user_id()
    if not owner_id:
        return jsonify({'error': 'Not logged in'}), 401
    class_filter = request.args.get('class')

    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            sql = """
                SELECT u.id, u.name, u.role, u.class,
                    COALESCE(SUM(CASE WHEN a.status = 'Present' THEN 1 ELSE 0 END), 0) AS presents,
                    COALESCE(SUM(CASE WHEN a.status = 'Absent' THEN 1 ELSE 0 END), 0) AS absents,
                    COALESCE(SUM(CASE WHEN a.status = 'Late' THEN 1 ELSE 0 END), 0) AS lates
                FROM users u LEFT JOIN attendance a ON u.id = a.user_id
                WHERE u.owner_id = %s
            """
            params = [owner_id]
            if class_filter:
                sql += " AND u.class = %s"
                params.append(class_filter)
            sql += " GROUP BY u.id ORDER BY u.name"
            cur.execute(sql, params)
            report = cur.fetchall()
            return jsonify([{'id': r[0], 'name': r[1], 'role': r[2], 'class': r[3], 'present': r[4], 'absent': r[5], 'late': r[6]} for r in report])
    finally:
        conn.close()

# --- CLASS MANAGEMENT ROUTES ---
@app.route('/classes', methods=['GET'])
def get_classes():
    owner_id = get_current_user_id()
    if not owner_id:
        return jsonify({'error': 'Not logged in'}), 401
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT DISTINCT class FROM users WHERE owner_id=%s AND class IS NOT NULL", (owner_id,))
            return jsonify([row[0] for row in cur.fetchall()])
    finally:
        conn.close()

@app.route('/class/<old_class>', methods=['PUT'])
def rename_class(old_class):
    owner_id = get_current_user_id()
    if not owner_id:
        return jsonify({'error': 'Not logged in'}), 401
    new_name = request.json.get('newName')
    if not new_name: return jsonify({'error': 'New class name required'}), 400

    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("UPDATE users SET class=%s WHERE class=%s AND owner_id=%s", (new_name, old_class, owner_id))
            conn.commit()
            return jsonify({'message': f'Class {old_class} renamed to {new_name}'})
    finally:
        conn.close()

@app.route('/class/<class_name>', methods=['DELETE'])
def delete_class(class_name):
    owner_id = get_current_user_id()
    if not owner_id:
        return jsonify({'error': 'Not logged in'}), 401
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM users WHERE class=%s AND owner_id=%s", (class_name, owner_id))
            conn.commit()
            return jsonify({'message': f'Class {class_name} and its students have been deleted'})
    finally:
        conn.close()

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)
