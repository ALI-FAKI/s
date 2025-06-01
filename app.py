from flask import Flask, request, jsonify, session
from flask_cors import CORS
import psycopg2
import hashlib
from functools import wraps
import os

app = Flask(__name__)
# Replace with your actual Vercel frontend URL in production!
CORS(app, supports_credentials=True, origins=["https://f-ken4wso36-ali-fakis-projects.vercel.app"])
app.secret_key = os.environ.get('SECRET_KEY', 'alifaliali24100')

# Connect to PostgreSQL using environment variable
DATABASE_URL = os.environ.get('DATABASE_URL')
if not DATABASE_URL:
    # Local fallback for development
    DATABASE_URL = "postgresql://postgres:1qaz1WSX@localhost:5432/attendance_db"
conn = psycopg2.connect(DATABASE_URL)
cur = conn.cursor()

# Create tables if not exist
cur.execute("""
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    role TEXT NOT NULL,
    password TEXT
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

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    name = data['name']
    role = data['role']
    password = hash_password(data['password'])
    try:
        cur.execute("INSERT INTO users (name, role, password) VALUES (%s, %s, %s) RETURNING id", (name, role, password))
        user_id = cur.fetchone()[0]
        conn.commit()
        return jsonify({'id': user_id, 'name': name, 'role': role})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    name = data['name']
    password = hash_password(data['password'])
    cur.execute("SELECT id, name, role FROM users WHERE name=%s AND password=%s", (name, password))
    user = cur.fetchone()
    if user:
        session['user_id'] = user[0]
        return jsonify({'id': user[0], 'name': user[1], 'role': user[2]})
    else:
        return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)
    return jsonify({'message': 'Logged out'})

@app.route('/api/users', methods=['POST'])
@login_required
def add_user():
    data = request.json
    cur.execute("INSERT INTO users (name, role) VALUES (%s, %s) RETURNING id", (data['name'], data['role']))
    user_id = cur.fetchone()[0]
    conn.commit()
    return jsonify({'id': user_id, 'name': data['name'], 'role': data['role']})

@app.route('/api/users', methods=['GET'])
@login_required
def get_users():
    cur.execute("SELECT id, name, role FROM users")
    users = cur.fetchall()
    return jsonify([{'id': u[0], 'name': u[1], 'role': u[2]} for u in users])

@app.route('/api/attendance', methods=['POST'])
@login_required
def mark_attendance():
    data = request.json
    cur.execute("INSERT INTO attendance (user_id, date, status) VALUES (%s, %s, %s) RETURNING id",
                (data['user_id'], data['date'], data['status']))
    att_id = cur.fetchone()[0]
    conn.commit()
    return jsonify({'id': att_id, **data})

@app.route('/api/attendance', methods=['GET'])
@login_required
def get_attendance():
    cur.execute("""
        SELECT a.id, u.name, a.date, a.status
        FROM attendance a
        JOIN users u ON a.user_id = u.id
    """)
    records = cur.fetchall()
    return jsonify([{'id': r[0], 'name': r[1], 'date': str(r[2]), 'status': r[3]} for r in records])

@app.route('/api/attendance/report', methods=['GET'])
@login_required
def attendance_report():
    cur.execute("""
        SELECT u.id, u.name, u.role,
            COALESCE(SUM(CASE WHEN a.status = 'Present' THEN 1 ELSE 0 END), 0) AS presents,
            COALESCE(SUM(CASE WHEN a.status = 'Absent' THEN 1 ELSE 0 END), 0) AS absents,
            COALESCE(SUM(CASE WHEN a.status = 'Late' THEN 1 ELSE 0 END), 0) AS lates
        FROM users u
        LEFT JOIN attendance a ON u.id = a.user_id
        GROUP BY u.id, u.name, u.role
        ORDER BY u.name
    """)
    report = cur.fetchall()
    return jsonify([
        {
            'id': r[0],
            'name': r[1],
            'role': r[2],
            'present': r[3],
            'absent': r[4],
            'late': r[5]
        } for r in report
    ])

if __name__ == '__main__':
    app.run(debug=True, port=5000, host='0.0.0.0')
