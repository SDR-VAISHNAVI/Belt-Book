from flask import Flask, request, jsonify, render_template, make_response
from flask_cors import CORS
from datetime import date
from collections import defaultdict
import psycopg2
from psycopg2.extras import RealDictCursor
from psycopg2 import pool
import requests as http_requests
from flask import send_from_directory
import os
import secrets
import bcrypt

app = Flask(__name__)
CORS(app, supports_credentials=True)

DATABASE_URL         = "postgresql://postgres.losiamfhydgdsojghcui:VaishnaviGiri@aws-1-ap-southeast-1.pooler.supabase.com:5432/postgres"
WHATSAPP_SERVICE_URL = os.environ.get("WHATSAPP_SERVICE_URL", "http://localhost:3000")

# Connection pool — reuses DB connections instead of opening a new one per request.
# minconn=1 keeps one connection always alive, maxconn=10 allows up to 10 concurrent.
# keepalives prevent stale connections from being dropped by Supabase after idle periods.
db_pool = pool.ThreadedConnectionPool(
    minconn=1,
    maxconn=10,
    dsn=DATABASE_URL,
    keepalives=1,
    keepalives_idle=30,
    keepalives_interval=10,
    keepalives_count=5
)

SESSION_COOKIE = "bb_session"

BELT_ORDER = [
    'White', 'Yellow', 'Orange', 'Green', 'Blue',
    'Purple 1', 'Purple 2', 'Brown 1', 'Brown 2', 'Black'
]
MONTH_NAMES = ['','January','February','March','April','May','June',
               'July','August','September','October','November','December']


# ──────────────────────────────────────────────────────────────
# DB HELPERS
# ──────────────────────────────────────────────────────────────

def get_conn():
    return db_pool.getconn()

def put_conn(conn):
    db_pool.putconn(conn)


def next_belt(current):
    clean = (current or '').lower().replace(' belt', '').strip()
    try:
        idx = next(i for i, b in enumerate(BELT_ORDER) if b.lower() == clean)
        return BELT_ORDER[min(idx + 1, len(BELT_ORDER) - 1)]
    except StopIteration:
        return current


# ──────────────────────────────────────────────────────────────
# AUTH HELPERS
# ──────────────────────────────────────────────────────────────

def get_current_owner():
    """Return owner dict from cookie token, or None."""
    token = request.cookies.get(SESSION_COOKIE)
    if not token or len(token) != 64:
        return None
    conn = get_conn()
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""
            UPDATE app_sessions
               SET last_seen = NOW()
             WHERE token = %s
         RETURNING owner_id
        """, (token,))
        row = cur.fetchone()
        if not row:
            conn.rollback()
            return None
        conn.commit()
        cur.execute("SELECT id, username, name FROM owners WHERE id = %s", (row['owner_id'],))
        owner = cur.fetchone()
        return dict(owner) if owner else None
    except Exception:
        conn.rollback()
        return None
    finally:
        cur.close(); put_conn(conn)


def require_auth():
    """Returns (owner_dict, None) or (None, error_response)."""
    owner = get_current_owner()
    if not owner:
        return None, (jsonify({"error": "Unauthorized"}), 401)
    return owner, None


# ──────────────────────────────────────────────────────────────
# STATIC / PWA
# ──────────────────────────────────────────────────────────────

@app.route('/static/service-worker.js')
def service_worker():
    return send_from_directory(
        os.path.join(app.root_path, 'static'),
        'service-worker.js',
        mimetype='application/javascript'
    )


# ──────────────────────────────────────────────────────────────
# AUTH ENDPOINTS
# ──────────────────────────────────────────────────────────────

@app.route('/api/auth/login', methods=['POST'], strict_slashes=False)
def login():
    data     = request.get_json() or {}
    username = (data.get('username') or '').strip().lower()
    password = (data.get('password') or '').strip()

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    conn = get_conn()
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT id, username, password, name FROM owners WHERE username = %s", (username,))
        owner = cur.fetchone()

        # FIX 2: Use bcrypt for secure password comparison.
        # The stored password must be a bcrypt hash (use hash_password() below when creating owners).
        if not owner or not bcrypt.checkpw(password.encode(), owner['password'].encode()):
            return jsonify({"error": "Invalid credentials"}), 401

        token = secrets.token_hex(32)   # 32 bytes = 64 hex chars

        cur2 = conn.cursor()
        cur2.execute(
            "INSERT INTO app_sessions (token, owner_id) VALUES (%s, %s)",
            (token, owner['id'])
        )
        conn.commit()
        cur2.close()

        resp = make_response(jsonify({
            "success": True,
            "owner": {"id": owner['id'], "username": owner['username'], "name": owner['name']}
        }))
        resp.set_cookie(
            SESSION_COOKIE, token,
            httponly=True,
            samesite='Strict',
            secure=os.environ.get("FLASK_ENV") != "development",
            max_age=60 * 60 * 24 * 365 * 10
        )
        return resp

    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        cur.close(); put_conn(conn)


@app.route('/api/auth/logout', methods=['POST'], strict_slashes=False)
def logout():
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        conn = get_conn()
        try:
            cur = conn.cursor()
            cur.execute("DELETE FROM app_sessions WHERE token = %s", (token,))
            conn.commit()
        except Exception:
            conn.rollback()
        finally:
            cur.close(); put_conn(conn)
    resp = make_response(jsonify({"success": True}))
    resp.delete_cookie(SESSION_COOKIE)
    return resp


@app.route('/api/auth/me', strict_slashes=False)
def me():
    owner = get_current_owner()
    if not owner:
        return jsonify({"authenticated": False}), 401
    return jsonify({"authenticated": True, "owner": owner})


# ──────────────────────────────────────────────────────────────
# UTILITY: hash a plain-text password (use when creating owners)
# e.g. call hash_password("mypassword") from a one-off script
# ──────────────────────────────────────────────────────────────

def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()


# ──────────────────────────────────────────────────────────────
# WHATSAPP — per-owner proxy
# ──────────────────────────────────────────────────────────────

@app.route('/api/send-absence-notifications', methods=['POST'], strict_slashes=False)
def send_absence_notifications():
    owner, err = require_auth()
    if err: return err

    data     = request.get_json() or {}
    students = data.get('students', [])
    att_date = data.get('date', str(date.today()))

    if not students:
        return jsonify({"success": True, "sent": 0, "failed": 0})

    try:
        payload = {
            "students": [
                {"name": s["name"], "phone_number": str(s["phone_number"])}
                for s in students if s.get("phone_number")
            ],
            "date": att_date,
            "owner_id": owner['id']
        }
        resp = http_requests.post(
            f"{WHATSAPP_SERVICE_URL}/send-absence",
            json=payload, timeout=30
        )
        try:
            result = resp.json()
        except Exception:
            return jsonify({"success": False,
                            "error": f"WA service non-JSON ({resp.status_code}): {resp.text[:200]}"}), 502
        return jsonify(result), resp.status_code
    except http_requests.exceptions.ConnectionError:
        return jsonify({"success": False, "error": "Could not reach WhatsApp service"}), 503
    except http_requests.exceptions.Timeout:
        return jsonify({"success": False, "error": "WhatsApp service timed out"}), 504
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/whatsapp/status', strict_slashes=False)
def wa_status():
    owner, err = require_auth()
    if err: return err
    try:
        resp = http_requests.get(
            f"{WHATSAPP_SERVICE_URL}/status",
            params={"owner_id": owner['id']},
            timeout=8
        )
        return jsonify(resp.json()), resp.status_code
    except Exception as e:
        return jsonify({"connected": False, "error": str(e)}), 503


@app.route('/api/whatsapp/connect', methods=['POST'], strict_slashes=False)
def wa_connect():
    owner, err = require_auth()
    if err: return err
    # Read whatsapp_number from the owners table
    conn = get_conn()
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT whatsapp_number FROM owners WHERE id = %s", (owner['id'],))
        row = cur.fetchone()
        phone_number = (row['whatsapp_number'] or '').strip() if row else ''
    except Exception as e:
        return jsonify({"error": f"DB error: {str(e)}"}), 500
    finally:
        cur.close(); put_conn(conn)

    if not phone_number:
        return jsonify({"error": "No WhatsApp number set for your account. Add whatsapp_number to the owners table in Supabase."}), 400

    try:
        resp = http_requests.post(
            f"{WHATSAPP_SERVICE_URL}/connect",
            json={"owner_id": owner['id'], "phone_number": phone_number},
            timeout=15
        )
        return jsonify(resp.json()), resp.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 503


@app.route('/api/whatsapp/qr', strict_slashes=False)
def wa_qr():
    owner, err = require_auth()
    if err: return err
    try:
        resp = http_requests.get(
            f"{WHATSAPP_SERVICE_URL}/qr-data",
            params={"owner_id": owner['id']},
            timeout=10
        )
        return jsonify(resp.json()), resp.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 503


@app.route('/api/whatsapp/logout', methods=['POST'], strict_slashes=False)
def wa_logout():
    owner, err = require_auth()
    if err: return err
    try:
        resp = http_requests.post(
            f"{WHATSAPP_SERVICE_URL}/logout",
            json={"owner_id": owner['id']},
            timeout=10
        )
        return jsonify(resp.json()), resp.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 503


# ──────────────────────────────────────────────────────────────
# DOJOS  (scoped to owner)
# ──────────────────────────────────────────────────────────────

@app.route('/api/dojos', strict_slashes=False)
def get_dojos():
    owner, err = require_auth()
    if err: return err
    conn = get_conn()
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT id, name FROM dojos WHERE owner_id = %s ORDER BY name", (owner['id'],))
        return jsonify(cur.fetchall())
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cur.close(); put_conn(conn)


@app.route('/api/dojos', methods=['POST'], strict_slashes=False)
def add_dojo():
    owner, err = require_auth()
    if err: return err
    data = request.get_json() or {}
    name = (data.get('name') or '').strip()
    if not name:
        return jsonify({"error": "name required"}), 400
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO dojos (name, owner_id) VALUES (%s, %s) RETURNING id",
            (name, owner['id'])
        )
        dojo_id = cur.fetchone()[0]
        conn.commit()
        return jsonify({"success": True, "id": dojo_id}), 201
    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        cur.close(); put_conn(conn)


@app.route('/api/dojos/<int:dojo_id>', methods=['DELETE'], strict_slashes=False)
def delete_dojo(dojo_id):
    owner, err = require_auth()
    if err: return err
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM dojos WHERE id = %s AND owner_id = %s", (dojo_id, owner['id']))
        conn.commit()
        return jsonify({"success": True})
    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        cur.close(); put_conn(conn)


# ──────────────────────────────────────────────────────────────
# BATCHES  (owner verified via dojo ownership)
# ──────────────────────────────────────────────────────────────

def _assert_dojo_owner(cur, dojo_id, owner_id):
    cur.execute("SELECT id FROM dojos WHERE id = %s AND owner_id = %s", (dojo_id, owner_id))
    if not cur.fetchone():
        raise ValueError("Dojo not found or access denied")


@app.route('/api/batches', strict_slashes=False)
def get_batches():
    owner, err = require_auth()
    if err: return err
    dojo_id = request.args.get('dojo_id')
    if not dojo_id:
        return jsonify({"error": "dojo_id required"}), 400
    conn = get_conn()
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        _assert_dojo_owner(cur, dojo_id, owner['id'])
        # FIX 3: Return class_time and days columns so the frontend can use them.
        cur.execute(
            "SELECT id, name, class_time, days FROM batches WHERE dojo_id = %s ORDER BY name",
            (dojo_id,)
        )
        return jsonify(cur.fetchall())
    except ValueError as e:
        return jsonify({"error": str(e)}), 403
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cur.close(); put_conn(conn)


@app.route('/api/batches', methods=['POST'], strict_slashes=False)
def add_batch():
    owner, err = require_auth()
    if err: return err
    data       = request.get_json() or {}
    name       = (data.get('name') or '').strip()
    dojo_id    = data.get('dojo_id')
    class_time = (data.get('class_time') or '').strip() or None
    days       = (data.get('days') or '').strip() or None
    if not name or not dojo_id:
        return jsonify({"error": "name and dojo_id required"}), 400
    conn = get_conn()
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        _assert_dojo_owner(cur, dojo_id, owner['id'])
        cur2 = conn.cursor()
        # FIX 3 (cont.): Persist class_time and days columns.
        cur2.execute(
            "INSERT INTO batches (name, dojo_id, class_time, days) VALUES (%s, %s, %s, %s) RETURNING id",
            (name, dojo_id, class_time, days)
        )
        batch_id = cur2.fetchone()[0]
        conn.commit()
        return jsonify({"success": True, "id": batch_id}), 201
    except ValueError as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 403
    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        cur.close(); put_conn(conn)


@app.route('/api/batches/<int:batch_id>', methods=['DELETE'], strict_slashes=False)
def delete_batch(batch_id):
    owner, err = require_auth()
    if err: return err
    conn = get_conn()
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""
            SELECT b.id FROM batches b
            JOIN dojos d ON b.dojo_id = d.id
            WHERE b.id = %s AND d.owner_id = %s
        """, (batch_id, owner['id']))
        if not cur.fetchone():
            return jsonify({"error": "Not found or access denied"}), 403
        cur2 = conn.cursor()
        cur2.execute("DELETE FROM batches WHERE id = %s", (batch_id,))
        conn.commit()
        return jsonify({"success": True})
    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        cur.close(); put_conn(conn)


# ──────────────────────────────────────────────────────────────
# STUDENTS  (owner verified through batch → dojo chain)
# ──────────────────────────────────────────────────────────────

def _assert_batch_owner(cur, batch_id, owner_id):
    cur.execute("""
        SELECT b.id FROM batches b
        JOIN dojos d ON b.dojo_id = d.id
        WHERE b.id = %s AND d.owner_id = %s
    """, (batch_id, owner_id))
    if not cur.fetchone():
        raise ValueError("Batch not found or access denied")


def _assert_student_owner(cur, student_id, owner_id):
    cur.execute("""
        SELECT s.id FROM students s
        JOIN batches b ON s.batch_id = b.id
        JOIN dojos   d ON b.dojo_id  = d.id
        WHERE s.id = %s AND d.owner_id = %s
    """, (student_id, owner_id))
    if not cur.fetchone():
        raise ValueError("Student not found or access denied")


@app.route('/api/students', strict_slashes=False)
def get_students():
    owner, err = require_auth()
    if err: return err
    batch_id = request.args.get('batch_id')
    dojo_id  = request.args.get('dojo_id')
    conn = get_conn()
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        if batch_id:
            _assert_batch_owner(cur, batch_id, owner['id'])
            cur.execute("""
                SELECT s.id, s.name, s.belt_level, s.batch_id,
                       s.phone_number, b.dojo_id, b.name AS batch_name
                FROM students s JOIN batches b ON s.batch_id = b.id
                WHERE s.batch_id = %s ORDER BY s.name
            """, (batch_id,))
        elif dojo_id:
            _assert_dojo_owner(cur, dojo_id, owner['id'])
            cur.execute("""
                SELECT s.id, s.name, s.belt_level, s.batch_id,
                       s.phone_number, b.dojo_id, b.name AS batch_name
                FROM students s JOIN batches b ON s.batch_id = b.id
                WHERE b.dojo_id = %s ORDER BY s.name
            """, (dojo_id,))
        else:
            return jsonify({"error": "batch_id or dojo_id required"}), 400
        return jsonify(cur.fetchall())
    except ValueError as e:
        return jsonify({"error": str(e)}), 403
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cur.close(); put_conn(conn)


@app.route('/api/students/stats', strict_slashes=False)
def student_stats():
    owner, err = require_auth()
    if err: return err
    conn = get_conn()
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""
            SELECT COUNT(*) AS total FROM students s
            JOIN batches b ON s.batch_id = b.id
            JOIN dojos   d ON b.dojo_id  = d.id
            WHERE d.owner_id = %s
        """, (owner['id'],))
        total = cur.fetchone()['total']
        cur.execute("""
            SELECT COUNT(*) AS black FROM students s
            JOIN batches b ON s.batch_id = b.id
            JOIN dojos   d ON b.dojo_id  = d.id
            WHERE d.owner_id = %s AND LOWER(s.belt_level) LIKE '%%black%%'
        """, (owner['id'],))
        black = cur.fetchone()['black']
        cur.execute("""
            SELECT COUNT(*) AS batches FROM batches b
            JOIN dojos d ON b.dojo_id = d.id
            WHERE d.owner_id = %s
        """, (owner['id'],))
        batches = cur.fetchone()['batches']
        return jsonify({"total": total, "black": black, "batches": batches})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cur.close(); put_conn(conn)


@app.route('/api/students/<int:student_id>/profile', strict_slashes=False)
def student_profile(student_id):
    owner, err = require_auth()
    if err: return err
    conn = get_conn()
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        _assert_student_owner(cur, student_id, owner['id'])

        cur.execute("""
            SELECT s.id, s.name, s.belt_level, s.phone_number,
                   b.name AS batch_name, b.id AS batch_id,
                   d.name AS dojo_name,  d.id AS dojo_id
            FROM students s JOIN batches b ON s.batch_id = b.id
            JOIN dojos d ON b.dojo_id = d.id
            WHERE s.id = %s
        """, (student_id,))
        student = cur.fetchone()
        if not student:
            return jsonify({"error": "Student not found"}), 404

        cur.execute("""
            SELECT date, status FROM attendance
            WHERE student_id = %s ORDER BY date DESC LIMIT 100
        """, (student_id,))
        att_records = cur.fetchall()

        cur.execute("""
            SELECT COUNT(*) AS total_classes,
                   SUM(CASE WHEN status='present' THEN 1 ELSE 0 END) AS total_present,
                   SUM(CASE WHEN status='absent'  THEN 1 ELSE 0 END) AS total_absent
            FROM attendance WHERE student_id = %s
        """, (student_id,))
        att_stats = cur.fetchone()

        cur.execute("""
            SELECT EXTRACT(YEAR  FROM date)::int AS year,
                   EXTRACT(MONTH FROM date)::int AS month,
                   SUM(CASE WHEN status='present' THEN 1 ELSE 0 END) AS present,
                   SUM(CASE WHEN status='absent'  THEN 1 ELSE 0 END) AS absent,
                   COUNT(*) AS total
            FROM attendance WHERE student_id = %s
            GROUP BY year, month ORDER BY year DESC, month DESC LIMIT 6
        """, (student_id,))
        monthly_att = cur.fetchall()

        cur.execute("""
            SELECT month, year, status FROM fees
            WHERE student_id = %s ORDER BY year DESC, month DESC LIMIT 12
        """, (student_id,))
        fee_records = cur.fetchall()

        total   = att_stats['total_classes'] or 0
        present = att_stats['total_present'] or 0
        absent  = att_stats['total_absent']  or 0
        pct     = round(present / total * 100, 1) if total else 0

        return jsonify({
            "student": dict(student),
            "attendance": {
                "records": [dict(r) for r in att_records],
                "stats":   {"total": total, "present": present, "absent": absent, "percentage": pct},
                "monthly": [dict(r) for r in monthly_att]
            },
            "fees": [dict(r) for r in fee_records]
        })
    except ValueError as e:
        return jsonify({"error": str(e)}), 403
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cur.close(); put_conn(conn)


@app.route('/api/students', methods=['POST'], strict_slashes=False)
def add_student():
    owner, err = require_auth()
    if err: return err
    data         = request.get_json() or {}
    name         = (data.get('name') or '').strip()
    batch_id     = data.get('batch_id')
    belt         = (data.get('belt_level') or 'White').strip()
    phone_number = (data.get('phone_number') or '').strip()
    if not name:     return jsonify({"error": "name required"}), 400
    if not batch_id: return jsonify({"error": "batch_id required"}), 400
    conn = get_conn()
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        _assert_batch_owner(cur, batch_id, owner['id'])
        cur2 = conn.cursor()
        cur2.execute("""
            INSERT INTO students (name, batch_id, belt_level, phone_number)
            VALUES (%s, %s, %s, %s) RETURNING id
        """, (name, batch_id, belt, phone_number or None))
        student_id = cur2.fetchone()[0]
        conn.commit()
        return jsonify({"success": True, "id": student_id}), 201
    except ValueError as e:
        conn.rollback(); return jsonify({"error": str(e)}), 403
    except Exception as e:
        conn.rollback(); return jsonify({"error": str(e)}), 500
    finally:
        cur.close(); put_conn(conn)


@app.route('/api/students/<int:student_id>', methods=['PUT'], strict_slashes=False)
def update_student(student_id):
    owner, err = require_auth()
    if err: return err
    data         = request.get_json() or {}
    name         = (data.get('name') or '').strip()
    batch_id     = data.get('batch_id')
    belt         = (data.get('belt_level') or 'White').strip()
    phone_number = (data.get('phone_number') or '').strip()
    if not name:     return jsonify({"error": "name required"}), 400
    if not batch_id: return jsonify({"error": "batch_id required"}), 400
    conn = get_conn()
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        _assert_student_owner(cur, student_id, owner['id'])
        _assert_batch_owner(cur, batch_id, owner['id'])
        cur2 = conn.cursor()
        cur2.execute("""
            UPDATE students SET name=%s, batch_id=%s, belt_level=%s, phone_number=%s
            WHERE id = %s
        """, (name, batch_id, belt, phone_number or None, student_id))
        conn.commit()
        return jsonify({"success": True})
    except ValueError as e:
        conn.rollback(); return jsonify({"error": str(e)}), 403
    except Exception as e:
        conn.rollback(); return jsonify({"error": str(e)}), 500
    finally:
        cur.close(); put_conn(conn)


@app.route('/api/students/<int:student_id>', methods=['DELETE'], strict_slashes=False)
def delete_student(student_id):
    owner, err = require_auth()
    if err: return err
    conn = get_conn()
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        _assert_student_owner(cur, student_id, owner['id'])
        cur2 = conn.cursor()
        cur2.execute("DELETE FROM attendance WHERE student_id=%s", (student_id,))
        cur2.execute("DELETE FROM fees WHERE student_id=%s", (student_id,))
        cur2.execute("DELETE FROM students WHERE id=%s", (student_id,))
        conn.commit()
        return jsonify({"success": True})
    except ValueError as e:
        conn.rollback(); return jsonify({"error": str(e)}), 403
    except Exception as e:
        conn.rollback(); return jsonify({"error": str(e)}), 500
    finally:
        cur.close(); put_conn(conn)


# ──────────────────────────────────────────────────────────────
# ATTENDANCE
# ──────────────────────────────────────────────────────────────

@app.route('/api/attendance', methods=['POST'], strict_slashes=False)
def mark_attendance():
    owner, err = require_auth()
    if err: return err
    body    = request.get_json() or {}
    records = body.get('records', [])
    if not records:
        return jsonify({"error": "records list is empty"}), 400
    conn = get_conn()
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        first_sid = records[0].get('student_id')
        _assert_student_owner(cur, first_sid, owner['id'])

        cur2 = conn.cursor()
        for r in records:
            att_date = r.get('date') or date.today().isoformat()
            # FIX 4: marked_at is now explicitly set so the column is never null.
            cur2.execute("""
                INSERT INTO attendance (student_id, status, date, marked_at)
                VALUES (%s, %s, %s, NOW())
                ON CONFLICT (student_id, date)
                DO UPDATE SET status = EXCLUDED.status, marked_at = NOW()
            """, (r['student_id'], r['status'], att_date))
        conn.commit()
        return jsonify({"success": True})
    except ValueError as e:
        conn.rollback(); return jsonify({"error": str(e)}), 403
    except Exception as e:
        conn.rollback(); return jsonify({"error": str(e)}), 500
    finally:
        cur.close(); put_conn(conn)


# ──────────────────────────────────────────────────────────────
# NO-ABSENCES MONTHLY REPORT
# ──────────────────────────────────────────────────────────────

@app.route('/api/attendance/no-absences', strict_slashes=False)
def no_absences():
    owner, err = require_auth()
    if err: return err
    dojo_id  = request.args.get('dojo_id')
    month    = request.args.get('month')
    year     = request.args.get('year')
    batch_id = request.args.get('batch_id')
    if not dojo_id or not month or not year:
        return jsonify({"error": "dojo_id, month, year required"}), 400

    conn = get_conn()
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        if dojo_id == 'all':
            base = """
                SELECT s.id, s.name, s.belt_level, b.name AS batch_name,
                       d.name AS dojo_name, b.id AS batch_id
                FROM students s JOIN batches b ON s.batch_id = b.id
                JOIN dojos d ON b.dojo_id = d.id
                WHERE d.owner_id = %s
            """
            params = [owner['id']]
            if batch_id:
                base += " AND s.batch_id = %s"; params.append(batch_id)
            base += " ORDER BY d.name, b.name, s.name"
            cur.execute(base, params)
        else:
            _assert_dojo_owner(cur, dojo_id, owner['id'])
            base = """
                SELECT s.id, s.name, s.belt_level, b.name AS batch_name,
                       d.name AS dojo_name, b.id AS batch_id
                FROM students s JOIN batches b ON s.batch_id = b.id
                JOIN dojos d ON b.dojo_id = d.id
                WHERE b.dojo_id = %s
            """
            params = [dojo_id]
            if batch_id:
                base += " AND s.batch_id = %s"; params.append(batch_id)
            base += " ORDER BY b.name, s.name"
            cur.execute(base, params)

        all_students = cur.fetchall()
        if not all_students:
            return jsonify({"no_absence_students": [], "had_absence_students": [], "total_students": 0})

        student_ids = [s['id'] for s in all_students]
        cur.execute("""
            SELECT DISTINCT student_id FROM attendance
            WHERE student_id = ANY(%s) AND status='absent'
              AND EXTRACT(MONTH FROM date)=%s AND EXTRACT(YEAR FROM date)=%s
        """, (student_ids, int(month), int(year)))
        had_abs = {r['student_id'] for r in cur.fetchall()}

        cur.execute("""
            SELECT DISTINCT student_id FROM attendance
            WHERE student_id = ANY(%s)
              AND EXTRACT(MONTH FROM date)=%s AND EXTRACT(YEAR FROM date)=%s
        """, (student_ids, int(month), int(year)))
        has_rec = {r['student_id'] for r in cur.fetchall()}

        no_abs, had_abs_list = [], []
        for s in all_students:
            sid = s['id']
            if sid in had_abs:       had_abs_list.append(dict(s))
            elif sid in has_rec:     no_abs.append(dict(s))

        return jsonify({"no_absence_students": no_abs,
                        "had_absence_students": had_abs_list,
                        "total_students": len(all_students)})
    except ValueError as e:
        return jsonify({"error": str(e)}), 403
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cur.close(); put_conn(conn)


# ──────────────────────────────────────────────────────────────
# DAILY REPORT
# ──────────────────────────────────────────────────────────────

@app.route('/api/reports', strict_slashes=False)
def get_report():
    owner, err = require_auth()
    if err: return err
    batch_id = request.args.get('batch_id')
    att_date = request.args.get('date')
    if not batch_id: return jsonify({"error": "batch_id required"}), 400
    if not att_date: return jsonify({"error": "date required"}), 400
    conn = get_conn()
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        _assert_batch_owner(cur, batch_id, owner['id'])
        cur.execute("""
            SELECT s.id, s.name, s.belt_level, b.name AS batch_name
            FROM students s JOIN batches b ON s.batch_id = b.id
            WHERE s.batch_id = %s ORDER BY s.name
        """, (batch_id,))
        students_list = cur.fetchall()
        if not students_list:
            return jsonify({"students": [], "summary": {"total":0,"present":0,"absent":0,"unmarked":0,"percent":0}})
        cur.execute("""
            SELECT a.student_id, a.status FROM attendance a
            JOIN students s ON a.student_id = s.id
            WHERE a.date = %s AND s.batch_id = %s
        """, (att_date, batch_id))
        att_map = {r['student_id']: r['status'] for r in cur.fetchall()}
        result  = [{"id": s["id"], "name": s["name"], "belt_level": s["belt_level"],
                    "batch_name": s.get("batch_name",""), "status": att_map.get(s["id"])}
                   for s in students_list]
        total    = len(result)
        present  = sum(1 for r in result if r["status"] == "present")
        absent   = sum(1 for r in result if r["status"] == "absent")
        unmarked = total - present - absent
        percent  = round(present / total * 100, 1) if total else 0
        return jsonify({"students": result, "summary": {
            "total": total, "present": present, "absent": absent,
            "unmarked": unmarked, "percent": percent
        }})
    except ValueError as e:
        return jsonify({"error": str(e)}), 403
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cur.close(); put_conn(conn)


# ──────────────────────────────────────────────────────────────
# FEES
# ──────────────────────────────────────────────────────────────

@app.route('/api/fees', strict_slashes=False)
def get_fees():
    owner, err = require_auth()
    if err: return err
    dojo_id = request.args.get('dojo_id')
    month   = request.args.get('month')
    year    = request.args.get('year')
    if not dojo_id or not month or not year:
        return jsonify({"error": "dojo_id, month, year required"}), 400
    conn = get_conn()
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        _assert_dojo_owner(cur, dojo_id, owner['id'])
        cur.execute("""
            SELECT s.id, s.name, s.belt_level,
                   b.id AS batch_id, b.name AS batch_name,
                   COALESCE(f.status, 'unpaid') AS fee_status
            FROM students s
            JOIN batches b ON s.batch_id = b.id
            LEFT JOIN fees f ON f.student_id = s.id AND f.month = %s AND f.year = %s
            WHERE b.dojo_id = %s
            ORDER BY b.name, s.name
        """, (month, year, dojo_id))
        return jsonify(cur.fetchall())
    except ValueError as e:
        return jsonify({"error": str(e)}), 403
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cur.close(); put_conn(conn)


@app.route('/api/fees', methods=['POST'], strict_slashes=False)
def update_fee():
    owner, err = require_auth()
    if err: return err
    data       = request.get_json() or {}
    student_id = data.get('student_id')
    month      = data.get('month')
    year       = data.get('year')
    status     = data.get('status', 'unpaid')
    if not student_id or not month or not year:
        return jsonify({"error": "student_id, month, year required"}), 400
    conn = get_conn()
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        _assert_student_owner(cur, student_id, owner['id'])
        cur2 = conn.cursor()
        cur2.execute("""
            INSERT INTO fees (student_id, month, year, status)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (student_id, month, year)
            DO UPDATE SET status = EXCLUDED.status
        """, (student_id, month, year, status))
        conn.commit()
        return jsonify({"success": True})
    except ValueError as e:
        conn.rollback(); return jsonify({"error": str(e)}), 403
    except Exception as e:
        conn.rollback(); return jsonify({"error": str(e)}), 500
    finally:
        cur.close(); put_conn(conn)


# ──────────────────────────────────────────────────────────────
# BELT TEST
# ──────────────────────────────────────────────────────────────

@app.route('/api/belt-test/students', strict_slashes=False)
def belt_test_students():
    owner, err = require_auth()
    if err: return err
    dojo_id  = request.args.get('dojo_id')
    batch_id = request.args.get('batch_id')
    if not dojo_id: return jsonify({"error": "dojo_id required"}), 400
    conn = get_conn()
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        _assert_dojo_owner(cur, dojo_id, owner['id'])
        if batch_id:
            cur.execute("""
                SELECT s.id, s.name, s.belt_level, b.name AS batch_name, b.id AS batch_id,
                       d.name AS dojo_name
                FROM students s JOIN batches b ON s.batch_id = b.id
                JOIN dojos d ON b.dojo_id = d.id
                WHERE b.dojo_id = %s AND s.batch_id = %s ORDER BY b.name, s.name
            """, (dojo_id, batch_id))
        else:
            cur.execute("""
                SELECT s.id, s.name, s.belt_level, b.name AS batch_name, b.id AS batch_id,
                       d.name AS dojo_name
                FROM students s JOIN batches b ON s.batch_id = b.id
                JOIN dojos d ON b.dojo_id = d.id
                WHERE b.dojo_id = %s ORDER BY b.name, s.name
            """, (dojo_id,))

        students = cur.fetchall()
        if not students: return jsonify([])

        student_ids = [s['id'] for s in students]
        cur.execute("""
            SELECT student_id,
                   SUM(CASE WHEN status='absent'  THEN 1 ELSE 0 END) AS absences,
                   SUM(CASE WHEN status='present' THEN 1 ELSE 0 END) AS present,
                   COUNT(*) AS total
            FROM attendance WHERE student_id = ANY(%s) GROUP BY student_id
        """, (student_ids,))
        att_map = {r['student_id']: r for r in cur.fetchall()}

        result = []
        for s in students:
            sid = s['id']
            att = att_map.get(sid)
            total    = int(att['total'])    if att else 0
            present  = int(att['present'])  if att else 0
            absences = int(att['absences']) if att else 0
            pct      = round(present / total * 100, 1) if total else 0
            result.append({**dict(s), "attendance_stats": {
                "total": total, "present": present, "absences": absences, "percentage": pct
            }})
        result.sort(key=lambda x: (x['attendance_stats']['absences'], -x['attendance_stats']['percentage']))
        return jsonify(result)
    except ValueError as e:
        return jsonify({"error": str(e)}), 403
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cur.close(); put_conn(conn)


@app.route('/api/belt-test/promote', methods=['POST'], strict_slashes=False)
def belt_test_promote():
    owner, err = require_auth()
    if err: return err
    data           = request.get_json() or {}
    ineligible_ids = set(data.get('ineligible_ids', []))
    student_ids    = data.get('student_ids', [])
    if not student_ids: return jsonify({"error": "student_ids required"}), 400
    conn = get_conn()
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""
            SELECT s.id FROM students s
            JOIN batches b ON s.batch_id = b.id
            JOIN dojos   d ON b.dojo_id  = d.id
            WHERE s.id = ANY(%s) AND d.owner_id = %s
        """, (student_ids, owner['id']))
        allowed = {r['id'] for r in cur.fetchall()}
        if len(allowed) != len(student_ids):
            return jsonify({"error": "Access denied to some students"}), 403

        cur.execute("SELECT id, belt_level FROM students WHERE id = ANY(%s)", (student_ids,))
        rows = cur.fetchall()
        promoted = []; skipped = []
        cur2 = conn.cursor()
        for row in rows:
            sid = row['id']; belt = row['belt_level']
            if sid in ineligible_ids:
                skipped.append({"id": sid, "belt": belt}); continue
            new_belt = next_belt(belt)
            cur2.execute("UPDATE students SET belt_level=%s WHERE id=%s", (new_belt, sid))
            promoted.append({"id": sid, "old_belt": belt, "new_belt": new_belt})
        conn.commit(); cur2.close()
        return jsonify({"success": True, "promoted": promoted, "skipped": skipped})
    except Exception as e:
        conn.rollback(); return jsonify({"error": str(e)}), 500
    finally:
        cur.close(); put_conn(conn)


# ──────────────────────────────────────────────────────────────
# HOME
# ──────────────────────────────────────────────────────────────

@app.route('/')
def home():
    return render_template('index.html')


@app.route('/test')
def test():
    try:
        conn = get_conn()
        cur  = conn.cursor()
        cur.execute("SELECT 1")
        cur.close(); put_conn(conn)
        return "DB OK"
    except Exception as e:
        return str(e), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
