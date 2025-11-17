from flask import Flask, render_template, request, redirect, url_for, flash, session, abort
from flask_bcrypt import Bcrypt
import mysql.connector
import os, re, calendar
from pathlib import Path
from dotenv import load_dotenv
from functools import wraps
from datetime import datetime, timedelta

# -----------------------
# Load .env located next to this file
# -----------------------
load_dotenv(dotenv_path=Path(__file__).with_name(".env"))

# -----------------------
# Flask / Bcrypt setup
# -----------------------
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev-secret")
bcrypt = Bcrypt(app)

@app.template_filter("strip_leading_zero")
def strip_leading_zero(s: str) -> str:
    return s.lstrip("0") if isinstance(s, str) else s

# -----------------------
# DB connection helper
# -----------------------
def get_conn():
    return mysql.connector.connect(
        host=os.getenv("DB_HOST", "localhost"),
        user=os.getenv("DB_USER", "root"),
        password=os.getenv("DB_PASS", ""),
        database=os.getenv("DB_NAME", "exam_reg_db"),
        auth_plugin="mysql_native_password",
    )

# -----------------------
# Auth rules
# Students: 10 digits @student.csn.edu; password must equal those 10 digits
# Faculty:  firstname.lastname@csn.edu; password must be at least 7 chars
# -----------------------
STUDENT_RE = re.compile(r"^(\d{10})@student\.csn\.edu$", re.IGNORECASE)
FACULTY_RE = re.compile(r"^[A-Za-z]+\.[A-Za-z]+@csn\.edu$", re.IGNORECASE)

def classify_email(email: str):
    """
    Returns ('student', nshe_digits) or ('faculty', None) or (None, None)
    """
    if not email:
        return (None, None)
    m = STUDENT_RE.match(email)
    if m:
        return ("student", m.group(1))
    m = FACULTY_RE.match(email)
    if m:
        return ("faculty", None)
    return (None, None)

# -----------------------
# Role guards
# -----------------------
def login_required(fn):
    @wraps(fn)
    def w(*a, **k):
        if not session.get("user_id"):
            flash("Please log in.", "error")
            return redirect(url_for("login"))
        return fn(*a, **k)
    return w

def student_required(fn):
    @wraps(fn)
    def w(*a, **k):
        if session.get("role") != "student":
            abort(403)
        return fn(*a, **k)
    return w

def faculty_required(fn):
    @wraps(fn)
    def w(*a, **k):
        if session.get("role") != "faculty":
            abort(403)
        return fn(*a, **k)
    return w

# -----------------------
# Home
# -----------------------
@app.route("/")
def home():
    return render_template("home.html", user_name=session.get("user_name"))

# -----------------------
# Sign Up
# -----------------------
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "GET":
        return render_template("signup.html")

    full_name = request.form.get("full_name", "").strip()
    email     = request.form.get("email", "").strip().lower()
    password  = request.form.get("password", "")
    confirm   = request.form.get("confirm", "")
    role_sel  = request.form.get("role", "student").strip().lower()

    if not full_name or not email or not password or not confirm:
        flash("All fields are required.", "error")
        return redirect(url_for("signup"))

    detected_role, nshe_digits = classify_email(email)
    if detected_role is None:
        flash("Use CSN email: student=10digits@student.csn.edu, faculty=firstname.lastname@csn.edu", "error")
        return redirect(url_for("signup"))

    if detected_role != role_sel:
        flash(f"Selected role ({role_sel}) does not match the email format.", "error")
        return redirect(url_for("signup"))

    # Password rules
    if detected_role == "student":
        # Must equal the 10 digits from the email
        if password != confirm or password != nshe_digits:
            flash("Student password must equal the 10 digits in your CSN email.", "error")
            return redirect(url_for("signup"))
        nshe_to_store = nshe_digits
    else:
        # Faculty: at least 7 chars
        if password != confirm or len(password) < 7:
            flash("Faculty password must be at least 7 characters.", "error")
            return redirect(url_for("signup"))
        nshe_to_store = ""  # no NSHE requirement for faculty

    pw_hash = bcrypt.generate_password_hash(password).decode("utf-8")

    try:
        conn = get_conn()
        cur  = conn.cursor()
        cur.execute(
            "INSERT INTO users (email, nshe, full_name, password_hash, role) VALUES (%s,%s,%s,%s,%s)",
            (email, nshe_to_store, full_name, pw_hash, detected_role),
        )
        conn.commit()
        cur.close(); conn.close()
        flash("Account created! Please log in.", "success")
        return redirect(url_for("login"))
    except mysql.connector.errors.IntegrityError:
        try:
            cur.close(); conn.close()
        except:
            pass
        flash("That email is already registered.", "error")
        return redirect(url_for("signup"))

# -----------------------
# Login / Logout
# -----------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    email    = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")

    detected_role, nshe_digits = classify_email(email)
    if detected_role is None:
        flash("Use CSN email: student=10digits@student.csn.edu, faculty=firstname.lastname@csn.edu", "error")
        return redirect(url_for("login"))

    conn = get_conn()
    cur  = conn.cursor(dictionary=True)
    cur.execute("SELECT id, full_name, password_hash, role FROM users WHERE email=%s", (email,))
    user = cur.fetchone()
    cur.close(); conn.close()

    if not user:
        flash("Invalid email or password.", "error")
        return redirect(url_for("login"))

    # Enforce the assignment’s PW policy in addition to hash check
    if user["role"] == "student":
        if password != nshe_digits:
            flash("Student password must equal the 10 digits in your CSN email.", "error")
            return redirect(url_for("login"))
    else:
        if len(password) < 7:
            flash("Faculty password must be at least 7 characters.", "error")
            return redirect(url_for("login"))

    if bcrypt.check_password_hash(user["password_hash"], password):
        session["user_id"]   = user["id"]
        session["user_name"] = user["full_name"]
        session["role"]      = user.get("role", "student")
        flash("Logged in!", "success")
        return redirect(url_for("student_portal" if session["role"] == "student" else "faculty_portal"))

    flash("Invalid email or password.", "error")
    return redirect(url_for("login"))

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for("home"))

# -----------------------
# Helpers to load sessions for calendar
# -----------------------
def fetch_sessions_for_month(user_id, year, month):
    """
    Returns: list of dict rows with:
      id, session_datetime (datetime), duration_minutes,
      exam_code, campus_name, building_name, room_number,
      capacity, booked (active), already_registered (bool),
      registration_id (int or None)
    """
    first = datetime(year, month, 1)
    if month == 12:
        last = datetime(year + 1, 1, 1) - timedelta(seconds=1)
    else:
        last = datetime(year, month + 1, 1) - timedelta(seconds=1)

    conn = get_conn()
    cur  = conn.cursor(dictionary=True)
    # booked = count of not-canceled registrations
    cur.execute(
        """
        SELECT
            s.id,
            s.session_datetime,
            s.duration_minutes,
            s.capacity,
            e.exam_code,
            l.campus_name, l.building_name, l.room_number,
            COALESCE(b.booked, 0) AS booked,
            r.id   AS registration_id,
            r.cancelled AS r_cancelled
        FROM exam_sessions s
        JOIN exams e      ON e.id = s.exam_id
        JOIN locations l  ON l.id = s.location_id
        LEFT JOIN (
            SELECT session_id, COUNT(*) AS booked
            FROM registrations
            WHERE cancelled = 0
            GROUP BY session_id
        ) b ON b.session_id = s.id
        LEFT JOIN registrations r
            ON r.session_id = s.id AND r.user_id = %s
        WHERE s.session_datetime >= %s AND s.session_datetime <= %s
        ORDER BY s.session_datetime ASC
        """,
        (user_id, first, last),
    )
    rows = cur.fetchall()
    cur.close(); conn.close()

    # Normalize flags
    for r in rows:
        r["already_registered"] = (r["registration_id"] is not None and r["r_cancelled"] == 0)
        r["is_full"] = r["booked"] >= r["capacity"]
    return rows

def group_by_iso_date(rows):
    """
    Make a dict: 'YYYY-MM-DD' -> list(rows)
    """
    by_day = {}
    for r in rows:
        dt = r["session_datetime"]
        iso = f"{dt.year:04d}-{dt.month:02d}-{dt.day:02d}"
        by_day.setdefault(iso, []).append(r)
    return by_day

def next_prev_year_month(year, month):
    # previous
    if month == 1:
        prev_year, prev_month = (year - 1, 12)
    else:
        prev_year, prev_month = (year, month - 1)
    # next
    if month == 12:
        next_year, next_month = (year + 1, 1)
    else:
        next_year, next_month = (year, month + 1)
    return prev_year, prev_month, next_year, next_month

# -----------------------
# Student Portal (calendar + register/cancel + history)
# -----------------------
@app.route("/student", defaults={"year": None, "month": None})
@app.route("/student/<int:year>/<int:month>")
@login_required
@student_required
def student_portal(year, month):
    if year is None or month is None:
        now = datetime.now()
        year, month = now.year, now.month

    rows = fetch_sessions_for_month(session["user_id"], year, month)
    by_day = group_by_iso_date(rows)

    # upcoming (this month)
    upcoming = [r for r in rows if r["session_datetime"] >= datetime(year, month, 1)]
    prev_year, prev_month, next_year, next_month = next_prev_year_month(year, month)

    return render_template(
        "student_portal.html",
        year=year,
        month=month,
        cal=calendar,
        by_day=by_day,
        upcoming=upcoming,
        prev_year=prev_year,
        prev_month=prev_month,
        next_year=next_year,
        next_month=next_month,
    )

@app.route("/student/register/<int:session_id>", methods=["POST"])
@login_required
@student_required
def student_register(session_id):
    user_id = session["user_id"]

    conn = get_conn()
    cur  = conn.cursor(dictionary=True)

    # Capacity check
    cur.execute("""
        SELECT s.capacity, COALESCE(b.booked,0) AS booked
        FROM exam_sessions s
        LEFT JOIN (
            SELECT session_id, COUNT(*) AS booked
            FROM registrations
            WHERE cancelled = 0
            GROUP BY session_id
        ) b ON b.session_id = s.id
        WHERE s.id = %s
    """, (session_id,))
    row = cur.fetchone()
    if not row:
        cur.close(); conn.close()
        flash("Session not found.", "error")
        return redirect(url_for("student_portal"))

    if row["booked"] >= row["capacity"]:
        cur.close(); conn.close()
        flash("That session is full.", "error")
        return redirect(url_for("student_portal"))

    # Register: allow re-register if previously canceled (flip cancelled back to 0)
    try:
        cur.execute("""
            INSERT INTO registrations (session_id, user_id, cancelled)
            VALUES (%s, %s, 0)
            ON DUPLICATE KEY UPDATE
              cancelled = VALUES(cancelled),
              cancelled_at = NULL
        """, (session_id, user_id))
        conn.commit()
        flash("Registered!", "success")
    except mysql.connector.errors.IntegrityError:
        flash("You are already registered for this session.", "info")

    cur.close(); conn.close()
    return redirect(url_for("student_portal"))

@app.route("/student/cancel/<int:registration_id>", methods=["POST"])
@student_required
def student_cancel(registration_id: int):
    """Cancel this user's registration (by registration_id)."""
    user_id = session["user_id"]

    conn = get_conn()
    cur = conn.cursor()

    # Only cancel if it belongs to this user and isn't already canceled
    cur.execute("""
        UPDATE registrations
        SET cancelled = 1,
            cancelled_at = NOW()
        WHERE id = %s
          AND user_id = %s
          AND cancelled = 0
    """, (registration_id, user_id))

    changed = cur.rowcount
    conn.commit()
    cur.close(); conn.close()

    if changed:
        flash("Appointment canceled.", "success")
    else:
        # Either it didn't exist, wasn't yours, or was already canceled
        flash("Nothing to cancel (not found or already canceled).", "warning")

    return redirect(url_for("student_portal"))

# -----------------------
# Faculty Portal (calendar + create session)
# -----------------------
@app.route("/faculty", defaults={"year": None, "month": None})
@app.route("/faculty/<int:year>/<int:month>")
@login_required
@faculty_required
def faculty_portal(year, month):
    if year is None or month is None:
        now = datetime.now()
        year, month = now.year, now.month

    # Load all sessions (faculty view does not need user-specific registration info)
    first = datetime(year, month, 1)
    last  = datetime(year + (month==12), (month % 12) + 1, 1) - timedelta(seconds=1)

    conn = get_conn()
    cur  = conn.cursor(dictionary=True)
    cur.execute("""
        SELECT
            s.id, s.session_datetime, s.duration_minutes, s.capacity,
            e.exam_code,
            l.campus_name, l.building_name, l.room_number,
            COALESCE(b.booked,0) AS booked
        FROM exam_sessions s
        JOIN exams e     ON e.id = s.exam_id
        JOIN locations l ON l.id = s.location_id
        LEFT JOIN (
            SELECT session_id, COUNT(*) AS booked
            FROM registrations
            WHERE cancelled = 0
            GROUP BY session_id
        ) b ON b.session_id = s.id
        WHERE s.session_datetime BETWEEN %s AND %s
        ORDER BY s.session_datetime ASC
    """, (first, last))
    rows = cur.fetchall()
    cur.close(); conn.close()

    by_day = group_by_iso_date(rows)
    prev_year, prev_month, next_year, next_month = next_prev_year_month(year, month)

    return render_template(
        "faculty_portal.html",
        year=year, month=month, cal=calendar,
        by_day=by_day,
        upcoming=rows,
        prev_year=prev_year, prev_month=prev_month,
        next_year=next_year, next_month=next_month
    )

@app.route("/faculty/session/new", methods=["GET","POST"])
@login_required
@faculty_required
def faculty_new_session():
    if request.method == "GET":
        # load dropdown data
        conn = get_conn()
        cur  = conn.cursor(dictionary=True)
        cur.execute("SELECT id, exam_code FROM exams ORDER BY exam_code")
        exams = cur.fetchall()
        cur.execute("""
            SELECT id, campus_name, building_name, room_number
            FROM locations ORDER BY campus_name, building_name, room_number
        """)
        locations = cur.fetchall()
        cur.close(); conn.close()
        return render_template("faculty_new_session.html", exams=exams, locations=locations)

    # POST create
    exam_id     = request.form.get("exam_id", type=int)
    location_id = request.form.get("location_id", type=int)
    when        = request.form.get("session_datetime", "").strip()
    capacity    = request.form.get("capacity", type=int)
    duration    = request.form.get("duration_minutes", type=int)  # optional

    if not exam_id or not location_id or not when or not capacity:
        flash("All fields are required.", "error")
        return redirect(url_for("faculty_new_session"))

    try:
        dt = datetime.fromisoformat(when)
    except ValueError:
        flash("Invalid date/time format. Use YYYY-MM-DDTHH:MM", "error")
        return redirect(url_for("faculty_new_session"))

    conn = get_conn()
    cur  = conn.cursor()
    cur.execute("""
        INSERT INTO exam_sessions (exam_id, session_datetime, location_id, creator_id, proctor_id, capacity, duration_minutes)
        VALUES (%s,%s,%s,%s,%s,%s,%s)
    """, (exam_id, dt, location_id, session["user_id"], session["user_id"], capacity, duration or None))
    conn.commit()
    cur.close(); conn.close()
    flash("Session created.", "success")
    return redirect(url_for("faculty_portal"))

@app.route("/student/history")
@student_required
def student_history():
    user_id = session["user_id"]

    conn = get_conn()
    cur = conn.cursor(dictionary=True)
    cur.execute("""
        SELECT
            r.id AS registration_id,
            r.registered_at,
            r.cancelled,
            r.cancelled_at,
            es.session_datetime,
            es.duration_minutes,
            e.exam_code,
            l.campus_name,
            l.building_name,
            l.room_number
        FROM registrations r
        JOIN exam_sessions es ON es.id = r.session_id
        JOIN exams e        ON e.id  = es.exam_id
        JOIN locations l    ON l.id  = es.location_id
        WHERE r.user_id = %s
        ORDER BY es.session_datetime DESC
    """, (user_id,))
    rows = cur.fetchall()
    cur.close(); conn.close()

    return render_template(
        "student_history.html",
        rows=rows
    )

# -----------------------
# Minimal pages
# -----------------------
@app.errorhandler(403)
def not_allowed(e):
    return "Forbidden", 403

if __name__ == "__main__":
    app.run(debug=True)
