from flask import Flask, render_template, request, redirect, url_for, flash, session, abort
from flask_bcrypt import Bcrypt
import mysql.connector
import os, re, random
from pathlib import Path
from dotenv import load_dotenv
from functools import wraps
from datetime import date, datetime

# ----------------------------------------------------
# Load .env (next to this file)
# ----------------------------------------------------
load_dotenv(dotenv_path=Path(__file__).with_name(".env"))

# ----------------------------------------------------
# Flask / Bcrypt setup
# ----------------------------------------------------
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev-secret")
bcrypt = Bcrypt(app)

# ----------------------------------------------------
# DB connection
# ----------------------------------------------------
def get_conn():
    return mysql.connector.connect(
        host=os.getenv("DB_HOST", "localhost"),
        user=os.getenv("DB_USER", "root"),
        password=os.getenv("DB_PASS", ""),
        database=os.getenv("DB_NAME", "exam_reg_db"),
        auth_plugin="mysql_native_password",
    )

# ----------------------------------------------------
# Regex rules
#   Students: 10 digits @student.csn.edu (password must equal those digits)
#   Faculty:  firstname.lastname@csn.edu (password >= 7 chars)
# ----------------------------------------------------
CSN_STUDENT_RE = re.compile(r"^(\d{10})@student\.csn\.edu$", re.IGNORECASE)
CSN_FACULTY_RE = re.compile(r"^[A-Za-z]+\.[A-Za-z]+@csn\.edu$", re.IGNORECASE)

def classify_email(email: str):
    """
    Returns:
      ('student', digits)  for student pattern
      ('faculty', None)    for faculty pattern
      (None, None)         if neither
    """
    if not email:
        return (None, None)
    m = CSN_STUDENT_RE.match(email)
    if m:
        return ("student", m.group(1))
    if CSN_FACULTY_RE.match(email):
        return ("faculty", None)
    return (None, None)

def generate_unique_faculty_nshe(conn):
    """
    users.nshe is NOT NULL and UNIQUE in your schema.
    For faculty (no real NSHE), generate a unique 10-digit placeholder.
    """
    cur = conn.cursor()
    while True:
        candidate = str(random.randint(10**9, 10**10 - 1))  # 10 digits
        cur.execute("SELECT 1 FROM users WHERE nshe=%s", (candidate,))
        if cur.fetchone() is None:
            cur.close()
            return candidate

# ----------------------------------------------------
# Auth guards
# ----------------------------------------------------
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

# ----------------------------------------------------
# Home
# ----------------------------------------------------
@app.route("/")
def home():
    return render_template("home.html", user_name=session.get("user_name"))

# ----------------------------------------------------
# Sign Up
# ----------------------------------------------------
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

    detected_role, student_digits = classify_email(email)
    if detected_role is None:
        flash("Use CSN email: student=10digits@student.csn.edu OR faculty=firstname.lastname@csn.edu", "error")
        return redirect(url_for("signup"))

    if detected_role != role_sel:
        flash(f"Selected role '{role_sel}' does not match the email pattern.", "error")
        return redirect(url_for("signup"))

    if detected_role == "student":
        # Password must equal the 10 digits from email
        if password != confirm or password != student_digits:
            flash("Student password must equal the 10 digits in your email.", "error")
            return redirect(url_for("signup"))
        nshe_value = student_digits
    else:
        # Faculty password must be >= 7 chars
        if password != confirm:
            flash("Passwords do not match.", "error")
            return redirect(url_for("signup"))
        if len(password) < 7:
            flash("Faculty password must be at least 7 characters.", "error")
            return redirect(url_for("signup"))
        conn = get_conn()
        nshe_value = generate_unique_faculty_nshe(conn)
        conn.close()

    pw_hash = bcrypt.generate_password_hash(password).decode("utf-8")

    try:
        conn = get_conn()
        cur  = conn.cursor()
        cur.execute(
            "INSERT INTO users (email, nshe, full_name, password_hash, role) VALUES (%s,%s,%s,%s,%s)",
            (email, nshe_value, full_name, pw_hash, detected_role),
        )
        conn.commit()
        cur.close(); conn.close()
        flash("Account created! Please log in.", "success")
        return redirect(url_for("login"))
    except mysql.connector.errors.IntegrityError as e:
        try:
            cur.close(); conn.close()
        except:
            pass
        if "Duplicate entry" in str(e):
            flash("That email (or NSHE) is already registered.", "error")
        else:
            flash("Could not create account.", "error")
        return redirect(url_for("signup"))

# ----------------------------------------------------
# Login / Logout
# ----------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    email    = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")

    role, student_digits = classify_email(email)
    if role is None:
        flash("Use CSN email: student=10digits@student.csn.edu OR faculty=firstname.lastname@csn.edu", "error")
        return redirect(url_for("login"))

    # Student rule: password must equal 10 digits in email
    if role == "student" and password != student_digits:
        flash("Student password must equal the 10 digits in your email.", "error")
        return redirect(url_for("login"))

    # Faculty rule: >= 7 chars (we'll still verify against stored hash)
    if role == "faculty" and len(password) < 7:
        flash("Faculty password must be at least 7 characters.", "error")
        return redirect(url_for("login"))

    conn = get_conn()
    cur  = conn.cursor(dictionary=True)
    cur.execute("SELECT id, full_name, password_hash, role FROM users WHERE email=%s", (email,))
    user = cur.fetchone()
    cur.close(); conn.close()

    if user and bcrypt.check_password_hash(user["password_hash"], password):
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

# ----------------------------------------------------
# Student dashboard: calendar + register + cancel
# ----------------------------------------------------
import calendar as _cal

@login_required
@student_required
@app.route("/student", defaults={"year": None, "month": None})
@app.route("/student/<int:year>/<int:month>")
def student_portal(year, month):
    today = date.today()
    year = year or today.year
    month = month or today.month

    # Month window [start, end)
    month_start = datetime(year, month, 1)
    month_end = datetime(year + (month == 12), (month % 12) + 1, 1)

    conn = get_conn()
    cur = conn.cursor(dictionary=True)
    cur.execute(
        """
        SELECT
          es.id,
          e.exam_code,
          es.session_datetime,
          l.campus_name,
          l.building_name,
          l.room_number,
          es.capacity,
          COUNT(r2.id) AS booked,
          r.id AS registration_id
        FROM exam_sessions es
        JOIN exams e     ON e.id = es.exam_id
        JOIN locations l ON l.id = es.location_id
        LEFT JOIN registrations r2 ON r2.session_id = es.id AND r2.cancelled = 0
        LEFT JOIN registrations r  ON r.session_id  = es.id AND r.user_id = %s AND r.cancelled = 0
        WHERE es.session_datetime >= %s AND es.session_datetime < %s
        GROUP BY es.id
        ORDER BY es.session_datetime
        """,
        (session["user_id"], month_start, month_end),
    )
    rows = cur.fetchall()
    cur.close(); conn.close()

    by_day = {}
    upcoming = []
    now = datetime.now()
    for row in rows:
        row["is_full"] = int(row["booked"]) >= int(row["capacity"])
        row["already_registered"] = row["registration_id"] is not None
        iso = row["session_datetime"].date().isoformat()
        by_day.setdefault(iso, []).append(row)
        if row["session_datetime"] >= now:
            upcoming.append(row)

    prev_y, prev_m = (year - 1, 12) if month == 1 else (year, month - 1)
    next_y, next_m = (year + 1, 1)  if month == 12 else (year, month + 1)

    return render_template(
        "student_portal.html",
        cal=_cal,
        year=year,
        month=month,
        prev_year=prev_y,
        prev_month=prev_m,
        next_year=next_y,
        next_month=next_m,
        by_day=by_day,
        upcoming=upcoming,
    )

@login_required
@student_required
@app.route("/student/register/<int:session_id>", methods=["POST"])
def student_register(session_id):
    user_id = session["user_id"]
    conn = get_conn()
    cur  = conn.cursor(dictionary=True)

    # 1) Validate session & capacity (active = cancelled=0)
    cur.execute("SELECT capacity FROM exam_sessions WHERE id=%s", (session_id,))
    s = cur.fetchone()
    if not s:
        cur.close(); conn.close()
        flash("Session not found.", "error")
        return redirect(url_for("student_portal"))

    cur.execute("SELECT COUNT(*) AS c FROM registrations WHERE session_id=%s AND cancelled=0", (session_id,))
    booked = cur.fetchone()["c"]
    if booked >= s["capacity"]:
        cur.close(); conn.close()
        flash("That session is full.", "error")
        return redirect(url_for("student_portal"))

    # 2) Already active?
    cur.execute("""
        SELECT id FROM registrations
        WHERE session_id=%s AND user_id=%s AND cancelled=0
        """, (session_id, user_id))
    if cur.fetchone():
        cur.close(); conn.close()
        flash("You are already registered for this session.", "info")
        return redirect(url_for("student_portal"))

    # 3) Try to REACTIVATE a cancelled registration instead of inserting a new row
    cur.execute("""
        SELECT id FROM registrations
        WHERE session_id=%s AND user_id=%s AND cancelled=1
        ORDER BY id DESC LIMIT 1
        """, (session_id, user_id))
    row = cur.fetchone()
    if row:
        cur.execute("""
            UPDATE registrations
            SET cancelled=0, cancelled_at=NULL, registered_at=NOW()
            WHERE id=%s
            """, (row["id"],))
        conn.commit()
        cur.close(); conn.close()
        flash("Registration reactivated!", "success")
        return redirect(url_for("student_portal"))

    # 4) No existing row at all → INSERT a fresh one
    cur.execute(
        "INSERT INTO registrations (session_id, user_id) VALUES (%s,%s)",
        (session_id, user_id)
    )
    conn.commit()
    cur.close(); conn.close()
    flash("Registered!", "success")
    return redirect(url_for("student_portal"))


@login_required
@student_required
@app.route("/student/cancel/<int:registration_id>", methods=["POST"])
def student_cancel(registration_id):
    user_id = session["user_id"]
    conn = get_conn()
    cur  = conn.cursor()
    cur.execute("DELETE FROM registrations WHERE id=%s AND user_id=%s", (registration_id, user_id))
    affected = cur.rowcount
    conn.commit()
    cur.close(); conn.close()

    flash("Registration cancelled." if affected else "Could not cancel that registration.",
          "success" if affected else "error")
    return redirect(url_for("student_portal"))

# ----------------------------------------------------
# Faculty dashboard: calendar + create session
# ----------------------------------------------------
@login_required
@faculty_required
@app.route("/faculty", defaults={"year": None, "month": None})
@app.route("/faculty/<int:year>/<int:month>")
def faculty_portal(year, month):
    today = date.today()
    year = year or today.year
    month = month or today.month

    month_start = datetime(year, month, 1)
    month_end = datetime(year + (month == 12), (month % 12) + 1, 1)

    conn = get_conn()
    cur = conn.cursor(dictionary=True)
    cur.execute(
        """
        SELECT
          es.id,
          e.exam_code,
          es.session_datetime,
          l.campus_name,
          l.building_name,
          l.room_number,
          es.capacity,
          COUNT(r2.id) AS booked
        FROM exam_sessions es
        JOIN exams e     ON e.id = es.exam_id
        JOIN locations l ON l.id = es.location_id
        LEFT JOIN registrations r2 ON r2.session_id = es.id AND r2.cancelled = 0
        WHERE es.session_datetime >= %s AND es.session_datetime < %s
        GROUP BY es.id
        ORDER BY es.session_datetime
        """,
        (month_start, month_end),
    )
    rows = cur.fetchall()
    cur.close(); conn.close()

    by_day = {}
    upcoming = []
    now = datetime.now()
    for row in rows:
        iso = row["session_datetime"].date().isoformat()
        by_day.setdefault(iso, []).append(row)
        if row["session_datetime"] >= now:
            upcoming.append(row)

    prev_y, prev_m = (year - 1, 12) if month == 1 else (year, month - 1)
    next_y, next_m = (year + 1, 1)  if month == 12 else (year, month + 1)

    return render_template(
        "faculty_portal.html",
        cal=_cal,
        year=year,
        month=month,
        prev_year=prev_y,
        prev_month=prev_m,
        next_year=next_y,
        next_month=next_m,
        by_day=by_day,
        upcoming=upcoming,
    )

@login_required
@faculty_required
@app.route("/faculty/new-session", methods=["GET", "POST"])
def faculty_new_session():
    if request.method == "GET":
        # Load choices
        conn = get_conn()
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT id, exam_code FROM exams ORDER BY exam_code")
        exams = cur.fetchall()
        cur.execute(
            "SELECT id, campus_name, building_name, room_number FROM locations ORDER BY campus_name, building_name, room_number"
        )
        locations = cur.fetchall()
        cur.close(); conn.close()
        return render_template("faculty_new_session.html", exams=exams, locations=locations)

    # POST create
    exam_id   = request.form.get("exam_id", type=int)
    loc_id    = request.form.get("location_id", type=int)
    dt_str    = request.form.get("session_datetime", "").strip()
    capacity  = request.form.get("capacity", type=int) or 20
    creator_id = proctor_id = session["user_id"]

    try:
        session_dt = datetime.fromisoformat(dt_str)  # expects "YYYY-MM-DDTHH:MM"
    except ValueError:
        flash("Invalid date/time format.", "error")
        return redirect(url_for("faculty_new_session"))

    conn = get_conn()
    cur  = conn.cursor()
    cur.execute(
        """
        INSERT INTO exam_sessions (exam_id, session_datetime, location_id, creator_id, proctor_id, capacity)
        VALUES (%s,%s,%s,%s,%s,%s)
        """,
        (exam_id, session_dt, loc_id, creator_id, proctor_id, capacity),
    )
    conn.commit()
    cur.close(); conn.close()
    flash("Exam session created.", "success")
    return redirect(url_for("faculty_portal"))

# ----------------------------------------------------
# Run
# ----------------------------------------------------
if __name__ == "__main__":
    app.run(debug=True)
