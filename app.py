from flask import Flask, render_template, request, redirect, url_for, flash, session, abort
from flask_bcrypt import Bcrypt
import mysql.connector
import os, re, hashlib
from pathlib import Path
from dotenv import load_dotenv
from functools import wraps

# Load .env next to this file
load_dotenv(dotenv_path=Path(__file__).with_name(".env"))

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev-secret")
bcrypt = Bcrypt(app)

def get_conn():
    return mysql.connector.connect(
        host=os.getenv("DB_HOST", "localhost"),
        user=os.getenv("DB_USER", "root"),
        password=os.getenv("DB_PASS", ""),
        database=os.getenv("DB_NAME", "exam_reg_db"),
        auth_plugin="mysql_native_password"
    )

# -----------------------
# Email rules:
#   Students: 10 digits @student.csn.edu  (password must equal those 10 digits)
#   Faculty:  firstname.lastname@csn.edu  (password >= 7 chars)
# -----------------------
CSN_STUDENT_RE = re.compile(r'^(\d{10})@student\.csn\.edu$', re.IGNORECASE)
CSN_FACULTY_RE = re.compile(r'^[A-Za-z]+\.[A-Za-z]+@csn\.edu$', re.IGNORECASE)

def classify_email(email: str):
    """
    Returns ('student', nshe_digits) if student, ('faculty', None) if faculty, else (None, None).
    """
    if not email:
        return (None, None)
    m = CSN_STUDENT_RE.match(email)
    if m:
        return ('student', m.group(1))
    if CSN_FACULTY_RE.match(email):
        return ('faculty', None)
    return (None, None)

def make_faculty_nshe(email: str) -> str:
    """
    Create a deterministic 10-digit surrogate from the faculty email so
    Users.nshe can remain NOT NULL and UNIQUE.
    """
    h = hashlib.sha256((email or "").lower().encode()).hexdigest()  # hex string
    digits = ''.join(ch for ch in h if ch.isdigit())
    if len(digits) < 10:
        # If not enough digits in the hex, fall back to numeric hash of the hex itself
        num = int(h, 16)
        digits = (digits + str(num))[:10]
    return digits[:10]

def faculty_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if session.get("role") != "faculty":
            abort(403)
        return fn(*args, **kwargs)
    return wrapper

# -----------------------
# Routes
# -----------------------
@app.route("/")
def home():
    return render_template("home.html", user_name=session.get("user_name"))

# --- SIGN UP ---
@app.route("/signup", methods=["GET","POST"])
def signup():
    if request.method == "POST":
        full_name = request.form.get("full_name","").strip()
        email     = request.form.get("email","").strip().lower()
        password  = request.form.get("password","")
        confirm   = request.form.get("confirm","")
        role_sel  = request.form.get("role","student").strip().lower()

        if not full_name or not email or not password or not confirm:
            flash("All fields are required.", "error")
            return redirect(url_for("signup"))

        detected_role, student_nshe = classify_email(email)
        if detected_role is None:
            flash("Use CSN email: student=10digits@student.csn.edu, faculty=firstname.lastname@csn.edu.", "error")
            return redirect(url_for("signup"))

        if detected_role != role_sel:
            flash(f"Selected role ({role_sel}) does not match the email pattern.", "error")
            return redirect(url_for("signup"))

        # Password rules
        if detected_role == "student":
            # must equal the 10 digits
            if password != confirm or password != student_nshe:
                flash("Student password must equal the 10 digits in your CSN email.", "error")
                return redirect(url_for("signup"))
            nshe_to_store = student_nshe
        else:
            # faculty: at least 7 chars
            if password != confirm or len(password) < 7:
                flash("Faculty password must be at least 7 characters.", "error")
                return redirect(url_for("signup"))
            nshe_to_store = make_faculty_nshe(email)

        pw_hash = bcrypt.generate_password_hash(password).decode("utf-8")

        try:
            conn = get_conn()
            cur  = conn.cursor()
            cur.execute(
                "INSERT INTO Users (email, nshe, full_name, password_hash, role) VALUES (%s,%s,%s,%s,%s)",
                (email, nshe_to_store, full_name, pw_hash, detected_role)
            )
            conn.commit()
            cur.close(); conn.close()
            flash("Account created! Please log in.", "success")
            return redirect(url_for("login"))
        except mysql.connector.errors.IntegrityError:
            try: cur.close(); conn.close()
            except: pass
            flash("That email (or NSHE surrogate) is already registered.", "error")
            return redirect(url_for("signup"))

    return render_template("signup.html")

# --- LOGIN ---
@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    email    = request.form.get("email","").strip().lower()
    password = request.form.get("password","")

    role, student_nshe = classify_email(email)
    if role is None:
        flash("Use CSN email: student=10digits@student.csn.edu, faculty=firstname.lastname@csn.edu.", "error")
        return redirect(url_for("login"))

    # Enforce password rule before hitting DB
    if role == "student":
        if password != student_nshe:
            flash("Student password must equal the 10 digits in your email.", "error")
            return redirect(url_for("login"))
    else:
        if len(password) < 7:
            flash("Faculty password must be at least 7 characters.", "error")
            return redirect(url_for("login"))

    conn = get_conn()
    cur  = conn.cursor(dictionary=True)
    cur.execute(
        "SELECT id, full_name, password_hash, role FROM Users WHERE email=%s",
        (email,)
    )
    user = cur.fetchone()
    cur.close(); conn.close()

    if user and bcrypt.check_password_hash(user["password_hash"], password):
        session["user_id"]   = user["id"]
        session["user_name"] = user["full_name"]
        session["role"]      = user.get("role","student")
        flash("Logged in!", "success")
        return redirect(url_for("home"))

    flash("Invalid email or password.", "error")
    return redirect(url_for("login"))

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for("home"))

# Example faculty-only page (optional)
@app.route("/admin/sessions")
@faculty_required
def manage_sessions():
    return "Faculty-only: session management placeholder"

if __name__ == "__main__":
    app.run(debug=True)
