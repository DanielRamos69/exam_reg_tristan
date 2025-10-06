from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_bcrypt import Bcrypt
import mysql.connector
import os
from dotenv import load_dotenv

from pathlib import Path
from dotenv import load_dotenv
load_dotenv(dotenv_path=Path(__file__).with_name(".env"))  # guarantees we load the .env next to app.py
import os
print("EMAIL_MODE =", os.getenv("EMAIL_MODE"))
import os
print("DB_USER =", os.getenv("DB_USER"))

import secrets, hashlib, smtplib
from email.message import EmailMessage
from datetime import datetime, timedelta

import re

CSN_EMAIL_RE = re.compile(r'^(\d{10})@student\.csn\.edu$', re.IGNORECASE)

def extract_nshe_from_email(email: str):
    m = CSN_EMAIL_RE.match(email or "")
    return m.group(1) if m else None

def send_email(to, subject, body):
    mode = os.getenv("EMAIL_MODE", "console").lower()
    if mode == "smtp":
        host = os.getenv("SMTP_HOST")
        port = int(os.getenv("SMTP_PORT", "587"))
        user = os.getenv("SMTP_USER")
        pwd  = os.getenv("SMTP_PASS")
        sender = os.getenv("FROM_EMAIL", user)
        if not all([host, port, user, pwd, sender]):
            print("[email] Missing SMTP env; using console")
            mode = "console"

    if mode == "smtp":
        msg = EmailMessage()
        msg["From"] = sender
        msg["To"] = to
        msg["Subject"] = subject
        msg.set_content(body)
        with smtplib.SMTP(host, port) as s:
            s.starttls()
            s.login(user, pwd)
            s.send_message(msg)
    else:
        # Console mode – prints the “email” in your terminal
        print("=== EMAIL (console) ===")
        print("To:", to)
        print("Subject:", subject)
        print(body)
        print("=======================")

def create_reset_token(user_id):
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    expires = datetime.utcnow() + timedelta(hours=1)

    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO password_resets (user_id, token_hash, expires_at, created_at) "
        "VALUES (%s,%s,%s,NOW())",
        (user_id, token_hash, expires)
    )
    conn.commit()
    cur.close()
    conn.close()
    return token

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev-secret")
bcrypt = Bcrypt(app)

# ---- MySQL connection (mysql-connector) ----
def get_conn():
    return mysql.connector.connect(
        host=os.getenv("DB_HOST", "localhost"),
        user=os.getenv("DB_USER"),          # make sure this matches your .env
        password=os.getenv("DB_PASS"),
        database=os.getenv("DB_NAME", "exam_reg_db"),
        auth_plugin="mysql_native_password"             # works with MySQL 8 default
    )

@app.route("/")
def home():
    return render_template("home.html", user_name=session.get("user_name"))

@app.route("/signup", methods=["GET","POST"])
def signup():
    if request.method == "POST":
        full_name = request.form.get("full_name","").strip()
        email = request.form.get("email","").strip().lower()
        password = request.form.get("password","")
        confirm = request.form.get("confirm","")

        if not full_name or not email or not password or not confirm:
            flash("All fields are required.", "error")
            return redirect(url_for("signup"))

        nshe = extract_nshe_from_email(email)
        if not nshe:
            flash("Use your CSN email like 8001234567@student.csn.edu.", "error")
            return redirect(url_for("signup"))

        if password != confirm or not re.fullmatch(r'\d{10}', password):
            flash("Password must be your 10-digit NSHE and match confirm.", "error")
            return redirect(url_for("signup"))

        if password != nshe:
            flash("Password must equal the NSHE number in your email.", "error")
            return redirect(url_for("signup"))

        pw_hash = bcrypt.generate_password_hash(password).decode("utf-8")

        try:
            conn = get_conn()
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO users (email, nshe, full_name, password_hash, role) VALUES (%s,%s,%s,%s,%s)",
                (email, nshe, full_name, pw_hash, "student")
            )
            conn.commit()
            cur.close(); conn.close()
            flash("Account created! Please log in.", "success")
            return redirect(url_for("login"))
        except mysql.connector.errors.IntegrityError:
            try: cur.close(); conn.close()
            except: pass
            flash("That CSN email is already registered.", "error")
            return redirect(url_for("signup"))

    return render_template("signup.html")

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    # POST: enforce CSN rules then check credentials
    email = request.form.get("email","").strip().lower()
    password = request.form.get("password","")

    if not email or not password:
        flash("Email and password are required.", "error")
        return redirect(url_for("login"))

    nshe = extract_nshe_from_email(email)
    if not nshe or not re.fullmatch(r'\d{10}', password):
        flash("Use your CSN email and your 10-digit NSHE as the password.", "error")
        return redirect(url_for("login"))

    conn = get_conn()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT id, full_name, password_hash, role FROM users WHERE email=%s", (email,))
    user = cur.fetchone()
    cur.close(); conn.close()

    if user and bcrypt.check_password_hash(user["password_hash"], password):
        session["user_id"] = user["id"]
        session["user_name"] = user["full_name"]
        session["role"] = user.get("role","student")
        flash("Logged in!", "success")
        return redirect(url_for("home"))

    flash("Invalid email or password.", "error")
    return redirect(url_for("login"))

    return render_template("login.html")

@app.route("/forgot", methods=["GET","POST"])
def forgot():
    if request.method == "POST":
        email = request.form.get("email","").strip().lower()
        if not email:
            flash("Email is required.", "error")
            return redirect(url_for("forgot"))

        conn = get_conn()
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT id FROM users WHERE email=%s", (email,))
        user = cur.fetchone()
        cur.close()
        conn.close()

        if user:
            token = create_reset_token(user["id"])
            reset_link = url_for("reset_password", token=token, _external=True)
            send_email(
                email,
                "Reset your password",
                f"Click to reset your password:\n{reset_link}\n\nThis link expires in 1 hour."
            )
            # Helpful during development: also show the link on the page
            if os.getenv("EMAIL_MODE", "console").lower() == "console":
                flash(f"DEV reset link: {reset_link}", "info")

        flash("If that email exists, we've sent reset instructions.", "info")
        return redirect(url_for("login"))

    return render_template("forgot.html")


@app.route("/reset/<token>", methods=["GET","POST"])
def reset_password(token):
    token_hash = hashlib.sha256(token.encode()).hexdigest()

    conn = get_conn()
    cur = conn.cursor(dictionary=True)
    cur.execute("""
        SELECT pr.id, pr.user_id, pr.expires_at, pr.used, u.full_name
        FROM password_resets pr
        JOIN users u ON u.id = pr.user_id
        WHERE pr.token_hash = %s
    """, (token_hash,))
    row = cur.fetchone()

    # invalid or expired
    if (not row) or row["used"] or (datetime.utcnow() > row["expires_at"]):
        cur.close()
        conn.close()
        flash("This reset link is invalid or expired.", "error")
        return redirect(url_for("forgot"))

    if request.method == "POST":
        new = request.form.get("password","")
        confirm = request.form.get("confirm","")
        if not new or new != confirm:
            flash("Passwords must match.", "error")
            return redirect(url_for("reset_password", token=token))

        pw_hash = bcrypt.generate_password_hash(new).decode("utf-8")

        cur2 = conn.cursor()
        try:
            cur2.execute("UPDATE users SET password_hash=%s WHERE id=%s", (pw_hash, row["user_id"]))
            cur2.execute("UPDATE password_resets SET used=1, used_at=NOW() WHERE id=%s", (row["id"],))
            conn.commit()
        finally:
            cur2.close()
            cur.close()
            conn.close()

        flash("Your password has been updated. Please log in.", "success")
        return redirect(url_for("login"))

    cur.close()
    conn.close()
    return render_template("reset.html", name=row["full_name"])

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for("home"))

if __name__ == "__main__":
    app.run(debug=True)

