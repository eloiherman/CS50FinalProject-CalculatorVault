import os

from dotenv import load_dotenv
from cryptography.fernet import Fernet
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, jsonify
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from flask_wtf import CSRFProtect

from helpers import apologize, login_required, safe_eval, password_strength

app = Flask(__name__)

app.config['SECRET_KEY'] = 'dev-change-me'
csrf = CSRFProtect(app)

app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

db = SQL("sqlite:///app.db")

load_dotenv()

VAULT_KEY = os.getenv("VAULT_KEY")
fernet = Fernet(VAULT_KEY)




@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@app.route("/index")
def index():
    if session.get("user_id") is None:
        return render_template("index.html")

    return redirect("/calc")


@app.route("/login", methods=["GET", "POST"])
def login():

    session.clear()

    if request.method == "POST":
        if not request.form.get("login_username"):
            return apologize("must provide username")

        elif not request.form.get("login_password"):
            return apologize("must provide password")

        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("login_username")
        )

        if len(rows) != 1 or not check_password_hash(
            rows[0]["password_hash"], request.form.get("login_password")
        ):
            return apologize("invalid username and/or password")

        session["user_id"] = rows[0]["id"]

        return redirect("/calc")

    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":
        if not request.form.get("username"):
            return apologize("must provide username")

        elif db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username")):
            return apologize("username already taken")

        elif not request.form.get("password"):
            return apologize("must provide password")

        elif not request.form.get("confirmation"):
            return apologize("must provide confirmation")

        elif not request.form.get("calc_target") or request.form.get("calc_target").strip() == "" or request.form.get("calc_target") == "0":
            return apologize("must provide calculation target")

        elif request.form.get("password") != request.form.get("confirmation"):
            return apologize("passwords must match")

        target = request.form.get("calc_target")
        if not target or not target.isdigit():
            return apologize("Target must be a digit")

        hash = generate_password_hash(request.form.get("password"))

        new_id = db.execute(
            "INSERT INTO users (username, password_hash, calc_target) VALUES (?, ?, ?)",
            request.form.get("username"),
            hash,
            request.form.get("calc_target")
        )
        session["user_id"] = new_id

        return redirect("/calc")
    else:
        return render_template("register.html")


@app.route("/calc")
@login_required
def calc():
    user = db.execute("SELECT calc_target FROM users WHERE id = ?", session["user_id"])[0]
    return render_template("calc.html", target=user["calc_target"])


@app.route("/unlock", methods=["POST"])
@login_required
def unlock():
    expr = request.form.get("expr", "")
    ok, value = safe_eval(expr)
    if not ok:
        flash("Invalid expression")
        return redirect("/calc")
    target = db.execute("SELECT calc_target FROM users WHERE id = ?",
                        session["user_id"])[0]["calc_target"]
    if value == target:
        session["vault_unlocked"] = True
        return redirect("/vault")
    flash("Wrong answer, try again")
    return redirect("/calc")


@app.route("/vault")
@login_required
def vault():
    data = db.execute("SELECT * FROM vault WHERE user_id = ?", session["user_id"])
    return render_template("vault.html", data=data)


@app.route("/add", methods=["GET", "POST"])
@login_required
def add():
    if request.method == "GET":
        return render_template("add.html")

    else:
        if not request.form.get("site_name") or not request.form.get("username") or not request.form.get("password"):
            return apologize("Missing something")

        site = request.form.get("site_name")
        username = request.form.get("username")
        password = request.form.get("password")

        score = password_strength(password)

        crypted = encrypt_password(password)

        db.execute("INSERT INTO vault (user_id, site_name, username, password_encrypted, pw_strenght) VALUES (?, ?, ?, ?, ?)",
                   session["user_id"], site, username, crypted, score)
        return redirect("/vault")


@app.route("/delete", methods=["GET", "POST"])
@login_required
def delete():
    if request.method == "GET":
        passwords = db.execute("SELECT site_name FROM vault WHERE user_id = ?", session["user_id"])
        return render_template("delete.html", passwords=passwords)

    else:
        if not request.form.get("site_name"):
            return apologize("Please select a site.")

        db.execute("DELETE FROM vault WHERE user_id = ? AND site_name = ?",
                   session["user_id"], request.form.get("site_name"))
        return redirect("/vault")


@app.route("/vault_password/<int:entry_id>", methods=["POST"])
@login_required
def vault_password(entry_id):
    crypted = db.execute(
        "SELECT id, user_id, password_encrypted FROM vault WHERE id = ? AND user_id = ?", entry_id, session["user_id"])
    if not crypted:
        return apologize("Password not found")

    try:
        plain_password = decrypt_password(crypted[0]["password_encrypted"])

    except Exception:
        return apologize("Error!")

    resp = jsonify({"password": plain_password})
    resp.headers["Cache-Control"] = "no-store"
    return resp


def encrypt_password(plain_password):
    encrypted = fernet.encrypt(plain_password.encode())
    return encrypted.decode()


def decrypt_password(encrypted_password):
    decrypted = fernet.decrypt(encrypted_password.encode())
    return decrypted.decode()

@app.route("/delete_account", methods=["POST", "GET"])
@login_required
def delete_account():
    if request.method == "GET":
        return render_template("delete_account.html")

    user_id = session["user_id"]

    db.execute("DELETE FROM vault WHERE user_id = ?", user_id)
    db.execute("DELETE FROM users WHERE id = ?", user_id)

    session.clear()

    flash("Your account has been permanently deleted.", "success")

    return redirect("/")
