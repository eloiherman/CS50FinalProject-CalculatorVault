from flask import redirect, render_template, session
from functools import wraps
import re

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)

    return decorated_function

def apologize(message):
    return render_template("apology.html", message=message)

def safe_eval(expr):
    if not re.fullmatch(r"[0-9+\-*/ ]+", expr):
        return False, None

    try:
        value = eval(expr, {"__builtins__": None}, {})
        return True, value
    except Exception:
        return False, None

def password_strength(p):
    score = 0
    length = len(p)

    if length >= 8:  score += 1
    if length >= 12: score += 1

    has_lower = re.search(r"[a-z]", p) is not None
    has_upper = re.search(r"[A-Z]", p) is not None
    has_digit = re.search(r"\d", p) is not None
    has_symb  = re.search(r"[^A-Za-z0-9]", p) is not None
    variety = sum([has_lower, has_upper, has_digit, has_symb])
    if variety >= 2: score += 1
    if variety >= 3: score += 1  # extra

    return min(score, 4)

def strength_label(score: int) -> str:
    return ["Very weak","Weak","Fair","Strong","Very strong"][max(0,min(score,4))]

