from functools import wraps
from flask import session, redirect, url_for, flash

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("You must be logged in.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper