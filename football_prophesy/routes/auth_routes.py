from flask import Blueprint, request, redirect, url_for, flash, render_template, session
from sqlalchemy import func
from models import db
from models.user import User

# Optional imports
from services.auth import login_required
from services.email_service import send_welcome_email

# Blueprint
auth_bp = Blueprint("auth", __name__)


# =========================
# REGISTER
# =========================
@auth_bp.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form["username"].strip()
        name = request.form["name"].strip()
        email = request.form["email"].strip()
        favorite_team = request.form.get("favorite_team")
        password = request.form["password"]

        # Username check (case insensitive)
        if User.query.filter(func.lower(User.username) == username.lower()).first():
            flash("Username already taken", "danger")
            return redirect(url_for("auth.register"))

        # Email check
        if User.query.filter(func.lower(User.email) == email.lower()).first():
            flash("Email already registered", "danger")
            return redirect(url_for("auth.register"))

        new_user = User(
            username=username,
            name=name,
            email=email,
            favorite_team=favorite_team
        )

        new_user.set_password(password)

        # Admin check
        if username.lower() == "thrillbill":
            new_user.is_admin = True

        db.session.add(new_user)
        db.session.commit()

        # Optional welcome email
        #try:
            #send_welcome_email(email, username)
        #except Exception:
            #pass

        flash("Account created! You can now log in.", "success")

        return redirect(url_for("auth.login"))

    return render_template("register.html")


# =========================
# LOGIN
# =========================
@auth_bp.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):

            session["user_id"] = user.id
            session["username"] = user.username

            # Score + rank will be set automatically
            # by main_bp.before_app_request
            session["rank"] = None
            session["total_points"] = 0

            return redirect(url_for("main.index"))

        flash("Invalid username or password", "danger")

    return render_template("login.html")


# =========================
# LOGOUT
# =========================
@auth_bp.route("/logout")
def logout():

    session.clear()

    flash("Logged out successfully!", "success")

    return redirect(url_for("auth.login"))