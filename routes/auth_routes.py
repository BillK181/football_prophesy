from flask import Blueprint, request, redirect, url_for, flash, render_template, session
from flask_login import login_user, logout_user, login_required
from sqlalchemy import func
from football_prophesy.models import db
from football_prophesy.models.user import User

# Optional imports
from football_prophesy.services.email_service import send_welcome_email

# Blueprint
auth_bp = Blueprint("auth", __name__)


# =========================
# REGISTER
# =========================
@auth_bp.route("/register", methods=["GET", "POST"])
def register():
# - Handles user registration: validates input, creates a new user with a hashed password, saves to the database, and redirects using the PRG pattern
    
    # Check if the form is submitted
    if request.method == "POST":
        
        # Get the values from the form and assign them
        username = request.form["username"].strip()
        name = request.form["name"].strip()
        email = request.form["email"].strip()
        favorite_team = request.form.get("favorite_team") # .get returns None if field is missing
        password = request.form["password"]

        # Username check (case insensitive)
        if User.query.filter(func.lower(User.username) == username.lower()).first():
            flash("Username already taken", "danger")
            return redirect(url_for("auth.register"))

        # Email check
        if User.query.filter(func.lower(User.email) == email.lower()).first():
            flash("Email already registered", "danger")
            return redirect(url_for("auth.register"))

        # Create new User object
        new_user = User(
            username=username,
            name=name,
            email=email,
            favorite_team=favorite_team
        )

        # Calls model method to hash password
        new_user.set_password(password)

        # Admin check
        if username.lower() == "thrillbill":
            new_user.is_admin = True

        # Save new User object to the db
        db.session.add(new_user)
        db.session.commit()

        # Welcome email
        try:
            send_welcome_email(new_user)
        except Exception:
            pass

        flash("Account created! You can now log in.", "success")

        return redirect(url_for("auth.login"))

    # Runs when user first visits page
    return render_template("register.html")


# =========================
# LOGIN
# =========================
@auth_bp.route("/login", methods=["GET", "POST"])
def login():
# - Handles user authentication: verifies credentials, stores user data in the session, and redirects on success or re-renders with an error on failure

    next_page = request.args.get("next")  # read from GET (or from form)
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)

            # Security check for open redirect
            if not next_page or not next_page.startswith("/"):
                next_page = url_for("main.index")

            return redirect(next_page)

        flash("Invalid username or password", "danger")

    return render_template("login.html", next=next_page)


# =========================
# LOGOUT
# =========================
@auth_bp.route("/logout")
def logout():
    logout_user()  # tells Flask-Login to remove authentication
    flash("Logged out successfully!", "success")
    return redirect(url_for("auth.login"))