from flask import Flask, render_template, redirect, url_for, request, session, flash
from flask_sqlalchemy import SQLAlchemy
from collections import defaultdict
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from smtplib import SMTPAuthenticationError
from sqlalchemy import func

# =========================
# APP SETUP
# =========================
app = Flask(__name__)
app.secret_key = os.environ.get['FLASK_SECRET_KEY']
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///football_prophesy.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# =========================
# IMPORT PLAYERS
# =========================
from scouting_combine_participants import players
from combine_results import actual_combine_results

# =========================
# MODELS
# =========================
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    favorite_team = db.Column(db.String(50), nullable=True)
    password_hash = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    predictions = db.relationship("Prediction", backref="user", lazy=True)
    comments = db.relationship("Comment", backref="user", lazy=True)

    # -----------------
    # Auth
    # -----------------
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    # -----------------
    # Scoring
    # -----------------
    def combine_points(self, year=2026):
        points = sum(pred.calculate_points() for pred in self.predictions
                     if pred.section == "scouting_combine" and pred.year == year)
        return points

    def total_points(self, year=2026):
        return self.combine_points(year)

    # -----------------
    # Ranking
    # -----------------
    def rank(self, year=2026):
        return next((i+1 for i, u in enumerate(self.leaderboard(year)) if u["user"].id == self.id), "-")

    # -----------------
    # Leaderboards
    # -----------------
    @classmethod
    def leaderboard(cls, year=2026):
        users = cls.query.all()
        ranked = sorted([{"user": u, "score": u.total_points(year)} for u in users],
                        key=lambda x: x["score"], reverse=True)
        return ranked

    @classmethod
    def combine_leaderboard(cls, year=2026):
        users = cls.query.all()
        ranked = sorted([{"user": u, "score": u.combine_points(year)} for u in users],
                        key=lambda x: x["score"], reverse=True)
        return ranked


class Prediction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    year = db.Column(db.Integer, default=2026)
    section = db.Column(db.String(50), default="scouting_combine")
    position_group = db.Column(db.String(50), nullable=False)
    drill = db.Column(db.String(50), nullable=False)
    place = db.Column(db.Integer, nullable=False)
    player_name = db.Column(db.String(100), nullable=False)

    def calculate_points(self):
        top3 = actual_combine_results.get(self.position_group, {}).get(self.drill, [])
        points = 0
        if self.player_name in top3:
            points += 3
            if self.place == top3.index(self.player_name) + 1:
                points += 5
        return points


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    page = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())
    is_admin = db.Column(db.Boolean, default=False)


# =========================
# LOGIN REQUIRED DECORATOR
# =========================
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("You must be logged in.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper

# =========================
# CREATE DATABASE
# =========================
with app.app_context():
    db.create_all()

# =========================
# EMAIL FUNCTION
# =========================
def send_welcome_email(user):
    sender = "ThrillBill@footballprophesy.com"  # Mailgun domain email
    receiver = user.email

    msg = MIMEMultipart("alternative")
    msg["Subject"] = "Welcome to Football Prophesy 🏈"
    msg["From"] = sender
    msg["To"] = receiver

    text = f"Hi {user.name},\nThanks for signing up to Football Prophesy!"
    html = f"<html><body><h2>Hi {user.name},</h2><p>Thanks for signing up to <b>Football Prophesy</b>!</p></body></html>"

    msg.attach(MIMEText(text, "plain"))
    msg.attach(MIMEText(html, "html"))

    SMTP_SERVER = "smtp.mailgun.org"
    SMTP_PORT = 587
    SMTP_USERNAME = os.environ.get("MAILGUN_SMTP_USER")
    SMTP_PASSWORD = os.environ.get("MAILGUN_SMTP_PASS")

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.sendmail(sender, receiver, msg.as_string())

# =========================
# BEFORE REQUEST
# =========================
@app.before_request
def load_user_info():
    user_id = session.get("user_id")
    if user_id:
        user = User.query.get(user_id)
        if user:
            session["username"] = user.username
            leaderboard = sorted(
                [(u.id, u.total_points()) for u in User.query.all()],
                key=lambda x: x[1],
                reverse=True
            )
            session["rank"] = next((i+1 for i, (uid, _) in enumerate(leaderboard) if uid == user_id), "-")
            session["total_points"] = user.total_points()

# =========================
# INDEX / HOME
# =========================
@app.route("/")
def index():
    return render_template(
        "index.html",
        top_players=User.leaderboard()[:10],
        combine_top_players=User.combine_leaderboard()[:10]
    )

# =========================
# REGISTER / LOGIN / LOGOUT
# =========================
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        name = request.form["name"]
        email = request.form["email"].strip()
        favorite_team = request.form.get("favorite_team")
        password = request.form["password"]

        if User.query.filter(func.lower(User.username) == username.lower()).first():
            flash("Username already taken", "danger")
            return redirect(url_for("register"))
        if User.query.filter(func.lower(User.email) == email.lower()).first():
            flash("Email already registered", "danger")
            return redirect(url_for("register"))

        new_user = User(username=username, name=name, email=email, favorite_team=favorite_team)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        try:
            send_welcome_email(new_user)
        except SMTPAuthenticationError:
            pass

        flash("Account created! You can now log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session["user_id"] = user.id
            session["is_admin"] = user.is_admin
            flash("Logged in successfully!", "success")
            return redirect(url_for("index"))
        else:
            flash("Invalid username or password", "danger")
            return redirect(url_for("login"))
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully!", "success")
    return redirect(url_for("login"))

# =========================
# SCOUTING COMBINE
# =========================
@app.route("/scouting-combine")
def scouting_combine():
    user_id = session.get("user_id")
    previous_preds = Prediction.query.filter_by(user_id=user_id, year=2026, section="scouting_combine").all()
    previous_predictions = {
        f"{pred.position_group}_{pred.drill}_{pred.place}": pred.player_name
        for pred in previous_preds
    }
    comments = Comment.query.filter_by(page="scouting_combine").order_by(Comment.timestamp.desc()).all()
    combine_top_players = User.combine_leaderboard()
    return render_template(
        "scouting_combine.html",
        combine_top_players=combine_top_players[:10],
        players=players,
        previous_predictions=previous_predictions,
        comments=comments
    )
from collections import defaultdict
from flask import flash, redirect, session, url_for
from datetime import datetime

@app.route("/submit-combine", methods=["POST"])
@login_required
def submit_combine():
    user_id = session.get("user_id")
    combine_deadline = datetime(2026, 2, 26, 14, 0)

    # Deadline check
    if datetime.utcnow() > combine_deadline:
        flash("Scouting Combine predictions are now closed.", "danger")
        return redirect(url_for("scouting_combine"))

    # Fetch existing predictions for this user/section/year
    existing_predictions = Prediction.query.filter_by(
        user_id=user_id, year=2026, section="scouting_combine"
    ).all()
    existing_dict = {f"{p.position_group}_{p.drill}_{p.place}": p for p in existing_predictions}

    # ==========================
    # Organize picks by drill
    # ==========================
    drill_groups = defaultdict(list)
    key_to_player = {}
    for key, player_name in request.form.items():
        if not player_name:
            continue
        parts = key.split("_")
        position_group = parts[0]
        drill = "_".join(parts[1:-1])
        place = int(parts[-1])
        drill_key = f"{position_group}_{drill}"
        drill_groups[drill_key].append(player_name)
        key_to_player[key] = player_name

    # ==========================
    # Detect duplicates and save valid picks
    # ==========================
    duplicate_drills = []
    for drill_key, picks in drill_groups.items():
        seen = set()
        for idx, player_name in enumerate(picks, start=1):
            prediction_key = f"{drill_key}_{idx}"
            if player_name in seen:
                # duplicate detected, skip saving this pick
                if drill_key not in duplicate_drills:
                    duplicate_drills.append(drill_key)
                continue
            seen.add(player_name)

            # Save or update
            if prediction_key in existing_dict:
                existing_dict[prediction_key].player_name = player_name
            else:
                db.session.add(
                    Prediction(
                        user_id=user_id,
                        year=2026,
                        section="scouting_combine",
                        position_group=drill_key.split("_")[0],
                        drill="_".join(drill_key.split("_")[1:]),
                        place=idx,
                        player_name=player_name,
                    )
                )

    db.session.commit()

    # ==========================
    # Flash messages
    # ==========================
    if duplicate_drills:
        drill_names = ", ".join([d.replace("_", " ") for d in duplicate_drills])
        flash(f"Some duplicate selections were ignored in: {drill_names}. Other picks were saved.", "warning")
    else:
        flash("Predictions submitted successfully!", "success")

    return redirect(url_for("scouting_combine"))

# =========================
# COMMENT ROUTES
# =========================
@app.route("/submit-comment", methods=["POST"])
@login_required
def submit_comment():
    page = request.form.get("page").lstrip('/')
    content = request.form.get("content")
    user_id = session.get("user_id")
    if not content.strip():
        flash("Comment cannot be empty.", "warning")
        return redirect(request.referrer)
    db.session.add(Comment(user_id=user_id, page=page, content=content))
    db.session.commit()
    flash("Comment posted!", "success")
    return redirect(request.referrer + "#comments")

@app.route("/delete-comment/<int:comment_id>", methods=["POST"])
@login_required
def delete_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    user_id = session.get("user_id")
    user = User.query.get(user_id)
    if comment.user_id == user_id or (user and user.is_admin):
        db.session.delete(comment)
        db.session.commit()
        flash("Comment deleted.", "success")
    else:
        flash("You do not have permission to delete this comment.", "danger")
    return redirect(request.referrer)

# =========================
# ACCOUNT PAGE
# =========================
@app.route("/account/<int:user_id>")
@login_required
def account(user_id):
    profile_user = User.query.get_or_404(user_id)
    total_points = profile_user.total_points()
    rank = profile_user.rank()
    comments = profile_user.comments
    return render_template("account.html",
                           profile_user=profile_user,
                           total_points=total_points,
                           rank=rank,
                           comments=comments)



# =========================
# PROPHESY REVIEWS
# =========================
@app.route("/account/<int:user_id>/scouting_combine")
@login_required
def user_combine_results(user_id):
    user = User.query.get_or_404(user_id)
    unlock_datetime = datetime(2026, 3, 3, 18, 0)
    if datetime.utcnow() < unlock_datetime:
        flash("Scouting Combine Results unlock March 3rd at 6PM.", "info")
        return redirect(url_for("account", user_id=user.id))

    predictions = [p for p in user.predictions if p.section=="scouting_combine" and p.year==2026]
    predictions_dict = {f"{p.position_group}_{p.drill}_{p.place}": p.player_name for p in predictions}
    feedback = {key: p.calculate_points() for key, p in zip(predictions_dict.keys(), predictions)}
    return render_template("scouting_combine_review.html",
                           user=user,
                           profile_user=user,
                           players=players,
                           predictions_dict=predictions_dict,
                           feedback=feedback,
                           event_name="Scouting Combine")


@app.route("/account/<int:user_id>/free_agency")
@login_required
def user_free_agency_results(user_id):
    user = User.query.get_or_404(user_id)
    flash("Free Agency results are not implemented yet.", "info")
    return redirect(url_for("account", user_id=user.id))

@app.route("/account/<int:user_id>/draft")
@login_required
def user_draft_results(user_id):
    user = User.query.get_or_404(user_id)
    flash("Draft results are not implemented yet.", "info")
    return redirect(url_for("account", user_id=user.id))

@app.route("/account/<int:user_id>/schedule_release")
@login_required
def user_schedule_release_results(user_id):
    user = User.query.get_or_404(user_id)
    flash("Schedule Release results are not implemented yet.", "info")
    return redirect(url_for("account", user_id=user.id))

@app.route("/account/<int:user_id>/preseason")
@login_required
def user_preseason_results(user_id):
    user = User.query.get_or_404(user_id)
    flash("Preseason results are not implemented yet.", "info")
    return redirect(url_for("account", user_id=user.id))

@app.route("/account/<int:user_id>/season_predictions")
@login_required
def user_season_predictions_results(user_id):
    user = User.query.get_or_404(user_id)
    flash("Season Predictions results are not implemented yet.", "info")
    return redirect(url_for("account", user_id=user.id))

@app.route("/account/<int:user_id>/season_picks")
@login_required
def user_season_picks_results(user_id):
    user = User.query.get_or_404(user_id)
    flash("Season Picks results are not implemented yet.", "info")
    return redirect(url_for("account", user_id=user.id))

@app.route("/account/<int:user_id>/postseason_predictions")
@login_required
def user_postseason_predictions_results(user_id):
    user = User.query.get_or_404(user_id)
    flash("Postseason Predictions results are not implemented yet.", "info")
    return redirect(url_for("account", user_id=user.id))

@app.route("/account/<int:user_id>/postseason_picks")
@login_required
def user_postseason_picks_results(user_id):
    user = User.query.get_or_404(user_id)
    flash("Postseason Picks results are not implemented yet.", "info")
    return redirect(url_for("account", user_id=user.id))

# =========================
# OTHER PAGES ROUTES
# =========================
@app.route("/free_agency")
def free_agency():
    return render_template("free_agency.html", players=players)

@app.route("/draft")
def draft():
    return render_template("draft.html", players=players)

@app.route("/schedule_release")
def schedule_release():
    return render_template("schedule_release.html", players=players)

@app.route("/preseason")
def preseason():
    return render_template("preseason.html", players=players)

@app.route("/season_predictions")
def season_predictions():
    return render_template("season_predictions.html", players=players)

@app.route("/season_picks")
def season_picks():
    return render_template("season_picks.html", players=players)

@app.route("/postseason_predictions")
def postseason_predictions():
    return render_template("postseason_predictions.html", players=players)

@app.route("/postseason_picks")
def postseason_picks():
    return render_template("postseason.html", players=players)

@app.route("/all_accounts")
@login_required
def all_accounts():
    users = User.query.all()
    users_with_points = [(user, user.total_points()) for user in users]
    users_sorted = sorted(users_with_points, key=lambda x: x[1], reverse=True)
    return render_template("all_accounts.html", users_sorted=users_sorted)

# =========================
# RUN APP
# =========================
if __name__ == "__main__":
    app.run(debug=True)