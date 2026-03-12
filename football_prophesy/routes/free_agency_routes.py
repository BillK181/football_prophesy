from flask import Blueprint, render_template, request, session, redirect, url_for, flash
from datetime import datetime

from models import User, Prediction, Comment, db

from data.free_agency_players import FREE_AGENCY_PLAYERS
from data.free_agency_results import FREE_AGENCY_RESULTS

from services.scoring import leaderboard


free_agency_bp = Blueprint("free_agency", __name__, url_prefix="/free_agency")


# =========================
# FREE AGENCY PAGE
# =========================
@free_agency_bp.route("/")
def free_agency():

    user_id = session.get("user_id")

    if not user_id:
        flash("You must be logged in to access this page.", "danger")
        return redirect(url_for("auth.login"))

    user = User.query.get_or_404(user_id)

    # Leaderboard
    users = User.query.all()
    free_agency_board = leaderboard(users, section="free_agency")[:10]
    top_players = [(entry["user"], entry["score"]) for entry in free_agency_board]

    # Existing predictions
    existing_predictions = Prediction.query.filter_by(
        user_id=user.id,
        year=2026,
        section="free_agency"
    ).all()

    # Prefill form values
    user_predictions = {}

    for p in existing_predictions:
        key_team = f"{p.player_name.replace(' ', '_')}_team"
        key_salary = f"{p.player_name.replace(' ', '_')}_salary"

        user_predictions[key_team] = p.team_prediction
        user_predictions[key_salary] = p.salary_prediction

    # Comments
    page = request.path.lstrip('/')

    comments = Comment.query.filter_by(page=page)\
        .order_by(Comment.timestamp.desc())\
        .all()

    return render_template(
        "free_agency.html",
        user=user,
        players=FREE_AGENCY_PLAYERS,
        top_players=top_players,
        user_predictions=user_predictions,
        comments=comments
    )


# =========================
# SUBMIT FREE AGENCY PICKS
# =========================
@free_agency_bp.route("/submit", methods=["POST"])
def submit_free_agency():

    user_id = session.get("user_id")

    if not user_id:
        flash("You must be logged in.", "danger")
        return redirect(url_for("auth.login"))

    free_agency_deadline = datetime(2026, 3, 9, 12, 0)

    if datetime.utcnow() > free_agency_deadline:
        flash("Free Agency predictions are now closed.", "danger")
        return redirect(url_for("free_agency.free_agency"))

    for key, value in request.form.items():

        if not value:
            continue

        if key.endswith("_team"):
            player_name = key[:-5].replace("_", " ")
            field = "team"

        elif key.endswith("_salary"):
            player_name = key[:-7].replace("_", " ")
            field = "salary"

        else:
            continue

        pred = Prediction.query.filter_by(
            user_id=user_id,
            player_name=player_name,
            section="free_agency",
            year=2026
        ).first()

        if not pred:
            pred = Prediction(
                user_id=user_id,
                player_name=player_name,
                section="free_agency",
                year=2026
            )

        if field == "team":
            pred.team_prediction = value
        else:
            pred.salary_prediction = value

        db.session.add(pred)

    db.session.commit()

    flash("Free Agency predictions saved!", "success")

    return redirect(url_for("free_agency.free_agency"))