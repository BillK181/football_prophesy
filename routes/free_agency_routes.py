from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required, current_user
from datetime import datetime
from zoneinfo import ZoneInfo

from football_prophesy.models.user import User
from football_prophesy.models.prediction import Prediction
from football_prophesy.models.comment import Comment
from football_prophesy.models.score import Score
from football_prophesy.extensions import db

from football_prophesy.data.free_agency_players import FREE_AGENCY_PLAYERS
from football_prophesy.data.free_agency_results import FREE_AGENCY_RESULTS


free_agency_bp = Blueprint("free_agency", __name__, url_prefix="/free_agency")


# =========================
# FREE AGENCY PAGE
# =========================
@free_agency_bp.route("/")
@login_required
def free_agency():
    """
    Displays the Free Agency page.
    - Shows leaderboard (section filtered)
    - Shows current user's previous predictions
    - Shows comments
    - Shows all available players
    """

    # Authentication, uses @login_required and current_user
    user = current_user

    players=FREE_AGENCY_PLAYERS
    
    # --- Leaderboard ---
    free_agency_leaderboard = Score.section_leaderboard(section="free_agency", limit=10)

    # --- Existing predictions ---
    existing_predictions = Prediction.query.filter_by(
        user_id=user.id,
        year=2026,
        section="free_agency"
    ).order_by(Prediction.id.asc()).all()

    paired = zip(players, existing_predictions)

    user_predictions = {}

    for p in existing_predictions:
        key_team = f"prediction_{p.id}_team"
        key_salary = f"prediction_{p.id}_salary"

        user_predictions[key_team] = p.team_prediction
        user_predictions[key_salary] = p.salary_prediction

    # --- Comments ---
    pages = ["free_agency", "free agency"]
    comments = Comment.query.filter(Comment.page.in_(pages)).order_by(Comment.timestamp.desc()).all()

    return render_template(
        "free_agency.html",
        user=user,
        page_title="Free Agency",
        css_file="css/free_agency.css",
        scoreboard_id="scoreboard",
        leaderboard=free_agency_leaderboard,
        results_url=url_for('account.free_agency_review', user_id=user.id),
        prediction_title="2026 Free Agency Predictions",
        submission_deadline="Submissions Lock 3/9 at 6am PST",
        instructions="Prophesy Where Each Free Agency Lands And For How Much",
        form_action=url_for('free_agency.submit_free_agency'),
        submit_text="Submit/Update Prophecy",
        page_name="free_agency",
        comments=comments,
        players=players,
        existing_predictions=existing_predictions,
        user_predictions=user_predictions,
        paired=paired
    )


# =========================
# SUBMIT FREE AGENCY PICKS
# =========================
@free_agency_bp.route("/submit", methods=["POST"])
@login_required
def submit_free_agency():
# Handles POST submissions of Free Agency predictions

    # Authentication, uses @login_required and current_user
    user = current_user

    # Deadline enforement
    free_agency_deadline = datetime(2026, 3, 9, 12, 0)
    if datetime.utcnow() > free_agency_deadline:
        flash("Free Agency predictions are now closed.", "danger")
        return redirect(url_for("free_agency.free_agency"))
    
    # Process form data:
    for key, value in request.form.items():
        # Skips empty values
        if not value:
            continue
        
        # Determine prediction type
        if key.endswith("_team"):
            # Extracts player_name from the key
            player_name = key[:-5].replace("_", " ")
            field = "team"
        elif key.endswith("_salary"):
            player_name = key[:-7].replace("_", " ")
            field = "salary"
        else:
            continue

        # Retrieve or create prediction object
        pred = Prediction.query.filter_by(
            user_id=current_user.id,
            player_name=player_name,
            section="free_agency",
            year=2026
        ).first()

        # If none exists, creates a new Prediction object
        if not pred:
            pred = Prediction(
                user_id=current_user.id,
                player_name=player_name,
                section="free_agency",
                year=2026
            )

        # Sets pred.team_prediction or pred.salary_prediction based on field
        if field == "team":
            pred.team_prediction = value
        else:
            pred.salary_prediction = value

        db.session.add(pred)

    # Commit changes to database
    db.session.commit()

    flash("Free Agency predictions saved!", "success")

    return redirect(url_for("free_agency.free_agency"))