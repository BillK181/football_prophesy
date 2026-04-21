from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required, current_user
from collections import defaultdict
from datetime import datetime
from zoneinfo import ZoneInfo

from football_prophesy.models.user import User
from football_prophesy.models.prediction import Prediction
from football_prophesy.models.comment import Comment
from football_prophesy.models.score import Score
from football_prophesy.extensions import db

from football_prophesy.data.combine_map import POSITION_DRILL_MAP
from football_prophesy.data.scouting_combine_participants import SCOUTING_COMBINE_PLAYERS



# Blueprint
combine_bp = Blueprint("combine", __name__, url_prefix="/scouting-combine")


# =========================
# SCOUTING COMBINE PAGE
# =========================
@combine_bp.route("/")
@login_required
def scouting_combine():
    """
    Displays the Scouting Combine page.
    - Shows leaderboard (section filtered)
    - Shows previous predictions for the current user
    - Shows comments
    - Shows available players for prediction
    """
    user = current_user

    # --- Previous predictions ---
    previous_preds = Prediction.query.filter_by(
        user_id=user.id,
        year=2026,
        section="scouting_combine"
    ).all()

    previous_predictions = {
        (pred.position_group.lower().replace(" ", "_"), pred.drill, pred.place): pred.player_id
        for pred in previous_preds
    }
    # --- Comments ---
    pages = ["scouting_combine", "scouting combine"]
    comments = Comment.query.filter(Comment.page.in_(pages)).order_by(Comment.timestamp.desc()).all()

    # --- Leaderboard ---
    combine_leaderboard = Score.section_leaderboard(section="scouting_combine", limit=10)

    return render_template(
        "scouting_combine.html",
        user=user,
        page_title="Scouting Combine",
        css_file="css/scouting_combine.css",
        scoreboard_id="scoreboard",
        leaderboard=combine_leaderboard,
        results_url=url_for('account.user_combine_results', user_id=user.id),
        prediction_title="2026 Scouting Combine Predictions",
        submission_deadline="Submissions Lock 2/26 at 12pm PST",
        instructions="Prophesy the Top 3 performers at each position for each drill.",
        form_action=url_for('combine.submit_combine'),
        submit_text="Submit Predictions",
        page_name="scouting_combine",
        comments=comments,
        players=SCOUTING_COMBINE_PLAYERS,
        previous_predictions=previous_predictions,
        position_drill_map=POSITION_DRILL_MAP
    )

# =========================
# SUBMIT COMBINE PREDICTIONS
# =========================
@combine_bp.route("/submit", methods=["POST"])
@login_required
def submit_combine():
# - Handles POST submissions of user predictions for the Scouting Combine.

    user = current_user

    # Create deadline
    combine_deadline = datetime(2026, 2, 26, 20, 0)

    # Enforces deadline
    if datetime.utcnow() > combine_deadline:
        flash("Scouting Combine predictions are now closed.", "danger")
        return redirect(url_for("combine.scouting_combine"))

    # Queries Prediction table for current user, year, and section
    existing_predictions = Prediction.query.filter_by(
        user_id=current_user.id,
        year=2026,
        section="scouting_combine"
    ).all()

    # Converts to a dictionary mapping keys like "position_drill_place" → Prediction object for easier updates.
    existing_dict = {
        f"{p.position_group}_{p.drill}_{p.place}": p
        for p in existing_predictions
    }

    # drill_groups = defaultdict(list) creates a dictionary that automatically initializes empty lists for new keys, allowing easy grouping of players by drill.
    drill_groups = defaultdict(list)

    # Iterates through the incoming http request (key = "position_drill_place", value = player_name).
    # Example key "WR_3_cone_2"
    for key, player_name in request.form.items():

        # Skip empty strings
        if not player_name.strip():
            continue
        
        # Splits form field key like "WR_3_cone_2" into position_group="WR", drill="3_cone", and place=2
        parts = key.split("_")
        position_group = parts[0]
        drill = "_".join(parts[1:-1])
        place = int(parts[-1])

        # Groups submitted player names by drill_key (position_group_drill) for possible scoring or display.
        drill_key = f"{position_group}_{drill}"
        drill_groups[drill_key].append(player_name.strip())
        prediction_key = f"{drill_key}_{place}"

        # If prediction already exists in existing_dict, update player_name and add to session.
        if prediction_key in existing_dict:
            existing_dict[prediction_key].player_name = player_name.strip()
            db.session.add(existing_dict[prediction_key])

        # Otherwise, create a new Prediction object and add to session.
        else:
            db.session.add(
                Prediction(
                    user_id=current_user.id,
                    year=2026,
                    section="scouting_combine",
                    position_group=position_group,
                    drill=drill,
                    place=place,
                    player_name=player_name.strip()
                )
            )

    # Commit changed to the db
    db.session.commit()

    flash("Predictions submitted successfully!", "success")

    return redirect(url_for("combine.scouting_combine"))