from flask import Blueprint, request, redirect, url_for, flash, render_template, session
from collections import defaultdict
from datetime import datetime

from models import User, Prediction, Comment, db

from data.combine_map import POSITION_DRILL_MAP
from data.scouting_combine_participants import SCOUTING_COMBINE_PLAYERS

from services.scoring import leaderboard


# Blueprint
combine_bp = Blueprint("combine", __name__, url_prefix="/scouting-combine")


# =========================
# SCOUTING COMBINE PAGE
# =========================
@combine_bp.route("/")
def scouting_combine():

    user_id = session.get("user_id")

    if not user_id:
        flash("You must be logged in to view this page.", "danger")
        return redirect(url_for("auth.login"))

    user = User.query.get(user_id)

    # Fetch previous predictions
    previous_preds = Prediction.query.filter_by(
        user_id=user_id,
        year=2026,
        section="scouting_combine"
    ).all()

    previous_predictions = {
        f"{pred.position_group}_{pred.drill}_{pred.place}": pred.player_name
        for pred in previous_preds
    }

    # Fetch comments
    comments = Comment.query.filter_by(page="scouting_combine")\
        .order_by(Comment.timestamp.desc())\
        .all()

    # Leaderboard
    users = User.query.all()

    combine_top_players = leaderboard(
        users,
        section="scouting_combine"
    )[:10]

    return render_template(
        "scouting_combine.html",
        user=user,
        combine_top_players=combine_top_players,
        previous_predictions=previous_predictions,
        comments=comments,
        position_drill_map=POSITION_DRILL_MAP,
        players=SCOUTING_COMBINE_PLAYERS
    )


# =========================
# SUBMIT COMBINE PREDICTIONS
# =========================
@combine_bp.route("/submit", methods=["POST"])
def submit_combine():

    user_id = session.get("user_id")

    if not user_id:
        flash("You must be logged in to submit predictions.", "danger")
        return redirect(url_for("auth.login"))

    # Deadline
    combine_deadline = datetime(2026, 2, 26, 20, 0)

    if datetime.utcnow() > combine_deadline:
        flash("Scouting Combine predictions are now closed.", "danger")
        return redirect(url_for("combine.scouting_combine"))

    # Existing predictions
    existing_predictions = Prediction.query.filter_by(
        user_id=user_id,
        year=2026,
        section="scouting_combine"
    ).all()

    existing_dict = {
        f"{p.position_group}_{p.drill}_{p.place}": p
        for p in existing_predictions
    }

    drill_groups = defaultdict(list)

    for key, player_name in request.form.items():

        if not player_name.strip():
            continue

        parts = key.split("_")

        position_group = parts[0]
        drill = "_".join(parts[1:-1])
        place = int(parts[-1])

        drill_key = f"{position_group}_{drill}"
        drill_groups[drill_key].append(player_name.strip())

        prediction_key = f"{drill_key}_{place}"

        if prediction_key in existing_dict:

            existing_dict[prediction_key].player_name = player_name.strip()
            db.session.add(existing_dict[prediction_key])

        else:

            db.session.add(
                Prediction(
                    user_id=user_id,
                    year=2026,
                    section="scouting_combine",
                    position_group=position_group,
                    drill=drill,
                    place=place,
                    player_name=player_name.strip()
                )
            )

    db.session.commit()

    flash("Predictions submitted successfully!", "success")

    return redirect(url_for("combine.scouting_combine"))