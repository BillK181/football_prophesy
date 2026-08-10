from flask import Blueprint, render_template, request, flash, redirect, url_for, jsonify
from flask_login import login_required, current_user
from collections import defaultdict
from datetime import datetime
from zoneinfo import ZoneInfo
import traceback
from football_prophesy.extensions import mail

from football_prophesy.decorators import admin_required
from football_prophesy.models.user import User
from football_prophesy.models.player import Player
from football_prophesy.models.prediction import Prediction
from football_prophesy.models.comment import Comment
from football_prophesy.models.score import Score
from football_prophesy.extensions import db
from football_prophesy.services.email_service import send_preseason_email
from football_prophesy.services.sleeper_players import update_players
from football_prophesy.services.scoring import recalc_preseason_scores
from football_prophesy.services.player_update import update_players_if_needed


# Blueprint
preseason_bp = Blueprint("preseason", __name__, url_prefix="/preseason")


# =========================
# Preseason page
# =========================
@preseason_bp.route("/")
@login_required
def preseason():
    user = current_user

    previous_preds = Prediction.query.filter_by(
        user_id=user.id,
        year=2026,
        section="preseason"
    ).all()

    # Comments 
    pages = ["preseason"]
    comments = Comment.query.filter(Comment.page.in_(pages)).order_by(Comment.timestamp.desc()).all()

    local_tz = ZoneInfo("America/Los_Angeles")

    for comment in comments:
        comment.local_timestamp = comment.timestamp.replace(
            tzinfo=ZoneInfo("UTC")
        ).astimezone(local_tz)

    # Leaderboard
    preseason_leaderboard = Score.section_leaderboard(section="preseason", limit=10)


    return render_template(
        "preseason.html",
        user=user,
        page_title="Preseason",
        css_file="css/preseason.css",
        scoreboard_id="scoreboard",
        leaderboard=preseason_leaderboard,
        results_url=url_for('account.user_preseason_results', user_id=user.id),
        form_action=url_for('preseason.submit_preseason'),
        submit_text="Submit/Change Predictions",
        comments=comments,
        page_name="preseason",
        previous_predictions=previous_preds,
    )

# =========================
# Get Players
# =========================
@preseason_bp.route("/players")
def get_players():

    players = Player.query.filter(
        Player.position.in_(["QB", "RB", "WR"]),
        Player.status == "Active"
    ).all()

    return jsonify([
        {
            "id": player.id,
            "name": player.name,
            "position": player.position,
            "team": player.team
        }
        for player in players
    ])

# =========================
# Submit preseason page
# =========================
@preseason_bp.route("/submit_preseason", methods=["POST"])
@login_required
def submit_preseason():

    PRESEASON_DEADLINE = datetime(
        2026, 8, 6, 20, 0,
        tzinfo=ZoneInfo("America/New_York")
    )

    now = datetime.now(ZoneInfo("America/New_York"))

    if now >= PRESEASON_DEADLINE:
        return jsonify({
            "status": "error",
            "message": "Preseason submissions are closed."
        }), 403


    data = request.get_json(silent=True) or {}

    user = current_user


    # Example expected positions:
    required_positions = [
        "QB1",
        "QB2",
        "QB3",
        "RB1",
        "RB2",
        "RB3",
        "WR1",
        "WR2",
        "WR3",
        "WR4"
    ]


    # Check missing positions
    missing_positions = [
        pos for pos in required_positions
        if not data.get(pos)
    ]

    if missing_positions:
        return jsonify({
            "status": "error",
            "message": f"Please select players for all positions. Missing: {', '.join(missing_positions)}"
        }), 400


    # Save predictions
    for position, player_id in data.items():

        if not position:
            continue

        try:
            player_id = int(player_id)
        except (ValueError, TypeError):
            continue


        pred = Prediction.query.filter_by(
            user_id=user.id,
            year=2026,
            section="preseason",
            preseason_position=position
        ).first()


        if pred:
            pred.player_id = player_id

        else:
            pred = Prediction(
                user_id=user.id,
                year=2026,
                section="preseason",
                preseason_position=position,
                player_id=player_id
            )

            db.session.add(pred)


    db.session.commit()


    return jsonify({
        "status": "ok",
        "message": "Preseason predictions submitted successfully!"
    })


# =========================
# Update draft page
# =========================
@preseason_bp.route("/update", methods=["GET", "POST"])
@login_required
@admin_required
def update_preseason():

    predictions = Prediction.query.filter(
        Prediction.year == 2026,
        Prediction.section == "preseason",
        Prediction.preseason_position.isnot(None),
        Prediction.player_id.isnot(None)
    ).all()

    seen_player_ids = set()
    unique_players = []

    for prediction in predictions:
        if prediction.player_id not in seen_player_ids:
            seen_player_ids.add(prediction.player_id)
            unique_players.append(prediction)

    completed_user_ids = set()
    completed_users = []

    for prediction in predictions:
        if prediction.user_id not in completed_user_ids:
            completed_user_ids.add(prediction.user_id)
            completed_users.append(prediction.user)


    if request.method == "POST":

        for prediction in unique_players:

            points = request.form.get(
                f"preseason_points_{prediction.player_id}"
            )

            if points and int(points) != 0:
                prediction.player.preseason_points = int(points)
            else:
                prediction.player.preseason_points = None

        db.session.commit()

        recalc_preseason_scores()

        flash(
            "Preseason points updated!",
            "success"
        )

        return redirect(
            url_for("preseason.update_preseason")
        )


    return render_template(
        "update_preseason.html",
        predictions=unique_players,
        completed_users=completed_users,
        page_title="Update Preseason",
        css_file="css/update_preseason.css"
    )

# =========================
# Update players
# =========================
@preseason_bp.route("/update_players", methods=["POST"])
@login_required
@admin_required
def update_players_route():
    update_players()

    flash("Players updated successfully!", "success")
    return redirect(url_for("preseason.update_preseason"))


# =========================
# Send preseason emails
# =========================
@preseason_bp.route("/send_emails", methods=["POST"])
@login_required
def send_preseason_emails():

    users = User.query.all()

    predictions = Prediction.query.filter(
            Prediction.year == 2026,
            Prediction.section == "preseason",
            Prediction.preseason_position.isnot(None),
            Prediction.player_id.isnot(None)
        ).all()
                
    completed_users = []
                
    for prediction in predictions:
        if prediction.user_id not in completed_users:
            completed_users.append(prediction.user_id)

    incomplete_users = []

    for user in users:
        if user.id not in completed_users:
            incomplete_users.append(user)
    
    sent = 0
    failed = 0

    for u in incomplete_users:

        if not u.email:
            continue

        success = send_preseason_email(u)

        if success:
            sent += 1
        else:
            failed += 1

    flash(
        f"Emails sent → {sent} success, {failed} failed",
        "success"
    )

    return redirect(url_for("preseason.update_preseason"))