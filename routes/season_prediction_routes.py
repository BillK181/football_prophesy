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
season_predictions_bp = Blueprint("season_predictions", __name__, url_prefix="/season_predictions")


# =========================
# Season predictions page
# =========================
@season_predictions_bp.route("/")
@login_required
def season_predictions():
    user = current_user

    previous_preds = Prediction.query.filter_by(
        user_id=user.id,
        year=2026,
        section="schedule_release"
    ).all()

    pages = ["season_predictions"]
    comments = Comment.query.filter(Comment.page.in_(pages)).order_by(Comment.timestamp.desc()).all()

    local_tz = ZoneInfo("America/Los_Angeles")

    for comment in comments:
        comment.local_timestamp = comment.timestamp.replace(
            tzinfo=ZoneInfo("UTC")
        ).astimezone(local_tz)

    # Leaderboard
    season_predictions_leaderboard = Score.section_leaderboard(section="season_predictions", limit=10)

    return render_template(
        "season_predictions.html",
        user=user,
        page_title="Season Predictions",
        css_file="css/season_predictions.css",
        scoreboard_id="scoreboard",
        leaderboard=season_predictions_leaderboard,
        results_url=url_for('account.user_season_predictions_results', user_id=user.id),
        form_action=url_for('season_predictions.submit_season_predictions'),
        submit_text="Submit/Change Predictions",
        comments=comments,
        page_name="season_predictions",
        previous_predictions=previous_preds,
    )

# =========================
# Submit season_predictions page
# =========================
@season_predictions_bp.route("/submit_season_predictions", methods=["POST"])
@login_required
def submit_season_predictions():
    return