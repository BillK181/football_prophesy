from flask import Blueprint, request, session, render_template
from flask_login import current_user
from football_prophesy.models.user import User
from football_prophesy.models.score import Score

from football_prophesy.services.route_tracking import track_route_usage

from football_prophesy.data.scouting_combine_participants import SCOUTING_COMBINE_PLAYERS


main_bp = Blueprint("main", __name__)


# =========================
# BEFORE REQUEST
# =========================
@main_bp.before_app_request
def load_user_info():
# Purpose: Track route usage for analytics.

    if not current_user.is_authenticated:
        return

    # Track route usage
    if request.endpoint:
        track_route_usage(request.endpoint)

# =========================
# INDEX / HOME
# =========================
@main_bp.route("/")
def index():

    # Fetch user
    user = current_user

    # Calculates leaderboards:
    top_players = Score.section_leaderboard(limit=10)
    
    return render_template(
        "index.html", 
        leaderboard=top_players,
        user=user
    )

# =========================
# OTHER PAGES
# =========================
@main_bp.route("/schedule_release")
def schedule_release():
    return render_template("schedule_release.html", players=SCOUTING_COMBINE_PLAYERS)


@main_bp.route("/preseason")
def preseason():
    return render_template("preseason.html", players=SCOUTING_COMBINE_PLAYERS)


@main_bp.route("/season_predictions")
def season_predictions():
    return render_template("season_predictions.html", players=SCOUTING_COMBINE_PLAYERS)


@main_bp.route("/season_picks")
def season_picks():
    return render_template("season_picks.html", players=SCOUTING_COMBINE_PLAYERS)


@main_bp.route("/postseason_predictions")
def postseason_predictions():
    return render_template("postseason_predictions.html", players=SCOUTING_COMBINE_PLAYERS)


@main_bp.route("/postseason_picks")
def postseason_picks():
    return render_template("postseason.html", players=SCOUTING_COMBINE_PLAYERS)