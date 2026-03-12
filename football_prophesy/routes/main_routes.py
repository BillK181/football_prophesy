from flask import Blueprint, request, session, render_template
from models.user import User

from services.route_tracking import track_route_usage
from services.scoring import leaderboard

from data.scouting_combine_participants import SCOUTING_COMBINE_PLAYERS


main_bp = Blueprint("main", __name__)


# =========================
# BEFORE REQUEST
# =========================
@main_bp.before_app_request
def load_user_info():
    user_id = session.get("user_id")

    if request.endpoint:
        track_route_usage(request.endpoint)

    if not user_id:
        return

    user = User.query.get(user_id)

    if not user:
        return

    users = User.query.all()

    # Calculate leaderboard
    scores = leaderboard(users)

    # Find this user's score + rank
    for rank_position, entry in enumerate(scores, start=1):
        if entry["user"].id == user.id:
            session["total_points"] = entry["score"]
            session["rank"] = rank_position
            break


# =========================
# INDEX / HOME
# =========================
@main_bp.route("/")
def index():

    users = User.query.all()

    overall = leaderboard(users)[:10]
    combine = leaderboard(users, section="scouting_combine")[:10]
    free_agency = leaderboard(users, section="free_agency")[:10]

    top_players = [(entry["user"], entry["score"]) for entry in overall]
    combine_top_players = [(entry["user"], entry["score"]) for entry in combine]
    free_agency_top_players = [(entry["user"], entry["score"]) for entry in free_agency]

    return render_template(
        "index.html",
        top_players=top_players,
        combine_top_players=combine_top_players,
        free_agency_top_players=free_agency_top_players
    )


# =========================
# OTHER PAGES
# =========================
@main_bp.route("/draft")
def draft():
    return render_template("draft.html", players=SCOUTING_COMBINE_PLAYERS)


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