from flask import Blueprint, render_template, request, flash, redirect, url_for, jsonify
from flask_login import login_required, current_user
from collections import defaultdict
from datetime import datetime
from zoneinfo import ZoneInfo
import traceback

import requests

from football_prophesy.decorators import admin_required
from football_prophesy.models.user import User
from football_prophesy.models.game import Game
from football_prophesy.models.prediction import Prediction
from football_prophesy.models.comment import Comment
from football_prophesy.models.score import Score
from football_prophesy.extensions import db
from football_prophesy.services.email_service import send_season_picks_email
from football_prophesy.services.sleeper_players import update_players
from football_prophesy.services.season_picks_scoring import recalc_season_picks_scores
from football_prophesy.services.games import update_games



# Blueprint
season_picks_bp = Blueprint("season_picks", __name__, url_prefix="/season_picks")

# =========================
# Season Picks page
# =========================
@season_picks_bp.route("/")
@login_required
def season_picks():

    user = current_user

    week = request.args.get("week", 1, type=int)

    games = Game.query.filter_by(
        season=2026,
        week=week,
        postseason=False,
    ).order_by(Game.date).all()

    local_tz = ZoneInfo("America/Los_Angeles")
    now = datetime.now(ZoneInfo("UTC"))

    for game in games:

        if game.date:

            # =========================
            # Game time
            # =========================

            game_time = game.date

            # Make sure game time is UTC
            if game_time.tzinfo is None:
                game_time = game_time.replace(
                    tzinfo=ZoneInfo("UTC")
                )

            # =========================
            # Local display time
            # =========================

            game.local_date = game_time.astimezone(local_tz)

            # =========================
            # Lock game once it starts
            # =========================

            game.locked = now >= game_time

            # =========================
            # Points
            # =========================

            # 10 points for games starting
            # after 5:00 PM Pacific
            if (
                game.local_date.hour > 17
                or (
                    game.local_date.hour == 17
                    and game.local_date.minute > 0
                )
            ):
                game.points = 10
            else:
                game.points = 5

        else:

            # No game time = don't lock it
            game.locked = False

    season_predictions = Prediction.query.filter_by(
        user_id=user.id,
        year=2026,
        section="season_predictions"
    ).all()

    previous_picks = {
        prediction.game_id: prediction.team_id
        for prediction in Prediction.query.filter_by(
            user_id=user.id,
            year=2026,
            section="season_picks"
        ).all()
    }

    # =========================
    # Comments
    # =========================

    pages = ["season picks"]

    comments = Comment.query.filter(
        Comment.page.in_(pages)
    ).order_by(
        Comment.timestamp.desc()
    ).all()

    for comment in comments:

        comment.local_timestamp = comment.timestamp.replace(
            tzinfo=ZoneInfo("UTC")
        ).astimezone(local_tz)

    # =========================
    # Leaderboard
    # =========================

    season_picks_leaderboard = Score.section_leaderboard(
        section="season_picks",
        limit=10
    )

    return render_template(
        "season_picks.html",
        user=user,
        css_file="css/season_picks.css",
        scoreboard_id="scoreboard",
        leaderboard=season_picks_leaderboard,
        results_url=url_for(
            "account.user_season_picks_results",
            user_id=user.id
        ),
        form_action=url_for(
            "season_picks.submit_season_picks"
        ),
        comments=comments,
        page_name="season_picks",
        previous_picks=previous_picks,
        season_predictions=season_predictions,
        week=week,
        weeks=range(1, 19),
        games=games
    )

# =========================
# Submit season_picks page
# =========================
@season_picks_bp.route("/submit_season_picks", methods=["POST"])
@login_required
def submit_season_picks():

    user = current_user

    now = datetime.now(ZoneInfo("UTC"))

    data = request.get_json(silent=True) or {}

    locked_picks = 0
    submitted_picks = 0

    for game_id, winner_team_id in data.items():

        if not winner_team_id:
            continue

        game_id = int(game_id)
        winner_team_id = int(winner_team_id)

        game = Game.query.get(game_id)

        if not game:
            continue

        # =========================
        # Check game lock
        # =========================

        game_time = game.date

        if game_time:

            if game_time.tzinfo is None:
                game_time = game_time.replace(
                    tzinfo=ZoneInfo("UTC")
                )

            if now >= game_time:
                locked_picks += 1
                continue

        # =========================
        # Find existing prediction
        # =========================

        prediction = Prediction.query.filter_by(
            user_id=user.id,
            year=2026,
            section="season_picks",
            game_id=game_id
        ).first()

        # =========================
        # Save prediction
        # =========================

        if prediction is None:

            prediction = Prediction(
                user_id=user.id,
                year=2026,
                section="season_picks",
                game_id=game_id,
                team_id=winner_team_id
            )

            db.session.add(prediction)

        else:

            prediction.team_id = winner_team_id

        submitted_picks += 1

    db.session.commit()

    # =========================
    # Response
    # =========================

    if locked_picks > 0:

        if submitted_picks > 0:

            message = (
                f"{submitted_picks} pick(s) submitted. "
                f"{locked_picks} pick(s) rejected because "
                f"the game had already started."
            )

        else:

            message = (
                "No picks were submitted because "
                "the selected games have already started."
            )

        return jsonify({
            "status": "warning",
            "message": message
        })

    return jsonify({
        "status": "success",
        "message": "Season Picks submitted successfully!"
    })


# =========================
# Update Season Picks page
# =========================
@season_picks_bp.route("/update", methods=["POST"])
@login_required
@admin_required
def update_season_picks():

    games_updated = True

    try:
        update_games(2026)

    except requests.exceptions.HTTPError as e:

        if e.response.status_code == 429:
            games_updated = False

        else:
            raise

    recalc_season_picks_scores()

    if games_updated:
        flash(
            "Games updated and Season Picks scores recalculated!",
            "success"
        )
    else:
        flash(
            "Games API is rate limited. Season Picks scores were recalculated using existing game data.",
            "warning"
        )

    return redirect(
        url_for("season_picks.season_picks")
    )




# =========================
# Send season_picks emails
# =========================
@season_picks_bp.route("/send_emails", methods=["POST"])
@login_required
@admin_required
def send_season_picks_emails():

    now = datetime.now(ZoneInfo("UTC"))

    # =========================
    # Find next upcoming game
    # =========================

    next_game = Game.query.filter(
        Game.season == 2026,
        Game.postseason == False,
        Game.date > now
    ).order_by(
        Game.date
    ).first()

    if not next_game:

        flash(
            "No upcoming Season Picks games found.",
            "warning"
        )

        return redirect(
            url_for("season_picks.season_picks")
        )

    current_week = next_game.week

    # =========================
    # Get all upcoming games
    # for this week
    # =========================

    week_games = Game.query.filter(
        Game.season == 2026,
        Game.week == current_week,
        Game.postseason == False,
        Game.date > now
    ).order_by(
        Game.date
    ).all()

    if not week_games:

        flash(
            f"No upcoming games found for Week {current_week}.",
            "warning"
        )

        return redirect(
            url_for("season_picks.season_picks")
        )

    week_game_ids = {
        game.id
        for game in week_games
    }

    # =========================
    # Get all users
    # =========================

    users = User.query.all()

    incomplete_users = []

    for user in users:

        if not user.email:
            continue

        # =========================
        # Get user's picks
        # for this week
        # =========================

        user_predictions = Prediction.query.filter(
            Prediction.user_id == user.id,
            Prediction.year == 2026,
            Prediction.section == "season_picks",
            Prediction.game_id.in_(week_game_ids)
        ).all()

        # =========================
        # Games already picked
        # =========================

        picked_game_ids = {
            prediction.game_id
            for prediction in user_predictions
        }

        # =========================
        # Games still missing
        # =========================

        missing_games = [
            game
            for game in week_games
            if game.id not in picked_game_ids
        ]

        # =========================
        # Only email users
        # with missing picks
        # =========================

        if missing_games:

            incomplete_users.append({
                "user": user,
                "missing_games": missing_games
            })

    # =========================
    # Send emails
    # =========================

    sent = 0
    failed = 0

    for entry in incomplete_users:

        user = entry["user"]

        missing_games = entry["missing_games"]

        # =========================
        # Earliest missing game
        # determines deadline
        # =========================

        deadline_game = min(
            missing_games,
            key=lambda game: game.date
        )

        deadline = deadline_game.date

        # =========================
        # Make sure deadline
        # is timezone aware
        # =========================

        if deadline.tzinfo is None:

            deadline = deadline.replace(
                tzinfo=ZoneInfo("UTC")
            )

        # =========================
        # Convert deadline to
        # Pacific time for email
        # =========================

        deadline = deadline.astimezone(
            ZoneInfo("America/Los_Angeles")
        )

        # =========================
        # Send email
        # =========================

        success = send_season_picks_email(
            user=user,
            week=current_week,
            missing_games=missing_games,
            deadline=deadline
        )

        if success:
            sent += 1
        else:
            failed += 1

    # =========================
    # Admin response
    # =========================

    flash(
        f"Week {current_week} reminder emails sent → "
        f"{sent} success, {failed} failed.",
        "success"
    )

    return redirect(
        url_for("season_picks.season_picks")
    )