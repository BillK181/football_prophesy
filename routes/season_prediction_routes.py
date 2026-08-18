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
from football_prophesy.models.team import Team
from football_prophesy.data.season_predictions_points import SEASON_PREDICTION_POINTS
from football_prophesy.extensions import db
from football_prophesy.services.email_service import send_preseason_email
from football_prophesy.services.sleeper_players import update_players
from football_prophesy.services.scoring import recalc_season_predictions_scores
from football_prophesy.services.player_update import update_players_if_needed

season_predictions_bp = Blueprint(
    "season_predictions",
    __name__,
    url_prefix="/season_predictions"
)

# ==================================================
# Season Predictions
# ==================================================
@season_predictions_bp.route("/")
@login_required
def season_predictions():
    user = current_user

    previous_preds = Prediction.query.filter_by(
        user_id=user.id,
        year=2026,
        section="season_predictions"
    ).all()

    pages = ["season_predictions"]

    comments = Comment.query.filter(
        Comment.page.in_(pages)
    ).order_by(
        Comment.timestamp.desc()
    ).all()

    local_tz = ZoneInfo("America/Los_Angeles")

    for comment in comments:
        comment.local_timestamp = comment.timestamp.replace(
            tzinfo=ZoneInfo("UTC")
        ).astimezone(local_tz)

    season_predictions_leaderboard = Score.section_leaderboard(
        section="season_predictions",
        limit=10
    )

    return render_template(
        "season_predictions.html",
        user=user,
        page_title="Season Predictions",
        css_file="css/season_predictions.css",
        scoreboard_id="scoreboard",
        leaderboard=season_predictions_leaderboard,
        results_url=url_for(
            "account.user_season_predictions_results",
            user_id=user.id
        ),
        form_action=url_for(
            "season_predictions.submit_season_predictions"
        ),
        submit_text="Submit/Change Predictions",
        comments=comments,
        page_name="season_predictions",
        previous_predictions=previous_preds,
    )

# ==================================================
# Get Players
# ==================================================
@season_predictions_bp.route("/players")
def get_players():
    players = Player.query.filter(
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

# ==================================================
# Submit
# ==================================================
@season_predictions_bp.route("/submit", methods=["POST"])
@login_required
def submit_season_predictions():

    SEASON_PREDICTIONS_DEADLINE = datetime(
        2026,
        9,
        9,
        20,
        0,
        tzinfo=ZoneInfo("America/New_York")
    )

    now = datetime.now(
        ZoneInfo("America/New_York")
    )

    if now >= SEASON_PREDICTIONS_DEADLINE:

        return jsonify({
            "status": "error",
            "message": "Season predictions submissions are closed."
        }), 403


    data = request.get_json(silent=True) or {}

    user = current_user


    # ==========================================
    # PLAYER PREDICTIONS
    # ==========================================

    player_prediction_keys = {
        "mvp_1",
        "sb_mvp_1",
        "passing_yards_1",
        "rushing_yards_1",
        "receiving_yards_1",
        "sacks_1",
        "tackles_1",
        "interceptions_1",
    }


    # ==========================================
    # PROCESS PREDICTIONS
    # ==========================================

    for prediction, value in data.items():

        if not value:
            continue


        pred = Prediction.query.filter_by(
            user_id=user.id,
            year=2026,
            section="season_predictions",
            season_prediction=prediction
        ).first()


        # ==========================================
        # PLAYER PREDICTION
        # ==========================================

        if prediction in player_prediction_keys:

            player_id = int(value)


            if pred:

                pred.player_id = player_id
                pred.team_id = None
                pred.team_prediction = None

            else:

                pred = Prediction(
                    user_id=user.id,
                    year=2026,
                    section="season_predictions",
                    season_prediction=prediction,
                    player_id=player_id,
                    team_id=None,
                    team_prediction=None
                )

                db.session.add(pred)


        # ==========================================
        # TEAM PREDICTION
        # ==========================================

        else:

            team_id = int(value)


            # Make sure the team actually exists
            team = Team.query.get(team_id)

            if not team:

                return jsonify({
                    "status": "error",
                    "message": "Invalid team selected."
                }), 400


            if pred:

                pred.team_id = team_id
                pred.player_id = None
                pred.team_prediction = None

            else:

                pred = Prediction(
                    user_id=user.id,
                    year=2026,
                    section="season_predictions",
                    season_prediction=prediction,
                    player_id=None,
                    team_id=team_id,
                    team_prediction=None
                )

                db.session.add(pred)


    db.session.commit()


    return jsonify({
        "status": "ok",
        "message": "Season predictions submitted successfully!"
    })

# ==================================================
# Update
# ==================================================
@season_predictions_bp.route("/update", methods=["GET", "POST"])
@login_required
def update_season_predictions():

    SEASON_PREDICTIONS_TEAMS = [
        "highest_scoring_offense",
        "lowest_scoring_offense",
        "best_defense",
        "worst_defense",
        "afc_1_seed",
        "nfc_1_seed",
        "afc_east_champion",
        "afc_south_champion",
        "afc_north_champion",
        "afc_west_champion",
        "nfc_east_champion",
        "nfc_south_champion",
        "nfc_north_champion",
        "nfc_west_champion",
    ]

    MULTI_PREDICTIONS = {
        "afc_playoff_teams": 7,
        "nfc_playoff_teams": 7,
        "afc_championship_matchup": 2,
        "nfc_championship_matchup": 2,
        "super_bowl_matchup": 2,
        "super_bowl_champion": 1,
    }

    SEASON_PREDICTIONS_PLAYERS = [
        "mvp",
        "sb_mvp",
        "passing_yards",
        "rushing_yards",
        "receiving_yards",
        "sacks",
        "tackles",
        "interceptions",
    ]

    teams = Team.query.order_by(Team.id).all()


    # ==================================================
    # POST
    # ==================================================

    if request.method == "POST":

        print("==========================================")
        print("UPDATING SEASON PREDICTIONS")
        print("FORM DATA:")
        print(request.form)
        print("==========================================")


        # ==================================================
        # UPDATE PLAYER AWARDS
        # ==================================================

        for season_prediction in SEASON_PREDICTIONS_PLAYERS:

            # ------------------------------------------
            # Get selected player ID
            # ------------------------------------------

            awarded_player_id = request.form.get(
                season_prediction
            )


            # ------------------------------------------
            # Remove this award from EVERY player
            # ------------------------------------------

            for player in Player.query.all():

                awards = list(
                    player.season_prediction or []
                )

                if season_prediction in awards:

                    awards.remove(
                        season_prediction
                    )

                    player.season_prediction = awards


            # ------------------------------------------
            # Add award to selected player
            # ------------------------------------------

            if awarded_player_id:

                player = Player.query.get(
                    int(awarded_player_id)
                )

                if player:

                    awards = list(
                        player.season_prediction or []
                    )

                    if season_prediction not in awards:

                        awards.append(
                            season_prediction
                        )

                    player.season_prediction = awards


        # ==================================================
        # UPDATE SINGULAR TEAM AWARDS
        # ==================================================

        for season_prediction in SEASON_PREDICTIONS_TEAMS:

            # ------------------------------------------
            # Get selected team IDs
            # ------------------------------------------

            awarded_team_ids = request.form.getlist(
                season_prediction
            )

            print(
                f"{season_prediction}: "
                f"{awarded_team_ids}"
            )


            # ------------------------------------------
            # Convert IDs to integers
            # ------------------------------------------

            awarded_team_ids = [
                int(team_id)
                for team_id in awarded_team_ids
                if team_id
            ]


            # ------------------------------------------
            # Remove this award from EVERY team
            # ------------------------------------------

            for team in Team.query.all():

                awards = list(
                    team.season_prediction or []
                )

                if season_prediction in awards:

                    awards.remove(
                        season_prediction
                    )

                    team.season_prediction = awards


            # ------------------------------------------
            # Add award to selected team(s)
            # ------------------------------------------

            for awarded_team_id in awarded_team_ids:

                team = Team.query.get(
                    awarded_team_id
                )

                if not team:
                    continue

                awards = list(
                    team.season_prediction or []
                )

                if season_prediction not in awards:

                    awards.append(
                        season_prediction
                    )

                team.season_prediction = awards

        # ==================================================
        # UPDATE MULTI TEAM AWARDS
        # ==================================================

        for season_prediction, selection_count in MULTI_PREDICTIONS.items():

            for count in range(1, selection_count + 1):

                prediction_name = f"{season_prediction}_{count}"

                awarded_team_id = request.form.get(
                    prediction_name
                )

                print(
                    f"{prediction_name}: "
                    f"{awarded_team_id}"
                )

                # Remove this prediction from every team
                for team in Team.query.all():

                    awards = list(
                        team.season_prediction or []
                    )

                    if prediction_name in awards:

                        awards.remove(prediction_name)

                        team.season_prediction = awards

                # Add prediction to selected team
                if awarded_team_id:

                    team = Team.query.get(
                        int(awarded_team_id)
                    )

                    if team:

                        awards = list(
                            team.season_prediction or []
                        )

                        if prediction_name not in awards:

                            awards.append(
                                prediction_name
                            )

                        team.season_prediction = awards

        # ==================================================
        # SAVE
        # ==================================================

        db.session.commit()


        print("==========================================")
        print("TEAM AWARDS AFTER COMMIT")
        print("==========================================")


        for team in Team.query.order_by(
            Team.id
        ).all():

            print(
                team.id,
                team.city,
                team.name,
                team.season_prediction
            )


        # ==================================================
        # RECALCULATE SCORES
        # ==================================================

        recalc_season_predictions_scores()


        # ==================================================
        # SUCCESS MESSAGE
        # ==================================================

        flash(
            "Season Predictions points updated!",
            "success"
        )


        return redirect(
            url_for(
                "season_predictions.update_season_predictions"
            )
        )


    # ==================================================
    # BUILD AWARDED PLAYER MAP
    # ==================================================

    awarded_players = {}

    for player in Player.query.all():

        for season_prediction in (
            player.season_prediction or []
        ):

            if (
                season_prediction
                in SEASON_PREDICTIONS_PLAYERS
            ):

                awarded_players[
                    season_prediction
                ] = player


    # ==================================================
    # BUILD AWARDED TEAM MAP
    # ==================================================

    awarded_teams = {}

    for team in Team.query.order_by(Team.id).all():

        for season_prediction in team.season_prediction or []:

            if season_prediction in SEASON_PREDICTIONS_TEAMS:

                awarded_teams.setdefault(
                    season_prediction,
                    []
                ).append(team)

            else:

                for prediction, selection_count in MULTI_PREDICTIONS.items():

                    if season_prediction.startswith(
                        f"{prediction}_"
                    ):

                        awarded_teams.setdefault(
                            season_prediction,
                            []
                        ).append(team)

                        break


    # ==================================================
    # GET USER PREDICTIONS
    # ==================================================

    predictions = Prediction.query.filter(
        Prediction.year == 2026,
        Prediction.section == "season_predictions",
        Prediction.season_prediction.isnot(None),
    ).all()


    # ==================================================
    # GET COMPLETED USERS
    # ==================================================

    completed_user_ids = set()

    completed_users = []

    for prediction in predictions:

        if (
            prediction.user_id
            not in completed_user_ids
        ):

            completed_user_ids.add(
                prediction.user_id
            )

            completed_users.append(
                prediction.user
            )


    # ==================================================
    # RENDER
    # ==================================================

    return render_template(
        "update_season_predictions.html",
        SEASON_PREDICTIONS_PLAYERS=SEASON_PREDICTIONS_PLAYERS,
        SEASON_PREDICTIONS_TEAMS=SEASON_PREDICTIONS_TEAMS,
        MULTI_PREDICTIONS=MULTI_PREDICTIONS,
        completed_users=completed_users,
        awarded_players=awarded_players,
        awarded_teams=awarded_teams,
        page_title="Update Season Predictions",
        css_file="css/update_season_predictions.css",
        teams=teams,
    )

# =========================
# Send season_predictions emails
# =========================
@season_predictions_bp.route("/send_emails", methods=["POST"])
@login_required
def send_season_predictions_emails():
    return