from flask import Blueprint, render_template, request, flash, redirect, url_for, jsonify
from flask_login import login_required, current_user
from collections import defaultdict
from datetime import datetime
from zoneinfo import ZoneInfo

from football_prophesy.decorators import admin_required
from football_prophesy.models.user import User
from football_prophesy.models.player import Player
from football_prophesy.models.prediction import Prediction
from football_prophesy.models.comment import Comment
from football_prophesy.models.score import Score
from football_prophesy.extensions import db

from football_prophesy.data.draft_profiles import PLAYERS_DATA



# Blueprint
draft_bp = Blueprint("draft", __name__, url_prefix="/draft")


# =========================
# Draft page
# =========================
@draft_bp.route("/")
@login_required
def draft():
    # Get user
    user = current_user

    # Get previous predictions first
    previous_preds = Prediction.query.filter_by(
        user_id=user.id,
        year=2026,
        section="draft"
    ).all()

    previous_predictions = { 
        pred.draft_position_group: pred.player_id
        for pred in previous_preds
    }

    # Get players from db
    db_players = Player.query.all()
    players_by_name = {p.name: p for p in db_players}

    # ✅ merge DB + static data safely
    players = {
        position: [
            {
                "id": players_by_name[p["name"]].id if p["name"] in players_by_name else None,
                "name": p["name"],
                "grade": p["grade"],
                "projection": p["projection"]
            }
            for p in position_players
        ]
        for position, position_players in PLAYERS_DATA.items()
    }

    # Actual pick data
    actual_picks = {
        player.id: player.actual_pick
        for player in db_players
    }

    # Calculate total for only the players the user picked
    current_score = sum(
        actual_picks.get(player_id) or 0
        for player_id in previous_predictions.values()
    )

    # Comments 
    pages = ["draft"]
    comments = Comment.query.filter(Comment.page.in_(pages)).order_by(Comment.timestamp.desc()).all()

    # Leaderboard
    draft_leaderboard = Score.section_leaderboard(section="draft", limit=10)

    return render_template(
        "draft.html",
        user=user,
        page_title="Draft",
        css_file="css/draft.css",
        scoreboard_id="scoreboard",
        leaderboard=draft_leaderboard,
        results_url=url_for('account.user_draft_results', user_id=user.id),
        prediction_title="2026 Draft Predictions",
        instructions="Prophesy which player at each position will be drafted first",
        form_action=url_for('draft.submit_draft'),
        submit_text="Submit/Change Predictions",
        page_name="draft",
        comments=comments,
        players=players,
        db_players=db_players,
        previous_predictions=previous_predictions,
        current_score=current_score,
        actual_picks=actual_picks
    )


# =========================
# Submit draft page
# =========================
@draft_bp.route("/submit_draft", methods=["POST"])
@login_required
def submit_draft():
    # Get player data
    data = request.get_json(silent=True) or {}
    
    DRAFT_DEADLINE = datetime(2026, 4, 23, 20, 0, tzinfo=ZoneInfo("America/New_York"))

    now = datetime.now(ZoneInfo("America/New_York"))

    if now >= DRAFT_DEADLINE:
        return jsonify({
            "status": "error",
            "message": "Draft submissions are closed."
        }), 403
    
    # Get current user
    user = current_user

    # All positions are required
    required_positions = list(PLAYERS_DATA.keys())

    # Check for missing selections
    missing_positions = [pos for pos in required_positions if pos not in data]
    if missing_positions:
        return jsonify({
            "status": "error",
            "message": f"Please select a player for all positions. Missing: {', '.join(missing_positions)}"
        }), 400

    # Get existing predictions
    for position, player_id in data.items():
        try:
            player_id = int(player_id)
        except (ValueError, TypeError):
            continue  # or return an error

        pred = Prediction.query.filter_by(
            user_id=user.id,
            year=2026,
            section="draft",
            draft_position_group=position
        ).first()

        if pred:
            pred.player_id = player_id
        else:
            pred = Prediction(
                user_id=user.id,
                year=2026,
                section="draft",
                draft_position_group=position,
                player_id=player_id
            )
            db.session.add(pred)

    db.session.commit()
    return jsonify({
        "status": "ok",
        "message": "Predictions submitted successfully!"
    })

# =========================
# Update draft page
# =========================
@draft_bp.route("/update_draft", methods=["GET", "POST"])
@login_required
@admin_required
def update_draft():

    # 1) Map static draft list to DB players
    db_players = Player.query.all()
    players_by_name = {p.name: p for p in db_players}

    all_players = []

    for position, position_players in PLAYERS_DATA.items():
        for p in position_players:

            db_player = players_by_name.get(p["name"])
            if not db_player:
                continue

            all_players.append(db_player)  # keep ORM objects

    # =========================
    # POST
    # =========================
    if request.method == "POST":

        for player in all_players:

            field_name = f"actual_pick_{player.id}"
            submitted_value = request.form.get(field_name)

            try:
                new_value = int(submitted_value) if submitted_value else None
            except ValueError:
                new_value = None

            player.actual_pick = new_value

        db.session.commit()
        return redirect(url_for("draft.update_draft"))

    # =========================
    # GET
    # =========================
    actual_picks = {
        player.id: player.actual_pick
        for player in all_players
    }

    return render_template(
        "update_draft.html",
        all_players=all_players,
        actual_picks=actual_picks,
        page_title="Update Draft",
        css_file="css/update_draft.css",
        submit_text="Submit",
        page_name="draft",
    )