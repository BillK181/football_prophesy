from flask import Blueprint, render_template, request, flash, redirect, url_for, jsonify
from flask_login import login_required, current_user
from datetime import datetime
from zoneinfo import ZoneInfo
from flask_mail import Message
import traceback

from football_prophesy.extensions import mail, db
from football_prophesy.decorators import admin_required

from football_prophesy.models.user import User
from football_prophesy.models.player import Player
from football_prophesy.models.prediction import Prediction
from football_prophesy.models.comment import Comment
from football_prophesy.models.score import Score

from football_prophesy.data.draft_profiles import PLAYERS_DATA


# =========================
# Blueprint
# =========================
draft_bp = Blueprint("draft", __name__, url_prefix="/draft")


# =========================
# SEED FUNCTION (REAL LOGIC)
# =========================
def seed_draft_players():
    existing_players = {
        p.name.strip().lower(): p
        for p in Player.query.all()
    }

    added = 0
    skipped = 0

    for _, players_list in PLAYERS_DATA.items():
        for p in players_list:

            name_key = p["name"].strip().lower()

            if name_key in existing_players:
                skipped += 1
                continue

            db.session.add(Player(
                name=p["name"].strip(),
                actual_pick=None
            ))

            added += 1

    db.session.commit()
    return added, skipped


# =========================
# Draft page
# =========================
@draft_bp.route("/")
@login_required
def draft():

    user = current_user

    previous_preds = Prediction.query.filter_by(
        user_id=user.id,
        year=2026,
        section="draft"
    ).all()

    previous_predictions = {
        pred.draft_position_group: pred.player_id
        for pred in previous_preds
    }

    db_players = Player.query.all()
    players_by_name = {p.name: p for p in db_players}

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

    actual_picks = {p.id: p.actual_pick for p in db_players}

    current_score = sum(
        actual_picks.get(pid) or 0
        for pid in previous_predictions.values()
    )

    comments = Comment.query.order_by(Comment.timestamp.desc()).all()
    draft_leaderboard = Score.section_leaderboard(section="draft", limit=10)

    return render_template(
        "draft.html",
        user=user,
        page_title="Draft",
        players=players,
        db_players=db_players,
        previous_predictions=previous_predictions,
        current_score=current_score,
        actual_picks=actual_picks,
        comments=comments,
        leaderboard=draft_leaderboard,
        form_action=url_for('draft.submit_draft')
    )


# =========================
# SUBMIT DRAFT
# =========================
@draft_bp.route("/submit_draft", methods=["POST"])
@login_required
def submit_draft():

    data = request.get_json(silent=True) or {}

    DEADLINE = datetime(2026, 4, 23, 20, 0, tzinfo=ZoneInfo("America/New_York"))
    now = datetime.now(ZoneInfo("America/New_York"))

    if now >= DEADLINE:
        return jsonify({"status": "error", "message": "Closed"}), 403

    user = current_user

    for position, player_id in data.items():

        try:
            player_id = int(player_id)
        except:
            continue

        pred = Prediction.query.filter_by(
            user_id=user.id,
            year=2026,
            section="draft",
            draft_position_group=position
        ).first()

        if pred:
            pred.player_id = player_id
        else:
            db.session.add(Prediction(
                user_id=user.id,
                year=2026,
                section="draft",
                draft_position_group=position,
                player_id=player_id
            ))

    db.session.commit()

    return jsonify({"status": "ok"})


# =========================
# UPDATE DRAFT (ADMIN)
# =========================
@draft_bp.route("/update_draft", methods=["GET", "POST"])
@login_required
@admin_required
def update_draft():

    db_players = Player.query.all()

    all_players = []

    for _, players_list in PLAYERS_DATA.items():
        for p in players_list:
            match = next((dbp for dbp in db_players if dbp.name == p["name"]), None)
            if match:
                all_players.append(match)

    if request.method == "POST":

        for player in all_players:
            value = request.form.get(f"actual_pick_{player.id}")

            try:
                player.actual_pick = int(value) if value else None
            except:
                player.actual_pick = None

        db.session.commit()
        return redirect(url_for("draft.update_draft"))

    return render_template(
        "update_draft.html",
        all_players=all_players
    )


# =========================
# SEED ROUTE (NOW CLEAN)
# =========================
@draft_bp.route("/seed_players", methods=["POST"])
@login_required
@admin_required
def seed_players():

    added, skipped = seed_draft_players()

    flash(f"Seed complete → Added: {added}, Skipped: {skipped}", "success")
    return redirect(url_for("draft.update_draft"))


# =========================
# EMAIL ROUTE
# =========================
@draft_bp.route("/send_draft_emails", methods=["POST"])
@login_required
@admin_required
def send_draft_emails():

    users = User.query.all()

    sent = 0
    failed = 0

    for u in users:

        if not u.email:
            continue

        try:
            msg = Message(
                subject="Draft Prophesy Now Available 🏈",
                sender="ThrillBill@footballprophesy.com",
                recipients=[u.email]
            )

            msg.body = f"""Hi {u.name},

The Draft Prophesy is now available!

https://footballprophesy.com/draft
"""

            mail.send(msg)
            sent += 1

        except Exception as e:
            print(f"[EMAIL ERROR] {u.email}: {e}")
            traceback.print_exc()
            failed += 1

    flash(f"Emails sent → {sent} success, {failed} failed", "success")
    return redirect(url_for("draft.update_draft"))