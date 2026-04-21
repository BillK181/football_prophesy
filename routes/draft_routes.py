from flask import Blueprint, render_template, request, flash, redirect, url_for, jsonify
from flask_login import login_required, current_user
from datetime import datetime
from zoneinfo import ZoneInfo
import traceback

from football_prophesy.decorators import admin_required
from football_prophesy.models.user import User
from football_prophesy.models.player import Player
from football_prophesy.models.prediction import Prediction
from football_prophesy.models.comment import Comment
from football_prophesy.models.score import Score
from football_prophesy.extensions import db, mail
from football_prophesy.data.draft_profiles import PLAYERS_DATA

from flask_mail import Message


# Blueprint
draft_bp = Blueprint("draft", __name__, url_prefix="/draft")


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

    comments = Comment.query.filter(Comment.page == "draft").order_by(Comment.timestamp.desc()).all()

    draft_leaderboard = Score.section_leaderboard(section="draft", limit=10)

    return render_template(
        "draft.html",
        user=user,
        players=players,
        db_players=db_players,
        previous_predictions=previous_predictions,
        actual_picks=actual_picks,
        current_score=current_score,
        comments=comments,
        leaderboard=draft_leaderboard,
        page_name="draft"
    )


# =========================
# UPDATE DRAFT
# =========================
@draft_bp.route("/update_draft", methods=["GET", "POST"])
@login_required
@admin_required
def update_draft():

    db_players = Player.query.all()
    players_by_name = {p.name: p for p in db_players}

    all_players = []

    for _, position_players in PLAYERS_DATA.items():
        for p in position_players:
            db_player = players_by_name.get(p["name"])
            if db_player:
                all_players.append(db_player)

    if request.method == "POST":

        for player in all_players:
            field = f"actual_pick_{player.id}"
            value = request.form.get(field)

            try:
                player.actual_pick = int(value) if value else None
            except ValueError:
                player.actual_pick = None

        db.session.commit()
        flash("Draft updated successfully", "success")
        return redirect(url_for("draft.update_draft"))

    actual_picks = {p.id: p.actual_pick for p in all_players}

    return render_template(
        "update_draft.html",
        all_players=all_players,
        actual_picks=actual_picks
    )


# =========================
# SEED PLAYERS (FIXED INLINE)
# =========================
@draft_bp.route("/seed_players", methods=["POST"])
@login_required
@admin_required
def seed_players():

    db_players = Player.query.all()
    existing = {p.name.strip().lower() for p in db_players}

    added = 0
    skipped = 0

    for _, players_list in PLAYERS_DATA.items():
        for p in players_list:

            key = p["name"].strip().lower()

            if key in existing:
                skipped += 1
                continue

            db.session.add(Player(
                name=p["name"].strip(),
                actual_pick=None
            ))

            added += 1

    db.session.commit()

    flash(f"Seed complete → Added: {added}, Skipped: {skipped}", "success")
    return redirect(url_for("draft.update_draft"))


# =========================
# SEND EMAILS (FIXED INLINE)
# =========================
@draft_bp.route("/send_draft_emails", methods=["POST"])
@login_required
@admin_required
def send_draft_emails():

    users = User.query.all()

    sent = 0
    failed = 0

    for user in users:

        if not user.email:
            continue

        try:
            msg = Message(
                subject="Draft Prophesy Now Available 🏈",
                sender="your_email@example.com",
                recipients=[user.email]
            )

            msg.body = f"""Hi {user.name},

The Draft Prophesy is now available!

https://footballprophesy.com/draft
"""

            mail.send(msg)
            sent += 1

        except Exception as e:
            print(f"[ERROR] Email failed for {user.email}: {e}")
            traceback.print_exc()
            failed += 1

    flash(f"Emails sent → {sent} success, {failed} failed", "success")
    return redirect(url_for("draft.update_draft"))