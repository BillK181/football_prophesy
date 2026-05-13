from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required, current_user
from datetime import datetime

from football_prophesy.models.prediction import Prediction
from football_prophesy.models.comment import Comment
from football_prophesy.models.score import Score
from football_prophesy.extensions import db

from football_prophesy.data.combine_map import POSITION_DRILL_MAP
from football_prophesy.data.scouting_combine_participants import SCOUTING_COMBINE_PLAYERS
from football_prophesy.services.scoring import recalc_schedule_release_scores
from football_prophesy.decorators import admin_required
from football_prophesy.services.email_service import send_schedule_release_email_to_all_users


schedule_bp = Blueprint("schedule", __name__, url_prefix="/schedule-release")


# =========================
# HELPERS
# =========================
def safe_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


# =========================
# SCHEDULE RELEASE PAGE
# =========================
@schedule_bp.route("/")
@login_required
def schedule_release():

    user = current_user

    previous_preds = Prediction.query.filter_by(
        user_id=user.id,
        year=2026,
        section="schedule_release"
    ).first()

    prev_dict = previous_preds.schedule_preds if previous_preds else {}

    SYSTEM_USER_ID = 0

    correct = Prediction.query.filter_by(
        user_id=SYSTEM_USER_ID,
        section="schedule_release",
        year=2026
    ).first()

    correct_dict = (
        correct.correct_schedule_preds
        if correct and correct.correct_schedule_preds
        else {}
    )

    pages = ["schedule release", "schedule_release"]
    comments = Comment.query.filter(
        Comment.page.in_(pages)
    ).order_by(Comment.timestamp.desc()).all()

    schedule_leaderboard = Score.section_leaderboard(
        section="schedule_release",
        limit=10
    )

    return render_template(
        "schedule_release.html",
        user=user,
        is_admin=current_user.is_admin,
        page_title="Schedule Release",
        css_file="css/schedule_release.css",
        scoreboard_id="scoreboard",
        leaderboard=schedule_leaderboard,
        results_url=url_for('account.user_schedule_release_results', user_id=user.id),
        prediction_title="2026 Schedule Release Predictions",
        submission_deadline="Submissions Lock 5/13 at 11pm PST",
        instructions="Predict Primetime Games",
        submit_text="Submit Predictions",
        page_name="schedule_release",
        comments=comments,
        form_action=url_for('schedule.submit_schedule'),
        players=SCOUTING_COMBINE_PLAYERS,
        previous_predictions=prev_dict,
        correct_answers=correct_dict,
        position_drill_map=POSITION_DRILL_MAP
    )


# =========================
# SUBMIT SCHEDULE
# =========================
@schedule_bp.route("/submit", methods=["POST"])
@login_required
def submit_schedule():

    schedule_deadline = datetime(2026, 5, 13, 23, 0)

    if datetime.utcnow() > schedule_deadline:
        flash("Schedule Release predictions are now closed.", "danger")
        return redirect(url_for("schedule.schedule_release"))

    fields = [
        "patriots_snf",
        "niners_snf",
        "steelers_snf",
        "chargers_snf",
        "chiefs_snf",
        "bears_snf",
        "lions_thg"
    ]

    schedule_preds = {
        field: safe_int(request.form.get(field))
        for field in fields
    }

    existing = Prediction.query.filter_by(
        user_id=current_user.id,
        year=2026,
        section="schedule_release"
    ).first()

    if existing:
        existing.schedule_preds = schedule_preds
    else:
        db.session.add(Prediction(
            user_id=current_user.id,
            year=2026,
            section="schedule_release",
            schedule_preds=schedule_preds
        ))

    db.session.commit()

    flash("Predictions submitted successfully!", "success")
    return redirect(url_for("schedule.schedule_release"))


# =========================
# ADMIN PAGE
# =========================
@schedule_bp.route("/admin", methods=["GET"])
@login_required
@admin_required
def update_schedule_page():
    return render_template("update_schedule.html", is_admin=True)


# =========================
# UPDATE SCHEDULE
# =========================
@schedule_bp.route("/update_schedule", methods=["POST"])
@login_required
@admin_required
def update_schedule():

    fields = [
        "patriots_snf",
        "niners_snf",
        "steelers_snf",
        "chargers_snf",
        "chiefs_snf",
        "bears_snf",
        "lions_thg"
    ]

    # Build correct answers safely
    def parse_nullable_int(value):
        if value is None:
            return None
        if value == "" or value == "none":
            return None
        try:
            return int(value)
        except ValueError:
            return None


    answers = {
        field: parse_nullable_int(request.form.get(f"{field}_correct"))
        for field in fields
    }

    SYSTEM_USER_ID = 0

    correct = Prediction.query.filter_by(
        user_id=SYSTEM_USER_ID,
        section="schedule_release",
        year=2026
    ).first()

    if not correct:
        correct = Prediction(
            user_id=SYSTEM_USER_ID,
            section="schedule_release",
            year=2026,
            schedule_preds={},
            correct_schedule_preds=answers
        )
        db.session.add(correct)
    else:
        correct.correct_schedule_preds = answers

    db.session.commit()

    # Recalculate leaderboard after update
    recalc_schedule_release_scores(year=2026)

    flash("Correct answers updated + scores recalculated", "success")

    return redirect(url_for("schedule.schedule_release"))


# =========================
# SEND SCHEDULE EMAILS
# =========================
@schedule_bp.route("/send_schedule_emails", methods=["POST"])
@login_required
@admin_required
def send_schedule_emails():

    send_schedule_release_email_to_all_users()

    flash("Schedule Release emails sent to all users!", "success")
    return redirect(url_for("schedule.update_schedule_page"))