from flask import Blueprint, render_template, flash, redirect, url_for
from flask_login import login_required, current_user
from football_prophesy.models import User, Prediction, Score
from datetime import datetime, timezone

from football_prophesy.data.free_agency_players import FREE_AGENCY_PLAYERS
from football_prophesy.data.free_agency_results import FREE_AGENCY_RESULTS
from football_prophesy.data.combine_map import POSITION_DRILL_MAP
from football_prophesy.data.combine_results import ACTUAL_COMBINE_RESULTS
from football_prophesy.data.scouting_combine_participants import SCOUTING_COMBINE_PLAYERS


# Blueprint
account_bp = Blueprint("account", __name__)


# -------------------------
# ACCOUNT PAGE
# -------------------------
@account_bp.route("/account/<int:user_id>")
@login_required
def account(user_id):
    # - Displays the main account page for a given user
    # - Requires login

    # Fetch user by ID, 404 if not found
    user = current_user

    score = Score.query.filter_by(
        user_id=user.id,
        year=2026
    ).first()

    total = score.total_points if score else 0
    rank = score.rank if score else None

    # Fetch scores per section
    combine_score = Score.query.filter_by(user_id=user.id, year=2026, section="scouting_combine").first()
    combine_points = combine_score.points if combine_score else 0

    free_agency_score = Score.query.filter_by(user_id=user.id, year=2026, section="free_agency").first()
    free_agency_points = free_agency_score.points if free_agency_score else 0

    draft_score = Score.query.filter_by(user_id=user.id, year=2026, section="draft").first()
    draft_points = draft_score.points if draft_score else 0

    # Fetch user's comments for display
    comments = user.comments

    # Render the template with all relevant user info
    return render_template(
        "account.html",
        user=user,
        total=total,
        rank=rank,
        comments=comments,
        combine_points=combine_points,
        free_agency_points=free_agency_points,
        draft_points=draft_points
    )


# -------------------------
# ALL ACCOUNTS
# -------------------------
@account_bp.route("/all_accounts")
@login_required
def all_accounts():
    
    user = current_user if current_user.is_authenticated else None

    # Calculates leaderboards:
    top_players = Score.section_leaderboard()
    
    return render_template("all_accounts.html", leaderboard=top_players, user=user)


# -------------------------
# SCOUTING COMBINE REVIEW
# -------------------------
@account_bp.route("/account/<int:user_id>/scouting_combine")
@login_required
def user_combine_results(user_id):

    user = User.query.get_or_404(user_id)

    flash("Scouting Combine Results are Under Maintenance.", "info")

    return redirect(url_for("account.account", user_id=user.id))

    # - Review page showing a user's scouting combine predictions vs actual results
    user = User.query.get_or_404(user_id)

    # Filter predictions to only scouting_combine and 2026
    predictions = [
        p for p in user.predictions
        if p.section == "scouting_combine" and p.year == 2026
    ]

    # Dictionary of user's predictions for quick lookup in template
    predictions_dict = {
        f"{p.position_group}_{p.drill}_{p.place}": p.player_name
        for p in predictions
    }

    # Calculate points for each prediction
    feedback = {
        f"{p.position_group}_{p.drill}_{p.place}":
        p.calculate_points(ACTUAL_COMBINE_RESULTS, POSITION_DRILL_MAP)
        for p in predictions
    }

    # Render template with predictions and calculated points
    return render_template(
        "scouting_combine_review.html",
        user=user,
        predictions_dict=predictions_dict,
        feedback=feedback,
        players=SCOUTING_COMBINE_PLAYERS,
        actual_combine_results=ACTUAL_COMBINE_RESULTS,
        position_drill_map=POSITION_DRILL_MAP,
        page_title="Scouting Combine Results",
        css_file="css/scouting_combine.css",
        container_class="combine-container",
        header_title="2026 Scouting Combine Results",
        subtext="Review the predictions. Correct picks show points, incorrect show ❌."
    )


# -------------------------
# FREE AGENCY REVIEW
# -------------------------
@account_bp.route("/account/<int:user_id>/free_agency")
@login_required
def free_agency_review(user_id):

    user = User.query.get_or_404(user_id)

    predictions = (
        Prediction.query
        .filter_by(
            user_id=user.id,
            section="free_agency",
            year=2026
        )
        .order_by(Prediction.id)
        .all()
    )

    # convert dict → ordered list
    actual_list = [
        {"player_name": name, **data}
        for name, data in FREE_AGENCY_RESULTS.items()
    ]

    points_feedback = {}

    for idx, p in enumerate(predictions):

        if idx >= len(actual_list):
            break

        actual = actual_list[idx]

        team_pred = p.team_prediction or "—"
        salary_pred = p.salary_prediction or "—"

        team_actual = actual["team"] or "—"
        salary_actual = actual["salary"] or "—"

        points_feedback[p.id] = {
            "player_name": actual["player_name"],
            "team": {
                "predicted": team_pred,
                "actual": team_actual,
                "points": 5 if team_pred == team_actual else 0
            },
            "salary": {
                "predicted": salary_pred,
                "actual": salary_actual,
                "points": 5 if salary_pred == salary_actual else 0
            }
        }

    return render_template(
        "free_agency_review.html",
        user=user,
        predictions=predictions,
        points_feedback=points_feedback,
        no_predictions=not bool(predictions),
        page_title="Free Agency Review",
        css_file="css/free_agency.css",
        container_class="free-agency-container",
        header_title="2026 Free Agency Review",
        subtext="See your predictions and points earned"
    )

# -------------------------
# DRAFT REVIEW
# -------------------------
@account_bp.route("/account/<int:user_id>/draft")
@login_required
def user_draft_results(user_id):
    user = current_user

    LOCK_TIME_UTC = datetime(2026, 4, 24, 0, 0, 0, tzinfo=timezone.utc)

    now = datetime.now(timezone.utc)

    if now < LOCK_TIME_UTC and not user.is_admin:
        flash("Draft review is locked until April 23rd at 5PM PST.", "warning")
        return redirect(url_for("account.account", user_id=user_id))

    users = User.query.all()

    draft_data = []

    for user in users:

        # get all draft predictions for this user
        predictions = (
            Prediction.query
            .filter_by(user_id=user.id, section="draft")
            .join(Prediction.player)
            .all()
        )

        # --- compute draft points ---
        # ✅ GET REAL DRAFT POINTS FROM SCORE TABLE
        score = Score.query.filter_by(
            user_id=user.id,
            year=2026,
            section="draft"
        ).first()

        points = score.points if score else 0

        draft_data.append({
            "user": user,
            "points": points,
            "picks": sorted(
                predictions,
                key=lambda x: (x.player.actual_pick if x.player and x.player.actual_pick is not None else 999)
            )
        })

    # sort leaderboard
    draft_data.sort(key=lambda x: x["points"], reverse=True)

    return render_template(
        "draft_review.html",
        draft_data=draft_data
    )

# -------------------------
# NOT IMPLEMENTED PAGES
# -------------------------
# - These routes are placeholders for future features.
# - Each flashes a message and redirects back to main account page.


@account_bp.route("/account/<int:user_id>/schedule_release")
@login_required
def user_schedule_release_results(user_id):

    user = User.query.get_or_404(user_id)

    flash("Schedule Release results are not implemented yet.", "info")

    return redirect(url_for("account.account", user_id=user.id))


@account_bp.route("/account/<int:user_id>/preseason")
@login_required
def user_preseason_results(user_id):

    user = User.query.get_or_404(user_id)

    flash("Preseason results are not implemented yet.", "info")

    return redirect(url_for("account.account", user_id=user.id))


@account_bp.route("/account/<int:user_id>/season_predictions")
@login_required
def user_season_predictions_results(user_id):

    user = User.query.get_or_404(user_id)

    flash("Season Predictions results are not implemented yet.", "info")

    return redirect(url_for("account.account", user_id=user.id))


@account_bp.route("/account/<int:user_id>/season_picks")
@login_required
def user_season_picks_results(user_id):

    user = User.query.get_or_404(user_id)

    flash("Season Picks results are not implemented yet.", "info")

    return redirect(url_for("account.account", user_id=user.id))


@account_bp.route("/account/<int:user_id>/postseason_predictions")
@login_required
def user_postseason_predictions_results(user_id):

    user = User.query.get_or_404(user_id)

    flash("Postseason Predictions results are not implemented yet.", "info")

    return redirect(url_for("account.account", user_id=user.id))


@account_bp.route("/account/<int:user_id>/postseason_picks")
@login_required
def user_postseason_picks_results(user_id):

    user = User.query.get_or_404(user_id)

    flash("Postseason Picks results are not implemented yet.", "info")

    return redirect(url_for("account.account", user_id=user.id))