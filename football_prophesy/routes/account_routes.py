from flask import Blueprint, render_template, flash, redirect, url_for
from models import User, Prediction
from services.scoring import total_points, rank
from services.auth import login_required

from data.free_agency_players import FREE_AGENCY_PLAYERS
from data.free_agency_results import FREE_AGENCY_RESULTS
from data.combine_map import POSITION_DRILL_MAP
from data.combine_results import ACTUAL_COMBINE_RESULTS
from data.scouting_combine_participants import SCOUTING_COMBINE_PLAYERS


# Blueprint
account_bp = Blueprint("account", __name__)


# -------------------------
# ACCOUNT PAGE
# -------------------------
@account_bp.route("/account/<int:user_id>")
@login_required
def account(user_id):

    profile_user = User.query.get_or_404(user_id)

    total = total_points(profile_user)
    user_rank = rank(profile_user, User.query.all())

    comments = profile_user.comments

    return render_template(
        "account.html",
        profile_user=profile_user,
        total_points=total,
        rank=user_rank,
        comments=comments
    )


# -------------------------
# ALL ACCOUNTS
# -------------------------
@account_bp.route("/all_accounts")
@login_required
def all_accounts():

    users = User.query.all()

    users_sorted = sorted(
        [(u, total_points(u)) for u in users],
        key=lambda x: x[1],
        reverse=True
    )

    return render_template("all_accounts.html", users_sorted=users_sorted)


# -------------------------
# SCOUTING COMBINE REVIEW
# -------------------------
@account_bp.route("/account/<int:user_id>/scouting_combine")
@login_required
def user_combine_results(user_id):

    user = User.query.get_or_404(user_id)

    predictions = [
        p for p in user.predictions
        if p.section == "scouting_combine" and p.year == 2026
    ]

    predictions_dict = {
        f"{p.position_group}_{p.drill}_{p.place}": p.player_name
        for p in predictions
    }

    feedback = {
        f"{p.position_group}_{p.drill}_{p.place}":
        p.calculate_points(ACTUAL_COMBINE_RESULTS, POSITION_DRILL_MAP)
        for p in predictions
    }

    return render_template(
        "scouting_combine_review.html",
        user=user,
        profile_user=user,
        predictions_dict=predictions_dict,
        feedback=feedback,
        players=SCOUTING_COMBINE_PLAYERS,
        actual_combine_results=ACTUAL_COMBINE_RESULTS,
        position_drill_map=POSITION_DRILL_MAP,
        event_name="Scouting Combine"
    )


# -------------------------
# FREE AGENCY REVIEW
# -------------------------
@account_bp.route("/account/<int:user_id>/free_agency")
@login_required
def free_agency_review(user_id):

    user = User.query.get_or_404(user_id)

    predictions = Prediction.query.filter_by(
        user_id=user.id,
        section="free_agency",
        year=2026
    ).all()

    user_predictions = {
        player: {"team": None, "salary": None}
        for player in FREE_AGENCY_PLAYERS
    }

    for p in predictions:

        name = p.player_name

        if name in user_predictions:

            if p.team_prediction:
                user_predictions[name]["team"] = p.team_prediction

            if p.salary_prediction:
                user_predictions[name]["salary"] = p.salary_prediction


    points_feedback = {}

    for player in FREE_AGENCY_PLAYERS:

        pred = user_predictions.get(player, {"team": None, "salary": None})
        actual = FREE_AGENCY_RESULTS.get(player, {"team": None, "salary": None})

        team_pred = pred["team"] or "—"
        team_actual = actual.get("team") or "—"

        salary_pred = pred["salary"] or "—"
        salary_actual = actual.get("salary") or "—"

        points_feedback[player] = {
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
        players=FREE_AGENCY_PLAYERS,
        points_feedback=points_feedback,
        no_predictions=not bool(predictions)
    )


# -------------------------
# NOT IMPLEMENTED PAGES
# -------------------------
@account_bp.route("/account/<int:user_id>/draft")
@login_required
def user_draft_results(user_id):

    user = User.query.get_or_404(user_id)

    flash("Draft results are not implemented yet.", "info")

    return redirect(url_for("account.account", user_id=user.id))


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