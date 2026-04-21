from football_prophesy.models.user import User
from football_prophesy.models.prediction import Prediction
from football_prophesy.models.score import Score

from football_prophesy.data.combine_results import ACTUAL_COMBINE_RESULTS
from football_prophesy.data.combine_map import POSITION_DRILL_MAP
from football_prophesy.data.free_agency_results import FREE_AGENCY_RESULTS

from extensions import db


# =========================================================
# MAIN RECALC FUNCTION (ALL SECTIONS)
# =========================================================
def recalc_scores(year=2026, actual_picks=None):
    """
    Recalculates ALL scores:
    - scouting combine
    - free agency
    - draft
    """

    sections = ["free_agency", "scouting_combine", "draft"]
    users = User.query.all()

    # ------------------------
    # Ensure Score rows exist
    # ------------------------
    for user in users:
        for section in sections:
            score_row = Score.query.filter_by(
                user_id=user.id,
                section=section,
                year=year
            ).first()

            if not score_row:
                score_row = Score(
                    user_id=user.id,
                    section=section,
                    year=year
                )
                db.session.add(score_row)

    db.session.commit()

    # ------------------------
    # Update section points
    # ------------------------
    score_rows = Score.query.filter_by(year=year).all()

    for score in score_rows:

        # --------------------
        # DRAFT SECTION
        # --------------------
        if score.section == "draft":
            raw = calculate_raw_draft_score(
                user_id=score.user_id,
                actual_picks=actual_picks or {}
            )

            score.points = convert_draft_score(raw)

        # --------------------
        # OTHER SECTIONS
        # --------------------
        else:
            score.update_points(
                combine_results=ACTUAL_COMBINE_RESULTS,
                free_agency_results=FREE_AGENCY_RESULTS,
                position_drill_map=POSITION_DRILL_MAP
            )

        db.session.add(score)

    db.session.commit()

    # ------------------------
    # Update ranks
    # ------------------------
    Score.update_ranks(users, section=None, year=year)

    for section in sections:
        Score.update_ranks(users, section=section, year=year)

    db.session.commit()


# =========================================================
# DRAFT SCORING HELPERS
# =========================================================
def calculate_raw_draft_score(user_id, actual_picks):
    """
    Sums draft pick values for a user's predictions.
    Lower is better.
    """

    preds = Prediction.query.filter_by(
        user_id=user_id,
        year=2026,
        section="draft"
    ).all()

    return sum(
        actual_picks.get(p.player_id, 300)
        for p in preds
    )


def convert_draft_score(raw_score):
    """
    Converts raw draft score → tiered points.
    """

    if raw_score <= 400:
        return 100
    elif raw_score <= 500:
        return 90
    elif raw_score <= 550:
        return 75
    elif raw_score <= 600:
        return 50
    elif raw_score <= 650:
        return 25
    elif raw_score <= 700:
        return 10
    else:
        return 0