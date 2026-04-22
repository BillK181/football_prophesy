from football_prophesy.models.user import User
from football_prophesy.models.prediction import Prediction
from football_prophesy.models.score import Score
from football_prophesy.models.player import Player

from football_prophesy.extensions import db


# =========================================================
# MAIN RECALC FUNCTION (ONLY DRAFT IS ACTIVE)
# =========================================================
def recalc_scores(year=2026):

    users = User.query.all()
    sections = ["free_agency", "scouting_combine", "draft"]

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
                db.session.add(Score(
                    user_id=user.id,
                    section=section,
                    year=year
                ))

    db.session.commit()

    # ------------------------
    # ONLY UPDATE DRAFT SCORES
    # ------------------------
    draft_scores = Score.query.filter_by(
        year=year,
        section="draft"
    ).all()

    for score in draft_scores:
        score.points = calculate_draft_score(score.user_id, year)

    db.session.commit()

    # ------------------------
    # DO NOT TOUCH FREE AGENCY OR COMBINE
    # (they remain frozen forever)
    # ------------------------

    # ------------------------
    # UPDATE TOTAL POINTS (USES FROZEN VALUES)
    # ------------------------
    for user in users:
        scores = Score.query.filter_by(
            user_id=user.id,
            year=year
        ).all()

        total = sum(s.points for s in scores)

        for s in scores:
            s.total_points = total

    db.session.commit()

    # ------------------------
    # UPDATE RANKS
    # ------------------------
    Score.update_ranks(users, section=None, year=year)
    Score.update_ranks(users, section="draft", year=year)

    db.session.commit()


# =========================================================
# DRAFT SCORING ONLY
# =========================================================
def calculate_draft_score(user_id, year=2026):

    user = User.query.get(user_id)
    if not user:
        return 0

    previous_preds = Prediction.query.filter_by(
        user_id=user_id,
        year=year,
        section="draft"
    ).all()

    # no predictions = 0 points
    if not previous_preds:
        return 0

    previous_predictions = {
        pred.draft_position_group: pred.player_id
        for pred in previous_preds
    }

    db_players = Player.query.all()

    actual_picks = {
        player.id: player.actual_pick
        for player in db_players
    }

    current_score = sum(
        actual_picks.get(pid) or 0
        for pid in previous_predictions.values()
    )

    return 1000 - current_score


# =========================================================
# OPTIONAL: DRAFT-ONLY RECALC (USE IN ADMIN ROUTE)
# =========================================================
def recalc_draft_scores(year=2026):

    users = User.query.all()

    # Ensure draft score rows exist
    for user in users:
        score = Score.query.filter_by(
            user_id=user.id,
            section="draft",
            year=year
        ).first()

        if not score:
            db.session.add(Score(
                user_id=user.id,
                section="draft",
                year=year
            ))

    db.session.commit()

    # Recalculate ONLY draft
    draft_scores = Score.query.filter_by(
        year=year,
        section="draft"
    ).all()

    for score in draft_scores:
        score.points = calculate_draft_score(score.user_id, year)

    db.session.commit()

    # Update draft ranks only
    Score.update_ranks(users, section="draft", year=year)

    db.session.commit()