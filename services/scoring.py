from football_prophesy.models.user import User
from football_prophesy.models.prediction import Prediction
from football_prophesy.models.score import Score
from football_prophesy.models.player import Player

from football_prophesy.extensions import db


SYSTEM_USER_ID = 0


# =========================================================
# MASTER RECALC FUNCTION
# =========================================================
def recalc_scores(year=2026):

    users = User.query.all()

    sections = [
        "free_agency",
        "scouting_combine",
        "draft",
        "schedule_release",
        "preseason"
    ]

    ensure_score_rows(users, sections, year)


    # Individual event scoring
    recalc_schedule_release_scores(year)
    recalc_preseason_scores(year)

    # Add these when ready
    # recalc_free_agency_scores(year)
    # recalc_combine_scores(year)
    # recalc_draft_scores(year)


    update_total_points(year)

    update_all_ranks(users, year)


# =========================================================
# CREATE MISSING SCORE ROWS
# =========================================================
def ensure_score_rows(users, sections, year):

    for user in users:

        for section in sections:

            existing = Score.query.filter_by(
                user_id=user.id,
                section=section,
                year=year
            ).first()

            if not existing:
                db.session.add(
                    Score(
                        user_id=user.id,
                        section=section,
                        year=year
                    )
                )

    db.session.commit()



# =========================================================
# DRAFT SCORING
# =========================================================
def recalc_draft_scores(year=2026):

    scores = Score.query.filter_by(
        year=year,
        section="draft"
    ).all()


    for score in scores:

        score.points = calculate_draft_score(
            score.user_id,
            year
        )

    db.session.commit()



def calculate_draft_score(user_id, year):

    predictions = Prediction.query.filter_by(
        user_id=user_id,
        year=year,
        section="draft"
    ).all()


    if not predictions:
        return 0


    player_ids = [
        prediction.player_id
        for prediction in predictions
    ]


    players = Player.query.filter(
        Player.id.in_(player_ids)
    ).all()


    total_pick_value = sum(
        player.actual_pick or 0
        for player in players
    )


    return 1000 - total_pick_value



# =========================================================
# SCHEDULE RELEASE SCORING
# =========================================================
def recalc_schedule_release_scores(year=2026):

    users = User.query.all()

    correct = Prediction.query.filter_by(
        user_id=SYSTEM_USER_ID,
        year=year,
        section="schedule_release"
    ).first()


    correct_answers = (
        correct.correct_schedule_preds
        if correct
        else {}
    )


    scores = Score.query.filter_by(
        year=year,
        section="schedule_release"
    ).all()


    for score in scores:


        predictions = Prediction.query.filter_by(
            user_id=score.user_id,
            year=year,
            section="schedule_release"
        ).all()


        score.points = sum(
            prediction.calculate_points(
                schedule_correct=correct_answers
            )
            for prediction in predictions
        )


    db.session.commit()
    update_total_points(year)
    update_all_ranks(users, year)



# =========================================================
# PRESEASON SCORING
# =========================================================
def recalc_preseason_scores(year=2026):

    users = db.session.query(Prediction.user_id).filter(
        Prediction.year == year,
        Prediction.section == "preseason"
    ).distinct().all()

    for (user_id,) in users:

        score = Score.query.filter_by(
            user_id=user_id,
            year=year,
            section="preseason"
        ).first()

        if not score:
            score = Score(
                user_id=user_id,
                year=year,
                section="preseason",
                points=0
            )
            db.session.add(score)


    db.session.commit()


    scores = Score.query.filter_by(
        year=year,
        section="preseason"
    ).all()


    for score in scores:

        predictions = Prediction.query.filter_by(
            user_id=score.user_id,
            year=year,
            section="preseason"
        ).all()

        score.points = sum(
            prediction.player.preseason_points or 0
            for prediction in predictions
            if prediction.player
        )


    db.session.commit()
    update_total_points(year)
    update_all_ranks(users, year)

# =========================================================
# TOTAL POINTS
# =========================================================
def update_total_points(year):


    users = User.query.all()


    for user in users:


        scores = Score.query.filter_by(
            user_id=user.id,
            year=year
        ).all()


        total = sum(
            score.points
            for score in scores
        )


        for score in scores:
            score.total_points = total


    db.session.commit()



# =========================================================
# RANKINGS
# =========================================================
def update_all_ranks(users, year):


    # Overall leaderboard
    Score.update_ranks(
        users,
        section=None,
        year=year
    )


    # Individual sections
    sections = [
        "draft",
        "schedule_release",
        "preseason",
        "free_agency",
        "scouting_combine"
    ]


    for section in sections:

        Score.update_ranks(
            users,
            section=section,
            year=year
        )


    db.session.commit()

    users = User.query.all()