from football_prophesy.models.user import User
from football_prophesy.models.prediction import Prediction
from football_prophesy.models.score import Score
from football_prophesy.models.player import Player
from football_prophesy.models.team import Team

from football_prophesy.extensions import db
from football_prophesy.data.season_predictions_points import SEASON_PREDICTION_POINTS
from football_prophesy.services.scoring import update_total_points, update_all_ranks


SYSTEM_USER_ID = 0


def recalc_season_picks_scores(year=2026):

    users = db.session.query(
        Prediction.user_id
    ).filter(
        Prediction.year == year,
        Prediction.section == "season_picks"
    ).distinct().all()

    # Create missing score rows
    for (user_id,) in users:

        score = Score.query.filter_by(
            user_id=user_id,
            year=year,
            section="season_picks"
        ).first()

        if not score:
            score = Score(
                user_id=user_id,
                year=year,
                section="season_picks",
                points=0
            )

            db.session.add(score)

    db.session.commit()

    # Recalculate scores
    scores = Score.query.filter_by(
        year=year,
        section="season_picks"
    ).all()

    for score in scores:

        predictions = Prediction.query.filter_by(
            user_id=score.user_id,
            year=year,
            section="season_picks"
        ).all()

        score.points = sum(
            prediction.calculate_points()
            for prediction in predictions
        )

    db.session.commit()

    update_total_points(year)

    update_all_ranks(
        User.query.all(),
        year
    )