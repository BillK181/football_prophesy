from football_prophesy.models.user import User
from football_prophesy.models.prediction import Prediction
from football_prophesy.models.score import Score
from football_prophesy.models.player import Player
from football_prophesy.models.team import Team

from football_prophesy.extensions import db
from football_prophesy.data.season_predictions_points import SEASON_PREDICTION_POINTS


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

    # Find all users who have preseason predictions
    users = db.session.query(Prediction.user_id).filter(
        Prediction.year == year,
        Prediction.section == "preseason"
    ).distinct().all()

    # Find each users score or give 0 then commit to db
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

    # Get scores from db
    scores = Score.query.filter_by(
        year=year,
        section="preseason"
    ).all()

    
    for score in scores:

        # Go into predictions model and find the user_id for the score
        predictions = Prediction.query.filter_by(
            user_id=score.user_id,
            year=year,
            section="preseason"
        ).all()

        # For each prediction, create a sum
        score.points = sum(
            prediction.player.preseason_points or 0
            for prediction in predictions
            if prediction.player
        )


    db.session.commit()
    update_total_points(year)
    update_all_ranks(users, year)


# =========================================================
# Season Predictions
# =========================================================

def recalc_season_predictions_scores(year=2026):

    MULTI_PREDICTIONS = {
        "afc_playoff_teams": 7,
        "nfc_playoff_teams": 7,
        "afc_championship_matchup": 2,
        "nfc_championship_matchup": 2,
        "super_bowl_matchup": 2,
        "super_bowl_champion": 1,
    }


    # ==================================================
    # FIND USERS WITH SEASON PREDICTIONS
    # ==================================================

    users = db.session.query(
        Prediction.user_id
    ).filter(
        Prediction.year == year,
        Prediction.section == "season_predictions"
    ).distinct().all()


    # ==================================================
    # CREATE MISSING SCORE ROWS
    # ==================================================

    for (user_id,) in users:

        score = Score.query.filter_by(
            user_id=user_id,
            year=year,
            section="season_predictions"
        ).first()

        if not score:

            score = Score(
                user_id=user_id,
                year=year,
                section="season_predictions",
                points=0
            )

            db.session.add(score)


    db.session.commit()


    # ==================================================
    # GET SCORES
    # ==================================================

    scores = Score.query.filter_by(
        year=year,
        section="season_predictions"
    ).all()


    # ==================================================
    # RECALCULATE EACH USER
    # ==================================================

    for score in scores:

        # Reset score
        score.points = 0


        # Get user's predictions
        predictions = Prediction.query.filter_by(
            user_id=score.user_id,
            year=year,
            section="season_predictions"
        ).all()


        # ==================================================
        # STORE MULTI-TEAM PREDICTIONS
        # ==================================================

        afc_playoff_teams = []

        nfc_playoff_teams = []

        afc_championship_teams = []

        nfc_championship_teams = []

        super_bowl_teams = []

        super_bowl_champion = []


        # ==================================================
        # PROCESS PREDICTIONS
        # ==================================================

        for prediction in predictions:

            season_prediction = prediction.season_prediction


            if not season_prediction:
                continue


            # ==================================================
            # DETERMINE BASE PREDICTION
            # ==================================================

            parts = season_prediction.rsplit("_", 1)


            if (
                len(parts) == 2
                and parts[1].isdigit()
            ):

                base_prediction = parts[0]

            else:

                base_prediction = season_prediction


            # ==================================================
            # PLAYER PREDICTION
            # ==================================================

            if prediction.player:

                player = prediction.player


                if base_prediction in (
                    player.season_prediction or []
                ):

                    score.points += (
                        SEASON_PREDICTION_POINTS[
                            base_prediction
                        ]
                    )


            # ==================================================
            # TEAM PREDICTION
            # ==================================================

            if prediction.team:

                team = prediction.team


                # ------------------------------------------
                # AFC PLAYOFF TEAMS
                # ------------------------------------------

                if base_prediction == "afc_playoff_teams":

                    afc_playoff_teams.append(team)


                # ------------------------------------------
                # NFC PLAYOFF TEAMS
                # ------------------------------------------

                elif base_prediction == "nfc_playoff_teams":

                    nfc_playoff_teams.append(team)


                # ------------------------------------------
                # AFC CHAMPIONSHIP MATCHUP
                # ------------------------------------------

                elif base_prediction == "afc_championship_matchup":

                    afc_championship_teams.append(team)


                # ------------------------------------------
                # NFC CHAMPIONSHIP MATCHUP
                # ------------------------------------------

                elif base_prediction == "nfc_championship_matchup":

                    nfc_championship_teams.append(team)


                # ------------------------------------------
                # SUPER BOWL MATCHUP
                # ------------------------------------------

                elif base_prediction == "super_bowl_matchup":

                    super_bowl_teams.append(team)


                # ------------------------------------------
                # SUPER BOWL CHAMPION
                # ------------------------------------------

                elif base_prediction == "super_bowl_champion":

                    super_bowl_champion.append(team)


                # ------------------------------------------
                # NORMAL SINGLE TEAM PREDICTION
                # ------------------------------------------

                elif base_prediction in (
                    team.season_prediction or []
                ):

                    score.points += (
                        SEASON_PREDICTION_POINTS[
                            base_prediction
                        ]
                    )


        # ==================================================
        # AFC PLAYOFF TEAMS
        # ==================================================

        for team in afc_playoff_teams:

            correct = any(
                f"afc_playoff_teams_{i}"
                in (team.season_prediction or [])
                for i in range(1, 8)
            )


            if correct:

                score.points += team.playoff_points


        # ==================================================
        # NFC PLAYOFF TEAMS
        # ==================================================

        for team in nfc_playoff_teams:

            correct = any(
                f"nfc_playoff_teams_{i}"
                in (team.season_prediction or [])
                for i in range(1, 8)
            )


            if correct:

                score.points += team.playoff_points


        # ==================================================
        # AFC CHAMPIONSHIP MATCHUP
        # ==================================================

        correct = 0


        for team in afc_championship_teams:

            if any(
                f"afc_championship_matchup_{i}"
                in (team.season_prediction or [])
                for i in range(1, 3)
            ):

                correct += 1


        if correct == 1:

            score.points += 15

        elif correct == 2:

            score.points += 50


        # ==================================================
        # NFC CHAMPIONSHIP MATCHUP
        # ==================================================

        correct = 0


        for team in nfc_championship_teams:

            if any(
                f"nfc_championship_matchup_{i}"
                in (team.season_prediction or [])
                for i in range(1, 3)
            ):

                correct += 1


        if correct == 1:

            score.points += 15

        elif correct == 2:

            score.points += 50


        # ==================================================
        # SUPER BOWL MATCHUP
        # ==================================================

        correct = 0


        for team in super_bowl_teams:

            if any(
                f"super_bowl_matchup_{i}"
                in (team.season_prediction or [])
                for i in range(1, 3)
            ):

                correct += 1


        if correct == 1:

            score.points += 25

        elif correct == 2:

            score.points += 100


        # ==================================================
        # SUPER BOWL CHAMPION
        # ==================================================

        for team in super_bowl_champion:

            if "super_bowl_champion_1" in (
                team.season_prediction or []
            ):

                score.points += (
                    SEASON_PREDICTION_POINTS[
                        "super_bowl_champion"
                    ]
                )


    # ==================================================
    # SAVE SCORES
    # ==================================================

    db.session.commit()


    # ==================================================
    # UPDATE TOTAL POINTS
    # ==================================================

    update_total_points(year)


    # ==================================================
    # UPDATE RANKS
    # ==================================================

    update_all_ranks(
        User.query.all(),
        year
    )

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
        "scouting_combine",
        "season_predictions"
    ]


    for section in sections:

        Score.update_ranks(
            users,
            section=section,
            year=year
        )


    db.session.commit()

    users = User.query.all()