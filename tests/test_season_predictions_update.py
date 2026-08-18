import pytest

from football_prophesy.extensions import db
from football_prophesy.models.team import Team
from football_prophesy.models.player import Player
from football_prophesy.models.user import User


@pytest.fixture
def admin_user(app):
    with app.app_context():
        user = User.query.first()

        if not user:
            user = User(
                username="test_admin",
                email="test_admin@test.com"
            )
            db.session.add(user)
            db.session.commit()

        return user


def test_update_team_award(client, app, admin_user):
    with app.app_context():

        team = Team.query.first()

        assert team is not None, "No teams exist in the database"

        response = client.post(
            "/season_predictions/update",
            data={
                "highest_scoring_offense": str(team.id)
            },
            follow_redirects=True
        )

        assert response.status_code == 200

        db.session.refresh(team)

        assert team.season_prediction is not None

        assert (
            "highest_scoring_offense"
            in team.season_prediction
        )


def test_update_each_single_team_award(client, app, admin_user):
    team = None

    with app.app_context():

        team = Team.query.first()

        assert team is not None, "No teams exist in the database"

        team_id = str(team.id)

        team_awards = [
            "highest_scoring_offense",
            "lowest_scoring_offense",
            "best_defense",
            "worst_defense",
            "afc_1_seed",
            "nfc_1_seed",
            "afc_east_champion",
            "afc_south_champion",
            "afc_north_champion",
            "afc_west_champion",
            "nfc_east_champion",
            "nfc_south_champion",
            "nfc_north_champion",
            "nfc_west_champion",
            "super_bowl_champion",
        ]

        form_data = {
            award: team_id
            for award in team_awards
        }

        response = client.post(
            "/season_predictions/update",
            data=form_data,
            follow_redirects=True
        )

        assert response.status_code == 200

        db.session.refresh(team)

        for award in team_awards:

            assert award in team.season_prediction, (
                f"{award} was not saved to "
                f"{team.name}"
            )


def test_update_afc_playoff_teams(client, app, admin_user):
    with app.app_context():

        teams = Team.query.filter_by(
            conference="AFC"
        ).limit(2).all()

        assert len(teams) == 2, (
            "Need at least 2 AFC teams"
        )

        response = client.post(
            "/season_predictions/update",
            data=[
                (
                    "afc_playoff_teams",
                    str(teams[0].id)
                ),
                (
                    "afc_playoff_teams",
                    str(teams[1].id)
                ),
            ],
            follow_redirects=True
        )

        assert response.status_code == 200

        db.session.refresh(teams[0])
        db.session.refresh(teams[1])

        assert (
            "afc_playoff_teams"
            in teams[0].season_prediction
        )

        assert (
            "afc_playoff_teams"
            in teams[1].season_prediction
        )


def test_update_nfc_playoff_teams(client, app, admin_user):
    with app.app_context():

        teams = Team.query.filter_by(
            conference="NFC"
        ).limit(2).all()

        assert len(teams) == 2, (
            "Need at least 2 NFC teams"
        )

        response = client.post(
            "/season_predictions/update",
            data=[
                (
                    "nfc_playoff_teams",
                    str(teams[0].id)
                ),
                (
                    "nfc_playoff_teams",
                    str(teams[1].id)
                ),
            ],
            follow_redirects=True
        )

        assert response.status_code == 200

        db.session.refresh(teams[0])
        db.session.refresh(teams[1])

        assert (
            "nfc_playoff_teams"
            in teams[0].season_prediction
        )

        assert (
            "nfc_playoff_teams"
            in teams[1].season_prediction
        )


def test_update_championship_matchup(client, app, admin_user):
    with app.app_context():

        teams = Team.query.limit(2).all()

        assert len(teams) == 2, (
            "Need at least 2 teams"
        )

        response = client.post(
            "/season_predictions/update",
            data=[
                (
                    "afc_championship_matchup",
                    str(teams[0].id)
                ),
                (
                    "afc_championship_matchup",
                    str(teams[1].id)
                ),
            ],
            follow_redirects=True
        )

        assert response.status_code == 200

        db.session.refresh(teams[0])
        db.session.refresh(teams[1])

        assert (
            "afc_championship_matchup"
            in teams[0].season_prediction
        )

        assert (
            "afc_championship_matchup"
            in teams[1].season_prediction
        )


def test_update_super_bowl_matchup(client, app, admin_user):
    with app.app_context():

        teams = Team.query.limit(2).all()

        assert len(teams) == 2, (
            "Need at least 2 teams"
        )

        response = client.post(
            "/season_predictions/update",
            data=[
                (
                    "super_bowl_matchup",
                    str(teams[0].id)
                ),
                (
                    "super_bowl_matchup",
                    str(teams[1].id)
                ),
            ],
            follow_redirects=True
        )

        assert response.status_code == 200

        db.session.refresh(teams[0])
        db.session.refresh(teams[1])

        assert (
            "super_bowl_matchup"
            in teams[0].season_prediction
        )

        assert (
            "super_bowl_matchup"
            in teams[1].season_prediction
        )