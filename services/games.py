import os
import requests
from datetime import datetime

from football_prophesy.extensions import db
from football_prophesy.models.game import Game
from football_prophesy.models.team import Team


TEAM_ABBR_MAP = {
    "WSH": "WAS"
}


def update_games(season=None):

    url = "https://api.balldontlie.io/nfl/v1/games"

    headers = {
        "Authorization": os.environ.get(
            "BALLDONTLIE_API_KEY"
        )
    }

    cursor = None
    total_games = 0

    while True:

        params = {
            "per_page": 100
        }

        if season is not None:
            params["seasons[]"] = season

        if cursor:
            params["cursor"] = cursor

        response = requests.get(
            url,
            headers=headers,
            params=params,
            timeout=10
        )

        response.raise_for_status()

        response_data = response.json()

        for game_data in response_data.get("data", []):

            game_id = game_data.get("id")

            if not game_id:
                continue

            # -------------------------
            # Teams
            # -------------------------

            home_abbr = game_data["home_team"]["abbreviation"]
            away_abbr = game_data["visitor_team"]["abbreviation"]

            home_abbr = TEAM_ABBR_MAP.get(
                home_abbr,
                home_abbr
            )

            away_abbr = TEAM_ABBR_MAP.get(
                away_abbr,
                away_abbr
            )

            home_team = Team.query.filter_by(
                abrv=home_abbr
            ).first()

            away_team = Team.query.filter_by(
                abrv=away_abbr
            ).first()

            if not home_team:
                print(
                    f"Could not find home team: {home_abbr}"
                )
                continue

            if not away_team:
                print(
                    f"Could not find away team: {away_abbr}"
                )
                continue

            # -------------------------
            # Existing / new game
            # -------------------------

            game = Game.query.filter_by(
                game_id=game_id
            ).first()

            if game is None:

                game = Game(
                    game_id=game_id
                )

                db.session.add(game)

            # -------------------------
            # Game information
            # -------------------------

            game.season = game_data.get("season")
            game.week = game_data.get("week")

            game.postseason = game_data.get(
                "postseason",
                False
            )

            game.summary = game_data.get("summary")
            game.venue = game_data.get("venue")

            game.status = game_data.get("status")
            game.status_state = game_data.get(
                "status_state"
            )

            # -------------------------
            # Date
            # -------------------------

            date_string = game_data.get("date")

            if date_string:

                game.date = datetime.fromisoformat(
                    date_string.replace(
                        "Z",
                        "+00:00"
                    )
                )

            # -------------------------
            # Teams
            # -------------------------

            game.home_team_id = home_team.id
            game.away_team_id = away_team.id

            # -------------------------
            # Final scores
            # -------------------------

            game.home_score = game_data.get(
                "home_team_score"
            )

            game.away_score = game_data.get(
                "visitor_team_score"
            )

            # -------------------------
            # Home scoring
            # -------------------------

            game.home_q1 = game_data.get(
                "home_team_q1"
            )

            game.home_q2 = game_data.get(
                "home_team_q2"
            )

            game.home_q3 = game_data.get(
                "home_team_q3"
            )

            game.home_q4 = game_data.get(
                "home_team_q4"
            )

            game.home_ot = game_data.get(
                "home_team_ot"
            )

            # -------------------------
            # Away scoring
            # -------------------------

            game.away_q1 = game_data.get(
                "visitor_team_q1"
            )

            game.away_q2 = game_data.get(
                "visitor_team_q2"
            )

            game.away_q3 = game_data.get(
                "visitor_team_q3"
            )

            game.away_q4 = game_data.get(
                "visitor_team_q4"
            )

            game.away_ot = game_data.get(
                "visitor_team_ot"
            )

            total_games += 1

        # -------------------------
        # Pagination
        # -------------------------

        cursor = response_data.get(
            "meta",
            {}
        ).get("next_cursor")

        if not cursor:
            break

    db.session.commit()

    print(
        f"Updated {total_games} games."
    )
