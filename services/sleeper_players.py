# services/sleeper_players.py
import requests
from datetime import datetime

from football_prophesy.extensions import db
from football_prophesy.models.player import Player


# -------------------------
# Player cache
# -------------------------

_player_cache = None


def cache_players():

    global _player_cache

    if _player_cache is None:
        _player_cache = Player.query.filter_by(
            status="Active"
        ).all()

    return _player_cache


def clear_player_cache():

    global _player_cache
    _player_cache = None



# -------------------------
# Update players from Sleeper
# -------------------------

def update_players():

    response = requests.get(
        "https://api.sleeper.app/v1/players/nfl"
    )

    players = response.json()


    for sleeper_id, data in players.items():

        player = Player.query.filter_by(
            sleeper_id=sleeper_id
        ).first()


        # Existing player from old database
        # doesn't have sleeper_id yet
        if player is None:

            first = data.get("first_name")
            last = data.get("last_name")

            name = f"{first or ''} {last or ''}".strip()

            player = Player.query.filter_by(
                name=name
            ).first()


        # Completely new player
        if player is None:

            player = Player(
                sleeper_id=sleeper_id,
                name="Unknown"
            )

            db.session.add(player)



        # -------------------------
        # Update ALL player fields
        # -------------------------

        player.sleeper_id = sleeper_id

        first = data.get("first_name")
        last = data.get("last_name")

        if first or last:
            player.name = f"{first or ''} {last or ''}".strip()
        else:
            player.name = "Unknown"


        player.position = data.get("position")
        player.fantasy_positions = data.get("fantasy_positions")

        player.team = data.get("team")
        player.number = data.get("number")

        player.college = data.get("college")
        player.birth_country = data.get("birth_country")

        player.age = data.get("age")
        player.years_exp = data.get("years_exp")

        player.height = data.get("height")
        player.weight = data.get("weight")


        player.status = data.get("status")
        player.injury_status = data.get("injury_status")
        player.injury_start_date = data.get("injury_start_date")
        player.practice_participation = data.get(
            "practice_participation"
        )


        player.depth_chart_position = data.get(
            "depth_chart_position"
        )

        player.depth_chart_order = data.get(
            "depth_chart_order"
        )


        player.hashtag = data.get("hashtag")

        player.search_first_name = data.get(
            "search_first_name"
        )

        player.search_last_name = data.get(
            "search_last_name"
        )

        player.search_full_name = data.get(
            "search_full_name"
        )

        player.search_rank = data.get(
            "search_rank"
        )


        player.fantasy_data_id = data.get(
            "fantasy_data_id"
        )

        player.sportradar_id = data.get(
            "sportradar_id"
        )

        player.stats_id = data.get(
            "stats_id"
        )

        player.espn_id = data.get(
            "espn_id"
        )

        player.rotowire_id = data.get(
            "rotowire_id"
        )

        player.rotoworld_id = data.get(
            "rotoworld_id"
        )

        player.yahoo_id = data.get(
            "yahoo_id"
        )

        player.last_updated = datetime.utcnow()


    db.session.commit()


    # Database changed, so refresh cache next time
    clear_player_cache()