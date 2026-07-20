from datetime import datetime, timedelta

from football_prophesy.models.player import Player
from football_prophesy.services.sleeper_players import update_players


def update_players_if_needed():

    latest_player = Player.query.order_by(
        Player.last_updated.desc()
    ).first()


    # No players exist OR no sync has ever happened
    if latest_player is None or latest_player.last_updated is None:
        update_players()
        return


    time_since_update = (
        datetime.utcnow() - latest_player.last_updated
    )


    if time_since_update >= timedelta(hours=24):
        update_players()