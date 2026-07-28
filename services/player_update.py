from datetime import datetime, timedelta

from football_prophesy.models.player import Player
from football_prophesy.services.sleeper_players import update_players


SYNC_INTERVAL = timedelta(hours=72)

def update_players_if_needed():
    latest_player = Player.query.order_by(
        Player.last_updated.desc()
    ).first()

    if (
        latest_player is None
        or latest_player.last_updated is None
        or datetime.utcnow() - latest_player.last_updated >= SYNC_INTERVAL
    ):
        update_players()