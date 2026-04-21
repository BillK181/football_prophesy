from app import app
from extensions import db
from models.player import Player
from data.draft_profiles import PLAYERS_DATA


def seed_draft_players():
    """
    Seed database with players from PLAYERS_DATA.
    Prevents duplicates and handles name normalization.
    """

    with app.app_context():

        existing_players = {
            p.name.strip().lower(): p
            for p in Player.query.all()
        }

        added = 0
        skipped = 0

        for position, players_list in PLAYERS_DATA.items():
            for p in players_list:

                name_key = p["name"].strip().lower()

                if name_key in existing_players:
                    skipped += 1
                    continue

                player = Player(
                    name=p["name"].strip(),
                    actual_pick=None
                )

                db.session.add(player)
                added += 1

        db.session.commit()

        print(f"Seeding complete → Added: {added}, Skipped: {skipped}")


if __name__ == "__main__":
    seed_draft_players()