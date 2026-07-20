from football_prophesy.extensions import db
from datetime import datetime


class Player(db.Model):
    __tablename__ = "player"

    # Your internal database ID
    id = db.Column(db.Integer, primary_key=True)

    # Sleeper's unique player ID
    sleeper_id = db.Column(db.String(50), unique=True, nullable=False)

    # -----------------------
    # Basic Player Information
    # -----------------------

    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))
    name = db.Column(db.String(100), nullable=False)

    position = db.Column(db.String(10))
    fantasy_positions = db.Column(db.JSON)

    team = db.Column(db.String(10))

    number = db.Column(db.Integer)

    college = db.Column(db.String(100))

    birth_country = db.Column(db.String(100))

    age = db.Column(db.Integer)

    years_exp = db.Column(db.Integer)

    height = db.Column(db.String(20))

    weight = db.Column(db.String(20))


    # -----------------------
    # Status / Availability
    # -----------------------

    status = db.Column(db.String(50))

    injury_status = db.Column(db.String(50))

    injury_start_date = db.Column(db.String(50))

    practice_participation = db.Column(db.String(50))


    # -----------------------
    # Depth Chart Information
    # -----------------------

    depth_chart_position = db.Column(db.Integer)

    depth_chart_order = db.Column(db.Integer)


    # -----------------------
    # Search / Fantasy Data
    # -----------------------

    hashtag = db.Column(db.String(200))

    search_first_name = db.Column(db.String(100))

    search_last_name = db.Column(db.String(100))

    search_full_name = db.Column(db.String(150))

    search_rank = db.Column(db.Integer)


    # -----------------------
    # External IDs
    # -----------------------

    fantasy_data_id = db.Column(db.Integer)

    sportradar_id = db.Column(db.String(100))

    stats_id = db.Column(db.String(100))

    espn_id = db.Column(db.String(100))

    rotowire_id = db.Column(db.String(100))

    rotoworld_id = db.Column(db.Integer)

    yahoo_id = db.Column(db.String(100))


    # -----------------------
    # Draft / Prediction Data
    # -----------------------

    actual_pick = db.Column(db.Integer, nullable=True)

    # -----------------------
    # Preseason Data
    # -----------------------

    preseason_points = db.Column(db.Integer, nullable=True)



    # Sleeper sync tracking
    last_updated = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow
    )