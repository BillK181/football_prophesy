from football_prophesy.extensions import db


class Team(db.Model):
    __tablename__ = "team"

    id = db.Column(db.Integer, primary_key=True)

    name = db.Column(db.String, nullable=False)
    city = db.Column(db.String, nullable=False)
    abrv = db.Column(db.String, nullable=False)

    season_prediction = db.Column(db.JSON, nullable=True)
    playoff_points = db.Column(db.Integer, nullable=True)