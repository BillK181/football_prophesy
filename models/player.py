from football_prophesy.extensions import db

class Player(db.Model):
    __tablename__ = "player"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    actual_pick = db.Column(db.Integer, nullable=True)
