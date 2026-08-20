from football_prophesy.extensions import db

from zoneinfo import ZoneInfo

PACIFIC = ZoneInfo("America/Los_Angeles")


class Game(db.Model):

    id = db.Column(db.Integer, primary_key=True)

    game_id = db.Column(db.Integer, unique=True, nullable=False)

    season = db.Column(db.Integer)
    week = db.Column(db.Integer)

    postseason = db.Column(db.Boolean, default=False)

    date = db.Column(db.DateTime)

    status = db.Column(db.String(50))
    status_state = db.Column(db.String(50))

    summary = db.Column(db.Text)
    venue = db.Column(db.String(255))

    home_team_id = db.Column(
        db.Integer,
        db.ForeignKey("team.id")
    )

    away_team_id = db.Column(
        db.Integer,
        db.ForeignKey("team.id")
    )

    home_score = db.Column(db.Integer)
    away_score = db.Column(db.Integer)

    home_q1 = db.Column(db.Integer)
    home_q2 = db.Column(db.Integer)
    home_q3 = db.Column(db.Integer)
    home_q4 = db.Column(db.Integer)
    home_ot = db.Column(db.Integer)

    away_q1 = db.Column(db.Integer)
    away_q2 = db.Column(db.Integer)
    away_q3 = db.Column(db.Integer)
    away_q4 = db.Column(db.Integer)
    away_ot = db.Column(db.Integer)

    home_team = db.relationship(
        "Team",
        foreign_keys=[home_team_id]
    )

    away_team = db.relationship(
        "Team",
        foreign_keys=[away_team_id]
    )

    @property
    def winner(self):
        if self.home_score is None or self.away_score is None:
            return None

        if self.home_score > self.away_score:
            return self.home_team

        if self.away_score > self.home_score:
            return self.away_team

        return None


    @property
    def winner_id(self):
        if self.home_score is None or self.away_score is None:
            return None

        if self.home_score > self.away_score:
            return self.home_team_id

        if self.away_score > self.home_score:
            return self.away_team_id

        return None

    @property
    def pick_points(self):
        if not self.date:
            return 5

        local_date = self.date.replace(tzinfo=ZoneInfo("UTC")).astimezone(PACIFIC)

        if local_date.hour >= 17:
            return 10

        return 5