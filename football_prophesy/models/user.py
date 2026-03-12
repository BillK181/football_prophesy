from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from extensions import db
from services.scoring import (
    total_points as scoring_total_points,
    rank as scoring_rank
)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    favorite_team = db.Column(db.String(50), nullable=True)
    password_hash = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    predictions = db.relationship("Prediction", backref="user", lazy=True)
    comments = db.relationship("Comment", backref="user", lazy=True)

    # -----------------
    # Auth
    # -----------------
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    # -----------------
    # Scoring Wrappers
    # -----------------
    def total_points(self, year=2026):
        return scoring_total_points(self, year)

    def rank(self, year=2026):
        return scoring_rank(self, year)

    # -----------------
    # Leaderboards
    # -----------------
    @classmethod
    def section_leaderboard(cls, section=None, year=2026):
        users = cls.query.all()
        leaderboard = []

        for user in users:
            if section:
                score = scoring_total_points(user, year, section=section)
            else:
                score = scoring_total_points(user, year)

            leaderboard.append({
                "user": user,
                "score": score or 0
            })

        leaderboard.sort(key=lambda x: x["score"], reverse=True)
        return leaderboard