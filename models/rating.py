from football_prophesy.extensions import db
from datetime import datetime, timezone


class Rating(db.Model):
    __tablename__ = "rating"

    __table_args__ = (
        db.UniqueConstraint(
            "user_id", "game_id",
            name="unique_user_game_rating"
        ),
        db.CheckConstraint(
            "rating >= 1 AND rating <= 5",
            name="valid_game_rating"
        ),
    )

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False
    )

    game_id = db.Column(
        db.Integer,
        db.ForeignKey("game.id"),
        nullable=False
    )

    rating = db.Column(db.Integer, nullable=False)

    created_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    updated_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False
    )