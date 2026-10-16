from football_prophesy.extensions import db
from datetime import datetime, timezone


class Likes(db.Model):
    __tablename__ = "likes"

    __table_args__ = (
        db.UniqueConstraint(
            "user_id", "game_id",
            name="unique_user_game_like"
        ),
        db.UniqueConstraint(
            "user_id", "comment_id",
            name="unique_user_comment_like"
        ),
        db.CheckConstraint(
            """
            (game_id IS NOT NULL AND comment_id IS NULL)
            OR
            (game_id IS NULL AND comment_id IS NOT NULL)
            """,
            name="like_exactly_one_target"
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
        nullable=True
    )

    comment_id = db.Column(
        db.Integer,
        db.ForeignKey("comment.id"),
        nullable=True
    )

    created_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )