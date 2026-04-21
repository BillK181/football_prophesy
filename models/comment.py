"""
Comment model represents a comment left by a user on a specific page.

- Each comment is linked to a user via user_id (ForeignKey to User.id), enabling navigation:
    - user.comments → all comments by a user
    - comment.user → the author of a comment
- __repr__ helper makes debugging easier:
    <Comment id=5 user_id=2 page='home'>
"""

from football_prophesy.extensions import db
from datetime import datetime

class Comment(db.Model):
    __tablename__ = "comment"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    page = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    

    # Relationship back to User is already in User: 
    # comments = db.relationship("Comment", backref="user", lazy=True)

    def __repr__(self):
        return f"<Comment id={self.id} user_id={self.user_id} page={self.page}>"