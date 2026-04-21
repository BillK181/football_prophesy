__tablename__ tells SQLAlchemy to use the database table named "comment" instead of automatically guessing "comment" or "comments".

Columns / Fields:
id → Primary key for the comment table. Unique identifier for each comment.
user_id → Foreign key linking to User.id. This connects the comment to its author.
    - With a relationship defined in User, you can do:
    - user.comments → all comments by a user
    - comment.user → the user who wrote a specific comment
page → The page or location where the comment appears.
content → The text of the comment.
timestamp → Automatically stores when the comment was created (default=datetime.utcnow).
is_admin → Boolean flag to mark whether this comment is an admin comment (default False).

Relationships:
Defined in the User model via db.relationship("Comment", backref="user").
Allows easy navigation between users and their comments.

Helper:
__repr__ is a debugging helper that makes printing comment objects readable:
<Comment id=5 user_id=2 page='home'>