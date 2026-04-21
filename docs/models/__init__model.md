from extensions import db
    - Imports the SQLAlchemy instance (db) that was initialized in your extensions.py.
    - This allows all models to share the same database connection and metadata.

from .user import User
    - Imports the User model from the local user.py file in the same models package.
    - Makes the User class available in this package namespace.

from .prediction import Prediction
    - Imports the Prediction model from prediction.py.
    - Represents predictions made by users, either for scouting combine drills or free agency.

from .comment import Comment
    - Imports the Comment model from comment.py.
    - Represents user comments on pages, predictions, or other content.

from .route_usage import RouteUsage
    - Imports the RouteUsage model from route_usage.py.
    - Tracks how often and when a user visits specific routes in the application.

all = ["db", "User", "Prediction", "Comment", "RouteUsage"]
    - Explicitly defines the public API of the models package.
    - When you do from models import *, only the names in __all__ are imported.
    - Makes it easier to import models from other parts of the app consistently: