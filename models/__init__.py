from football_prophesy.extensions import db

from .user import User
from .prediction import Prediction
from .comment import Comment
from .route_usage import RouteUsage
from .score import Score

__all__ = ["db", "User", "Prediction", "Comment", "RouteUsage"]