from football_prophesy.extensions import db

from .user import User
from .prediction import Prediction
from .comment import Comment
from .likes import Likes
from .rating import Rating
from .route_usage import RouteUsage
from .score import Score
from .team import Team
from .game import Game

__all__ = ["db", "User", "Prediction", "Comment", "Likes", "Rating", "RouteUsage", "Score", "Team", "Game"]