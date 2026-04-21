# models/user.py
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from football_prophesy.extensions import db
from football_prophesy.data.combine_results import ACTUAL_COMBINE_RESULTS
from football_prophesy.data.combine_map import POSITION_DRILL_MAP
from football_prophesy.data.free_agency_results import FREE_AGENCY_RESULTS


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
        """
        Hash and store a user's password securely.
        - password: plaintext password
        - Stores hash in self.password_hash
        """
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """
        Verify a plaintext password against the stored hash.
        - Returns True if password matches, False otherwise
        """
        return check_password_hash(self.password_hash, password)

    # -----------------
    # Scoring
    # -----------------
    def total_points(self, year=2026, section=None, combine_results=None, position_drill_map=None, free_agency_results=None):
        """
        Calculate total points for this user across all predictions.
        Parameters:
        - year: filter predictions for a specific year
        - section: filter by 'scouting_combine' or 'free_agency'
        - combine_results: external combine results data (optional)
        - position_drill_map: mapping of predicted drills to actual drills (optional)
        - free_agency_results: external free agency results (optional)
        Returns:
        - int: total points earned
        """
         # Use default data if not provided
        if combine_results is None:
            combine_results = ACTUAL_COMBINE_RESULTS
        if position_drill_map is None:
            position_drill_map = POSITION_DRILL_MAP
        if free_agency_results is None:
            free_agency_results = FREE_AGENCY_RESULTS
        points = 0

        # Loop over all predictions for this user
        for pred in self.predictions:
            if pred.year != year:
                continue # Skip predictions from other years
            if section and pred.section != section:
                continue # Skip predictions not in the requested section

            # Add points for this prediction using the Prediction model's logic
            points += pred.calculate_points(
                combine_results=combine_results,
                position_drill_map=position_drill_map,
                free_agency_results=free_agency_results
            )
        return points

    def rank(self, users, year=2026, combine_results=None, position_drill_map=None, free_agency_results=None):
        """
        Determine this user's rank among a list of users.
        - users: list of User objects to compare against
        - Returns rank (1 = highest score)
        """
        # Get this user's total points
        my_points = self.total_points(
            year=year,
            combine_results=combine_results,
            position_drill_map=position_drill_map,
            free_agency_results=free_agency_results
        )
        # Loop over users one at a time and count how many users have more points than this user
        better_users = [
            u for u in users
            if u.total_points(
                year=year,
                combine_results=combine_results,
                position_drill_map=position_drill_map,
                free_agency_results=free_agency_results
            ) > my_points
        ]
        return len(better_users) + 1  #Rank = # of users with more points + 1
    

    