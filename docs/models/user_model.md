
Quick Interview Review: 

Scoring:
- total_points(year=2026, section=None, combine_results=None, position_drill_map=None, free_agency_results=None)
    - Calculates total points for this user
    - Loops through self.predictions
    - Filters by year and section if specified
    - Uses calculate_points for each prediction
    - Returns sum of points

- rank(users, year=2026, combine_results=None, position_drill_map=None, free_agency_results=None)
    - Computes rank among a list of users
    - Compares total_points to all users
    - Returns position as integer (1 = highest)

Leaderboards:
- section_leaderboard(cls, users, section=None, year=2026, combine_results=None, position_drill_map=None, free_agency_results=None)
    - Class method; operates on User class, not instance
    - Loops through all users, calculates total points for section/year
    - Builds list of dicts: {"user": user, "score": score}
    - Sorts descending by score
    - Returns leaderboard for display or ranking






Full Review:

- db.Model, UserMixin:
    - Inherits from SQLAlchemy’s base model for ORM mapping (db.Model) and Flask-Login’s UserMixin which adds login methods like is_authenticated and get_id().

Fields:
Primary:
    - id – Primary key, unique for each user. Auto-incremented.
    - username – Unique login username, required.
    - name – User’s display name, required.
    - email – Unique email address, required.
    - favorite_team – Optional favorite team for personalization.
    -  password_hash – Stores the hashed password. nullable=False ensures every user has a password.
    - is_admin – Boolean, default False. Flags admin users.
Relationships:
    - predictions – Links all Prediction rows associated with this user. backref="user" allows prediction.user.
    - comments – Links all Comment rows associated with this user. backref="user" allows comment.user.
    - lazy=True → loads relationships only when accessed (lazy-loading)

- def set_password(self, password):
    - Takes a plaintext password and hashes it using werkzeug.security.generate_password_hash.
    - Stores the hash in password_hash.
    - Never stores plaintext passwords.

- def check_password(self, password):
    - Compares a plaintext password to the stored hash using werkzeug.security.check_password_hash.
    - Returns True if they match, False otherwise.

Scoring:
    - def total_points(self, year=2026, section=None, combine_results=None, position_drill_map=None, free_agency_results=None):
        - Instance method that calculates total points for this user.
        - Accepts optional external datasets (dependency injection). Defaults fall back to imported constants (ACTUAL_COMBINE_RESULTS, POSITION_DRILL_MAP, FREE_AGENCY_RESULTS).
        - Loops through all self.predictions. Skips predictions from other years. Skips predictions not in the requested section if section is specified. Calls calculate_points on each relevant prediction and sums them.
        - Returns total integer points.
    - def rank(self, users, year=2026, combine_results=None, position_drill_map=None, free_agency_results=None):
        - Computes the user’s rank among a list of users.
        - Gets this user’s total points.
        - Gets this user’s total points.
        - Returns len(better_users) + 1 → rank (1 = highest score).

Leaderboards:
    - def section_leaderboard(cls, users, section=None, year=2026, combine_results=None, position_drill_map=None, free_agency_results=None):
        - Class method — operates on the class rather than an instance.
        - Loops over all users to calculate their total points in a given section and year. The section is specified in the route. Score.section_leaderboard(users, section="scouting_combine")
        - Builds a list of dictionaries: {"user": user, "score": score}.
        - Sorts the leaderboard descending by score.
        - Returns sorted leaderboard for display or ranking.

