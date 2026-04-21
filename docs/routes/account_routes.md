Imports:
    - render_template – Renders Jinja2 templates.
    - flash – Shows one-time messages to the user.
    - redirect, url_for – Redirect to other routes using endpoint names.
    - User, Prediction – SQLAlchemy models for users and predictions.
    - login_required – Decorator from services.auth to protect routes.
    - Data imports (FREE_AGENCY_PLAYERS, ACTUAL_COMBINE_RESULTS, etc.) – Provide actual results or constants needed for scoring and displaying predictions.

Blueprint("account", __name__)
    - Creates a Flask Blueprint for all account-related routes.
    - account_bp groups related routes together and allows them to be registered in app.py as a modular component (optionally with a URL prefix).
    - Blueprints help scale applications by separating concerns (auth, main, API, etc.)


@account_bp.route("/account/<int:user_id>")
@login_required
def account(user_id):
    - Route: /account/<user_id> – Dynamic route for any user ID.
    - @login_required ensures only logged-in users can view account pages.
    - profile_user = User.query.get_or_404(user_id)
        - Fetches the user object by id. Returns 404 if the user doesn’t exist.
    - total = User.total_points(profile_user)
        - Calls the total_points method on this user instance. Calculates points across all sections (scouting combine, free agency, etc.) for year 2026.
    - user_rank = User.rank(profile_user, User.query.all())
        - Depends on total_points calculation for each user 
        - Calculates rank by comparing against all users
        - Requires loading all users into memory
        - Can become expensive as user count grows
    - comments = profile_user.comments
        - Fetches all comments made by this user.
    - render_template(...)
        - Passes user info, total points, rank, and comments to account.html template.


@account_bp.route("/all_accounts")
@login_required
def all_accounts():
    - Route: /all_accounts – Shows a leaderboard for all users.
    - users = User.query.all()
        - Loads all users into memory
        - Simple implementation but not scalable for large datasets
        - Acceptable here because full dataset comparison is required for ranking
    - leaderboard = Score.section_leaderboard(users, section=None, year=2026)
        - Calls the class method section_leaderboard to calculate and sort users by score.
        - section_leaderboard:
            - Handles both score calculation and sorting
            - Centralizes leaderboard logic in the model layer
            - Keeps route thin and focused on data flow
    - section=None → includes all sections when calculating total points.
        - Returns a sorted list of dictionaries:
        - [{"user": user_obj, "score": total_points}, ...]
    - render_template("all_accounts.html", users_sorted=leaderboard)
        - Passes leaderboard data to the template. Each entry in the template loop will have entry.user and entry.score.


@account_bp.route("/account/<int:user_id>/scouting_combine")
@login_required
def user_combine_results(user_id):
    - Route: /account/<user_id>/scouting_combine
    - Shows a user’s scouting combine predictions vs actual results.
    - User.query.get_or_404(user_id)
        - Fetches a user by primary key
        - Automatically raises a 404 error if not found
        - Used in multiple routes to simplify error handling
    - Filter predictions:
        - Only include predictions where section == "scouting_combine" and year == 2026.
    - predictions_dict:
        - Converts a list of predictions into a dictionary
        - Enables O(1) lookup in the template
        - Avoids inefficient nested loops in Jinja
        - Key structure ("position_drill_place") ensures uniqueness
    - feedback dictionary:
        - Stores calculated points for each prediction
        - Uses the same key structure as predictions_dict for alignment
        - Delegates scoring logic to the model (calculate_points)
        - Keeps routes focused on orchestration, not business logic
    - render_template passes predictions, points, and all actual data for display.


@account_bp.route("/account/<int:user_id>/free_agency")
@login_required
def free_agency_review(user_id):
    - Route: /account/<user_id>/free_agency
    - Shows user predictions for free agency vs actual results.
    - User.query.get_or_404(user_id)
        - Fetches a user by primary key
        - Automatically raises a 404 error if not found
        - Used in multiple routes to simplify error handling
    - Fetch predictions:
        - Query all predictions matching:
            - user_id
            - section = "free_agency"
            - year = 2026
    - user_predictions:
        - Pre-initialized dictionary for every player
        - Ensures consistent structure even if user made no predictions
        - Prevents missing-key errors in templates
    - Population step:
        - Iterates through fetched predictions
        - Updates corresponding player entries (team/salary)
    - points_feedback:
        - Compares predicted vs actual values per player
        - Awards:
            - 5 points for correct team
            - 5 points for correct salary
        - Stores:
            - predicted values
            - actual values
            - calculated points
        - Structured for direct rendering in templates without additional logic
    - render_template(...)
        - Passes players, predictions, and points_feedback to the template.
        - no_predictions:
            - Converts predictions list into a boolean
            - True if empty, False if user has predictions
            - Used for conditional rendering in the template



- Data Transformation Pattern:
    - Converts database query results (lists of objects)
    - Into dictionaries keyed for fast lookup
    - This shifts complexity from templates → Python
    - Reduces template complexity
    - Improves runtime efficiency by avoiding repeated iteration


Design Insight:
- The application consistently moves logic out of templates into Python
- Reinforces separation of concerns:
    - Routes = orchestration
    - Models = business logic
    - Templates = presentation


Performance Considerations:
- Multiple routes use User.query.all()
    - Loads entire user table into memory
    - Acceptable for small datasets
    - Would need optimization (pagination, database-side ranking) at scale

- Dictionary transformations:
    - Trade increased memory usage for O(1) lookup time
    - Eliminate repeated iteration in templates
    - Significantly improve rendering efficiency