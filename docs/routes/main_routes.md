Imports:
- Blueprint – Organizes Flask routes into modular components; allows separating related routes (e.g., main, combine, free_agency) and registering them in app.py.
- request – Access incoming HTTP request data (form fields, query params, headers, cookies).
- session – Stores user-specific data across requests (login state, temporary variables); Flask stores it in a signed cookie.
- render_template – Renders HTML templates using Jinja2 and allows passing Python variables to the template.
- current_user – Provides the current authenticated user object from Flask-Login.
- User – SQLAlchemy model representing users (account info, predictions, etc.)
- track_route_usage – Custom service to track which endpoints users visit.
- SCOUTING_COMBINE_PLAYERS – Constant list of combine participants for display on pages.

Blueprint("main", __name__):
- Creates a Flask Blueprint for main site routes.
- main_bp – Blueprint object for organizing main pages, modularizes code, easy to register in app.py.

@main_bp.before_app_request
def load_user_info():
- Runs before every request across the entire app (not just main_bp routes).
- Purpose: Track route usage for analytics
- Checks if a user is logged in using Flask-Login's current_user.
    - current_user.is_authenticated returns True if the user is logged in, False otherwise.
    - If not authenticated, the function immediately returns (stops execution) to prevent further processing.
    - Ensures that only logged-in users have their info loaded or route tracking applied.
- Track route usage:
    - request.endpoint gives the current route function name
    - Calls track_route_usage(request.endpoint) to log visits
- Ensures analytics are tracked and user info is available via current_user for templates and routes.

@main_bp.route("/")
def index():
- Displays the homepage / index page.
- Fetches logged-in user:
    - Uses Flask-Login current_user if authenticated; else None
- Fetches all users to calculate leaderboards
- Calculates leaderboards:
    - overall = top 10 users by total points (all sections)
    - combine = top 10 users filtered by section="scouting_combine"
    - free_agency = top 10 users filtered by section="free_agency"
- Converts leaderboard entries from dictionaries into tuples for easier use in templates.
    - Each entry from Score.section_leaderboard(users) is a dict: {"user": <User>, "score": <int>}.
    - The comprehension [(entry["user"], entry["score"]) for entry in leaderboard] iterates over each dict entry:
        - entry["user"] → the User object
        - entry["score"] → the user's total points
    - Result is a list of tuples: [(User1, 120), (User2, 110), ...]
    - Makes it easier to loop in Jinja2 templates:
        - e.g., {% for user, score in top_players %} {{ user.username }} - {{ score }} {% endfor %}
- Renders "index.html" with:
    - top_players → overall leaderboard
    - combine_top_players → scouting combine leaderboard
    - free_agency_top_players → free agency leaderboard
    - user → current logged-in user

@main_bp.route("/draft")
def draft():
- Renders draft page with SCOUTING_COMBINE_PLAYERS list
- Template: "draft.html"

@main_bp.route("/schedule_release")
def schedule_release():
- Renders schedule release page
- Template: "schedule_release.html"
- Passes SCOUTING_COMBINE_PLAYERS for display if needed

@main_bp.route("/preseason")
def preseason():
- Renders preseason page
- Template: "preseason.html"
- Passes SCOUTING_COMBINE_PLAYERS for context

@main_bp.route("/season_predictions")
def season_predictions():
- Renders season predictions page
- Template: "season_predictions.html"
- Passes SCOUTING_COMBINE_PLAYERS

@main_bp.route("/season_picks")
def season_picks():
- Renders season picks page
- Template: "season_picks.html"
- Passes SCOUTING_COMBINE_PLAYERS

@main_bp.route("/postseason_predictions")
def postseason_predictions():
- Renders postseason predictions page
- Template: "postseason_predictions.html"
- Passes SCOUTING_COMBINE_PLAYERS

@main_bp.route("/postseason_picks")
def postseason_picks():
- Renders postseason picks page
- Template: "postseason.html"
- Passes SCOUTING_COMBINE_PLAYERS