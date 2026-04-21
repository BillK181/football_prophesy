Imports:
- Blueprint – Organizes Flask routes into modular components; allows you to separate related routes (e.g., auth, main, combine, free_agency) and register them in app.py.
- request – Access incoming HTTP request data (form fields, query params, headers, cookies).
- redirect, url_for – redirect sends a user to another route; url_for generates the URL for a route based on the function name to avoid hardcoding.
- flash – Sends one-time messages to templates (success, warning, error) that disappear after being displayed.
- render_template – Renders HTML templates using Jinja2 and allows passing Python variables to the template.
- login_required – Decorator from Flask-Login that ensures only authenticated users can access a route.
- current_user – Provides the current authenticated user object from Flask-Login.
- datetime – Provides classes for date and time manipulation; used here for deadlines.
- db – SQLAlchemy database instance for creating, querying, updating, deleting rows.
- User, Prediction, Comment – SQLAlchemy models representing database tables:
    - User – Stores account info
    - Prediction – Stores user predictions (combine or free agency)
    - Comment – Stores user comments
- Constants:
    - FREE_AGENCY_PLAYERS – List of players available for Free Agency predictions
    - FREE_AGENCY_RESULTS – Stores actual results (used for scoring, optional here)

Blueprint("free_agency", __name__, url_prefix="/free_agency"):
- Creates a Flask Blueprint for all Free Agency-related routes
- free_agency_bp – Flask Blueprint for all Free Agency routes; modularizes code, allows a URL prefix /free_agency, and enables easy registration in app.py
- Blueprints help scale applications by separating concerns (auth, main, API, combine, free_agency)

@free_agency_bp.route("/")
@login_required
def free_agency():
- Displays the Free Agency page where users can:
    - View the leaderboard
    - See their previous predictions
    - Read and post comments
    - See all available players
- Authentication:
    - Uses @login_required to ensure only logged-in users can access
    - Uses current_user from Flask-Login to get the authenticated user
- Fetch current user:
    - current_user is a User object already loaded by Flask-Login
    - No need to query User by ID manually
- Retrieve leaderboard:
    - Queries all users
    - Calls Score.section_leaderboard(users, section="free_agency")
    - Takes top 10 users for display
- Retrieve previous predictions:
    - Queries Prediction table filtered by:
        - user_id=current_user.id
        - year=2026
        - section="free_agency" or "free agency"
    - Converts predictions into a dictionary for easy template pre-filling
        - Keys like "Player_Name_team" or "Player_Name_salary"
        - Values are the predicted team or salary
- Fetch comments:
    - Queries Comment table filtered by page="free_agency"
    - Orders by timestamp descending
- Template: free_agency.html
    - page_title → "Free Agency"
    - css_file → "css/free_agency.css"
    - scoreboard_id → "free_agency_scoreboard"
    - leaderboard → free_agency_top_players (top 10 leaderboard)
    - results_url → URL to view current user's Free Agency results
    - prediction_title → "2026 Free Agency Predictions"
    - submission_deadline → "Submissions Lock 3/9 at 6am PST"
    - instructions → "Prophesy Where Each Free Agency Lands And For How Much"
    - form_action → URL to submit Free Agency predictions
    - submit_text → "Submit/Update Prophecy"
    - page_name → "free_agency" (used for comments)
    - comments → comments for the page
    - players → FREE_AGENCY_PLAYERS (list of participants)
    - user_predictions → dictionary of user's prior predictions


@free_agency_bp.route("/submit", methods=["POST"])
@login_required
def submit_free_agency():
- Handles POST submissions of Free Agency predictions
- Authentication:
    - Uses @login_required
    - Uses current_user from Flask-Login
- Deadline enforcement:
    - free_agency_deadline = datetime(2026, 3, 9, 12, 0)
    - If datetime.utcnow() > deadline, flashes a message and redirects back
- Process form data:
    - Iterates over request.form.items()
    - Skips empty values
    - Determines prediction type:
        - Ends with "_team" → field = "team"
        - Ends with "_salary" → field = "salary"
        - Extracts player_name from the key
- Retrieve or create Prediction object:
    - Queries Prediction table for user_id, player_name, section="free_agency", year=2026
    - If none exists, creates a new Prediction object
- Update Prediction:
    - Sets pred.team_prediction or pred.salary_prediction based on field
    - Adds pred to db.session
- Commit changes to database:
    - db.session.commit()
- Feedback and redirect:
    - flash("Free Agency predictions saved!", "success")
    - Redirects to free_agency.free_agency using PRG pattern