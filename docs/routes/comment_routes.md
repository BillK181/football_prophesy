Imports:
    - Blueprint – Organizes routes into modular components; allows grouping related functionality (e.g., comments, auth) and registering them in the main app.
    - request – Handles incoming HTTP request data (form data, JSON payloads, query parameters).
    - jsonify – Converts Python data structures (dict, list) into a JSON response for APIs or AJAX requests.
    - redirect, url_for – redirect sends the user to another route; url_for dynamically generates URLs based on route function names.
    - flash – Stores one-time messages (success, error, warning) to be displayed to the user on the next request.
    - session – Stores user-specific data across requests (e.g., user ID, login state) using signed cookies.
Models:
    - db – SQLAlchemy instance used to interact with the database (queries, inserts, updates, deletes).
    - User – Model representing users; typically used for authentication, ownership, and user-related queries.
        - Comment.user – SQLAlchemy relationship linking Comment to the User who created it; allows retrieving the username easily.
    - Comment – Model representing user comments; stores content, associated page, user reference, and timestamp.
Utilities:
    - datetime (from datetime) – Provides date and time functionality; commonly used for timestamps (e.g., when a comment is created) and time-based logic.
    - ZoneInfo – Provides timezone support; used to convert UTC timestamps to local time (PST/PDT).


Blueprint("comment", __name__)
    - Creates a Flask Blueprint for all comment-related routes.
    - comment_bp groups related routes together and allows them to be registered in app.py as a modular component (optionally with a URL prefix).
    - Blueprints help scale applications by separating concerns (auth, main, API, etc.)
    - Modular Blueprints allow reusing the same blueprint in multiple apps or under different URL prefixes.


@comment_bp.route("/submit_comment", methods=["POST"])
def submit_comment():
    - Handles AJAX submission of a new comment and returns JSON response
    - Returns JSON, so the front-end can dynamically add new comments without page reload.
    - Retrieve input and session data
        - page = request.form.get("page", "").strip().replace('_', ' ').replace('-', ' ').lower()
            - Gets the page identifier from the form.
            - Removes leading / with lstrip("/").
            - Replaces underscores and hyphens with spaces for human-readable display.
        - content = request.form.get("content", "").strip() → trims whitespace from the comment text.
        - user_id = current_user.id → retrieves the logged-in user's ID from Flask-Login’s current_user
    - Validate input
        - If content is empty, return a JSON error response:
            - {"success": False, "error": "Comment cannot be empty."}
        - Prevents storing blank comments.
    - Save UTC variable for PST conversion
    - Create comment object
        - If valid, instantiate Comment(user_id, page, content, timestamp=datetime.utcnow()).
        - Sets timestamp to the current UTC time.
    - Add comment to the database
        - db.session.add(comment) → stages the new comment for insertion.
        - db.session.commit() → saves it permanently to the database.
    - Convert timestamp to PST/PDT for JSON response
        - utc_now.replace(tzinfo=ZoneInfo("UTC"))
            - The utc_now variable is a datetime object in UTC (from datetime.utcnow()).
            - .replace(tzinfo=ZoneInfo("UTC")) marks the datetime as timezone-aware in UTC.
                - Without this, utc_now is "naive" (has no timezone info), and timezone conversions will fail or raise warnings.
        - .astimezone(ZoneInfo("America/Los_Angeles"))
            - Converts the UTC datetime to Pacific Time (handles PST or PDT automatically, depending on the date).
            - ZoneInfo("America/Los_Angeles") comes from Python’s standard zoneinfo module.
            - Result: a timezone-aware datetime in PST/PDT.
        - .strftime("%m-%d-%Y %I:%M %p")
            - Formats the datetime as a human-readable string for JSON or display.
            - Example output: "03-24-2026 04:15 PM"
            - Format codes:
                - %m → zero-padded month (01–12)
                - %d → zero-padded day of the month (01–31)
                - %Y → 4-digit year
                - %I → hour (12-hour clock, 01–12)
                - %M → minutes (00–59)
                - %p → AM/PM
    - Retrieve display username
        - username = comment.user.username if comment.user else "Guest"
        - Defaults to "Guest" if the user object is missing.
    - Return JSON response
        - Includes:
            - success: indicates submission success.
            - username: for display next to the comment.
            - content: the text of the comment.
            - timestamp: formatted for display ("%m-%d-%Y").
        - Enables the front-end to update the comment list dynamically without refreshing the page.


@comment_bp.route("/delete-comment/<int:comment_id>", methods=["POST"])
@login_required
def delete_comment(comment_id):
    - Deletes a comment via AJAX and returns JSON for the front-end.
    - Only the comment author or an admin can delete.
    - Front-end can dynamically:
        - Remove comments without reloading the page
        - Show/hide delete buttons based on user permissions (can_delete)
    - Retrieve the comment object:
        - comment = Comment.query.get_or_404(comment_id)
        - Fetches comment by ID; returns 404 if not found.
    - Check permissions:
        - current_user.id → logged-in user's ID
        - current_user.is_admin → check if user is admin
        - Allow deletion if:
            - User is the comment author (comment.user_id == current_user.id), or
            - User is an admin (current_user.is_admin)
    - Perform deletion:
        - db.session.delete(comment) → mark comment for deletion
        - db.session.commit() → permanently remove from database
        - Return JSON: {"success": True, "comment_id": comment_id}
    - Unauthorized deletion attempt:
        - Return JSON: {"success": False, "message": "You do not have permission to delete this comment."}
        - Front-end can alert user that deletion failed.
