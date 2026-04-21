# services/routetracking.py

from flask import g
from flask_login import current_user
from datetime import datetime
from football_prophesy.extensions import db
from football_prophesy.models.route_usage import RouteUsage

def track_route_usage(route_name: str):
    """
    Track a user's access to a specific route.
    route_name > string identifier for the route function.
    """

    # Check if current_user is authenticated
    if not current_user.is_authenticated:
    # No logged-in user; nothing to track
        return
    # Use current_user.id as the user_id for tracking.
    user_id = current_user.id

    # Check if there's already a usage record for this user + route
    usage = RouteUsage.query.filter_by(user_id=user_id, route_name=route_name).first()
    # Get current UTC timestamp
    now = datetime.utcnow()

    # If a record exists
    if usage:
        # Increment count and update timestamp
        usage.count += 1
        usage.last_visited = now
    else:
        # Create new record if it doesn't exist
        usage = RouteUsage(user_id=user_id, route_name=route_name, count=1, last_visited=now)
        db.session.add(usage)

    # Store in g (a list) to commit later
    if not hasattr(g, "route_usage_to_commit"):
        g.route_usage_to_commit = []
    g.route_usage_to_commit.append(usage)


# -------------------------
# Teardown: Commit usages at end of request
# -------------------------
from flask import Flask

def init_app(app: Flask):
    """
    Attach a teardown handler to commit all route usage records at the end of the request.
    Call this in your main app to register the teardown request.
    """

    @app.teardown_request
    def commit_route_usage(exception=None):
        """
        Commit all route usage records stored in g.
        Handles rollback on failure.
        """

        # Check if g.route_usage_to_commit exists
        if hasattr(g, "route_usage_to_commit"):
            # For each usage record in the list, merge it into the session
            for usage in g.route_usage_to_commit:
                db.session.merge(usage)
            # Commit all changes in a try/except block
            try:
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                print(f"[RouteTracking] Failed to commit route usage: {e}")