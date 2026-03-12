# services/routetracking.py

from flask import g, session
from datetime import datetime
from models import db
from models.route_usage import RouteUsage

def track_route_usage(route_name: str):
    """
    Track a user's access to a specific route.
    Stores the usage in g to commit at the end of the request.
    """
    user_id = session.get("user_id")
    if not user_id:
        # No logged-in user; nothing to track
        return

    # Check if there's already a usage record for this user + route
    usage = RouteUsage.query.filter_by(user_id=user_id, route_name=route_name).first()
    now = datetime.utcnow()

    if usage:
        # Increment count and update timestamp
        usage.count += 1
        usage.last_visited = now
    else:
        # Create new record if it doesn't exist
        usage = RouteUsage(user_id=user_id, route_name=route_name, count=1, last_visited=now)
        db.session.add(usage)

    # Store in g to commit later
    if not hasattr(g, "route_usage_to_commit"):
        g.route_usage_to_commit = []
    g.route_usage_to_commit.append(usage)


# -------------------------
# Teardown: Commit usages at end of request
# -------------------------
from flask import Flask

def init_app(app: Flask):
    """
    Call this in your main app to register the teardown request.
    Example: init_app(app)
    """

    @app.teardown_request
    def commit_route_usage(exception=None):
        """
        Commit all route usage records stored in g.
        Handles rollback on failure.
        """
        if hasattr(g, "route_usage_to_commit"):
            for usage in g.route_usage_to_commit:
                db.session.merge(usage)
            try:
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                print(f"[RouteTracking] Failed to commit route usage: {e}")