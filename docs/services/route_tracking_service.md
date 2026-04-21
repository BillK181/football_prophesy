Imports:
- flask.g – A request-scoped object to store data during the request lifecycle.
- flask.session – Stores user session data (used here to get the logged-in user_id).
- datetime.datetime – Used to timestamp route visits in UTC.
- models.db – SQLAlchemy database instance for committing RouteUsage records.
- models.route_usage.RouteUsage – SQLAlchemy model that tracks per-user route access.

Function: track_route_usage(route_name: str)
- Purpose: Record that a user accessed a specific route.
- Parameters: route_name – string identifier for the route function.
    - Check if current_user is authenticated; return immediately if not.
        - Use current_user.id as the user_id for tracking.
    - Query RouteUsage table for an existing record matching user_id and route_name.
    - Get current UTC timestamp.
    - If a record exists:
        - Increment usage.count by 1.
        - Update usage.last_visited to now.
    - Else:
        - Create a new RouteUsage record with count=1 and last_visited=now.
        - Add it to the session with db.session.add().
    - Store the usage object in g.route_usage_to_commit (a list) to defer committing until request teardown.

Function: init_app(app: Flask)
- Purpose: Attach a teardown handler to commit all route usage records at the end of the request.
- Usage: Call init_app(app) in your main application to enable automatic route tracking.
    - Define a @app.teardown_request function commit_route_usage.
        - if not hasattr(g, "route_usage_to_commit"): g.route_usage_to_commit = []
            - This is checking whether g (Flask’s global request object) already has a route_usage_to_commit attribute. If it doesn’t, it creates an empty list. This prevents an AttributeError when you try to append to it later.
        - Check if g.route_usage_to_commit exists.
        - For each usage record in the list, merge it into the session.
        - Commit all changes in a try/except block:
            - On failure, rollback and print an error message.

Notes:
- Using g allows temporary storage of records during a request without committing multiple times.
- Merging before commit ensures both new and updated records are handled correctly.
- Teardown ensures commit happens after the request finishes, avoiding partial updates.
- This tracks per-user, per-route access and updates last visited timestamps automatically.