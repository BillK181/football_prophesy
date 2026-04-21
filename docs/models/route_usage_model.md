db.Model:
    - Inherits from SQLAlchemy’s base model for ORM mapping. Enables mapping Python objects to database tables.

Fields:
Primary:
    - id – Primary key, unique for each route usage entry. Auto-incremented by default.
    - user_id – Foreign key linking this route usage entry to a User.
        - nullable=False ensures every route usage entry belongs to a user.
        - index=True speeds up queries filtering by user_id.
    - route_name – Name of the route being tracked (e.g., "/dashboard"). Required field.
    - count – Integer tracking how many times the user has visited this route. Defaults to 0.
    - last_visited – Datetime of the last visit. Defaults to datetime.utcnow when the row is created.

Relationships:
    user – Relationship to the User model.
        - backref="route_usage" automatically adds a (.route_usage) attribute to each User instance, giving a list of all RouteUsage entries for that user.