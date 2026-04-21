"""
Flask application factory (CLEANED VERSION)

Key rules fixed here:
- ALL imports must use package paths (football_prophesy.*)
- Avoid mixing script-style imports (config, models, routes, etc.)
- Ensure Flask-Migrate is properly initialized
"""

from flask import Flask
from flask_login import LoginManager, current_user

# ✅ FIX: package-level imports (required for Flask CLI)
from football_prophesy.config import Config
from football_prophesy.extensions import db, migrate
from football_prophesy.services.route_tracking import init_app as init_route_tracking
from football_prophesy.routes import register_blueprints


def create_app():
    # -------------------------
    # 1. Create Flask app
    # -------------------------
    app = Flask(__name__)

    # -------------------------
    # 2. Load config
    # -------------------------
    app.config.from_object(Config)

    # -------------------------
    # 3. Initialize extensions
    # -------------------------
    db.init_app(app)
    migrate.init_app(app, db)

    # -------------------------
    # 4. Login setup
    # -------------------------
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"

    # -------------------------
    # 5. Import models (AFTER db init to avoid circular imports)
    # -------------------------
    from football_prophesy.models import User, Prediction, Comment, Score
    from football_prophesy.models.route_usage import RouteUsage

    # -------------------------
    # 6. User loader
    # -------------------------
    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    # -------------------------
    # 7. Context processor (global template variables)
    # -------------------------
    @app.context_processor
    def inject_user_data():
        if not current_user.is_authenticated:
            return {}

        score = Score.query.filter_by(
            user_id=current_user.id,
            year=2026
        ).first()

        return {
            "total": score.total_points if score else 0,
            "rank": score.rank if score else None
        }

    # -------------------------
    # 8. Register routes / blueprints
    # -------------------------
    register_blueprints(app)

    # -------------------------
    # 9. Custom services
    # -------------------------
    init_route_tracking(app)

    return app


# -------------------------
# 10. Flask entry point (required for CLI)
# -------------------------
app = create_app()

if __name__ == "__main__":
    app.run(debug=False)