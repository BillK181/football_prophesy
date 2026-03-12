from flask import Flask
from flask_login import LoginManager
from config import Config
from extensions import db, migrate
from services.route_tracking import init_app as init_route_tracking

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)

    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))
    
    # Import models
    from models import User, Prediction, Comment
    from models.route_usage import RouteUsage

    # Register blueprints
    from routes.auth_routes import auth_bp
    from routes.main_routes import main_bp
    from routes.combine_routes import combine_bp
    from routes.free_agency_routes import free_agency_bp
    from routes.comment_routes import comment_bp
    from routes.account_routes import account_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(combine_bp)
    app.register_blueprint(free_agency_bp)
    app.register_blueprint(comment_bp)
    app.register_blueprint(account_bp)

    # Route tracking
    init_route_tracking(app)

    return app


app = create_app()

if __name__ == "__main__":
    app.run(debug=True)