# routes/__init__.py
from flask import Flask

def register_blueprints(app: Flask):
    """
    Import and register all blueprints here.
    """
    # Import blueprints
    from .account_routes import account_bp 
    from .auth_routes import auth_bp
    from .combine_routes import combine_bp
    from .comment_routes import comment_bp
    from .draft_routes import draft_bp
    from .free_agency_routes import free_agency_bp
    from .main_routes import main_bp

    # Register blueprints
    app.register_blueprint(account_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(combine_bp)
    app.register_blueprint(comment_bp)
    app.register_blueprint(draft_bp)
    app.register_blueprint(free_agency_bp)
    app.register_blueprint(main_bp)
