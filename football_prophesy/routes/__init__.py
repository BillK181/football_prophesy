# routes/__init__.py
from flask import Flask

def register_blueprints(app: Flask):
    """
    Import and register all blueprints here.
    """
    # Import blueprints
    from .combine import combine_bp
    from .free_agency import free_agency_bp
    # Add more blueprints as you create them, e.g.:
    # from .other_module import other_bp

    # Register blueprints
    app.register_blueprint(combine_bp)
    app.register_blueprint(free_agency_bp)
    # app.register_blueprint(other_bp)