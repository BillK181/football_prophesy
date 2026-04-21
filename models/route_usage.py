from datetime import datetime
from football_prophesy.extensions import db 

class RouteUsage(db.Model):
    __tablename__ = "route_usage"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    route_name = db.Column(db.String(100), nullable=False)
    count = db.Column(db.Integer, default=0)
    last_visited = db.Column(db.DateTime, default=datetime.utcnow)

    # Optional relationship back to User
    user = db.relationship("User", backref="route_usage")