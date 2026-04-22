from football_prophesy.extensions import db   
from football_prophesy.models.user import User          
from football_prophesy.models.prediction import Prediction  

class Score(db.Model):
    __tablename__ = "score"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    year = db.Column(db.Integer, default=2026)
    section = db.Column(db.String(50), nullable=False)  # e.g. "scouting_combine"
    
    # Section points
    points = db.Column(db.Integer, default=0)
    
    # Total points across all sections for this user
    total_points = db.Column(db.Integer, default=0)
    
    rank = db.Column(db.Integer, default=None)

    user = db.relationship("User", backref="scores")

    def update_points(self, combine_results=None, free_agency_results=None, position_drill_map=None):
        """
        Update this section's points, and total points for the user.
        """
        user = User.query.get(self.user_id)
        if not user:
            return

        # ❌ Skip draft (handled separately)
        if self.section == "draft":
            return

        # ✅ Section points (non-draft only)
        self.points = user.total_points(
            year=self.year,
            section=self.section,
            combine_results=combine_results,
            position_drill_map=position_drill_map,
            free_agency_results=free_agency_results
        )

        # ✅ Total points (this will include draft AFTER recalc_scores runs)
        scores = Score.query.filter_by(user_id=self.user_id, year=self.year).all()
        self.total_points = sum(s.points for s in scores)
    
    @classmethod
    def update_ranks(cls, users, section=None, year=2026):
        """
        Update ranks for a list of users.
        - section=None → rank by total points
        - section="scouting_combine" → rank by that section
        """
        if section:
            scores = Score.query.filter_by(year=year, section=section).order_by(Score.points.desc()).all()
        else:
            scores = Score.query.filter_by(year=year).order_by(Score.total_points.desc()).all()

        for rank, score_row in enumerate(scores, 1):
            score_row.rank = rank
    

    # -----------------
    # Leaderboards
    # -----------------
    @classmethod
    def section_leaderboard(cls, users=None, section=None, year=2026, limit=None):
        """
        Returns a leaderboard with one entry per user.
        - section=None → total points across all sections
        - section="scouting_combine" → points for that section only
        """
        if users is None:
            users = User.query.all()

        leaderboard = []

        for user in users:
            # Calculate points for the section or total points
            if section:
                score = cls.query.filter_by(user_id=user.id, year=year, section=section).first()
                points = score.points if score else 0
            else:
                # Sum all sections for total points
                scores = cls.query.filter_by(user_id=user.id, year=year).all()
                points = sum(s.points for s in scores)

            leaderboard.append({
                "user": user,
                "points": points,
                "rank": None
            })

        # Sort descending by points
        leaderboard.sort(key=lambda x: x["points"], reverse=True)

        # Assign rank
        for idx, entry in enumerate(leaderboard, 1):
            entry["rank"] = idx

        # Apply limit if needed
        if limit:
            leaderboard = leaderboard[:limit]

        return leaderboard