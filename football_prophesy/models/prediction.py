from extensions import db

class Prediction(db.Model):
    __tablename__ = "prediction"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    year = db.Column(db.Integer, default=2026)
    section = db.Column(db.String(50), default="scouting_combine")

    # Free Agency predictions (one row per player)
    player_name = db.Column(db.String(100), nullable=False)
    team_prediction = db.Column(db.String(100), nullable=True)
    salary_prediction = db.Column(db.String(50), nullable=True)

    # Scouting Combine fields
    position_group = db.Column(db.String(50), nullable=True)
    drill = db.Column(db.String(50), nullable=True)
    place = db.Column(db.Integer, nullable=True)

    # ------------------------
    # Scouting Combine Scoring
    # ------------------------
    def calculate_points(self, results_data, position_drill_map):
        if self.section == "scouting_combine":
            return self._calculate_combine_points(results_data, position_drill_map)
        return 0

    def _calculate_combine_points(self, results_data, position_drill_map):

        position_map = {
            "quarterbacks": "Quarterbacks",
            "quarterback": "Quarterbacks",
            "running": "Running Backs",
            "running backs": "Running Backs",
            "wide": "Wide Receivers",
            "wide receivers": "Wide Receivers",
            "tight": "Tight Ends",
            "tight ends": "Tight Ends",
            "offensive": "Offensive Linemen",
            "offensive linemen": "Offensive Linemen",
            "defensive linemen": "Defensive Linemen",
            "defensive backs": "Defensive Backs",
            "linebackers": "Linebackers",
            "linebacker": "Linebackers",
            "specialists": "Specialists",
        }

        normalized_position = (self.position_group or "").strip().lower()
        drill = (self.drill or "").strip()
        place = self.place

        if normalized_position == "defensive":

            if drill.startswith("linemen_"):
                pos_key = "Defensive Linemen"

            elif drill.startswith("backs_"):
                pos_key = "Defensive Backs"

            else:
                return 0

        elif normalized_position == "offensive":

            if drill.startswith("linemen_"):
                pos_key = "Offensive Linemen"

            elif drill.startswith("backs_"):
                pos_key = "Running Backs"

            elif drill.startswith("receivers_"):
                pos_key = "Wide Receivers"

            elif drill.startswith("ends_"):
                pos_key = "Tight Ends"

            else:
                return 0

        else:

            pos_key = position_map.get(normalized_position)

            if not pos_key:
                return 0


        # FIXED DRILL MAPPING
        mapped_drill = position_drill_map.get(pos_key, {}).get(drill, drill)

        drill_results = results_data.get(pos_key, {}).get(mapped_drill, {})

        if not drill_results:
            return 0


        predicted_name = (self.player_name or "").strip().lower()
        points = 0


        def flatten(items):

            for item in items:

                if isinstance(item, list):
                    yield from flatten(item)

                elif isinstance(item, str) and "," in item:
                    for name in item.split(","):
                        yield name.strip()

                else:
                    yield item


        # +1 if player appears anywhere in top 3
        for place_players in drill_results.values():

            for p in flatten(place_players):

                if isinstance(p, str) and predicted_name == p.strip().lower():
                    points += 1
                    break


        # +3 if exact place match
        actual_players = drill_results.get(place, [])

        actual_flat = [
            p.strip().lower()
            for p in flatten(actual_players)
            if isinstance(p, str)
        ]

        if predicted_name in actual_flat:
            points += 3


        return points