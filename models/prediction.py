from football_prophesy.extensions import db

class Prediction(db.Model):
    __tablename__ = "prediction"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    year = db.Column(db.Integer, default=2026)
    section = db.Column(db.String(50), default="scouting_combine")
    player_id = db.Column(db.Integer, db.ForeignKey("player.id"), nullable=False)
    player = db.relationship("Player")
    player_name = db.Column(db.String(100), nullable=True)

    # Draft fields
    draft_position_group = db.Column(db.String(50), nullable=True)

    # Free Agency predictions (one row per player)
    team_prediction = db.Column(db.String(100), nullable=True)
    salary_prediction = db.Column(db.String(50), nullable=True)

    # Scouting Combine fields
    position_group = db.Column(db.String(50), nullable=True)
    drill = db.Column(db.String(50), nullable=True)
    place = db.Column(db.Integer, nullable=True)


    # ------------------------
    # Scoring
    # ------------------------
    def calculate_points(self, combine_results=None, position_drill_map=None, free_agency_results=None):
        """
        Calculate points for this prediction based on its section.
        
        Parameters:
        - combine_results: dict of actual combine results (injected from outside)
        - position_drill_map: dict to normalize drill names
        - free_agency_results: dict of actual free agency results (injected from outside)
        
        Returns:
        - int: total points for this prediction
        """

        # -----------------------------
        # Scouting Combine Section
        # -----------------------------
        if self.section == "scouting_combine":
            if combine_results is None:
                return 0  # No data → no points
            return self._calculate_combine_points(combine_results, position_drill_map)

        # -----------------------------
        # Free Agency Section
        # -----------------------------
        elif self.section == "free_agency":
            if free_agency_results is None:
                return 0  # No data → no points
            
            actual = free_agency_results.get(self.player.name, {})
            points = 0

            # +5 if predicted team matches actual
            if self.team_prediction and actual.get("team") == self.team_prediction:
                points += 5

            # +5 if predicted salary matches actual
            if self.salary_prediction and actual.get("salary") == self.salary_prediction:
                points += 5

            return points
        
        # -----------------------------
        # Draft Section
        # -----------------------------
        elif self.section == "draft":
            return 0  # handled by Score system

        # -----------------------------
        # Unknown section → no points
        # -----------------------------
        return 0

    def _calculate_combine_points(self, results_data, position_drill_map):
        """
        Calculate the points for a single scouting combine prediction.

        Parameters:
            self: the Prediction instance (gives access to player_name, position_group, drill, place)
            results_data (dict): nested dictionary of actual results (from DB)
            position_drill_map (dict): maps predicted drill names to actual drill names in results_data

        Returns:
            int: points scored for this prediction
        """


        # Normalize input
        normalized_position = (self.position_group or "").lower()
        drill = (self.drill or "").strip()

        # Sets the place as a number for each prediction
        place = self.place

        # If the mapping dictionary is missing, we cannot translate drills → no points
        if not position_drill_map:
            return 0


        # Map multiple ways a position might be written to a standard position key
        # This handles inconsistent or shorthand position names from user predictions
        position_map = {
            "quarterbacks": "Quarterbacks",
            "quarterback": "Quarterbacks",
            "running": "Running Backs",
            "running backs": "Running Backs",
            "wide": "Wide Receivers",
            "wide receivers": "Wide Receivers",
            "tight": "Tight Ends",
            "tight ends": "Tight Ends",
            "offensive linemen": "Offensive Linemen",
            "defensive linemen": "Defensive Linemen",
            "defensive backs": "Defensive Backs",
            "linebackers": "Linebackers",
            "linebacker": "Linebackers",
            "specialists": "Specialists",
        }

        # Go into position map using normalized position as key and return positions as pos_key
        pos_key = position_map.get(normalized_position)

        # Fallback for ambiguous groups
        # Handles values where the position key couldn't fix
        if not pos_key:
            if normalized_position in ["offensive", "defense", "defensive"]:
                if drill.startswith("linemen_"):
                    pos_key = "Offensive Linemen" if normalized_position == "offensive" else "Defensive Linemen"  # Ternary conditional 
                elif drill.startswith("backs_"):
                    pos_key = "Running Backs" if normalized_position == "offensive" else "Defensive Backs"  # Ternary conditional 
                elif drill.startswith("receivers_"):
                    pos_key = "Wide Receivers"
                elif drill.startswith("ends_"):
                    pos_key = "Tight Ends"

        # If we still don't know the position → cannot score
        if not pos_key:
            return 0
        

        # Using pos_key I go into position_drill_map to find the correct drill name
        # Example: "40_yard", the data got submitted as "receivers_40_yard"
        mapped_drill = position_drill_map.get(pos_key, {}).get(drill, drill)

        # I use mapped_drill to go into results data with the correct drill name and return the (results) at the drill for value for the primary key(pos_key)
        drill_results = results_data.get(pos_key, {}).get(mapped_drill, {})
        if not drill_results:
            # No results available → cannot score
            return 0

        # Normalize predicted player name for comparison
        predicted_name = (self.player.name if self.player else "").strip().lower()
        points = 0

        # Helper function: flatten nested lists
        # This handles multiple names in a single string or nested lists
        # e.g., ["Player A", ["Player B, Player C"]]
        def flatten(items):
            for item in items:
                if isinstance(item, list):
                    yield from flatten(item)
                elif isinstance(item, str) and "," in item:
                    for name in item.split(","):
                        yield name.strip()
                else:
                    yield item

        # +1 point if predicted player appears anywhere in top 3
        # drill_results.values() iterates over all ranks (1st, 2nd, 3rd, etc.)
        for place_players in drill_results.values():
            for p in flatten(place_players):
                if isinstance(p, str) and predicted_name == p.strip().lower():
                    points += 1
                    break # only one +1 per place

        # +3 points if predicted place matches exactly
        # drill_results.get(place, []) retrieves the list of players at that place
        actual_players = drill_results.get(place, [])
        # Flatten the list and normalize
        actual_flat = [p.strip().lower() for p in flatten(actual_players) if isinstance(p, str)]
        if predicted_name in actual_flat:
            points += 3
        
        # Return total points
        return points
    
    