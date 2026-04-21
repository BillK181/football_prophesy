- db.Model: Inherits from SQLAlchemy’s base model. Enables ORM mapping between Python objects and database tables.

- __tablename__ tells SQLAlchemy to use the database table named "prediction" instead of automatically guessing "prediction" or "predictions".

Fields:
Primary:
- id - Primary key, unique for each row. 
    Auto-incremented by default.
- user_id - Foreign key linking this prediction to a user.
    nullable=False ensures every prediction belongs to a user.
    Allows relationships: prediction.user (via backref on User) and user.predictions.
- year - The season or year the prediction applies to.
    Defaults to 2026 if no value is provided.
- section - Categorizes the type of prediction: 
    "free_agency" or "scouting_combine"
    Can be used to filter or calculate points separately.

Free Agency:
- player_name - The player being predicted (required).
- team_prediction - Predicted team for the player (optional).
- salary_prediction - Predicted team for the player (optional).

Scouting Combine:
- position_group - Player’s position (QB, RB, WR, etc.)or    broad group (offensive/defensive).
- drill - Name of the specific combine drill (40-yard dash,bench press, etc.).
- place - The predicted rank or placement for the player in that drill.


def calculate_points(self, combine_results=None, position_drill_map=None, free_agency_results=None):
- This is an instance method. 
Parameters:
    - combine_results: dict of actual combine results (injected from outside)
    - position_drill_map: dict to normalize drill names
    - free_agency_results: dict of actual free agency results (injected from outside)
- Calculates points for this prediction only.
- Accepts external datasets as parameters (dependency injection) so you don’t hardcode data inside the model.
- Returns 0 if the required results data is missing.
- Returns an integer representing points earned.

- Scouting Combine
    - Checks if section is scouting_combine
    - Checks if combine results have been implented
    - Delegates to _calculate_combine_points if section == "scouting_combine".

- Free Agency
    - Checks if section is free_agency
    - Checks if free agent results have been implented
    - I set actual as a dictionary of results with player name being the key
    - I initialize points
    - I calculate team prediction scoring by comparing the team prediction of self with the actual team of the player
    - I do the same with salary predictions
    - I return my points


def _calculate_combine_points(self, results_data, position_drill_map):
    - This is an instance method. 
    - I normalize the predicted position groups with strip and lower
    - I set a position_map dictionary to help align the predictions with how the actual data looks. This allows my code to always work with one canonical position name.
    - I go into my position_map with .get(normalized_positions) to get the value associate with the key. Example: tight -> tight end
    - For values that couldn't be fixed with the position key, I have ternary conditionals to fix. 
    - Using .get() I use my pos_key to go into the position_drill_map list of dicts to retrieve the value (drill name). 
    - I use mapped_drill to go into results data with the correct position name from pos_key and return the matching value for the given key of drill name. If drill isn't found it returns the original drill
    - Normalize predicted names
    - I initialize my points counter
    - def flatten
        - nested helper function
        - isinstance(item, list) → checks what type of object item is.
            - True → item is a Python list (like ["Player A", "Player B"])
            - False → item is not a list (maybe a string like "Player A")
            - yield from flatten(item) → recursion: if item is itself a list, call flatten again on this sublist. Handles nested lists of arbitrary depth (e.g., [["Player A"], ["Player B, Player C"]])
            - yield produces items one by one, which is why the loops work on both lists and nested lists seamlessly.
        - if there is a "," in the name, seperate it into different names
        - if there is just one name, give names as they are shown
        - After flattening, all items are guaranteed to be strings, so isinstance checks later are optional.
    - I grab all of the finishers from each drill and flatten then to allow for the ties to be grabbed. If the predicted player appears anywhere in the drill results, give 1 point.
        - drill_results is a dictionary of place → list of players.
        - drill_results.values() iterates over all ranks (1st, 2nd, 3rd, etc.)
        - drill_results.values() → [["Player A"], ["Player B, Player C"], [["Player D"], "Player E"]]. So place_players loops over each place’s list of players.
        - for p in flatten(place_players) → flatten the list to get individual player names: ["Player B, Player C"] → "Player B", "Player C", [["Player D"], "Player E"] → "Player D", "Player E"
        - if isinstance(p, str) and predicted_name == p.strip().lower(). if isinstance(p, str) and predicted_name == p.strip().lower(). Compares normalized predicted name to actual player name
        - points += 1 → award 1 point for appearing in top 3 (any place)
        - break → stop checking this place once a match is found
    - I grab a list of players at a specific place. I flatten and normalize. I then check to see if the predicted player at the place matches the actual player in that place. 
        - place is the predicted rank, used to fetch the actual players at that place.
        - Uses self.place to get the predicted rank.
        - drill_results.get(place, []) → retrieves the list of players at the predicted place only.
        - if predicted_name in actual_flat: → checks if the predicted player matches the exact place.
        - it uses the numeric place from the prediction to directly index into drill_results.
    - I return total points


