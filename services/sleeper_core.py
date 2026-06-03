import requests
import os
import json
import time
from datetime import datetime

PLAYERS_CACHE_FILE = "players_cache.json"
CACHE_TTL = 60 * 60 * 24 


# =========================
# USER
# =========================

# Get User Object From Requested Input
def get_user(username):
    sleeper_user = requests.get(f"https://api.sleeper.app/v1/user/{username}")
    if sleeper_user.status_code != 200:
        print("User Not Found")
        return None
    return sleeper_user.json()

# Get Mulitple User Objects From Requested Input
def get_multiple_users(multiple_usernames):
    multiple_users = []

    for username in multiple_usernames:
        user = get_user(username)

        if user is None:
            print(f"Skipping invalid user: {username}")
            continue

        multiple_users.append(user)

    return multiple_users

# Get Username From User Object
def get_username(user):
    return user.get("username")

# Get User_ID From User Object
def get_user_id(user):
    return user.get("user_id")

# Get User_ID For Multiple Users
def get_multiple_users_ids(multiple_users):
    multiple_users_ids = []
    for user in multiple_users:
        multiple_users_ids.append(get_user_id(user))
    return multiple_users_ids


# =========================
# LEAGUE
# =========================


# Get League Objects
def get_user_leagues(user_id, year):
    league = requests.get(f"https://api.sleeper.app/v1/user/{user_id}/leagues/nfl/{year}")
    return league.json()

# Get League Objects For Multiple User_IDs
def get_multiple_users_leagues(multiple_users_ids, year):
    multiple_users_leagues = {}

    for user_id in multiple_users_ids:
        multiple_users_leagues[user_id] = get_user_leagues(user_id, year)

    return multiple_users_leagues

# Get League Name From League Object
def get_league_names(user_leagues):
    return [league.get("name") for league in user_leagues]

# Get League Names From Multiple League Objects
def get_multiple_users_league_names(multiple_users_leagues):
    multiple_users_league_names = {}

    for user_id, user_leagues in multiple_users_leagues.items():
        multiple_users_league_names[user_id] = get_league_names(user_leagues)

    return multiple_users_league_names

# Get League ID From League Object
def get_league_ids(user_leagues):
    return [league.get("league_id") for league in user_leagues]

# Get Multiple League_IDs from Mulitple League Objects
def get_multiple_users_league_ids(multiple_users_leagues):
    multiple_users_league_ids = {}

    for user_id, user_leagues in multiple_users_leagues.items():
        multiple_users_league_ids[user_id] = get_league_ids(user_leagues)

    return multiple_users_league_ids

# =========================
# ROSTER
# =========================


# Get Roster Objects From League_ID
def get_roster(league_id):
    roster = requests.get(f"https://api.sleeper.app/v1/league/{league_id}/rosters")
    return roster.json()

# Get Multiple Roster Objects From Multiple League_IDs
def get_multiple_rosters(multiple_users_league_ids):
    multiple_rosters = {}
    for user_id, league_ids in multiple_users_league_ids.items():
        multiple_rosters[user_id] = {}
        for league_id in league_ids:
            multiple_rosters[user_id][league_id] = get_roster(league_id)
    return multiple_rosters

# Get Roster_ID from Roster Object
def get_roster_id(roster, user_id):
    for team_roster in roster:
        if team_roster.get("owner_id") == user_id:
            return team_roster.get("roster_id")
    return None

# Get Multiple Roster_IDs From Multiple Roster Objects
def get_multiple_roster_ids(multiple_rosters):
    multiple_roster_ids = {}
    for user_id, leagues in multiple_rosters.items():
        multiple_roster_ids[user_id] = {}
        for league_id, roster in leagues.items():
            roster_id = get_roster_id(roster, user_id)
            multiple_roster_ids[user_id][league_id] = roster_id

    return multiple_roster_ids

# Get Owner_ID From Roster Object Using Roster_ID
def get_owner_id(rosters, roster_id):
    for roster in rosters:
        if roster["roster_id"] == roster_id:
            return roster["owner_id"]
    return None

# =========================
# LEAGUE USERS
# =========================


# Get League_Users Object (All Users In League) Using League_ID
def get_league_users(league_id):
    users = requests.get(f"https://api.sleeper.app/v1/league/{league_id}/users")
    return users.json()

# Get League_Users Object (All Users In League) For Multiple Leagues Using Multiple League_IDs
def get_multiple_users_league_users(multiple_users_league_ids):
    multiple_users_league_users = {}
    for user_id, league_ids in multiple_users_league_ids.items():
        multiple_users_league_users[user_id] = {}
        for league_id in league_ids:
            multiple_users_league_users[user_id][league_id] = (get_league_users(league_id))

    return multiple_users_league_users


# Get Username, Display_Names, Team_Name, and Avatar From League User Object
def get_team_info(rosters, league_users, roster_id):

    # Get Owner_Id From Roster_ID
    owner_id = get_owner_id(rosters, roster_id)
    if owner_id is None:
        return None

    # Find User Object For Owner_ID
    for user in league_users:
        if user["user_id"] == owner_id:

            return {
                "username": user.get("username"),
                "display_name": user.get("display_name"),
                "team_name": user.get("metadata", {}).get("team_name"),
                "avatar": user.get("avatar")
            }

    return None

# Get Multiple Usernames, Display_Namess, Team_Names, and Avatars From Multiple League User Objects
def get_multiple_team_info(multiple_rosters, multiple_league_users, multiple_roster_ids):
    result = {}
    for user_id, leagues in multiple_roster_ids.items():
        
        result[user_id] = {}

        for league_id, roster_id in leagues.items():

            # Get data from roster and league objects
            rosters = multiple_rosters[user_id][league_id]
            users = multiple_league_users[user_id][league_id]

            # Put data into function to get team info
            result[user_id][league_id] = get_team_info(rosters, users, roster_id)

    return result


# =========================
# NFL DATA
# =========================


# Get Current Week of Season
def get_week():
    nfl_object = requests.get(f"https://api.sleeper.app/v1/state/nfl").json()
    return nfl_object["week"]


# =========================
# MATCHUPS
# =========================


# Get Matchup Object Using League_ID and Week
def get_matchups(league_id, week):
    matchups = requests.get(
        f"https://api.sleeper.app/v1/league/{league_id}/matchups/{week}"
    )
    return matchups.json()

# Get Multiple Matchup Objects Using Week And Multiple League_IDs
def get_multiple_users_matchups(multiple_users_league_ids, week):

    multiple_users_matchups = {}

    for user_id, leagues in multiple_users_league_ids.items():

        multiple_users_matchups[user_id] = {}

        for league_id in leagues:
            multiple_users_matchups[user_id][league_id] = get_matchups(league_id, week)
    return multiple_users_matchups

# Get Matchup_ID Using Matchup Object and Roster_ID
def get_matchup_id(matchups, roster_id):
    for matchup in matchups:
        if matchup["roster_id"] == roster_id:
            return matchup["matchup_id"]

    return None

# Get Multiple Matchup_IDs Using Multiple Matchup Objects and Multiple Roster_IDs
def get_multiple_users_matchup_ids(multiple_users_matchups, multiple_users_roster_ids):
    multiple_users_matchup_ids = {}
    for user_id, leagues in multiple_users_matchups.items():
        multiple_users_matchup_ids[user_id] = {}

        for league_id, matchups in leagues.items():
            roster_id = multiple_users_roster_ids[user_id][league_id]
            matchup_id = get_matchup_id(matchups, roster_id)
            multiple_users_matchup_ids[user_id][league_id] = matchup_id

    return multiple_users_matchup_ids

# Get Opponents Roster_ID Using Matchup Object, Matchup_ID, And Roster_ID
def get_opponent_roster_id(matchups, matchup_id, roster_id):
    for matchup in matchups:
        if matchup["matchup_id"] == matchup_id and matchup["roster_id"] != roster_id:
            return matchup["roster_id"]
    return None

# Get A Dictionary Containing All Players and Points They Scored For Multiple Users Using Multiple Matchup Objects And Multiple Matchup IDs
# Returns { user_id: { league_id: { matchup_id: { roster_id: { "players": [ { "player_id": "...", "points": ...}]}}}}}
def get_multiple_users_player_points(multiple_users_matchups, multiple_users_matchup_ids):
    multiple_users_player_points = {}

    for user_id, leagues in multiple_users_matchups.items():
        multiple_users_player_points[user_id] = {}

        for league_id, matchups in leagues.items():
            multiple_users_player_points[user_id][league_id] = {}
            matchup_id = multiple_users_matchup_ids[user_id][league_id]

            multiple_users_player_points[user_id][league_id][matchup_id] = {}

            for matchup in matchups:

                # Using matchup_id get roster_id, all players on the team and the points they scored for that roster_id
                if matchup["matchup_id"] == matchup_id:
                    roster_id = matchup["roster_id"]
                    players = matchup.get("players", [])
                    points = matchup.get("players_points", {})

                    player_data = [
                        {
                            "player_id": player_id,
                            "points": float(points.get(player_id, 0) or 0)
                        }
                        for player_id in players
                    ]

                    multiple_users_player_points[user_id][league_id][matchup_id][roster_id] = {
                        "players": player_data
                    }

    return multiple_users_player_points

# Get The Starters For Each Team In A Matchup Using Multiple Matchup Objects
# returns { user_id: { league_id: { matchup_id: { roster_id: [starter1, starter2]}}}}
def get_multiple_users_matchup_starters(multiple_users_matchups):
    multiple_users_matchup_starters = {}

    for user_id, leagues in multiple_users_matchups.items():
        multiple_users_matchup_starters[user_id] = {}

        for league_id, matchups in leagues.items():
            multiple_users_matchup_starters[user_id][league_id] = {}

            # Using matchup_id get roster_id and a list of starters for that roster_id
            for matchup in matchups:
                matchup_id = matchup["matchup_id"]
                roster_id = matchup["roster_id"]
                starters = matchup.get("starters", [])

                # ensure structure exists
                if matchup_id not in multiple_users_matchup_starters[user_id][league_id]:
                    multiple_users_matchup_starters[user_id][league_id][matchup_id] = {}

                multiple_users_matchup_starters[user_id][league_id][matchup_id][roster_id] = starters

    return multiple_users_matchup_starters


# =========================
# PLAYERS
# =========================


# Get Player Objects Only Once Per Day
def get_players():

    # Check if cached and if less than 24 hours old
    if os.path.exists(PLAYERS_CACHE_FILE):
        with open(PLAYERS_CACHE_FILE, "r") as f:
            cache = json.load(f)

        if time.time() - cache["timestamp"] < CACHE_TTL:
            return cache["data"]

    # Otherwise fetch from API
    print("Fetching players from Sleeper API...")

    data = requests.get(
        "https://api.sleeper.app/v1/players/nfl"
    ).json()

    # Save cache
    with open(PLAYERS_CACHE_FILE, "w") as f:
        json.dump(
            {
                "timestamp": time.time(),
                "data": data
            },
            f,
            ensure_ascii=False,
            separators=(",", ":")
        )

    return data

# Get Team Info As Well As The Starters In A Matchup With Name, Team, Position, And Points
# Returns { user_id: { league_id: { matchup_id: { roster_id: { "team_info": ..., "players": [ { "name": ..., "team": ..., "position": ..., "points": ... } ] } } } } }
def get_players_in_matchup(players, multiple_users_matchup_starters, multiple_users_player_points, multiple_rosters, multiple_users_league_users):

    matchup_team_info_starter_info = {}

    for user_id, leagues in multiple_users_matchup_starters.items():
        matchup_team_info_starter_info[user_id] = {}

        for league_id, matchups in leagues.items():
            matchup_team_info_starter_info[user_id][league_id] = {}

            for matchup_id, matchup_teams in matchups.items():
                matchup_team_info_starter_info[user_id][league_id][matchup_id] = {}

                # Points map build
                points_map = {}

                # Try to get data for user_id, league_id, and matchup_id, if it doesn’t exist → return {} instead of crashing
                matchup_points_raw = (multiple_users_player_points.get(user_id, {}).get(league_id, {}).get(matchup_id, {}))

                for roster_id, data in matchup_points_raw.items():
                    
                    # Get [ { "player_id": "...", "points": ...}] from multiple_users_player_points
                    player_list = data.get("players", [])

                    for entry in player_list:
                        player_id = entry["player_id"]
                        points = entry["points"]

                        try:
                            points = float(points)
                        except:
                            points = 0.0

                        points_map[player_id] = (roster_id, points)

                # Get roster object and league users object using league id then get team info using roster_id
                for roster_id, starters in matchup_teams.items():

                    rosters = multiple_rosters[user_id][league_id]
                    league_users = multiple_users_league_users[user_id][league_id]

                    team_info = get_team_info(rosters, league_users, roster_id)

                    if not team_info:
                        continue

                    matchup_team_info_starter_info[user_id][league_id][matchup_id][roster_id] = {
                        "team_info": team_info,
                        "players": []
                    }

                    # Using Player_ID, Look Up Starters In Players Object For Name, Team, and Position
                    for player_id in starters:

                        if not player_id or player_id in ["0", "IR", "BN"]:
                            continue

                        player = players.get(player_id)
                        if not player:
                            continue

                        full_name = f"{player.get('first_name')} {player.get('last_name')}"
                        nfl_team = player.get("team")
                        position = player.get("position")

                        _, score = points_map.get(player_id, (None, 0))

                        matchup_team_info_starter_info[user_id][league_id][matchup_id][roster_id]["players"].append({
                            "name": full_name,
                            "team": nfl_team,
                            "position": position,
                            "points": score
                        })

    return matchup_team_info_starter_info


# =========================
# FILTERING
# =========================

# Get Teams Unwatched From Teams_Watched
def teams_unwatched(teams_watched_filter):
    nfl_teams = {
        "ARI", "ATL", "BAL", "BUF", "CAR", "CHI", "CIN", "CLE",
        "DAL", "DEN", "DET", "GB", "HOU", "IND", "JAX", "KC",
        "LV", "LAC", "LAR", "MIA", "MIN", "NE", "NO", "NYG",
        "NYJ", "PHI", "PIT", "SEA", "SF", "TB", "TEN", "WAS"
    }

    teams_watched_filter = {t.upper() for t in teams_watched_filter}

    # Remove watched teams
    remaining = nfl_teams - teams_watched_filter

    return list(remaining)

# Filter Players By Teams Filter, Returns A Filterd Version Of Matchup_Team_Info_Stater_Info
def filter_by_team(matchup_team_info_starter_info, teams_watched_filter):

    teams_watched_filter = set(team.lower() for team in teams_watched_filter)
    filtered_matchup_players = {}

    for user_id, leagues in matchup_team_info_starter_info.items():
        filtered_matchup_players[user_id] = {}

        for league_id, matchups in leagues.items():
            filtered_matchup_players[user_id][league_id] = {}

            for matchup_id, rosters in matchups.items():
                filtered_matchup_players[user_id][league_id][matchup_id] = {}

                for roster_id, roster_data in rosters.items():
                    filtered_players = []

                    for player in roster_data["players"]:
                        team = player.get("team")

                        if team and team.lower() in teams_watched_filter:
                            filtered_players.append(player)

                    filtered_matchup_players[user_id][league_id][matchup_id][roster_id] = {
                        "team_info": roster_data["team_info"],
                        "players": filtered_players
                    }

    return filtered_matchup_players

# Strips And Replaces Player Points With 0 for Filtered Players
def strip_scores(matchup_team_info_starter_info, teams_playing):
    teams_playing = set(team.lower() for team in teams_playing)

    stripped_matchup_players = {}

    for user_id, leagues in matchup_team_info_starter_info.items():
        stripped_matchup_players[user_id] = {}

        for league_id, matchups in leagues.items():
            stripped_matchup_players[user_id][league_id] = {}

            for matchup_id, rosters in matchups.items():
                stripped_matchup_players[user_id][league_id][matchup_id] = {}

                for roster_id, roster_data in rosters.items():
                    stripped_players = []

                    for player in roster_data["players"]:
                        team = player.get("team")

                        if team and team.lower() in teams_playing:

                            # copy player so we don't mutate original data
                            new_player = player.copy()
                            new_player["points"] = 0

                            stripped_players.append(new_player)

                    stripped_matchup_players[user_id][league_id][matchup_id][roster_id] = {
                        "team_info": roster_data["team_info"],
                        "players": stripped_players
                    }

    return stripped_matchup_players


# =========================
# PRINT
# =========================

# Build Team Data For A Roster In A Matchup
def build_team(roster_id, rosters, user_id, league_id, matchup_id, stripped_matchup_player, stripped_unwatched_player, position_order):

    team_data = rosters[roster_id]

    players = sorted(
        team_data["players"],
        key=lambda p: position_order.get(p.get("position"), 99)
    )

    team_info = team_data["team_info"]

    score = sum(p["points"] for p in players)

    stripped_players = (stripped_matchup_player.get(user_id, {}).get(league_id, {}).get(matchup_id, {}).get(roster_id, {}).get("players", []))

    unwatched_players = (stripped_unwatched_player.get(user_id, {}).get(league_id, {}).get(matchup_id, {}).get(roster_id, {}).get("players", []))

    stripped_players = sorted(stripped_players, key=lambda p: position_order.get(p.get("position"), 99))
    unwatched_players = sorted(unwatched_players, key=lambda p: position_order.get(p.get("position"), 99))

    stripped_score = sum(p["points"] for p in stripped_players)
    unwatched_score = sum(p["points"] for p in unwatched_players)

    final_score = score - stripped_score - unwatched_score

    return team_info, final_score, players, stripped_players, unwatched_players

# Print A Teams Breakdown
def print_team(team_info, score, players, stripped_players, unwatched_players, position_order):

    print(f"\n{team_info['team_name']} | {score:.2f} pts")

    for p in players:
        print(f"  {p.get('position','?')} | {p['name']} | {p['team']} | {p['points']}")

    if stripped_players:
        print("\n   ↓↓↓ CURRENTLY PLAYING ↓↓↓\n")
        for p in stripped_players:
            print(f"  {p.get('position','?')} | {p['name']} | {p['team']} | 0.0")

    if unwatched_players:
        print("\n   ↓↓↓ STILL TO PLAY ↓↓↓\n")
        for p in unwatched_players:
            print(f"  {p.get('position','?')} | {p['name']} | {p['team']} | 0.0")

# Print League Header
def print_league_header(league_name):
    print("\n------------------------------------")
    print(league_name)
    print("------------------------------------")

# Print All Matchups For All Users
def print_matchups(filtered_matchup_players, stripped_matchup_player, stripped_unwatched_player, multiple_users, multiple_users_leagues, multiple_users_matchup_ids):

    user_map = {u["user_id"]: u for u in multiple_users}

    position_order = {"QB": 0, "RB": 1, "WR": 2, "TE": 3}

    def get_league_name(user_id, league_id):
        for league in multiple_users_leagues[user_id]:
            if league["league_id"] == league_id:
                return league["name"]
        return "Unknown League"

    for user_id in sorted(filtered_matchup_players.keys()):

        user = user_map.get(user_id)
        if not user:
            continue

        print("\n\n####################################\n")
        print(get_username(user).upper())
        print("\n####################################")

        leagues = filtered_matchup_players[user_id]

        sorted_leagues = sorted(
            leagues.keys(),
            key=lambda lid: get_league_name(user_id, lid).lower()
        )

        for league_id in sorted_leagues:

            league_name = get_league_name(user_id, league_id)
            print_league_header(league_name)

            matchups = leagues[league_id]

            user_matchup_id = multiple_users_matchup_ids[user_id][league_id]
            if user_matchup_id is None:
                continue

            rosters = matchups.get(user_matchup_id)
            if not rosters or len(rosters) != 2:
                continue

            roster_ids = list(rosters.keys())
            r1, r2 = roster_ids[0], roster_ids[1]

            # TEAM 1
            t1 = build_team(
                r1, rosters, user_id, league_id, user_matchup_id,
                stripped_matchup_player, stripped_unwatched_player,
                position_order
            )

            print_team(*t1, position_order)

            # TEAM 2
            t2 = build_team(
                r2, rosters, user_id, league_id, user_matchup_id,
                stripped_matchup_player, stripped_unwatched_player,
                position_order
            )

            print_team(*t2, position_order)

# =========================
# MAIN
# =========================            


def main(multiple_usernames, teams_watched_filter, teams_playing, week, year):
    players = get_players()

    year = 2025 # For Testing, will be year = datetime.now().year once season starts

    multiple_users = get_multiple_users(multiple_usernames)

    multiple_users_ids = get_multiple_users_ids(multiple_users)

    multiple_users_leagues = get_multiple_users_leagues(multiple_users_ids, year)

    multiple_users_league_ids = get_multiple_users_league_ids(multiple_users_leagues)

    multiple_users_league_users = get_multiple_users_league_users(multiple_users_league_ids)

    multiple_rosters = get_multiple_rosters(multiple_users_league_ids)

    multiple_roster_ids = get_multiple_roster_ids(multiple_rosters)

    week = 2 # For Testing, will be getweek() once season starts

    multiple_users_matchups = get_multiple_users_matchups(multiple_users_league_ids, week)

    multiple_users_matchup_ids = get_multiple_users_matchup_ids(multiple_users_matchups, multiple_roster_ids)

    multiple_users_player_points = get_multiple_users_player_points(multiple_users_matchups, multiple_users_matchup_ids)

    multiple_users_matchup_starters = get_multiple_users_matchup_starters(multiple_users_matchups)

    matchup_team_info_starter_info = get_players_in_matchup(
        players,
        multiple_users_matchup_starters,
        multiple_users_player_points,
        multiple_rosters,
        multiple_users_league_users
    )

    unwatched_teams = teams_unwatched(teams_watched_filter)

    filtered_matchup_players = filter_by_team(
        matchup_team_info_starter_info,
        teams_watched_filter
    )

    stripped_matchup_player = strip_scores(
        matchup_team_info_starter_info,
        teams_playing
    )

    stripped_unwatched_player = strip_scores(
        matchup_team_info_starter_info,
        unwatched_teams
    )

    # =========================
    # NEW: STRUCTURED OUTPUT
    # =========================

    user_map = {u["user_id"]: u for u in multiple_users}

    result = {
        "users": {}
    }

    position_order = {"QB": 0, "RB": 1, "WR": 2, "TE": 3}

    for user_id, leagues in filtered_matchup_players.items():

        user_obj = user_map.get(user_id, {})

        result["users"][user_id] = {
            "username": user_obj.get("username"),
            "display_name": user_obj.get("display_name"),
            "leagues": {}
        }

        for league_id, matchups in leagues.items():

            user_matchup_id = multiple_users_matchup_ids[user_id].get(league_id)
            if user_matchup_id is None:
                continue

            rosters = matchups.get(user_matchup_id)
            if not rosters or len(rosters) != 2:
                continue

            roster_ids = list(rosters.keys())
            r1, r2 = roster_ids[0], roster_ids[1]

            team1 = build_team(
                r1, rosters, user_id, league_id, user_matchup_id,
                stripped_matchup_player,
                stripped_unwatched_player,
                position_order
            )

            team2 = build_team(
                r2, rosters, user_id, league_id, user_matchup_id,
                stripped_matchup_player,
                stripped_unwatched_player,
                position_order
            )

            def pack(team_tuple):
                team_info, score, players, stripped_players, unwatched_players = team_tuple

                scored_players = [
                    {
                        "name": p["name"],
                        "team": p["team"],
                        "position": p["position"],
                        "points": p["points"]
                    }
                    for p in players
                    if float(p.get("points", 0) or 0) > 0
                ]

                return {
                    "team_name": team_info["team_name"],
                    "score": round(score, 2),
                    "scored_players": scored_players,
                    "currently_playing": stripped_players,
                    "still_to_play": unwatched_players
                }

            league_name = next(
                (l.get("name") for l in multiple_users_leagues[user_id] if l.get("league_id") == league_id),
                "Unknown League"
            )

            result["users"][user_id]["leagues"][league_id] = {
                "league_name": league_name,
                "matchup_id": user_matchup_id,
                "teams": [
                    pack(team1),
                    pack(team2)
                ]
            }

    return result