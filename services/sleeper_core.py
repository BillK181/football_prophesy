import requests
import os
import json
import time

# =========================
# CACHE (PLAYERS)
# =========================

PLAYERS_CACHE_FILE = "players_cache.json"
CACHE_TTL = 60 * 60 * 24  # 24 hours


# =========================
# USER
# =========================

def get_user(username):
    res = requests.get(f"https://api.sleeper.app/v1/user/{username}")
    if res.status_code != 200:
        return None
    return res.json()


def get_user_id(user):
    return user.get("user_id")


def get_username(user):
    return user.get("username")


# =========================
# LEAGUE
# =========================

def get_user_leagues(user_id, year):
    res = requests.get(
        f"https://api.sleeper.app/v1/user/{user_id}/leagues/nfl/{year}"
    )
    return res.json() or []


def get_league_users(league_id):
    res = requests.get(
        f"https://api.sleeper.app/v1/league/{league_id}/users"
    )
    return res.json() or []


# =========================
# ROSTERS
# =========================

def get_roster(league_id):
    res = requests.get(
        f"https://api.sleeper.app/v1/league/{league_id}/rosters"
    )
    return res.json() or []


def get_roster_id(rosters, user_id):
    for r in rosters:
        if r.get("owner_id") == user_id:
            return r.get("roster_id")
    return None


# =========================
# TEAM INFO
# =========================

def get_team_info(rosters, league_users, roster_id):
    owner_id = None

    for r in rosters:
        if r.get("roster_id") == roster_id:
            owner_id = r.get("owner_id")
            break

    if not owner_id:
        return None

    for u in league_users:
        if u.get("user_id") == owner_id:
            return {
                "username": u.get("username"),
                "display_name": u.get("display_name"),
                "team_name": (u.get("metadata") or {}).get("team_name"),
                "avatar": u.get("avatar")
            }

    return None


# =========================
# NFL STATE
# =========================

def get_week():
    res = requests.get("https://api.sleeper.app/v1/state/nfl")
    return res.json().get("week")


# =========================
# MATCHUPS
# =========================

def get_matchups(league_id, week):
    res = requests.get(
        f"https://api.sleeper.app/v1/league/{league_id}/matchups/{week}"
    )
    return res.json() or []


def get_matchup_id(matchups, roster_id):
    for m in matchups:
        if m.get("roster_id") == roster_id:
            return m.get("matchup_id")
    return None


def get_matchup_teams(matchups, matchup_id):
    teams = {}

    for m in matchups:
        if m.get("matchup_id") == matchup_id:
            teams[m.get("roster_id")] = m.get("starters", [])

    return teams


def get_starter_points(matchups, matchup_id):
    points = []

    for m in matchups:
        if m.get("matchup_id") == matchup_id:
            roster_id = m.get("roster_id")

            for player_id, score in (m.get("players_points") or {}).items():
                points.append([roster_id, player_id, score])

    return points


# =========================
# PLAYERS (CACHED)
# =========================

def get_players():
    if os.path.exists(PLAYERS_CACHE_FILE):
        with open(PLAYERS_CACHE_FILE, "r") as f:
            cache = json.load(f)

        if time.time() - cache.get("timestamp", 0) < CACHE_TTL:
            return cache.get("data", {})

    res = requests.get("https://api.sleeper.app/v1/players/nfl")
    data = res.json()

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


# =========================
# BUILD MATCHUP OUTPUT
# =========================

def get_players_in_matchup(players, matchup_teams, starter_points, rosters, league_users):
    matchup_players = {}

    # FIXED: safer mapping
    points_map = {}
    for roster_id, player_id, points in starter_points:
        points_map[player_id] = [roster_id, points]

    for roster_id, starters in matchup_teams.items():

        team_info = get_team_info(rosters, league_users, roster_id)
        if not team_info:
            continue

        matchup_players[roster_id] = {
            "team_info": team_info,
            "players": []
        }

        for player_id in starters:

            if not player_id or player_id in ["0", "IR", "BN"]:
                continue

            player = players.get(player_id)
            if not player:
                continue

            # FIXED: safe name build
            first = player.get("first_name") or ""
            last = player.get("last_name") or ""
            full_name = f"{first} {last}".strip()

            nfl_team = player.get("team") or ""

            _, score = points_map.get(player_id, [None, 0])

            matchup_players[roster_id]["players"].append({
                "name": full_name,
                "team": nfl_team,
                "points": score
            })

    return matchup_players