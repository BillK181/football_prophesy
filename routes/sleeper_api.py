from flask import Blueprint, request, jsonify
from flask_cors import CORS

from football_prophesy.services.sleeper_core import *

sleeper_api = Blueprint("sleeper_api", __name__)

# Enable CORS for this blueprint (fixes frontend fetch issues)
CORS(sleeper_api)


# =========================
# GET LEAGUES
# =========================
@sleeper_api.route("/sleeper/leagues", methods=["GET"])
def leagues():

    username = request.args.get("username")
    if not username:
        return jsonify({"error": "username required"}), 400

    user = get_user(username)
    if not user:
        return jsonify({"error": "user not found"}), 404

    user_id = get_user_id(user)
    year = request.args.get("year", default=2025, type=int)

    leagues_data = get_user_leagues(user_id, year) or []

    simplified = [
        {
            "name": l.get("name"),
            "league_id": l.get("league_id"),
            "total_rosters": l.get("total_rosters")
        }
        for l in leagues_data
        if l
    ]

    return jsonify(simplified), 200


# =========================
# GET MATCHUP
# =========================
@sleeper_api.route("/sleeper/matchup", methods=["GET"])
def matchup():

    try:
        username = request.args.get("username")
        league_id = request.args.get("league_id")
        week = request.args.get("week", type=int)
        teams_raw = request.args.getlist("team")

        if not username or not league_id:
            return jsonify({"error": "username and league_id required"}), 400

        # -------------------------
        # USER
        # -------------------------
        user = get_user(username)
        if not user:
            return jsonify({"error": "user not found"}), 404

        sleeper_id = get_user_id(user)

        # -------------------------
        # LEAGUE DATA
        # -------------------------
        league_users = get_league_users(league_id) or []
        roster_data = get_roster(league_id) or []

        roster_id = get_roster_id(roster_data, sleeper_id)
        if not roster_id:
            return jsonify({"error": "roster not found"}), 404

        # -------------------------
        # WEEK / MATCHUP
        # -------------------------
        if not week:
            week = get_week()

        matchups = get_matchups(league_id, week) or []

        matchup_id = get_matchup_id(matchups, roster_id)
        if not matchup_id:
            return jsonify({"error": "no matchup found (bye week?)"}), 404

        starter_points = get_starter_points(matchups, matchup_id)
        matchup_teams = get_matchup_teams(matchups, matchup_id)

        # -------------------------
        # PLAYERS
        # -------------------------
        players = get_players()
        if not players:
            return jsonify({"error": "failed to load players"}), 500

        matchup_players = get_players_in_matchup(
            players,
            matchup_teams,
            starter_points,
            roster_data,
            league_users
        )

        # -------------------------
        # TEAM FILTERING (FIXED)
        # -------------------------
        if teams_raw:
            teams = []
            for t in teams_raw:
                teams.extend(t.split(","))
            teams = [t.strip().lower() for t in teams if t.strip()]

            for r_id, data in matchup_players.items():
                data["players"] = [
                    p for p in data.get("players", [])
                    if p.get("team") and p["team"].lower() in teams
                ]

        return jsonify(matchup_players), 200

    except Exception as e:
        # Catch-all safety so frontend never hangs or gets HTML errors
        return jsonify({"error": "internal server error", "details": str(e)}), 500