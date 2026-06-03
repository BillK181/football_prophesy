from flask import Blueprint, request, jsonify
import io
import sys

from ..services.sleeper_core import main

sleeper_api = Blueprint("sleeper_api", __name__)


@sleeper_api.route("/run", methods=["POST"])
def run():
    data = request.get_json()

    multiple_usernames = data.get("multiple_usernames", [])
    teams_watched_filter = data.get("teams_watched_filter", [])
    teams_playing = data.get("teams_playing", [])
    week = data.get("week", None)
    year = data.get("year", None)

    result = main(
        multiple_usernames,
        teams_watched_filter,
        teams_playing,
        week,
        year
    )

    return jsonify({
        "status": "success",
        "data": result
    })