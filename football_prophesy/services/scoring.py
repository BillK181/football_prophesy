# services/scoring.py

from data.combine_results import ACTUAL_COMBINE_RESULTS
from data.combine_map import POSITION_DRILL_MAP
from data.free_agency_results import FREE_AGENCY_RESULTS


# -------------------------
# Scouting Combine Points
# -------------------------
def combine_points(user, year=2026, position_drill_map=None):
    """Calculate total scouting combine points for a user in a given year."""

    if position_drill_map is None:
        position_drill_map = POSITION_DRILL_MAP

    points = 0

    for pred in user.predictions:

        if pred.section != "scouting_combine":
            continue

        if pred.year != year:
            continue

        points += pred.calculate_points(
            ACTUAL_COMBINE_RESULTS,
            position_drill_map
        )

    return points


# -------------------------
# Free Agency Points
# -------------------------
def free_agency_points(user, year=2026):
    """Calculate total free agency points for a user in a given year."""

    points = 0

    for pred in user.predictions:

        if pred.section != "free_agency":
            continue

        if pred.year != year:
            continue

        actual = FREE_AGENCY_RESULTS.get(pred.player_name, {})

        # Team prediction
        if pred.team_prediction and actual.get("team") == pred.team_prediction:
            points += 5

        # Salary prediction
        if pred.salary_prediction and actual.get("salary") == pred.salary_prediction:
            points += 5

    return points


# -------------------------
# Total Points
# -------------------------
def total_points(user, year=2026, section=None, position_drill_map=None):
    """
    Calculate total points for a user.

    section=None → overall leaderboard
    section="scouting_combine" → combine leaderboard
    section="free_agency" → free agency leaderboard
    """

    if section == "scouting_combine":
        return combine_points(user, year, position_drill_map)

    if section == "free_agency":
        return free_agency_points(user, year)

    # Overall score
    return (
        combine_points(user, year, position_drill_map)
        + free_agency_points(user, year)
    )


# -------------------------
# Ranking
# -------------------------
def rank(user, users, year=2026):
    """
    Return the user's rank among all users.
    'users' must be passed in to avoid circular imports.
    """

    my_points = total_points(user, year)

    better_users = [
        u for u in users
        if total_points(u, year) > my_points
    ]

    return len(better_users) + 1


# -------------------------
# Leaderboards
# -------------------------
def leaderboard(users, year=2026, section=None):
    """
    Universal leaderboard generator.

    section=None → overall leaderboard
    section="scouting_combine" → combine leaderboard
    section="free_agency" → free agency leaderboard
    """

    ranked = sorted(
        [
            {
                "user": user,
                "score": total_points(user, year, section=section)
            }
            for user in users
        ],
        key=lambda entry: entry["score"],
        reverse=True
    )

    return ranked