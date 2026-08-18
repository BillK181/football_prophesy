from football_prophesy.extensions import db
from football_prophesy.models.team import Team


TEAMS = [
    # AFC
    {
        "id": 1,
        "name": "Buffalo Bills",
        "city": "Buffalo",
        "abrv": "BUF",
        "playoff_points": 20,
    },
    {
        "id": 2,
        "name": "Baltimore Ravens",
        "city": "Baltimore",
        "abrv": "BAL",
        "playoff_points": 20,
    },
    {
        "id": 3,
        "name": "New England Patriots",
        "city": "New England",
        "abrv": "NE",
        "playoff_points": 22,
    },
    {
        "id": 4,
        "name": "Cincinnati Bengals",
        "city": "Cincinnati",
        "abrv": "CIN",
        "playoff_points": 23,
    },
    {
        "id": 5,
        "name": "Kansas City Chiefs",
        "city": "Kansas City",
        "abrv": "KC",
        "playoff_points": 23,
    },
    {
        "id": 6,
        "name": "Los Angeles Chargers",
        "city": "Los Angeles",
        "abrv": "LAC",
        "playoff_points": 24,
    },
    {
        "id": 7,
        "name": "Houston Texans",
        "city": "Houston",
        "abrv": "HOU",
        "playoff_points": 25,
    },
    {
        "id": 8,
        "name": "Denver Broncos",
        "city": "Denver",
        "abrv": "DEN",
        "playoff_points": 26,
    },
    {
        "id": 9,
        "name": "Jacksonville Jaguars",
        "city": "Jacksonville",
        "abrv": "JAX",
        "playoff_points": 29,
    },
    {
        "id": 10,
        "name": "Pittsburgh Steelers",
        "city": "Pittsburgh",
        "abrv": "PIT",
        "playoff_points": 39,
    },
    {
        "id": 11,
        "name": "Indianapolis Colts",
        "city": "Indianapolis",
        "abrv": "IND",
        "playoff_points": 41,
    },
    {
        "id": 12,
        "name": "Tennessee Titans",
        "city": "Tennessee",
        "abrv": "TEN",
        "playoff_points": 75,
    },
    {
        "id": 13,
        "name": "Las Vegas Raiders",
        "city": "Las Vegas",
        "abrv": "LV",
        "playoff_points": 93,
    },
    {
        "id": 14,
        "name": "Cleveland Browns",
        "city": "Cleveland",
        "abrv": "CLE",
        "playoff_points": 120,
    },
    {
        "id": 15,
        "name": "New York Jets",
        "city": "New York",
        "abrv": "NYJ",
        "playoff_points": 128,
    },
    {
        "id": 16,
        "name": "Miami Dolphins",
        "city": "Miami",
        "abrv": "MIA",
        "playoff_points": 240,
    },

    # NFC
    {
        "id": 17,
        "name": "Los Angeles Rams",
        "city": "Los Angeles",
        "abrv": "LAR",
        "playoff_points": 18,
    },
    {
        "id": 18,
        "name": "Detroit Lions",
        "city": "Detroit",
        "abrv": "DET",
        "playoff_points": 22,
    },
    {
        "id": 19,
        "name": "Seattle Seahawks",
        "city": "Seattle",
        "abrv": "SEA",
        "playoff_points": 23,
    },
    {
        "id": 20,
        "name": "San Francisco 49ers",
        "city": "San Francisco",
        "abrv": "SF",
        "playoff_points": 25,
    },
    {
        "id": 21,
        "name": "Philadelphia Eagles",
        "city": "Philadelphia",
        "abrv": "PHI",
        "playoff_points": 25,
    },
    {
        "id": 22,
        "name": "Green Bay Packers",
        "city": "Green Bay",
        "abrv": "GB",
        "playoff_points": 28,
    },
    {
        "id": 23,
        "name": "Dallas Cowboys",
        "city": "Dallas",
        "abrv": "DAL",
        "playoff_points": 29,
    },
    {
        "id": 24,
        "name": "Chicago Bears",
        "city": "Chicago",
        "abrv": "CHI",
        "playoff_points": 31,
    },
    {
        "id": 25,
        "name": "Tampa Bay Buccaneers",
        "city": "Tampa Bay",
        "abrv": "TB",
        "playoff_points": 37,
    },
    {
        "id": 26,
        "name": "Minnesota Vikings",
        "city": "Minnesota",
        "abrv": "MIN",
        "playoff_points": 38,
    },
    {
        "id": 27,
        "name": "New Orleans Saints",
        "city": "New Orleans",
        "abrv": "NO",
        "playoff_points": 41,
    },
    {
        "id": 28,
        "name": "Atlanta Falcons",
        "city": "Atlanta",
        "abrv": "ATL",
        "playoff_points": 48,
    },
    {
        "id": 29,
        "name": "Washington Commanders",
        "city": "Washington",
        "abrv": "WAS",
        "playoff_points": 48,
    },
    {
        "id": 30,
        "name": "Carolina Panthers",
        "city": "Carolina",
        "abrv": "CAR",
        "playoff_points": 50,
    },
    {
        "id": 31,
        "name": "New York Giants",
        "city": "New York",
        "abrv": "NYG",
        "playoff_points": 56,
    },
    {
        "id": 32,
        "name": "Arizona Cardinals",
        "city": "Arizona",
        "abrv": "ARI",
        "playoff_points": 315,
    },
]


def seed_teams():
    for team_data in TEAMS:

        team = Team.query.filter_by(
            id=team_data["id"]
        ).first()

        if not team:
            team = Team(
                id=team_data["id"],
                name=team_data["name"],
                city=team_data["city"],
                abrv=team_data["abrv"],
                playoff_points=team_data["playoff_points"],
                season_prediction=[]
            )

            db.session.add(team)

        else:
            team.name = team_data["name"]
            team.city = team_data["city"]
            team.abrv = team_data["abrv"]
            team.playoff_points = team_data["playoff_points"]

    db.session.commit()