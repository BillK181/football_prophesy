// ==========================================
// NFL TEAMS
// ==========================================

const teams = [
    {
        id: 1,
        name: "Patriots",
        city: "New England",
        abrv: "NE",
        playoff_points: 22
    },
    {
        id: 2,
        name: "Ravens",
        city: "Baltimore",
        abrv: "BAL",
        playoff_points: 20
    },
    {
        id: 3,
        name: "Bills",
        city: "Buffalo",
        abrv: "BUF",
        playoff_points: 20
    },
    {
        id: 4,
        name: "Bengals",
        city: "Cincinnati",
        abrv: "CIN",
        playoff_points: 23
    },
    {
        id: 5,
        name: "Chiefs",
        city: "Kansas City",
        abrv: "KC",
        playoff_points: 23
    },
    {
        id: 6,
        name: "Chargers",
        city: "Los Angeles",
        abrv: "LAC",
        playoff_points: 24
    },
    {
        id: 7,
        name: "Texans",
        city: "Houston",
        abrv: "HOU",
        playoff_points: 25
    },
    {
        id: 8,
        name: "Broncos",
        city: "Denver",
        abrv: "DEN",
        playoff_points: 26
    },
    {
        id: 9,
        name: "Jaguars",
        city: "Jacksonville",
        abrv: "JAX",
        playoff_points: 29
    },
    {
        id: 10,
        name: "Steelers",
        city: "Pittsburgh",
        abrv: "PIT",
        playoff_points: 39
    },
    {
        id: 11,
        name: "Colts",
        city: "Indianapolis",
        abrv: "IND",
        playoff_points: 41
    },
    {
        id: 12,
        name: "Titans",
        city: "Tennessee",
        abrv: "TEN",
        playoff_points: 75
    },
    {
        id: 13,
        name: "Raiders",
        city: "Las Vegas",
        abrv: "LV",
        playoff_points: 93
    },
    {
        id: 14,
        name: "Browns",
        city: "Cleveland",
        abrv: "CLE",
        playoff_points: 120
    },
    {
        id: 15,
        name: "Jets",
        city: "New York",
        abrv: "NYJ",
        playoff_points: 128
    },
    {
        id: 16,
        name: "Dolphins",
        city: "Miami",
        abrv: "MIA",
        playoff_points: 240
    },
    {
        id: 17,
        name: "Rams",
        city: "Los Angeles",
        abrv: "LAR",
        playoff_points: 18
    },
    {
        id: 18,
        name: "Lions",
        city: "Detroit",
        abrv: "DET",
        playoff_points: 22
    },
    {
        id: 19,
        name: "Seahawks",
        city: "Seattle",
        abrv: "SEA",
        playoff_points: 23
    },
    {
        id: 20,
        name: "49ers",
        city: "San Francisco",
        abrv: "SF",
        playoff_points: 25
    },
    {
        id: 21,
        name: "Eagles",
        city: "Philadelphia",
        abrv: "PHI",
        playoff_points: 25
    },
    {
        id: 22,
        name: "Packers",
        city: "Green Bay",
        abrv: "GB",
        playoff_points: 28
    },
    {
        id: 23,
        name: "Cowboys",
        city: "Dallas",
        abrv: "DAL",
        playoff_points: 29
    },
    {
        id: 24,
        name: "Bears",
        city: "Chicago",
        abrv: "CHI",
        playoff_points: 31
    },
    {
        id: 25,
        name: "Buccaneers",
        city: "Tampa Bay",
        abrv: "TB",
        playoff_points: 37
    },
    {
        id: 26,
        name: "Vikings",
        city: "Minnesota",
        abrv: "MIN",
        playoff_points: 38
    },
    {
        id: 27,
        name: "Saints",
        city: "New Orleans",
        abrv: "NO",
        playoff_points: 41
    },
    {
        id: 28,
        name: "Falcons",
        city: "Atlanta",
        abrv: "ATL",
        playoff_points: 48
    },
    {
        id: 29,
        name: "Commanders",
        city: "Washington",
        abrv: "WAS",
        playoff_points: 48
    },
    {
        id: 30,
        name: "Panthers",
        city: "Carolina",
        abrv: "CAR",
        playoff_points: 50
    },
    {
        id: 31,
        name: "Giants",
        city: "New York",
        abrv: "NYG",
        playoff_points: 56
    },
    {
        id: 32,
        name: "Cardinals",
        city: "Arizona",
        abrv: "ARI",
        playoff_points: 315
    }
];


// ==========================================
// WAIT FOR PAGE TO LOAD
// ==========================================

document.addEventListener("DOMContentLoaded", () => {

    // ==========================================
    // STORE PLAYERS
    // ==========================================

    let players = [];

    const selectedPlayers = [];


    // ==========================================
    // GET PLAYERS FROM DATABASE
    // ==========================================

    fetch("/season_predictions/players")

        .then(response => response.json())

        .then(data => {

            players = data;

            console.log(players);
            console.log(`Loaded ${players.length} players`);


            // ==========================================
            // PLAYER SEARCH
            // ==========================================

            const searches =
                document.querySelectorAll(
                    ".player-search"
                );


            searches.forEach(search => {

                const playerSearchContainer =
                    search.closest(
                        ".player-search-container"
                    );


                const suggestions =
                    playerSearchContainer.querySelector(
                        ".search-results"
                    );


                const hiddenInput =
                    playerSearchContainer.querySelector(
                        "input[type='hidden']"
                    );


                // ==========================================
                // PLAYER INPUT
                // ==========================================

                search.addEventListener(
                    "input",
                    () => {

                        const value =
                            search.value
                                .trim()
                                .toLowerCase();


                        suggestions.innerHTML = "";


                        if (value === "") {

                            hiddenInput.value = "";

                            return;

                        }


                        const matches =
                            players.filter(
                                player => {

                                    return (
                                        player.name
                                            ?.toLowerCase()
                                            .includes(value)
                                    );

                                }
                            );


                        // ==========================================
                        // CREATE PLAYER SUGGESTIONS
                        // ==========================================

                        matches.forEach(
                            player => {

                                const div =
                                    document.createElement(
                                        "div"
                                    );


                                div.textContent =
                                    `${player.name} (${player.team || "FA"})`;


                                div.addEventListener(
                                    "click",
                                    () => {

                                        const previousId =
                                            hiddenInput.value;


                                        const index =
                                            selectedPlayers.indexOf(
                                                previousId
                                            );


                                        if (index !== -1) {

                                            selectedPlayers.splice(
                                                index,
                                                1
                                            );

                                        }


                                        search.value =
                                            player.name;


                                        hiddenInput.value =
                                            player.id;


                                        if (
                                            !selectedPlayers.includes(
                                                String(player.id)
                                            )
                                        ) {

                                            selectedPlayers.push(
                                                String(player.id)
                                            );

                                        }


                                        suggestions.innerHTML =
                                            "";

                                    }
                                );


                                suggestions.appendChild(
                                    div
                                );

                            }
                        );

                    }
                );

            });


            // ==========================================
            // TEAM SEARCH
            // ==========================================

            const teamSearches =
                document.querySelectorAll(
                    ".team-search"
                );


            teamSearches.forEach(search => {

                // ==========================================
                // FIND PREDICTION CARD
                // ==========================================

                const predictionCard =
                    search.closest(
                        ".prediction-card"
                    );


                // ==========================================
                // FIND PREDICTION TITLE
                // ==========================================

                const predictionLabel =
                    predictionCard.querySelector(
                        ".predictions-label label"
                    );


                const predictionTitle =
                    predictionLabel
                        ? predictionLabel.textContent
                            .trim()
                            .toLowerCase()
                        : "";


                // ==========================================
                // FIND SEARCH CONTAINER
                // ==========================================

                const teamSearchContainer =
                    search.closest(
                        ".team-search-container"
                    );


                const suggestions =
                    teamSearchContainer.querySelector(
                        ".search-results"
                    );


                const hiddenInput =
                    teamSearchContainer.querySelector(
                        "input[type='hidden']"
                    );


                // ==========================================
                // LOAD EXISTING TEAM PREDICTION
                // ==========================================

                const existingTeam =
                    search.dataset.existingTeam;


                if (existingTeam) {

                    const existingTeamId =
                        Number(existingTeam);


                    const existingTeamObject =
                        teams.find(
                            team =>
                                team.id === existingTeamId
                        );


                    if (existingTeamObject) {

                        search.value =
                            `${existingTeamObject.city} ${existingTeamObject.name}`;

                        hiddenInput.value =
                            existingTeamObject.id;

                    }

                }


                // ==========================================
                // PLAYOFF PREDICTION?
                // ==========================================

                const isAfcPlayoffPrediction =
                    predictionTitle.includes(
                        "pick 2 afc teams"
                    );


                const isNfcPlayoffPrediction =
                    predictionTitle.includes(
                        "pick 2 nfc teams"
                    );


                const isPlayoffPrediction =
                    isAfcPlayoffPrediction ||
                    isNfcPlayoffPrediction;


                // ==========================================
                // DUPLICATE-PROHIBITED PREDICTION?
                // ==========================================

                const preventsDuplicateTeams =
                    predictionTitle.includes(
                        "pick 2 afc teams"
                    ) ||
                    predictionTitle.includes(
                        "pick 2 nfc teams"
                    ) ||
                    predictionTitle.includes(
                        "afc championship matchup"
                    ) ||
                    predictionTitle.includes(
                        "nfc championship matchup"
                    ) ||
                    predictionTitle.includes(
                        "super bowl matchup"
                    );


                // ==========================================
                // DETERMINE AFC / NFC
                // ==========================================

                const afcTeams = [
                    1, 2, 3, 4, 5, 6, 7, 8,
                    9, 10, 11, 12, 13, 14, 15, 16
                ];


                const nfcTeams = [
                    17, 18, 19, 20, 21, 22, 23, 24,
                    25, 26, 27, 28, 29, 30, 31, 32
                ];

                const divisions = {
                    afc_east_champion: [1, 3, 15, 16],
                    afc_north_champion: [2, 4, 10, 14],
                    afc_south_champion: [7, 9, 11, 12],
                    afc_west_champion: [5, 6, 8, 13],

                    nfc_east_champion: [21, 23, 29, 31],
                    nfc_north_champion: [18, 22, 24, 26],
                    nfc_south_champion: [25, 27, 28, 30],
                    nfc_west_champion: [17, 19, 20, 32]
                };


                // ==========================================
                // SHOW TEAM RESULTS
                // ==========================================

                function showTeamResults(
                    searchValue = ""
                ) {

                    suggestions.innerHTML = "";


                    const value =
                        searchValue
                            .trim()
                            .toLowerCase();


                    // ==========================================
                    // FIND MATCHING TEAMS
                    // ==========================================

                    let matches =
                        teams.filter(team => {

                            // ==========================================
                            // AFC / NFC FILTER
                            // ==========================================

                            if (
                                predictionTitle.includes("afc") &&
                                !predictionTitle.includes("nfc")
                            ) {

                                if (
                                    !afcTeams.includes(
                                        team.id
                                    )
                                ) {

                                    return false;

                                }

                            }


                            if (
                                predictionTitle.includes("nfc") &&
                                !predictionTitle.includes("afc")
                            ) {

                                if (
                                    !nfcTeams.includes(
                                        team.id
                                    )
                                ) {

                                    return false;

                                }

                            }

                            // ==========================================
                            // DIVISION FILTER
                            // ==========================================

                            const divisionKey =
                                Object.keys(divisions).find(
                                    division =>
                                        predictionTitle.includes(
                                            division.replaceAll("_", " ")
                                        )
                                );


                            if (divisionKey) {

                                if (
                                    !divisions[divisionKey].includes(
                                        team.id
                                    )
                                ) {

                                    return false;

                                }

                            }


                            // ==========================================
                            // DO NOT SHOW ALREADY SELECTED TEAMS
                            // ==========================================

                            if (
                                preventsDuplicateTeams
                            ) {

                                const selectedTeamIds =
                                    Array.from(
                                        predictionCard.querySelectorAll(
                                            "input[type='hidden']"
                                        )
                                    )
                                    .filter(
                                        input =>
                                            input !== hiddenInput
                                    )
                                    .map(
                                        input =>
                                            Number(input.value)
                                    );


                                if (
                                    selectedTeamIds.includes(
                                        team.id
                                    )
                                ) {

                                    return false;

                                }

                            }


                            // ==========================================
                            // SEARCH FILTER
                            // ==========================================

                            if (value === "") {

                                return true;

                            }


                            const nameMatch =
                                team.name
                                    .toLowerCase()
                                    .includes(value);


                            const cityMatch =
                                team.city
                                    .toLowerCase()
                                    .includes(value);


                            const abbreviationMatch =
                                team.abrv
                                    .toLowerCase()
                                    .includes(value);


                            return (
                                nameMatch ||
                                cityMatch ||
                                abbreviationMatch
                            );

                        });


                    // ==========================================
                    // SORT PLAYOFF TEAMS BY POINTS
                    // ==========================================

                    if (isPlayoffPrediction) {

                        matches.sort(
                            (teamA, teamB) =>
                                teamA.playoff_points -
                                teamB.playoff_points
                        );

                    }


                    // ==========================================
                    // CREATE TEAM SUGGESTIONS
                    // ==========================================

                    matches.forEach(team => {

                        const div =
                            document.createElement(
                                "div"
                            );


                        const fullName =
                            `${team.city} ${team.name}`;


                        // ==========================================
                        // PLAYOFF TEAM DISPLAY
                        // ==========================================

                        if (isPlayoffPrediction) {

                            div.style.fontSize =
                                "14px";


                            const teamName =
                                document.createElement(
                                    "span"
                                );


                            teamName.textContent =
                                team.name;


                            const pointsText =
                                document.createElement(
                                    "span"
                                );


                            pointsText.textContent =
                                ` : ${team.playoff_points} Points`;


                            pointsText.style.fontWeight =
                                "bold";


                            pointsText.style.color =
                                "#d9b00e";


                            div.appendChild(
                                teamName
                            );


                            div.appendChild(
                                pointsText
                            );

                        }

                        else {

                            div.textContent =
                                fullName;

                        }


                        // ==========================================
                        // TEAM CLICK
                        // ==========================================

                        div.addEventListener(
                            "click",
                            () => {

                                // ==========================================
                                // PREVENT DUPLICATE TEAM
                                // ==========================================

                                if (
                                    preventsDuplicateTeams
                                ) {

                                    const allHiddenInputs =
                                        predictionCard.querySelectorAll(
                                            "input[type='hidden']"
                                        );


                                    const alreadySelected =
                                        Array.from(
                                            allHiddenInputs
                                        )
                                        .some(
                                            input =>
                                                input !== hiddenInput &&
                                                Number(input.value) ===
                                                team.id
                                        );


                                    if (
                                        alreadySelected
                                    ) {

                                        alert(
                                            "⚠️ You cannot select the same team twice."
                                        );

                                        return;

                                    }

                                }


                                // ==========================================
                                // PLAYOFF PREDICTIONS
                                // ==========================================

                                if (
                                    isPlayoffPrediction
                                ) {

                                    search.value =
                                        `${team.name} : ${team.playoff_points} Points`;

                                }

                                // ==========================================
                                // ALL OTHER TEAM PREDICTIONS
                                // ==========================================

                                else {

                                    search.value =
                                        fullName;

                                }


                                // ==========================================
                                // STORE NUMERIC TEAM ID
                                // ==========================================

                                hiddenInput.value =
                                    team.id;


                                console.log(
                                    `Selected team: ${fullName} (ID: ${team.id})`
                                );


                                // ==========================================
                                // CLEAR RESULTS
                                // ==========================================

                                suggestions.innerHTML =
                                    "";

                            }
                        );


                        suggestions.appendChild(
                            div
                        );

                    });

                }


                // ==========================================
                // CLICK SEARCH BAR
                // ==========================================

                search.addEventListener(
                    "click",
                    () => {

                        showTeamResults(
                            search.value
                        );

                    }
                );


                // ==========================================
                // TYPE IN SEARCH BAR
                // ==========================================

                search.addEventListener(
                    "input",
                    () => {

                        showTeamResults(
                            search.value
                        );

                    }
                );


                // ==========================================
                // CLEAR RESULTS WHEN FOCUS IS LOST
                // ==========================================

                search.addEventListener(
                    "blur",
                    () => {

                        setTimeout(
                            () => {

                                suggestions.innerHTML =
                                    "";

                            },
                            200
                        );

                    }
                );

            });

        })


        // ==========================================
        // ERROR LOADING PLAYERS
        // ==========================================

        .catch(error => {

            console.error(
                "Error loading players:",
                error
            );

        });


    // ==========================================
    // SUBMIT PREDICTIONS VIA AJAX
    // ==========================================

    const form =
        document.querySelector(
            ".prediction-container form"
        );


    if (form) {

        form.addEventListener(
            "submit",
            async (e) => {

                e.preventDefault();


                const predictions = {};

                document
                    .querySelectorAll(
                        ".prediction-card input[type='hidden']"
                    )
                    .forEach(
                        input => {

                            if (input.value) {

                                predictions[input.name] =
                                    input.value;

                            }

                        }
                    );


                console.log(
                    "Submitting predictions:",
                    predictions
                );


                try {

                    const csrfTokenInput =
                        form.querySelector(
                            "[name=csrf_token]"
                        );


                    const csrfToken =
                        csrfTokenInput
                            ? csrfTokenInput.value
                            : "";


                    const response =
                        await fetch(
                            form.action,
                            {
                                method: "POST",

                                headers: {
                                    "Content-Type":
                                        "application/json",

                                    "X-CSRFToken":
                                        csrfToken
                                },

                                body:
                                    JSON.stringify(
                                        predictions
                                    )
                            }
                        );


                    const data =
                        await response.json();


                    // ==========================================
                    // SUCCESS
                    // ==========================================

                    if (
                        data.status === "ok"
                    ) {

                        alert(
                            "✅ " +
                            data.message
                        );

                    }

                    // ==========================================
                    // ERROR
                    // ==========================================

                    else {

                        alert(
                            "⚠️ " +
                            data.message
                        );

                    }

                }

                catch (error) {

                    console.error(error);

                    alert(
                        "❌ Failed to submit predictions."
                    );

                }

            }
        );

    }

});