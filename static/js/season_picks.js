console.log("SEASON PICKS JS LOADED");

document.addEventListener("DOMContentLoaded", function () {

    console.log("DOM LOADED");


    // =========================
    // Select winners
    // =========================

    document.querySelectorAll(".game-card").forEach(function (game) {

        const teams = game.querySelectorAll(
            ".home-team, .away-team"
        );

        const winnerInput = game.querySelector(
            ".winner-input"
        );


        teams.forEach(function (team) {

            team.addEventListener("click", function () {

                // -------------------------
                // Don't allow picks after
                // game has started
                // -------------------------

                if (game.classList.contains("locked")) {

                    console.log(
                        "Game is locked:",
                        game.dataset.gameId
                    );

                    showFlashMessage(
                        "This game has already started. Your pick cannot be changed.",
                        "warning"
                    );

                    return;
                }


                // -------------------------
                // Remove previous selection
                // -------------------------

                teams.forEach(function (team) {

                    team.classList.remove("selected");

                });


                // -------------------------
                // Select new team
                // -------------------------

                this.classList.add("selected");


                // -------------------------
                // Store team ID
                // -------------------------

                winnerInput.value =
                    this.dataset.teamId;


                console.log(
                    "Selected team:",
                    this.dataset.teamId
                );

            });

        });

    });


    // =========================
    // AJAX submit
    // =========================

    const form = document.getElementById(
        "season-picks-form"
    );

    console.log("FORM:", form);


    if (!form) {

        console.error(
            "Season picks form not found!"
        );

        return;
    }


    form.addEventListener(
        "submit",
        async function (event) {

            console.log("FORM SUBMITTED");

            event.preventDefault();


            // -------------------------
            // Collect picks
            // -------------------------

            const picks = {};


            document.querySelectorAll(
                ".game-card"
            ).forEach(function (game) {

                const gameId =
                    game.dataset.gameId;

                const winnerInput =
                    game.querySelector(
                        ".winner-input"
                    );


                // -------------------------
                // Don't submit locked games
                // -------------------------

                if (
                    game.classList.contains("locked")
                ) {

                    console.log(
                        "Skipping locked game:",
                        gameId
                    );

                    return;
                }


                // -------------------------
                // Add selected pick
                // -------------------------

                if (
                    gameId &&
                    winnerInput &&
                    winnerInput.value
                ) {

                    picks[gameId] =
                        winnerInput.value;

                }

            });


            console.log(
                "PICKS:",
                picks
            );


            // -------------------------
            // Don't submit if there
            // are no available picks
            // -------------------------

            if (
                Object.keys(picks).length === 0
            ) {

                showFlashMessage(
                    "There are no available picks to submit.",
                    "warning"
                );

                return;
            }


            // -------------------------
            // Submit to Flask
            // -------------------------

            try {

                const response = await fetch(
                    form.action,
                    {
                        method: "POST",

                        headers: {
                            "Content-Type":
                                "application/json",

                            "X-Requested-With":
                                "XMLHttpRequest"
                        },

                        body: JSON.stringify(picks)
                    }
                );


                console.log(
                    "RESPONSE STATUS:",
                    response.status
                );


                // -------------------------
                // Read Flask response
                // -------------------------

                const data =
                    await response.json();


                console.log(
                    "RESPONSE DATA:",
                    data
                );


                // -------------------------
                // Show response
                // -------------------------

                showFlashMessage(
                    data.message ||
                    "Your picks could not be submitted.",
                    data.status ||
                    "error"
                );


                // -------------------------
                // Completely successful
                // submission
                // -------------------------

                if (
                    response.ok &&
                    data.status === "success"
                ) {

                    setTimeout(function () {

                        window.location.reload();

                    }, 1000);

                }

            } catch (error) {

                console.error(
                    "SUBMIT ERROR:",
                    error
                );


                showFlashMessage(
                    "Something went wrong submitting your picks.",
                    "error"
                );

            }

        }
    );


    // =========================
    // Flash message
    // =========================

    function showFlashMessage(
        message,
        category
    ) {

        console.log(
            "SHOWING FLASH:",
            message,
            category
        );


        const flashContainer =
            document.getElementById(
                "flash-messages"
            );


        if (!flashContainer) {

            console.error(
                "flash-messages container does not exist!"
            );

            return;
        }


        // -------------------------
        // Clear existing message
        // -------------------------

        flashContainer.innerHTML = "";


        // -------------------------
        // Create flash
        // -------------------------

        const flash =
            document.createElement("div");


        flash.className =
            "flash " + category;


        flash.textContent =
            message;


        flashContainer.appendChild(
            flash
        );


        // -------------------------
        // Remove after 4 seconds
        // -------------------------

        setTimeout(function () {

            flash.remove();

        }, 4000);

    }

});