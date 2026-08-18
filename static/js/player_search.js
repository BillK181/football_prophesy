document.addEventListener("DOMContentLoaded", () => {

    let players = [];

    fetch("/season_predictions/players")
        .then(response => response.json())
        .then(data => {

            players = data;

            console.log(`Loaded ${players.length} players`);

            const searches =
                document.querySelectorAll(".player-search");

            searches.forEach(search => {

                const container =
                    search.closest(".player-search-container");

                const suggestions =
                    container.querySelector(".search-results");

                const hiddenInput =
                    container.querySelector(
                        "input[type='hidden']"
                    );

                search.addEventListener("input", () => {

                    const value =
                        search.value.trim().toLowerCase();

                    suggestions.innerHTML = "";

                    if (value === "") {
                        hiddenInput.value = "";
                        return;
                    }

                    const matches =
                        players.filter(player =>
                            player.name
                                ?.toLowerCase()
                                .includes(value)
                        );

                    matches.forEach(player => {

                        const div =
                            document.createElement("div");

                        div.textContent =
                            `${player.name} (${player.team || "FA"})`;

                        div.addEventListener("click", () => {

                            search.value = player.name;

                            hiddenInput.value = player.id;

                            suggestions.innerHTML = "";

                        });

                        suggestions.appendChild(div);

                    });

                });

            });

        })

        .catch(error => {
            console.error(
                "Error loading players:",
                error
            );
        });

});