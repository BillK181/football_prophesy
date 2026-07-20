// Team name aliases
const teamNames = {
    "ari": "arizona",
    "atl": "atlanta",
    "bal": "baltimore",
    "buf": "buffalo",
    "car": "carolina",
    "chi": "chicago",
    "cin": "cincinnati",
    "cle": "cleveland",
    "dal": "dallas",
    "den": "denver",
    "det": "detroit",
    "gb": "green bay",
    "hou": "houston",
    "ind": "indianapolis",
    "jax": "jacksonville",
    "kc": "kansas city",
    "lv": "las vegas",
    "lac": "los angeles",
    "lar": "los angeles",
    "mia": "miami",
    "min": "minnesota",
    "ne": "new england",
    "no": "new orleans",
    "nyg": "new york giants",
    "nyj": "new york jets",
    "phi": "philadelphia",
    "pit": "pittsburgh",
    "sf": "san francisco",
    "sea": "seattle",
    "tb": "tampa bay",
    "ten": "tennessee",
    "was": "washington"
};

// Extra team nicknames
const teamNicknames = {
    "ari": ["cardinals"],
    "atl": ["falcons"],
    "bal": ["ravens"],
    "buf": ["bills"],
    "car": ["panthers"],
    "chi": ["bears"],
    "cin": ["bengals"],
    "cle": ["browns"],
    "dal": ["cowboys"],
    "den": ["broncos"],
    "det": ["lions"],
    "gb": ["packers"],
    "hou": ["texans"],
    "ind": ["colts"],
    "jax": ["jaguars"],
    "kc": ["chiefs"],
    "lv": ["raiders"],
    "lac": ["chargers"],
    "lar": ["rams"],
    "mia": ["dolphins"],
    "min": ["vikings"],
    "ne": ["patriots"],
    "no": ["saints"],
    "nyg": ["giants"],
    "nyj": ["jets"],
    "phi": ["eagles"],
    "pit": ["steelers"],
    "sf": ["49ers", "niners"],
    "sea": ["seahawks"],
    "tb": ["buccaneers", "bucs"],
    "ten": ["titans"],
    "was": ["commanders"]
};

// Wait until the page HTML is fully loaded
document.addEventListener("DOMContentLoaded", () => {

    // Store players pulled from Flask
    let players = [];

    // Players previously selected
    const selectedPlayers = [];


    // Get players from database
    fetch("/preseason/players")
        .then(response => response.json())
        .then(data => {

            players = data;

            console.log(players); // check that players loaded
            console.log(`Loaded ${players.length} players`);

            // Find every player search box on the page
            const searches = document.querySelectorAll(".player-search");


            // Set up autocomplete for each search box
            searches.forEach(search => {

                // Find the matching results box for this specific input
                const playerSlot = search.closest(".player-slot");

                const suggestions = playerSlot.querySelector(".search-results");

                const hiddenInput = playerSlot.querySelector("input[type='hidden']");


                // Listen for typing
                search.addEventListener("input", () => {


                    // Get what the user typed
                    const value = search.value.toLowerCase();


                    // Get the position this search box is for (QB, RB, WR)
                    const position = search.dataset.position;


                    // Clear out any previous suggestions
                    suggestions.innerHTML = "";


                    // If nothing is typed, don't show anything
                    if (value === "") return;


                    // Look through all items with the correct position and find matches
                    // Don't include previous selections
                    const matches = players.filter(player => {

                    const team = player.team?.trim().toLowerCase();

                    const fullTeamName = teamNames[team] || "";

                    const nicknames = teamNicknames[team] || [];

                    return (
                        player.position === position &&

                        (
                            player.name?.toLowerCase().includes(value) ||

                            team === value ||

                            fullTeamName === value ||

                            nicknames.some(name =>
                                name === value
                            )
                        ) 
                        &&
                        !selectedPlayers.includes(String(player.id))
                    );

                });


                    // For every matching item
                    matches.forEach(player => {


                        // Create a suggestion element
                        const div = document.createElement("div");


                        // Fill in the suggestion text
                        div.textContent = `${player.name} (${player.team || "FA"})`;


                        // When clicked, update selected players, fill the search box, and clear suggestions
                        div.addEventListener("click", () => {

                            // Get the previously selected player ID
                            const previousId = hiddenInput.value;

                            // Remove old player from selected list
                            const index = selectedPlayers.indexOf(previousId);

                            if (index !== -1) {
                                selectedPlayers.splice(index, 1);
                            }


                            // Select the new player
                            search.value = player.name;

                            hiddenInput.value = player.id;


                            // Store ID instead of name
                            if (!selectedPlayers.includes(String(player.id))) {
                                selectedPlayers.push(String(player.id));
                            }


                            // Clear suggestions
                            suggestions.innerHTML = "";

                            // If user clears the input, remove the player selection
                            if (value === "") {

                                if (hiddenInput.value) {

                                    const index = selectedPlayers.indexOf(
                                        String(hiddenInput.value)
                                    );

                                    if (index !== -1) {
                                        selectedPlayers.splice(index, 1);
                                    }

                                    hiddenInput.value = "";

                                }

                                return;
                            }

                        });


                        // Add the suggestion to the results list
                        suggestions.appendChild(div);

                    });

                });

            });

        })

        .catch(error => {
            console.error("Error loading players:", error);
        });


            // -----------------------------
            // Submit preseason predictions via AJAX
            // -----------------------------
            const form = document.querySelector(".prediction-container form");

            form.addEventListener("submit", async (e) => {

                e.preventDefault(); // stop page reload


                const predictions = {};

                document.querySelectorAll("input[type='hidden']").forEach(input => {

                    if (input.value) {
                        predictions[input.name] = input.value;
                    }

                });


                const requiredPositions = [
                    "QB1",
                    "QB2",
                    "QB3",
                    "RB1",
                    "RB2",
                    "RB3",
                    "WR1",
                    "WR2",
                    "WR3",
                    "WR4"
                ];


                const missing = requiredPositions.filter(
                    position => !predictions[position]
                );


                if (missing.length > 0) {

                    alert(
                        "⚠️ Please select players for all positions. Missing: " 
                        + missing.join(", ")
                    );

                    return;
                }


                try {

                    const csrfTokenInput = form.querySelector("[name=csrf_token]");
                    const csrfToken = csrfTokenInput ? csrfTokenInput.value : "";


                    const response = await fetch(form.action, {

                        method: "POST",

                        headers: {
                            "Content-Type": "application/json",
                            "X-CSRFToken": csrfToken
                        },

                        body: JSON.stringify(predictions)

                    });


                    const data = await response.json();


                    if (data.status === "ok") {

                        alert("✅ " + data.message);

                    } else {

                        alert("⚠️ " + data.message);

                    }


                } catch(error) {

                    console.error(error);
                    alert("❌ Failed to submit predictions.");

                }


            });

});