document.addEventListener("DOMContentLoaded", function() {
    const selections = {}; // staged selections

    // -----------------------------
    // Initialize selections from pre-selected buttons
    // -----------------------------
    document.querySelectorAll(".draft-prediction-row").forEach(row => {
        const position = row.dataset.position;
        const selectedBtn = row.querySelector(".selector-btn.selected");
        if (selectedBtn) selections[position] = selectedBtn.dataset.player;
    });

    // -----------------------------
    // Handle button clicks
    // -----------------------------
    document.querySelectorAll(".draft-prediction-row").forEach(row => {
        const position = row.dataset.position;

        row.querySelectorAll(".selector-btn").forEach(btn => {
            btn.addEventListener("click", () => {
                // Deselect all buttons in this row
                row.querySelectorAll(".selector-btn").forEach(b => b.classList.remove("selected"));

                // Select clicked button
                btn.classList.add("selected");

                // Stage selection
                selections[position] = btn.dataset.player;
            });
        });
    });

    // -----------------------------
    // Submit form via AJAX
    // -----------------------------
    const form = document.querySelector(".prediction-container form");
    form.addEventListener("submit", async (e) => {
        e.preventDefault(); // prevent normal form submit

        // Get required positions from the DOM
        const requiredPositions = Array.from(document.querySelectorAll(".draft-prediction-row"))
            .map(row => row.dataset.position);

        // Find missing selections
        const missing = requiredPositions.filter(pos => !selections[pos]);
        if(missing.length > 0) {
            alert("⚠️ Please select a player for all positions. Missing: " + missing.join(", "));
            return; // stop submission
        }

        try {
            const csrfTokenInput = form.querySelector('[name=csrf_token]');
            const csrfToken = csrfTokenInput ? csrfTokenInput.value : "";

            const response = await fetch(form.action, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "X-CSRFToken": csrfToken
                },
                body: JSON.stringify(selections)
            });

            const data = await response.json();

            if(data.status === "ok") {
                alert("✅ " + data.message);
            } else {
                alert("⚠️ " + (data.message || "Some selections are missing!"));
            }

        } catch(err) {
            console.error(err);
            alert("❌ Failed to submit predictions.");
        }
    });
});