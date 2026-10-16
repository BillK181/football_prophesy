
const ratingIcons = document.querySelectorAll('.rating-icon');

const ratingBoard = document.querySelector('#rating-board');

const ratingBoardTitle = document.querySelector('#rating-board-title');

const closeRatingBoard = document.querySelector('#close-rating-board');

const ratingStars = document.querySelectorAll('.rating-star');

const ratingStarsContainer = document.querySelector('#rating-stars');

let currentGameId = null;


// Display rating board on rating icon click
ratingIcons.forEach(icon => {
    icon.addEventListener('click', function() {

        const gameCard = this.closest('.game-card');
        const gameId = gameCard.dataset.gameId;

        currentGameId = gameId;

        ratingBoardTitle.textContent =
            gameCard.querySelector('.away-team > span:first-child').textContent
            + ' @ ' +
            gameCard.querySelector('.home-team > span:first-child').textContent;

        // Reset stars whenever the board opens
        ratingStars.forEach(star => {
            star.classList.remove('active');
        });

        ratingStarsContainer.classList.remove('disabled');

        ratingBoard.style.display = 'block';
    });
});


// Close rating board button
closeRatingBoard.addEventListener('click', function() {
    ratingBoard.style.display = 'none';
});


// Submit game rating when a star is clicked
ratingStars.forEach(star => {
    star.addEventListener('click', function() {

        // Prevent multiple submissions
        if (ratingStarsContainer.classList.contains('disabled')) {
            return;
        }

        const rating = Number(this.dataset.rating);

        if (!currentGameId || rating < 1 || rating > 5) {
            return;
        }

        // Highlight the selected star and all stars before it
        ratingStars.forEach(otherStar => {
            const otherRating = Number(otherStar.dataset.rating);

            if (otherRating <= rating) {
                otherStar.classList.add('active');
            } else {
                otherStar.classList.remove('active');
            }
        });

        // Prevent another click during the delay
        ratingStarsContainer.classList.add('disabled');

        // Wait half a second before submitting
        setTimeout(() => {

            fetch('/season_picks/ratings', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    game_id: currentGameId,
                    rating: rating
                })
            })
                .then(response => {
                    if (!response.ok) {
                        throw new Error('Failed to submit rating');
                    }

                    return response.json();
                })
                .then(data => {
                    console.log('Rating submitted:', data);

                    ratingBoard.style.display = 'none';
                })
                .catch(error => {
                    console.error(error);

                    // Allow the user to try again if submission fails
                    ratingStarsContainer.classList.remove('disabled');
                });

        }, 500);
    });
});
