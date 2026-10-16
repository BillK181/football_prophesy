// Season prediction button
const seasonPredictionButton = document.querySelectorAll('.prediction-card');

// Season prediction board
const seasonPredictionBoard = document.querySelector('#season-prediction-board');

// Hide board when page loads
seasonPredictionBoard.style.display = 'none';

// Season prediction title selected
let currentPrediction = null;

// Season prediction 
const displayedSeasonPredictions = document.querySelector('#displayed-season-predictions');

// Season prediction board title
const predictionBoardTitle = document.querySelector('#season-prediction-board-title');

// Close button
const closeSeasonPredictionBoard = document.querySelector('#close-season-prediction-board');

// Predictions
let predictions = []

// Display predictions

function displayPredictions() {
    displayedSeasonPredictions.textContent = '';

    predictions.forEach(prediction => {
        const predictionElement = document.createElement('div');
        predictionElement.classList.add('season-prediction');

        const seasonPred = document.createElement('p');
        seasonPred.classList.add('season-pred-content');

        let points = '';

        if (prediction.points !== null) {
            points = ` (${prediction.points} points)`;
        }

        if (prediction.teamPoints !== null && prediction.teamPoints !== undefined && prediction.teamPoints !== '') {
            points += ` (${prediction.teamPoints} points)`;
        }

        seasonPred.textContent = `${prediction.username} - ${prediction.seasonPred}${points}`;

        predictionElement.appendChild(seasonPred);
        displayedSeasonPredictions.appendChild(predictionElement);
    });
}


// Display prediction board and fetch predictions
seasonPredictionButton.forEach(button => {
    button.addEventListener('click', async function() {
        const predictionLabel = this.querySelector('.prediction-label');
        const predictionType = this.dataset.prediction;

        const pointsKey = predictionType.replace(/_\d+$/, '');
        const points = predictionsPoints[pointsKey];

        predictionBoardTitle.textContent =
            `${predictionLabel.textContent.trim()} - ${points ?? 'Variable'} points`;

        seasonPredictionBoard.style.display = 'block';

        const response = await fetch(
            `/season_picks/get_predictions?season_prediction=${encodeURIComponent(predictionType)}`
        );

        predictions = await response.json();
        displayPredictions();
    });
});

// Close prediction board
closeSeasonPredictionBoard.addEventListener('click', function () {
    seasonPredictionBoard.style.display = 'none';
})



