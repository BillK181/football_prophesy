
// Comment icon
const commentIcons = document.querySelectorAll('.comment-icon');

// Comment board
const commentBoard = document.querySelector('#comment-board');

let currentGameId = null;

const commentInput = document.querySelector('#game-comment-input');
const submitButton = document.querySelector('#game-comment-submit');

const gameComments = document.querySelector('#game-comments');

const commentBoardTitle = document.querySelector('#comment-board-title');

// Comments
let comments = []


function displayComments() {
    gameComments.textContent = '';

    comments.forEach(comment => {
        const commentElement = document.createElement('div');
        commentElement.classList.add('game-comment');

        const header = document.createElement('div');
        header.classList.add('game-comment-header');

        const username = document.createElement('strong');
        username.textContent = comment.username;

        const timestamp = document.createElement('small');
        timestamp.textContent = new Date(comment.timestamp).toLocaleString();

        const content = document.createElement('p');
        content.classList.add('game-comment-text');
        content.textContent = comment.content;

        header.appendChild(username);
        header.appendChild(timestamp);

        commentElement.appendChild(header);
        commentElement.appendChild(content);

        gameComments.appendChild(commentElement);
    });
}


// Display comment board on comment icon click
commentIcons.forEach(icon => {
    icon.addEventListener('click', function() {

        const gameCard = this.closest('.game-card');
        const gameId = gameCard.dataset.gameId;
        currentGameId = gameId;
        gameComments.textContent = '';

        console.log(gameId);

        commentBoardTitle.textContent = gameCard.querySelector('.away-team > span:first-child').textContent
        + ' @ ' +
        gameCard.querySelector('.home-team > span:first-child').textContent;

        commentBoard.style.display = 'block';

        // Get comments
        fetch(`/season_picks/comments?game_id=${gameId}`)
            .then(response => response.json())

            .then(data => {
                comments = data;

                displayComments();

                console.log(comments);
                console.log(`Loaded ${comments.length} comments`);
            })
    });
});




// Close comment board button
const closeCommentBoard = document.querySelector('#close-comment-board');

closeCommentBoard.addEventListener('click', function() {
    commentBoard.style.display = 'none';
});


// Submit game comment
submitButton.addEventListener('click', function() {

    // Content
    const content = commentInput.value.trim();

    // Check if no content nor game Id
    if (!content || !currentGameId) {
        return;
    }

    // Submit comment to db
    fetch('/season_picks/comments', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            game_id: currentGameId,
            content: content
        })
    })
        .then(response => {
            if (!response.ok) {
                throw new Error('Failed to submit comment')
            }

            return response.json();
        })
        .then(data => {
            console.log('Comment submitted:', data);

            commentInput.value = ''
        })
        .catch(error => {
            console.error(error);
        })
})