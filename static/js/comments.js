// comments.js

document.addEventListener("DOMContentLoaded", function() {

    const commentsList = document.getElementById("comments-list");

    // ---- Submit Comment ----
    const form = document.getElementById("comment-form");
    if (form) {
        form.addEventListener("submit", function(e) {
            e.preventDefault(); // prevent page reload
            const formData = new FormData(form);

            fetch(form.action, {
                method: "POST",
                body: formData
            })
            .then(resp => resp.json())
            .then(data => {
                if (!data.success) {
                    alert(data.error || "Something went wrong");
                    return;
                }

                const noComments = commentsList.querySelector(".no-comments");
                if (noComments) noComments.remove();

                // Create new comment div
                const div = document.createElement("div");
                div.className = "comment";
                div.id = `comment-${data.comment_id}`;

                let innerHTML = `<strong>${data.username}</strong>
                                 <em>${data.timestamp}</em>
                                 <p>${data.content}</p>`;

                if (data.can_delete) {
                    innerHTML += `<button class="delete-comment-btn" data-comment-id="${data.comment_id}">Delete</button>`;
                }

                div.innerHTML = innerHTML;
                commentsList.prepend(div);

                form.reset();
            })
            .catch(err => console.error("Comment error:", err));
        });
    }

    // ---- Delete Comment ---- (delegated listener works for dynamically added comments)
    if (commentsList) {
        commentsList.addEventListener("click", function(e) {
            if (!e.target.classList.contains("delete-comment-btn")) return;

            e.preventDefault(); // prevent form submission / page reload

            const commentId = e.target.dataset.commentId;
            if (!commentId) return;

            fetch(`/delete-comment/${commentId}`, {
                method: "POST"
            })
            .then(resp => resp.json())
            .then(data => {
                if (data.success) {
                    const div = document.getElementById(`comment-${commentId}`);
                    if (div) div.remove();

                    // Optional: show "No comments" message if list is empty
                    if (commentsList.children.length === 0) {
                        const p = document.createElement("p");
                        p.className = "no-comments";
                        p.textContent = "No comments yet. Be the first!";
                        commentsList.appendChild(p);
                    }
                } else {
                    alert(data.message || "Failed to delete comment.");
                }
            })
            .catch(err => console.error("Delete error:", err));
        });
    }

});