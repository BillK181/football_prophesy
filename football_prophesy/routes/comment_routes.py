from flask import Blueprint, request, jsonify, redirect, url_for, flash, session
from models import db, User
from models.comment import Comment
from datetime import datetime

comment_bp = Blueprint("comment", __name__)


# =========================
# SUBMIT COMMENT
# =========================
@comment_bp.route("/submit_comment", methods=["POST"])
def submit_comment():

    page = request.form.get("page", "").lstrip("/")
    content = request.form.get("content", "").strip()
    user_id = session.get("user_id")

    if not content:
        return jsonify({
            "success": False,
            "error": "Comment cannot be empty."
        })

    comment = Comment(
        user_id=user_id,
        page=page,
        content=content,
        timestamp=datetime.utcnow()
    )

    db.session.add(comment)
    db.session.commit()

    # Get username safely
    username = comment.user.username if comment.user else "Guest"

    return jsonify({
        "success": True,
        "username": username,
        "content": comment.content,
        "timestamp": comment.timestamp.strftime("%m-%d-%Y")
    })


# =========================
# DELETE COMMENT
# =========================
@comment_bp.route("/delete-comment/<int:comment_id>", methods=["POST"])
def delete_comment(comment_id):

    comment = Comment.query.get_or_404(comment_id)

    user_id = session.get("user_id")
    user = User.query.get(user_id)

    if comment.user_id == user_id or (user and user.is_admin):
        db.session.delete(comment)
        db.session.commit()
        flash("Comment deleted.", "success")
    else:
        flash("You do not have permission to delete this comment.", "danger")

    return redirect(request.referrer or url_for("main.index"))