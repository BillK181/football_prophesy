from flask import Blueprint, request, jsonify, redirect, url_for, flash, session, render_template
from flask_login import current_user, login_required
from football_prophesy.models import db, User
from football_prophesy.models.comment import Comment
from datetime import datetime
from zoneinfo import ZoneInfo

comment_bp = Blueprint("comment", __name__)


# =========================
# SUBMIT COMMENT
# =========================
@comment_bp.route("/submit_comment", methods=["POST"])
@login_required
def submit_comment():
# Handles AJAX submission of a new comment and returns JSON response

    # Retrieve input and session data
    page = request.form.get("page", "").strip().replace('_', ' ').replace('-', ' ').lower()
    content = request.form.get("content", "").strip()
    user_id = current_user.id

    # Validate input
    if not content:
        return jsonify({"success": False, "error": "Comment cannot be empty."})

    # Save UTC variable for PST conversion
    utc_now = datetime.utcnow()

    # Create comment object
    comment = Comment(
        user_id=user_id,
        page=page,
        content=content,
        timestamp=utc_now  # Save as UTC
    )

    # Add comment to the database
    db.session.add(comment)
    db.session.commit()

    # Convert timestamp to PST/PDT for JSON response
    pst_time = utc_now.replace(tzinfo=ZoneInfo("UTC")).astimezone(ZoneInfo("America/Los_Angeles"))
    formatted_time = pst_time.strftime("%m-%d-%Y %I:%M %p")

    # Retrieve display username
    username = comment.user.username if comment.user else "Guest"

    # Return JSON response
    return jsonify({
        "success": True,
        "username": username,
        "content": comment.content,
        "timestamp": formatted_time,
        "comment_id": comment.id,
        "can_delete": True  # user can delete their own comment
    })

# =========================
# DELETE COMMENT
# =========================
@comment_bp.route("/delete-comment/<int:comment_id>", methods=["POST"])
@login_required
def delete_comment(comment_id):

    # Retrieve the comment object
    comment = Comment.query.get_or_404(comment_id)

    # Check permissions
    if comment.user_id == current_user.id or current_user.is_admin:
        # Delete the comment
        db.session.delete(comment)
        db.session.commit()
        return jsonify({"success": True, "comment_id": comment_id})
    
    # Unauthorized deletion attempt
    return jsonify({"success": False, "message": "You do not have permission to delete this comment."})