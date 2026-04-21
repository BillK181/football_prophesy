from app import app
from football_prophesy.services.email_service import send_draft_email_to_all_users

with app.app_context():
    send_draft_email_to_all_users()