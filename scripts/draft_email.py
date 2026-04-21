from football_prophesy.app import create_app
from football_prophesy.services.email_service import send_draft_email_to_all_users

app = create_app()

with app.app_context():
    send_draft_email_to_all_users()