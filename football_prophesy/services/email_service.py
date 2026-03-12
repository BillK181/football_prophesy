import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

def send_welcome_email(user):
    sender = "ThrillBill@footballprophesy.com"  # Mailgun domain email
    receiver = user.email

    # Create the message
    msg = MIMEMultipart("alternative")
    msg["Subject"] = "Welcome to Football Prophesy 🏈"
    msg["From"] = sender
    msg["To"] = receiver

    # Email body
    text = f"Hi {user.name},\nThanks for signing up to Football Prophesy!"
    html = f"""
    <html>
      <body>
        <h2>Hi {user.name},</h2>
        <p>Thanks for signing up to <b>Football Prophesy</b>!</p>
      </body>
    </html>
    """

    msg.attach(MIMEText(text, "plain"))
    msg.attach(MIMEText(html, "html"))

    # Mailgun SMTP credentials
    SMTP_SERVER = "smtp.mailgun.org"
    SMTP_PORT = 587
    SMTP_USERNAME = os.environ.get("MAILGUN_SMTP_USER")
    SMTP_PASSWORD = os.environ.get("MAILGUN_SMTP_PASS")

    # Send email
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.sendmail(sender, receiver, msg.as_string())
    except Exception as e:
        print(f"Failed to send welcome email: {e}")