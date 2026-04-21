import os
import smtplib
import time
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from football_prophesy.models.user import User
from football_prophesy.extensions import db


# ==============================
# CONFIG
# ==============================
SMTP_SERVER = "smtp.mailgun.org"
SMTP_PORT = 587
SMTP_USERNAME = os.environ.get("MAILGUN_SMTP_USER")
SMTP_PASSWORD = os.environ.get("MAILGUN_SMTP_PASS")
SENDER = "ThrillBill@footballprophesy.com"


# ==============================
# SAFETY CHECK (IMPORTANT)
# ==============================
if not SMTP_USERNAME or not SMTP_PASSWORD:
    raise ValueError("Missing Mailgun SMTP credentials in environment variables")


# ==============================
# CORE EMAIL SENDER
# ==============================
def send_email(msg, receiver):
    """
    Low-level SMTP sender using Mailgun
    """
    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.sendmail(SENDER, receiver, msg.as_string())


# ==============================
# WELCOME EMAIL
# ==============================
def send_welcome_email(user):
    msg = MIMEMultipart("alternative")
    msg["Subject"] = "Welcome to Football Prophesy 🏈"
    msg["From"] = SENDER
    msg["To"] = user.email

    text = f"""Hi {user.name},

Thanks for signing up to Football Prophesy!
Visit: https://footballprophesy.com
"""

    html = f"""
    <html>
      <body>
        <h2>Hi {user.name},</h2>
        <p>
          Thanks for signing up to <b>Football Prophesy</b>!<br><br>
          Start making predictions today on the platform.
        </p>
      </body>
    </html>
    """

    msg.attach(MIMEText(text, "plain"))
    msg.attach(MIMEText(html, "html"))

    try:
        send_email(msg, user.email)
        return True
    except Exception as e:
        print(f"[ERROR] Welcome email failed for {user.email}: {e}")
        return False


# ==============================
# PASSWORD RESET EMAIL
# ==============================
def send_password_reset_email(user, reset_link):
    msg = MIMEMultipart("alternative")
    msg["Subject"] = "Password Reset Request 🔒"
    msg["From"] = SENDER
    msg["To"] = user.email

    text = f"""Hi {user.name},

We received a request to reset your password.

Reset here:
{reset_link}

If you didn’t request this, ignore this email.
"""

    html = f"""
    <html>
      <body>
        <h2>Hi {user.name},</h2>
        <p>We received a request to reset your password.</p>

        <p style="text-align:center;">
          <a href="{reset_link}" 
             style="background:#1E90FF;color:white;padding:10px 20px;text-decoration:none;border-radius:5px;">
             Reset Password
          </a>
        </p>

        <p>If you didn’t request this, ignore this email.</p>
      </body>
    </html>
    """

    msg.attach(MIMEText(text, "plain"))
    msg.attach(MIMEText(html, "html"))

    try:
        send_email(msg, user.email)
        return True
    except Exception as e:
        print(f"[ERROR] Reset email failed for {user.email}: {e}")
        return False


# ==============================
# DRAFT EMAIL BUILDER
# ==============================
def build_draft_email(user):
    msg = MIMEMultipart("alternative")
    msg["Subject"] = "Draft Prophesy Now Available 🏈"
    msg["From"] = SENDER
    msg["To"] = user.email

    text = f"""Hi {user.name},

The Draft Prophesy is now available!

Make your predictions here:
https://footballprophesy.com/draft
"""

    html = f"""
    <html>
      <body>
        <h2>Hi {user.name},</h2>
        <p>
          The Draft Prophesy is now available!<br><br>
          Click <a href="https://footballprophesy.com/draft">here</a> to make your predictions.
        </p>
      </body>
    </html>
    """

    msg.attach(MIMEText(text, "plain"))
    msg.attach(MIMEText(html, "html"))

    return msg


# ==============================
# DRAFT EMAIL SENDER (SINGLE USER)
# ==============================
def send_draft_email(user):
    try:
        msg = build_draft_email(user)
        send_email(msg, user.email)
        return True
    except Exception as e:
        print(f"[ERROR] Draft email failed for {user.email}: {e}")
        return False


# ==============================
# BULK EMAIL SENDER
# ==============================
def send_draft_email_to_all_users(batch_size=50, delay=0.5):
    total = User.query.count()
    print(f"Starting email send to {total} users...")

    sent = 0
    failed = 0

    for offset in range(0, total, batch_size):
        users = User.query.offset(offset).limit(batch_size).all()

        for user in users:

            if not user.email:
                continue

            success = send_draft_email(user)

            if success:
                sent += 1
            else:
                failed += 1

            time.sleep(delay)

        db.session.commit()
        print(f"Progress: {sent} sent, {failed} failed")

    print("Email sending complete.")
    print(f"Final: {sent} sent, {failed} failed")