import os
import smtplib
import time
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from dotenv import load_dotenv

from football_prophesy.models.user import User
from football_prophesy.extensions import db

load_dotenv()

# ==============================
# CONFIG
# ==============================
SMTP_SERVER = "smtp.mailgun.org"
SMTP_PORT = 587

SENDER = "ThrillBill <no-reply@footballprophesy.com>"

# OPTIONAL: disable email safely in dev
EMAIL_ENABLED = os.environ.get("EMAIL_ENABLED", "true").lower() == "true"


# ==============================
# CORE EMAIL SENDER
# ==============================
def send_email(msg, receiver):
    if not EMAIL_ENABLED:
        print(f"[EMAIL DISABLED] Would send to {receiver}")
        return True

    smtp_user = os.environ.get("MAILGUN_SMTP_USER")
    smtp_pass = os.environ.get("MAILGUN_SMTP_PASS")

    if not smtp_user or not smtp_pass:
        raise ValueError("Missing Mailgun SMTP credentials")

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.set_debuglevel(1)
        server.starttls()
        server.login(smtp_user, smtp_pass)

        server.sendmail(
            SENDER,
            receiver,
            msg.as_bytes()
        )


# ==============================
# EMAIL HELPERS
# ==============================
def make_email(subject, user, text, html):
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = SENDER
    msg["To"] = user.email

    msg.attach(MIMEText(text, "plain", "utf-8"))
    msg.attach(MIMEText(html, "html", "utf-8"))

    return msg


# ==============================
# WELCOME EMAIL
# ==============================
def send_welcome_email(user):
    try:
        msg = make_email(
            "Welcome to Football Prophesy 🏈",
            user,
            f"""Hi {user.name},

Thanks for signing up to Football Prophesy!
https://footballprophesy.com
""",
            f"""
            <html>
              <body>
                <h2>Hi {user.name},</h2>
                <p>Thanks for joining Football Prophesy!</p>
              </body>
            </html>
            """
        )

        send_email(msg, user.email)
        return True

    except Exception as e:
        print(f"[ERROR] Welcome email failed for {user.email}: {e}")
        return False


# ==============================
# PASSWORD RESET EMAIL
# ==============================
def send_password_reset_email(user, reset_link):
    try:
        msg = make_email(
            "Password Reset Request 🔒",
            user,
            f"""Hi {user.name},

We received a request to reset your password.

Reset here:
{reset_link}

If you didn’t request this, ignore this email.
""",
            f"""
            <html>
              <body>
                <h2>Hi {user.name},</h2>
                <p>Reset your password below:</p>

                <p style="text-align:center;">
                  <a href="{reset_link}"
                     style="background:#1E90FF;color:white;padding:10px 20px;text-decoration:none;border-radius:5px;">
                     Reset Password
                  </a>
                </p>
              </body>
            </html>
            """
        )

        send_email(msg, user.email)
        return True

    except Exception as e:
        print(f"[ERROR] Reset email failed for {user.email}: {e}")
        return False


# ==============================
# DRAFT EMAIL
# ==============================
def build_draft_email(user):
    return make_email(
        "Draft Prophesy Now Available 🏈",
        user,
        f"""Hi {user.name},

The Draft Prophesy is now available!

https://footballprophesy.com/draft
""",
        f"""
        <html>
          <body>
            <h2>Hi {user.name},</h2>
            <p>
              The Draft is live!<br><br>
              <a href="https://footballprophesy.com/draft">Click here</a>
            </p>
          </body>
        </html>
        """
    )


def send_draft_email(user):
    try:
        msg = build_draft_email(user)
        send_email(msg, user.email)
        return True
    except Exception as e:
        print(f"[ERROR] Draft email failed for {user.email}: {e}")
        return False


# ==============================
# SCHEDULE RELEASE EMAIL (NEW)
# ==============================
def build_schedule_release_email(user):
    return make_email(
        "Schedule Release is Live 🏈",
        user,
        f"""Hi {user.name},

The NFL Schedule Release is now live!

https://footballprophesy.com/schedule
""",
        f"""
        <html>
          <body>
            <h2>Hi {user.name},</h2>
            <p>
              The schedule is now live!<br><br>
              <a href="https://footballprophesy.com/schedule">
                View Schedule
              </a>
            </p>
          </body>
        </html>
        """
    )


def send_schedule_release_email(user):
    try:
        msg = build_schedule_release_email(user)
        send_email(msg, user.email)
        return True
    except Exception as e:
        print(f"[ERROR] Schedule email failed for {user.email}: {e}")
        return False


# ==============================
# BULK EMAIL SENDER (DRAFT)
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

            if send_draft_email(user):
                sent += 1
            else:
                failed += 1

            time.sleep(delay)

        db.session.commit()
        print(f"Progress: {sent} sent, {failed} failed")

    print("Email sending complete.")
    print(f"Final: {sent} sent, {failed} failed")

# ==============================
# BULK EMAIL SENDER (SCHEDULE RELEASE)
# ==============================
def send_schedule_release_email_to_all_users(batch_size=50, delay=0.5):
    total = User.query.count()
    print(f"Sending schedule emails to {total} users...")

    sent = 0
    failed = 0

    for offset in range(0, total, batch_size):
        users = User.query.offset(offset).limit(batch_size).all()

        for user in users:
            if not user.email:
                continue

            try:
                send_schedule_release_email(user)
                sent += 1
            except Exception as e:
                print(f"[ERROR] {user.email}: {e}")
                failed += 1

            time.sleep(delay)

        db.session.commit()
        print(f"Progress: {sent} sent, {failed} failed")

    print("DONE")
    print(f"Final: {sent} sent, {failed} failed")