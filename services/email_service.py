import os
import smtplib
import time

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from dotenv import load_dotenv
from flask import render_template

from football_prophesy.models.user import User
from football_prophesy.extensions import db


load_dotenv()


# ==============================
# CONFIG
# ==============================

SMTP_SERVER = "smtp.mailgun.org"
SMTP_PORT = 587

SENDER = "Football Prophesy <no-reply@footballprophesy.com>"

EMAIL_ENABLED = (
    os.environ.get("EMAIL_ENABLED", "true").lower() == "true"
)



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
        raise ValueError(
            "Missing Mailgun SMTP credentials"
        )


    with smtplib.SMTP(
        SMTP_SERVER,
        SMTP_PORT
    ) as server:

        server.starttls()

        server.login(
            smtp_user,
            smtp_pass
        )


        server.sendmail(
            SENDER,
            receiver,
            msg.as_bytes()
        )



# ==============================
# EMAIL BUILDER
# ==============================

def make_email(subject, user, text, html):

    msg = MIMEMultipart("alternative")

    msg["Subject"] = subject
    msg["From"] = SENDER
    msg["To"] = user.email


    msg.attach(
        MIMEText(
            text,
            "plain",
            "utf-8"
        )
    )


    msg.attach(
        MIMEText(
            html,
            "html",
            "utf-8"
        )
    )


    return msg



# ==============================
# WELCOME EMAIL
# ==============================

def build_welcome_email(user):

    html = render_template(
        "emails/welcome_email.html",
        user=user
    )


    text = f"""
Hi {user.name},

Thanks for signing up for Football Prophesy!

Visit:
https://footballprophesy.com
"""


    return make_email(
        "Welcome to Football Prophesy 🏈",
        user,
        text,
        html
    )



def send_welcome_email(user):

    try:

        msg = build_welcome_email(user)

        send_email(
            msg,
            user.email
        )

        return True


    except Exception as e:

        print(
            f"[ERROR] Welcome email failed for {user.email}: {e}"
        )

        return False



# ==============================
# PASSWORD RESET EMAIL
# ==============================

def build_password_reset_email(user, reset_link):

    html = render_template(
        "emails/password_reset_email.html",
        user=user,
        reset_link=reset_link
    )


    text = f"""
Hi {user.name},

We received a request to reset your password.

Reset here:

{reset_link}

If you did not request this, ignore this email.
"""


    return make_email(
        "Password Reset Request 🔒",
        user,
        text,
        html
    )



def send_password_reset_email(user, reset_link):

    try:

        msg = build_password_reset_email(
            user,
            reset_link
        )


        send_email(
            msg,
            user.email
        )


        return True


    except Exception as e:

        print(
            f"[ERROR] Password reset failed for {user.email}: {e}"
        )

        return False



# ==============================
# DRAFT EMAIL
# ==============================

def build_draft_email(user):

    html = render_template(
        "emails/draft_email.html",
        user=user
    )


    text = f"""
Hi {user.name},

The Draft Prophesy is now available!

Submit your predictions:

https://footballprophesy.com/draft
"""


    return make_email(
        "Draft Prophesy Now Available 🏈",
        user,
        text,
        html
    )



def send_draft_email(user):

    try:

        msg = build_draft_email(user)

        send_email(
            msg,
            user.email
        )

        return True


    except Exception as e:

        print(
            f"[ERROR] Draft email failed for {user.email}: {e}"
        )

        return False



# ==============================
# SCHEDULE RELEASE EMAIL
# ==============================

def build_schedule_release_email(user):

    html = render_template(
        "emails/schedule_release_email.html",
        user=user
    )


    text = f"""
Hi {user.name},

The Schedule Release section is back open!

Submit your predictions:

https://footballprophesy.com/schedule
"""


    return make_email(
        "Schedule Release Is Back Live 🏈",
        user,
        text,
        html
    )



def send_schedule_release_email(user):

    try:

        msg = build_schedule_release_email(
            user
        )


        send_email(
            msg,
            user.email
        )


        return True


    except Exception as e:

        print(
            f"[ERROR] Schedule email failed for {user.email}: {e}"
        )

        return False



# ==============================
# PRESEASON EMAIL
# ==============================

def build_preseason_email(user):

    html = render_template(
        "emails/preseason_email.html",
        user=user
    )


    text = f"""
Hi {user.name},

Preseason Predictions are now live!

Submit before 5:00 PM PST on August 6th.

https://footballprophesy.com/preseason
"""


    return make_email(
        "🏈 Preseason Predictions Are Live!",
        user,
        text,
        html
    )



def send_preseason_email(user):

    try:

        msg = build_preseason_email(
            user
        )


        send_email(
            msg,
            user.email
        )


        return True


    except Exception as e:

        print(
            f"[ERROR] Preseason email failed for {user.email}: {e}"
        )

        return False



# ==============================
# BULK SENDERS
# ==============================

def send_draft_email_to_all_users(
    batch_size=50,
    delay=0.5
):

    send_bulk_email(
        send_draft_email,
        "draft",
        batch_size,
        delay
    )



def send_schedule_release_email_to_all_users(
    batch_size=50,
    delay=0.5
):

    send_bulk_email(
        send_schedule_release_email,
        "schedule release",
        batch_size,
        delay
    )



def send_preseason_email_to_all_users(
    batch_size=50,
    delay=0.5
):

    send_bulk_email(
        send_preseason_email,
        "preseason",
        batch_size,
        delay
    )



def send_bulk_email(
    email_function,
    label,
    batch_size,
    delay
):

    total = User.query.count()

    print(
        f"Sending {label} emails to {total} users..."
    )


    sent = 0
    failed = 0


    for offset in range(
        0,
        total,
        batch_size
    ):

        users = (
            User.query
            .offset(offset)
            .limit(batch_size)
            .all()
        )


        for user in users:

            if not user.email:
                continue


            if email_function(user):
                sent += 1
            else:
                failed += 1


            time.sleep(delay)


        db.session.commit()


        print(
            f"Progress: {sent} sent, {failed} failed"
        )


    print("DONE")
    print(
        f"Final: {sent} sent, {failed} failed"
    )