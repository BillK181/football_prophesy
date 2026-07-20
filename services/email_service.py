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
# Email colors
# ==============================

EMAIL_COLORS = {
    "primary": "#efc588",
    "secondary": "#9c6e56",
    "background": "#efc588",
    "accent": "#d9b00e",
    "dark": "#0b1f3a",
    "red": "#d32f2f",
    "text": "#333333",
    "light": "#f4f4f4",
}


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
        "Schedule Release is Back Live 🏈",
        user,
        f"""Hi {user.name},

After a short outage the Schedule Release section now once again allows submissions. Be sure to submit before 6am PST May 14th!
https://www.footballprophesy.com/schedule
""",
        f"""
        <html>
          <body>
            <h2>Hi {user.name},</h2>
            <p>
              After a short outage the Schedule Release section now once again allows submissions. Be sure to submit before 6am PST May 14th!<br><br>
              <a href="https://www.footballprophesy.com/schedule">
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


# ==============================
# Preseason emails
# ==============================

def build_preseason_email(user):
    return make_email(
        "🏈 Preseason Predictions Are Live!",
        user,
        f"""Hi {user.name},

Preseason Predictions are now live! Be sure to submit before 5pm on August 6th.

Submit here:
https://www.footballprophesy.com/preseason
""",
        f"""
        <!DOCTYPE html>
        <html>
        <body style="
            margin:0;
            padding:0;
            background-color:#f8f1e7;
            font-family:'Helvetica Neue', Helvetica, Arial, sans-serif;
        ">

          <table width="100%" cellpadding="0" cellspacing="0" style="background-color:{EMAIL_COLORS['background']};">
            <tr>
              <td align="center" style="padding:30px 15px;">

                <table 
                  width="100%"
                  cellpadding="0"
                  cellspacing="0"
                  style="
                    background:white;
                    border-radius:12px;
                    overflow:hidden;
                    box-shadow:0 4px 12px rgba(0,0,0,0.1);
                  "
                >

                  <!-- Header -->
                  <tr>
                    <td style="
                      background:{EMAIL_COLORS['secondary']};
                      padding:30px;
                      text-align:center;
                    ">

                      <img
                        src="https://www.footballprophesy.com/static/images/football_prophesy.png"
                        alt="Football Prophesy"
                        style="
                          width:400px;
                          max-width:100%;
                          height:auto;
                          display:block;
                          margin:auto;
                        "
                      >

                      <p style="
                        color:white;
                        margin:20px 0 0;
                        font-size:18px;
                      ">
                        Preseason Predictions Are Live!
                      </p>

                    </td>
                  </tr>


                  <!-- Body -->
                  <tr>
                    <td style="
                      padding:30px;
                      color:{EMAIL_COLORS['text']};
                    ">

                      <h2 style="
                        margin-top:0;
                        color:black;
                      ">
                        Hi {user.name},
                      </h2>


                      <p style="
                        font-size:16px;
                        line-height:1.6;
                      ">
                        The preseason event is officially open!
                        Choose your players and compete against other
                        Football Prophesy users.
                      </p>


                      <!-- Deadline -->
                      <div style="
                        background:{EMAIL_COLORS['primary']};
                        padding:15px;
                        margin:20px 0;
                        border-radius:5px;
                        font-size:15px;
                      ">
                        ⏰ <strong>Submission Deadline:</strong><br>
                        August 6th at 5:00 PM
                      </div>


                      <!-- Button -->
                      <div style="
                        text-align:center;
                        margin:30px 0;
                      ">

                        <a href="https://www.footballprophesy.com/preseason"
                           style="
                             background:{EMAIL_COLORS['secondary']};
                             color:white;
                             text-decoration:none;
                             padding:14px 30px;
                             border-radius:8px;
                             font-weight:bold;
                             display:inline-block;
                             font-size:16px;
                           ">
                          Submit Predictions
                        </a>

                      </div>


                      <p style="
                        font-size:14px;
                        color:#666;
                        line-height:1.5;
                      ">
                        Good luck, and may your predictions reign supreme!
                      </p>

                    </td>
                  </tr>


                  <!-- Footer -->
                  <tr>
                    <td style="
                      background:{EMAIL_COLORS['light']};
                      text-align:center;
                      padding:15px;
                      font-size:12px;
                      color:#777;
                    ">
                      Football Prophesy © 2026<br>
                      <a href="https://www.footballprophesy.com"
                         style="
                           color:{EMAIL_COLORS['secondary']};
                           text-decoration:none;
                         ">
                        www.footballprophesy.com
                      </a>
                    </td>
                  </tr>

                </table>

              </td>
            </tr>
          </table>

        </body>
        </html>
        """
    )



def send_preseason_email(user):
    try:
        msg = build_preseason_email(user)
        send_email(msg, user.email)
        return True
    except Exception as e:
        print(f"[ERROR] Preseason email failed for {user.email}: {e}")
        return False