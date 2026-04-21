Imports:
- os – Access environment variables for sensitive data like SMTP credentials.
- smtplib – Standard Python library to connect and send emails via SMTP.
- email.mime.multipart.MIMEMultipart – Allows constructing multi-part emails (plain + HTML).
- email.mime.text.MIMEText – Represents the email body in plain text or HTML format.

send_welcome_email(user)
    - Purpose: Send a welcome email to a newly registered user.
    - Parameters: user – an object representing the new user (expects at least .name and .email attributes).
    - Define sender and receiver:
        - sender: fixed email address (Mailgun domain email).
        - receiver: user.email.
    - Create the email message:
        - msg = MIMEMultipart("alternative") allows both plain text and HTML content.
        - Set headers: Subject, From, To.
    - Prepare email body:
        - text: plain text version, fallback for email clients that don’t render HTML.
        - html: formatted HTML version with personalized greeting using user.name.
    - Attach both text and HTML parts to msg using MIMEText.
    - SMTP configuration:
        - SMTP_SERVER: "smtp.mailgun.org"
        - SMTP_PORT: 587
        - SMTP_USERNAME and SMTP_PASSWORD retrieved from environment variables for security.
    - Send the email:
        - Open SMTP connection using smtplib.SMTP.
        - Start TLS for secure connection.
        - Log in with SMTP credentials.
        - Send email using server.sendmail(sender, receiver, msg.as_string()).
    - Error handling:
        - Wrap sending logic in try/except.
        - Print any exceptions to console if email fails to send.

Notes:
- Using both plain text and HTML ensures maximum compatibility with email clients.
- Environment variables protect sensitive credentials from being hard-coded.
- Mailgun SMTP is used as the email service provider.