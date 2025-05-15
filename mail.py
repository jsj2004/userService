import smtplib
from email.message import EmailMessage
from dotenv import load_dotenv
import os

load_dotenv()

# Email configuration
def sendmail( receiver_email: str,  url : str):
    sender_email = os.getenv("EMAIL")
    subject = "Password reset link"
    body = "Click following link to reset password " + url
    app_password = os.getenv("EMAIL_PASS")  # Use an app-specific password if using Gmail

# Create the email message
    msg = EmailMessage()
    msg['From'] = sender_email
    msg['To'] = receiver_email
    msg['Subject'] = subject
    msg.set_content(body)

# Send the email via Gmail SMTP
    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
        smtp.login(sender_email, app_password)
        smtp.send_message(msg)