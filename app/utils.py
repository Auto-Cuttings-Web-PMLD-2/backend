from flask_mail import Message
from app import mail
from flask import current_app

def send_reset_email(to_email, reset_link):
    msg = Message(
        subject='Reset Password',
        recipients=[to_email],
        body=f'Klik link berikut untuk reset password kamu: {reset_link}',
        sender=current_app.config['MAIL_USERNAME']
    )
    mail.send(msg)