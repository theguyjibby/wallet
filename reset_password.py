from itsdangerous import URLSafeTimedSerializer
from flask import current_app, url_for
from flask_mail import Message

def _get_serializer():
    return URLSafeTimedSerializer(current_app.config['SECRET_KEY'])

def generate_reset_token(email):
    s = _get_serializer()
    return s.dumps(email, salt='password-reset-salt')

def verify_reset_token(token, max_age=3600):
    s = _get_serializer()
    try:
        # URLSafeTimedSerializer supports max_age in loads
        email = s.loads(token, salt='password-reset-salt', max_age=max_age)
    except Exception:
        return None
    return email

def send_reset_email(user):
    """
    Send a password-reset email for `user`.
    Expects a Flask app context (so current_app is available) and
    Flask-Mail initialized on the app (registered in app.extensions['mail']).
    """
    token = generate_reset_token(user.email)
    reset_link = url_for('reset_token_route', token=token, _external=True)

    msg = Message(
        subject='Password Reset Request',
        sender=current_app.config.get('MAIL_DEFAULT_SENDER'),
        recipients=[user.email]
    )
    msg.body = (
        f"Hi {getattr(user, 'username', '')},\n\n"
        "You requested a password reset. Click the link below to reset your password:\n\n"
        f"{reset_link}\n\n"
        "If you did not request this, please ignore this message."
    )

    # Get the Mail instance registered on the app
    mail = current_app.extensions.get('mail')
    if mail is None:
        # Fail fast with a clear message (avoid creating a Mail instance repeatedly)
        raise RuntimeError("Flask-Mail is not initialized on the application (no 'mail' extension).")
    mail.send(msg)

