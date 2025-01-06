from django.core.mail import send_mail
from django.conf import settings
import logging
import jwt
from datetime import datetime, timedelta
from decouple import config


logger = logging.getLogger(__name__)


def send_verification_email_helper(to_email, verification_link):
    try:
        subject = 'Verify your Email Address'
        message = f'Please verify your emial address by clicking on the following link: {verification_link}'
        email_from = settings.EMAIL_HOST_USER
        recipient_list = [to_email]
        send_mail(subject, message, email_from, recipient_list)
        return True
    except Exception as e:
        logger.error(f'Error sending email: {e}')
        return False


def generate_verification_email_token(userId):
    payload = {
        'data': {'userId': str(userId)},
        'exp': datetime.utcnow() + timedelta(days=1),
        'iat': datetime.utcnow()
    }

    token = jwt.encode(payload, 'my_secret_key', algorithm='HS256')
    return token


def decode_jwt(token):
    """
    Decode a JWT to retrieve the payload.

    :param token: The JWT token to decode.
    :return: The decoded payload as a dictionary.
    """
    try:
        payload = jwt.decode(token, 'my_secret_key', algorithms=['HS256'])
        return payload['data']
    except jwt.ExpiredSignatureError:
        raise Exception('Token has expired')
    except jwt.InvalidTokenError:
        raise Exception('Invalid token')
