
from cryptography.fernet import Fernet
ENCRYPTION_KEY = 'Z3JpcHBoaFZObm9BQjZTd2ZIV1NFQ1A3UkE5VWVWc3U='
from django.conf import settings

cipher = Fernet(ENCRYPTION_KEY)

# Encrypt a string


def encrypt_string(plain_text):
    return cipher.encrypt(plain_text.encode()).decode()

# Decrypt a string


def decrypt_string(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()
