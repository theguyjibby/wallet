from Crypto.Cipher import AES
import base64
import os
from hashlib import sha256



def encrypt_message(private_key, password):
    key = sha256(password.encode()).digest()
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(private_key.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode()

def decrypt_message(encrypted_message, password):
    key = sha256(password.encode()).digest()
    data = base64.b64decode(encrypted_message)
    nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    try:
        return cipher.decrypt_and_verify(ciphertext, tag).decode()
    except (ValueError, KeyError):
        return None