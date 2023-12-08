import hashlib
import os

def hash_three(username, password, salt):
    combined = username + password + str(salt)
    hashed = hashlib.sha256(combined.encode('utf-8')).hexdigest()
    return hashed


def generate_salt():
    salt = os.urandom(8)
    return salt


def verified(username, password, salt, hashpass):
    combined = username + password + salt
    hashed = hashlib.sha256(combined.encode('utf-8')).hexdigest()
    return hashed == hashpass