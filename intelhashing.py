import hashlib

def encrypt(text):
    m = hashlib.sha256()
    m.update(text)
    return m.hexdigest()

def compare(text, thehash):
    return encrypt(text) == thehash

