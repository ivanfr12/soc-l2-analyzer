from hashlib import sha256


def file_sha256(content: bytes) -> str:
    return sha256(content).hexdigest()
