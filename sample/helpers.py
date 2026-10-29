import re
import logging
from vulnerable_sample import hash_password


def register(username, password):
    # hash_password is used here, so it should NOT be reported as unused project-wide
    return {"user": username, "hash": hash_password(password)}
