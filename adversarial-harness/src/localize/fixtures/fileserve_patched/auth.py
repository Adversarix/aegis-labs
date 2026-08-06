from functools import wraps
from flask import request, abort

def require_login(fn):
    @wraps(fn)
    def wrapper(*a, **k):
        if not request.headers.get("Authorization"):
            abort(401)
        return fn(*a, **k)
    return wrapper
