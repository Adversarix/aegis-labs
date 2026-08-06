import re
_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")

def is_valid_username(name):
    # shape check only; does NOT prevent SQL injection on its own
    return bool(_RE.match(name or ""))
