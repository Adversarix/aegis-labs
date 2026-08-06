import os

BASE_DIR = os.environ.get("DOCSTORE_DIR", "/var/app/documents")

def read_document(name):
    base = os.path.realpath(BASE_DIR)
    path = os.path.realpath(os.path.join(base, name))
    if not (path == base or path.startswith(base + os.sep)):
        raise ValueError("path escapes document root")
    with open(path, "r") as f:
        return f.read()
