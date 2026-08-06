import os

BASE_DIR = os.environ.get("DOCSTORE_DIR", "/var/app/documents")

def read_document(name):
    # Return the contents of a stored document by name.
    path = os.path.join(BASE_DIR, name)
    with open(path, "r") as f:
        return f.read()
