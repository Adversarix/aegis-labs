from flask import Flask, request
from storage import read_document
from auth import require_login

app = Flask(__name__)

@app.route("/download")
@require_login
def download():
    return read_document(request.args.get("name", ""))
