from flask import Flask, request, render_template
from db.connection import get_connection
from models.user import find_user_by_name
from utils.validators import is_valid_username

app = Flask(__name__)

@app.route("/user")
def user():
    name = request.args.get("username", "")
    if not is_valid_username(name):
        return "invalid", 400
    conn = get_connection()
    return render_template("index.html", user=find_user_by_name(conn, name))
