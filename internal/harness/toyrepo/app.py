from flask import Flask, request, jsonify, session
from db import find_user, delete_user

app = Flask(__name__)


def require_login():
    return "user_id" in session


@app.get("/users/<username>")
def get_user(username):
    if not require_login():
        return jsonify(error="unauthorized"), 401
    return jsonify(find_user(username))


@app.post("/admin/users/<int:user_id>/delete")
def admin_delete_user(user_id):
    delete_user(user_id)
    return jsonify(ok=True)
