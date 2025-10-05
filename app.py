from flask import Flask, request, jsonify
from flask_cors import CORS
import uuid, time

app = Flask(__name__)
CORS(app)

users = {}
sessions = {}

VERSION = "0.1"

@app.route("/", methods=["GET"])
def index():
    return jsonify({"message": "Launcher API Online", "version": VERSION})

@app.route("/ping", methods=["GET"])
def ping():
    return jsonify({"status": "ok", "message": "pong"})

@app.route("/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
    if username in users:
        return jsonify({"error": "User already exists"}), 400
    users[username] = {"password": password, "created": int(time.time())}
    return jsonify({"message": "User registered successfully", "username": username})

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
    user = users.get(username)
    if not user or user.get("password") != password:
        return jsonify({"error": "Invalid username or password"}), 401
    token = str(uuid.uuid4())
    sessions[token] = {"username": username, "created": int(time.time())}
    return jsonify({"message": "Login successful", "token": token, "username": username})

@app.route("/me", methods=["GET"])
def me():
    auth = request.headers.get("Authorization", "")
    token = None
    if auth.startswith("Bearer "):
        token = auth.split(" ", 1)[1].strip()
    if not token:
        token = request.args.get("token")
    if not token or token not in sessions:
        return jsonify({"error": "Unauthorized"}), 401
    username = sessions[token]["username"]
    return jsonify({"username": username, "message": f"Hello {username}"})

@app.route("/logout", methods=["POST"])
def logout():
    data = request.get_json(silent=True) or {}
    token = data.get("token") or request.headers.get("Authorization", "").replace("Bearer ", "")
    if token in sessions:
        del sessions[token]
    return jsonify({"message": "Logged out"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
