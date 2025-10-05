
"""
launcher_api - Flask backend for your SAMP launcher
Features:
- Register / Login with JWT
- Endpoints: /version, /news, /mods, /server_status
- Simple SQLite storage for users and server status
- Reads static JSON files from data/ for version/news/mods (you can update these from GitHub)
- CORS enabled so your launcher can call it from desktop clients
Notes:
- Replace SECRET_KEY with a secure value in production (use environment variable)
- To run locally:
    pip install -r requirements.txt
    python app.py
- To deploy on Render/Railway, push this repo to GitHub and follow their deploy steps.
"""

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import os
import json
import time
import jwt

# ---------------- Config ----------------
APP_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(APP_DIR, "data")
DB_PATH = os.path.join(APP_DIR, "launcher.db")

# Secret: replace with env var in production!
SECRET_KEY = os.environ.get("LAUNCHER_SECRET", "replace_this_with_a_secure_secret")

JWT_ALGO = "HS256"
TOKEN_EXP_SECONDS = 60 * 60 * 24 * 7  # 7 days

# Ensure data folder exists
os.makedirs(DATA_DIR, exist_ok=True)

# Default sample files if missing
def ensure_default_files():
    version_f = os.path.join(DATA_DIR, "version.json")
    news_f = os.path.join(DATA_DIR, "news.json")
    mods_f = os.path.join(DATA_DIR, "mods.json")
    server_f = os.path.join(DATA_DIR, "server.json")

    if not os.path.exists(version_f):
        with open(version_f, "w", encoding="utf-8") as f:
            json.dump({
                "latest_version": "1.0.0",
                "changelog": "Initial release",
                "players_online": 0,
                "server_ip": "87.107.155.110",
                "server_port": 15226
            }, f, indent=2)

    if not os.path.exists(news_f):
        with open(news_f, "w", encoding="utf-8") as f:
            json.dump({
                "news": [
                    {"title": "Welcome", "content": "Launcher API ready."}
                ]
            }, f, indent=2)

    if not os.path.exists(mods_f):
        with open(mods_f, "w", encoding="utf-8") as f:
            json.dump({
                "mods": [
                    {"name": "Example Mod", "version": "1.0", "description": "Test mod", "download_url": "https://example.com/mod.zip"}
                ]
            }, f, indent=2)

    if not os.path.exists(server_f):
        with open(server_f, "w", encoding="utf-8") as f:
            json.dump({
                "name": "My SAMP Server",
                "server_ip": "87.107.155.110",
                "server_port": 15226,
                "players_online": 0,
                "max_players": 100,
                "updated_at": int(time.time())
            }, f, indent=2)

ensure_default_files()

# ---------------- DB ----------------
def init_db():
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at INTEGER NOT NULL
        )
    """)
    con.commit()
    con.close()

init_db()

# ---------------- App ----------------
app = Flask(__name__)
CORS(app)

# ---------------- Helpers ----------------
def create_token(user_id, username):
    payload = {
        "uid": user_id,
        "username": username,
        "iat": int(time.time()),
        "exp": int(time.time()) + TOKEN_EXP_SECONDS
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALGO)
    # PyJWT returns str in v2+, ensure str
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    return token

def verify_token(token):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGO])
        return payload
    except Exception:
        return None

def read_json_file(name):
    path = os.path.join(DATA_DIR, name)
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

# ---------------- Routes ----------------
@app.route("/")
def index():
    return jsonify({"message": "Launcher API Online", "version": "0.1"})

# -- version endpoint (read from data/version.json)
@app.route("/version", methods=["GET"])
def version():
    data = read_json_file("version.json") or read_json_file("update.json")
    if not data:
        return jsonify({"error": "version file not found"}), 404
    return jsonify(data)

# -- news endpoint
@app.route("/news", methods=["GET"])
def news():
    data = read_json_file("news.json")
    if not data:
        return jsonify({"news": []})
    return jsonify(data)

# -- mods endpoint
@app.route("/mods", methods=["GET"])
def mods():
    data = read_json_file("mods.json")
    if not data:
        return jsonify({"mods": []})
    return jsonify(data)

# -- server status (reads server.json)
@app.route("/server_status", methods=["GET"])
def server_status():
    data = read_json_file("server.json")
    if not data:
        return jsonify({"error": "server info not found"}), 404
    return jsonify(data)

# -- register
@app.route("/register", methods=["POST"])
def register():
    body = request.get_json(force=True)
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""

    if not username or not password:
        return jsonify({"status": "error", "message": "username and password required"}), 400

    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("SELECT id FROM users WHERE username=?", (username,))
    if cur.fetchone():
        con.close()
        return jsonify({"status": "error", "message": "username already exists"}), 409

    pw_hash = generate_password_hash(password)
    cur.execute("INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                (username, pw_hash, int(time.time())))
    con.commit()
    user_id = cur.lastrowid
    con.close()

    token = create_token(user_id, username)
    return jsonify({"status": "ok", "token": token, "username": username})

# -- login
@app.route("/login", methods=["POST"])
def login():
    body = request.get_json(force=True)
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""

    if not username or not password:
        return jsonify({"status": "error", "message": "username and password required"}), 400

    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("SELECT id, password_hash FROM users WHERE username=?", (username,))
    row = cur.fetchone()
    con.close()
    if not row:
        return jsonify({"status": "error", "message": "invalid credentials"}), 401

    user_id, pw_hash = row
    if not check_password_hash(pw_hash, password):
        return jsonify({"status": "error", "message": "invalid credentials"}), 401

    token = create_token(user_id, username)
    return jsonify({"status": "ok", "token": token, "username": username})

# -- admin: update server status (protected by SECRET_KEY query param or JWT)
@app.route("/admin/update_server", methods=["POST"])
def admin_update_server():
    # simple protection: require secret in header or query param
    secret = request.headers.get("X-ADMIN-SECRET") or request.args.get("secret")
    if not secret or secret != SECRET_KEY:
        return jsonify({"status": "error", "message": "unauthorized"}), 401

    body = request.get_json(force=True)
    srv = read_json_file("server.json") or {}
    srv.update(body)
    srv["updated_at"] = int(time.time())
    with open(os.path.join(DATA_DIR, "server.json"), "w", encoding="utf-8") as f:
        json.dump(srv, f, indent=2)
    return jsonify({"status": "ok", "server": srv})

# -- optional: serve files from data/ (useful for small mod zips you store in repo)
@app.route("/data/<path:filename>", methods=["GET"])
def serve_data(filename):
    return send_from_directory(DATA_DIR, filename, as_attachment=True)

# ---------------- Run ----------------
if __name__ == "__main__":
    # Use port from env if provided (Render sets PORT)
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
