
import sqlite3
import secrets

from functools import wraps
from flask import Flask, request, jsonify, g
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
DATABASE = "nokiachat.db"


def connect_db():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    return db


def init_db():
    db = connect_db()
    db.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS tokens (
        token TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS conversations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        kind TEXT NOT NULL,
        name TEXT
    );

    CREATE TABLE IF NOT EXISTS members (
        conversation_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        PRIMARY KEY (conversation_id, user_id)
    );

    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        conversation_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        content TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    """)
    db.commit()
    db.close()


def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "Login required"}), 401

        db = connect_db()
        user = db.execute("""
            SELECT users.id, users.username
            FROM tokens
            JOIN users ON users.id = tokens.user_id
            WHERE tokens.token = ?
        """, (auth[7:],)).fetchone()
        db.close()

        if user is None:
            return jsonify({"error": "Invalid token"}), 401

        g.user = user
        return func(*args, **kwargs)
    return wrapper


@app.post("/register")
def register():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or len(username) > 20:
        return jsonify({"error": "Invalid username"}), 400
    if not isinstance(password, str) or len(password) < 8:
        return jsonify({"error": "Password too short"}), 400

    db = connect_db()
    try:
        db.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            (username, generate_password_hash(password))
        )
        db.commit()
    except sqlite3.IntegrityError:
        db.close()
        return jsonify({"error": "Username already exists"}), 409

    db.close()
    return jsonify({"success": True})


@app.post("/login")
def login():
    data = request.get_json(silent=True) or {}
    db = connect_db()
    user = db.execute(
        "SELECT * FROM users WHERE username = ?",
        (data.get("username", ""),)
    ).fetchone()

    if user is None or not check_password_hash(
        user["password"], data.get("password", "")
    ):
        db.close()
        return jsonify({"error": "Wrong username or password"}), 401

    token = secrets.token_urlsafe(32)
    db.execute(
        "INSERT INTO tokens (token, user_id) VALUES (?, ?)",
        (token, user["id"])
    )
    db.commit()
    db.close()

    return jsonify({"token": token, "username": user["username"]})


@app.post("/conversations")
@login_required
def create_conversation():
    data = request.get_json(silent=True) or {}
    kind = data.get("kind")
    member_ids = data.get("members", [])

    if kind not in ("private", "group"):
        return jsonify({"error": "Invalid conversation type"}), 400
    if not isinstance(member_ids, list):
        return jsonify({"error": "Invalid members"}), 400

    try:
        member_ids = set(member_ids)
        member_ids.add(g.user["id"])
        member_ids = sorted(member_ids)

        if kind == "private" and len(member_ids) != 2:
            return jsonify({"error": "Private chat needs two users"}), 400
        if kind == "group" and len(member_ids) < 2:
            return jsonify({"error": "Group needs two users"}), 400

        db = connect_db()
        placeholders = ",".join("?" for _ in member_ids)
        users = db.execute(
            f"SELECT id FROM users WHERE id IN ({placeholders})",
            tuple(member_ids)
        ).fetchall()

        if len(users) != len(member_ids):
            db.close()
            return jsonify({"error": "Unknown user"}), 400

        name = data.get("name") if kind == "group" else None
        cur = db.execute(
            "INSERT INTO conversations (kind, name) VALUES (?, ?)",
            (kind, name)
        )
        conversation_id = cur.lastrowid

        for user_id in member_ids:
            db.execute(
                "INSERT INTO members VALUES (?, ?)",
                (conversation_id, user_id)
            )

        db.commit()
        db.close()
        return jsonify({"conversation_id": conversation_id})

    except (TypeError, ValueError):
        return jsonify({"error": "Invalid member IDs"}), 400


@app.post("/messages")
@login_required
def send_message():
    data = request.get_json(silent=True) or {}
    conversation_id = data.get("conversation_id")
    content = data.get("content", "")

    if not isinstance(content, str) or not content.strip() or len(content) > 1000:
        return jsonify({"error": "Invalid message"}), 400

    db = connect_db()
    member = db.execute("""
        SELECT 1 FROM members
        WHERE conversation_id = ? AND user_id = ?
    """, (conversation_id, g.user["id"])).fetchone()

    if member is None:
        db.close()
        return jsonify({"error": "Conversation not found"}), 404

    cur = db.execute("""
        INSERT INTO messages (conversation_id, user_id, content)
        VALUES (?, ?, ?)
    """, (conversation_id, g.user["id"], content.strip()))

    message_id = cur.lastrowid
    db.commit()
    db.close()
    return jsonify({"message_id": message_id})


@app.get("/messages/<int:conversation_id>")
@login_required
def get_messages(conversation_id):
    after = request.args.get("after", default=0, type=int)
    db = connect_db()

    member = db.execute("""
        SELECT 1 FROM members
        WHERE conversation_id = ? AND user_id = ?
    """, (conversation_id, g.user["id"])).fetchone()

    if member is None:
        db.close()
        return jsonify({"error": "Conversation not found"}), 404

    messages = db.execute("""
        SELECT messages.id, users.username,
               messages.content, messages.created_at
        FROM messages
        JOIN users ON users.id = messages.user_id
        WHERE messages.conversation_id = ? AND messages.id > ?
        ORDER BY messages.id ASC
        LIMIT 100
    """, (conversation_id, after)).fetchall()

    db.close()
    return jsonify([dict(row) for row in messages])


@app.get("/health")
def health():
    return jsonify({"status": "ok", "name": "NokiaChat"})


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=False)
