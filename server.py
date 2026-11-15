
import os
import secrets
from pathlib import Path
from functools import wraps

from flask import Flask, request, jsonify, g
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)

database_url = os.environ.get("DATABASE_URL")

if database_url:
    if database_url.startswith("postgres://"):
        database_url = database_url.replace(
            "postgres://", "postgresql+psycopg://", 1
        )
    elif database_url.startswith("postgresql://"):
        database_url = database_url.replace(
            "postgresql://", "postgresql+psycopg://", 1
        )
    app.config["SQLALCHEMY_DATABASE_URI"] = database_url
else:
    db_path = Path(__file__).resolve().parent / "nokiachat.db"
    app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{db_path}"

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)


class Token(db.Model):
    token = db.Column(db.String(100), primary_key=True)
    user_id = db.Column(db.Integer, ForeignKey("user.id"), nullable=False)


class Conversation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    kind = db.Column(db.String(10), nullable=False)
    name = db.Column(db.String(60))


class Member(db.Model):
    conversation_id = db.Column(
        db.Integer, ForeignKey("conversation.id"), primary_key=True
    )
    user_id = db.Column(
        db.Integer, ForeignKey("user.id"), primary_key=True
    )


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    conversation_id = db.Column(
        db.Integer, ForeignKey("conversation.id"), nullable=False
    )
    user_id = db.Column(
        db.Integer, ForeignKey("user.id"), nullable=False
    )
    content = db.Column(db.String(1000), nullable=False)
    created_at = db.Column(
        db.DateTime, server_default=db.func.current_timestamp()
    )


def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")

        if not auth.startswith("Bearer "):
            return jsonify({"error": "Login required"}), 401

        print("DEBUG AUTH PREFIX:", repr(auth[:7]), flush=True)
        print("DEBUG TOKEN LENGTH:", len(auth[7:]), flush=True)
        
        token = db.session.get(Token, auth[7:])

        if token is None:
            return jsonify({"error": "Invalid token"}), 401

        user = db.session.get(User, token.user_id)

        if user is None:
            return jsonify({"error": "Invalid token"}), 401

        g.user = user
        return func(*args, **kwargs)

    return wrapper


@app.post("/register")
def register():
    data = request.get_json(silent=True) or {}

    print("DEBUG JSON:", data, flush=True)
    print("DEBUG CONTENT TYPE:", request.content_type, flush=True)

    username = data.get("username")
    password = data.get("password")

    if not isinstance(username, str):
        return jsonify({"error": "Invalid username"}), 400

    username = username.strip()

    if not username or len(username) > 20:
        return jsonify({"error": "Invalid username"}), 400

    if not isinstance(password, str) or len(password) < 8:
        return jsonify({"error": "Password too short"}), 400

    user = User(
        username=username,
        password=generate_password_hash(password)
    )

    db.session.add(user)

    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        return jsonify({"error": "Username already exists"}), 409

    return jsonify({"success": True})


@app.post("/login")
def login():
    data = request.get_json(silent=True) or {}

    username = data.get("username")
    password = data.get("password")

    if not isinstance(username, str) or not isinstance(password, str):
        return jsonify({"error": "Invalid login data"}), 400

    user = User.query.filter_by(username=username).first()

    if user is None or not check_password_hash(user.password, password):
        return jsonify({"error": "Wrong username or password"}), 401

    token_value = secrets.token_urlsafe(32)

    db.session.add(Token(token=token_value, user_id=user.id))
    db.session.commit()

    return jsonify({
        "token": token_value,
        "username": user.username
    })


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

    if any(type(uid) is not int or uid <= 0 for uid in member_ids):
        return jsonify({"error": "Invalid member IDs"}), 400

    member_ids = set(member_ids)
    member_ids.add(g.user.id)
    member_ids = sorted(member_ids)

    if kind == "private" and len(member_ids) != 2:
        return jsonify({"error": "Private chat needs two users"}), 400

    if kind == "group" and len(member_ids) < 2:
        return jsonify({"error": "Group needs two users"}), 400

    users = User.query.filter(User.id.in_(member_ids)).all()

    if len(users) != len(member_ids):
        return jsonify({"error": "Unknown user"}), 400

    name = data.get("name") if kind == "group" else None

    if name is not None:
        if not isinstance(name, str) or len(name) > 60:
            return jsonify({"error": "Invalid group name"}), 400

    conversation = Conversation(kind=kind, name=name)
    db.session.add(conversation)
    db.session.flush()

    for user_id in member_ids:
        db.session.add(Member(
            conversation_id=conversation.id,
            user_id=user_id
        ))

    db.session.commit()

    return jsonify({"conversation_id": conversation.id})


@app.post("/messages")
@login_required
def send_message():
    data = request.get_json(silent=True) or {}

    print("DEBUG JSON:", data, flush=True)
    print("DEBUG CONTENT TYPE:", request.content_type, flush=True)

    conversation_id = data.get("conversation_id")
    content = data.get("content", "")

    if isinstance(conversation_id, bool) or not isinstance(conversation_id, int):
        return jsonify({
            "error": "Invalid conversation ID",
            "received": repr(conversation_id),
            "type": str(type(conversation_id)),
         "content_type": request.content_type
        }), 400
        

    if not isinstance(content, str) or not content.strip() or len(content) > 1000:
        return jsonify({"error": "Invalid message"}), 400

    member = Member.query.filter_by(
        conversation_id=conversation_id,
        user_id=g.user.id
    ).first()

    if member is None:
        return jsonify({"error": "Conversation not found"}), 404

    message = Message(
        conversation_id=conversation_id,
        user_id=g.user.id,
        content=content.strip()
    )

    db.session.add(message)
    db.session.commit()

    return jsonify({"message_id": message.id})


@app.get("/messages/<int:conversation_id>")
@login_required
def get_messages(conversation_id):
    after = request.args.get("after", default=0, type=int)

    if after is None or after < 0:
        return jsonify({"error": "Invalid message ID"}), 400

    member = Member.query.filter_by(
        conversation_id=conversation_id,
        user_id=g.user.id
    ).first()

    if member is None:
        return jsonify({"error": "Conversation not found"}), 404

    messages = (
        db.session.query(Message, User.username)
        .join(User, User.id == Message.user_id)
        .filter(
            Message.conversation_id == conversation_id,
            Message.id > after
        )
        .order_by(Message.id.asc())
        .limit(100)
        .all()
    )

    result = []

    for message, username in messages:
        result.append({
            "id": message.id,
            "username": username,
            "content": message.content,
            "created_at": (
                message.created_at.isoformat()
                if message.created_at else None
            )
        })

    return jsonify(result)


@app.get("/health")
def health():
    return jsonify({"status": "ok", "name": "NokiaChat"})


with app.app_context():
    db.create_all()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)

