from typing import Dict, Optional

import eventlet
eventlet.monkey_patch()

from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit


def create_app() -> Flask:
	app = Flask(__name__, static_folder="static", template_folder="templates")

	# For local development, a secret key is fine to be static.
	app.config["SECRET_KEY"] = "dev_secret_key_for_secure_chatroom_web"
	return app


app = create_app()
# Force eventlet mode and enable logs for diagnostics through the tunnel
socketio = SocketIO(
	app,
	cors_allowed_origins="*",
	async_mode="eventlet",
	logger=True,
	engineio_logger=True,
	ping_interval=25,
	ping_timeout=60,
)

# Online user mappings
sid_to_nickname: Dict[str, str] = {}
nickname_to_sid: Dict[str, str] = {}


@app.route("/")
def index():
	return render_template("index.html")

@app.route("/healthz")
def healthz():
	return {"ok": True}


def assign_nickname(sid: str, desired: str) -> Optional[str]:
	desired = (desired or "").strip()
	if not desired:
		return "Nickname cannot be empty."
	if desired in nickname_to_sid:
		return f"Nickname {desired} is already taken."
	sid_to_nickname[sid] = desired
	nickname_to_sid[desired] = sid
	return None


@socketio.on("connect")
def on_connect():
	print(f"[WEB] client connected: sid={request.sid}")
	emit("system", {"text": "Welcome! Please set your nickname to start chatting."})


@socketio.on("set_nick")
def on_set_nick(data):
	sid = request.sid
	desired = (data or {}).get("nickname", "")
	print(f"[WEB] set_nick from sid={sid}, desired={desired!r}")
	error = assign_nickname(sid, desired)
	if error:
		emit("system", {"text": error})
		return
	nickname = sid_to_nickname[sid]
	# Tell this client its nickname explicitly for UI state
	emit("nick", {"nickname": nickname})
	emit("system", {"text": f"Your nickname is now: {nickname}"})
	emit("broadcast", {"text": f"[SYSTEM] {nickname} joined the chatroom."}, broadcast=True, include_self=False)


def find_sid_by_nickname(name: str) -> Optional[str]:
	return nickname_to_sid.get(name)


@socketio.on("chat_message")
def on_chat_message(data):
	sender_sid = request.sid
	text = (data or {}).get("text", "")
	nickname = sid_to_nickname.get(sender_sid)
	print(f"[WEB] chat_message from sid={sender_sid}, nick={nickname!r}, text={text!r}")

	# Guard: nickname must be set first
	if not nickname:
		emit("system", {"text": "Please set your nickname first."})
		return

	text = text.strip()
	if not text:
		return

	# Private message by command: /w target message
	if text.startswith("/w "):
		parts = text.split(" ", 2)
		if len(parts) < 3:
			emit("system", {"text": "Private chat format: /w target_nickname message"})
			return
		target_name = parts[1].strip()
		content = parts[2].strip()
		if not content:
			emit("system", {"text": "Private message cannot be empty."})
			return
		target_sid = find_sid_by_nickname(target_name)
		if not target_sid:
			emit("system", {"text": f"User {target_name} not found."})
			return
		# Send to target and confirm to self
		emit("message", {"text": f"[PRIVATE][{nickname} -> you] {content}", "sender": nickname}, room=target_sid)
		emit("message", {"text": f"[PRIVATE][you -> {target_name}] {content}", "sender": nickname})
		return

	# Change nickname: /nick new_name
	if text.startswith("/nick "):
		new_name = text[6:].strip()
		if not new_name:
			emit("system", {"text": "New nickname cannot be empty."})
			return
		if new_name in nickname_to_sid:
			emit("system", {"text": f"Nickname {new_name} is already taken."})
			return
		# Update mappings
		old_name = sid_to_nickname.get(sender_sid)
		if old_name:
			nickname_to_sid.pop(old_name, None)
		sid_to_nickname[sender_sid] = new_name
		nickname_to_sid[new_name] = sender_sid
		emit("system", {"text": f"You changed nickname to: {new_name}"})
		emit("broadcast", {"text": f"[SYSTEM] {old_name} changed nickname to {new_name}."}, broadcast=True, include_self=False)
		return

	# Normal broadcast message
	emit("message", {"text": f"[{nickname}] {text}", "sender": nickname}, broadcast=True)


@socketio.on("disconnect")
def on_disconnect():
	sid = request.sid
	left_name = sid_to_nickname.pop(sid, None)
	print(f"[WEB] client disconnected: sid={sid}, nick={left_name!r}")
	if left_name:
		nickname_to_sid.pop(left_name, None)
		emit("broadcast", {"text": f"[SYSTEM] {left_name} left the chatroom."}, broadcast=True, include_self=False)


if __name__ == "__main__":
	# Bind to all interfaces so it can be exposed via tunnel
	socketio.run(app, host="0.0.0.0", port=5000)


