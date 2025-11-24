(() => {
	const socket = io({
		transports: ["websocket", "polling"],
		reconnection: true,
		reconnectionAttempts: 8,
		reconnectionDelay: 800
	});

	const messagesEl = document.getElementById("messages");
	const nicknameEl = document.getElementById("nickname");
	const setNickBtn = document.getElementById("setNickBtn");
	const messageInputEl = document.getElementById("messageInput");
	const sendBtn = document.getElementById("sendBtn");
	const nickStatusEl = document.getElementById("nickStatus");

	let currentNick = "";

	function appendMessage(text, cssClass = "") {
		const line = document.createElement("div");
		line.className = `line ${cssClass}`.trim();
		line.textContent = text;
		messagesEl.appendChild(line);
		messagesEl.scrollTop = messagesEl.scrollHeight;
	}

	// Connection lifecycle logs/status
	socket.on("connect", () => {
		appendMessage("[SYSTEM] Connected", "system");
	});
	socket.on("disconnect", (reason) => {
		appendMessage(`[SYSTEM] Disconnected: ${reason}`, "system");
	});
	socket.on("connect_error", (err) => {
		appendMessage(`[SYSTEM] Connect error: ${err.message}`, "system");
	});
	socket.on("reconnect_attempt", (n) => {
		appendMessage(`[SYSTEM] Reconnect attempt ${n}`, "system");
	});

	socket.on("nick", (payload) => {
		if (payload && payload.nickname) {
			currentNick = payload.nickname;
			nickStatusEl.textContent = `Nickname: ${currentNick}`;
		}
	});

	socket.on("system", (payload) => {
		if (payload && payload.text) {
			appendMessage(payload.text, "system");
			nickStatusEl.textContent = payload.text.startsWith("Your nickname is now")
				? "Nickname set"
				: nickStatusEl.textContent;
		}
	});

	socket.on("broadcast", (payload) => {
		if (payload && payload.text) {
			appendMessage(payload.text, "broadcast");
		}
	});

	socket.on("message", (payload) => {
		if (payload && payload.text) {
			const sender = payload.sender || "";
			let isSelf = !!currentNick && sender === currentNick;
			// Fallback: if sender missing (older messages), infer by prefix
			if (!isSelf && currentNick && !sender) {
				const prefix = `[${currentNick}]`;
				if (payload.text.startsWith(prefix)) isSelf = true;
			}
			appendMessage(payload.text, isSelf ? "self" : "other");
		}
	});

	setNickBtn.addEventListener("click", () => {
		const desired = nicknameEl.value.trim();
		socket.emit("set_nick", { nickname: desired });
	});

	messageInputEl.addEventListener("keyup", (ev) => {
		if (ev.key === "Enter") {
			sendBtn.click();
		}
	});

	sendBtn.addEventListener("click", () => {
		const text = messageInputEl.value;
		if (!text.trim()) return;
		socket.emit("chat_message", { text });
		messageInputEl.value = "";
		messageInputEl.focus();
	});

	// Autofocus nickname on first load
	nicknameEl.focus();
})();


