import socket
import threading

from cryptography.fernet import InvalidToken
from encryption import encrypt_msg, decrypt_msg  # encryption.py in the current directory

HOST = '127.0.0.1'
PORT = 55555

 # Store all online client sockets
clients = []
 # Store each client's nickname: socket -> nickname
nicknames = {}
clients_lock = threading.Lock()  # Lock when accessing clients and nicknames to prevent multithreading conflicts


def send_encrypted(sock: socket.socket, text: str):
    """Encrypt text and send to a client."""
    try:
        token = encrypt_msg(text)
        sock.sendall(token)
    except Exception as e:
        print(f"[SYSTEM] Failed to send encrypted message to client: {e}")


def broadcast(message: str, sender_sock=None):
    """
    Broadcast message to all online clients (send after encryption).
    message is a string with prefix.
    sender_sock is currently only for extension (e.g., not sending back to self in future), not used here.
    """
    try:
        data = encrypt_msg(message + "\n")
    except Exception as e:
        print(f"[SYSTEM] Failed to encrypt before broadcast: {e}")
        return

    with clients_lock:
        dead_clients = []
        for c in clients:
            try:
                c.sendall(data)
            except (BrokenPipeError, OSError):
                dead_clients.append(c)

        for dc in dead_clients:
            if dc in clients:
                clients.remove(dc)
            if dc in nicknames:
                del nicknames[dc]


def find_socket_by_nickname(target_name: str):
    """Find the socket corresponding to the nickname, return None if not found."""
    with clients_lock:
        for sock, name in nicknames.items():
            if name == target_name:
                return sock
    return None


def handle_client(conn: socket.socket, addr):
    """Each client corresponds to a thread: responsible for nickname management, command parsing, message forwarding (all encrypted communication)."""
    print(f"[SYSTEM] Client connected: {addr}")

    with clients_lock:
        clients.append(conn)

    nickname = None
    try:
        # Prompt client to set nickname first
        send_encrypted(conn, "Welcome to the secure chatroom!\n")
        send_encrypted(conn, "Please set your nickname first using a command, e.g.: /nick Alice\n")

        while True:
            data = conn.recv(4096)
            if not data:
                print(f"[SYSTEM] Client disconnected: {addr}")
                break

            try:
                msg = decrypt_msg(data).strip()
            except InvalidToken:
                print(f"[SYSTEM] Received data could not be decrypted, from {addr}, discarded.")
                continue
            except Exception as e:
                print(f"[SYSTEM] Decryption failed from {addr}: {e}")
                continue

            if not msg:
                continue

            # Only allow /nick if nickname not set yet
            if nickname is None:
                if msg.startswith("/nick "):
                    desired = msg[6:].strip()
                    if not desired:
                        send_encrypted(conn, "Nickname cannot be empty, please re-enter, e.g.: /nick Alice\n")
                        continue

                    with clients_lock:
                        if desired in nicknames.values():
                            send_encrypted(conn, f"Nickname {desired} is already taken, please choose another one.\n")
                            continue
                        nicknames[conn] = desired
                        nickname = desired

                    send_encrypted(conn, f"[SYSTEM] Your current nickname is: {nickname}\n")
                    broadcast(f"[SYSTEM] {nickname} joined the chatroom.", sender_sock=conn)
                    print(f"[SYSTEM] {addr} set nickname to {nickname}")
                else:
                    send_encrypted(conn, "Please use /nick your_name to set nickname first, e.g.: /nick Alice\n")
                continue

            # Nickname already set, start handling commands / normal chat
            print(f"[RECEIVED][{nickname}@{addr}] {msg}")

            # Change nickname: /nick new_name
            if msg.startswith("/nick "):
                new_name = msg[6:].strip()
                if not new_name:
                    send_encrypted(conn, "New nickname cannot be empty.\n")
                    continue

                with clients_lock:
                    if new_name in nicknames.values():
                        send_encrypted(conn, f"Nickname {new_name} is already taken, please choose another one.\n")
                        continue
                    old_name = nickname
                    nicknames[conn] = new_name
                    nickname = new_name

                send_encrypted(conn, f"[SYSTEM] You have changed your nickname to: {nickname}\n")
                broadcast(f"[SYSTEM] {old_name} changed nickname to {nickname}.", sender_sock=conn)
                continue

            # Private chat: /w target_nickname message
            if msg.startswith("/w "):
                parts = msg.split(" ", 2)
                if len(parts) < 3:
                    send_encrypted(conn, "Private chat command format: /w target_nickname message\n")
                    continue

                target_name = parts[1].strip()
                content = parts[2].strip()
                if not content:
                    send_encrypted(conn, "Private chat message cannot be empty.\n")
                    continue

                target_sock = find_socket_by_nickname(target_name)
                if target_sock is None:
                    send_encrypted(conn, f"[SYSTEM] User with nickname {target_name} not found.\n")
                    continue

                # Send to target
                try:
                    send_encrypted(target_sock, f"[PRIVATE][{nickname} -> you] {content}\n")
                except Exception:
                    send_encrypted(conn, f"[SYSTEM] Private chat failed, target may be offline.\n")
                    continue

                # Confirm to self
                try:
                    send_encrypted(conn, f"[PRIVATE][you -> {target_name}] {content}\n")
                except Exception:
                    pass
                continue

            # Normal message: group chat
            broadcast(f"[{nickname}] {msg}", sender_sock=conn)

    except (ConnectionResetError, OSError):
        print(f"[SYSTEM] Client connection interrupted due to error: {addr}")

    finally:
        with clients_lock:
            if conn in clients:
                clients.remove(conn)
            left_name = nicknames.pop(conn, None)
        conn.close()
        if left_name:
            broadcast(f"[SYSTEM] {left_name} left the chatroom.")
            print(f"[SYSTEM] {left_name}@{addr} offline and cleaned up.")
        else:
            print(f"[SYSTEM] Client without nickname {addr} cleaned up.")


def server_console():
    """
    Server's own console input thread:
    Input on the server side will be broadcast to all clients.
    """
    while True:
        try:
            msg = input("You (server broadcast): ")
        except EOFError:
            break

        if msg.strip().lower() in ("/quit", "/exit"):
            print("[SYSTEM] Server console input thread exited (will not automatically kill connected clients)")
            break

        broadcast(f"[SERVER] {msg}")


def run_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        s.bind((HOST, PORT))
        s.listen()
        print(f"[SYSTEM] Server started, listening on {HOST}:{PORT} (encrypted communication enabled)...")

        console_thread = threading.Thread(target=server_console, daemon=True)
        console_thread.start()

        while True:
            try:
                conn, addr = s.accept()
            except OSError:
                print("[SYSTEM] accept error, server will exit soon")
                break

            client_thread = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            client_thread.start()


if __name__ == "__main__":
    run_server()
