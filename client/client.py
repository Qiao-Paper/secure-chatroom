import socket
import threading

from cryptography.fernet import InvalidToken
from encryption import encrypt_msg, decrypt_msg  # encryption.py in the current directory

HOST = '127.0.0.1'
PORT = 55555


def handle_receive(sock: socket.socket):
    """
    Background thread: Responsible for receiving encrypted messages from the server, decrypting, and printing them.
    """
    while True:
        try:
            data = sock.recv(4096)
            if not data:
                print("\n[SYSTEM] Server connection closed")
                break

            try:
                text = decrypt_msg(data)
            except InvalidToken:
                print("\n[SYSTEM] Received data could not be decrypted, discarded.")
                continue
            except Exception as e:
                print(f"\n[SYSTEM] Decryption failed: {e}")
                continue

            print(f"\n{text}", end="")
        except (ConnectionResetError, OSError):
            print("\n[SYSTEM] Connection interrupted due to error")
            break

    try:
        sock.close()
    except OSError:
        pass


def run_client():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        print(f"[SYSTEM] Connecting to server {HOST}:{PORT} ...")
        s.connect((HOST, PORT))
        print("[SYSTEM] Connected to server (encrypted communication).")
        print("[SYSTEM] First, set your nickname with a command, e.g.: /nick Alice")
        print("[SYSTEM] Normal chat: Just type your message and press Enter")
        print("[SYSTEM] Private chat: /w target_nickname message   e.g.: /w Bob hi")
        print("[SYSTEM] Exit: /quit or /exit\n")

        recv_thread = threading.Thread(target=handle_receive, args=(s,), daemon=True)
        recv_thread.start()

        while True:
            try:
                msg = input("You (client): ")
            except EOFError:
                break

            if msg.strip().lower() in ("/quit", "/exit"):
                print("[SYSTEM] Client connection closed")
                try:
                    s.close()
                except OSError:
                    pass
                break

            try:
                token = encrypt_msg(msg + "\n")
                s.sendall(token)
            except (BrokenPipeError, OSError):
                print("[SYSTEM] Unable to send message, connection closed")
                break


if __name__ == "__main__":
    run_client()
