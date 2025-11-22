import socket
import threading
import time
import csv
import sys

import base64
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

HOST = '127.0.0.1'
PORT = 55555

 # Default parameters: can be overridden via command line
DEFAULT_CLIENTS = 5
DEFAULT_MESSAGES_PER_CLIENT = 5

 # ======= Encryption config: must be identical to server/client/encryption.py =======
PASSPHRASE = b"my_super_secret_chatroom_password"
SALT = b"static_salt_1234"


def _derive_key() -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=390000,
    )
    key = kdf.derive(PASSPHRASE)
    return base64.urlsafe_b64encode(key)


_KEY = _derive_key()
_cipher = Fernet(_KEY)


def encrypt_msg(plaintext: str) -> bytes:
    return _cipher.encrypt(plaintext.encode("utf-8"))


def decrypt_msg(token: bytes) -> str:
    return _cipher.decrypt(token).decode("utf-8")


 # ======= Global results array =======
results_lock = threading.Lock()
 # Each record: (client_id, msg_index, rtt_seconds)
results = []


def bot_worker(client_id: int, messages_per_client: int):
    """
    Single bot client:
    - Connect to server
    - /nick botX
    - Send several MSG-X-Y messages
    - Wait for server to broadcast back its own message, calculate RTT
    """
    nickname = f"bot{client_id}"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            # Each recv blocks at most 1 second, prevents hanging
            s.settimeout(1.0)
            s.connect((HOST, PORT))
            print(f"[bot{client_id}] Connected to server")

            # 1) Send nickname command
            s.sendall(encrypt_msg(f"/nick {nickname}\n"))

            # 2) Try to read welcome / system messages a few times (just to clear buffer)
            start = time.time()
            while time.time() - start < 2.0:
                try:
                    data = s.recv(4096)
                except socket.timeout:
                    break
                if not data:
                    break
                try:
                    _ = decrypt_msg(data)
                except InvalidToken:
                    # Received incomplete or concatenated ciphertext, just discard
                    continue
                except Exception:
                    break

            # 3) Send test messages
            for m in range(messages_per_client):
                payload = f"MSG-{client_id}-{m}"
                t0 = time.time()
                s.sendall(encrypt_msg(payload + "\n"))

                # Wait up to 2 seconds for own broadcast, prevents infinite loop
                wait_deadline = t0 + 2.0
                while True:
                    now = time.time()
                    if now > wait_deadline:
                        print(f"[bot{client_id}] Timeout waiting for broadcast of {payload}, skipping this one")
                        break

                    try:
                        data = s.recv(4096)
                    except socket.timeout:
                        # No data received this time, keep waiting
                        continue

                    if not data:
                        print(f"[bot{client_id}] Connection closed")
                        return

                    try:
                        text = decrypt_msg(data)
                    except InvalidToken:
                        # Possibly multiple/partial ciphertexts concatenated, if can't decrypt just discard and continue
                        continue
                    except Exception as e:
                        print(f"[bot{client_id}] Decryption failed: {e}")
                        return

                    # Server broadcast format: [nickname] MSG-...
                    if f"[{nickname}]" in text and payload in text:
                        t1 = time.time()
                        rtt = t1 - t0
                        with results_lock:
                            results.append((client_id, m, rtt))
                        print(f"[bot{client_id}] Message {m} RTT = {rtt:.4f} seconds")
                        break

    except Exception as e:
        print(f"[bot{client_id}] Error: {e}")


def main():
    # Command line argument parsing: python load_test.py 10 5
    if len(sys.argv) >= 2:
        num_clients = int(sys.argv[1])
    else:
        num_clients = DEFAULT_CLIENTS

    if len(sys.argv) >= 3:
        messages_per_client = int(sys.argv[2])
    else:
        messages_per_client = DEFAULT_MESSAGES_PER_CLIENT

    print(f"[SYSTEM] Preparing to start {num_clients} clients, each sending {messages_per_client} messages.")
    print("[SYSTEM] Please make sure the encrypted server is running.")

    threads = []
    for cid in range(num_clients):
        t = threading.Thread(target=bot_worker, args=(cid, messages_per_client))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    if not results:
        print("[SYSTEM] No RTT data collected, server may not be running or encryption config mismatch.")
        return

    filename = "latency_log.csv"
    try:
        with open(filename, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["client_id", "message_index", "rtt_seconds"])
            writer.writerows(results)
    except Exception as e:
        print(f"[SYSTEM] Failed to write CSV file: {e}")
        return

    all_rtts = [r[2] for r in results]
    avg_rtt = sum(all_rtts) / len(all_rtts)
    max_rtt = max(all_rtts)
    min_rtt = min(all_rtts)

    print(f"[SYSTEM] Recorded {len(results)} RTT data entries")
    print(f"[SYSTEM] Average RTT: {avg_rtt:.4f} seconds")
    print(f"[SYSTEM] Minimum RTT: {min_rtt:.4f} seconds")
    print(f"[SYSTEM] Maximum RTT: {max_rtt:.4f} seconds")
    print(f"[SYSTEM] Detailed data written to {filename}")


if __name__ == "__main__":
    main()
