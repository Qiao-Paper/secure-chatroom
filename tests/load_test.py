import socket
import threading
import time
import csv
import sys

# 为了和 server/client 一致，这里直接复制相同的加密逻辑
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import InvalidToken


HOST = '127.0.0.1'
PORT = 55555

# 默认参数：可以通过命令行替换
DEFAULT_CLIENTS = 5
DEFAULT_MESSAGES_PER_CLIENT = 5


# ======= 加密相关：必须和 server/client/encryption.py 保持一致 =======
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


# ======= 压测逻辑 =======
results_lock = threading.Lock()
# 每条记录：(client_id, msg_index, rtt_seconds)
results = []


def bot_worker(client_id: int, messages_per_client: int):
    nickname = f"bot{client_id}"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((HOST, PORT))
        s.settimeout(5.0)
        print(f"[bot{client_id}] 已连接到服务器")

        # 发送昵称命令
        s.sendall(encrypt_msg(f"/nick {nickname}\n"))

        # 略微读取几条欢迎和系统消息，但不做处理
        try:
            for _ in range(5):
                data = s.recv(4096)
                if not data:
                    break
                _ = decrypt_msg(data)
        except Exception:
            pass

        for m in range(messages_per_client):
            # 构造一条只有自己会用到的特殊内容，方便匹配
            payload = f"MSG-{client_id}-{m}"
            t0 = time.time()
            s.sendall(encrypt_msg(payload + "\n"))

            # 等待服务器广播回这一条
            while True:
                try:
                    data = s.recv(4096)
                    if not data:
                        print(f"[bot{client_id}] 连接被关闭")
                        return
                    text = decrypt_msg(data)
                except (InvalidToken, TimeoutError):
                    continue
                except Exception:
                    return

                # 广播格式是：[nickname] 消息
                if f"[{nickname}]" in text and payload in text:
                    t1 = time.time()
                    rtt = t1 - t0
                    with results_lock:
                        results.append((client_id, m, rtt))
                    print(f"[bot{client_id}] 第 {m} 条消息 RTT = {rtt:.4f} 秒")
                    break

        s.close()

    except Exception as e:
        print(f"[bot{client_id}] 出错：{e}")


def main():
    # 解析命令行参数：python load_test.py 10 20
    if len(sys.argv) >= 2:
        num_clients = int(sys.argv[1])
    else:
        num_clients = DEFAULT_CLIENTS

    if len(sys.argv) >= 3:
        messages_per_client = int(sys.argv[2])
    else:
        messages_per_client = DEFAULT_MESSAGES_PER_CLIENT

    print(f"[系统] 准备启动 {num_clients} 个客户端，每个发送 {messages_per_client} 条消息。")
    print("[系统] 请确保加密版服务器已经在运行。")

    threads = []
    for cid in range(num_clients):
        t = threading.Thread(target=bot_worker, args=(cid, messages_per_client))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    if not results:
        print("[系统] 没有采集到任何 RTT 数据，可能是服务器没有运行或加解密配置不一致。")
        return

    # 写入 CSV
    filename = "latency_log.csv"
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["client_id", "message_index", "rtt_seconds"])
        writer.writerows(results)

    # 简单统计
    all_rtts = [r[2] for r in results]
    avg_rtt = sum(all_rtts) / len(all_rtts)
    max_rtt = max(all_rtts)
    min_rtt = min(all_rtts)

    print(f"[系统] 共记录 {len(results)} 条 RTT 数据")
    print(f"[系统] 平均 RTT: {avg_rtt:.4f} 秒")
    print(f"[系统] 最小 RTT: {min_rtt:.4f} 秒")
    print(f"[系统] 最大 RTT: {max_rtt:.4f} 秒")
    print(f"[系统] 已将详细数据写入 {filename}，可用 Excel / Python 画图分析。")


if __name__ == "__main__":
    main()
