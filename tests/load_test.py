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

# 默认参数：可以通过命令行覆盖
DEFAULT_CLIENTS = 5
DEFAULT_MESSAGES_PER_CLIENT = 5

# ======= 加密配置：必须和 server/client/encryption.py 完全一致 =======
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


# ======= 全局结果数组 =======
results_lock = threading.Lock()
# 每条记录：(client_id, msg_index, rtt_seconds)
results = []


def bot_worker(client_id: int, messages_per_client: int):
    """
    单个机器人客户端：
    - 连接服务器
    - /nick botX
    - 发送若干条 MSG-X-Y 消息
    - 等待服务器广播回自己的那条消息，计算 RTT
    """
    nickname = f"bot{client_id}"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            # 单次 recv 最多阻塞 1 秒，防止一直卡着
            s.settimeout(1.0)
            s.connect((HOST, PORT))
            print(f"[bot{client_id}] 已连接到服务器")

            # 1) 发送昵称命令
            s.sendall(encrypt_msg(f"/nick {nickname}\n"))

            # 2) 尝试读取几次欢迎 / 系统消息（只为把缓冲区清干净）
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
                    # 收到了不完整或拼在一起的密文，丢弃即可
                    continue
                except Exception:
                    break

            # 3) 正式发送测试消息
            for m in range(messages_per_client):
                payload = f"MSG-{client_id}-{m}"
                t0 = time.time()
                s.sendall(encrypt_msg(payload + "\n"))

                # 最多等待 2 秒收到自己那条广播，防止无限死循环
                wait_deadline = t0 + 2.0
                while True:
                    now = time.time()
                    if now > wait_deadline:
                        print(f"[bot{client_id}] 等待 {payload} 广播超时，放弃这一条")
                        break

                    try:
                        data = s.recv(4096)
                    except socket.timeout:
                        # 这次没收到任何数据，继续等
                        continue

                    if not data:
                        print(f"[bot{client_id}] 连接被关闭")
                        return

                    try:
                        text = decrypt_msg(data)
                    except InvalidToken:
                        # 可能是多条/半条密文拼在一起，解不了就丢掉继续
                        continue
                    except Exception as e:
                        print(f"[bot{client_id}] 解密失败: {e}")
                        return

                    # 服务器广播格式：[nickname] MSG-...
                    if f"[{nickname}]" in text and payload in text:
                        t1 = time.time()
                        rtt = t1 - t0
                        with results_lock:
                            results.append((client_id, m, rtt))
                        print(f"[bot{client_id}] 第 {m} 条消息 RTT = {rtt:.4f} 秒")
                        break

    except Exception as e:
        print(f"[bot{client_id}] 出错：{e}")


def main():
    # 命令行参数解析：python load_test.py 10 5
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
        print("[系统] 没有采集到任何 RTT 数据，可能是服务器未运行，或加密配置不一致。")
        return

    filename = "latency_log.csv"
    try:
        with open(filename, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["client_id", "message_index", "rtt_seconds"])
            writer.writerows(results)
    except Exception as e:
        print(f"[系统] 写入 CSV 文件失败: {e}")
        return

    all_rtts = [r[2] for r in results]
    avg_rtt = sum(all_rtts) / len(all_rtts)
    max_rtt = max(all_rtts)
    min_rtt = min(all_rtts)

    print(f"[系统] 共记录 {len(results)} 条 RTT 数据")
    print(f"[系统] 平均 RTT: {avg_rtt:.4f} 秒")
    print(f"[系统] 最小 RTT: {min_rtt:.4f} 秒")
    print(f"[系统] 最大 RTT: {max_rtt:.4f} 秒")
    print(f"[系统] 已将详细数据写入 {filename}")


if __name__ == "__main__":
    main()
