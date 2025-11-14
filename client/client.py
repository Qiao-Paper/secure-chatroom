import socket
import threading

from cryptography.fernet import InvalidToken
from encryption import encrypt_msg, decrypt_msg  # 本目录下的 encryption.py

HOST = '127.0.0.1'
PORT = 55555


def handle_receive(sock: socket.socket):
    """后台线程：负责接收服务器发来的加密消息并解密打印。"""
    while True:
        try:
            data = sock.recv(4096)
            if not data:
                print("\n[系统] 服务器已关闭连接")
                break

            try:
                text = decrypt_msg(data)
            except InvalidToken:
                print("\n[系统] 收到无法解密的数据，已丢弃。")
                continue
            except Exception as e:
                print(f"\n[系统] 解密失败：{e}")
                continue

            print(f"\n{text}", end="")
        except (ConnectionResetError, OSError):
            print("\n[系统] 连接异常中断")
            break

    try:
        sock.close()
    except OSError:
        pass


def run_client():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        print(f"[系统] 正在连接服务器 {HOST}:{PORT} ...")
        s.connect((HOST, PORT))
        print("[系统] 已连接到服务器（加密通信）。")
        print("[系统] 首先用命令设置昵称，例如：/nick Alice")
        print("[系统] 普通聊天：直接输入内容回车即可")
        print("[系统] 私聊：/w 对方昵称 内容   例如：/w Bob hi")
        print("[系统] 退出：/quit 或 /exit\n")

        recv_thread = threading.Thread(target=handle_receive, args=(s,), daemon=True)
        recv_thread.start()

        while True:
            try:
                msg = input("你(客户端): ")
            except EOFError:
                break

            if msg.strip().lower() in ("/quit", "/exit"):
                print("[系统] 客户端关闭连接")
                try:
                    s.close()
                except OSError:
                    pass
                break

            try:
                token = encrypt_msg(msg + "\n")
                s.sendall(token)
            except (BrokenPipeError, OSError):
                print("[系统] 无法发送消息，连接已关闭")
                break


if __name__ == "__main__":
    run_client()
