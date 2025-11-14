import socket
import threading

from cryptography.fernet import InvalidToken
from encryption import encrypt_msg, decrypt_msg  # 本目录下的 encryption.py

HOST = '127.0.0.1'
PORT = 55555

# 保存所有在线客户端 socket
clients = []
# 保存每个客户端的昵称：socket -> nickname
nicknames = {}
clients_lock = threading.Lock()  # 访问 clients 和 nicknames 时加锁，防止多线程冲突


def send_encrypted(sock: socket.socket, text: str):
    """对 text 加密后发送给某个客户端。"""
    try:
        token = encrypt_msg(text)
        sock.sendall(token)
    except Exception as e:
        print(f"[系统] 向客户端发送加密消息失败：{e}")


def broadcast(message: str, sender_sock=None):
    """
    向所有在线客户端广播消息（加密后发送）。
    message 是已经带好前缀的字符串。
    sender_sock 目前只用于扩展（比如以后不回发给自己），这里可以不用。
    """
    try:
        data = encrypt_msg(message + "\n")
    except Exception as e:
        print(f"[系统] 广播前加密失败：{e}")
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
    """根据昵称找到对应的 socket，没有就返回 None。"""
    with clients_lock:
        for sock, name in nicknames.items():
            if name == target_name:
                return sock
    return None


def handle_client(conn: socket.socket, addr):
    """每个客户端对应一个线程：负责昵称管理、解析命令、转发消息（全部加密通信）。"""
    print(f"[系统] 客户端已连接：{addr}")

    with clients_lock:
        clients.append(conn)

    nickname = None
    try:
        # 提示客户端先设置昵称
        send_encrypted(conn, "欢迎连接安全聊天室！\n")
        send_encrypted(conn, "请先使用命令设置昵称，例如：/nick Alice\n")

        while True:
            data = conn.recv(4096)
            if not data:
                print(f"[系统] 客户端断开：{addr}")
                break

            try:
                msg = decrypt_msg(data).strip()
            except InvalidToken:
                print(f"[系统] 收到无法解密的数据，来自 {addr}，已丢弃。")
                continue
            except Exception as e:
                print(f"[系统] 解密失败来自 {addr}：{e}")
                continue

            if not msg:
                continue

            # 还没有昵称时，只允许用 /nick
            if nickname is None:
                if msg.startswith("/nick "):
                    desired = msg[6:].strip()
                    if not desired:
                        send_encrypted(conn, "昵称不能为空，请重新输入，例如：/nick Alice\n")
                        continue

                    with clients_lock:
                        if desired in nicknames.values():
                            send_encrypted(conn, f"昵称 {desired} 已被占用，请换一个。\n")
                            continue
                        nicknames[conn] = desired
                        nickname = desired

                    send_encrypted(conn, f"[系统] 你现在的昵称是：{nickname}\n")
                    broadcast(f"[系统] {nickname} 加入了聊天室。", sender_sock=conn)
                    print(f"[系统] {addr} 设置昵称为 {nickname}")
                else:
                    send_encrypted(conn, "请先使用 /nick 你的名字 设置昵称，例如：/nick Alice\n")
                continue

            # 已经有昵称了，开始处理各类命令 / 普通聊天
            print(f"[收到][{nickname}@{addr}] {msg}")

            # 修改昵称：/nick 新名字
            if msg.startswith("/nick "):
                new_name = msg[6:].strip()
                if not new_name:
                    send_encrypted(conn, "新昵称不能为空。\n")
                    continue

                with clients_lock:
                    if new_name in nicknames.values():
                        send_encrypted(conn, f"昵称 {new_name} 已被占用，请换一个。\n")
                        continue
                    old_name = nickname
                    nicknames[conn] = new_name
                    nickname = new_name

                send_encrypted(conn, f"[系统] 你已将昵称修改为：{nickname}\n")
                broadcast(f"[系统] {old_name} 修改昵称为 {nickname}。", sender_sock=conn)
                continue

            # 私聊：/w 目标昵称 内容
            if msg.startswith("/w "):
                parts = msg.split(" ", 2)
                if len(parts) < 3:
                    send_encrypted(conn, "私聊命令格式：/w 对方昵称 内容\n")
                    continue

                target_name = parts[1].strip()
                content = parts[2].strip()
                if not content:
                    send_encrypted(conn, "私聊内容不能为空。\n")
                    continue

                target_sock = find_socket_by_nickname(target_name)
                if target_sock is None:
                    send_encrypted(conn, f"[系统] 未找到昵称为 {target_name} 的用户。\n")
                    continue

                # 给对方发
                try:
                    send_encrypted(target_sock, f"[私聊][{nickname} -> 你] {content}\n")
                except Exception:
                    send_encrypted(conn, f"[系统] 私聊失败，对方可能已离线。\n")
                    continue

                # 给自己确认
                try:
                    send_encrypted(conn, f"[私聊][你 -> {target_name}] {content}\n")
                except Exception:
                    pass
                continue

            # 普通消息：群聊
            broadcast(f"[{nickname}] {msg}", sender_sock=conn)

    except (ConnectionResetError, OSError):
        print(f"[系统] 客户端异常中断：{addr}")

    finally:
        with clients_lock:
            if conn in clients:
                clients.remove(conn)
            left_name = nicknames.pop(conn, None)
        conn.close()
        if left_name:
            broadcast(f"[系统] {left_name} 离开了聊天室。")
            print(f"[系统] {left_name}@{addr} 离线并已清理。")
        else:
            print(f"[系统] 未设置昵称的客户端 {addr} 已清理。")


def server_console():
    """
    服务器自己的控制台输入线程：
    在服务器端输入内容，群发给所有客户端。
    """
    while True:
        try:
            msg = input("你(服务器广播): ")
        except EOFError:
            break

        if msg.strip().lower() in ("/quit", "/exit"):
            print("[系统] 服务器控制台输入线程退出（不会自动杀掉已连接客户端）")
            break

        broadcast(f"[SERVER] {msg}")


def run_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        s.bind((HOST, PORT))
        s.listen()
        print(f"[系统] 服务器已启动，监听 {HOST}:{PORT}（加密通信已开启）...")

        console_thread = threading.Thread(target=server_console, daemon=True)
        console_thread.start()

        while True:
            try:
                conn, addr = s.accept()
            except OSError:
                print("[系统] accept 出错，服务器即将退出")
                break

            client_thread = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            client_thread.start()


if __name__ == "__main__":
    run_server()
