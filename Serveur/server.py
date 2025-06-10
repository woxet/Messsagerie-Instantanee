import socket
import threading

from logger import log_message
from datetime import datetime

HOST = "127.0.0.1"
PORT = 5000

clients = {}
lock = threading.Lock()

def broadcast(sender_username, message):
    timestamp = datetime.now().strftime("%d-%m-%Y %H:%M:%S")
    with lock:
        for username, conn in clients.items():
            if username != sender_username:
                try:
                    conn.send(f"[{sender_username}] {message}".encode())
                    log_message(sender_username, username, message, timestamp)
                except:
                    pass

def handle_client(conn, addr):
    try:
        conn.send("Veuillez entrer votre nom d'utilisateur : ".encode())
        username = conn.recv(1024).decode().strip()

        with lock:
            clients[username] = conn
        print(f"[+] {username} connecté depuis {addr}")

        while True:
            message = conn.recv(1024).decode()
            if not message:
                break
            print(f"[{username}] {message}")
            broadcast(username, message)
    except:
        pass
    finally:
        with lock:
            if username in clients:
                del clients[username]
        conn.close()
        print(f"[-] {username} s'est déconnecté")

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()
    print(f"[+] Serveur en écoute sur {HOST}:{PORT}")

    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    main()