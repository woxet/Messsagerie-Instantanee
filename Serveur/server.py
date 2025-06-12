import socket
import threading
from datetime import datetime

from logger import *
from authentificator import *

HOST = "127.0.0.1"
PORT = 5000

clients = {}
lock = threading.Lock()

sys_logger = init_sys_logger()
msg_logger = init_message_logger()

def broadcast(sender_username, message):
    timestamp = datetime.now().strftime("%d-%m-%Y %H:%M:%S")
    with lock:
        for username, conn in clients.items():
            if username != sender_username:
                try:
                    conn.sendall(f"[{sender_username}] {message}\n".encode())
                    log_message(sender_username, username, message, timestamp)
                except Exception as e:
                    sys_logger.warning(f"Erreur lors de l'envoi à {username} : {e}")

def auth(conn: socket.socket):
    try:
        while True:
            conn.sendall(
                "Bienvenue !\n\n1. Inscription\n2. Connexion\n3. Quitter\n> ".encode()
            )
            choice = conn.recv(1024).decode().strip()
            if choice == "1":
                conn.sendall("Nom complet:\n> ".encode())
                name = conn.recv(1024).decode().strip()
                conn.sendall("Nom d'utilisateur:\n> ".encode())
                user_id = conn.recv(1024).decode().strip()
                conn.sendall("Mot de passe:\n> ".encode())
                password = conn.recv(1024).decode().strip()
                if signup(name, user_id, password, conn):
                    continue
            elif choice == "2":
                conn.sendall("Nom d'utilisateur:\n> ".encode())
                user_id = conn.recv(1024).decode().strip()
                conn.sendall("Mot de passe:\n> ".encode())
                password = conn.recv(1024).decode().strip()
                if login(user_id, password, conn):
                    return user_id
            elif choice == "3":
                conn.sendall("Bye !\n".encode())
                return None
            else:
                conn.sendall("Choix invalide.\n".encode())
    except Exception as e:
        sys_logger.error(f"Erreur lors de l'authentification : {e}")
        return None

def handle_client(conn: socket.socket, addr):
    username = None
    try:
        username = auth(conn)
        if username is None:
            conn.close()
            sys_logger.info(f"Connexion depuis {addr} fermée sans authentification")
            return

        with lock:
            clients[username] = conn
        sys_logger.info(f"{username} connecté depuis {addr}")

        while True:
            message = conn.recv(1024).decode()
            if not message:
                break
            sys_logger.debug(f"Message reçu de {username}")
            broadcast(username, message)
    except Exception as e:
        sys_logger.warning(f"Erreur avec le client {addr} : {e}")
    finally:
        with lock:
            if username in clients:
                del clients[username]
        try:
            conn.shutdown(socket.SHUT_RDWR)
        except:
            pass
        conn.close()
        if username:
            sys_logger.info(f"{username} s'est déconnecté")

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()
    sys_logger.info(f"Serveur en écoute sur {HOST}:{PORT}")

    threads = []

    try:
        while True:
            conn, addr = server.accept()
            sys_logger.info(f"Connexion entrante depuis {addr}")
            t = threading.Thread(target=handle_client, args=(conn, addr))
            t.start()
            threads.append(t)
    except KeyboardInterrupt:
        sys_logger.info("Arrêt du serveur via KeyboardInterrupt")
    finally:
        server.close()
        for t in threads:
            t.join()
        sys_logger.info("Tous les threads clients terminés. Serveur arrêté.")


if __name__ == "__main__":
    main()
