import socket
import threading
from datetime import datetime
import os

from logger import *
from authentificator import *

HOST = "127.0.0.1"
PORT = 5000

clients = {}
lock = threading.Lock()

sys_logger = init_sys_logger()
msg_logger = init_message_logger()

talk_sessions = {}  # { username: destinataire }

os.makedirs("conversations", exist_ok=True)

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

def get_conversation_filename(user1, user2):
    users = sorted([user1, user2])
    return f"conversations/{users[0]}__{users[1]}.txt"

def handle_client(conn: socket.socket, addr):
    username = auth(conn)
    if username is None:
        conn.close()
        return

    with lock:
        clients[username] = conn
    talk_sessions[username] = None

    try:
        while True:
            message = conn.recv(4096).decode().strip()
            if not message:
                break

            # Commande /talk
            if message.startswith("/talk "):
                dest = message[6:].strip()
                if dest == username:
                    conn.sendall(f"[Système] Vous ne pouvez pas parler à vous-même.\n".encode())
                    continue
                
                users = load_users()
                if dest not in (u["user_id"] for u in users):
                    conn.sendall(f"[Système] Utilisateur inconnu.\n".encode())
                    continue

                talk_sessions[username] = dest

                filename = get_conversation_filename(username, dest)
                if os.path.exists(filename):
                    with open(filename, "r", encoding="utf-8") as f:
                        conn.sendall(f"[Historique avec {dest}]\n{f.read()}".encode())
                else:
                    conn.sendall(f"[Système] Nouvelle conversation avec {dest}.\n".encode())
                continue

            # Commande /exit
            if message == "/exit":
                other = talk_sessions.get(username)
                talk_sessions[username] = None
                continue


            # Message en mode talk
            dest = talk_sessions.get(username)
            if dest:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                formatted = f"[{timestamp}] {username}: {message}\n"
                filename = get_conversation_filename(username, dest)

                with open(filename, "a", encoding="utf-8") as f:
                    f.write(formatted)

                # Envoi direct si les deux sont en talk l’un avec l’autre
                with lock:
                    if talk_sessions.get(dest) == username and dest in clients:
                        try:
                            clients[dest].sendall(formatted.encode())
                        except Exception as e:
                            sys_logger.warning(f"Échec d'envoi à {dest}: {e}")
            else:
                conn.sendall(f"[Système] Pas en conversation. Utilisez /talk <nom>\n".encode())

    finally:
        # Retirer l'utilisateur courant
        with lock:
            clients.pop(username, None)

            # Libérer aussi la session talk de l'autre s'il y a réciprocité
            other = talk_sessions.get(username)
            talk_sessions.pop(username,*
                               None)

            if other and talk_sessions.get(other) == username:
                talk_sessions[other] = None
                other_conn = clients.get(other)
                if other_conn:
                    try:
                        other_conn.sendall(f"[Système] {username} s’est déconnecté. Conversation terminée.\n".encode())
                    except Exception as e:
                        sys_logger.warning(f"Erreur lors de l’envoi au partenaire {other} : {e}")

        # Fermer proprement la socket
        try:
            conn.shutdown(socket.SHUT_RDWR)
        except:
            pass
        conn.close()
        if username:
            sys_logger.info(f"{username} s’est déconnecté")


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()
    sys_logger.info(f"Serveur en écoute sur {HOST}:{PORT}")
    #print the current process id
    sys_logger.info(f"Serveur PID : {os.getpid()}")
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
