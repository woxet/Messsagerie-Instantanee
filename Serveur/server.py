import socket
import threading
import os
import json
from datetime import datetime
import signal

from logger import *
from authentificator import *

HOST = "127.0.0.1"
PORT = 5000

clients = {}
talk_sessions = {}  # user -> current peer
talk_ready = {}     # user -> True if /talk has been issued
lock = threading.Lock()
stop_server = False

sys_logger = init_sys_logger()
os.makedirs("conversations", exist_ok=True)
os.makedirs("bundles", exist_ok=True)
os.makedirs("pending", exist_ok=True)

def handle_sigint(sig, frame):
    global stop_server
    stop_server = True
signal.signal(signal.SIGINT, handle_sigint)

def get_conversation_filename(user1, user2):
    return f"conversations/{'__'.join(sorted([user1, user2]))}.txt"

def send_json(conn, obj):
    try:
        conn.sendall((json.dumps(obj) + "\n").encode())
    except:
        pass

def handle_client(conn: socket.socket, addr):
    username = None
    try:
        send_json(conn, {
            "type": "auth_prompt",
            "message": "Bienvenue ! Veuillez vous inscrire ou vous connecter.",
            "options": ["Inscription", "Connexion", "Quitter"]
        })

        while True:
            line = conn.makefile().readline()
            if not line:
                break

            try:
                data = json.loads(line.strip())
            except json.JSONDecodeError:
                send_json(conn, {"type": "system", "message": "[Erreur] Format JSON invalide."})
                continue

            req_type = data.get("type")
            if not req_type:
                send_json(conn, {"type": "system", "message": "[Erreur] Champ 'type' manquant."})
                continue

            match req_type:
                case "register":
                    name = data.get("name", "")
                    username = data.get("user_id", "")
                    password = data.get("password", "")
                    if signup(name, username, password, conn):
                        send_json(conn, {"type": "register_success", "message": "Inscription réussie."})
                    else:
                        username = None
                        send_json(conn, {"type": "system", "message": "[Erreur] Ce nom d'utilisateur existe déjà."})
                    continue

                case "login":
                    username = data.get("user_id", "")
                    password = data.get("password", "")
                    if login(username, password, conn):
                        send_json(conn, {"type": "auth_success", "message": f"Bienvenue, {username} !"})
                        with lock:
                            clients[username] = conn
                            talk_sessions[username] = None
                            talk_ready[username] = False
                    else:
                        username = None
                        send_json(conn, {"type": "system", "message": "[Erreur] Identifiants invalides."})
                    continue

                case "post_bundle":
                    uid = data.get("user_id")
                    try:
                        with open(f"bundles/{uid}.json", "w") as f:
                            json.dump({
                                "IK": data["IK"],
                                "SPK": data["SPK"],
                                "OPK": data["OPK"]
                            }, f)
                        send_json(conn, {"type": "bundle_ack"})
                        sys_logger.info(f"Bundle reçu pour {uid}")
                    except Exception as e:
                        send_json(conn, {"type": "system", "message": f"[Erreur] Sauvegarde bundle : {e}"})
                    continue

                case "get_bundle":
                    target = data.get("target")
                    talk_ready[username] = True
                    talk_sessions[username] = target

                    bundle_path = f"bundles/{target}.json"
                    if not os.path.exists(bundle_path):
                        send_json(conn, {"type": "system", "message": "[!] Bundle introuvable."})
                    else:
                        with open(bundle_path, "r") as f:
                            bundle = json.load(f)
                        bundle["user_id"] = target
                        send_json(conn, {
                            "type": "bundle_response",
                            "from": target,
                            "bundle": bundle
                        })

                        pending_file = f"pending/{username}_{target}.txt"
                        if os.path.exists(pending_file):
                            with open(pending_file, "r", encoding="utf-8") as f:
                                for line in f:
                                    send_json(conn, json.loads(line.strip()))
                            os.remove(pending_file)
                    continue

                case "message":
                    sender = data.get("from")
                    dest = data.get("to")
                    header = data.get("header")
                    nonce = data.get("nonce")
                    ciphertext = data.get("ciphertext")

                    message_data = {
                        "type": "message",
                        "from": sender,
                        "to": dest,
                        "header": header,
                        "nonce": nonce,
                        "ciphertext": ciphertext
                    }

                    with lock:
                        if dest in clients and talk_ready.get(dest, False) and talk_sessions.get(dest) == sender:
                            try:
                                send_json(clients[dest], message_data)
                                sys_logger.info(f"Message transmis de {sender} à {dest}")
                            except Exception as e:
                                print(f"[DEBUG] Erreur d'envoi direct à {dest} : {e}")
                        else:
                            pending_path = f"pending/{dest}_{sender}.txt"
                            with open(pending_path, "a", encoding="utf-8") as f:
                                f.write(json.dumps(message_data) + "\n")
                            print(f"[DEBUG] Message stocké en attente pour {dest}")
                    continue

                case "quit":
                    break

                case _:
                    send_json(conn, {"type": "system", "message": "[!] Type de requête inconnu."})

    except Exception as e:
        sys_logger.error(f"[!] Erreur pour {addr}: {e}")

    finally:
        if username:
            with lock:
                clients.pop(username, None)
                talk_sessions.pop(username, None)
                talk_ready.pop(username, None)
            sys_logger.info(f"{username} déconnecté")

        try:
            conn.shutdown(socket.SHUT_RDWR)
        except:
            pass
        conn.close()

def main():
    os.system("cls" if os.name == "nt" else "clear")
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()
    server.settimeout(1.0)

    sys_logger.info(f"Serveur PID : {os.getpid()}")
    sys_logger.info(f"Écoute sur {HOST}:{PORT}")

    threads = []

    try:
        while not stop_server:
            try:
                conn, addr = server.accept()
                sys_logger.info(f"Connexion depuis {addr}")
                t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
                t.start()
                threads.append(t)
            except socket.timeout:
                continue

    finally:
        sys_logger.info("Arrêt du serveur via KeyboardInterrupt")
        server.close()

        sys_logger.info("Fermeture des connexions clients...")
        with lock:
            for conn in clients.values():
                try:
                    conn.sendall(b"[Systeme] Le serveur va s'arreter. Deconnexion...\n")
                    conn.shutdown(socket.SHUT_RDWR)
                except:
                    pass
                try:
                    conn.close()
                except:
                    pass

        for t in threads:
            t.join()

        sys_logger.info("Tous les threads clients terminés. Serveur arrêté.")

if __name__ == "__main__":
    main()
