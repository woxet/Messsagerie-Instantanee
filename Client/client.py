import socket
import threading
import signal
import os
import json
from datetime import datetime
from getpass import getpass

from utils import generate_and_send_bundle
from Secu.x3dh import X3DHUser
from Secu.dratchet import *
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization

HOST = "127.0.0.1"
PORT = 5000

current_target = None
auth_done = threading.Event()
stop_event = threading.Event()
x3dh_self = X3DHUser()
ratchet_sessions = {}
ephemeral_keys = {}
received_bundles = {}
user_id = None

os.makedirs("historique", exist_ok=True)
os.makedirs("ratchet_states", exist_ok=True)
os.makedirs("keys", exist_ok=True)

def save_ratchet_state(user_id, state):
    filepath = os.path.join("ratchet_states", f"{user_id}.json")
    with open(filepath, "w") as f:
        json.dump(state.to_dict(), f)

def load_ratchet_state(user_id):
    filepath = os.path.join("ratchet_states", f"{user_id}.json")
    if not os.path.exists(filepath):
        return None
    with open(filepath, "r") as f:
        data = json.load(f)
    return State.from_dict(data)

def save_local_history(dest, message):
    try:
        with open(f"historique/{dest}.txt", "a", encoding="utf-8") as f:
            f.write(message)
    except Exception as e:
        print(f"[Erreur] Historique local : {e}")

def get_infos():
    print(
        "\nCommandes disponibles :\n"
        "  - Lancer une discussion        : /talk <user_id>\n"
        "  - Quitter une conversation     : /exit\n"
        "  - Clore la connexion           : /quit ou CTRL+C\n"
        "  - Obtenir la liste des commandes : /infos\n> ",
        end=""
    )

def receive_messages(sock):
    global x3dh_self, user_id, current_target
    sock_file = sock.makefile('r')

    # Chargement des états Ratchet précédemment enregistrés
    for user_file in os.listdir("ratchet_states"):
        uid = user_file.replace(".json", "")
        state = load_ratchet_state(uid)
        if state:
            ratchet_sessions[uid] = state

    while not stop_event.is_set():
        try:
            line = sock_file.readline()
            if not line:
                print("[*] Connexion au serveur interrompue.")
                stop_event.set()
                break

            try:
                obj = json.loads(line)

                if obj["type"] == "auth_prompt":
                    print(obj["message"])
                    for i, option in enumerate(obj["options"], 1):
                        print(f"{i}. {option.capitalize()}")
                    print("> ", end="")

                elif obj["type"] in ("register_success", "auth_success"):
                    print(f"[Système] {obj['message']}")
                    if obj["type"] == "register_success" and user_id:
                        x3dh_self = generate_and_send_bundle(sock, user_id)
                    if obj["type"] == "auth_success":
                        auth_done.set()
                        get_infos()

                elif obj["type"] == "system":
                    print(f"[Système] {obj['message']}")
                    print("> ", end="")

                elif obj["type"] == "message":
                    sender = obj["from"]
                    header_hex = obj["header"]
                    nonce = bytes.fromhex(obj["nonce"])
                    ct = bytes.fromhex(obj["ciphertext"])
                    
                    try:
                        full_header = bytes.fromhex(header_hex)
                    except Exception as e:
                        print(f"[Erreur] Header invalide de {sender} : {e}")
                        continue

                    # Cas où le message est un premier message avec session X3DH intégrée
                    if len(full_header) == 104:
                        ik_bytes = full_header[:32]
                        eph_bytes = full_header[32:64]
                        real_header = full_header[64:]

                        try:
                            rk = x3dh_self.compute_shared_key_receiver(ik_bytes, eph_bytes)
                            eph_pub = X25519PublicKey.from_public_bytes(eph_bytes)
                            state = RatchetInit(
                                is_initiator=False,
                                root_key=rk,
                                dh_self_priv=x3dh_self.SPK_priv,
                                dh_remote_pub=eph_pub
                            )
                            DHRatchet(state, eph_pub)
                            ratchet_sessions[sender] = state
                            save_ratchet_state(sender, state)
                            print(f"[+] Session réceptrice sécurisée avec {sender}")
                        except Exception as e:
                            print(f"[Erreur] Échec session récepteur : {type(e).__name__} – {e}")
                            continue

                        header = real_header

                    else:
                        # Header classique
                        header = full_header

                    if sender not in ratchet_sessions:
                        print(f"[!] Aucune session active avec {sender} pour déchiffrement.")
                        continue

                    try:
                        plaintext = RatchetDecrypt(ratchet_sessions[sender], header, nonce, ct, AD=header)
                    except Exception as e:
                        print(f"[Erreur] Déchiffrement avec {sender} : {type(e).__name__} – {e}")
                        continue

                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    msg = f"[{timestamp}] {sender}: {plaintext.decode()}\n"
                    print(msg, end="")
                    save_local_history(sender, msg)


                elif obj["type"] == "bundle_response":
                    bundle = obj["bundle"]
                    received_bundles[bundle["user_id"]] = bundle
                    current = bundle["user_id"]
                    if os.path.exists(f"historique/{current}.txt"):
                        with open(f"historique/{current}.txt", "r", encoding="utf-8") as f:
                            print(f"[Historique avec {current}]\n{f.read()}")
                    else:
                        print(f"[Système] Nouvelle conversation avec {current}.")
                    print("[Système] En attente de message pour établir session...")

                elif obj["type"] == "confirm":
                    print(f"[OK] {obj['message']}")

                else:
                    print(line)

            except json.JSONDecodeError:
                print("[Système] Format JSON invalide.")
                print(line)

        except Exception as e:
            print(f"[!] Erreur réception : {e}")
            break

    stop_event.set()


def send_messages(sock):
    global current_target, user_id

    while not stop_event.is_set():
        try:
            message = input().strip()

            if not auth_done.is_set():
                if message == "1":
                    name = input("Nom complet: ").strip()
                    user_id = input("Nom d'utilisateur: ").strip()
                    password = getpass("Mot de passe: ").strip()
                    req = {"type": "register", "name": name, "user_id": user_id, "password": password}
                    sock.sendall((json.dumps(req) + "\n").encode())
                elif message == "2":
                    user_id = input("Nom d'utilisateur: ").strip()
                    password = getpass("Mot de passe: ").strip()
                    req = {"type": "login", "user_id": user_id, "password": password}
                    sock.sendall((json.dumps(req) + "\n").encode())
                elif message == "3":
                    stop_event.set()
                    return
                else:
                    print("[!] Choix invalide.")
                continue

            if message.lower() == "/quit":
                stop_event.set()
                break

            elif message.lower() == "/infos":
                get_infos()
                continue

            elif message.startswith("/talk "):
                dest = message[6:].strip()
                current_target = dest
                req = {"type": "get_bundle", "target": dest}
                sock.sendall((json.dumps(req) + "\n").encode())
                continue

            elif message.lower() == "/exit":
                current_target = None
                print("[*] Conversation fermée.")
                continue

            elif current_target:
                if current_target not in ratchet_sessions:
                    if current_target not in received_bundles:
                        print("[!] Aucun bundle reçu. Réessayez avec /talk.")
                        continue
                    eph_priv = X25519PrivateKey.generate()
                    ephemeral_keys[current_target] = eph_priv
                    rk = x3dh_self.compute_shared_key_initiator({
                        "IK": bytes.fromhex(received_bundles[current_target]["IK"]),
                        "SPK": bytes.fromhex(received_bundles[current_target]["SPK"]),
                        "OPK": bytes.fromhex(received_bundles[current_target]["OPK"]),
                    }, eph_priv)
                    SPK_pub = X25519PublicKey.from_public_bytes(bytes.fromhex(received_bundles[current_target]["SPK"]))
                    state = RatchetInit(True, rk, dh_remote_pub=SPK_pub)
                    ratchet_sessions[current_target] = state
                    save_ratchet_state(current_target, state)
                    print("[Système] Session initiée avec", current_target)

                st = ratchet_sessions[current_target]
                header, nonce, ct = RatchetEncrypt(st, message.encode())

                if current_target in ephemeral_keys:
                    ik_bytes = x3dh_self.IK_pub.public_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PublicFormat.Raw
                    )
                    eph_pub = ephemeral_keys[current_target].public_key().public_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PublicFormat.Raw
                    )
                    header = ik_bytes + eph_pub + header
                    del ephemeral_keys[current_target]

                req = {
                    "type": "message",
                    "from": user_id,
                    "to": current_target,
                    "header": header.hex(),
                    "nonce": nonce.hex(),
                    "ciphertext": ct.hex()
                }
                sock.sendall((json.dumps(req) + "\n").encode())

                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                formatted = f"[{timestamp}] Moi: {message}\n"
                save_local_history(current_target, formatted)
            else:
                print("[!] Pas en conversation. Utilisez /talk <nom>")

        except Exception as e:
            print(f"[!] Erreur d’envoi : {e}")
            break

    stop_event.set()

def main():
    os.system("cls" if os.name == "nt" else "clear")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((HOST, PORT))
    except Exception as e:
        print(f"[!] Connexion échouée : {e}")
        return

    signal.signal(signal.SIGINT, lambda s, f: stop_event.set())
    threading.Thread(target=receive_messages, args=(sock,), daemon=True).start()
    threading.Thread(target=send_messages, args=(sock,), daemon=True).start()

    while not stop_event.is_set():
        pass

    try:
        sock.shutdown(socket.SHUT_RDWR)
    except:
        pass
    sock.close()
    print("[*] Déconnecté.")

if __name__ == "__main__":
    main()