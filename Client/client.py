import socket
import threading
import sys
import signal

HOST = "127.0.0.1"
PORT = 5000

current_target = None
auth_done = threading.Event()
stop_event = threading.Event()


def receive_messages(sock):
    while not stop_event.is_set():
        try:
            message = sock.recv(4096).decode()
            if not message:
                break
            print(message, end="")
            sys.stdout.flush()
            if message.startswith("Bienvenue, "):  # détection du message de bienvenue
                auth_done.set()
        except:
            break
    stop_event.set()

current_target = None


def send_messages(sock):
    global current_target
    authenticated = False

    while not stop_event.is_set():
        try:
            message = input()

            if not auth_done.is_set():
                # On laisse uniquement passer les choix initiaux tant qu'on n'est pas connecté
                sock.send(message.encode())
                continue

            # Authentifié ici
            if message.lower() == "/quit":
                stop_event.set()
                break
            elif message.startswith("/talk "):
                dest = message[6:].strip()
                if dest:
                    current_target = dest
                    sock.send(message.encode())
                continue
            elif message.strip() == "/exit":
                current_target = None
                sock.send(message.encode())
                print("[*] Conversation fermée.")
                continue
            elif current_target:
                sock.send(message.encode())
            else:
                print("[!] Pas en conversation. Utilisez /talk <nom>")
        except:
            break
    stop_event.set()

def main():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client.connect((HOST, PORT))
    except Exception as e:
        print(f"[!] Échec de la connexion au serveur : {e}")
        return

    def handle_interrupt(sig, frame):
        stop_event.set()

    signal.signal(signal.SIGINT, handle_interrupt)

    recv_thread = threading.Thread(target=receive_messages, args=(client,), daemon=True)
    send_thread = threading.Thread(target=send_messages, args=(client,), daemon=True)

    recv_thread.start()
    send_thread.start()

    while not stop_event.is_set():
        try:
            recv_thread.join(timeout=0.5)
            send_thread.join(timeout=0.5)
        except:
            break
    try:
        client.shutdown(socket.SHUT_RDWR)
    except:
        pass
    client.close()
    print("[*] Déconnecté.")

if __name__ == "__main__":
    main()
