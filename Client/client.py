import socket
import threading
import sys
import signal

HOST = "127.0.0.1"
PORT = 5000

stop_event = threading.Event()

def receive_messages(sock):
    while not stop_event.is_set():
        try:
            message = sock.recv(4096).decode()
            if not message:
                break
            print(message, end="")
            sys.stdout.flush()
        except:
            break
    stop_event.set()

def send_messages(sock):
    while not stop_event.is_set():
        try:
            message = input()
            if message.strip().lower() == "/quit":
                stop_event.set()
                break
            sock.send(message.encode())
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
