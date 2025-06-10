import socket
import threading

HOST = "127.0.0.1"
PORT = 5000

def receive_messages(sock):
    while True:
        try:
            message = sock.recv(1024).decode()
            if not message:
                break
            print(message)
        except:
            break


def send_messages(sock):
    while True:
        try:
            message = input()
            sock.send(message.encode())
        except:
            break


def main():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((HOST, PORT))

    initial_prompt = client.recv(1024).decode()
    username = input(initial_prompt)
    client.send(username.encode())

    print(f"[+] Connecté en tant que {username}")

    threading.Thread(target=receive_messages, args=(client,), daemon=True).start()
    threading.Thread(target=send_messages, args=(client,), daemon=True).start()

    while True:
        pass


if __name__ == "__main__":
    main()
