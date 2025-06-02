import socket
import threading
import os
import subprocess

CLE_FILE = "cle.key"
IV_FILE = "iv.key"
ALGO = "aes-256-cbc"

def generer_cle_iv():
    if not os.path.exists(CLE_FILE):
        os.system(f"openssl rand -out {CLE_FILE} 32")
        print(f"Clé générée dans {CLE_FILE}")
    if not os.path.exists(IV_FILE):
        os.system(f"openssl rand -out {IV_FILE} 16")
        print(f"IV généré dans {IV_FILE}")

def charger_hex(file_path):
    with open(file_path, "rb") as f:
        return f.read().hex()

def chiffrer(message):
    with open("plain.txt", "w", encoding='utf-8') as f:
        f.write(message)
    subprocess.run([
        "openssl", "enc", f"-{ALGO}", "-K", charger_hex(CLE_FILE), "-iv", charger_hex(IV_FILE),
        "-nosalt", "-in", "plain.txt", "-out", "cipher.bin"
    ], check=True)
    with open("cipher.bin", "rb") as f:
        return f.read()

def dechiffrer(data):
    with open("cipher.bin", "wb") as f:
        f.write(data)
    subprocess.run([
        "openssl", "enc", f"-d", f"-{ALGO}", "-K", charger_hex(CLE_FILE), "-iv", charger_hex(IV_FILE),
        "-nosalt", "-in", "cipher.bin", "-out", "plain.txt"
    ], check=True)
    with open("plain.txt", "r", encoding='utf-8') as f:
        return f.read()

# --- Serveur ---
clients = []
def gerer_client(conn, addr):
    print(f"{addr} connecté.")
    clients.append(conn)
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break
            message = dechiffrer(data)
            print(f"{addr} : {message}")
            for c in clients:
                if c != conn:
                    try:
                        ct = chiffrer(f"{addr}: {message}")
                        c.sendall(ct)
                    except:
                        pass
    except:
        pass
    finally:
        print(f"{addr} déconnecté.")
        clients.remove(conn)
        conn.close()

def demarrer_serveur(hote='0.0.0.0', port=5000):
    generer_cle_iv()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((hote, port))
    server.listen()
    print(f"Serveur lancé sur {hote}:{port}")
    while True:
        conn, addr = server.accept()
        threading.Thread(target=gerer_client, args=(conn, addr), daemon=True).start()

# --- Client ---
def recevoir_messages(sock):
    while True:
        try:
            data = sock.recv(4096)
            if data:
                msg = dechiffrer(data)
                print(f"\n{msg}")
            else:
                break
        except:
            break

def demarrer_client(hote='127.0.0.1', port=5000):
    if not os.path.exists(CLE_FILE) or not os.path.exists(IV_FILE):
        print("Le fichier clé ou IV est manquant.")
        return
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((hote, port))
    print(f"Connecté à {hote}:{port}")
    threading.Thread(target=recevoir_messages, args=(client,), daemon=True).start()
    try:
        while True:
            msg = input()
            if msg:
                ct = chiffrer(msg)
                client.sendall(ct)
    except:
        client.close()

# --- Main ---
if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2 or sys.argv[1] not in ("serveur", "client"):
        print("Usage : python chat_openssl.py serveur|client")
        sys.exit(1)
    if sys.argv[1] == "serveur":
        demarrer_serveur()
    elif sys.argv[1] == "client":
        hote = input("Adresse du serveur (default 127.0.0.1): ") or "127.0.0.1"
        demarrer_client(hote)
