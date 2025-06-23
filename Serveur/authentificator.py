import json
import bcrypt
import os
import socket
import logging

USER_DB = "user_db.json"
logger = logging.getLogger("sys")


def load_users():
    if not os.path.exists(USER_DB):
        return []
    with open(USER_DB, "r") as f:
        return json.load(f)

def save_users(users):
    with open(USER_DB, "w") as f:
        json.dump(users, f, indent=4)

def signup(name, user_id, password, conn: socket):
    users = load_users()
    if any(u["user_id"] == user_id for u in users):
        conn.sendall("Ce nom d'utilisateur existe déjà.\n\n".encode())
        return False

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    user = {"id": len(users), "name": name, "user_id": user_id, "pass": hashed}
    users.append(user)
    save_users(users)
    conn.sendall("Inscription réussie.".encode())
    return True

def login(user_id, password, conn: socket):
    users = load_users()
    for user in users:
        if user["user_id"] == user_id:
            if bcrypt.checkpw(password.encode(), user["pass"].encode()):
                conn.sendall(f"Bienvenue, {user['name']} !\n".encode())
                return True
            else:
                conn.sendall("Mot de passe incorrect.\n".encode())
                logger.warning(f"{user_id} mot de passe incorrect")
                return False
    conn.sendall("Utilisateur non trouve.\n".encode())
    logger.warning(f"{user_id} utilisateur inconnu")
    return False
