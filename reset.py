import os
import shutil

# Définir les chemins relatifs
paths_to_clean = [
    "Serveur/bundles",
    "Serveur/conversations",
    "Serveur/logs",
    "Serveur/pending",
    "Client/historique",
    "Client/keys",
    "Client/ratchet_states"
]

files_to_delete = [
    "Serveur/user_db.json"
]

def delete_contents(folder):
    if os.path.exists(folder):
        for filename in os.listdir(folder):
            path = os.path.join(folder, filename)
            try:
                if os.path.isfile(path) or os.path.islink(path):
                    os.remove(path)
                elif os.path.isdir(path):
                    shutil.rmtree(path)
            except Exception as e:
                print(f"[!] Erreur suppression {path} : {e}")

def main():
    for folder in paths_to_clean:
        print(f"[*] Nettoyage : {folder}")
        delete_contents(folder)

    for file in files_to_delete:
        if os.path.exists(file):
            try:
                os.remove(file)
                print(f"[*] Supprimé : {file}")
            except Exception as e:
                print(f"[!] Erreur suppression {file} : {e}")

    print("[✓] Réinitialisation terminée.")

if __name__ == "__main__":
    main()
