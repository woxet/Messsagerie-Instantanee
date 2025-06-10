from datetime import datetime

LOG_FILE = "Serveur/logs/messages.log"

def log_message(expediteur, destinataire, message, timestamp=None):
    if timestamp is None:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    entry = f"[{timestamp}] {expediteur} -> {destinataire} : {message}\n"

    with open(LOG_FILE, "a", encoding="utf-8") as log:
        log.write(entry)
