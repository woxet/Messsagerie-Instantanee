# Protocoles Cryptographiques Avancée 2025 

## Application de Messagerie Instantanée Sécurisée

Ce projet consiste à développer une application de messagerie instantanée permettant à deux utilisateurs, typiquement nommés **Alice** et **Bob**, de communiquer de manière **sécurisée**, même en mode **asynchrone** (hors ligne).

L'application doit garantir plusieurs **propriétés de sécurité fondamentales** :

- **Authentification** des participants : chaque utilisateur doit prouver son identité.
- **Chiffrement des échanges** : confidentialité des messages échangés.
- **Mode asynchrone** : la réception différée des messages doit rester sécurisée.
- **Intégrité des données** : les messages ne doivent pas pouvoir être modifiés à l’insu des parties.
- **Protection contre les attaques par rejeu** : un message intercepté ne doit pas pouvoir être réutilisé.
- **Forward Secrecy** : la compromission d’une clé ne permet pas de déchiffrer les anciens messages.
- **Backward Secrecy** : la compromission d’une clé ne permet pas de déchiffrer les futurs messages.

Voir le [sujet](sujet.pdf) pour plus de détails.

------

## Installation
### Requirements
- Créer le venv :
```bash 
python -m venv venv
```

- Selectionner le venv :

| Platform | Shell         | Commande pour activer l'environnement virtuel |
|----------|---------------|-----------------------------------------------|
| POSIX    | bash/zsh      | `$ source venv/bin/activate`                  |
|          | fish          | `$ source venv/bin/activate.fish`             |
|          | csh/tcsh      | `$ source venv/bin/activate.csh`              |
|          | pwsh          | `$ venv/bin/Activate.ps1`                     |
| Windows  | cmd.exe       | `C:\> venv\Scripts\activate.bat`              |
|          | PowerShell    | `PS C:\> venv\Scripts\Activate.ps1`           |

- Installer les librairies : 
```bash
python -m pip install -r requirements.txt
```

## Lancement
### Serveur
Démarrer le serveur en premier :
```bash
cd Serveur
python server.py
```

Eteindre le serveur : `CTRL+C`

### Client
Lancer une instance client :
```bash
cd Client
python client.py
```

Commandes à connaitre :
- Lancer une discussion : `/talk <user_id>`
- Quitter une conversation : `/talk <other_user_id>` ou `/exit`
- Clore la connexion : `/quit` ou `CTRL+C`
- Obtenir les commandes : `/infos`

---
## Documentation sécurité
[TLS/SSL](https://www.cloudflare.com/fr-fr/learning/ssl/transport-layer-security-tls/) (CloudFlare)
[X3DH](https://signal.org/docs/specifications/x3dh/x3dh.pdf) (Signal)
[Double Ratchet](https://fr.wikipedia.org/wiki/Algorithme_%C3%A0_Double_Ratchet) (Wikipédia)
[Double Ratchet](https://signal.org/docs/specifications/doubleratchet/doubleratchet.pdf) (Signal)