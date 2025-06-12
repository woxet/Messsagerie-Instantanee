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

