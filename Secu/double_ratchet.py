from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from dh_ratchet import DiffieHellman
from kdf import kdf_chain_key, kdf_root_key

# https://www.youtube.com/watch?v=9sO2qdTci-s
class DoubleRatchet:
    """
    Implémentation simplifiée du protocole Double Ratchet (Signal).
    Combine un ratchet asymétrique (DH) et un ratchet symétrique (HKDF).
    """

    def __init__(self, root_key: bytes, is_initiator=True, dh_parameters=None):
        # Clé racine partagée à l'initialisation
        self.root_key = root_key

        self.dh_parameters = dh_parameters or DiffieHellman().parameters
        self.dh_self = DiffieHellman(parameters=self.dh_parameters)
        
        self.dh_remote = None
        self.send_chain_key = None
        self.recv_chain_key = None

        self.is_initiator = is_initiator

    def initialize_session(self, remote_pubkey: bytes):
        """
        Initialisation de la session : échange initial de clés DH.
        En fonction du rôle (initiateur ou récepteur), on initialise soit :
        - la chaîne d'envoi (si on initie)
        - la chaîne de réception (si on répond)
        """
        self.dh_remote = remote_pubkey
        shared_secret = self.dh_self.compute_shared_key(remote_pubkey)

        if self.is_initiator:
            self.root_key, self.send_chain_key = kdf_root_key(
                self.root_key, shared_secret
            )
        else:
            self.root_key, self.recv_chain_key = kdf_root_key(
                self.root_key, shared_secret
            )

    def ratchet_step(self, remote_pubkey: bytes):
        """
        Lorsqu'on reçoit un message avec une nouvelle clé DH distante :
        - on effectue un DH avec notre ancienne paire → recv_chain_key
        - on génère une nouvelle paire locale (ratchet)
        - on effectue un nouveau DH avec cette paire → send_chain_key
        """
        self.dh_remote = remote_pubkey

        # Étape 1 : mise à jour de la chaîne de réception
        shared_secret = self.dh_self.compute_shared_key(self.dh_remote)
        self.root_key, self.recv_chain_key = kdf_root_key(self.root_key, shared_secret)

        # Étape 2 : génération d'une nouvelle paire locale (DH ratchet)
        self.dh_self = DiffieHellman(parameters=self.dh_parameters)

        # Étape 3 : mise à jour de la chaîne d'envoi
        shared_secret = self.dh_self.compute_shared_key(self.dh_remote)
        self.root_key, self.send_chain_key = kdf_root_key(self.root_key, shared_secret)

    def encrypt(self, plaintext: bytes) -> dict:
        """
        Chiffrement d’un message.
        Chaque message utilise une nouvelle clé dérivée via le send_chain_key.
        Le message retourné contient :
        - la nouvelle clé publique (si changement)
        - le nonce, le texte chiffré et le tag (authentification)
        """
        if self.send_chain_key is None:
            raise Exception("Send chain not initialized.")

        # Dérive une clé de message + met à jour la chaîne
        self.send_chain_key, message_key = kdf_chain_key(self.send_chain_key)

        # Génération d’un nonce unique pour AES-GCM (obligatoire)
        nonce = get_random_bytes(12)

        # Chiffrement avec AES en mode GCM (authentifié)
        cipher = AES.new(message_key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)

        return {
            "dh_pub": self.dh_self.get_public_bytes(),  # notre clé publique actuelle
            "nonce": nonce,
            "ciphertext": ciphertext,
            "tag": tag,
        }

    def decrypt(self, message: dict):
        """
        Déchiffrement d’un message.
        Si le message provient d’une nouvelle clé DH distante, déclenche un DH ratchet.
        Ensuite, dérive la clé de réception et déchiffre le message.
        """
        dh_pub = message["dh_pub"]

        # Si la clé publique distante a changé (nouveau ratchet)
        if self.dh_remote is None or dh_pub != self.dh_remote:
            self.ratchet_step(dh_pub)

        if self.recv_chain_key is None:
            raise Exception("La chaîne de réception n’est pas initialisée.")

        # Dérive la clé de message + met à jour la chaîne
        self.recv_chain_key, message_key = kdf_chain_key(self.recv_chain_key)

        # Déchiffrement en mode AES-GCM
        cipher = AES.new(message_key, AES.MODE_GCM, nonce=message["nonce"])
        plaintext = cipher.decrypt_and_verify(message["ciphertext"], message["tag"])
        return plaintext
