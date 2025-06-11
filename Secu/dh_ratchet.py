from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

class DiffieHellman:
    def __init__(self, parameters: dh.DHParameters = None):
        # Si aucun paramètre DH n’est fourni, on les génère (p, g) avec 2048 bits de sécurité
        if parameters is None:
            self.parameters = dh.generate_parameters(generator=2, key_size=2048)
        else:
            self.parameters = parameters

        # Génération de la clé privée et récupération de la clé publique correspondante
        self.private_key = self.parameters.generate_private_key()
        self.public_key = self.private_key.public_key()

        self.shared_key = None
        self.derived_key = None

    def get_public_bytes(self):
        # Sérialise la clé publique DH au format PEM pour l’envoi sur le réseau
        return self.public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

    def compute_shared_key(self, peer_public_bytes: bytes):
        # Reconstruct la clé publique de l’autre participant à partir du format PEM reçu
        peer_public_key = serialization.load_pem_public_key(peer_public_bytes, backend=default_backend())

        # Effectue l’échange Diffie-Hellman : g^(ab) mod p
        self.shared_key = self.private_key.exchange(peer_public_key)

        # Utilise HKDF pour dériver une clé symétrique à partir du secret partagé
        # Cela garantit une sortie de longueur fixe et adaptée au chiffrement (ex: AES-256)
        self.derived_key = HKDF(
            algorithm=hashes.SHA256(), 
            length=32, 
            salt=None, # A ajouter ?
            info=b"handshake data", 
        ).derive(self.shared_key)

        return (self.derived_key)  # Retourne la clé symétrique
