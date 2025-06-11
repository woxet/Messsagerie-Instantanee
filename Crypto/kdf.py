from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

def kdf_chain_key(chain_key: bytes) -> (bytes, bytes):
    """
    Dérive deux clés à partir d'une clé de chaîne symétrique :
    - une nouvelle chaîne de dérivation (chaîne suivante)
    - une clé de message à usage unique (message_key)

    Cette fonction est utilisée à chaque message envoyé ou reçu, et assure la propriété de **forward secrecy**.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),  # Fonction de hachage utilisée dans HMAC
        length=64,  # 64 octets en sortie = 32 pour la nouvelle chaîne + 32 pour la clé de message
        salt=None,
        info=b"ratchet-step",  # Séparation des usages avec un contexte différent
    )

    output = hkdf.derive(chain_key)  
    return output[:32], output[32:]  # new_chain_key, message_key


def kdf_root_key(root_key: bytes, dh_out: bytes) -> (bytes, bytes):
    """
    Dérive :
    - une nouvelle root key
    - une nouvelle chaîne de clés

    Cette fonction est utilisée après un nouveau DH Ratchet :
    `dh_out` = secret partagé via Diffie-Hellman
    `root_key` = état précédent de la racine

    Elle assure la **backward secrecy** : si un ratchet est compromis, les précédents restent sûrs.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64, 
        salt=root_key,  # L'ancienne root_key sert de "sel" sécurisé
        info=b"root-update",
    )

    output = hkdf.derive(dh_out) 
    return output[:32], output[32:]  # new_root_key, new_chain_key
