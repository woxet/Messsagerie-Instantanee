from cryptography.hazmat.primitives.asymmetric import dh
from Secu.dh_ratchet import DiffieHellman

# Initialisation commune des paramètres
params = dh.generate_parameters(generator=2, key_size=2048)

alice = DiffieHellman(parameters=params)
bob = DiffieHellman(parameters=params)

# Échange des clés publiques
alice_pub = alice.get_public_bytes()
bob_pub = bob.get_public_bytes()

# Calcul des clés partagées
alice_key = alice.compute_shared_key(bob_pub)
bob_key = bob.compute_shared_key(alice_pub)

print("Clé d'Alice :", alice_key.hex())
print("Clé de Bob  :", bob_key.hex())

assert alice_key == bob_key, "Erreur : les clés ne correspondent pas !"
