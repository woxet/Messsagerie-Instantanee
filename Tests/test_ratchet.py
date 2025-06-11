import os
from Secu.double_ratchet import DoubleRatchet
from Secu.dh_ratchet import DiffieHellman

shared_root_key = os.urandom(32)

params = DiffieHellman().parameters

alice = DoubleRatchet(root_key=shared_root_key, is_initiator=True, dh_parameters=params)
bob = DoubleRatchet(root_key=shared_root_key, is_initiator=False, dh_parameters=params)

# Initialisation côté Alice
alice.initialize_session(bob.dh_self.get_public_bytes())

# Initialisation côté Bob
bob.initialize_session(alice.dh_self.get_public_bytes())

# Alice envoie un message
msg = b"Hello Bob"
encrypted = alice.encrypt(msg)

# Bob le déchiffre
decrypted = bob.decrypt(encrypted)
print("Message déchiffré :", decrypted.decode())
