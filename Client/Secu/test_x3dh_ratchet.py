from x3dh import X3DHUser
from dratchet import *
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization

def test_x3dh_plus_double_ratchet():
    print("== Étape 1 : X3DH ==")
    # Bob prépare ses clés
    bob = X3DHUser()
    bob_bundle = bob.get_bundle()

    # Alice génère ses clés + clé éphémère
    alice = X3DHUser()
    eph_priv = X25519PrivateKey.generate()

    # Alice dérive la root key
    rk_alice = alice.compute_shared_key_initiator(bob_bundle, eph_priv)

    # Bob dérive la même root key
    rk_bob = bob.compute_shared_key_receiver(
        alice.IK_pub.public_bytes(encoding=serialization.Encoding.Raw,
                                  format=serialization.PublicFormat.Raw),
        eph_priv.public_key().public_bytes(encoding=serialization.Encoding.Raw,
                                           format=serialization.PublicFormat.Raw)
    )

    print("[✓] Clé partagée dérivée.")
    assert rk_alice == rk_bob, "Les clés dérivées ne correspondent pas !"
    print("Clé partagée :", rk_alice.hex())

    print("\n== Étape 2 : Initialisation Double Ratchet ==")
    # Alice et Bob initialisent leur état de session
    alice_state = RatchetInit(
        is_initiator=True,
        root_key=rk_alice,
        dh_remote_pub=bob.SPK_pub
    )

    bob_state = RatchetInit(
        is_initiator=False,
        root_key=rk_bob,
        dh_self_priv=bob.SPK_priv
    )
    print("[✓] État initialisé des deux côtés.")

    print("\n== Étape 3 : Échange de messages ==")

    # Alice envoie un message à Bob
    header1, nonce1, ct1 = RatchetEncrypt(alice_state, b"Salut Bob !")
    print("[→] Alice envoie : Salut Bob !")

    msg1 = RatchetDecrypt(bob_state, header1, nonce1, ct1)
    print("[←] Bob reçoit  :", msg1.decode())

    # Bob répond
    header2, nonce2, ct2 = RatchetEncrypt(bob_state, b"Salut Alice !")
    print("[→] Bob envoie  : Salut Alice !")

    msg2 = RatchetDecrypt(alice_state, header2, nonce2, ct2)
    print("[←] Alice reçoit:", msg2.decode())

if __name__ == "__main__":
    test_x3dh_plus_double_ratchet()
