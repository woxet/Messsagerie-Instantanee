from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey
)
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization

class X3DHUser:
    def __init__(self):
        self.IK_priv = X25519PrivateKey.generate()
        self.IK_pub = self.IK_priv.public_key()

        self.SPK_priv = X25519PrivateKey.generate()
        self.SPK_pub = self.SPK_priv.public_key()

        self.OPK_priv = X25519PrivateKey.generate()
        self.OPK_pub = self.OPK_priv.public_key()

    def get_bundle(self):
        return {
            "IK": self.IK_pub.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            ),
            "SPK": self.SPK_pub.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            ),
            "OPK": self.OPK_pub.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
        }

    def compute_shared_key_initiator(self, bob_bundle, eph_priv):
        IK_A_priv = self.IK_priv
        EPH_A_priv = eph_priv

        IK_B_pub = X25519PublicKey.from_public_bytes(bob_bundle["IK"])
        SPK_B_pub = X25519PublicKey.from_public_bytes(bob_bundle["SPK"])
        OPK_B_pub = X25519PublicKey.from_public_bytes(bob_bundle["OPK"])

        DH1 = IK_A_priv.exchange(SPK_B_pub)
        DH2 = EPH_A_priv.exchange(IK_B_pub)
        DH3 = EPH_A_priv.exchange(SPK_B_pub)
        DH4 = EPH_A_priv.exchange(OPK_B_pub)

        print(f"[X3DH Initiator] DH1 (IKa, SPKb)  : {DH1.hex()}")
        print(f"[X3DH Initiator] DH2 (EPHa, IKb)  : {DH2.hex()}")
        print(f"[X3DH Initiator] DH3 (EPHa, SPKb) : {DH3.hex()}")
        print(f"[X3DH Initiator] DH4 (EPHa, OPKb) : {DH4.hex()}")

        dh_concat = DH1 + DH2 + DH3 + DH4

        shared_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"x3dh derived key"
        ).derive(dh_concat)

        print(f"[X3DH Initiator] Shared key       : {shared_key.hex()}")
        return shared_key

    def compute_shared_key_receiver(self, alice_IK_pub_bytes, alice_EPH_pub_bytes):
        IK_B_priv = self.IK_priv
        SPK_B_priv = self.SPK_priv
        OPK_B_priv = self.OPK_priv

        IK_A_pub = X25519PublicKey.from_public_bytes(alice_IK_pub_bytes)
        EPH_A_pub = X25519PublicKey.from_public_bytes(alice_EPH_pub_bytes)

        DH1 = SPK_B_priv.exchange(IK_A_pub)
        DH2 = IK_B_priv.exchange(EPH_A_pub)
        DH3 = SPK_B_priv.exchange(EPH_A_pub)
        DH4 = OPK_B_priv.exchange(EPH_A_pub)

        print(f"[X3DH Receiver] DH1 (SPKb, IKa)  : {DH1.hex()}")
        print(f"[X3DH Receiver] DH2 (IKb, EPHa)  : {DH2.hex()}")
        print(f"[X3DH Receiver] DH3 (SPKb, EPHa) : {DH3.hex()}")
        print(f"[X3DH Receiver] DH4 (OPKb, EPHa) : {DH4.hex()}")

        dh_concat = DH1 + DH2 + DH3 + DH4

        shared_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"x3dh derived key"
        ).derive(dh_concat)

        print(f"[X3DH Receiver] Shared key       : {shared_key.hex()}")
        return shared_key


if __name__ == "__main__":
    bob = X3DHUser()
    bob_bundle = bob.get_bundle()

    alice = X3DHUser()
    eph_priv = X25519PrivateKey.generate()

    shared_key_alice = alice.compute_shared_key_initiator(bob_bundle, eph_priv)

    shared_key_bob = bob.compute_shared_key_receiver(
        alice.IK_pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ),
        eph_priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    )

    print("Clés égales ?", shared_key_alice == shared_key_bob)
