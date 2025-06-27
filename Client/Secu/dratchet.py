import os
import struct
from dataclasses import dataclass
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey
)
from cryptography.hazmat.primitives import serialization

def GENERATE_DH():
    return X25519PrivateKey.generate()

def DH(dh_pair: X25519PrivateKey, dh_pub: X25519PublicKey) -> bytes:
    return dh_pair.exchange(dh_pub)

def KDF_RK(rk: bytes, dh_out: bytes) -> tuple[bytes, bytes]:
    """Retourne (root_key, chain_key) – HKDF-SHA256, 64 octets."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=rk,
        info=b"DoubleRatchetRoot"
    )
    out = hkdf.derive(dh_out)
    return out[:32], out[32:]

def KDF_CK(ck: bytes) -> tuple[bytes, bytes]:
    """
    Renvoie (new_chain_key, message_key) :
    HMAC-SHA256, avec constantes 0x01 / 0x02 comme dans la spec.
    """
    def _h(label: bytes) -> bytes:
        h = hmac.HMAC(ck, hashes.SHA256())
        h.update(label)
        return h.finalize()
    mk  = _h(b"\x01")          # message key
    nck = _h(b"\x02")          # next chain key
    return nck, mk[:32]        # tronque MK à 32 o.

def ENCRYPT(mk: bytes, pt: bytes, ad: bytes) -> tuple[bytes, bytes]:
    nonce = os.urandom(12)
    ct = AESGCM(mk).encrypt(nonce, pt, ad)
    return nonce, ct

def DECRYPT(mk: bytes, nonce: bytes, ct: bytes, ad: bytes) -> bytes:
    return AESGCM(mk).decrypt(nonce, ct, ad)

def HEADER(dh_pub: X25519PublicKey, pn: int, n: int) -> bytes:
    """
    Encodage : dh_pub (32 o) || PN (uint32 big-endian) || N (uint32 big-endian)
    """
    return dh_pub.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw
    ) + struct.pack(">II", pn, n)

def PARSE_HEADER(hdr: bytes) -> tuple[X25519PublicKey, int, int]:
    if len(hdr) != 32 + 8:
        raise ValueError("Header invalid length")
    dh = X25519PublicKey.from_public_bytes(hdr[:32])
    pn, n = struct.unpack(">II", hdr[32:])
    return dh, pn, n

def CONCAT(ad: bytes, header: bytes) -> bytes:
    return ad + header

from dataclasses import dataclass
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey
)
from cryptography.hazmat.primitives import serialization

@dataclass
class State:
    DHs: X25519PrivateKey | None
    DHr: X25519PublicKey  | None
    RK : bytes | None
    CKs: bytes | None
    CKr: bytes | None
    Ns : int
    Nr : int
    PN : int

    def to_dict(self):
        return {
            "rk": self.RK.hex() if self.RK else None,
            "dh_self_priv": self.DHs.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            ).hex() if self.DHs else None,
            "dh_remote_pub": self.DHr.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            ).hex() if self.DHr else None,
            "CKs": self.CKs.hex() if self.CKs else None,
            "CKr": self.CKr.hex() if self.CKr else None,
            "Ns": self.Ns,
            "Nr": self.Nr,
            "PN": self.PN
        }

    @classmethod
    def from_dict(cls, data):
        return cls(
            DHs=X25519PrivateKey.from_private_bytes(bytes.fromhex(data["dh_self_priv"])) if data["dh_self_priv"] else None,
            DHr=X25519PublicKey.from_public_bytes(bytes.fromhex(data["dh_remote_pub"])) if data["dh_remote_pub"] else None,
            RK=bytes.fromhex(data["rk"]) if data["rk"] else None,
            CKs=bytes.fromhex(data["CKs"]) if data["CKs"] else None,
            CKr=bytes.fromhex(data["CKr"]) if data["CKr"] else None,
            Ns=data["Ns"],
            Nr=data["Nr"],
            PN=data["PN"]
        )

def RatchetInit(
    is_initiator: bool,
    root_key: bytes,
    dh_remote_pub: X25519PublicKey | None = None,
    dh_self_priv: X25519PrivateKey | None = None
) -> State:
    st = State(None, None, root_key, None, None, 0, 0, 0)

    if is_initiator:
        if dh_remote_pub is None:
            raise ValueError("Initiateur requiert la clé publique distante (DHr)")
        st.DHs = GENERATE_DH()
        st.DHr = dh_remote_pub
        st.RK, st.CKs = KDF_RK(root_key, DH(st.DHs, st.DHr))
    else:
        if dh_self_priv is None:
            raise ValueError("Récepteur requiert sa propre clé privée (DHs)")
        st.DHs = dh_self_priv
        st.DHr = None
    return st

def DHRatchet(st: State, header_dh: X25519PublicKey):
    st.PN = st.Ns
    st.Ns = st.Nr = 0
    st.DHr = header_dh
    
    st.RK, st.CKr = KDF_RK(st.RK, DH(st.DHs, st.DHr))

    st.DHs = GENERATE_DH()

    st.RK, st.CKs = KDF_RK(st.RK, DH(st.DHs, st.DHr))

def RatchetEncrypt(st: State, plaintext: bytes, AD: bytes=b"") -> tuple[bytes, bytes, bytes]:
    st.CKs, mk = KDF_CK(st.CKs)
    header = HEADER(st.DHs.public_key(), st.PN, st.Ns)
    st.Ns += 1
    nonce, ct = ENCRYPT(mk, plaintext, CONCAT(AD, header))
    return header, nonce, ct

def RatchetDecrypt(st: State, header: bytes, nonce: bytes, ct: bytes, AD: bytes=b"") -> bytes:
    hdr_dh, hdr_pn, hdr_n = PARSE_HEADER(header)

    if st.DHr is None or \
       hdr_dh.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw) != \
       st.DHr.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw):
        DHRatchet(st, hdr_dh)

    if hdr_n != st.Nr:
        print("[!] Message reçu dans le désordre — ignoré.")
        return b"[message ignore]"

    st.CKr, mk = KDF_CK(st.CKr)
    st.Nr += 1
    return DECRYPT(mk, nonce, ct, CONCAT(AD, header))

if __name__ == "__main__":
    SK = os.urandom(32)

    bob_keypair = GENERATE_DH()

    alice = RatchetInit(
        is_initiator=True,
        root_key=SK,
        dh_remote_pub=bob_keypair.public_key()
    )

    bob = RatchetInit(
        is_initiator=False,
        root_key=SK,
        dh_self_priv=bob_keypair
    )

    for msg in (b"Salut Bob !", b"Deuxieme msg"):
        header, nonce, ct = RatchetEncrypt(alice, msg)
        plaintext = RatchetDecrypt(bob, header, nonce, ct)
        print("Bob reçoit :", plaintext.decode())

    header, nonce, ct = RatchetEncrypt(bob, b"Bien recu Alice")
    plaintext = RatchetDecrypt(alice, header, nonce, ct)
    print("Alice reçoit :", plaintext.decode())