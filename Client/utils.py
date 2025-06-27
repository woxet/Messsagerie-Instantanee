from Secu.x3dh import X3DHUser
import json
import os
from cryptography.hazmat.primitives import serialization

def generate_and_send_bundle(sock, user_id):
    user = X3DHUser()

    with open(f"keys/{user_id}_private_keys.pem", "wb") as f:
        f.write(user.IK_priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
        f.write(user.SPK_priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
        f.write(user.OPK_priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    bundle = {
        "type": "post_bundle",
        "user_id": user_id,
        "IK": user.IK_pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ).hex(),
        "SPK": user.SPK_pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ).hex(),
        "OPK": user.OPK_pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ).hex()
    }

    sock.sendall((json.dumps(bundle) + "\n").encode())
    print(f"[DEBUG] Bundle envoyé pour {user_id}")

    return user
