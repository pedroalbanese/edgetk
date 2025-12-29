#!/usr/bin/env python3
import argparse
from nacl.public import PrivateKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

# =========================
# Generate Keys
# =========================
def generate_keys(priv_path="private.pem", pub_path="public.pem"):
    # Generate private key
    priv_key = x25519.X25519PrivateKey.generate()
    pub_key = priv_key.public_key()

    # Save private key (PEM)
    priv_pem = priv_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(priv_path, "wb") as f:
        f.write(priv_pem)
    print(f"✔ Private key saved to {priv_path}")

    # Save public key (PEM)
    pub_pem = pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(pub_path, "wb") as f:
        f.write(pub_pem)
    print(f"✔ Public key saved to {pub_path}")

# =========================
# Load Keys from PEM
# =========================
def load_private_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def load_public_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())

# =========================
# Compute Shared Key
# =========================
def compute_shared(priv_path, peer_pub_path):
    priv_key = load_private_key(priv_path)
    peer_pub = load_public_key(peer_pub_path)

    shared = priv_key.exchange(peer_pub)
    print("Shared key (hex):", shared.hex())

# =========================
# CLI
# =========================
def main():
    parser = argparse.ArgumentParser(description="X25519 Key Exchange CLI")
    sub = parser.add_subparsers(dest="cmd")

    g = sub.add_parser("gen", help="Generate X25519 key pair")
    g.add_argument("--priv", default="private.pem", help="Private key output path")
    g.add_argument("--pub", default="public.pem", help="Public key output path")

    s = sub.add_parser("shared", help="Compute shared key using your private key and peer's public key")
    s.add_argument("--priv", required=True, help="Your private key path")
    s.add_argument("--peer", required=True, help="Peer's public key path")

    args = parser.parse_args()

    if args.cmd == "gen":
        generate_keys(priv_path=args.priv, pub_path=args.pub)
    elif args.cmd == "shared":
        compute_shared(priv_path=args.priv, peer_pub_path=args.peer)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
