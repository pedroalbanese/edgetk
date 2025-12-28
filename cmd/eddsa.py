#!/usr/bin/env python3
import binascii
import argparse
import sys

import nacl.signing
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# =========================
# Generate Keys
# =========================
def generate_keys(priv_path, pub_path):
    signing_key = nacl.signing.SigningKey.generate()
    seed = signing_key._seed
    pub = signing_key.verify_key.encode()

    # Salvar chave pública
    pub_obj = ed25519.Ed25519PublicKey.from_public_bytes(pub)
    pub_pem = pub_obj.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with open(pub_path, "wb") as f:
        f.write(pub_pem)
    print(f"✔ Public key saved to {pub_path}")

    # Salvar chave privada (não criptografada)
    priv_obj = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
    priv_pem = priv_obj.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(priv_path, "wb") as f:
        f.write(priv_pem)
    print(f"✔ Private key saved to {priv_path} (PKCS#8 unencrypted)")

# =========================
# Sign Message
# =========================
def sign_message(priv_path, msg_path):
    # Carregar chave privada
    with open(priv_path, "rb") as f:
        pem_data = f.read()
    priv_obj = serialization.load_pem_private_key(pem_data, password=None, backend=default_backend())
    seed = priv_obj.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    signing_key = nacl.signing.SigningKey(seed)

    # Ler mensagem
    with open(msg_path, "rb") as f:
        message = f.read()

    # Gerar assinatura
    signature = signing_key.sign(message).signature
    sig_hex = binascii.hexlify(signature).decode()

    # Saída para stdout
    print(sig_hex)

# =========================
# Verify Signature
# =========================
def verify_signature(pub_path, msg_path, sig_hex):
    # Carregar chave pública
    with open(pub_path, "rb") as f:
        pub_data = f.read()
    pub_obj = serialization.load_pem_public_key(pub_data, backend=default_backend())
    raw_pub = pub_obj.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    verify_key = nacl.signing.VerifyKey(raw_pub)

    # Ler mensagem
    with open(msg_path, "rb") as f:
        message = f.read()

    # Converter assinatura de hex
    try:
        signature = binascii.unhexlify(sig_hex)
    except binascii.Error:
        print("✖ Invalid signature hex")
        sys.exit(1)

    try:
        verify_key.verify(message, signature)
        print("✔ Signature valid")
    except Exception:
        print("✖ Signature invalid")

# =========================
# CLI
# =========================
def main():
    parser = argparse.ArgumentParser(description="Ed25519 tool with stdout signature")
    sub = parser.add_subparsers(dest="cmd")

    g = sub.add_parser("gen")
    g.add_argument("--priv", default="private.pem")
    g.add_argument("--pub", default="public.pem")

    s = sub.add_parser("sign")
    s.add_argument("--priv", required=True)
    s.add_argument("--msg", required=True)

    v = sub.add_parser("verify")
    v.add_argument("--pub", required=True)
    v.add_argument("--msg", required=True)
    v.add_argument("--sig", required=True, help="Signature in hex to verify")

    args = parser.parse_args()

    if args.cmd == "gen":
        generate_keys(args.priv, args.pub)
    elif args.cmd == "sign":
        sign_message(args.priv, args.msg)
    elif args.cmd == "verify":
        verify_signature(args.pub, args.msg, args.sig)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()

