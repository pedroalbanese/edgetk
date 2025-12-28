#!/usr/bin/env python3
import argparse
import os
import sys

import nacl.bindings

# =========================
# Encrypt with AAD (string), output to stdout
# =========================
def encrypt_file(key_hex, infile, aad_str=None):
    key = bytes.fromhex(key_hex)
    nonce = os.urandom(12)  # 12-byte nonce
    aad = aad_str.encode() if aad_str else None

    with open(infile, "rb") as f:
        plaintext = f.read()

    ciphertext_and_tag = nacl.bindings.crypto_aead_chacha20poly1305_ietf_encrypt(
        plaintext,
        aad=aad,
        nonce=nonce,
        key=key
    )

    # Write nonce + ciphertext + tag to stdout
    sys.stdout.buffer.write(nonce + ciphertext_and_tag)

# =========================
# Decrypt with AAD (string), read from stdin
# =========================
def decrypt_file(key_hex, aad_str=None):
    key = bytes.fromhex(key_hex)
    aad = aad_str.encode() if aad_str else None

    # Read ciphertext + tag from stdin
    data = sys.stdin.buffer.read()
    if len(data) < 12:
        print("✖ Invalid input, too short", file=sys.stderr)
        sys.exit(1)

    nonce = data[:12]
    ciphertext_and_tag = data[12:]

    try:
        plaintext = nacl.bindings.crypto_aead_chacha20poly1305_ietf_decrypt(
            ciphertext_and_tag,
            aad=aad,
            nonce=nonce,
            key=key
        )
        sys.stdout.buffer.write(plaintext)
    except Exception as e:
        print("✖ Decryption failed:", e, file=sys.stderr)
        sys.exit(1)

# =========================
# CLI
# =========================
def main():
    parser = argparse.ArgumentParser(description="ChaCha20-Poly1305 (with string AAD), stdin/stdout")
    sub = parser.add_subparsers(dest="cmd")

    enc = sub.add_parser("encrypt")
    enc.add_argument("--key", required=True, help="32-byte key in hex")
    enc.add_argument("--infile", required=True)
    enc.add_argument("--aad", help="AAD as string (optional)")

    dec = sub.add_parser("decrypt")
    dec.add_argument("--key", required=True, help="32-byte key in hex")
    dec.add_argument("--aad", help="AAD as string (optional)")

    args = parser.parse_args()

    if args.cmd == "encrypt":
        encrypt_file(args.key, args.infile, aad_str=args.aad)
    elif args.cmd == "decrypt":
        decrypt_file(args.key, aad_str=args.aad)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()

