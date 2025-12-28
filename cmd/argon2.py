#!/usr/bin/env python3
import argparse
import sys
import getpass
import nacl.pwhash
import nacl.exceptions

# =========================
# Hash a password (Argon2id)
# =========================
def hash_password(password=None):
    if password is None:
        password = getpass.getpass("Password: ").encode()
    else:
        password = password.encode()

    hashed = nacl.pwhash.argon2id.str(password)
    sys.stdout.buffer.write(hashed + b"\n")

# =========================
# Verify password against Argon2 hash
# =========================
def verify_password(hash_str=None, password=None):
    if hash_str is None:
        hash_str = input("Hash: ").strip()
    if password is None:
        password = getpass.getpass("Password: ").encode()
    else:
        password = password.encode()

    try:
        nacl.pwhash.verify(hash_str.encode(), password)
        print("✔ Password matches the Argon2 hash!")
    except nacl.exceptions.InvalidkeyError:
        print("✖ Password does NOT match the Argon2 hash!")
    except Exception as e:
        print(f"✖ Verification error: {e}")

# =========================
# CLI
# =========================
def main():
    parser = argparse.ArgumentParser(description="Argon2 (libsodium) hash/verify CLI")
    sub = parser.add_subparsers(dest="cmd")

    h = sub.add_parser("hash")
    h.add_argument("--password", help="Password to hash (optional, otherwise prompted)")

    v = sub.add_parser("verify")
    v.add_argument("--hash", help="Argon2 hash to verify against (optional, otherwise prompted)")
    v.add_argument("--password", help="Password to verify (optional, otherwise prompted)")

    args = parser.parse_args()

    if args.cmd == "hash":
        hash_password(password=args.password)
    elif args.cmd == "verify":
        verify_password(hash_str=args.hash, password=args.password)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()

