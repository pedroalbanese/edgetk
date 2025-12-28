#!/usr/bin/env python3
import argparse
import getpass
import hashlib

# -----------------------------
# Hash password using hashlib.scrypt
# -----------------------------
def scrypt_hash(password=None, salt_str=None, n=16384, key_len=32):
    if password is None:
        password = getpass.getpass("Password: ").encode()
    else:
        password = password.encode()

    if salt_str is None:
        salt_str = getpass.getpass("Salt (string): ")
    salt = salt_str.encode()

    derived_key = hashlib.scrypt(
        password,
        salt=salt,
        n=n,
        r=8,
        p=1,
        maxmem=0,
        dklen=key_len
    )

    # Output to stdout
    print(f"Salt (string): {salt_str}")
    print(f"Derived key (hex): {derived_key.hex()}")

# -----------------------------
# Verify password against hash
# -----------------------------
def scrypt_verify(password=None, salt_str=None, derived_hex=None, n=16384):
    if password is None:
        password = getpass.getpass("Password: ").encode()
    else:
        password = password.encode()

    if salt_str is None:
        salt_str = getpass.getpass("Salt (string): ")
    salt = salt_str.encode()

    if derived_hex is None:
        derived_hex = getpass.getpass("Derived key (hex): ").strip()
    derived_bytes = bytes.fromhex(derived_hex)

    new_derived = hashlib.scrypt(
        password,
        salt=salt,
        n=n,
        r=8,
        p=1,
        maxmem=0,
        dklen=len(derived_bytes)
    )

    if new_derived == derived_bytes:
        print("✔ Password matches the Scrypt hash!")
    else:
        print("✖ Password does NOT match the Scrypt hash!")

# -----------------------------
# CLI
# -----------------------------
def main():
    parser = argparse.ArgumentParser(description="Scrypt CLI (hashlib)")
    sub = parser.add_subparsers(dest="cmd")

    # Hash command
    h = sub.add_parser("hash", help="Hash a password")
    h.add_argument("--password", help="Password to hash")
    h.add_argument("--salt", help="Salt as string (default: prompted)")
    h.add_argument("--iter", type=int, default=16384, help="Scrypt iterations (n, default: 16384)")
    h.add_argument("--keylen", type=int, default=32, help="Derived key length in bytes")

    # Verify command
    v = sub.add_parser("verify", help="Verify a password against a derived key")
    v.add_argument("--password", help="Password to verify")
    v.add_argument("--salt", help="Salt as string")
    v.add_argument("--derived", help="Derived key in hex")
    v.add_argument("--iter", type=int, default=16384, help="Scrypt iterations (n, default: 16384)")

    args = parser.parse_args()

    if args.cmd == "hash":
        scrypt_hash(password=args.password, salt_str=args.salt, n=args.iter, key_len=args.keylen)
    elif args.cmd == "verify":
        scrypt_verify(password=args.password, salt_str=args.salt, derived_hex=args.derived, n=args.iter)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()

