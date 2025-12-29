#!/usr/bin/env python3
import argparse
import getpass
import hashlib

# -----------------------------
# Derive key using hashlib.scrypt (KDF)
# -----------------------------
def scrypt_derive(secret=None, salt_str=None, n=16384, key_len=32):
	if secret is None:
		secret = getpass.getpass("Secret: ").encode()
	else:
		secret = secret.encode()

	if salt_str is None:
		salt_str = getpass.getpass("Salt (string): ")
	salt = salt_str.encode()

	derived_key = hashlib.scrypt(
		secret,
		salt=salt,
		n=n,
		r=8,
		p=1,
		maxmem=0,
		dklen=key_len
	)

	print(f"Salt (string): {salt_str}")
	print(f"Derived key (hex): {derived_key.hex()}")

# -----------------------------
# Re-derive and compare key
# -----------------------------
def scrypt_compare(secret=None, salt_str=None, derived_hex=None, n=16384):
	if secret is None:
		secret = getpass.getpass("Secret: ").encode()
	else:
		secret = secret.encode()

	if salt_str is None:
		salt_str = getpass.getpass("Salt (string): ")
	salt = salt_str.encode()

	if derived_hex is None:
		derived_hex = getpass.getpass("Derived key (hex): ").strip()
	derived_bytes = bytes.fromhex(derived_hex)

	new_derived = hashlib.scrypt(
		secret,
		salt=salt,
		n=n,
		r=8,
		p=1,
		maxmem=0,
		dklen=len(derived_bytes)
	)

	if new_derived == derived_bytes:
		print("✔ Derived key matches")
	else:
		print("✖ Derived key does NOT match")

# -----------------------------
# CLI
# -----------------------------
def main():
	parser = argparse.ArgumentParser(description="Scrypt KDF CLI (hashlib)")
	sub = parser.add_subparsers(dest="cmd")

	d = sub.add_parser("derive", help="Derive a key from a secret")
	d.add_argument("--secret", help="Input secret")
	d.add_argument("--salt", help="Salt as string")
	d.add_argument("--iter", type=int, default=16384, help="Scrypt N parameter (default: 16384)")
	d.add_argument("--keylen", type=int, default=32, help="Derived key length (bytes)")

	c = sub.add_parser("compare", help="Re-derive and compare a key")
	c.add_argument("--secret", help="Input secret")
	c.add_argument("--salt", help="Salt as string")
	c.add_argument("--derived", help="Derived key (hex)")
	c.add_argument("--iter", type=int, default=16384, help="Scrypt N parameter (default: 16384)")

	args = parser.parse_args()

	if args.cmd == "derive":
		scrypt_derive(
			secret=args.secret,
			salt_str=args.salt,
			n=args.iter,
			key_len=args.keylen
		)
	elif args.cmd == "compare":
		scrypt_compare(
			secret=args.secret,
			salt_str=args.salt,
			derived_hex=args.derived,
			n=args.iter
		)
	else:
		parser.print_help()

if __name__ == "__main__":
	main()
