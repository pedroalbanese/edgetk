#!/usr/bin/env python3
"""
EDGE Crypto Toolbox - Integrated Cryptographic Tools
Contains: Argon2, ChaCha20-Poly1305, Ed25519, Scrypt, X25519
"""

import argparse
import sys
import getpass
import os
import hashlib
import base64
import binascii

# Required libraries
import nacl.pwhash
import nacl.exceptions
import nacl.bindings
import nacl.signing
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.backends import default_backend

# =========================
# Shared PEM Encryption/Decryption Functions (RFC 1423)
# =========================

# Available ciphers (following RFC 1423 and EdgeTK format)
SUPPORTED_CIPHERS = {
    "aes128": ("AES-128-CBC", 16),      # 16 bytes = 128 bits
    "aes192": ("AES-192-CBC", 24),      # 24 bytes = 192 bits
    "aes256": ("AES-256-CBC", 32),      # 32 bytes = 256 bits (default)
    "camellia128": ("CAMELLIA-128-CBC", 16),
    "camellia192": ("CAMELLIA-192-CBC", 24),
    "camellia256": ("CAMELLIA-256-CBC", 32),
    "sm4": ("SM4-CBC", 16),             # 16 bytes = 128 bits
}

def validate_cipher(cipher_name):
    """Validate and normalize cipher name"""
    cipher_name = cipher_name.lower()
    if cipher_name in SUPPORTED_CIPHERS:
        return cipher_name
    # Try to find by alias
    aliases = {
        "aes": "aes256",
        "aes-128": "aes128",
        "aes-192": "aes192",
        "aes-256": "aes256",
        "camellia": "camellia256",
        "camellia-128": "camellia128",
        "camellia-192": "camellia192",
        "camellia-256": "camellia256",
    }
    if cipher_name in aliases:
        return aliases[cipher_name]
    
    # List available ciphers
    available = ", ".join(sorted(SUPPORTED_CIPHERS.keys()))
    raise ValueError(f"Unsupported cipher: {cipher_name}. Available: {available}")

def get_cipher_info(cipher_name):
    """Get cipher display name and key size"""
    cipher_name = validate_cipher(cipher_name)
    return SUPPORTED_CIPHERS[cipher_name]

def derive_key_rfc1423(password, salt, key_length):
    """
    Derive key using the RFC 1423 algorithm (MD5-based)
    Similar to what EdgeTK uses
    """
    if isinstance(password, str):
        password = password.encode('utf-8')
    
    d = b''
    key = b''
    
    while len(key) < key_length:
        md5 = hashlib.md5()
        md5.update(d)
        md5.update(password)
        md5.update(salt[:8])  # Use first 8 bytes of IV as salt
        d = md5.digest()
        key += d
    
    return key[:key_length]

def encrypt_pem_block(data, password, cipher_name="aes256"):
    """Encrypt data using RFC 1423 format with BEGIN/END PRIVATE KEY"""
    if isinstance(password, str):
        password = password.encode('utf-8')
    
    # Get cipher information
    cipher_display_name, key_length = get_cipher_info(cipher_name)
    
    # Generate random IV (16 bytes for all supported ciphers)
    iv = os.urandom(16)
    
    # Derive key using RFC 1423 algorithm
    key = derive_key_rfc1423(password, iv, key_length)
    
    # Select cipher algorithm based on cipher_name
    if cipher_name.startswith("aes"):
        algorithm = algorithms.AES(key)
    elif cipher_name.startswith("camellia"):
        try:
            from cryptography.hazmat.primitives.ciphers.algorithms import Camellia
            algorithm = Camellia(key)
        except ImportError:
            raise ValueError(f"Camellia not supported in this cryptography version")
    elif cipher_name == "sm4":
        try:
            from cryptography.hazmat.primitives.ciphers.algorithms import SM4
            algorithm = SM4(key)
        except ImportError:
            raise ValueError(f"SM4 not supported in this cryptography version")
    else:
        raise ValueError(f"Unsupported cipher algorithm: {cipher_name}")
    
    block_size = 16  # All supported ciphers use 16-byte blocks
    
    # Encrypt data using cryptography library
    padder = padding.PKCS7(block_size * 8).padder()  # block_size in bits
    padded_data = padder.update(data) + padder.finalize()
    
    cipher = Cipher(algorithm, modes.CBC(iv))
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    
    # Create headers
    headers = {
        "Proc-Type": "4,ENCRYPTED",
        "DEK-Info": f"{cipher_display_name},{binascii.hexlify(iv).decode()}"
    }
    
    return encrypted_data, headers, cipher_display_name

def decrypt_pem_block(encrypted_data, password, iv_hex, cipher_display_name):
    """Decrypt data using RFC 1423 format"""
    if isinstance(password, str):
        password = password.encode('utf-8')
    
    # Decode IV
    iv = binascii.unhexlify(iv_hex)
    
    # Determine cipher name from display name
    cipher_name = None
    key_length = None
    for key, (display, length) in SUPPORTED_CIPHERS.items():
        if display == cipher_display_name:
            cipher_name = key
            key_length = length
            break
    
    if cipher_name is None:
        raise ValueError(f"Unsupported cipher: {cipher_display_name}")
    
    # Derive key using RFC 1423 algorithm
    key = derive_key_rfc1423(password, iv, key_length)
    block_size = 16  # All supported ciphers use 16-byte blocks
    
    # Select cipher algorithm
    if cipher_name.startswith("aes"):
        algorithm = algorithms.AES(key)
    elif cipher_name.startswith("camellia"):
        try:
            from cryptography.hazmat.primitives.ciphers.algorithms import Camellia
            algorithm = Camellia(key)
        except ImportError:
            raise ValueError(f"Camellia not supported in this cryptography version")
    elif cipher_name == "sm4":
        try:
            from cryptography.hazmat.primitives.ciphers.algorithms import SM4
            algorithm = SM4(key)
        except ImportError:
            raise ValueError(f"SM4 not supported in this cryptography version")
    else:
        raise ValueError(f"Unsupported cipher algorithm: {cipher_name}")
    
    # Decrypt data
    cipher = Cipher(algorithm, modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(encrypted_data) + decryptor.finalize()
    
    # Remove padding
    unpadder = padding.PKCS7(block_size * 8).unpadder()
    try:
        data = unpadder.update(decrypted_padded) + unpadder.finalize()
        return data
    except ValueError:
        # If unpadding fails, password is probably wrong
        raise ValueError("Incorrect password or corrupted data")

def parse_encrypted_pem(pem_content):
    """Parse an encrypted PEM file with BEGIN/END PRIVATE KEY"""
    lines = pem_content.strip().split('\n')
    headers = {}
    data_lines = []
    in_headers = False
    in_data = False
    
    for line in lines:
        if line.startswith('-----BEGIN PRIVATE KEY-----'):
            in_headers = True
            continue
        elif line.startswith('-----END PRIVATE KEY-----'):
            break
        elif in_headers and ':' in line:
            key, value = line.split(':', 1)
            headers[key.strip()] = value.strip()
        elif line == '' and in_headers:
            # Empty line marks end of headers, start of data
            in_headers = False
            in_data = True
        elif in_data:
            data_lines.append(line.strip())
    
    return headers, ''.join(data_lines)

def load_encrypted_private_key(priv_path, password):
    """Load and decrypt an encrypted private key with BEGIN/END PRIVATE KEY"""
    with open(priv_path, "r") as f:
        pem_content = f.read()
    
    # Parse PEM
    headers, b64_data = parse_encrypted_pem(pem_content)
    
    # Check if we have the required headers
    if 'DEK-Info' not in headers:
        # Try to load as unencrypted key
        priv_obj = serialization.load_pem_private_key(
            pem_content.encode(),
            password=None,
            backend=default_backend()
        )
        return priv_obj
    
    # Parse DEK-Info
    dek_info = headers['DEK-Info']
    cipher_display_name, iv_hex = dek_info.split(',')
    
    # Decode base64 data
    encrypted_data = base64.b64decode(b64_data)
    
    # Decrypt
    try:
        der_data = decrypt_pem_block(encrypted_data, password, iv_hex, cipher_display_name)
    except ValueError as e:
        raise ValueError(f"Decryption failed: {e}")
    
    # Convert DER back to private key object
    # First create PEM from DER
    b64_der = base64.b64encode(der_data).decode()
    pem_der = f"-----BEGIN PRIVATE KEY-----\n"
    for i in range(0, len(b64_der), 64):
        pem_der += b64_der[i:i+64] + "\n"
    pem_der += "-----END PRIVATE KEY-----\n"
    
    # Load the private key
    priv_obj = serialization.load_pem_private_key(
        pem_der.encode(),
        password=None,
        backend=default_backend()
    )
    
    return priv_obj

# =========================
# 1. ARGON2 (Password Hashing)
# =========================

def argon2_hash_password(password=None):
    """Hash a password using Argon2id"""
    if password is None:
        password = getpass.getpass("Password: ").encode()
    else:
        password = password.encode()

    hashed = nacl.pwhash.argon2id.str(password)
    sys.stdout.buffer.write(hashed + b"\n")

def argon2_verify_password(hash_str=None, password=None):
    """Verify password against Argon2 hash"""
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
# 2. CHACHA20-POLY1305 (Encryption)
# =========================

def chacha20_encrypt_file(key_hex, infile, aad_str=None):
    """Encrypt with AAD (string), output to stdout"""
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

def chacha20_decrypt_file(key_hex, aad_str=None):
    """Decrypt with AAD (string), read from stdin"""
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
# 3. EDDSA (Ed25519 Signatures)
# =========================

def eddsa_generate_keys(priv_path, pub_path, cipher_name="aes256"):
    """Generate Ed25519 key pair with optional encryption"""
    signing_key = nacl.signing.SigningKey.generate()
    seed = signing_key._seed
    pub = signing_key.verify_key.encode()

    # Save public key
    pub_obj = ed25519.Ed25519PublicKey.from_public_bytes(pub)
    pub_pem = pub_obj.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with open(pub_path, "wb") as f:
        f.write(pub_pem)
    print(f"✔ Public key saved to {pub_path}")

    # Ask for password (optional - press Enter for no encryption)
    password = getpass.getpass("Enter password to encrypt private key (press Enter for no encryption): ")
    
    if password:
        # User provided a password - encrypt the key
        # Generate unencrypted private key in PKCS8 format
        priv_obj = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
        priv_pem = priv_obj.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        
        # Extract the actual DER bytes (without PEM headers)
        lines = priv_pem.decode().split('\n')
        der_b64 = ''.join([line.strip() for line in lines 
                          if line.strip() and not line.startswith('-----')])
        der_data = base64.b64decode(der_b64)
        
        # Encrypt the DER data using RFC 1423
        try:
            encrypted_data, headers, cipher_display_name = encrypt_pem_block(der_data, password, cipher_name)
        except ValueError as e:
            print(f"✖ Error: {e}")
            sys.exit(1)
        
        # Build encrypted PEM with BEGIN/END PRIVATE KEY
        encrypted_pem = "-----BEGIN PRIVATE KEY-----\n"
        for key, value in headers.items():
            encrypted_pem += f"{key}: {value}\n"
        encrypted_pem += "\n"
        
        # Add base64 encoded encrypted data
        b64_data = base64.b64encode(encrypted_data).decode()
        # Split into 64 character lines
        for i in range(0, len(b64_data), 64):
            encrypted_pem += b64_data[i:i+64] + "\n"
        
        encrypted_pem += "-----END PRIVATE KEY-----\n"
        
        with open(priv_path, "w") as f:
            f.write(encrypted_pem)
        
        print(f"✔ Encrypted private key saved to {priv_path}")
        print(f"  Cipher: {cipher_display_name}")
    else:
        # No password provided - save unencrypted key
        priv_obj = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
        priv_pem = priv_obj.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        with open(priv_path, "wb") as f:
            f.write(priv_pem)
        print(f"✔ Unencrypted private key saved to {priv_path}")

def eddsa_sign_message(priv_path, msg_path):
    """Sign a message with Ed25519"""
    # Check if private key is encrypted
    with open(priv_path, "rb") as f:
        pem_data = f.read()
    content = pem_data.decode('utf-8', errors='ignore')
    
    password = None
    if 'Proc-Type: 4,ENCRYPTED' in content and 'DEK-Info:' in content:
        password = getpass.getpass("Enter password to decrypt private key: ")
    
    try:
        # Try to load as encrypted key
        priv_obj = load_encrypted_private_key(priv_path, password)
    except Exception as e:
        # If it fails, try to load as unencrypted key
        try:
            priv_obj = serialization.load_pem_private_key(
                pem_data, 
                password=None, 
                backend=default_backend()
            )
        except Exception:
            print(f"✖ Error loading private key: {e}")
            sys.exit(1)
    
    # Extract the seed in raw format
    seed = priv_obj.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    signing_key = nacl.signing.SigningKey(seed)

    # Read message
    with open(msg_path, "rb") as f:
        message = f.read()

    # Generate signature
    signature = signing_key.sign(message).signature
    sig_hex = binascii.hexlify(signature).decode()

    # Output to stdout
    print(sig_hex)

def eddsa_verify_signature(pub_path, msg_path, sig_hex):
    """Verify Ed25519 signature"""
    # Load public key
    with open(pub_path, "rb") as f:
        pub_data = f.read()
    pub_obj = serialization.load_pem_public_key(pub_data, backend=default_backend())
    raw_pub = pub_obj.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    verify_key = nacl.signing.VerifyKey(raw_pub)

    # Read message
    with open(msg_path, "rb") as f:
        message = f.read()

    # Convert signature from hex
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
# 4. SCRYPT (Key Derivation)
# =========================

def scrypt_derive(secret=None, salt_str=None, n=16384, key_len=32):
    """Derive key using hashlib.scrypt (KDF)"""
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

def scrypt_compare(secret=None, salt_str=None, derived_hex=None, n=16384):
    """Re-derive and compare key"""
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

# =========================
# 5. X25519 (Key Exchange)
# =========================

def x25519_generate_keys(priv_path="private.pem", pub_path="public.pem", cipher_name="aes256"):
    """Generate X25519 key pair with optional encryption"""
    # Generate private key
    priv_key = x25519.X25519PrivateKey.generate()
    pub_key = priv_key.public_key()

    # Save public key
    pub_pem = pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(pub_path, "wb") as f:
        f.write(pub_pem)
    print(f"✔ Public key saved to {pub_path}")

    # Ask for password (optional - press Enter for no encryption)
    password = getpass.getpass("Enter password to encrypt private key (press Enter for no encryption): ")
    
    if password:
        # User provided a password - encrypt the key
        # Generate unencrypted private key in PKCS8 format
        priv_pem = priv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Extract the actual DER bytes (without PEM headers)
        lines = priv_pem.decode().split('\n')
        der_b64 = ''.join([line.strip() for line in lines 
                          if line.strip() and not line.startswith('-----')])
        der_data = base64.b64decode(der_b64)
        
        # Encrypt the DER data using RFC 1423
        try:
            encrypted_data, headers, cipher_display_name = encrypt_pem_block(der_data, password, cipher_name)
        except ValueError as e:
            print(f"✖ Error: {e}")
            sys.exit(1)
        
        # Build encrypted PEM with BEGIN/END PRIVATE KEY
        encrypted_pem = "-----BEGIN PRIVATE KEY-----\n"
        for key, value in headers.items():
            encrypted_pem += f"{key}: {value}\n"
        encrypted_pem += "\n"
        
        # Add base64 encoded encrypted data
        b64_data = base64.b64encode(encrypted_data).decode()
        # Split into 64 character lines
        for i in range(0, len(b64_data), 64):
            encrypted_pem += b64_data[i:i+64] + "\n"
        
        encrypted_pem += "-----END PRIVATE KEY-----\n"
        
        with open(priv_path, "w") as f:
            f.write(encrypted_pem)
        
        print(f"✔ Encrypted private key saved to {priv_path}")
        print(f"  Cipher: {cipher_display_name}")
    else:
        # No password provided - save unencrypted key
        priv_pem = priv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(priv_path, "wb") as f:
            f.write(priv_pem)
        print(f"✔ Unencrypted private key saved to {priv_path}")

def x25519_compute_shared(priv_path, peer_pub_path):
    """Compute shared key using X25519"""
    # Check if private key is encrypted
    with open(priv_path, "rb") as f:
        pem_data = f.read()
    content = pem_data.decode('utf-8', errors='ignore')
    
    password = None
    if 'Proc-Type: 4,ENCRYPTED' in content and 'DEK-Info:' in content:
        password = getpass.getpass("Enter password to decrypt private key: ")
    
    try:
        # Try to load as encrypted key
        priv_key = load_encrypted_private_key(priv_path, password)
    except Exception as e:
        # If it fails, try to load as unencrypted key
        try:
            priv_key = serialization.load_pem_private_key(
                pem_data, 
                password=None, 
                backend=default_backend()
            )
        except Exception:
            print(f"✖ Error loading private key: {e}")
            sys.exit(1)
    
    # Load peer's public key
    with open(peer_pub_path, "rb") as f:
        peer_pub = serialization.load_pem_public_key(f.read())

    shared = priv_key.exchange(peer_pub)
    print("Shared key (hex):", shared.hex())

# =========================
# List available ciphers
# =========================

def list_ciphers():
    """List all available ciphers"""
    print("Available ciphers for private key encryption:")
    print("-" * 50)
    
    # Group by type for better organization
    print("AES (Recommended):")
    for cipher in ["aes128", "aes192", "aes256"]:
        display_name, key_size = SUPPORTED_CIPHERS[cipher]
        bits = key_size * 8
        print(f"  {cipher:15} -> {display_name:20} ({bits}-bit, {key_size} bytes key)")
    
    print("\nCamellia:")
    for cipher in ["camellia128", "camellia192", "camellia256"]:
        display_name, key_size = SUPPORTED_CIPHERS[cipher]
        bits = key_size * 8
        print(f"  {cipher:15} -> {display_name:20} ({bits}-bit, {key_size} bytes key)")
    
    print("\nOther ciphers:")
    for cipher in ["sm4"]:
        display_name, key_size = SUPPORTED_CIPHERS[cipher]
        bits = key_size * 8
        print(f"  {cipher:15} -> {display_name:20} ({bits}-bit, {key_size} bytes key)")
    
    print("\nNotes:")
    print("  • Default cipher: aes256")
    print("  • AES-256-CBC is recommended for security")
    print("  • SM4 is a Chinese standard cipher")

# =========================
# CLI MAIN FUNCTION
# =========================

def main():
    parser = argparse.ArgumentParser(
        description="Crypto Toolbox (Argon2, ChaCha20, Ed25519, Scrypt, X25519)"
    )
    sub = parser.add_subparsers(dest="tool")

    # ======================
    # Argon2
    # ======================
    arg = sub.add_parser("argon2", help="Argon2 password hashing")
    argsub = arg.add_subparsers(dest="cmd")

    a_hash = argsub.add_parser("hash", help="Hash a password")
    a_hash.add_argument("--password", help="Password to hash (optional, otherwise prompted)")

    a_ver = argsub.add_parser("verify", help="Verify password against hash")
    a_ver.add_argument("--hash", help="Argon2 hash to verify against")
    a_ver.add_argument("--password", help="Password to verify")

    # ======================
    # ChaCha20
    # ======================
    cha = sub.add_parser("chacha20", help="ChaCha20-Poly1305 encryption")
    chasub = cha.add_subparsers(dest="cmd")

    c_enc = chasub.add_parser("encrypt", help="Encrypt a file")
    c_enc.add_argument("--key", required=True, help="32-byte key in hex")
    c_enc.add_argument("--infile", required=True, help="Input file to encrypt")
    c_enc.add_argument("--aad", help="AAD as string (optional)")

    c_dec = chasub.add_parser("decrypt", help="Decrypt from stdin")
    c_dec.add_argument("--key", required=True, help="32-byte key in hex")
    c_dec.add_argument("--aad", help="AAD as string (optional)")

    # ======================
    # EdDSA
    # ======================
    ed = sub.add_parser("eddsa", help="Ed25519 signatures")
    edsub = ed.add_subparsers(dest="cmd")

    ed_gen = edsub.add_parser("gen", help="Generate key pair")
    ed_gen.add_argument("--priv", default="private.pem", help="Private key output")
    ed_gen.add_argument("--pub", default="public.pem", help="Public key output")
    ed_gen.add_argument("--cipher", default="aes256", 
                       help="Cipher algorithm (default: aes256). Use 'list' to see options")

    ed_sign = edsub.add_parser("sign", help="Sign a message")
    ed_sign.add_argument("--priv", required=True, help="Private key file")
    ed_sign.add_argument("--msg", required=True, help="Message file to sign")

    ed_ver = edsub.add_parser("verify", help="Verify a signature")
    ed_ver.add_argument("--pub", required=True, help="Public key file")
    ed_ver.add_argument("--msg", required=True, help="Message file")
    ed_ver.add_argument("--sig", required=True, help="Signature in hex to verify")

    # ======================
    # Scrypt
    # ======================
    sc = sub.add_parser("scrypt", help="Scrypt key derivation")
    scsub = sc.add_subparsers(dest="cmd")

    sc_d = scsub.add_parser("derive", help="Derive a key")
    sc_d.add_argument("--secret", help="Input secret")
    sc_d.add_argument("--salt", help="Salt as string")
    sc_d.add_argument("--iter", type=int, default=16384, help="Scrypt N parameter")
    sc_d.add_argument("--keylen", type=int, default=32, help="Derived key length (bytes)")

    sc_c = scsub.add_parser("compare", help="Re-derive and compare a key")
    sc_c.add_argument("--secret", help="Input secret")
    sc_c.add_argument("--salt", help="Salt as string")
    sc_c.add_argument("--derived", help="Derived key (hex)")
    sc_c.add_argument("--iter", type=int, default=16384, help="Scrypt N parameter")

    # ======================
    # X25519
    # ======================
    x = sub.add_parser("x25519", help="X25519 key exchange")
    xsub = x.add_subparsers(dest="cmd")

    x_gen = xsub.add_parser("gen", help="Generate key pair")
    x_gen.add_argument("--priv", default="private.pem", help="Private key output")
    x_gen.add_argument("--pub", default="public.pem", help="Public key output")
    x_gen.add_argument("--cipher", default="aes256", 
                      help="Cipher algorithm (default: aes256). Use 'list' to see options")

    x_sh = xsub.add_parser("shared", help="Compute shared key")
    x_sh.add_argument("--priv", required=True, help="Your private key")
    x_sh.add_argument("--peer", required=True, help="Peer's public key")

    # ======================
    # List ciphers
    # ======================
    list_cmd = sub.add_parser("ciphers", help="List available cipher algorithms")

    args = parser.parse_args()

    # ======================
    # Dispatcher
    # ======================
    if args.tool == "argon2":
        if args.cmd == "hash":
            argon2_hash_password(args.password)
        elif args.cmd == "verify":
            argon2_verify_password(args.hash, args.password)

    elif args.tool == "chacha20":
        if args.cmd == "encrypt":
            chacha20_encrypt_file(args.key, args.infile, args.aad)
        elif args.cmd == "decrypt":
            chacha20_decrypt_file(args.key, args.aad)

    elif args.tool == "eddsa":
        if args.cmd == "gen":
            if args.cipher.lower() == "list":
                list_ciphers()
            else:
                eddsa_generate_keys(args.priv, args.pub, args.cipher)
        elif args.cmd == "sign":
            eddsa_sign_message(args.priv, args.msg)
        elif args.cmd == "verify":
            eddsa_verify_signature(args.pub, args.msg, args.sig)

    elif args.tool == "scrypt":
        if args.cmd == "derive":
            scrypt_derive(args.secret, args.salt, args.iter, args.keylen)
        elif args.cmd == "compare":
            scrypt_compare(args.secret, args.salt, args.derived, args.iter)

    elif args.tool == "x25519":
        if args.cmd == "gen":
            if args.cipher.lower() == "list":
                list_ciphers()
            else:
                x25519_generate_keys(args.priv, args.pub, args.cipher)
        elif args.cmd == "shared":
            x25519_compute_shared(args.priv, args.peer)

    elif args.tool == "ciphers":
        list_ciphers()
        
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
