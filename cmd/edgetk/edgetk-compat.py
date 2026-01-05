#!/usr/bin/env python3
"""
EDGE Crypto Toolbox - Integrated Cryptographic Tools
Contains: Argon2, ChaCha20-Poly1305, Ed25519, Scrypt, X25519, Hashsum, HMAC, AES-GCM, SM4-GCM, Camellia-GCM, HKDF
"""

import argparse
import sys
import getpass
import os
import hashlib
import base64
import binascii
import glob
import json
from pathlib import Path
import time
import hmac as hmac_lib

try:
    import blake3
    BLAKE3_AVAILABLE = True
except ImportError:
    BLAKE3_AVAILABLE = False

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
# HKDF FUNCTIONS (RFC 5869)
# =========================

def hkdf_extract(salt, ikm, hash_algo='sha256'):
    """
    HKDF-Extract(salt, IKM) -> PRK
    
    Args:
        salt: Optional salt value (bytes or None)
        ikm: Input keying material (bytes)
        hash_algo: Hash algorithm to use (default: sha256)
    
    Returns:
        Pseudo-random key (PRK) as bytes
    """
    if salt is None:
        # If no salt provided, use hash_len zeros
        hash_len = hashlib.new(hash_algo).digest_size
        salt = b'\x00' * hash_len
    
    if isinstance(salt, str):
        salt = salt.encode('utf-8')
    if isinstance(ikm, str):
        ikm = ikm.encode('utf-8')
    
    # PRK = HMAC-Hash(salt, IKM)
    return hmac_lib.new(salt, ikm, digestmod=hash_algo).digest()

def hkdf_expand(prk, info, length, hash_algo='sha256'):
    """
    HKDF-Expand(PRK, info, L) -> OKM
    
    Args:
        prk: Pseudo-random key (bytes from extract step)
        info: Optional context and application specific info (bytes)
        length: Length of output keying material in bytes
        hash_algo: Hash algorithm to use
    
    Returns:
        Output keying material (OKM) as bytes
    """
    if isinstance(prk, str):
        prk = prk.encode('utf-8')
    if info is None:
        info = b''
    elif isinstance(info, str):
        info = info.encode('utf-8')
    
    hash_len = hashlib.new(hash_algo).digest_size
    if length > 255 * hash_len:
        raise ValueError(f"Length {length} too large for {hash_algo}")
    
    n = (length + hash_len - 1) // hash_len  # ceil(length / hash_len)
    t = b''
    okm = b''
    
    for i in range(1, n + 1):
        # T(i) = HMAC-Hash(PRK, T(i-1) | info | i)
        t = hmac_lib.new(prk, t + info + bytes([i]), digestmod=hash_algo).digest()
        okm += t
    
    return okm[:length]

def hkdf(salt, ikm, info=None, length=32, hash_algo='sha256'):
    """
    HKDF(salt, IKM, info, L) -> OKM
    
    Full HKDF implementation following RFC 5869
    
    Args:
        salt: Optional salt value (string or None)
        ikm: Input keying material (string)
        info: Optional context and application specific info (string)
        length: Desired output length in bytes
        hash_algo: Hash algorithm to use
    
    Returns:
        Output keying material as bytes
    """
    prk = hkdf_extract(salt, ikm, hash_algo)
    return hkdf_expand(prk, info, length, hash_algo)

def hkdf_calc(salt=None, ikm=None, info=None, length=32, hash_algo='sha256'):
    """
    Calculate HKDF from command line
    
    Args:
        salt: Salt value (string, default: none/zeros)
        ikm: Input keying material (string)
        info: Optional info (string)
        length: Output length in bytes
        hash_algo: Hash algorithm to use
    """
    # Get salt
    if salt is None:
        salt_input = getpass.getpass("Salt (string, empty for none): ").strip()
        salt = salt_input if salt_input else None
    else:
        salt = salt
    
    # Get IKM
    if ikm is None:
        ikm = getpass.getpass("Input Key Material (string): ").strip()
    else:
        ikm = ikm
    
    # Get info
    if info is None:
        info_input = input("Info (string, empty for none): ").strip()
        info = info_input if info_input else None
    else:
        info = info
    
    # Calculate HKDF
    try:
        okm = hkdf(salt, ikm, info, length, hash_algo)
        
        print(f"\nHKDF-{hash_algo} Results:")
        print("-" * 60)
        print(f"Salt: '{salt}'" if salt else "Salt: None (zeros)")
        print(f"IKM: '{ikm}'")
        print(f"Info: '{info}'" if info else "Info: None")
        print(f"Length: {length} bytes")
        print(f"\nOutput Key Material (OKM):")
        print(f"  Hex: {okm.hex()}")
        print(f"  Base64: {base64.b64encode(okm).decode()}")
        
        # Show in 32-byte chunks for readability
        if length > 32:
            print(f"\nChunks:")
            for i in range(0, len(okm), 32):
                chunk = okm[i:i+32]
                print(f"  [{i:3d}-{i+len(chunk)-1:3d}]: {chunk.hex()}")
        
        return okm
        
    except Exception as e:
        print(f"✖ HKDF calculation failed: {e}", file=sys.stderr)
        sys.exit(1)

def hkdf_derive(salt=None, ikm=None, info=None, length=32, hash_algo='sha256'):
    """
    Derive key using HKDF with different input methods
    """
    # Get salt
    if salt is None:
        salt_input = input("Salt (string, enter for none): ").strip()
        salt = salt_input if salt_input else None
    else:
        salt = salt
    
    # Get IKM
    if ikm is None:
        print("Input Key Material (IKM) - choose source:")
        print("  1. Enter as text")
        print("  2. Read from file")
        choice = input("Choice [1]: ").strip() or "1"
        
        if choice == "1":
            ikm = getpass.getpass("IKM text: ")
        elif choice == "2":
            file_path = input("File path: ")
            with open(file_path, 'r', encoding='utf-8') as f:
                ikm = f.read()
        else:
            print("✖ Invalid choice", file=sys.stderr)
            sys.exit(1)
    
    # Get info
    if info is None:
        info_input = input("Info (string, enter for none): ").strip()
        info = info_input if info_input else None
    else:
        info = info
    
    # Get length
    if length is None:
        try:
            length = int(input(f"Output length in bytes [32]: ").strip() or "32")
        except:
            length = 32
    
    # Calculate HKDF
    okm = hkdf(salt, ikm, info, length, hash_algo)
    
    print(f"\n✅ HKDF-{hash_algo} derived {length} bytes")
    print(f"\nOutput Key Material:")
    print(f"Hex: {okm.hex()}")
    
    # Ask if user wants to save to file
    save = input("\nSave to file? (y/N): ").strip().lower()
    if save == 'y':
        filename = input("Filename: ").strip()
        try:
            with open(filename, 'wb') as f:
                f.write(okm)
            print(f"✅ Saved to {filename}")
        except Exception as e:
            print(f"✖ Error saving file: {e}", file=sys.stderr)
    
    return okm

def hkdf_compare():
    """
    Re-derive HKDF and compare with expected value
    """
    print("HKDF Comparison")
    print("Enter parameters to re-derive and compare:")
    
    # Get parameters
    salt_input = input("Salt (string, enter for none): ").strip()
    salt = salt_input if salt_input else None
    
    ikm = getpass.getpass("IKM (string): ").strip()
    
    info_input = input("Info (string, enter for none): ").strip()
    info = info_input if info_input else None
    
    length_input = input("Output length in bytes [32]: ").strip() or "32"
    length = int(length_input)
    
    hash_algo = input("Hash algorithm [sha256]: ").strip() or "sha256"
    
    expected_hex = input("Expected output (hex): ").strip()
    expected = bytes.fromhex(expected_hex)
    
    # Re-derive
    okm = hkdf(salt, ikm, info, length, hash_algo)
    
    print(f"\nComparison:")
    print(f"  Expected: {expected.hex()}")
    print(f"  Actual:   {okm.hex()}")
    
    if okm == expected:
        print("\n✅ HKDF outputs match!")
        return True
    else:
        print("\n❌ HKDF outputs DO NOT match!")
        return False

def list_hkdf_algorithms():
    """List all available algorithms for HKDF"""
    print("Available algorithms for HKDF:")
    print("-" * 60)
    
    # Algorithms suitable for HKDF (must have HMAC support)
    hkdf_algs = [
        ('sha256', '256-bit (Recommended)', 32),
        ('sha384', '384-bit', 48),
        ('sha512', '512-bit (Strong)', 64),
        ('sha3_256', '256-bit SHA-3', 32),
        ('sha3_384', '384-bit SHA-3', 48),
        ('sha3_512', '512-bit SHA-3', 64),
        ('blake2b', 'Up to 512-bit', 64),
        ('blake2s', 'Up to 256-bit', 32),
        ('sha224', '224-bit', 28),
        ('sha1', '160-bit (WEAK)', 20),
    ]
    
    print("Algorithm       Security        Hash Length")
    print("-" * 60)
    
    for alg, security, hash_len in hkdf_algs:
        if alg in hashlib.algorithms_available:
            print(f"  {alg:12} {security:20} {hash_len:3} bytes")
    
    print("\nSecurity recommendations:")
    print("  • Use SHA-256 or SHA-512 for general purposes")
    print("  • Use SHA-3 family for post-quantum security")
    print("  • Minimum recommended output: 32 bytes (256 bits)")
    print("  • Salt should be random or pseudo-random")
    print("  • Info can be used for key separation")
    print("  • Default: sha256")

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
# 6. HASHSUM (File Hash Calculator and Verifier)
# =========================

def calculate_file_hash(file_path, hash_algo='sha256'):
    """Calculate hash of a single file with support for modern algorithms"""
    try:
        if hash_algo.startswith('blake2'):
            # BLAKE2 family
            if hash_algo == 'blake2b':
                hash_func = hashlib.blake2b()
            elif hash_algo == 'blake2s':
                hash_func = hashlib.blake2s()
            elif hash_algo == 'blake2b_256':
                hash_func = hashlib.blake2b(digest_size=32)
            elif hash_algo == 'blake2b_512':
                hash_func = hashlib.blake2b(digest_size=64)
            elif hash_algo == 'blake2s_128':
                hash_func = hashlib.blake2s(digest_size=16)
            elif hash_algo == 'blake2s_256':
                hash_func = hashlib.blake2s(digest_size=32)
            else:
                # Default BLAKE2b-512
                hash_func = hashlib.blake2b()
        
        elif hash_algo.startswith('sha3_'):
            # SHA-3 family
            if hash_algo == 'sha3_224':
                hash_func = hashlib.sha3_224()
            elif hash_algo == 'sha3_256':
                hash_func = hashlib.sha3_256()
            elif hash_algo == 'sha3_384':
                hash_func = hashlib.sha3_384()
            elif hash_algo == 'sha3_512':
                hash_func = hashlib.sha3_512()
            else:
                # Default SHA3-256
                hash_func = hashlib.sha3_256()
        
        elif hash_algo == 'blake3':
            # BLAKE3 requires the blake3 library
            if not BLAKE3_AVAILABLE:
                print(f"✖ BLAKE3 not available. Install with: pip install blake3", file=sys.stderr)
                return None
            hash_func = blake3.blake3()
        
        elif hash_algo == 'shake_128':
            # SHAKE128 - extensible output function
            hash_func = hashlib.shake_128()
        
        elif hash_algo == 'shake_256':
            # SHAKE256 - extensible output function
            hash_func = hashlib.shake_256()
        
        else:
            # Standard hashlib algorithms
            hash_func = hashlib.new(hash_algo)
        
        with open(file_path, 'rb') as f:
            # Read file in chunks to handle large files
            for chunk in iter(lambda: f.read(4096), b''):
                hash_func.update(chunk)
        
        # Handle variable-length outputs
        if hash_algo in ['shake_128', 'shake_256']:
            # SHAKE algorithms need output length specified
            return hash_func.hexdigest(32)  # 32 bytes = 256 bits
        else:
            return hash_func.hexdigest()
            
    except FileNotFoundError:
        return None
    except PermissionError:
        return None
    except ValueError as e:
        print(f"✖ Error with algorithm {hash_algo}: {e}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"✖ Error processing {file_path}: {e}", file=sys.stderr)
        return None

def list_hash_algorithms():
    """List all available hash algorithms"""
    print("Available hash algorithms:")
    print("-" * 60)
    
    # Standard algorithms
    print("Standard algorithms:")
    std_algs = ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512']
    for alg in std_algs:
        if alg in hashlib.algorithms_available:
            print(f"  {alg:15} - {hashlib.new(alg).digest_size * 8}-bit")
    
    # SHA-3 family
    print("\nSHA-3 family (Keccak):")
    sha3_algs = ['sha3_224', 'sha3_256', 'sha3_384', 'sha3_512', 
                 'shake_128', 'shake_256']
    for alg in sha3_algs:
        if alg in hashlib.algorithms_available:
            if alg.startswith('shake'):
                print(f"  {alg:15} - Variable length (extensible output)")
            else:
                print(f"  {alg:15} - {hashlib.new(alg).digest_size * 8}-bit")
    
    # BLAKE2 family
    print("\nBLAKE2 family:")
    blake2_algs = ['blake2b', 'blake2s']
    for alg in blake2_algs:
        if alg in hashlib.algorithms_available:
            print(f"  {alg:15} - {hashlib.new(alg).digest_size * 8}-bit")
    # BLAKE2 variants
    print("  blake2b_256      - 256-bit BLAKE2b")
    print("  blake2b_512      - 512-bit BLAKE2b")
    print("  blake2s_128      - 128-bit BLAKE2s")
    print("  blake2s_256      - 256-bit BLAKE2s")
    
    # BLAKE3
    if BLAKE3_AVAILABLE:
        print(f"\nBLAKE3 family:")
        print("  blake3          - 256-bit BLAKE3 (modern, fast)")
    else:
        print(f"\nBLAKE3: Install with 'pip install blake3'")
    
    print("\nOther available algorithms:")
    other_algs = sorted([alg for alg in hashlib.algorithms_available 
                        if alg not in std_algs + sha3_algs + blake2_algs])
    for alg in other_algs:
        print(f"  {alg:15}")
    
    print("\nNotes:")
    print("  • Recommended: sha256, sha3_256, blake2b, blake3")
    print("  • Avoid: md5, sha1 (cryptographically broken)")
    print("  • Default: sha256")

def hashsum(pattern, recursive=False, hash_algo='sha256', output_file=None):
    """
    Calculate hashes for files matching a pattern
    
    Args:
        pattern: File pattern (e.g., *.py, file.txt)
        recursive: Whether to process subdirectories
        hash_algo: Hash algorithm
        output_file: Optional file to save results
    """
    # Check if algorithm is available
    available_algs = list(hashlib.algorithms_available)
    # Add our custom BLAKE2 variants
    custom_algs = ['blake2b_256', 'blake2b_512', 'blake2s_128', 'blake2s_256']
    
    if hash_algo in custom_algs:
        # Custom variants are always available if base BLAKE2 is available
        if 'blake2b' not in hashlib.algorithms_available or 'blake2s' not in hashlib.algorithms_available:
            print(f"✖ BLAKE2 not available in this Python version", file=sys.stderr)
            sys.exit(1)
    elif hash_algo == 'blake3':
        if not BLAKE3_AVAILABLE:
            print(f"✖ BLAKE3 not available. Install with: pip install blake3", file=sys.stderr)
            sys.exit(1)
    elif hash_algo not in available_algs:
        print(f"✖ Unsupported hash algorithm: {hash_algo}", file=sys.stderr)
        print(f"\nUse 'hashsum list' to see available algorithms")
        sys.exit(1)
    
    results = {}
    files_found = 0
    files_processed = 0
    errors = 0
    
    print(f"Calculating {hash_algo} hashes...")
    print(f"Pattern: {pattern}")
    print(f"Recursive: {'Yes' if recursive else 'No'}")
    print("-" * 80)
    
    if recursive:
        # Use pathlib for recursive pattern matching
        base_dir = Path.cwd()
        for file_path in base_dir.rglob(pattern):
            files_found += 1
            if file_path.is_file():
                relative_path = str(file_path.relative_to(base_dir))
                file_hash = calculate_file_hash(file_path, hash_algo)
                if file_hash:
                    results[relative_path] = file_hash
                    files_processed += 1
                    print(f"{file_hash}  {relative_path}")
                else:
                    errors += 1
                    print(f"✖ ERROR: Could not process {relative_path}", file=sys.stderr)
    else:
        # Non-recursive glob
        for file_path in glob.glob(pattern):
            files_found += 1
            if os.path.isfile(file_path):
                file_hash = calculate_file_hash(file_path, hash_algo)
                if file_hash:
                    results[file_path] = file_hash
                    files_processed += 1
                    print(f"{file_hash}  {file_path}")
                else:
                    errors += 1
                    print(f"✖ ERROR: Could not process {file_path}", file=sys.stderr)
    
    # Save results to file if specified
    if output_file:
        try:
            with open(output_file, 'w') as f:
                # Include metadata
                f.write(f"# Hashsum generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"# Algorithm: {hash_algo}\n")
                f.write(f"# Pattern: {pattern}\n")
                f.write(f"# Recursive: {recursive}\n")
                f.write("#\n")
                for file_path, file_hash in sorted(results.items()):
                    # Adicionar asterisco antes do nome do arquivo como em outros hashers
                    f.write(f"{file_hash} *{file_path}\n")
            print(f"\n✔ Results saved to: {output_file}")
        except Exception as e:
            print(f"✖ Error saving results to {output_file}: {e}", file=sys.stderr)
    
    # Print summary
    print("-" * 80)
    print(f"Summary:")
    print(f"  Files found: {files_found}")
    print(f"  Files processed: {files_processed}")
    print(f"  Errors: {errors}")
    
    if files_processed == 0:
        print("⚠ No files were processed. Check your pattern or directory permissions.")
    
    return results

def check_hashsum(hash_file, check_all=False):
    """
    Verify hashes from a hash file
    
    Args:
        hash_file: File containing hashes to verify
        check_all: If True, continue checking even if some files are missing
    """
    if not os.path.exists(hash_file):
        print(f"✖ Hash file not found: {hash_file}", file=sys.stderr)
        sys.exit(1)
    
    try:
        with open(hash_file, 'r') as f:
            lines = f.readlines()
    except Exception as e:
        print(f"✖ Error reading hash file: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Parse hash file
    expected_hashes = {}
    hash_algo = 'sha256'  # default
    
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            # Extract hash algorithm from comment if available
            if line.startswith('# Algorithm:'):
                hash_algo = line.split(':')[1].strip()
            continue
        
        # Parse hash and filename
        parts = line.split()
        if len(parts) >= 2:
            # Hash is first part, filename is the rest (pode ter asterisco)
            file_hash = parts[0]
            file_path = ' '.join(parts[1:])
            
            # Remover asterisco se presente
            if file_path.startswith('*'):
                file_path = file_path[1:]
            
            expected_hashes[file_path] = file_hash
    
    if not expected_hashes:
        print("⚠ No hashes found in the file")
        return
    
    print(f"Verifying {hash_algo} hashes from: {hash_file}")
    print(f"Files to check: {len(expected_hashes)}")
    print("-" * 80)
    
    checked = 0
    passed = 0
    failed = 0
    missing = 0
    
    for file_path, expected_hash in sorted(expected_hashes.items()):
        if os.path.exists(file_path):
            current_hash = calculate_file_hash(file_path, hash_algo)
            if current_hash:
                checked += 1
                if current_hash.lower() == expected_hash.lower():
                    passed += 1
                    print(f"✔ {file_path}: OK")
                else:
                    failed += 1
                    print(f"✖ {file_path}: FAILED")
                    print(f"  Expected: {expected_hash}")
                    print(f"  Got:      {current_hash}")
            else:
                failed += 1
                print(f"✖ {file_path}: ERROR (could not read file)")
        else:
            missing += 1
            if check_all:
                print(f"✖ {file_path}: MISSING")
            else:
                print(f"✖ {file_path}: MISSING - stopping verification")
                print("Use --all to continue even if some files are missing")
                break
    
    print("-" * 80)
    print(f"Verification complete:")
    print(f"  Checked: {checked}")
    print(f"  Passed: {passed}")
    print(f"  Failed: {failed}")
    print(f"  Missing: {missing}")
    
    if failed == 0 and missing == 0:
        print("\n✔ All files verified successfully!")
        return True
    else:
        print("\n⚠ Verification failed or incomplete")
        return False

# =========================
# 7. HMAC (Hash-based Message Authentication Code)
# =========================

def generate_hmac(key, data, hash_algo='sha256'):
    """
    Generate HMAC for data using specified hash algorithm
    
    Args:
        key: Secret key (bytes or string)
        data: Data to authenticate (bytes or string)
        hash_algo: Hash algorithm to use (default: sha256)
    
    Returns:
        HMAC digest in hex
    """
    if isinstance(key, str):
        key = key.encode('utf-8')
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    # Get the hash function constructor
    try:
        # Try to get hash function from hashlib
        hash_func = getattr(hashlib, hash_algo, None)
        if hash_func is None:
            # For custom variants or SHA-3
            if hash_algo.startswith('sha3_'):
                hash_func = getattr(hashlib, hash_algo)
            elif hash_algo.startswith('blake2'):
                # For BLAKE2, we need to use hashlib.new
                hmac_obj = hmac_lib.new(key, data, digestmod=hash_algo)
                return hmac_obj.hexdigest()
            else:
                # Try to create via hashlib.new
                hmac_obj = hmac_lib.new(key, data, digestmod=hash_algo)
                return hmac_obj.hexdigest()
    except AttributeError:
        # Fall back to hashlib.new
        try:
            hmac_obj = hmac_lib.new(key, data, digestmod=hash_algo)
            return hmac_obj.hexdigest()
        except ValueError:
            raise ValueError(f"Unsupported hash algorithm for HMAC: {hash_algo}")
    
    # Create HMAC with the hash function
    hmac_obj = hmac_lib.HMAC(key, data, digestmod=hash_func)
    return hmac_obj.hexdigest()

def hmac_calc(key=None, data=None, file_path=None, hash_algo='sha256'):
    """
    Calculate HMAC for data or file
    
    Args:
        key: Secret key (prompt if not provided)
        data: String data to authenticate
        file_path: File to authenticate (takes precedence over data)
        hash_algo: Hash algorithm to use
    """
    # Get key
    if key is None:
        key = getpass.getpass("Enter secret key: ")
    
    # Get data from file or input
    if file_path:
        if not os.path.exists(file_path):
            print(f"✖ File not found: {file_path}", file=sys.stderr)
            sys.exit(1)
        try:
            with open(file_path, 'rb') as f:
                data_bytes = f.read()
            data_source = f"file: {file_path}"
        except Exception as e:
            print(f"✖ Error reading file: {e}", file=sys.stderr)
            sys.exit(1)
    elif data is None:
        print("Enter data to authenticate (Ctrl+D to finish):")
        try:
            data_lines = []
            while True:
                line = sys.stdin.readline()
                if not line:
                    break
                data_lines.append(line)
            data_bytes = ''.join(data_lines).encode('utf-8')
            data_source = "stdin input"
        except KeyboardInterrupt:
            print("\n✖ Input cancelled", file=sys.stderr)
            sys.exit(1)
    else:
        data_bytes = data.encode('utf-8') if isinstance(data, str) else data
        data_source = "provided data"
    
    # Calculate HMAC
    try:
        hmac_result = generate_hmac(key, data_bytes, hash_algo)
        
        print(f"HMAC-{hash_algo} calculation:")
        print(f"  Data source: {data_source}")
        print(f"  Key length: {len(key) if isinstance(key, bytes) else len(key.encode('utf-8'))} bytes")
        print(f"  Data length: {len(data_bytes)} bytes")
        print(f"  HMAC (hex): {hmac_result}")
        print(f"  HMAC (base64): {base64.b64encode(bytes.fromhex(hmac_result)).decode()}")
        
        return hmac_result
        
    except Exception as e:
        print(f"✖ HMAC calculation failed: {e}", file=sys.stderr)
        sys.exit(1)

def hmac_verify(key=None, hmac_value=None, data=None, file_path=None, hash_algo='sha256'):
    """
    Verify HMAC for data or file
    
    Args:
        key: Secret key (prompt if not provided)
        hmac_value: HMAC to verify (hex string)
        data: String data to verify
        file_path: File to verify (takes precedence over data)
        hash_algo: Hash algorithm used
    """
    # Get key
    if key is None:
        key = getpass.getpass("Enter secret key: ")
    
    # Get HMAC value
    if hmac_value is None:
        hmac_value = input("Enter HMAC to verify (hex): ").strip()
    
    # Get data from file or input
    if file_path:
        if not os.path.exists(file_path):
            print(f"✖ File not found: {file_path}", file=sys.stderr)
            sys.exit(1)
        try:
            with open(file_path, 'rb') as f:
                data_bytes = f.read()
            data_source = f"file: {file_path}"
        except Exception as e:
            print(f"✖ Error reading file: {e}", file=sys.stderr)
            sys.exit(1)
    elif data is None:
        print("Enter data to verify (Ctrl+D to finish):")
        try:
            data_lines = []
            while True:
                line = sys.stdin.readline()
                if not line:
                    break
                data_lines.append(line)
            data_bytes = ''.join(data_lines).encode('utf-8')
            data_source = "stdin input"
        except KeyboardInterrupt:
            print("\n✖ Input cancelled", file=sys.stderr)
            sys.exit(1)
    else:
        data_bytes = data.encode('utf-8') if isinstance(data, str) else data
        data_source = "provided data"
    
    # Calculate HMAC for comparison
    try:
        calculated_hmac = generate_hmac(key, data_bytes, hash_algo)
        
        print(f"HMAC-{hash_algo} verification:")
        print(f"  Data source: {data_source}")
        print(f"  Provided HMAC: {hmac_value}")
        print(f"  Calculated HMAC: {calculated_hmac}")
        
        # Compare using constant-time comparison to prevent timing attacks
        if hmac_lib.compare_digest(calculated_hmac.lower(), hmac_value.lower()):
            print("\n✔ HMAC verification successful! The data is authentic.")
            return True
        else:
            print("\n✖ HMAC verification FAILED! The data has been tampered with or the key is wrong.")
            return False
            
    except Exception as e:
        print(f"✖ HMAC verification failed: {e}", file=sys.stderr)
        sys.exit(1)

def list_hmac_algorithms():
    """List all available algorithms for HMAC"""
    print("Available algorithms for HMAC:")
    print("-" * 60)
    
    # Algorithms commonly used with HMAC
    hmac_algs = [
        ('md5', '64-bit (INSECURE, for legacy only)'),
        ('sha1', '80-bit (WEAK, not recommended)'),
        ('sha224', '112-bit'),
        ('sha256', '128-bit (Recommended)'),
        ('sha384', '192-bit'),
        ('sha512', '256-bit (Strong)'),
        ('sha3_224', '112-bit SHA-3'),
        ('sha3_256', '128-bit SHA-3'),
        ('sha3_384', '192-bit SHA-3'),
        ('sha3_512', '256-bit SHA-3'),
        ('blake2b', 'Variable (256-512 bit)'),
        ('blake2s', 'Variable (128-256 bit)'),
    ]
    
    for alg, security in hmac_algs:
        if hasattr(hashlib, alg) or alg in hashlib.algorithms_available:
            print(f"  {alg:15} - {security}")
    
    print("\nAdditional algorithms available via hashlib.new():")
    other_algs = sorted([alg for alg in hashlib.algorithms_available 
                        if alg not in [a[0] for a in hmac_algs]])
    for alg in other_algs[:10]:  # Show first 10
        print(f"  {alg:15}")
    
    if len(other_algs) > 10:
        print(f"  ... and {len(other_algs) - 10} more")
    
    print("\nSecurity recommendations:")
    print("  • Use SHA-256 or SHA-512 for general purposes")
    print("  • Use SHA-3 family for post-quantum security")
    print("  • Use BLAKE2 for high performance")
    print("  • AVOID: MD5, SHA-1 (cryptographically broken)")
    print("  • Key should be at least as long as the hash output")
    print("  • Default: sha256")

# =========================
# 8. AEAD ENCRYPTION (AES-GCM, SM4-GCM, Camellia-GCM)
# =========================

def gcm_encrypt_file(cipher_algo, key_hex, infile, aad_str=None):
    """
    Encrypt file using AES-GCM, SM4-GCM or Camellia-GCM
    
    Args:
        cipher_algo: Algorithm to use ('aes', 'sm4', or 'camellia')
        key_hex: Key in hex format (length depends on algorithm)
        infile: Input file to encrypt
        aad_str: Additional authenticated data (optional)
    """
    # Validate and normalize algorithm
    cipher_algo = cipher_algo.lower()
    
    # Determine key length based on algorithm
    if cipher_algo == 'aes':
        # AES supports 128, 192, 256 bits (16, 24, 32 bytes)
        key = bytes.fromhex(key_hex)
        if len(key) not in [16, 24, 32]:
            print(f"✖ AES key must be 16, 24, or 32 bytes (got {len(key)} bytes)", file=sys.stderr)
            sys.exit(1)
        algorithm = algorithms.AES(key)
        
    elif cipher_algo == 'sm4':
        # SM4 uses 128-bit key (16 bytes)
        key = bytes.fromhex(key_hex)
        if len(key) != 16:
            print(f"✖ SM4 key must be 16 bytes (128 bits), got {len(key)} bytes", file=sys.stderr)
            sys.exit(1)
        try:
            from cryptography.hazmat.primitives.ciphers.algorithms import SM4
            algorithm = SM4(key)
        except ImportError:
            print("✖ SM4 not supported in this cryptography version", file=sys.stderr)
            sys.exit(1)
            
    elif cipher_algo == 'camellia':
        # Camellia supports 128, 192, 256 bits (16, 24, 32 bytes)
        key = bytes.fromhex(key_hex)
        if len(key) not in [16, 24, 32]:
            print(f"✖ Camellia key must be 16, 24, or 32 bytes (got {len(key)} bytes)", file=sys.stderr)
            sys.exit(1)
        try:
            from cryptography.hazmat.primitives.ciphers.algorithms import Camellia
            algorithm = Camellia(key)
        except ImportError:
            print("✖ Camellia not supported in this cryptography version", file=sys.stderr)
            sys.exit(1)
            
    else:
        print(f"✖ Unsupported algorithm: {cipher_algo}. Use 'aes', 'sm4', or 'camellia'", file=sys.stderr)
        sys.exit(1)
    
    # Generate random nonce (12 bytes recommended for GCM)
    nonce = os.urandom(12)
    
    # Prepare AAD if provided
    aad = aad_str.encode() if aad_str else None
    
    # Read input file
    with open(infile, "rb") as f:
        plaintext = f.read()
    
    # Create cipher and encrypt
    cipher = Cipher(algorithm, modes.GCM(nonce))
    encryptor = cipher.encryptor()
    
    # Update AAD if provided
    if aad:
        encryptor.authenticate_additional_data(aad)
    
    # Encrypt data
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    
    # Get authentication tag
    tag = encryptor.tag
    
    # Write nonce + ciphertext + tag to stdout
    # Format: nonce (12 bytes) + ciphertext + tag (16 bytes)
    sys.stdout.buffer.write(nonce + ciphertext + tag)
    
    # Also print info to stderr for user feedback
    print(f"✔ {cipher_algo.upper()}-GCM encryption complete", file=sys.stderr)
    print(f"  Key size: {len(key) * 8} bits", file=sys.stderr)
    print(f"  Nonce size: {len(nonce) * 8} bits", file=sys.stderr)
    print(f"  Tag size: {len(tag) * 8} bits", file=sys.stderr)
    print(f"  Input size: {len(plaintext)} bytes", file=sys.stderr)
    print(f"  Output size: {len(nonce) + len(ciphertext) + len(tag)} bytes", file=sys.stderr)
    if aad:
        print(f"  AAD size: {len(aad)} bytes", file=sys.stderr)

def gcm_decrypt_file(cipher_algo, key_hex, aad_str=None):
    """
    Decrypt from stdin using AES-GCM, SM4-GCM or Camellia-GCM
    
    Args:
        cipher_algo: Algorithm to use ('aes', 'sm4', or 'camellia')
        key_hex: Key in hex format (length depends on algorithm)
        aad_str: Additional authenticated data (optional)
    """
    # Validate and normalize algorithm
    cipher_algo = cipher_algo.lower()
    
    # Determine key based on algorithm
    if cipher_algo == 'aes':
        key = bytes.fromhex(key_hex)
        if len(key) not in [16, 24, 32]:
            print(f"✖ AES key must be 16, 24, or 32 bytes (got {len(key)} bytes)", file=sys.stderr)
            sys.exit(1)
        algorithm = algorithms.AES(key)
        
    elif cipher_algo == 'sm4':
        key = bytes.fromhex(key_hex)
        if len(key) != 16:
            print(f"✖ SM4 key must be 16 bytes (128 bits), got {len(key)} bytes", file=sys.stderr)
            sys.exit(1)
        try:
            from cryptography.hazmat.primitives.ciphers.algorithms import SM4
            algorithm = SM4(key)
        except ImportError:
            print("✖ SM4 not supported in this cryptography version", file=sys.stderr)
            sys.exit(1)
            
    elif cipher_algo == 'camellia':
        key = bytes.fromhex(key_hex)
        if len(key) not in [16, 24, 32]:
            print(f"✖ Camellia key must be 16, 24, or 32 bytes (got {len(key)} bytes)", file=sys.stderr)
            sys.exit(1)
        try:
            from cryptography.hazmat.primitives.ciphers.algorithms import Camellia
            algorithm = Camellia(key)
        except ImportError:
            print("✖ Camellia not supported in this cryptography version", file=sys.stderr)
            sys.exit(1)
            
    else:
        print(f"✖ Unsupported algorithm: {cipher_algo}. Use 'aes', 'sm4', or 'camellia'", file=sys.stderr)
        sys.exit(1)
    
    # Prepare AAD if provided
    aad = aad_str.encode() if aad_str else None
    
    # Read encrypted data from stdin
    data = sys.stdin.buffer.read()
    
    # Minimum size: nonce (12) + tag (16) = 28 bytes
    if len(data) < 28:
        print("✖ Invalid input, too short", file=sys.stderr)
        sys.exit(1)
    
    # Extract nonce (first 12 bytes), tag (last 16 bytes), ciphertext (middle)
    nonce = data[:12]
    tag = data[-16:]
    ciphertext = data[12:-16]
    
    # Create cipher and decrypt
    cipher = Cipher(algorithm, modes.GCM(nonce, tag))
    decryptor = cipher.decryptor()
    
    # Update AAD if provided
    if aad:
        decryptor.authenticate_additional_data(aad)
    
    try:
        # Decrypt data
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Write plaintext to stdout
        sys.stdout.buffer.write(plaintext)
        
        # Print success message to stderr
        print(f"✔ {cipher_algo.upper()}-GCM decryption successful", file=sys.stderr)
        print(f"  Decrypted size: {len(plaintext)} bytes", file=sys.stderr)
        
    except Exception as e:
        print(f"✖ Decryption failed: {e}", file=sys.stderr)
        print("  Possible causes:", file=sys.stderr)
        print("  • Incorrect key", file=sys.stderr)
        print("  • Incorrect AAD", file=sys.stderr)
        print("  • Corrupted or tampered data", file=sys.stderr)
        sys.exit(1)

def list_gcm_algorithms():
    """List all available GCM algorithms"""
    print("Available GCM algorithms:")
    print("-" * 50)
    
    print("AES-GCM (Recommended):")
    print("  aes-128-gcm     - 128-bit key, 12-byte nonce")
    print("  aes-192-gcm     - 192-bit key, 12-byte nonce")
    print("  aes-256-gcm     - 256-bit key, 12-byte nonce (Default)")
    
    print("\nCamellia-GCM:")
    print("  camellia-128-gcm - 128-bit key, 12-byte nonce")
    print("  camellia-192-gcm - 192-bit key, 12-byte nonce")
    print("  camellia-256-gcm - 256-bit key, 12-byte nonce")
    
    print("\nSM4-GCM (Chinese standard):")
    print("  sm4-gcm         - 128-bit key, 12-byte nonce")
    
    print("\nNotes:")
    print("  • GCM provides both confidentiality and authentication")
    print("  • Nonce should be unique for each encryption with the same key")
    print("  • Default nonce size: 12 bytes (96 bits)")
    print("  • Tag size: 16 bytes (128 bits)")
    print("  • AAD (Additional Authenticated Data) is optional")
    print("  • Recommended: AES-256-GCM")

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
        description="Crypto Toolbox (Argon2, ChaCha20, Ed25519, Scrypt, X25519, Hashsum, HMAC, GCM, HKDF)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # HKDF - calculate
  python %(prog)s hkdf calc --salt "my salt" --ikm "input key" --info "context" --length 32
  python %(prog)s hkdf derive  # interactive mode
  python %(prog)s hkdf compare  # verify derivation
  python %(prog)s hkdf list     # list available algorithms
  
  # GCM - AES-GCM encryption
  python %(prog)s gcm encrypt --algo aes --key $(openssl rand -hex 32) --infile secret.txt
  python %(prog)s gcm encrypt --algo aes --key $(openssl rand -hex 32) --infile secret.txt --aad "metadata"
  
  # GCM - AES-GCM decryption
  cat encrypted.bin | python %(prog)s gcm decrypt --algo aes --key $(openssl rand -hex 32)
  cat encrypted.bin | python %(prog)s gcm decrypt --algo aes --key $(openssl rand -hex 32) --aad "metadata"
  
  # GCM - SM4-GCM encryption
  python %(prog)s gcm encrypt --algo sm4 --key $(openssl rand -hex 16) --infile secret.txt
  
  # GCM - Camellia-GCM encryption
  python %(prog)s gcm encrypt --algo camellia --key $(openssl rand -hex 32) --infile secret.txt
  
  # GCM - list algorithms
  python %(prog)s gcm list
  
  # HMAC - calculate
  python %(prog)s hmac calc --key "secret" --data "message"
  python %(prog)s hmac calc --key "secret" --file message.txt
  
  # HMAC - list algorithms
  python %(prog)s hmac list
  
  # Hashsum - calculate hashes
  python %(prog)s hashsum calc "*.py"
  python %(prog)s hashsum calc "*.py" -r -a sha3_256 -o hashes.txt
  
  # Hashsum - list available algorithms
  python %(prog)s hashsum list
  
  # Hashsum - verify hashes
  python %(prog)s hashsum check hashes.txt
  
  # Argon2 password hashing
  python %(prog)s argon2 hash
  python %(prog)s argon2 verify --hash "$HASH"
  
  # ChaCha20 encryption
  python %(prog)s chacha20 encrypt --key $(openssl rand -hex 32) --infile secret.txt
  cat encrypted.bin | python %(prog)s chacha20 decrypt --key $(openssl rand -hex 32)
  
  # Ed25519 signatures
  python %(prog)s eddsa gen --priv private.pem --pub public.pem
  python %(prog)s eddsa sign --priv private.pem --msg message.txt
  python %(prog)s eddsa verify --pub public.pem --msg message.txt --sig SIGNATURE_HEX
  
  # Scrypt key derivation
  python %(prog)s scrypt derive
  python %(prog)s scrypt compare --derived DERIVED_HEX
  
  # X25519 key exchange
  python %(prog)s x25519 gen --priv alice_priv.pem --pub alice_pub.pem
  python %(prog)s x25519 shared --priv alice_priv.pem --peer bob_pub.pem
  
  # List available ciphers
  python %(prog)s ciphers
        """
    )
    
    sub = parser.add_subparsers(dest="tool", title="Available tools")

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
    # Hashsum
    # ======================
    hs = sub.add_parser("hashsum", help="Calculate and verify file hashes")
    hssub = hs.add_subparsers(dest="cmd")

    hs_calc = hssub.add_parser("calc", help="Calculate hashes for files")
    hs_calc.add_argument("pattern", nargs='?', default="*", 
                        help="File pattern (e.g., '*.py', 'file.txt'). Default: '*' (all files)")
    
    # Para capturar todos os argumentos restantes quando o shell expande
    hs_calc.add_argument("files", nargs='*', 
                        help="Files to process (when shell expands pattern)")
    
    hs_calc.add_argument("-r", "--recursive", action="store_true", 
                        help="Process subdirectories recursively")
    hs_calc.add_argument("-a", "--algorithm", default="sha256",
                        help="Hash algorithm (default: sha256). Use 'list' to see all options")
    hs_calc.add_argument("-o", "--output", help="Save hashes to file")
    
    hs_check = hssub.add_parser("check", help="Verify hashes from a file")
    hs_check.add_argument("hash_file", help="File containing hashes to verify")
    hs_check.add_argument("--all", action="store_true", 
                         help="Continue even if some files are missing")
    
    hs_list = hssub.add_parser("list", help="List all available hash algorithms")

    # ======================
    # HMAC
    # ======================
    hm = sub.add_parser("hmac", help="HMAC (Hash-based Message Authentication Code)")
    hmsub = hm.add_subparsers(dest="cmd")

    hm_calc = hmsub.add_parser("calc", help="Calculate HMAC")
    hm_calc.add_argument("--key", help="Secret key (optional, will prompt if not provided)")
    hm_calc.add_argument("--data", help="Data to authenticate (string)")
    hm_calc.add_argument("--file", help="File to authenticate (takes precedence over --data)")
    hm_calc.add_argument("--algo", default="sha256",
                        help="Hash algorithm (default: sha256). Use 'list' to see options")

    hm_ver = hmsub.add_parser("verify", help="Verify HMAC")
    hm_ver.add_argument("--key", help="Secret key (optional, will prompt if not provided)")
    hm_ver.add_argument("--hmac", required=True, help="HMAC to verify (hex string)")
    hm_ver.add_argument("--data", help="Data to verify (string)")
    hm_ver.add_argument("--file", help="File to verify (takes precedence over --data)")
    hm_ver.add_argument("--algo", default="sha256",
                       help="Hash algorithm (default: sha256)")

    hm_list = hmsub.add_parser("list", help="List all available HMAC algorithms")

    # ======================
    # GCM (AEAD Encryption)
    # ======================
    gcm = sub.add_parser("gcm", help="GCM encryption (AES-GCM, SM4-GCM, Camellia-GCM)")
    gcmsub = gcm.add_subparsers(dest="cmd")

    gcm_enc = gcmsub.add_parser("encrypt", help="Encrypt a file with GCM")
    gcm_enc.add_argument("--algo", required=True, choices=['aes', 'sm4', 'camellia'],
                        help="Algorithm to use: aes, sm4, or camellia")
    gcm_enc.add_argument("--key", required=True, 
                        help="Key in hex (16 bytes for AES-128/SM4, 24 for AES-192, 32 for AES-256/Camellia-256)")
    gcm_enc.add_argument("--infile", required=True, help="Input file to encrypt")
    gcm_enc.add_argument("--aad", help="AAD as string (optional)")

    gcm_dec = gcmsub.add_parser("decrypt", help="Decrypt from stdin with GCM")
    gcm_dec.add_argument("--algo", required=True, choices=['aes', 'sm4', 'camellia'],
                        help="Algorithm to use: aes, sm4, or camellia")
    gcm_dec.add_argument("--key", required=True, 
                        help="Key in hex (16 bytes for AES-128/SM4, 24 for AES-192, 32 for AES-256/Camellia-256)")
    gcm_dec.add_argument("--aad", help="AAD as string (optional)")

    gcm_list = gcmsub.add_parser("list", help="List all available GCM algorithms")

    # ======================
    # HKDF (Key Derivation)
    # ======================
    hk = sub.add_parser("hkdf", help="HKDF key derivation (RFC 5869)")
    hksub = hk.add_subparsers(dest="cmd", required=True)
    
    hk_calc = hksub.add_parser("calc", help="Calculate HKDF")
    hk_calc.add_argument("--salt", help="Salt (string)")
    hk_calc.add_argument("--ikm", help="Input Key Material (string)")
    hk_calc.add_argument("--info", help="Context info (string)")
    hk_calc.add_argument("--length", type=int, default=32, help="Output length in bytes")
    hk_calc.add_argument("--algo", default="sha256", help="Hash algorithm")
    
    hk_derive = hksub.add_parser("derive", help="Derive key with HKDF (interactive)")
    hk_derive.add_argument("--salt", help="Salt (string)")
    hk_derive.add_argument("--ikm", help="Input Key Material (string)")
    hk_derive.add_argument("--info", help="Context info (string)")
    hk_derive.add_argument("--length", type=int, default=32, help="Output length in bytes")
    hk_derive.add_argument("--algo", default="sha256", help="Hash algorithm")
    
    hk_compare = hksub.add_parser("compare", help="Compare HKDF output")
    
    hk_list = hksub.add_parser("list", help="List HKDF algorithms")

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

    elif args.tool == "hashsum":
        if args.cmd == "calc":
            # Determinar se estamos processando um padrão ou arquivos específicos
            if args.files:
                # Se temos arquivos específicos (shell expandiu o padrão)
                _hashsum_list(args.files, args.recursive, args.algorithm, args.output)
            else:
                # Usar padrão
                hashsum(args.pattern, args.recursive, args.algorithm, args.output)
        elif args.cmd == "check":
            check_hashsum(args.hash_file, args.all)
        elif args.cmd == "list":
            list_hash_algorithms()

    elif args.tool == "hmac":
        if args.cmd == "calc":
            hmac_calc(args.key, args.data, args.file, args.algo)
        elif args.cmd == "verify":
            hmac_verify(args.key, args.hmac, args.data, args.file, args.algo)
        elif args.cmd == "list":
            list_hmac_algorithms()

    elif args.tool == "gcm":
        if args.cmd == "encrypt":
            gcm_encrypt_file(args.algo, args.key, args.infile, args.aad)
        elif args.cmd == "decrypt":
            gcm_decrypt_file(args.algo, args.key, args.aad)
        elif args.cmd == "list":
            list_gcm_algorithms()

    elif args.tool == "hkdf":
        if args.cmd == "calc":
            hkdf_calc(args.salt, args.ikm, args.info, args.length, args.algo)
        elif args.cmd == "derive":
            hkdf_derive(args.salt, args.ikm, args.info, args.length, args.algo)
        elif args.cmd == "compare":
            hkdf_compare()
        elif args.cmd == "list":
            list_hkdf_algorithms()

    elif args.tool == "ciphers":
        list_ciphers()
        
    else:
        parser.print_help()

def _hashsum_list(file_list, recursive=False, hash_algo='sha256', output_file=None):
    """
    Versão alternativa do hashsum que aceita uma lista de arquivos
    em vez de um padrão (para lidar com expansão do shell)
    """
    # Check algorithm availability (simplified check)
    if hash_algo == 'blake3' and not BLAKE3_AVAILABLE:
        print(f"✖ BLAKE3 not available. Install with: pip install blake3", file=sys.stderr)
        sys.exit(1)
    
    results = {}
    files_found = len(file_list)
    files_processed = 0
    errors = 0
    
    print(f"Calculating {hash_algo} hashes...")
    print(f"Processing {files_found} files")
    print(f"Recursive: {'Yes' if recursive else 'No'}")
    print("-" * 80)
    
    for file_path in file_list:
        if os.path.isfile(file_path):
            file_hash = calculate_file_hash(file_path, hash_algo)
            if file_hash:
                results[file_path] = file_hash
                files_processed += 1
                print(f"{file_hash}  {file_path}")
            else:
                errors += 1
                print(f"✖ ERROR: Could not process {file_path}", file=sys.stderr)
        elif recursive and os.path.isdir(file_path):
            # Se for diretório e recursivo estiver habilitado
            for root, dirs, files in os.walk(file_path):
                for file in files:
                    full_path = os.path.join(root, file)
                    file_hash = calculate_file_hash(full_path, hash_algo)
                    if file_hash:
                        results[full_path] = file_hash
                        files_processed += 1
                        print(f"{file_hash}  {full_path}")
                    else:
                        errors += 1
                        print(f"✖ ERROR: Could not process {full_path}", file=sys.stderr)
        else:
            errors += 1
            print(f"✖ ERROR: Not a file {file_path}", file=sys.stderr)
    
    # Save results to file if specified
    if output_file:
        try:
            with open(output_file, 'w') as f:
                # Include metadata
                f.write(f"# Hashsum generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"# Algorithm: {hash_algo}\n")
                f.write(f"# Files processed: {files_found}\n")
                f.write(f"# Recursive: {recursive}\n")
                f.write("#\n")
                for file_path, file_hash in sorted(results.items()):
                    # Adicionar asterisco antes do nome do arquivo como em outros hashers
                    f.write(f"{file_hash} *{file_path}\n")
            print(f"\n✔ Results saved to: {output_file}")
        except Exception as e:
            print(f"✖ Error saving results to {output_file}: {e}", file=sys.stderr)
    
    # Print summary
    print("-" * 80)
    print(f"Summary:")
    print(f"  Files provided: {files_found}")
    print(f"  Files processed: {files_processed}")
    print(f"  Errors: {errors}")
    
    if files_processed == 0:
        print("⚠ No files were processed. Check file paths and permissions.")

if __name__ == "__main__":
    main()
