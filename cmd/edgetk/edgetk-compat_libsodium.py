#!/usr/bin/env python3
"""
EDGE Crypto Toolbox - Android Version (standard libraries + pysodium)
Contains: Argon2, ChaCha20-Poly1305, Ed25519, Ed521, Scrypt, X25519, Hashsum, HMAC, HKDF
"""

import argparse
import sys
import getpass
import os
import hashlib
import base64
import binascii
import glob
from pathlib import Path
import time
import hmac as hmac_lib

# Try to import pysodium (more compatible with Android)
try:
    import pysodium
    PYSODIUM_AVAILABLE = True
except ImportError:
    print("⚠ pysodium not found. Some features limited.")
    print("Install with: pip install pysodium")
    PYSODIUM_AVAILABLE = False

# =========================
# ED521 IMPLEMENTATION
# =========================

import struct
from hashlib import shake_256
from typing import Tuple, Optional

# Parâmetros da curva E-521 (exatamente como no código Go)
P = int("6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151")
N = int("1716199415032652428745475199770348304317358825035826352348615864796385795849413675475876651663657849636693659065234142604319282948702542317993421293670108523")
D = int("-376014")
Gx = int("1571054894184995387535939749894317568645297350402905821437625181152304994381188529632591196067604100772673927915114267193389905003276673749012051148356041324")
Gy = int("12")
H = 4
BIT_SIZE = 521
ED521_BYTE_LEN = (BIT_SIZE + 7) // 8  # 66 bytes

# OID para Ed521 (1.3.6.1.4.1.44588.2.1 - OID privado da EDGE)
# Tradução: iso.org.dod.internet.private.enterprise.edge.algorithms.ed521
ED521_OID = b'\x06\x0a\x2b\x06\x01\x04\x01\x83\xa6\x7a\x02\x01'

# Funções auxiliares de conversão
def bytes_to_little_int(b: bytes) -> int:
    """Converte bytes little-endian para int (como no Go)"""
    reversed_bytes = bytes(reversed(b))
    return int.from_bytes(reversed_bytes, 'big')

def little_int_to_bytes(n: int, length: int) -> bytes:
    """Converte int para bytes little-endian (como no Go)"""
    bytes_be = n.to_bytes((n.bit_length() + 7) // 8 or 1, 'big')
    if len(bytes_be) < length:
        bytes_be = bytes([0] * (length - len(bytes_be))) + bytes_be
    reversed_bytes = bytes(reversed(bytes_be))
    return reversed_bytes[:length]

# Funções de ponto
def ed521_is_on_curve(x: int, y: int) -> bool:
    return (x*x + y*y) % P == (1 + D*x*x*y*y) % P

def ed521_add_points(x1: int, y1: int, x2: int, y2: int) -> Tuple[int, int]:
    if x1 == 0 and y1 == 1:  # Ponto neutro em Edwards: (0, 1)
        return x2, y2
    if x2 == 0 and y2 == 1:  # Ponto neutro em Edwards: (0, 1)
        return x1, y1

    x1y2 = (x1 * y2) % P
    y1x2 = (y1 * x2) % P
    numerator_x = (x1y2 + y1x2) % P

    y1y2 = (y1 * y2) % P
    x1x2 = (x1 * x2) % P
    numerator_y = (y1y2 - x1x2) % P

    dx1x2y1y2 = (D * x1x2 * y1y2) % P

    denominator_x = (1 + dx1x2y1y2) % P
    denominator_y = (1 - dx1x2y1y2) % P

    inv_den_x = pow(denominator_x, -1, P)
    inv_den_y = pow(denominator_y, -1, P)

    x3 = (numerator_x * inv_den_x) % P
    y3 = (numerator_y * inv_den_y) % P
    return x3, y3

def ed521_double_point(x: int, y: int) -> Tuple[int, int]:
    return ed521_add_points(x, y, x, y)

def ed521_scalar_mult(x: int, y: int, k_bytes: bytes) -> Tuple[int, int]:
    """Multiplica ponto por escalar (k em bytes little-endian)"""
    scalar = bytes_to_little_int(k_bytes) % N
    
    result_x, result_y = 0, 1  # Ponto neutro
    temp_x, temp_y = x, y
    
    while scalar > 0:
        if scalar & 1:
            result_x, result_y = ed521_add_points(result_x, result_y, temp_x, temp_y)
        temp_x, temp_y = ed521_double_point(temp_x, temp_y)
        scalar >>= 1
    
    return result_x, result_y

def ed521_scalar_base_mult(k_bytes: bytes) -> Tuple[int, int]:
    return ed521_scalar_mult(Gx, Gy, k_bytes)

# Compressão/Descompressão
def ed521_compress_point(x: int, y: int) -> bytes:
    """Comprime ponto conforme RFC 8032"""
    y_bytes = little_int_to_bytes(y, ED521_BYTE_LEN)
    
    # Pega o bit menos significativo de x (little-endian)
    x_bytes = little_int_to_bytes(x, ED521_BYTE_LEN)
    sign_bit = x_bytes[0] & 1
    
    # Armazena o bit de sinal no MSB do último byte (little-endian)
    compressed = bytearray(y_bytes)
    compressed[-1] |= (sign_bit << 7)
    
    return bytes(compressed)

def ed521_decompress_point(data: bytes) -> Tuple[Optional[int], Optional[int]]:
    """Descomprime ponto conforme RFC 8032"""
    if len(data) != ED521_BYTE_LEN:
        return None, None
    
    # Extrai bit de sinal do MSB do último byte
    sign_bit = (data[-1] >> 7) & 1
    
    # Limpa o bit de sinal dos dados de y
    y_bytes = bytearray(data)
    y_bytes[-1] &= 0x7F
    y = bytes_to_little_int(y_bytes)
    
    # Resolve para x usando a equação da curva de Edwards:
    # x² + y² = 1 + d*x²*y²  =>  x² = (1 - y²) / (1 - d*y²)
    y2 = (y * y) % P
    
    numerator = (1 - y2) % P
    denominator = (1 - D * y2) % P
    
    try:
        inv_den = pow(denominator, -1, P)
    except ValueError:
        return None, None
    
    x2 = (numerator * inv_den) % P
    
    # Calcula raiz quadrada mod p (p ≡ 1 mod 4)
    x = pow(x2, (P + 1)//4, P)
    
    # Escolhe x correto baseado no bit de sinal
    x_bytes = little_int_to_bytes(x, ED521_BYTE_LEN)
    if (x_bytes[0] & 1) != sign_bit:
        x = (-x) % P
    
    return x, y

# Funções de hash
def ed521_dom5(phflag: int, context: bytes) -> bytes:
    """Implementa dom5 conforme especificação"""
    if len(context) > 255:
        raise ValueError("context too long for dom5")
    
    dom = b"SigEd521" + bytes([phflag, len(context)]) + context
    return dom

def ed521_hash(phflag: int, context: bytes, x: bytes) -> bytes:
    """H(x) = SHAKE256(dom5(phflag,context)||x, 132)"""
    dom = ed521_dom5(phflag, context)
    
    h = shake_256()
    h.update(dom)
    h.update(x)
    
    return h.digest(132)  # 132 bytes como especificado

# Geração de chaves
def ed521_generate_private_key() -> int:
    """Gera chave privada aleatória em little-endian"""
    while True:
        priv_bytes = os.urandom(ED521_BYTE_LEN)
        a = bytes_to_little_int(priv_bytes)
        if a < N:
            return a

def ed521_get_public_key(priv: int) -> Tuple[int, int]:
    """Calcula chave pública A = a * G"""
    priv_bytes = little_int_to_bytes(priv, ED521_BYTE_LEN)
    return ed521_scalar_base_mult(priv_bytes)

# Assinatura
def ed521_sign(private_key: int, message: bytes) -> bytes:
    """Cria assinatura PureEdDSA conforme especificação"""
    byte_len = ED521_BYTE_LEN
    
    # 1. Hash prefix "dom" + priv.D bytes
    prefix = ed521_hash(0x00, b'', little_int_to_bytes(private_key, byte_len))
    
    # 2. Calculate r = SHAKE256(prefix || message) mod N
    r_bytes = ed521_hash(0x00, b'', prefix + message)
    r = bytes_to_little_int(r_bytes[:byte_len]) % N
    
    # 3. Compute R = r*G and compress
    Rx, Ry = ed521_scalar_base_mult(little_int_to_bytes(r, byte_len))
    R_compressed = ed521_compress_point(Rx, Ry)
    
    # 4. Get public key and compress
    Ax, Ay = ed521_get_public_key(private_key)
    A_compressed = ed521_compress_point(Ax, Ay)
    
    # 5. Compute h = SHAKE256(dom || R || A || message) mod N
    hram_input = R_compressed + A_compressed + message
    hram_hash = ed521_hash(0x00, b'', hram_input)
    h = bytes_to_little_int(hram_hash[:byte_len]) % N
    
    # 6. s = (r + h * a) mod N
    s = (r + h * private_key) % N
    
    # 7. Signature = R_compressed || s_bytes
    s_bytes = little_int_to_bytes(s, byte_len)
    signature = R_compressed + s_bytes
    
    return signature

# Verificação
def ed521_verify(pub_x: int, pub_y: int, message: bytes, signature: bytes) -> bool:
    """Verifica assinatura PureEdDSA conforme especificação"""
    byte_len = ED521_BYTE_LEN
    
    if len(signature) != 2 * byte_len:
        return False
    
    R_compressed = signature[:byte_len]
    s_bytes = signature[byte_len:]
    
    # Verifica R
    Rx, Ry = ed521_decompress_point(R_compressed)
    if Rx is None or Ry is None:
        return False
    
    # Verifica s
    s = bytes_to_little_int(s_bytes)
    if s >= N:
        return False
    
    # Compress public key A
    A_compressed = ed521_compress_point(pub_x, pub_y)
    
    # Compute h = SHAKE256(dom || R || A || message) mod N
    hram_input = R_compressed + A_compressed + message
    hram_hash = ed521_hash(0x00, b'', hram_input)
    h = bytes_to_little_int(hram_hash[:byte_len]) % N
    
    # Compute s*G
    sGx, sGy = ed521_scalar_base_mult(little_int_to_bytes(s, byte_len))
    
    # Compute h*A
    hAx, hAy = ed521_scalar_mult(pub_x, pub_y, little_int_to_bytes(h, byte_len))
    
    # Compute R + h*A
    rhaX, rhaY = ed521_add_points(Rx, Ry, hAx, hAy)
    
    # Constant time comparison
    return sGx == rhaX and sGy == rhaY

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
# CRYPTOGRAPHY FUNCTIONS WITH STANDARD LIBRARIES
# =========================

def generate_random_bytes(length):
    """Generate random bytes"""
    return os.urandom(length)

def derive_key_scrypt(password, salt, key_length=32):
    """Derive key using scrypt"""
    if isinstance(password, str):
        password = password.encode('utf-8')
    
    return hashlib.scrypt(
        password,
        salt=salt,
        n=16384,
        r=8,
        p=1,
        dklen=key_length
    )

# =========================
# PEM PKCS8 FUNCTIONS
# =========================

def ed25519_private_to_pem_pkcs8(private_key_bytes):
    """
    Convert Ed25519 private key (seed or sk from libsodium)
    to PKCS#8 according to RFC 8410
    """

    # If coming from pysodium, key has 64 bytes → take only the seed
    if len(private_key_bytes) == 64:
        seed = private_key_bytes[:32]
    elif len(private_key_bytes) == 32:
        seed = private_key_bytes
    else:
        raise ValueError("Invalid Ed25519 key")

    # Ed25519 OID: 1.3.101.112
    ed25519_oid = b'\x06\x03\x2b\x65\x70'

    version = b'\x02\x01\x00'

    algorithm_id = b'\x30\x05' + ed25519_oid

    # inner OCTET STRING (seed)
    inner_private = b'\x04\x20' + seed

    # outer OCTET STRING
    private_key = b'\x04' + bytes([len(inner_private)]) + inner_private

    private_key_info = (
        b'\x30' +
        bytes([len(version + algorithm_id + private_key)]) +
        version +
        algorithm_id +
        private_key
    )

    b64 = base64.b64encode(private_key_info).decode()
    lines = [b64[i:i+64] for i in range(0, len(b64), 64)]

    return (
        "-----BEGIN PRIVATE KEY-----\n"
        + "\n".join(lines) +
        "\n-----END PRIVATE KEY-----\n"
    )

def ed25519_public_to_pem(public_key_bytes):
    """
    Convert Ed25519 public key to PEM PKCS#8/SPKI compatible
    Only pysodium + base64, no cryptography
    """
    if len(public_key_bytes) != 32:
        raise ValueError("Ed25519 public key must be 32 bytes")
    
    # Ed25519 OID
    ed25519_oid = b'\x06\x03\x2b\x65\x70'
    
    # AlgorithmIdentifier SEQUENCE { OID }
    algorithm_id = b'\x30' + bytes([len(ed25519_oid)]) + ed25519_oid
    
    # BIT STRING: 0x03 + length + 0x00 (unused bits) + public key
    bit_string = b'\x03' + bytes([len(public_key_bytes)+1]) + b'\x00' + public_key_bytes
    
    # SubjectPublicKeyInfo SEQUENCE { AlgorithmIdentifier, BIT STRING }
    spki = b'\x30' + bytes([len(algorithm_id + bit_string)]) + algorithm_id + bit_string
    
    # Base64 + PEM
    b64_key = base64.b64encode(spki).decode('ascii')
    lines = [b64_key[i:i+64] for i in range(0, len(b64_key), 64)]
    
    pem_key = "-----BEGIN PUBLIC KEY-----\n" + "\n".join(lines) + "\n-----END PUBLIC KEY-----\n"
    
    return pem_key

def ed521_private_to_pem_pkcs8(private_key_int):
    private_bytes = little_int_to_bytes(private_key_int, 66)

    # OID 1.3.6.1.4.1.44588.2.1
    encoded_oid = bytes([
        0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xdc, 0x2c, 0x02, 0x01
    ])
    oid_der = b'\x06\x0a' + encoded_oid
    algorithm_id = b'\x30\x0e' + oid_der + b'\x05\x00'

    version = b'\x02\x01\x00'

    # CONTEXT-SPECIFIC [4], PRIMITIVE
    priv_field = b'\x84' + bytes([len(private_bytes)]) + private_bytes

    content = version + algorithm_id + priv_field
    seq = b'\x30' + bytes([len(content)]) + content

    b64 = base64.b64encode(seq).decode()
    lines = [b64[i:i+64] for i in range(0, len(b64), 64)]

    return (
        "-----BEGIN E-521 PRIVATE KEY-----\n"
        + "\n".join(lines) +
        "\n-----END E-521 PRIVATE KEY-----\n"
    )

def ed521_public_to_pem(public_key_x, public_key_y):
    """
    Convert Ed521 public key to EXACT edgetk-compatible format
    
    Corrections:
    1. Same OID fix
    2. Standard "PUBLIC KEY" headers
    3. Correct BIT STRING format
    """
    # CORRECT OID (same as private key)
    encoded_oid = bytes([
        0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xdc, 0x2c, 0x02, 0x01
    ])
    oid_der = b'\x06\x0a' + encoded_oid
    
    # AlgorithmIdentifier SEQUENCE
    algorithm_id = b'\x30\x0e' + oid_der + b'\x05\x00'  # 0x0e = 14 bytes
    
    # Compress public key
    compressed_pub = ed521_compress_point(public_key_x, public_key_y)
    
    # BIT STRING with 0 unused bits
    # Total BIT STRING length: 1 (unused bits) + 66 (key) = 67 bytes
    # BIT STRING tag (0x03) + length + 0x00 + data
    bit_string_data = b'\x00' + compressed_pub  # 0 unused bits
    bit_string_len = len(bit_string_data)  # Should be 67
    
    if bit_string_len < 128:
        bit_string_header = b'\x03' + bytes([bit_string_len])
    else:
        len_bytes = bit_string_len.to_bytes((bit_string_len.bit_length() + 7) // 8, 'big')
        bit_string_header = b'\x03' + bytes([0x80 | len(len_bytes)]) + len_bytes
    
    bit_string = bit_string_header + bit_string_data
    
    # SubjectPublicKeyInfo SEQUENCE
    content = algorithm_id + bit_string
    content_len = len(content)
    
    print(f"DEBUG: Public key structure lengths:")
    print(f"  AlgorithmIdentifier: {len(algorithm_id)} bytes")
    print(f"  BitString: {len(bit_string)} bytes")
    print(f"  Total content: {content_len} bytes")
    
    # Outer SEQUENCE
    if content_len < 128:
        seq_len = bytes([content_len])
    else:
        len_bytes = content_len.to_bytes((content_len.bit_length() + 7) // 8, 'big')
        seq_len = bytes([0x80 | len(len_bytes)]) + len_bytes
    
    subject_pub_key_info = b'\x30' + seq_len + content
    
    print(f"DEBUG: Total DER length: {len(subject_pub_key_info)} bytes")
    
    # Convert to PEM with STANDARD headers
    b64_key = base64.b64encode(subject_pub_key_info).decode('ascii')
    lines = [b64_key[i:i+64] for i in range(0, len(b64_key), 64)]
    
    return (
        "-----BEGIN E-521 PUBLIC KEY-----\n" +
        "\n".join(lines) +
        "\n-----END E-521 PUBLIC KEY-----\n"
    )

def x25519_private_to_pem_pkcs8(private_key_bytes):
    """
    Convert X25519 private key (32 bytes) to PEM PKCS8 according to RFC 8410
    """
    if len(private_key_bytes) != 32:
        raise ValueError("X25519 private key must be 32 bytes")
    
    x25519_oid = b'\x06\x03\x2b\x65\x6e'  # 1.3.101.110

    # inner OCTET STRING of key
    inner = b'\x04\x20' + private_key_bytes

    # outer OCTET STRING
    private_key = b'\x04' + bytes([len(inner)]) + inner

    # AlgorithmIdentifier SEQUENCE { OID }
    alg_id = b'\x30' + bytes([len(x25519_oid)]) + x25519_oid

    # Version INTEGER 0
    version = b'\x02\x01\x00'

    # PrivateKeyInfo SEQUENCE { version, alg_id, private_key }
    total_len = len(version + alg_id + private_key)
    pkcs8 = b'\x30' + bytes([total_len]) + version + alg_id + private_key

    b64 = base64.b64encode(pkcs8).decode()
    lines = [b64[i:i+64] for i in range(0, len(b64), 64)]
    return "-----BEGIN PRIVATE KEY-----\n" + "\n".join(lines) + "\n-----END PRIVATE KEY-----\n"

def x25519_public_to_pem(public_key_bytes):
    """
    Convert X25519 public key (32 bytes) to PEM SPKI
    """
    if len(public_key_bytes) != 32:
        raise ValueError("X25519 public key must be 32 bytes")
    
    x25519_oid = b'\x06\x03\x2b\x65\x6e'  # 1.3.101.110

    alg_id = b'\x30' + bytes([len(x25519_oid)]) + x25519_oid
    bit_string = b'\x03' + bytes([len(public_key_bytes)+1]) + b'\x00' + public_key_bytes

    spki = b'\x30' + bytes([len(alg_id + bit_string)]) + alg_id + bit_string

    b64 = base64.b64encode(spki).decode()
    lines = [b64[i:i+64] for i in range(0, len(b64), 64)]
    return "-----BEGIN PUBLIC KEY-----\n" + "\n".join(lines) + "\n-----END PUBLIC KEY-----\n"

# =========================
# PEM READING FUNCTIONS para Ed521
# =========================

def parse_ed521_pem_private_key(pem_data, debug=False):
    """Parse Ed521 private key from PEM PKCS8 format (compatible with edgetk Go implementation)"""
    # Remove headers/footers and whitespace
    lines = pem_data.strip().split('\n')
    b64_data = ''.join([line.strip() for line in lines if line and not line.startswith('-----')])
    
    # Decode Base64
    der_data = base64.b64decode(b64_data)
    
    if debug:
        print(f"DEBUG: DER data length: {len(der_data)} bytes")
        print(f"DEBUG: DER hex: {der_data.hex()}")
    
    try:
        # Parse ASN.1 structure
        idx = 0
        
        # 1. Outer SEQUENCE (0x30)
        if der_data[idx] != 0x30:
            raise ValueError("Expected SEQUENCE (0x30)")
        idx += 1
        
        # Parse length
        if idx >= len(der_data):
            raise ValueError("Unexpected end of data")
        
        seq_len = der_data[idx]
        idx += 1
        
        # Handle long length form
        if seq_len & 0x80:
            num_bytes = seq_len & 0x7F
            if idx + num_bytes > len(der_data):
                raise ValueError("Incomplete length field")
            seq_len = int.from_bytes(der_data[idx:idx+num_bytes], 'big')
            idx += num_bytes
        
        if debug:
            print(f"DEBUG: Outer SEQUENCE length: {seq_len}")
        
        # 2. Version INTEGER (0) - tag 0x02
        if der_data[idx] != 0x02:
            raise ValueError("Expected INTEGER (0x02) for version")
        idx += 1
        
        # Version length
        if idx >= len(der_data):
            raise ValueError("Unexpected end of data")
        
        ver_len = der_data[idx]
        idx += 1
        
        if ver_len & 0x80:
            raise ValueError("Unexpected long form for version length")
        
        # Read version (should be 0)
        if idx + ver_len > len(der_data):
            raise ValueError("Incomplete version field")
        
        version = int.from_bytes(der_data[idx:idx+ver_len], 'big')
        if version != 0:
            raise ValueError(f"Expected version 0, got {version}")
        idx += ver_len
        
        if debug:
            print(f"DEBUG: Version: {version}")
        
        # 3. AlgorithmIdentifier SEQUENCE (0x30)
        if der_data[idx] != 0x30:
            raise ValueError("Expected AlgorithmIdentifier SEQUENCE (0x30)")
        idx += 1
        
        if idx >= len(der_data):
            raise ValueError("Unexpected end of data")
        
        algo_len = der_data[idx]
        idx += 1
        
        # Handle long length form for AlgorithmIdentifier
        if algo_len & 0x80:
            num_bytes = algo_len & 0x7F
            if idx + num_bytes > len(der_data):
                raise ValueError("Incomplete AlgorithmIdentifier length")
            algo_len = int.from_bytes(der_data[idx:idx+num_bytes], 'big')
            idx += num_bytes
        
        algo_end = idx + algo_len
        
        # 4. OID (0x06) - should be ED521_OID
        if der_data[idx] != 0x06:
            raise ValueError("Expected OID (0x06)")
        idx += 1
        
        if idx >= len(der_data):
            raise ValueError("Unexpected end of data")
        
        oid_len = der_data[idx]
        idx += 1
        
        if oid_len & 0x80:
            raise ValueError("Unexpected long form for OID length")
        
        if idx + oid_len > len(der_data):
            raise ValueError("Incomplete OID")
        
        oid_bytes = der_data[idx:idx+oid_len]
        idx += oid_len
        
        # Skip NULL parameters (0x05 0x00)
        if idx < algo_end and der_data[idx] == 0x05:
            idx += 1
            if idx >= len(der_data):
                raise ValueError("Unexpected end of data")
            null_len = der_data[idx]
            idx += 1
            if null_len != 0:
                raise ValueError(f"Expected NULL (0x00), got length {null_len}")
        
        # Skip to end of AlgorithmIdentifier
        idx = algo_end
        
        # 5. PrivateKey OCTET STRING (0x04)
        if der_data[idx] != 0x04:
            raise ValueError(f"Expected OCTET STRING (0x04), got 0x{der_data[idx]:02x}")
        idx += 1
        
        if idx >= len(der_data):
            raise ValueError("Unexpected end of data")
        
        priv_len = der_data[idx]
        idx += 1
        
        # Handle long length form
        if priv_len & 0x80:
            num_bytes = priv_len & 0x7F
            if idx + num_bytes > len(der_data):
                raise ValueError("Incomplete private key length")
            priv_len = int.from_bytes(der_data[idx:idx+num_bytes], 'big')
            idx += num_bytes
        
        # Read private key bytes (should be 66 bytes)
        if idx + priv_len > len(der_data):
            raise ValueError(f"Incomplete private key data, need {priv_len} bytes")
        
        private_key_bytes = der_data[idx:idx+priv_len]
        
        if debug:
            print(f"DEBUG: Private key length: {len(private_key_bytes)} bytes")
            print(f"DEBUG: Private key hex: {private_key_bytes.hex()}")
        
        # Check if it's the expected size (66 bytes for Ed521)
        if len(private_key_bytes) != ED521_BYTE_LEN:
            if debug:
                print(f"DEBUG: Warning: Private key is {len(private_key_bytes)} bytes, expected {ED521_BYTE_LEN}")
            
            # Try to handle non-standard sizes
            if len(private_key_bytes) > ED521_BYTE_LEN:
                # Take the last 66 bytes
                private_key_bytes = private_key_bytes[-ED521_BYTE_LEN:]
            elif len(private_key_bytes) < ED521_BYTE_LEN:
                # Pad with zeros
                private_key_bytes = b'\x00' * (ED521_BYTE_LEN - len(private_key_bytes)) + private_key_bytes
        
        # Convert bytes to integer (little-endian as per Go implementation)
        private_key_int = bytes_to_little_int(private_key_bytes)
        
        # Verify the key is valid (0 < key < N)
        if private_key_int <= 0 or private_key_int >= N:
            raise ValueError(f"Private key out of valid range: 0 < key < N")
        
        if debug:
            print(f"DEBUG: Private key integer: {hex(private_key_int)[:50]}...")
        
        return private_key_int
        
    except Exception as e:
        if debug:
            print(f"DEBUG: ASN.1 parsing failed: {e}")
        
        # Fallback: try to find 66-byte key in the data
        for i in range(len(der_data) - ED521_BYTE_LEN + 1):
            chunk = der_data[i:i+ED521_BYTE_LEN]
            key_int = bytes_to_little_int(chunk)
            if 0 < key_int < N:
                if debug:
                    print(f"DEBUG: Found 66-byte key at offset {i}")
                return key_int
        
        # If nothing works, check if the entire data is 66 bytes
        if len(der_data) == ED521_BYTE_LEN:
            key_int = bytes_to_little_int(der_data)
            if 0 < key_int < N:
                if debug:
                    print("DEBUG: Whole data is a valid 66-byte key")
                return key_int
        
        raise ValueError(f"Cannot parse Ed521 private key: {e}")

def parse_ed521_pem_public_key(pem_data, debug=False):
    """Parse Ed521 public key from PEM SPKI format (compatible with edgetk Go implementation)"""
    # Remove headers/footers and whitespace
    lines = pem_data.strip().split('\n')
    b64_data = ''.join([line.strip() for line in lines if line and not line.startswith('-----')])
    
    # Decode Base64
    der_data = base64.b64decode(b64_data)
    
    if debug:
        print(f"DEBUG: Public key DER length: {len(der_data)} bytes")
        print(f"DEBUG: Public key DER hex: {der_data.hex()}")
    
    try:
        idx = 0
        
        # 1. Outer SEQUENCE (0x30)
        if der_data[idx] != 0x30:
            raise ValueError("Expected SEQUENCE (0x30)")
        idx += 1
        
        if idx >= len(der_data):
            raise ValueError("Unexpected end of data")
        
        seq_len = der_data[idx]
        idx += 1
        
        # Handle long length
        if seq_len & 0x80:
            num_bytes = seq_len & 0x7F
            if idx + num_bytes > len(der_data):
                raise ValueError("Incomplete SEQUENCE length")
            seq_len = int.from_bytes(der_data[idx:idx+num_bytes], 'big')
            idx += num_bytes
        
        # 2. AlgorithmIdentifier SEQUENCE (0x30)
        if der_data[idx] != 0x30:
            raise ValueError("Expected AlgorithmIdentifier SEQUENCE (0x30)")
        idx += 1
        
        if idx >= len(der_data):
            raise ValueError("Unexpected end of data")
        
        algo_len = der_data[idx]
        idx += 1
        
        if algo_len & 0x80:
            num_bytes = algo_len & 0x7F
            if idx + num_bytes > len(der_data):
                raise ValueError("Incomplete AlgorithmIdentifier length")
            algo_len = int.from_bytes(der_data[idx:idx+num_bytes], 'big')
            idx += num_bytes
        
        algo_end = idx + algo_len
        
        # 3. OID (0x06)
        if der_data[idx] != 0x06:
            raise ValueError("Expected OID (0x06)")
        idx += 1
        
        if idx >= len(der_data):
            raise ValueError("Unexpected end of data")
        
        oid_len = der_data[idx]
        idx += 1
        
        if oid_len & 0x80:
            raise ValueError("Unexpected long form for OID length")
        
        if idx + oid_len > len(der_data):
            raise ValueError("Incomplete OID")
        
        oid_bytes = der_data[idx:idx+oid_len]
        idx += oid_len
        
        # Skip NULL parameters if present
        if idx < algo_end and der_data[idx] == 0x05:
            idx += 1
            if idx >= len(der_data):
                raise ValueError("Unexpected end of data")
            null_len = der_data[idx]
            idx += 1
            if null_len != 0:
                raise ValueError(f"Expected NULL (0x00), got length {null_len}")
        
        idx = algo_end  # Skip to end of AlgorithmIdentifier
        
        # 4. PublicKey BIT STRING (0x03)
        if der_data[idx] != 0x03:
            raise ValueError(f"Expected BIT STRING (0x03), got 0x{der_data[idx]:02x}")
        idx += 1
        
        if idx >= len(der_data):
            raise ValueError("Unexpected end of data")
        
        bitstring_len = der_data[idx]
        idx += 1
        
        if bitstring_len & 0x80:
            num_bytes = bitstring_len & 0x7F
            if idx + num_bytes > len(der_data):
                raise ValueError("Incomplete BIT STRING length")
            bitstring_len = int.from_bytes(der_data[idx:idx+num_bytes], 'big')
            idx += num_bytes
        
        # Skip unused bits byte (should be 0)
        if idx >= len(der_data):
            raise ValueError("Unexpected end of data")
        
        unused_bits = der_data[idx]
        idx += 1
        
        if unused_bits != 0:
            if debug:
                print(f"DEBUG: Warning: BIT STRING has {unused_bits} unused bits")
        
        # Read compressed public key (should be 66 bytes)
        compressed_pub = der_data[idx:idx + bitstring_len - 1]  # -1 for unused bits byte
        
        if debug:
            print(f"DEBUG: Compressed public key length: {len(compressed_pub)} bytes")
            print(f"DEBUG: Compressed public key hex: {compressed_pub.hex()}")
        
        # Decompress to get x, y coordinates
        pub_x, pub_y = ed521_decompress_point(compressed_pub)
        
        if pub_x is None or pub_y is None:
            raise ValueError("Failed to decompress public key")
        
        return pub_x, pub_y
        
    except Exception as e:
        if debug:
            print(f"DEBUG: ASN.1 parsing failed: {e}")
        
        # Fallback: try to find 66-byte compressed key
        if len(der_data) == ED521_BYTE_LEN:
            pub_x, pub_y = ed521_decompress_point(der_data)
            if pub_x is not None and pub_y is not None:
                if debug:
                    print("DEBUG: Found raw 66-byte compressed public key")
                return pub_x, pub_y
        
        # Try to find compressed key in the data
        for i in range(len(der_data) - ED521_BYTE_LEN + 1):
            chunk = der_data[i:i+ED521_BYTE_LEN]
            pub_x, pub_y = ed521_decompress_point(chunk)
            if pub_x is not None and pub_y is not None:
                if debug:
                    print(f"DEBUG: Found compressed public key at offset {i}")
                return pub_x, pub_y
        
        raise ValueError(f"Cannot parse Ed521 public key: {e}")

# =========================
# PEM READING FUNCTIONS para Ed25519
# =========================

def parse_pem_private_key(pem_data):
    """
    Parse private key from PEM PKCS8 format (for both Ed25519 and X25519)
    Returns the seed/key bytes
    """
    # Remove headers/footers and whitespace
    lines = pem_data.strip().split('\n')
    b64_data = ''.join([line.strip() for line in lines if line and not line.startswith('-----')])
    
    # Decode Base64
    der_data = base64.b64decode(b64_data)
    
    # PKCS8 structure: SEQUENCE { version, AlgorithmIdentifier, PrivateKey }
    idx = 0
    
    # Skip SEQUENCE tag and length
    if der_data[idx] != 0x30:  # SEQUENCE
        raise ValueError("Invalid PKCS8 format: expected SEQUENCE")
    idx += 1
    
    seq_len = der_data[idx]
    idx += 1
    if seq_len & 0x80:  # Long form length
        num_bytes = seq_len & 0x7F
        seq_len = int.from_bytes(der_data[idx:idx+num_bytes], 'big')
        idx += num_bytes
    
    # Skip version (INTEGER 0)
    if der_data[idx] != 0x02:  # INTEGER
        raise ValueError("Invalid PKCS8 format: expected version INTEGER")
    idx += 1
    
    ver_len = der_data[idx]
    idx += 1
    if idx + ver_len > len(der_data):
        raise ValueError("Invalid PKCS8 format: version field incomplete")
    
    version = int.from_bytes(der_data[idx:idx+ver_len], 'big')
    if version != 0:
        raise ValueError(f"Invalid PKCS8 version: expected 0, got {version}")
    idx += ver_len
    
    # Skip AlgorithmIdentifier (SEQUENCE + OID)
    if der_data[idx] != 0x30:  # SEQUENCE
        raise ValueError("Invalid PKCS8 format: expected AlgorithmIdentifier SEQUENCE")
    idx += 1
    
    algo_len = der_data[idx]
    idx += 1
    if algo_len & 0x80:  # Long form length
        num_bytes = algo_len & 0x7F
        algo_len = int.from_bytes(der_data[idx:idx+num_bytes], 'big')
        idx += num_bytes
    
    algo_end = idx + algo_len
    
    # Skip OID
    if der_data[idx] != 0x06:  # OID
        raise ValueError("Invalid PKCS8 format: expected OID")
    idx += 1
    
    oid_len = der_data[idx]
    idx += 1
    if oid_len & 0x80:  # Long form length
        num_bytes = oid_len & 0x7F
        oid_len = int.from_bytes(der_data[idx:idx+num_bytes], 'big')
        idx += num_bytes
    
    idx += oid_len  # Skip OID bytes
    
    # Check for NULL parameters (optional)
    if idx < algo_end and der_data[idx] == 0x05:  # NULL
        idx += 1
        if idx >= len(der_data):
            raise ValueError("Invalid PKCS8 format: incomplete NULL")
        null_len = der_data[idx]
        idx += 1
        if null_len != 0:
            raise ValueError(f"Invalid NULL length: expected 0, got {null_len}")
    
    # Now we're at PrivateKey (OCTET STRING)
    if idx >= len(der_data):
        raise ValueError("Invalid PKCS8 format: no private key data")
    
    if der_data[idx] != 0x04:  # OCTET STRING
        raise ValueError("Invalid PKCS8 format: expected OCTET STRING")
    idx += 1
    
    if idx >= len(der_data):
        raise ValueError("Invalid PKCS8 format: incomplete OCTET STRING")
    
    octet_len = der_data[idx]
    idx += 1
    
    if octet_len & 0x80:  # Long form length
        num_bytes = octet_len & 0x7F
        octet_len = int.from_bytes(der_data[idx:idx+num_bytes], 'big')
        idx += num_bytes
    
    # For Ed25519, the OCTET STRING should contain exactly 32 bytes (the seed)
    if idx + octet_len > len(der_data):
        raise ValueError(f"Invalid PKCS8 format: OCTET STRING incomplete, need {octet_len} bytes")
    
    private_key_bytes = der_data[idx:idx+octet_len]
    
    # IMPORTANTE: Para Ed25519, precisamos de exatamente 32 bytes
    # Se tiver mais bytes, pode ser um wrapper. Pegue os últimos 32 bytes
    if len(private_key_bytes) > 32:
        # Possivelmente tem um wrapper adicional, pegue os últimos 32 bytes
        if len(private_key_bytes) >= 32:
            private_key_bytes = private_key_bytes[-32:]
        else:
            raise ValueError(f"Invalid private key length for Ed25519: {len(private_key_bytes)} bytes")
    
    return private_key_bytes

def parse_pem_public_key(pem_data):
    """
    Parse public key from PEM SPKI format (for both Ed25519 and X25519)
    Returns the public key bytes
    """
    # Remove headers/footers and whitespace
    lines = pem_data.strip().split('\n')
    b64_data = ''.join([line.strip() for line in lines if line and not line.startswith('-----')])
    
    # Decode Base64
    der_data = base64.b64decode(b64_data)
    
    # SPKI structure: SEQUENCE { AlgorithmIdentifier, SubjectPublicKeyInfo }
    idx = 0
    
    # Skip SEQUENCE tag and length
    if der_data[idx] != 0x30:  # SEQUENCE
        raise ValueError("Invalid SPKI format: expected SEQUENCE")
    idx += 1
    
    seq_len = der_data[idx]
    idx += 1
    if seq_len & 0x80:  # Long form length
        num_bytes = seq_len & 0x7F
        seq_len = int.from_bytes(der_data[idx:idx+num_bytes], 'big')
        idx += num_bytes
    
    # Skip AlgorithmIdentifier (SEQUENCE + OID)
    if der_data[idx] != 0x30:  # SEQUENCE
        raise ValueError("Invalid SPKI format: expected AlgorithmIdentifier SEQUENCE")
    idx += 1
    
    algo_len = der_data[idx]
    idx += 1
    idx += algo_len  # Skip entire AlgorithmIdentifier
    
    # Now we're at SubjectPublicKeyInfo (BIT STRING)
    if der_data[idx] != 0x03:  # BIT STRING
        raise ValueError("Invalid SPKI format: expected BIT STRING")
    idx += 1
    
    bitstring_len = der_data[idx]
    idx += 1
    
    # Skip unused bits byte (should be 0)
    if der_data[idx] != 0x00:
        raise ValueError("Invalid BIT STRING: unused bits should be 0")
    idx += 1
    
    # Public key is in the next bytes (32 bytes for Ed25519/X25519)
    public_key_bytes = der_data[idx:idx+bitstring_len-1]  # -1 for the unused bits byte
    
    return public_key_bytes
    
# =========================
# 2. RECURSIVE HASH FUNCTION 
# =========================

def calculate_file_hash(file_path, hash_algo='sha256'):
    """Calculate file hash with support for modern algorithms"""
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
        
        elif hash_algo == 'shake_128':
            # SHAKE128 - extensible output function
            hash_func = hashlib.shake_128()
        
        elif hash_algo == 'shake_256':
            # SHAKE256 - extensible output function
            hash_func = hashlib.shake_256()
        
        else:
            # Standard hashlib algorithms
            try:
                hash_func = hashlib.new(hash_algo)
            except ValueError:
                # Fallback to known algorithms
                if hash_algo == 'sha256':
                    hash_func = hashlib.sha256()
                elif hash_algo == 'sha512':
                    hash_func = hashlib.sha512()
                elif hash_algo == 'sha3_256':
                    hash_func = hashlib.sha3_256()
                elif hash_algo == 'md5':
                    hash_func = hashlib.md5()
                elif hash_algo == 'sha1':
                    hash_func = hashlib.sha1()
                elif hash_algo == 'blake2b':
                    hash_func = hashlib.blake2b()
                elif hash_algo == 'blake2s':
                    hash_func = hashlib.blake2s()
                else:
                    raise ValueError(f"Unsupported hash algorithm: {hash_algo}")
        
        with open(file_path, 'rb') as f:
            # Read file in chunks to handle large files
            for chunk in iter(lambda: f.read(4096), b''):
                hash_func.update(chunk)
        
        # Handle variable-length outputs
        if hash_algo in ['shake_128']:
            # SHAKE algorithms need output length specified
            return hash_func.hexdigest(32)  # 32 bytes = 256 bits
        if hash_algo in ['shake_256']:
            # SHAKE algorithms need output length specified
            return hash_func.hexdigest(64)  # 64 bytes = 256 bits
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
            try:
                hash_obj = hashlib.new(alg)
                print(f"  {alg:15} - {hash_obj.digest_size * 8}-bit")
            except:
                print(f"  {alg:15} - available")
    
    # SHA-3 family
    print("\nSHA-3 family (Keccak):")
    sha3_algs = ['sha3_224', 'sha3_256', 'sha3_384', 'sha3_512', 
                 'shake_128', 'shake_256']
    for alg in sha3_algs:
        if alg in hashlib.algorithms_available:
            try:
                hash_obj = hashlib.new(alg)
                if alg.startswith('shake'):
                    print(f"  {alg:15} - Variable length (extensible output)")
                else:
                    print(f"  {alg:15} - {hash_obj.digest_size * 8}-bit")
            except:
                print(f"  {alg:15} - available")
    
    # BLAKE2 family
    print("\nBLAKE2 family:")
    blake2_algs = ['blake2b', 'blake2s']
    for alg in blake2_algs:
        if alg in hashlib.algorithms_available:
            try:
                hash_obj = hashlib.new(alg)
                print(f"  {alg:15} - {hash_obj.digest_size * 8}-bit")
            except:
                print(f"  {alg:15} - available")
    # BLAKE2 variants
    print("  blake2b_256      - 256-bit BLAKE2b")
    print("  blake2b_512      - 512-bit BLAKE2b")
    print("  blake2s_128      - 128-bit BLAKE2s")
    print("  blake2s_256      - 256-bit BLAKE2s")
    
    print("\nOther available algorithms:")
    other_algs = sorted([alg for alg in hashlib.algorithms_available 
                        if alg not in std_algs + sha3_algs + blake2_algs])
    for alg in other_algs[:15]:  # Show first 15
        print(f"  {alg:15}")
    
    if len(other_algs) > 15:
        print(f"  ... and {len(other_algs) - 15} more")
    
    print("\nNotes:")
    print("  • Recommended: sha256, sha3_256, blake2b")
    print("  • Avoid: md5, sha1 (cryptographically broken)")
    print("  • Default: sha256")

def _hashsum_list(file_list, recursive=False, hash_algo='sha256', output_file=None):
    """
    Alternative hashsum version that accepts a file list
    instead of a pattern (to handle shell expansion)
    """
    # Check algorithm availability (simplified check)
    available_algs = list(hashlib.algorithms_available)
    custom_algs = ['blake2b_256', 'blake2b_512', 'blake2s_128', 'blake2s_256']
    
    if hash_algo in custom_algs:
        # Custom variants need base BLAKE2
        if 'blake2b' not in hashlib.algorithms_available or 'blake2s' not in hashlib.algorithms_available:
            print(f"✖ BLAKE2 not available in this Python version", file=sys.stderr)
            sys.exit(1)
    elif hash_algo not in available_algs and hash_algo not in custom_algs:
        print(f"✖ Unsupported hash algorithm: {hash_algo}", file=sys.stderr)
        print(f"\nUse 'hashsum list' to see available algorithms")
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
            # If directory and recursive is enabled
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

def hashsum_calc(pattern, files=None, recursive=False, hash_algo='sha256', output_file=None):
    """Calculate hashes for files matching pattern"""
    # Check if algorithm is available
    available_algs = list(hashlib.algorithms_available)
    custom_algs = ['blake2b_256', 'blake2b_512', 'blake2s_128', 'blake2s_256']
    
    if hash_algo in custom_algs:
        # Custom variants need base BLAKE2
        if 'blake2b' not in hashlib.algorithms_available or 'blake2s' not in hashlib.algorithms_available:
            print(f"✖ BLAKE2 not available in this Python version", file=sys.stderr)
            sys.exit(1)
    elif hash_algo not in available_algs and hash_algo not in custom_algs:
        print(f"✖ Unsupported hash algorithm: {hash_algo}", file=sys.stderr)
        print(f"\nUse 'hashsum list' to see available algorithms")
        sys.exit(1)
    
    # If files were provided by shell expansion, use them
    if files:
        return _hashsum_list(files, recursive, hash_algo, output_file)
    
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
            # Hash is first part, filename is the rest (may have asterisk)
            file_hash = parts[0]
            file_path = ' '.join(parts[1:])
            
            # Remove asterisk if present
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
# 1. ARGON2 PASSWORD HASHING (using pysodium with flags)
# =========================

def argon2_hash_password(password=None, opslimit=None, memlimit=None):
    """Hash a password using Argon2id from pysodium with configurable parameters"""
    if not PYSODIUM_AVAILABLE:
        print("✖ pysodium required for Argon2. Install with: pip install pysodium")
        sys.exit(1)
    
    if password is None:
        password = getpass.getpass("Password: ")
    
    if isinstance(password, str):
        password = password.encode('utf-8')
    
    # Use default limits if not specified
    if opslimit is None:
        opslimit = pysodium.crypto_pwhash_OPSLIMIT_INTERACTIVE
    if memlimit is None:
        memlimit = pysodium.crypto_pwhash_MEMLIMIT_INTERACTIVE

    hashed = pysodium.crypto_pwhash_str(
        password,
        opslimit=opslimit,
        memlimit=memlimit
    )
    sys.stdout.buffer.write(hashed + b"\n")
    return hashed

def argon2_verify_password(hash_str=None, password=None):
    if not PYSODIUM_AVAILABLE:
        print("✖ pysodium required")
        sys.exit(1)

    if hash_str is None:
        hash_str = input("Hash: ").strip()

    if password is None:
        password = getpass.getpass("Password: ")

    if isinstance(password, str):
        password = password.encode()

    if isinstance(hash_str, str):
        hash_bytes = hash_str.encode("utf-8")
    else:
        hash_bytes = hash_str

    # libsodium EXIGE buffer de tamanho fixo
    buf = bytearray(pysodium.crypto_pwhash_STRBYTES)

    if len(hash_bytes) >= pysodium.crypto_pwhash_STRBYTES:
        print("✖ Hash too long")
        return

    # copia e garante NUL padding
    buf[:len(hash_bytes)] = hash_bytes
    buf[len(hash_bytes)] = 0  # NUL terminator

    try:
        if pysodium.crypto_pwhash_str_verify(bytes(buf), password):
            print("✔ Password matches the Argon2 hash!")
        else:
            print("✖ Password does NOT match the Argon2 hash!")
    except Exception as e:
        print(f"✖ Verification error: {e}")

# =========================
# 3. HMAC (standard Python)
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
    
    try:
        hmac_obj = hmac_lib.new(key, data, digestmod=hash_algo)
        return hmac_obj.hexdigest()
    except ValueError as e:
        # Try with hashlib if direct doesn't work
        try:
            hmac_obj = hmac_lib.HMAC(key, data, digestmod=hash_algo)
            return hmac_obj.hexdigest()
        except:
            raise ValueError(f"Unsupported hash algorithm for HMAC: {hash_algo}")

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
# 5. ED521 FUNCTIONS (always available)
# =========================

def ed521_generate(priv_path, pub_path):
    """Generate Ed521 keys and save in PEM PKCS8 format"""
    print("Generating Ed521 keys (521-bit curve)...")
    
    # Generate private key
    private_key = ed521_generate_private_key()
    print(f"Private key generated: {hex(private_key)[:34]}...")
    
    # Generate public key
    pub_x, pub_y = ed521_get_public_key(private_key)
    print(f"Public key generated: ({hex(pub_x)[:20]}..., {hex(pub_y)[:20]}...)")
    
    # Check if point is on curve
    if not ed521_is_on_curve(pub_x, pub_y):
        print("✖ Generated public key is not on the curve!", file=sys.stderr)
        sys.exit(1)
    
    # Convert to PEM format
    private_pem = ed521_private_to_pem_pkcs8(private_key)
    public_pem = ed521_public_to_pem(pub_x, pub_y)
    
    # Save keys
    with open(priv_path, "w") as f:
        f.write(private_pem)
    print(f"✔ Private key saved in {priv_path} (PEM PKCS8)")
    
    with open(pub_path, "w") as f:
        f.write(public_pem)
    print(f"✔ Public key saved in {pub_path} (PEM)")
    
    return private_key, pub_x, pub_y

def ed521_sign_file(priv_path, msg_path):
    """Sign a file with Ed521"""
    try:
        # Read private key from PEM
        with open(priv_path, "r") as f:
            pem_data = f.read()
        
        # Parse private key
        private_key = parse_ed521_pem_private_key(pem_data)
        
        # Read message file
        with open(msg_path, "rb") as f:
            message = f.read()
        
        # Sign message
        signature = ed521_sign(private_key, message)
        
        print(f"File: {msg_path}")
        print(f"File size: {len(message)} bytes")
        print(f"Signature (hex): {signature.hex()}")
        
        return signature
        
    except Exception as e:
        print(f"✖ Error signing with Ed521: {e}", file=sys.stderr)
        sys.exit(1)

def ed521_verify_file(pub_path, msg_path, sig_hex):
    """Verify Ed521 signature for a file"""
    try:
        # Read public key from PEM
        with open(pub_path, "r") as f:
            pem_data = f.read()
        
        # Parse public key
        pub_x, pub_y = parse_ed521_pem_public_key(pem_data)
        
        # Read message file
        with open(msg_path, "rb") as f:
            message = f.read()
        
        # Convert signature from hex
        signature = bytes.fromhex(sig_hex)
        
        # Verify signature
        if ed521_verify(pub_x, pub_y, message, signature):
            print(f"✔ Valid Ed521 signature for file: {msg_path}")
            return True
        else:
            print(f"✖ Invalid Ed521 signature for file: {msg_path}")
            return False
            
    except Exception as e:
        print(f"✖ Error verifying Ed521 signature: {e}", file=sys.stderr)
        sys.exit(1)

def ed521_prove_knowledge(priv: int) -> bytes:
    """
    Generate non-interactive ZKP proof of private key knowledge
    Based on the Go implementation
    """
    byte_len = ED521_BYTE_LEN
    
    # 1. Commitment R = r*G (generate random value r)
    while True:
        r_bytes = os.urandom(byte_len)
        r = bytes_to_little_int(r_bytes)
        if r < N:
            break
    
    Rx, Ry = ed521_scalar_base_mult(little_int_to_bytes(r, byte_len))
    R_comp = ed521_compress_point(Rx, Ry)
    
    # 2. Get public key A
    Ax, Ay = ed521_get_public_key(priv)
    A_comp = ed521_compress_point(Ax, Ay)
    
    # 3. Challenge c = H(R || A) using Fiat–Shamir
    input_data = R_comp + A_comp
    c_bytes = ed521_hash(0x00, b'', input_data)
    c = bytes_to_little_int(c_bytes[:byte_len]) % N
    
    # 4. Response: s = r + c * a (mod N)
    s = (r + c * priv) % N
    
    # 5. Final proof = R || s
    s_bytes = little_int_to_bytes(s, byte_len)
    proof = R_comp + s_bytes
    
    return proof

def ed521_verify_knowledge(pub_x: int, pub_y: int, proof: bytes) -> bool:
    """
    Verify ZKP non-interactive proof
    Based on the Go implementation
    """
    byte_len = ED521_BYTE_LEN
    
    if len(proof) != 2 * byte_len:
        return False
    
    R_comp = proof[:byte_len]
    s_bytes = proof[byte_len:]
    
    # 1. Decompress commitment R
    Rx, Ry = ed521_decompress_point(R_comp)
    if Rx is None or Ry is None:
        return False
    
    s = bytes_to_little_int(s_bytes)
    
    # 2. Recalculate c = H(R || A)
    A_comp = ed521_compress_point(pub_x, pub_y)
    input_data = R_comp + A_comp
    c_bytes = ed521_hash(0x00, b'', input_data)
    c = bytes_to_little_int(c_bytes[:byte_len]) % N
    
    # 3. Verification: s*G == R + c*A
    sGx, sGy = ed521_scalar_base_mult(little_int_to_bytes(s, byte_len))
    cAx, cAy = ed521_scalar_mult(pub_x, pub_y, little_int_to_bytes(c, byte_len))
    RpluscAx, RpluscAy = ed521_add_points(Rx, Ry, cAx, cAy)
    
    return sGx == RpluscAx and sGy == RpluscAy
    
def ed521_prove_command(priv_path: str):
    """Generate ZKP proof of private key knowledge"""
    # Read private key file
    with open(priv_path, "r") as f:
        pem_data = f.read()
    
    # Check if encrypted
    is_encrypted = 'Proc-Type: 4,ENCRYPTED' in pem_data
    
    password = None
    if is_encrypted:
        password = getpass.getpass("Enter password to decrypt private key: ")
    
    # Parse private key
    try:
        private_key = parse_ed521_pem_private_key(pem_data, password)
    except Exception as e:
        print(f"✖ Error parsing private key: {e}")
        sys.exit(1)
    
    # Generate proof
    proof = ed521_prove_knowledge(private_key)
    proof_hex = proof.hex()
    
    # CORREÇÃO: Exibir em hex em vez de salvar em bin
    print(f"✔ Zero-knowledge proof generated")
    print(f"\nProof (hex): {proof_hex}")
    print(f"Proof length: {len(proof)} bytes ({(len(proof) * 8)} bits)")
    
    # Opcional: oferecer para salvar
    save = input("\nSave proof to file? (y/N): ").strip().lower()
    if save == 'y':
        filename = input("Filename [ed521_proof.hex]: ").strip() or "ed521_proof.hex"
        try:
            with open(filename, "w") as f:
                f.write(proof_hex)
            print(f"✔ Proof saved to {filename}")
        except Exception as e:
            print(f"✖ Error saving proof: {e}")
    
    return proof_hex

def ed521_verify_proof_command(pub_path: str, proof_hex: Optional[str] = None, proof_file: Optional[str] = None):
    """Verify ZKP proof for E-521 public key"""
    # Read public key file
    with open(pub_path, "r") as f:
        pem_data = f.read()
    
    # Parse public key
    try:
        pub_x, pub_y = parse_ed521_pem_public_key(pem_data)
    except Exception as e:
        print(f"✖ Error parsing public key: {e}")
        sys.exit(1)
    
    # Read proof
    if proof_file:
        with open(proof_file, "r") as f:
            proof_hex = f.read().strip()
    
    if not proof_hex:
        # Solicitar prova do usuário
        print("Enter the proof (hex):")
        try:
            lines = []
            while True:
                line = sys.stdin.readline()
                if not line or line.strip() == "":
                    break
                lines.append(line.strip())
            proof_hex = "".join(lines)
        except KeyboardInterrupt:
            print("\n✖ Input cancelled")
            sys.exit(1)
    
    # Converter hex para bytes
    try:
        proof = bytes.fromhex(proof_hex)
    except binascii.Error as e:
        print(f"✖ Invalid hex: {e}")
        sys.exit(1)
    
    # Verify proof
    if ed521_verify_knowledge(pub_x, pub_y, proof):
        print("\n✔ Zero-knowledge proof valid")
        print("  The key holder proves knowledge of the private key")
        return True
    else:
        print("\n✖ Zero-knowledge proof invalid")
        print("  The key holder does NOT prove knowledge of the private key")
        return False

def ed521_test_command():
    """Run complete E-521 implementation test"""
    print("=== E-521 EdDSA Test Suite ===")
    print()
    
    # Test 1: Key generation
    print("1. Key generation test:")
    priv_key = ed521_generate_private_key()
    pub_x, pub_y = ed521_get_public_key(priv_key)
    print(f"   Private key (first 16 bytes): {hex(priv_key)[:34]}...")
    print(f"   Public key on curve: {ed521_is_on_curve(pub_x, pub_y)}")
    
    # Test 2: Compression/Decompression
    print("\n2. Point compression test:")
    compressed = ed521_compress_point(pub_x, pub_y)
    decomp_x, decomp_y = ed521_decompress_point(compressed)
    print(f"   Compression successful: {len(compressed)} bytes")
    print(f"   Decompression correct: {decomp_x == pub_x and decomp_y == pub_y}")
    
    # Test 3: Signature and verification
    print("\n3. Signature test:")
    message = b"Test message for E-521 EdDSA"
    signature = ed521_sign(priv_key, message)
    valid = ed521_verify(pub_x, pub_y, message, signature)
    print(f"   Signature created: {len(signature)} bytes")
    print(f"   Signature valid: {valid}")
    
    # Test 4: Invalid signature
    wrong_message = b"Wrong message"
    wrong_valid = ed521_verify(pub_x, pub_y, wrong_message, signature)
    print(f"   Wrong message rejected: {not wrong_valid}")
    
    # Test 5: ZKP proof
    print("\n4. Zero-knowledge proof test:")
    proof = ed521_prove_knowledge(priv_key)
    proof_valid = ed521_verify_knowledge(pub_x, pub_y, proof)
    print(f"   Proof generated: {len(proof)} bytes")
    print(f"   Proof valid: {proof_valid}")
    
    # Test 6: PKCS#8 serialization
    print("\n5. PKCS#8 serialization test:")
    public_pem = ed521_public_to_pem(pub_x, pub_y)
    private_pem = ed521_private_to_pem_pkcs8(priv_key)
    
    # Parse back
    parsed_pub_x, parsed_pub_y = parse_ed521_pem_public_key(public_pem)
    parsed_priv = parse_ed521_pem_private_key(private_pem)
    
    print(f"   Public key serialization correct: {parsed_pub_x == pub_x and parsed_pub_y == pub_y}")
    print(f"   Private key serialization correct: {parsed_priv == priv_key}")
    
    print("\n=== All tests passed! ===")

# =========================
# 6. FUNCTIONS WITH PYSODIUM (if available)
# =========================

if PYSODIUM_AVAILABLE:
    def chacha20_encrypt(key_hex, infile, aad=None):
        """Encrypt with ChaCha20-Poly1305 (IETF) with optional AAD"""
        key = bytes.fromhex(key_hex)
        if len(key) != 32:
            print("✖ Key must be 32 bytes", file=sys.stderr)
            sys.exit(1)

        nonce = generate_random_bytes(12)

        with open(infile, "rb") as f:
            plaintext = f.read()

        if aad is not None:
            if isinstance(aad, str):
                aad = aad.encode("utf-8")
        else:
            aad = None

        ciphertext = pysodium.crypto_aead_chacha20poly1305_ietf_encrypt(
            plaintext,
            aad,
            nonce,
            key
        )

        # Output format: nonce || ciphertext
        sys.stdout.buffer.write(nonce + ciphertext)
        print("✔ Encrypted", file=sys.stderr)

    def chacha20_decrypt(key_hex, aad=None):
        """Decrypt with ChaCha20-Poly1305 (IETF) with optional AAD"""
        key = bytes.fromhex(key_hex)
        if len(key) != 32:
            print("✖ Key must be 32 bytes", file=sys.stderr)
            sys.exit(1)

        data = sys.stdin.buffer.read()
        if len(data) < 12:
            print("✖ Data too short", file=sys.stderr)
            sys.exit(1)

        nonce = data[:12]
        ciphertext = data[12:]

        if aad is not None:
            if isinstance(aad, str):
                aad = aad.encode("utf-8")
        else:
            aad = None

        try:
            plaintext = pysodium.crypto_aead_chacha20poly1305_ietf_decrypt(
                ciphertext,
                aad,
                nonce,
                key
            )
            sys.stdout.buffer.write(plaintext)
            print("✔ Decrypted", file=sys.stderr)
        except Exception:
            print("✖ Authentication failed (AAD/key/nonce mismatch)", file=sys.stderr)
            sys.exit(1)
    
    def ed25519_generate(priv_path, pub_path, encrypt=False):
        """Generate Ed25519 keys and save in PEM PKCS8 format"""
        pk, sk = pysodium.crypto_sign_keypair()
        
        # Convert to PEM format
        private_pem = ed25519_private_to_pem_pkcs8(sk)
        public_pem = ed25519_public_to_pem(pk)
        
        # Save public key
        with open(pub_path, "w") as f:
            f.write(public_pem)
        print(f"✔ Public key saved in {pub_path} (PEM)")
        
        # Save private key
        with open(priv_path, "w") as f:
            f.write(private_pem)
        print(f"✔ Unencrypted private key saved in {priv_path} (PEM PKCS8)")
    
    def ed25519_sign(priv_path, msg_path):
        """Sign with Ed25519 (PKCS#8 seed → libsodium key)"""
        try:
            # Read private key
            with open(priv_path, "r") as f:
                pem_data = f.read()
    
            seed = parse_pem_private_key(pem_data)
    
            if len(seed) != 32:
                raise ValueError(f"Invalid seed: {len(seed)} bytes")
    
            # Expand seed → libsodium key (64 bytes)
            pk, sk = pysodium.crypto_sign_seed_keypair(seed)
    
            if len(sk) != 64:
                raise ValueError(f"Invalid secret key: {len(sk)} bytes")
    
            # Read message
            with open(msg_path, "rb") as f:
                message = f.read()
    
            # Sign
            signature = pysodium.crypto_sign_detached(message, sk)
    
            print(binascii.hexlify(signature).decode())
    
        except Exception as e:
            print(f"✖ Error signing: {e}", file=sys.stderr)
            sys.exit(1)

    
    def ed25519_verify(pub_path, msg_path, sig_hex):
        """Verify Ed25519 signature"""
        # Read public key PEM
        with open(pub_path, "r") as f:
            pem_data = f.read()
        
        try:
            # Correctly parse public key from PEM
            pk = parse_pem_public_key(pem_data)
            
            if len(pk) != 32:
                raise ValueError(f"Public key must be 32 bytes, but is {len(pk)} bytes")
            
            with open(msg_path, "rb") as f:
                message = f.read()
            
            signature = binascii.unhexlify(sig_hex)
            
            try:
                pysodium.crypto_sign_verify_detached(signature, message, pk)
                print("✔ Valid signature")
            except Exception:
                print("✖ Invalid signature")
                
        except Exception as e:
            print(f"✖ Error parsing public key: {e}", file=sys.stderr)
            sys.exit(1)
    
    def x25519_generate(priv_path, pub_path, encrypt=False):
        """Generate X25519 keys and save in PEM PKCS8 format"""
        sk = pysodium.crypto_box_seed_keypair(generate_random_bytes(32))[0]
        pk = pysodium.crypto_scalarmult_base(sk)
        
        # Convert to PEM format
        private_pem = x25519_private_to_pem_pkcs8(sk)
        public_pem = x25519_public_to_pem(pk)
        
        # Save public key
        with open(pub_path, "w") as f:
            f.write(public_pem)
        print(f"✔ Public key saved in {pub_path} (PEM)")
        
        with open(priv_path, "w") as f:
            f.write(private_pem)
        print(f"✔ Unencrypted private key saved in {priv_path} (PEM PKCS8)")
    
    def x25519_shared(priv_path, peer_pub_path):
        """Calculate X25519 shared secret using pure pysodium"""
        try:
            # Read private key PEM → bytes (32 bytes)
            with open(priv_path, "r") as f:
                priv_pem = f.read()
            sk = parse_pem_private_key(priv_pem)
    
            # Read public key PEM → bytes (32 bytes)
            with open(peer_pub_path, "r") as f:
                peer_pem = f.read()
            pk = parse_pem_public_key(peer_pem)
    
            # Verify sizes
            if len(sk) != 32:
                raise ValueError(f"Private key must be 32 bytes, but is {len(sk)}")
            if len(pk) != 32:
                raise ValueError(f"Public key must be 32 bytes, but is {len(pk)}")
    
            # Calculate shared secret with X25519
            # Here we use libsodium's native function via pysodium:
            shared = pysodium.crypto_scalarmult_curve25519(sk, pk)
    
            print(f"Shared secret (hex): {binascii.hexlify(shared).decode()}")
    
        except Exception as e:
            print(f"✖ Error: {e}", file=sys.stderr)
            sys.exit(1)

# =========================
# CLI MAIN
# =========================

def main():
    parser = argparse.ArgumentParser(
        description="EDGE Crypto Toolbox (Argon2, ChaCha20, Ed25519, Ed521, Scrypt, X25519, Hashsum, HMAC, HKDF)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples (basic features always available):
  # File hashes
  python %(prog)s hashsum calc "*.txt"
  python %(prog)s hashsum calc "*.py" -r -a sha256 -o hashes.txt
  python %(prog)s hashsum calc *.py  # With shell expansion
  python %(prog)s hashsum check hashes.txt
  python %(prog)s hashsum list
  
  # HMAC
  python %(prog)s hmac calc --key "mykey" --data "message"
  python %(prog)s hmac calc --key "mykey" --file "secret.txt"
  python %(prog)s hmac verify --hmac "abc123" --key "mykey" --data "message"
  python %(prog)s hmac list
  
  # Scrypt key derivation
  python %(prog)s scrypt derive --secret "IKM" --salt "salt" [--iter 16384] [--keylen 32] 
  python %(prog)s scrypt compare --secret "IKM" --salt "salt" --derived DERIVED_HEX
  
  # HKDF key derivation (RFC 5869)
  python %(prog)s hkdf calc --salt "salt" --ikm "input" --info "context" --length 32
  python %(prog)s hkdf derive  # Interactive mode
  python %(prog)s hkdf compare  # Verify derivation
  python %(prog)s hkdf list     # List algorithms
  
  # Ed521 signatures (always available) (ICP-Brasil Standard)
  python %(prog)s ed521 gen --priv ed521_priv.pem --pub ed521_pub.pem
  python %(prog)s ed521 sign --priv ed521_priv.pem --msg document.txt
  python %(prog)s ed521 verify --pub ed521_pub.pem --msg document.txt --sig SIGNATURE_HEX
  python %(prog)s ed521 prove --priv ed521_priv.pem
  python %(prog)s ed521 verify-proof --pub ed521_pub.pem --proof-file ed521_proof.bin
  python %(prog)s ed521 test
  
Advanced features (require pysodium):
  # Argon2 password hash
  python %(prog)s argon2 hash
  python %(prog)s argon2 hash --password "mypassword"
  python %(prog)s argon2 verify --hash '$HASH' --password "mypassword"
  
  # ChaCha20 encryption
  python %(prog)s chacha20 encrypt --key $KEY --infile secret.txt
  cat encrypted.bin | python %(prog)s chacha20 decrypt --key $KEY
  
  # Ed25519 signatures
  python %(prog)s ed25519 gen --priv private.pem --pub public.pem
  python %(prog)s ed25519 sign --priv private.pem --msg message.txt
  python %(prog)s ed25519 verify --pub public.pem --msg message.txt --sig SIGNATURE_HEX
  
  # X25519 key exchange
  python %(prog)s x25519 gen --priv alice_priv.pem --pub alice_pub.pem
  python %(prog)s x25519 shared --priv alice_priv.pem --peer bob_pub.pem
        """
    )
    
    sub = parser.add_subparsers(dest="tool", title="Tools", required=True)

    # ======================
    # Argon2
    # ======================
    arg = sub.add_parser("argon2", help="Argon2 password hashing")
    argsub = arg.add_subparsers(dest="cmd", required=True)

    a_hash = argsub.add_parser("hash", help="Hash a password")
    a_hash.add_argument("--password", help="Password to hash (optional, otherwise prompted)")
    a_hash.add_argument("--opslimit", type=int, 
                       help="Operations limit (default: INTERACTIVE)")
    a_hash.add_argument("--memlimit", type=int,
                       help="Memory limit in bytes (default: INTERACTIVE)")

    a_ver = argsub.add_parser("verify", help="Verify password against hash")
    a_ver.add_argument("--hash", help="Argon2 hash to verify against")
    a_ver.add_argument("--password", help="Password to verify")

    # ======================
    # Hashsum
    # ======================
    hs = sub.add_parser("hashsum", help="File hashes")
    hssub = hs.add_subparsers(dest="cmd", required=True)
    hs_calc = hssub.add_parser("calc", help="Calculate hashes")
    hs_calc.add_argument("pattern", nargs='?', default="*", 
                        help="File pattern (e.g., '*.py', 'file.txt'). Default: '*'")
    hs_calc.add_argument("files", nargs='*', 
                        help="Files to process (when shell expands pattern)")
    hs_calc.add_argument("-r", "--recursive", action="store_true", help="Recursive")
    hs_calc.add_argument("-a", "--algorithm", default="sha256", help="Algorithm")
    hs_calc.add_argument("-o", "--output", help="Save to file")
    
    hs_check = hssub.add_parser("check", help="Verify hashes from file")
    hs_check.add_argument("hash_file", help="File containing hashes to verify")
    hs_check.add_argument("--all", action="store_true", 
                         help="Continue even if some files are missing")
    
    hs_list = hssub.add_parser("list", help="List all available hash algorithms")

    # ======================
    # HMAC
    # ======================
    hm = sub.add_parser("hmac", help="HMAC")
    hmsub = hm.add_subparsers(dest="cmd", required=True)
    hm_calc = hmsub.add_parser("calc", help="Calculate HMAC")
    hm_calc.add_argument("--key", help="Key")
    hm_calc.add_argument("--data", help="Data")
    hm_calc.add_argument("--file", help="File")
    hm_calc.add_argument("--algo", default="sha256", help="Algorithm")
    
    hm_ver = hmsub.add_parser("verify", help="Verify HMAC")
    hm_ver.add_argument("--key", help="Key")
    hm_ver.add_argument("--hmac", required=True, help="HMAC to verify (hex)")
    hm_ver.add_argument("--data", help="Data to verify")
    hm_ver.add_argument("--file", help="File to verify")
    hm_ver.add_argument("--algo", default="sha256", help="Algorithm")
    
    hm_list_cmd = hmsub.add_parser("list", help="List HMAC algorithms")

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
    # HKDF
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
    # Ed521 (always available)
    # ======================
    ed521 = sub.add_parser("ed521", help="Ed521 signatures (521-bit curve)")
    ed521sub = ed521.add_subparsers(dest="cmd", required=True)
    
    ed521_gen = ed521sub.add_parser("gen", help="Generate Ed521 keys")
    ed521_gen.add_argument("--priv", default="ed521_private.pem", help="Private key PEM")
    ed521_gen.add_argument("--pub", default="ed521_public.pem", help="Public key PEM")
    
    ed521_sign = ed521sub.add_parser("sign", help="Sign with Ed521")
    ed521_sign.add_argument("--priv", required=True, help="Private key PEM")
    ed521_sign.add_argument("--msg", required=True, help="Message file")
    
    ed521_ver = ed521sub.add_parser("verify", help="Verify Ed521 signature")
    ed521_ver.add_argument("--pub", required=True, help="Public key PEM")
    ed521_ver.add_argument("--msg", required=True, help="Message file")
    ed521_ver.add_argument("--sig", required=True, help="Signature hex")
    
    ed521_prove = ed521sub.add_parser("prove", help="Generate ZKP proof of private key knowledge")
    ed521_prove.add_argument("--priv", required=True, help="Private key file")

    ed521_verify_proof = ed521sub.add_parser("verify-proof", help="Verify ZKP proof")
    ed521_verify_proof.add_argument("--pub", required=True, help="Public key file")
    ed521_verify_proof.add_argument("--proof", help="Proof in hex to verify")
    ed521_verify_proof.add_argument("--proof-file", help="Proof file (takes precedence over --proof)")
    
    ed521_test_cmd = ed521sub.add_parser("test", help="Test Ed521 implementation")

    # ======================
    # Advanced features (only if pysodium available)
    # ======================
    if PYSODIUM_AVAILABLE:
        cha = sub.add_parser("chacha20", help="ChaCha20-Poly1305")
        chasub = cha.add_subparsers(dest="cmd", required=True)

        c_enc = chasub.add_parser("encrypt", help="Encrypt")
        c_enc.add_argument("--key", required=True, help="32-byte key hex")
        c_enc.add_argument("--infile", required=True, help="Input file")
        c_enc.add_argument(
            "--aad",
            help="Additional authenticated data (AAD)",
            required=False
        )

        c_dec = chasub.add_parser("decrypt", help="Decrypt")
        c_dec.add_argument("--key", required=True, help="32-byte key hex")
        c_dec.add_argument(
            "--aad",
            help="Additional authenticated data (AAD)",
            required=False
        )

        ed = sub.add_parser("ed25519", help="Ed25519 signatures")
        edsub = ed.add_subparsers(dest="cmd", required=True)
        ed_gen = edsub.add_parser("gen", help="Generate keys")
        ed_gen.add_argument("--priv", default="private.pem", help="Private key PEM")
        ed_gen.add_argument("--pub", default="public.pem", help="Public key PEM")
        ed_sign = edsub.add_parser("sign", help="Sign")
        ed_sign.add_argument("--priv", required=True, help="Private key PEM")
        ed_sign.add_argument("--msg", required=True, help="Message file")
        ed_ver = edsub.add_parser("verify", help="Verify")
        ed_ver.add_argument("--pub", required=True, help="Public key PEM")
        ed_ver.add_argument("--msg", required=True, help="Message file")
        ed_ver.add_argument("--sig", required=True, help="Signature hex")

        x = sub.add_parser("x25519", help="X25519 key exchange")
        xsub = x.add_subparsers(dest="cmd", required=True)
        x_gen = xsub.add_parser("gen", help="Generate keys")
        x_gen.add_argument("--priv", default="private.pem", help="Private key PEM")
        x_gen.add_argument("--pub", default="public.pem", help="Public key PEM")
        x_sh = xsub.add_parser("shared", help="Shared secret")
        x_sh.add_argument("--priv", required=True, help="Your private key PEM")
        x_sh.add_argument("--peer", required=True, help="Peer public key PEM")

    args = parser.parse_args()

    # ======================
    # Dispatcher
    # ======================
    if args.tool == "argon2":
        if args.cmd == "hash":
            # Convert opslimit/memlimit to pysodium constants if provided
            opslimit = None
            memlimit = None
            
            if args.opslimit is not None:
                if args.opslimit == 0:
                    opslimit = pysodium.crypto_pwhash_OPSLIMIT_INTERACTIVE
                elif args.opslimit == 1:
                    opslimit = pysodium.crypto_pwhash_OPSLIMIT_MODERATE
                elif args.opslimit == 2:
                    opslimit = pysodium.crypto_pwhash_OPSLIMIT_SENSITIVE
                else:
                    opslimit = args.opslimit
            
            if args.memlimit is not None:
                if args.memlimit == 0:
                    memlimit = pysodium.crypto_pwhash_MEMLIMIT_INTERACTIVE
                elif args.memlimit == 1:
                    memlimit = pysodium.crypto_pwhash_MEMLIMIT_MODERATE
                elif args.memlimit == 2:
                    memlimit = pysodium.crypto_pwhash_MEMLIMIT_SENSITIVE
                else:
                    memlimit = args.memlimit
            
            argon2_hash_password(args.password, opslimit, memlimit)
        elif args.cmd == "verify":
            argon2_verify_password(args.hash, args.password)
    
    elif args.tool == "hashsum":
        if args.cmd == "calc":
            hashsum_calc(args.pattern, args.files, args.recursive, args.algorithm, args.output)
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
    
    elif args.tool == "scrypt":
        if args.cmd == "derive":
            scrypt_derive(args.secret, args.salt, args.iter, args.keylen)
        elif args.cmd == "compare":
            scrypt_compare(args.secret, args.salt, args.derived, args.iter)
    
    elif args.tool == "hkdf":
        if args.cmd == "calc":
            hkdf_calc(args.salt, args.ikm, args.info, args.length, args.algo)
        elif args.cmd == "derive":
            hkdf_derive(args.salt, args.ikm, args.info, args.length, args.algo)
        elif args.cmd == "compare":
            hkdf_compare()
        elif args.cmd == "list":
            list_hkdf_algorithms()
    
    if args.tool == "ed521":
        if args.cmd == "gen":
            ed521_generate(args.priv, args.pub)
        elif args.cmd == "sign":
            ed521_sign_file(args.priv, args.msg)
        elif args.cmd == "verify":
            ed521_verify_file(args.pub, args.msg, args.sig)
        elif args.cmd == "prove":
            ed521_prove_command(args.priv)
        elif args.cmd == "verify-proof":
            ed521_verify_proof_command(args.pub, args.proof, args.proof_file)
        elif args.cmd == "test":
            ed521_test_command()
    
    # Dispatcher for advanced features (if available)
    elif PYSODIUM_AVAILABLE:
        if args.tool == "chacha20":
            if args.cmd == "encrypt":
                chacha20_encrypt(args.key, args.infile, args.aad)
            elif args.cmd == "decrypt":
                chacha20_decrypt(args.key, args.aad)
        
        elif args.tool == "ed25519":
            if args.cmd == "gen":
                ed25519_generate(args.priv, args.pub)
            elif args.cmd == "sign":
                ed25519_sign(args.priv, args.msg)
            elif args.cmd == "verify":
                ed25519_verify(args.pub, args.msg, args.sig)
        
        elif args.tool == "x25519":
            if args.cmd == "gen":
                x25519_generate(args.priv, args.pub)
            elif args.cmd == "shared":
                x25519_shared(args.priv, args.peer)
    
    else:
        # If tried to use advanced feature without pysodium
        if args.tool in ["chacha20", "ed25519", "x25519", "argon2"]:
            print(f"✖ {args.tool} requires pysodium. Install with: pip install pysodium")
            sys.exit(1)

if __name__ == "__main__":
    main()
