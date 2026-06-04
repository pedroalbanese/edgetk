#!/usr/bin/env python3
"""
EDGE Crypto Toolbox - Pure Python Version
Contains: Ed521, Scrypt, X25519, X448, Hashsum, HMAC, HKDF, Curupira block cipher in AEAD mode LetterSoup, Anubis-GCM
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
import struct
from typing import Tuple, Optional, List
import secrets

# =========================
# X25519 IMPLEMENTATION (Pure Python)
# =========================

# Field modulus p = 2^255 - 19
X25519_P = 2**255 - 19
# Base point u-coordinate (9 in little-endian)
X25519_BASE_POINT = bytes([
    9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
])
X25519_SCALAR_BYTES = 32
X25519_POINT_BYTES = 32

def x25519_modp_add(a: int, b: int) -> int:
    """Modular addition: (a + b) mod p"""
    return (a + b) % X25519_P

def x25519_modp_sub(a: int, b: int) -> int:
    """Modular subtraction: (a - b) mod p"""
    return (a - b) % X25519_P

def x25519_modp_mul(a: int, b: int) -> int:
    """Modular multiplication: (a * b) mod p"""
    return (a * b) % X25519_P

def x25519_modp_sqr(a: int) -> int:
    """Modular squaring: (a * a) mod p"""
    return (a * a) % X25519_P

def x25519_decode_scalar(k: bytes) -> int:
    """Decode a 32-byte scalar for Curve25519 with clamping"""
    if len(k) != 32:
        raise ValueError("Scalar must be 32 bytes")
    
    k_array = bytearray(k)
    # Clear the lowest 3 bits
    k_array[0] &= 0xF8
    # Clear the highest bit
    k_array[31] &= 0x7F
    # Set the second highest bit
    k_array[31] |= 0x40
    
    # Convert to integer (little-endian)
    result = 0
    for i, byte in enumerate(k_array):
        result += byte << (8 * i)
    
    return result

def x25519_decode_u_coordinate(u: bytes) -> int:
    """Decode a 32-byte u-coordinate for Curve25519"""
    if len(u) != 32:
        raise ValueError("u-coordinate must be 32 bytes")
    
    # Clear the high bit for uniformity
    u_array = bytearray(u)
    u_array[31] &= 0x7F
    
    # Convert to integer (little-endian)
    result = 0
    for i, byte in enumerate(u_array):
        result += byte << (8 * i)
    
    return result

def x25519_encode_u_coordinate(u: int) -> bytes:
    """Encode a u-coordinate to 32 bytes (little-endian)"""
    if u < 0 or u >= X25519_P:
        raise ValueError("u-coordinate out of range")
    
    result = bytearray(32)
    for i in range(32):
        result[i] = (u >> (8 * i)) & 0xFF
    return bytes(result)

def x25519_scalar_mult(scalar: bytes, u: bytes) -> bytes:
    """
    X25519 scalar multiplication: k * u
    Implementation following RFC 7748 section 5
    """
    if len(scalar) != 32:
        raise ValueError(f"Scalar must be 32 bytes, got {len(scalar)}")
    if len(u) != 32:
        raise ValueError(f"u-coordinate must be 32 bytes, got {len(u)}")
    
    a = x25519_decode_scalar(scalar)
    u_int = x25519_decode_u_coordinate(u)
    
    # Montgomery ladder
    x1 = u_int
    x2 = 1
    z2 = 0
    x3 = u_int
    z3 = 1
    
    swap = 0
    a_limbs = [(a >> i) & 1 for i in range(255)]
    
    for t in range(254, -1, -1):
        k_t = a_limbs[t]
        swap ^= k_t
        
        # Conditional swap
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        
        swap = k_t
        
        # Montgomery ladder step
        A = x25519_modp_add(x2, z2)
        AA = x25519_modp_sqr(A)
        B = x25519_modp_sub(x2, z2)
        BB = x25519_modp_sqr(B)
        E = x25519_modp_sub(AA, BB)
        C = x25519_modp_add(x3, z3)
        D = x25519_modp_sub(x3, z3)
        DA = x25519_modp_mul(D, A)
        CB = x25519_modp_mul(C, B)
        
        x3 = x25519_modp_sqr(x25519_modp_add(DA, CB))
        z3 = x25519_modp_mul(u_int, x25519_modp_sqr(x25519_modp_sub(DA, CB)))
        x2 = x25519_modp_mul(AA, BB)
        z2 = x25519_modp_mul(E, x25519_modp_add(AA, x25519_modp_mul(121665, E)))
    
    # Final conditional swap
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    
    # Compute result: x2 * z2^(p-2) mod p
    if z2 == 0:
        return bytes([0] * 32)
    
    z2_inv = pow(z2, X25519_P - 2, X25519_P)
    result_int = (x2 * z2_inv) % X25519_P
    
    return x25519_encode_u_coordinate(result_int)

def x25519_base_point_mult(scalar: bytes) -> bytes:
    """Multiply base point by scalar: k * G"""
    return x25519_scalar_mult(scalar, X25519_BASE_POINT)

def x25519_generate_private_key() -> bytes:
    """Generate X25519 private key (scalar)"""
    private_bytes = os.urandom(X25519_SCALAR_BYTES)
    
    # Clamp as per RFC 7748
    private_bytes = bytearray(private_bytes)
    private_bytes[0] &= 0xF8  # Clear bottom 3 bits
    private_bytes[31] &= 0x7F  # Clear highest bit
    private_bytes[31] |= 0x40  # Set second highest bit
    
    return bytes(private_bytes)

def x25519_get_public_key(private_key: bytes) -> bytes:
    """Compute X25519 public key from private key"""
    return x25519_base_point_mult(private_key)

def x25519_shared_secret(private_key: bytes, peer_public_key: bytes) -> bytes:
    """Calculate X25519 shared secret"""
    return x25519_scalar_mult(private_key, peer_public_key)

# =========================
# X448 IMPLEMENTATION (Pure Python)
# =========================

# Field modulus p = 2^448 - 2^224 - 1
X448_P = 2**448 - 2**224 - 1

# Curve constant A = 156326
X448_A = 156326
X448_A24 = 39081  # (A-2)/4 = (156326 - 2)/4 = 39081

# Base point u-coordinate = 5 (little-endian)
X448_BASE_POINT = bytes([
    5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0
])

# Scalar size in bytes
X448_SCALAR_BYTES = 56
X448_POINT_BYTES = 56

def x448_modp_add(a: int, b: int) -> int:
    """Modular addition: (a + b) mod p"""
    return (a + b) % X448_P

def x448_modp_sub(a: int, b: int) -> int:
    """Modular subtraction: (a - b) mod p"""
    return (a - b) % X448_P

def x448_modp_mul(a: int, b: int) -> int:
    """Modular multiplication: (a * b) mod p"""
    return (a * b) % X448_P

def x448_modp_sqr(a: int) -> int:
    """Modular squaring: (a * a) mod p"""
    return (a * a) % X448_P

def x448_modp_inv(a: int) -> int:
    """Modular inverse: a^(p-2) mod p"""
    return pow(a, X448_P - 2, X448_P)

def x448_clamp_scalar(scalar: bytes) -> bytes:
    """
    Clamp scalar according to RFC 7748 section 5 for X448:
    - Clear the 2 least significant bits of the first byte
    - Set the most significant bit of the last byte
    """
    if len(scalar) != X448_SCALAR_BYTES:
        raise ValueError(f"Scalar must be {X448_SCALAR_BYTES} bytes")
    
    clamped = bytearray(scalar)
    # Clear bits 0-1 (2 LSBs) - RFC 7748: set the three least significant bits of the first byte to 0
    clamped[0] &= 0xFC  # 0xFC = 11111100
    
    # Set the most significant bit (bit 447) - RFC 7748: set the most significant bit of the last byte to 1
    clamped[55] |= 0x80  # 0x80 = 10000000
    
    return bytes(clamped)

def x448_decode_scalar(k: bytes) -> int:
    """Decode a 56-byte scalar for X448 with clamping"""
    if len(k) != X448_SCALAR_BYTES:
        raise ValueError(f"Scalar must be {X448_SCALAR_BYTES} bytes")
    
    # Apply clamping
    k_clamped = x448_clamp_scalar(k)
    
    # Convert to integer (little-endian)
    return int.from_bytes(k_clamped, 'little')

def x448_decode_u_coordinate(u: bytes) -> int:
    """Decode a 56-byte u-coordinate for X448"""
    if len(u) != X448_POINT_BYTES:
        raise ValueError(f"u-coordinate must be {X448_POINT_BYTES} bytes")
    
    # Convert to integer (little-endian)
    return int.from_bytes(u, 'little')

def x448_encode_u_coordinate(u: int) -> bytes:
    """Encode a u-coordinate to 56 bytes (little-endian)"""
    if u < 0 or u >= X448_P:
        raise ValueError("u-coordinate out of range")
    
    return u.to_bytes(X448_POINT_BYTES, 'little')

def x448_scalar_mult(scalar: bytes, u: bytes) -> bytes:
    """
    X448 scalar multiplication: k * u
    Implementation following RFC 7748 section 5 exactly
    """
    if len(scalar) != X448_SCALAR_BYTES:
        raise ValueError(f"Scalar must be {X448_SCALAR_BYTES} bytes, got {len(scalar)}")
    if len(u) != X448_POINT_BYTES:
        raise ValueError(f"u-coordinate must be {X448_POINT_BYTES} bytes, got {len(u)}")
    
    # Apply clamping EXACTLY as per RFC 7748
    k = bytearray(scalar)
    k[0] &= 0xFC  # Clear bits 0-1
    k[55] |= 0x80  # Set bit 447
    
    k_int = int.from_bytes(k, 'little')
    u_int = int.from_bytes(u, 'little')
    
    # Montgomery ladder initialization
    x1 = u_int % X448_P
    x2 = 1
    z2 = 0
    x3 = u_int % X448_P
    z3 = 1
    swap = 0
    
    # Process all 448 bits from most significant to least
    for t in range(447, -1, -1):
        k_t = (k_int >> t) & 1
        swap ^= k_t
        
        # Conditional swap
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        
        swap = k_t
        
        # Montgomery ladder step
        a = x448_modp_add(x2, z2)
        aa = x448_modp_sqr(a)
        b = x448_modp_sub(x2, z2)
        bb = x448_modp_sqr(b)
        e = x448_modp_sub(aa, bb)
        c = x448_modp_add(x3, z3)
        d = x448_modp_sub(x3, z3)
        da = x448_modp_mul(d, a)
        cb = x448_modp_mul(c, b)
        
        x3 = x448_modp_sqr(x448_modp_add(da, cb))
        z3_temp = x448_modp_sub(da, cb)
        z3 = x448_modp_mul(x448_modp_sqr(z3_temp), x1)
        
        x2 = x448_modp_mul(aa, bb)
        z2 = x448_modp_mul(e, x448_modp_add(aa, x448_modp_mul(X448_A24, e)))
    
    # Final conditional swap
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    
    # Compute result: x2 * z2^(-1) mod p
    if z2 == 0:
        raise ValueError("X448: low order point")
    
    z2_inv = x448_modp_inv(z2)
    result_int = x448_modp_mul(x2, z2_inv)
    
    return x448_encode_u_coordinate(result_int)

def x448_base_point_mult(scalar: bytes) -> bytes:
    """Multiply base point by scalar: k * G"""
    return x448_scalar_mult(scalar, X448_BASE_POINT)

def x448_generate_private_key() -> bytes:
    """Generate X448 private key with proper clamping"""
    private_bytes = os.urandom(X448_SCALAR_BYTES)
    return x448_clamp_scalar(private_bytes)

def x448_get_public_key(private_key: bytes) -> bytes:
    """Compute X448 public key from private key"""
    return x448_base_point_mult(private_key)

def x448_shared_secret(private_key: bytes, peer_public_key: bytes) -> bytes:
    """Calculate X448 shared secret"""
    return x448_scalar_mult(private_key, peer_public_key)

# =========================
# ANUBIS BLOCK CIPHER IMPLEMENTATION
# =========================

class Anubis:
    """
    Anubis block cipher implementation - faithful translation from Go.
    """
    
    # T-tables exactly as in Go implementation
    _T0 = [
        0xba69d2bb, 0x54a84de5, 0x2f5ebce2, 0x74e8cd25, 0x53a651f7, 0xd3bb6bd0, 0xd2b96fd6, 0x4d9a29b3,
        0x50a05dfd, 0xac458acf, 0x8d070e09, 0xbf63c6a5, 0x70e0dd3d, 0x52a455f1, 0x9a29527b, 0x4c982db5,
        0xeac98f46, 0xd5b773c4, 0x97336655, 0xd1bf63dc, 0x3366ccaa, 0x51a259fb, 0x5bb671c7, 0xa651a2f3,
        0xdea15ffe, 0x48903dad, 0xa84d9ad7, 0x992f5e71, 0xdbab4be0, 0x3264c8ac, 0xb773e695, 0xfce5d732,
        0xe3dbab70, 0x9e214263, 0x913f7e41, 0x9b2b567d, 0xe2d9af76, 0xbb6bd6bd, 0x4182199b, 0x6edca579,
        0xa557aef9, 0xcb8b0b80, 0x6bd6b167, 0x95376e59, 0xa15fbee1, 0xf3fbeb10, 0xb17ffe81, 0x0204080c,
        0xcc851792, 0xc49537a2, 0x1d3a744e, 0x14285078, 0xc39b2bb0, 0x63c69157, 0xdaa94fe6, 0x5dba69d3,
        0x5fbe61df, 0xdca557f2, 0xe9137dfa, 0x1394cd87, 0xe11f7ffe, 0x5ab475c1, 0x6cd8ad75, 0x5cb86dd5,
        0xf7f3fb08, 0x264c98d4, 0xffe3db38, 0xedc79354, 0xe8cd874a, 0x9d274e69, 0x6fdea17f, 0x8e010203,
        0x19326456, 0xa05dbae7, 0xf0fde71a, 0x890f1e11, 0x0f1e3c22, 0x070e1c12, 0xaf4386c5, 0xfbebcb20,
        0x08102030, 0x152a547e, 0x0d1a342e, 0x04081018, 0x01020406, 0x64c88d45, 0xdfa35bf8, 0x76ecc529,
        0x79f2f90b, 0xdda753f4, 0xf48e3d7a, 0x162c5874, 0xfc823f7e, 0x376edcb2, 0xa9736dda, 0x3870e090,
        0xb96fdeb1, 0xd13773e6, 0xe9cf834c, 0xd4be356a, 0x49e355aa, 0xd93b71e2, 0xf1077bf6, 0x0a0f8c05,
        0xd53172e4, 0x1a17880d, 0xff0ef6f1, 0xa8fc2a54, 0xf8843e7c, 0x65d95ebc, 0x9cd2274e, 0x0589468c,
        0x30280c18, 0x894365ca, 0xbd6d68d0, 0x995b61c2, 0x0c0a0306, 0x23bcc19f, 0x41ef57ae, 0x7fced6b1,
        0x43ecd9af, 0x7dcd58b0, 0x47ead8ad, 0x854966cc, 0x7bc8d7b3, 0xe89c3a74, 0x078ac88d, 0xf0883c78,
        0xcf26fae9, 0x62539631, 0xa6f5a753, 0x5a77982d, 0x9752ecc5, 0xdab7b86d, 0x3ba8c793, 0x82c3ae41,
        0xb96b69d2, 0x31a74b96, 0x96ddab4b, 0x9ed1a94f, 0x814f67ce, 0x283c0a14, 0x018f478e, 0xef16f2f9,
        0xee99b577, 0x88cc2244, 0xb364e5d7, 0x9f5eeec1, 0xc2a3be61, 0xacfa2b56, 0x3e21811f, 0x486c1224,
        0x362d831b, 0x6c5a1b36, 0x38240e1c, 0x8cca2346, 0xf304f5f7, 0x0983458a, 0x84c62142, 0x1f9ece81,
        0x39ab4992, 0xb0e82c58, 0xc32cf9ef, 0xbf6ee6d1, 0xe293b671, 0xa0f02850, 0x5c72172e, 0x322b8219,
        0x685c1a34, 0x161d8b0b, 0xdf3efee1, 0x121b8a09, 0x24360912, 0x038cc98f, 0x26358713, 0x25b94e9c,
        0xa37ce1df, 0xb8e42e5c, 0xb762e4d5, 0xa77ae0dd, 0x8b40ebcb, 0x7a47903d, 0xaaffa455, 0x78441e3c,
        0x2e398517, 0x9d5d60c0, 0x00000000, 0x94de254a, 0xf702f4f5, 0xe31cf1ff, 0x6a5f9435, 0x2c3a0b16,
        0xbb68e7d3, 0xc92375ea, 0x9b58efc3, 0xd0b83468, 0xc4a63162, 0x77c2d4b5, 0x67dad0bd, 0x22338611,
        0xe5197efc, 0x8ec9ad47, 0xd334fde7, 0xa4f62952, 0xc0a03060, 0xec9a3b76, 0x46659f23, 0xc72af8ed,
        0x3faec691, 0x4c6a1326, 0x1814060c, 0x141e050a, 0x33a4c597, 0x44661122, 0xc12f77ee, 0xed157cf8,
        0xf5017af4, 0xfd0d78f0, 0xd8b4366c, 0x70481c38, 0xe4963972, 0x79cb59b2, 0x60501830, 0x45e956ac,
        0xf68db37b, 0xfa87b07d, 0x90d82448, 0x80c02040, 0xf28bb279, 0x724b9239, 0xb6eda35b, 0x27bac09d,
        0x0d854488, 0x955162c4, 0x40601020, 0xea9fb475, 0x2a3f8415, 0x11974386, 0x764d933b, 0x2fb6c299,
        0x35a14a94, 0xcea9bd67, 0x06058f03, 0xb4ee2d5a, 0xcaafbc65, 0x4a6f9c25, 0xb5616ad4, 0x1d9d4080,
        0x1b98cf83, 0xb2eba259, 0x3a27801d, 0x21bf4f9e, 0x7c421f3e, 0x0f86ca89, 0x92dbaa49, 0x15914284,
    ]
    
    _T1 = [
        0x69babbd2, 0xa854e54d, 0x5e2fe2bc, 0xe87425cd, 0xa653f751, 0xbbd3d06b, 0xb9d2d66f, 0x9a4db329,
        0xa050fd5d, 0x45accf8a, 0x078d090e, 0x63bfa5c6, 0xe0703ddd, 0xa452f155, 0x299a7b52, 0x984cb52d,
        0xc9ea468f, 0xb7d5c473, 0x33975566, 0xbfd1dc63, 0x6633aacc, 0xa251fb59, 0xb65bc771, 0x51a6f3a2,
        0xa1defe5f, 0x9048ad3d, 0x4da8d79a, 0x2f99715e, 0xabdbe04b, 0x6432acc8, 0x73b795e6, 0xe5fc32d7,
        0xdbe370ab, 0x219e6342, 0x3f91417e, 0x2b9b7d56, 0xd9e276af, 0x6bbbbdd6, 0x82419b19, 0xdc6e79a5,
        0x57a5f9ae, 0x8bcb800b, 0xd66b67b1, 0x3795596e, 0x5fa1e1be, 0xfbf310eb, 0x7fb181fe, 0x04020c08,
        0x85cc9217, 0x95c4a237, 0x3a1d4e74, 0x28147850, 0x9bc3b02b, 0xc6635791, 0xa9dae64f, 0xba5dd369,
        0xbe5fdf61, 0xa5dcf257, 0xfa7d13e9, 0x87cd9413, 0xfe7f1fe1, 0xb45ac175, 0xd86c75ad, 0xb85cd56d,
        0xf3f708fb, 0x4c26d498, 0xe3ff38db, 0xc7ed5493, 0xcde84a87, 0x279d694e, 0xde6f7fa1, 0x018e0302,
        0x32195664, 0x5da0e7ba, 0xfdf01ae7, 0x0f89111e, 0x1e0f223c, 0x0e07121c, 0x43afc586, 0xebfb20cb,
        0x10083020, 0x2a157e54, 0x1a0d2e34, 0x08041810, 0x02010604, 0xc864458d, 0xa3dff85b, 0xec7629c5,
        0xf2790bf9, 0xa7ddf453, 0x7a3d8ef4, 0x2c167458, 0x7e3f82fc, 0x6e37b2dc, 0xda6d73a9, 0x703890e0,
        0x6fb9b1de, 0xe67337d1, 0xcfe94c83, 0x6a35bed4, 0xaa55e349, 0xe2713bd9, 0xf67b07f1, 0x058c0f0a,
        0xe47231d5, 0x0d88171a, 0xf1f60eff, 0x542afca8, 0x7c3e84f8, 0xbc5ed965, 0x4e27d29c, 0x8c468905,
        0x180c2830, 0xca654389, 0xd0686dbd, 0xc2615b99, 0x06030a0c, 0x9fc1bc23, 0xae57ef41, 0xb1d6ce7f,
        0xafd9ec43, 0xb058cd7d, 0xadd8ea47, 0xcc664985, 0xb3d7c87b, 0x743a9ce8, 0x8dc88a07, 0x783c88f0,
        0xe9fa26cf, 0x31965362, 0x53a7f5a6, 0x2d98775a, 0xc5ec5297, 0x6db8b7da, 0x93c7a83b, 0x41aec382,
        0xd2696bb9, 0x964ba731, 0x4babdd96, 0x4fa9d19e, 0xce674f81, 0x140a3c28, 0x8e478f01, 0xf9f216ef,
        0x77b599ee, 0x4422cc88, 0xd7e564b3, 0xc1ee5e9f, 0x61bea3c2, 0x562bfaac, 0x1f81213e, 0x24126c48,
        0x1b832d36, 0x361b5a6c, 0x1c0e2438, 0x4623ca8c, 0xf7f504f3, 0x8a458309, 0x4221c684, 0x81ce9e1f,
        0x9249ab39, 0x582ce8b0, 0xeff92cc3, 0xd1e66ebf, 0x71b693e2, 0x5028f0a0, 0x2e17725c, 0x19822b32,
        0x341a5c68, 0x0b8b1d16, 0xe1fe3edf, 0x098a1b12, 0x12093624, 0x8fc98c03, 0x13873526, 0x9c4eb925,
        0xdfe17ca3, 0x5c2ee4b8, 0xd5e462b7, 0xdde07aa7, 0xcbeb408b, 0x3d90477a, 0x55a4ffaa, 0x3c1e4478,
        0x1785392e, 0xc0605d9d, 0x00000000, 0x4a25de94, 0xf5f402f7, 0xfff11ce3, 0x35945f6a, 0x160b3a2c,
        0xd3e768bb, 0xea7523c9, 0xc3ef589b, 0x6834b8d0, 0x6231a6c4, 0xb5d4c277, 0xbdd0da67, 0x11863322,
        0xfc7e19e5, 0x47adc98e, 0xe7fd34d3, 0x5229f6a4, 0x6030a0c0, 0x763b9aec, 0x239f6546, 0xedf82ac7,
        0x91c6ae3f, 0x26136a4c, 0x0c061418, 0x0a051e14, 0x97c5a433, 0x22116644, 0xee772fc1, 0xf87c15ed,
        0xf47a01f5, 0xf0780dfd, 0x6c36b4d8, 0x381c4870, 0x723996e4, 0xb259cb79, 0x30185060, 0xac56e945,
        0x7bb38df6, 0x7db087fa, 0x4824d890, 0x4020c080, 0x79b28bf2, 0x39924b72, 0x5ba3edb6, 0x9dc0ba27,
        0x8844850d, 0xc4625195, 0x20106040, 0x75b49fea, 0x15843f2a, 0x86439711, 0x3b934d76, 0x99c2b62f,
        0x944aa135, 0x67bda9ce, 0x038f0506, 0x5a2deeb4, 0x65bcafca, 0x259c6f4a, 0xd46a61b5, 0x80409d1d,
        0x83cf981b, 0x59a2ebb2, 0x1d80273a, 0x9e4fbf21, 0x3e1f427c, 0x89ca860f, 0x49aadb92, 0x84429115,
    ]
    
    _T2 = [
        0xd2bbba69, 0x4de554a8, 0xbce22f5e, 0xcd2574e8, 0x51f753a6, 0x6bd0d3bb, 0x6fd6d2b9, 0x29b34d9a,
        0x5dfd50a0, 0x8acfac45, 0x0e098d07, 0xc6a5bf63, 0xdd3d70e0, 0x55f152a4, 0x527b9a29, 0x2db54c98,
        0x8f46eac9, 0x73c4d5b7, 0x66559733, 0x63dcd1bf, 0xccaa3366, 0x59fb51a2, 0x71c75bb6, 0xa2f3a651,
        0x5ffedea1, 0x3dad4890, 0x9ad7a84d, 0x5e71992f, 0x4be0dbab, 0xc8ac3264, 0xe695b773, 0xd732fce5,
        0xab70e3db, 0x42639e21, 0x7e41913f, 0x567d9b2b, 0xaf76e2d9, 0xd6bdbb6b, 0x199b4182, 0xa5796edc,
        0xaef9a557, 0x0b80cb8b, 0xb1676bd6, 0x6e599537, 0xbee1a15f, 0xeb10f3fb, 0xfe81b17f, 0x080c0204,
        0x1792cc85, 0x37a2c495, 0x744e1d3a, 0x50781428, 0x2bb0c39b, 0x915763c6, 0x4fe6daa9, 0x69d35dba,
        0x61df5fbe, 0x57f2dca5, 0xe9137dfa, 0x1394cd87, 0xe11f7ffe, 0x75c15ab4, 0xad756cd8, 0x6dd55cb8,
        0xfb08f7f3, 0x98d4264c, 0xdb38ffe3, 0x9354edc7, 0x874ae8cd, 0x4e699d27, 0xa17f6fde, 0x02038e01,
        0x64561932, 0xbae7a05d, 0xe71af0fd, 0x1e11890f, 0x3c220f1e, 0x1c12070e, 0x86c5af43, 0xcb20fbeb,
        0x20300810, 0x547e152a, 0x342e0d1a, 0x10180408, 0x04060102, 0x8d4564c8, 0x5bf8dfa3, 0xc52976ec,
        0xf90b79f2, 0x53f4dda7, 0xf48e3d7a, 0x5874162c, 0xfc823f7e, 0xdcb2376e, 0xa9736dda, 0xe0903870,
        0xdeb1b96f, 0xd13773e6, 0x834ce9cf, 0xd4be356a, 0x49e355aa, 0xd93b71e2, 0xf1077bf6, 0x0a0f8c05,
        0xd53172e4, 0x1a17880d, 0xff0ef6f1, 0xa8fc2a54, 0xf8843e7c, 0x65d95ebc, 0x9cd2274e, 0x0589468c,
        0x30280c18, 0x894365ca, 0xbd6d68d0, 0x995b61c2, 0x0c0a0306, 0x23bcc19f, 0x41ef57ae, 0x7fced6b1,
        0x43ecd9af, 0x7dcd58b0, 0x47ead8ad, 0x854966cc, 0x7bc8d7b3, 0xe89c3a74, 0x078ac88d, 0xf0883c78,
        0xcf26fae9, 0x62539631, 0xa6f5a753, 0x5a77982d, 0x9752ecc5, 0xdab7b86d, 0x3ba8c793, 0x82c3ae41,
        0xb96b69d2, 0x31a74b96, 0x96ddab4b, 0x9ed1a94f, 0x814f67ce, 0x283c0a14, 0x018f478e, 0xef16f2f9,
        0xee99b577, 0x88cc2244, 0xb364e5d7, 0x9f5eeec1, 0xc2a3be61, 0xacfa2b56, 0x3e21811f, 0x486c1224,
        0x362d831b, 0x6c5a1b36, 0x38240e1c, 0x8cca2346, 0xf304f5f7, 0x0983458a, 0x84c62142, 0x1f9ece81,
        0x39ab4992, 0xb0e82c58, 0xc32cf9ef, 0xbf6ee6d1, 0xe293b671, 0xa0f02850, 0x5c72172e, 0x322b8219,
        0x685c1a34, 0x161d8b0b, 0xdf3efee1, 0x121b8a09, 0x24360912, 0x038cc98f, 0x26358713, 0x25b94e9c,
        0xa37ce1df, 0xb8e42e5c, 0xb762e4d5, 0xa77ae0dd, 0x8b40ebcb, 0x7a47903d, 0xaaffa455, 0x78441e3c,
        0x2e398517, 0x9d5d60c0, 0x00000000, 0x94de254a, 0xf702f4f5, 0xe31cf1ff, 0x6a5f9435, 0x2c3a0b16,
        0xbb68e7d3, 0xc92375ea, 0x9b58efc3, 0xd0b83468, 0xc4a63162, 0x77c2d4b5, 0x67dad0bd, 0x22338611,
        0xe5197efc, 0x8ec9ad47, 0xd334fde7, 0xa4f62952, 0xc0a03060, 0xec9a3b76, 0x46659f23, 0xc72af8ed,
        0x3faec691, 0x4c6a1326, 0x1814060c, 0x141e050a, 0x33a4c597, 0x44661122, 0xc12f77ee, 0xed157cf8,
        0xf5017af4, 0xfd0d78f0, 0xd8b4366c, 0x70481c38, 0xe4963972, 0x79cb59b2, 0x60501830, 0x45e956ac,
        0xf68db37b, 0xfa87b07d, 0x90d82448, 0x80c02040, 0xf28bb279, 0x724b9239, 0xb6eda35b, 0x27bac09d,
        0x0d854488, 0x955162c4, 0x40601020, 0xea9fb475, 0x2a3f8415, 0x11974386, 0x764d933b, 0x2fb6c299,
        0x35a14a94, 0xcea9bd67, 0x06058f03, 0xb4ee2d5a, 0xcaafbc65, 0x4a6f9c25, 0xb5616ad4, 0x1d9d4080,
        0x1b98cf83, 0xb2eba259, 0x3a27801d, 0x21bf4f9e, 0x7c421f3e, 0x0f86ca89, 0x92dbaa49, 0x15914284,
    ]
    
    _T3 = [
        0xbbd269ba, 0xe54da854, 0xe2bc5e2f, 0x25cde874, 0xf751a653, 0xd06bbbd3, 0xd66fb9d2, 0xb3299a4d,
        0xfd5da050, 0xcf8a45ac, 0x090e078d, 0xa5c663bf, 0x3ddde070, 0xf155a452, 0x7b52299a, 0xb52d984c,
        0x468fc9ea, 0xc473b7d5, 0x55663397, 0xdc63bfd1, 0xaacc6633, 0xfb59a251, 0xc771b65b, 0xf3a251a6,
        0xfe5fa1de, 0xad3d9048, 0xd79a4da8, 0x715e2f99, 0xe04babdb, 0xacc86432, 0x95e673b7, 0x32d7e5fc,
        0x70abdbe3, 0x6342219e, 0x417e3f91, 0x7d562b9b, 0x76afd9e2, 0xbdd66bbb, 0x9b198241, 0x79a5dc6e,
        0xf9ae57a5, 0x800b8bcb, 0x67b1d66b, 0x596e3795, 0xe1be5fa1, 0x10ebfbf3, 0x81fe7fb1, 0x0c080402,
        0x921785cc, 0xa23795c4, 0x4e743a1d, 0x78502814, 0xb02b9bc3, 0x5791c663, 0xe64fa9da, 0xd369ba5d,
        0xdf61be5f, 0xf257a5dc, 0x13e9fa7d, 0x941387cd, 0x1fe1fe7f, 0xc175b45a, 0x75add86c, 0xd56db85c,
        0x08fbf3f7, 0xd4984c26, 0x38dbe3ff, 0x5493c7ed, 0x4a87cde8, 0x694e279d, 0x7fa1de6f, 0x0302018e,
        0x56643219, 0xe7ba5da0, 0x1ae7fdf0, 0x111e0f89, 0x223c1e0f, 0x121c0e07, 0xc58643af, 0x20cbebfb,
        0x30201008, 0x7e542a15, 0x2e341a0d, 0x18100804, 0x06040201, 0x458dc864, 0xf85ba3df, 0x29c5ec76,
        0x0bf9f279, 0xf453a7dd, 0x8ef47a3d, 0x74582c16, 0x82fc7e3f, 0xb2dc6e37, 0x73a9da6d, 0x90e07038,
        0xb1de6fb9, 0x37d1e673, 0x4c83cfe9, 0xbed46a35, 0xe349aa55, 0x3bd9e271, 0x07f1f67b, 0x0f0a058c,
        0x31d5e472, 0x171a0d88, 0x0efff1f6, 0xfca8542a, 0x84f87c3e, 0xd965bc5e, 0xd29c4e27, 0x89058c46,
        0x2830180c, 0x4389ca65, 0x6dbdd068, 0x5b99c261, 0x0a0c0603, 0xbc239fc1, 0xef41ae57, 0xce7fb1d6,
        0xec43afd9, 0xcd7db058, 0xea47add8, 0x4985cc66, 0xc87bb3d7, 0x9ce8743a, 0x8a078dc8, 0x88f0783c,
        0x26cfe9fa, 0x53623196, 0xf5a653a7, 0x775a2d98, 0x5297c5ec, 0xb7da6db8, 0xa83b93c7, 0xc38241ae,
        0x6bb9d269, 0xa731964b, 0xdd964bab, 0xd19e4fa9, 0x4f81ce67, 0x3c28140a, 0x8f018e47, 0x16eff9f2,
        0x99ee77b5, 0xcc884422, 0x64b3d7e5, 0x5e9fc1ee, 0xa3c261be, 0xfaac562b, 0x213e1f81, 0x6c482412,
        0x2d361b83, 0x5a6c361b, 0x24381c0e, 0xca8c4623, 0x04f3f7f5, 0x83098a45, 0xc6844221, 0x9e1f81ce,
        0xab399249, 0xe8b0582c, 0x2cc3eff9, 0x6ebfd1e6, 0x93e271b6, 0xf0a05028, 0x725c2e17, 0x2b321982,
        0x5c68341a, 0x1d160b8b, 0x3edfe1fe, 0x1b12098a, 0x36241209, 0x8c038fc9, 0x35261387, 0xb9259c4e,
        0x7ca3dfe1, 0xe4b85c2e, 0x62b7d5e4, 0x7aa7dde0, 0x408bcbeb, 0x477a3d90, 0xffaa55a4, 0x44783c1e,
        0x392e1785, 0x5d9dc060, 0x00000000, 0xde944a25, 0x02f7f5f4, 0x1ce3fff1, 0x5f6a3594, 0x3a2c160b,
        0x68bbd3e7, 0x23c9ea75, 0x589bc3ef, 0xb8d06834, 0xa6c46231, 0xc277b5d4, 0xda67bdd0, 0x33221186,
        0x19e5fc7e, 0xc98e47ad, 0x34d3e7fd, 0xf6a45229, 0xa0c06030, 0x9aec763b, 0x6546239f, 0x2ac7edf8,
        0xae3f91c6, 0x6a4c2613, 0x14180c06, 0x1e140a05, 0xa43397c5, 0x66442211, 0x2fc1ee77, 0x15edf87c,
        0x01f5f47a, 0x0dfdf078, 0xb4d86c36, 0x4870381c, 0x96e47239, 0xcb79b259, 0x50603018, 0xe945ac56,
        0x8df67bb3, 0x87fa7db0, 0xd8904824, 0xc0804020, 0x8bf279b2, 0x4b723992, 0xedb65ba3, 0xba279dc0,
        0x850d8844, 0x5195c462, 0x60402010, 0x9fea75b4, 0x3f2a1584, 0x97118643, 0x4d763b93, 0xb62f99c2,
        0xa135944a, 0xa9ce67bd, 0x0506038f, 0xeeb45a2d, 0xafca65bc, 0x6f4a259c, 0x61b5d46a, 0x9d1d8040,
        0x981b83cf, 0xebb259a2, 0x273a1d80, 0xbf219e4f, 0x427c3e1f, 0x860f89ca, 0xdb9249aa, 0x91158442,
    ]
    
    _T4 = [
        0xbabababa, 0x54545454, 0x2f2f2f2f, 0x74747474, 0x53535353, 0xd3d3d3d3, 0xd2d2d2d2, 0x4d4d4d4d,
        0x50505050, 0xacacacac, 0x8d8d8d8d, 0xbfbfbfbf, 0x70707070, 0x52525252, 0x9a9a9a9a, 0x4c4c4c4c,
        0xeaeaeaea, 0xd5d5d5d5, 0x97979797, 0xd1d1d1d1, 0x33333333, 0x51515151, 0x5b5b5b5b, 0xa6a6a6a6,
        0xdededede, 0x48484848, 0xa8a8a8a8, 0x99999999, 0xdbdbdbdb, 0x32323232, 0xb7b7b7b7, 0xfcfcfcfc,
        0xe3e3e3e3, 0x9e9e9e9e, 0x91919191, 0x9b9b9b9b, 0xe2e2e2e2, 0xbbbbbbbb, 0x41414141, 0x6e6e6e6e,
        0xa5a5a5a5, 0xcbcbcbcb, 0x6b6b6b6b, 0x95959595, 0xa1a1a1a1, 0xf3f3f3f3, 0xb1b1b1b1, 0x02020202,
        0xcccccccc, 0xc4c4c4c4, 0x1d1d1d1d, 0x14141414, 0xc3c3c3c3, 0x63636363, 0xdadadada, 0x5d5d5d5d,
        0x5f5f5f5f, 0xdcdcdcdc, 0x7d7d7d7d, 0xcdcdcdcd, 0x7f7f7f7f, 0x5a5a5a5a, 0x6c6c6c6c, 0x5c5c5c5c,
        0xf7f7f7f7, 0x26262626, 0xffffffff, 0xedededed, 0xe8e8e8e8, 0x9d9d9d9d, 0x6f6f6f6f, 0x8e8e8e8e,
        0x19191919, 0xa0a0a0a0, 0xf0f0f0f0, 0x89898989, 0x0f0f0f0f, 0x07070707, 0xafafafaf, 0xfbfbfbfb,
        0x08080808, 0x15151515, 0x0d0d0d0d, 0x04040404, 0x01010101, 0x64646464, 0xdfdfdfdf, 0x76767676,
        0x79797979, 0xdddddddd, 0x3d3d3d3d, 0x16161616, 0x3f3f3f3f, 0x37373737, 0x6d6d6d6d, 0x38383838,
        0xb9b9b9b9, 0x73737373, 0xe9e9e9e9, 0x35353535, 0x55555555, 0x71717171, 0x7b7b7b7b, 0x8c8c8c8c,
        0x72727272, 0x88888888, 0xf6f6f6f6, 0x2a2a2a2a, 0x3e3e3e3e, 0x5e5e5e5e, 0x27272727, 0x46464646,
        0x0c0c0c0c, 0x65656565, 0x68686868, 0x61616161, 0x03030303, 0xc1c1c1c1, 0x57575757, 0xd6d6d6d6,
        0xd9d9d9d9, 0x58585858, 0xd8d8d8d8, 0x66666666, 0xd7d7d7d7, 0x3a3a3a3a, 0xc8c8c8c8, 0x3c3c3c3c,
        0xfafafafa, 0x96969696, 0xa7a7a7a7, 0x98989898, 0xecececec, 0xb8b8b8b8, 0xc7c7c7c7, 0xaeaeaeae,
        0x69696969, 0x4b4b4b4b, 0xabababab, 0xa9a9a9a9, 0x67676767, 0x0a0a0a0a, 0x47474747, 0xf2f2f2f2,
        0xb5b5b5b5, 0x22222222, 0xe5e5e5e5, 0xeeeeeeee, 0xbebebebe, 0x2b2b2b2b, 0x81818181, 0x12121212,
        0x83838383, 0x1b1b1b1b, 0x0e0e0e0e, 0x23232323, 0xf5f5f5f5, 0x45454545, 0x21212121, 0xcececece,
        0x49494949, 0x2c2c2c2c, 0xf9f9f9f9, 0xe6e6e6e6, 0xb6b6b6b6, 0x28282828, 0x17171717, 0x82828282,
        0x1a1a1a1a, 0x8b8b8b8b, 0xfefefefe, 0x8a8a8a8a, 0x09090909, 0xc9c9c9c9, 0x87878787, 0x4e4e4e4e,
        0xe1e1e1e1, 0x2e2e2e2e, 0xe4e4e4e4, 0xe0e0e0e0, 0xebebebeb, 0x90909090, 0xa4a4a4a4, 0x1e1e1e1e,
        0x85858585, 0x60606060, 0x00000000, 0x25252525, 0xf4f4f4f4, 0xf1f1f1f1, 0x94949494, 0x0b0b0b0b,
        0xe7e7e7e7, 0x75757575, 0xefefefef, 0x34343434, 0x31313131, 0xd4d4d4d4, 0xd0d0d0d0, 0x86868686,
        0x7e7e7e7e, 0xadadadad, 0xfdfdfdfd, 0x29292929, 0x30303030, 0x3b3b3b3b, 0x9f9f9f9f, 0xf8f8f8f8,
        0xc6c6c6c6, 0x13131313, 0x06060606, 0x05050505, 0xc5c5c5c5, 0x11111111, 0x77777777, 0x7c7c7c7c,
        0x7a7a7a7a, 0x78787878, 0x36363636, 0x1c1c1c1c, 0x39393939, 0x59595959, 0x18181818, 0x56565656,
        0xb3b3b3b3, 0xb0b0b0b0, 0x24242424, 0x20202020, 0xb2b2b2b2, 0x92929292, 0xa3a3a3a3, 0xc0c0c0c0,
        0x44444444, 0x62626262, 0x10101010, 0xb4b4b4b4, 0x84848484, 0x43434343, 0x93939393, 0xc2c2c2c2,
        0x4a4a4a4a, 0xbdbdbdbd, 0x8f8f8f8f, 0x2d2d2d2d, 0xbcbcbcbc, 0x9c9c9c9c, 0x6a6a6a6a, 0x40404040,
        0xcfcfcfcf, 0xa2a2a2a2, 0x80808080, 0x4f4f4f4f, 0x1f1f1f1f, 0xcacacaca, 0xaaaaaaaa, 0x42424242,
    ]
    
    _T5 = [
        0x00000000, 0x01020608, 0x02040c10, 0x03060a18, 0x04081820, 0x050a1e28, 0x060c1430, 0x070e1238,
        0x08103040, 0x09123648, 0x0a143c50, 0x0b163a58, 0x0c182860, 0x0d1a2e68, 0x0e1c2470, 0x0f1e2278,
        0x10206080, 0x11226688, 0x12246c90, 0x13266a98, 0x142878a0, 0x152a7ea8, 0x162c74b0, 0x172e72b8,
        0x183050c0, 0x193256c8, 0x1a345cd0, 0x1b365ad8, 0x1c3848e0, 0x1d3a4ee8, 0x1e3c44f0, 0x1f3e42f8,
        0x2040c01d, 0x2142c615, 0x2244cc0d, 0x2346ca05, 0x2448d83d, 0x254ade35, 0x264cd42d, 0x274ed225,
        0x2850f05d, 0x2952f655, 0x2a54fc4d, 0x2b56fa45, 0x2c58e87d, 0x2d5aee75, 0x2e5ce46d, 0x2f5ee265,
        0x3060a09d, 0x3162a695, 0x3264ac8d, 0x3366aa85, 0x3468b8bd, 0x356abeb5, 0x366cb4ad, 0x376eb2a5,
        0x387090dd, 0x397296d5, 0x3a749ccd, 0x3b769ac5, 0x3c7888fd, 0x3d7a8ef5, 0x3e7c84ed, 0x3f7e82e5,
        0x40809d3a, 0x41829b32, 0x4284912a, 0x43869722, 0x4488851a, 0x458a8312, 0x468c890a, 0x478e8f02,
        0x4890ad7a, 0x4992ab72, 0x4a94a16a, 0x4b96a762, 0x4c98b55a, 0x4d9ab352, 0x4e9cb94a, 0x4f9ebf42,
        0x50a0fdba, 0x51a2fbb2, 0x52a4f1aa, 0x53a6f7a2, 0x54a8e59a, 0x55aae392, 0x56ace98a, 0x57aeef82,
        0x58b0cdfa, 0x59b2cbf2, 0x5ab4c1ea, 0x5bb6c7e2, 0x5cb8d5da, 0x5dbad3d2, 0x5ebcd9ca, 0x5fbedfc2,
        0x60c05d27, 0x61c25b2f, 0x62c45137, 0x63c6573f, 0x64c84507, 0x65ca430f, 0x66cc4917, 0x67ce4f1f,
        0x68d06d67, 0x69d26b6f, 0x6ad46177, 0x6bd6677f, 0x6cd87547, 0x6dda734f, 0x6edc7957, 0x6fde7f5f,
        0x70e03da7, 0x71e23baf, 0x72e431b7, 0x73e637bf, 0x74e82587, 0x75ea238f, 0x76ec2997, 0x77ee2f9f,
        0x78f00de7, 0x79f20bef, 0x7af401f7, 0x7bf607ff, 0x7cf815c7, 0x7dfa13cf, 0x7efc19d7, 0x7ffe1fdf,
        0x801d2774, 0x811f217c, 0x82192b64, 0x831b2d6c, 0x84153f54, 0x8517395c, 0x86113344, 0x8713354c,
        0x880d1734, 0x890f113c, 0x8a091b24, 0x8b0b1d2c, 0x8c050f14, 0x8d07091c, 0x8e010304, 0x8f03050c,
        0x903d47f4, 0x913f41fc, 0x92394be4, 0x933b4dec, 0x94355fd4, 0x953759dc, 0x963153c4, 0x973355cc,
        0x982d77b4, 0x992f71bc, 0x9a297ba4, 0x9b2b7dac, 0x9c256f94, 0x9d27699c, 0x9e216384, 0x9f23658c,
        0xa05de769, 0xa15fe161, 0xa259eb79, 0xa35bed71, 0xa455ff49, 0xa557f941, 0xa651f359, 0xa753f551,
        0xa84dd729, 0xa94fd121, 0xaa49db39, 0xab4bdd31, 0xac45cf09, 0xad47c901, 0xae41c319, 0xaf43c511,
        0xb07d87e9, 0xb17f81e1, 0xb2798bf9, 0xb37b8df1, 0xb4759fc9, 0xb57799c1, 0xb67193d9, 0xb77395d1,
        0xb86db7a9, 0xb96fb1a1, 0xba69bbb9, 0xbb6bbdb1, 0xbc65af89, 0xbd67a981, 0xbe61a399, 0xbf63a591,
        0xc09dba4e, 0xc19fbc46, 0xc299b65e, 0xc39bb056, 0xc495a26e, 0xc597a466, 0xc691ae7e, 0xc793a876,
        0xc88d8a0e, 0xc98f8c06, 0xca89861e, 0xcb8b8016, 0xcc85922e, 0xcd879426, 0xce819e3e, 0xcf839836,
        0xd0bddace, 0xd1bfdcc6, 0xd2b9d6de, 0xd3bbd0d6, 0xd4b5c2ee, 0xd5b7c4e6, 0xd6b1cefe, 0xd7b3c8f6,
        0xd8adea8e, 0xd9afec86, 0xdaa9e69e, 0xdbabe096, 0xdca5f2ae, 0xdda7f4a6, 0xdea1febe, 0xdfa3f8b6,
        0xe0dd7a53, 0xe1df7c5b, 0xe2d97643, 0xe3db704b, 0xe4d56273, 0xe5d7647b, 0xe6d16e63, 0xe7d3686b,
        0xe8cd4a13, 0xe9cf4c1b, 0xeac94603, 0xebcb400b, 0xecc55233, 0xedc7543b, 0xeec15e23, 0xefc3582b,
        0xf0fd1ad3, 0xf1ff1cdb, 0xf2f916c3, 0xf3fb10cb, 0xf4f502f3, 0xf5f704fb, 0xf6f10ee3, 0xf7f308eb,
        0xf8ed2a93, 0xf9ef2c9b, 0xfae92683, 0xfbeb208b, 0xfce532b3, 0xfde734bb, 0xfee13ea3, 0xffe338ab,
    ]
    
    # Round constants
    _rc = [
        0xba542f74, 0x53d3d24d, 0x50ac8dbf, 0x70529a4c,
        0xead597d1, 0x33515ba6, 0xde48a899, 0xdb32b7fc,
        0xe39e919b, 0xe2bb416e, 0xa5cb6b95, 0xa1f3b102,
        0xccc41d14, 0xc363da5d, 0x5fdc7dcd, 0x7f5a6c5c,
        0xf726ffed, 0xe89d6f8e, 0x19a0f089,
    ]
    
    # Constants
    _MIN_N = 4
    _MAX_N = 10
    _MIN_ROUNDS = (8 + _MIN_N)
    _MAX_ROUNDS = (8 + _MAX_N)
    _MIN_KEYSIZEB = (4 * _MIN_N)
    _MAX_KEYSIZEB = (4 * _MAX_N)
    _KEYSIZEB = 16  # 128-bit key by default
    _BLOCKSIZE = 128
    _BLOCKSIZEB = (_BLOCKSIZE // 8)
    
    def __init__(self, key: bytes):
        """
        Initialize Anubis cipher with the given key.
        
        Args:
            key: Key bytes (16 bytes for 128-bit key by default)
        
        Raises:
            ValueError: If key length is invalid
        """
        self.key_bits = len(key) * 8
        
        # Determine N length parameter
        if self.key_bits not in [128, 160, 192, 224, 256, 288, 320]:
            raise ValueError(f"Invalid key size: {self.key_bits} bits. "
                           f"Supported sizes: 128, 160, 192, 224, 256, 288, 320 bits")
        
        N = self.key_bits // 32
        
        # Determine number of rounds from key size
        self.R = 8 + N
        
        # Prepare key state (kappa)
        kappa = [0] * self._MAX_N
        inter = [0] * self._MAX_N
        
        # Map cipher key to initial key state (mu) - using XOR like Go code
        for i in range(N):
            pos = i * 4
            kappa[i] = (
                (key[pos] << 24) ^
                (key[pos + 1] << 16) ^
                (key[pos + 2] << 8) ^
                key[pos + 3]
            )
        
        # Generate R + 1 round keys
        self.round_key_enc = [[0, 0, 0, 0] for _ in range(self.R + 1)]
        self.round_key_dec = [[0, 0, 0, 0] for _ in range(self.R + 1)]
        
        for r in range(self.R + 1):
            K0, K1, K2, K3 = 0, 0, 0, 0
            
            # Generate r-th round key K^r
            # Start with kappa[N-1]
            K0 = self._T4[(kappa[N - 1] >> 24) & 0xFF]
            K1 = self._T4[(kappa[N - 1] >> 16) & 0xFF]
            K2 = self._T4[(kappa[N - 1] >> 8) & 0xFF]
            K3 = self._T4[kappa[N - 1] & 0xFF]
            
            # Process remaining kappa values
            for i in range(N - 2, -1, -1):
                K0 = self._T4[(kappa[i] >> 24) & 0xFF] ^ \
                    (self._T5[(K0 >> 24) & 0xFF] & 0xff000000) ^ \
                    (self._T5[(K0 >> 16) & 0xFF] & 0x00ff0000) ^ \
                    (self._T5[(K0 >> 8) & 0xFF] & 0x0000ff00) ^ \
                    (self._T5[K0 & 0xFF] & 0x000000ff)
                
                K1 = self._T4[(kappa[i] >> 16) & 0xFF] ^ \
                    (self._T5[(K1 >> 24) & 0xFF] & 0xff000000) ^ \
                    (self._T5[(K1 >> 16) & 0xFF] & 0x00ff0000) ^ \
                    (self._T5[(K1 >> 8) & 0xFF] & 0x0000ff00) ^ \
                    (self._T5[K1 & 0xFF] & 0x000000ff)
                
                K2 = self._T4[(kappa[i] >> 8) & 0xFF] ^ \
                    (self._T5[(K2 >> 24) & 0xFF] & 0xff000000) ^ \
                    (self._T5[(K2 >> 16) & 0xFF] & 0x00ff0000) ^ \
                    (self._T5[(K2 >> 8) & 0xFF] & 0x0000ff00) ^ \
                    (self._T5[K2 & 0xFF] & 0x000000ff)
                
                K3 = self._T4[kappa[i] & 0xFF] ^ \
                    (self._T5[(K3 >> 24) & 0xFF] & 0xff000000) ^ \
                    (self._T5[(K3 >> 16) & 0xFF] & 0x00ff0000) ^ \
                    (self._T5[(K3 >> 8) & 0xFF] & 0x0000ff00) ^ \
                    (self._T5[K3 & 0xFF] & 0x000000ff)
            
            self.round_key_enc[r][0] = K0
            self.round_key_enc[r][1] = K1
            self.round_key_enc[r][2] = K2
            self.round_key_enc[r][3] = K3
            
            # Compute kappa^{r+1} from kappa^r
            if r == self.R:
                break
            
            for i in range(N):
                j = i
                inter[i] = self._T0[(kappa[j] >> 24) & 0xFF]
                
                j -= 1
                if j < 0:
                    j = N - 1
                inter[i] ^= self._T1[(kappa[j] >> 16) & 0xFF]
                
                j -= 1
                if j < 0:
                    j = N - 1
                inter[i] ^= self._T2[(kappa[j] >> 8) & 0xFF]
                
                j -= 1
                if j < 0:
                    j = N - 1
                inter[i] ^= self._T3[kappa[j] & 0xFF]
            
            kappa[0] = inter[0] ^ self._rc[r]
            for i in range(1, N):
                kappa[i] = inter[i]
        
        # Generate inverse key schedule
        for i in range(4):
            self.round_key_dec[0][i] = self.round_key_enc[self.R][i]
            self.round_key_dec[self.R][i] = self.round_key_enc[0][i]
        
        for r in range(1, self.R):
            for i in range(4):
                v = self.round_key_enc[self.R - r][i]
                self.round_key_dec[r][i] = (
                    self._T0[self._T4[(v >> 24) & 0xFF] & 0xFF] ^
                    self._T1[self._T4[(v >> 16) & 0xFF] & 0xFF] ^
                    self._T2[self._T4[(v >> 8) & 0xFF] & 0xFF] ^
                    self._T3[self._T4[v & 0xFF] & 0xFF]
                )
    
    @property
    def block_size(self) -> int:
        """Return the block size in bytes."""
        return self._BLOCKSIZEB
    
    @property
    def key_size(self) -> int:
        """Return the key size in bytes."""
        return self.key_bits // 8
    
    def _crypt(self, input_bytes: bytes, round_key: List[List[int]], R: int) -> bytes:
        """Internal encryption/decryption function."""
        if len(input_bytes) != self.block_size:
            raise ValueError(f"Input block must be {self.block_size} bytes")
        
        state = [0, 0, 0, 0]
        inter = [0, 0, 0, 0]
        
        # Map plaintext block to cipher state and add initial round key
        # Using XOR exactly as in Go code
        for i in range(4):
            pos = i * 4
            state[i] = (
                (input_bytes[pos] << 24) ^
                (input_bytes[pos + 1] << 16) ^
                (input_bytes[pos + 2] << 8) ^
                input_bytes[pos + 3]
            ) ^ round_key[0][i]
        
        # R - 1 full rounds
        for r in range(1, R):
            inter[0] = (
                self._T0[(state[0] >> 24) & 0xFF] ^
                self._T1[(state[1] >> 24) & 0xFF] ^
                self._T2[(state[2] >> 24) & 0xFF] ^
                self._T3[(state[3] >> 24) & 0xFF] ^
                round_key[r][0]
            )
            inter[1] = (
                self._T0[(state[0] >> 16) & 0xFF] ^
                self._T1[(state[1] >> 16) & 0xFF] ^
                self._T2[(state[2] >> 16) & 0xFF] ^
                self._T3[(state[3] >> 16) & 0xFF] ^
                round_key[r][1]
            )
            inter[2] = (
                self._T0[(state[0] >> 8) & 0xFF] ^
                self._T1[(state[1] >> 8) & 0xFF] ^
                self._T2[(state[2] >> 8) & 0xFF] ^
                self._T3[(state[3] >> 8) & 0xFF] ^
                round_key[r][2]
            )
            inter[3] = (
                self._T0[state[0] & 0xFF] ^
                self._T1[state[1] & 0xFF] ^
                self._T2[state[2] & 0xFF] ^
                self._T3[state[3] & 0xFF] ^
                round_key[r][3]
            )
            
            state[0] = inter[0]
            state[1] = inter[1]
            state[2] = inter[2]
            state[3] = inter[3]
        
        # Last round - exactly as in Go code with proper masking
        inter[0] = (
            (self._T0[(state[0] >> 24) & 0xFF] & 0xff000000) ^
            (self._T1[(state[1] >> 24) & 0xFF] & 0x00ff0000) ^
            (self._T2[(state[2] >> 24) & 0xFF] & 0x0000ff00) ^
            (self._T3[(state[3] >> 24) & 0xFF] & 0x000000ff) ^
            round_key[R][0]
        )
        inter[1] = (
            (self._T0[(state[0] >> 16) & 0xFF] & 0xff000000) ^
            (self._T1[(state[1] >> 16) & 0xFF] & 0x00ff0000) ^
            (self._T2[(state[2] >> 16) & 0xFF] & 0x0000ff00) ^
            (self._T3[(state[3] >> 16) & 0xFF] & 0x000000ff) ^
            round_key[R][1]
        )
        inter[2] = (
            (self._T0[(state[0] >> 8) & 0xFF] & 0xff000000) ^
            (self._T1[(state[1] >> 8) & 0xFF] & 0x00ff0000) ^
            (self._T2[(state[2] >> 8) & 0xFF] & 0x0000ff00) ^
            (self._T3[(state[3] >> 8) & 0xFF] & 0x000000ff) ^
            round_key[R][2]
        )
        inter[3] = (
            (self._T0[state[0] & 0xFF] & 0xff000000) ^
            (self._T1[state[1] & 0xFF] & 0x00ff0000) ^
            (self._T2[state[2] & 0xFF] & 0x0000ff00) ^
            (self._T3[state[3] & 0xFF] & 0x000000ff) ^
            round_key[R][3]
        )
        
        # Map cipher state to output bytes
        output = bytearray(self.block_size)
        for i in range(4):
            w = inter[i]
            pos = i * 4
            output[pos] = (w >> 24) & 0xFF
            output[pos + 1] = (w >> 16) & 0xFF
            output[pos + 2] = (w >> 8) & 0xFF
            output[pos + 3] = w & 0xFF
        
        return bytes(output)
    
    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypt a 16-byte block of plaintext.
        
        Args:
            plaintext: 16 bytes of plaintext to encrypt
        
        Returns:
            16 bytes of ciphertext
        """
        return self._crypt(plaintext, self.round_key_enc, self.R)
    
    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        Decrypt a 16-byte block of ciphertext.
        
        Args:
            ciphertext: 16 bytes of ciphertext to decrypt
        
        Returns:
            16 bytes of plaintext
        """
        return self._crypt(ciphertext, self.round_key_dec, self.R)

def new(key: bytes) -> Anubis:
    """
    Create a new Anubis cipher instance.
    
    Args:
        key: Key bytes (16 bytes for 128-bit key by default)
    
    Returns:
        Anubis cipher instance
    """
    return Anubis(key)

# =========================
# ANUBIS GCM IMPLEMENTATION
# =========================

class AnubisGCM:
    """
    Galois/Counter Mode for Anubis.
    Implements authenticated encryption with associated data.
    Compatible with Go's crypto/cipher interface.
    """
    
    # Block size in bytes (Anubis is 128-bit)
    _BLOCK_SIZE = 16
    
    def __init__(self, cipher: Anubis, nonce: Optional[bytes] = None, tag_size: int = 16):
        """
        Initialize GCM mode for Anubis.
        
        Args:
            cipher: Anubis cipher instance
            nonce: Nonce/IV (if None, will be generated)
            tag_size: Size of authentication tag in bytes (must be between 12 and 16)
        
        Raises:
            ValueError: If tag_size is invalid
        """
        if tag_size < 12 or tag_size > 16:
            raise ValueError("tag_size must be between 12 and 16 bytes")
        
        self.cipher = cipher
        self.tag_size = tag_size
        
        if nonce is None:
            # Generate random nonce (96 bits recommended by NIST)
            self.nonce = os.urandom(12)
        else:
            self.nonce = nonce
        
        # Initialize GHASH key
        self._init_ghash()
    
    def _init_ghash(self):
        """Initialize GHASH key (H)."""
        # H = E_K(0^128)
        zero_block = bytes(self._BLOCK_SIZE)
        self._ghash_key = self.cipher.encrypt(zero_block)
    
    def _ghash(self, data: bytes) -> bytes:
        """
        GHASH function (Galois Hash).
        
        Args:
            data: Data to hash (must be multiple of 16 bytes)
        
        Returns:
            16-byte hash
        """
        if not data:
            return bytes(self._BLOCK_SIZE)
        
        # Pad data to multiple of 16 bytes if necessary
        if len(data) % self._BLOCK_SIZE != 0:
            padding = self._BLOCK_SIZE - (len(data) % self._BLOCK_SIZE)
            data = data + bytes(padding)
        
        # Convert H to integer for multiplication
        H = int.from_bytes(self._ghash_key, 'big')
        
        # Initialize result
        result = 0
        
        # Process 16-byte blocks
        for i in range(0, len(data), self._BLOCK_SIZE):
            block = data[i:i + self._BLOCK_SIZE]
            # Convert block to integer (big-endian)
            block_int = int.from_bytes(block, 'big')
            
            # Multiply: result = (result XOR block) * H in GF(2^128)
            result ^= block_int
            result = self._gmult(result, H)
        
        return result.to_bytes(self._BLOCK_SIZE, 'big')
    
    def _gmult(self, x: int, y: int) -> int:
        """
        Multiplication in GF(2^128) with irreducible polynomial
        x^128 + x^7 + x^2 + x + 1.
        
        Args:
            x: First 128-bit integer
            y: Second 128-bit integer
        
        Returns:
            Product in GF(2^128)
        """
        # Russian peasant algorithm
        z = 0
        v = y
        
        # Process 128 bits
        for i in range(127, -1, -1):
            if (x >> i) & 1:
                z ^= v
            
            # Reduce v if MSB is set
            if v & 1:
                v = (v >> 1) ^ 0xE1000000000000000000000000000000
            else:
                v >>= 1
        
        return z
    
    def _inc32(self, counter_block: bytes) -> bytes:
        """
        Increment the rightmost 32 bits of a 16-byte block.
        
        Args:
            counter_block: 16-byte counter block
        
        Returns:
            Incremented counter block
        """
        # Extract the last 4 bytes (32 bits)
        counter_int = int.from_bytes(counter_block[12:], 'big')
        counter_int = (counter_int + 1) & 0xFFFFFFFF
        
        # Reconstruct the block
        return counter_block[:12] + counter_int.to_bytes(4, 'big')
    
    def _compute_tag(self, ciphertext: bytes, associated_data: bytes) -> bytes:
        """
        Compute authentication tag.
        
        Args:
            ciphertext: Encrypted data
            associated_data: Associated data
        
        Returns:
            Authentication tag
        """
        # Encode lengths
        len_a = len(associated_data) * 8  # bits
        len_c = len(ciphertext) * 8       # bits
        
        len_block = struct.pack('>QQ', len_a, len_c)
        
        # GHASH input: A || C || len(A) || len(C)
        # Note: A and C are zero-padded to 16-byte boundaries
        auth_data = associated_data
        if len(auth_data) % self._BLOCK_SIZE != 0:
            padding = self._BLOCK_SIZE - (len(auth_data) % self._BLOCK_SIZE)
            auth_data = auth_data + bytes(padding)
        
        cipher_data = ciphertext
        if len(cipher_data) % self._BLOCK_SIZE != 0:
            padding = self._BLOCK_SIZE - (len(cipher_data) % self._BLOCK_SIZE)
            cipher_data = cipher_data + bytes(padding)
        
        ghash_input = auth_data + cipher_data + len_block
        
        # Compute GHASH
        S = self._ghash(ghash_input)
        
        # Compute tag: T = MSB_t(GCTR_K(J0, S))
        # where J0 is the initial counter block
        if len(self.nonce) == 12:
            # For 96-bit nonce: J0 = nonce || 0^31 || 1
            J0 = self.nonce + b'\x00\x00\x00\x01'
        else:
            # For other nonce lengths: J0 = GHASH_H(nonce || 0^{s+64} || len(nonce))
            s = (16 - (len(self.nonce) % 16)) % 16
            nonce_padded = self.nonce + bytes(s) + b'\x00\x00\x00\x00\x00\x00\x00\x00' + struct.pack('>Q', len(self.nonce) * 8)
            J0 = self._ghash(nonce_padded)
        
        # Encrypt J0 to get tag
        tag_full = self._gctr(J0, S)
        
        # Truncate to tag_size
        return tag_full[:self.tag_size]
    
    def _gctr(self, icb: bytes, X: bytes) -> bytes:
        """
        GCTR function (Counter Mode).
        
        Args:
            icb: Initial counter block
            X: Data to encrypt/decrypt
        
        Returns:
            Encrypted/decrypted data
        """
        if not X:
            return b''
        
        # Calculate number of blocks
        n = (len(X) + self._BLOCK_SIZE - 1) // self._BLOCK_SIZE
        
        Y_blocks = []
        cb = icb
        
        for i in range(n):
            # Encrypt counter block
            encrypted_cb = self.cipher.encrypt(cb)
            
            # Determine block size (full block except for last)
            if i == n - 1:
                block_size = len(X) % self._BLOCK_SIZE
                if block_size == 0:
                    block_size = self._BLOCK_SIZE
            else:
                block_size = self._BLOCK_SIZE
            
            # XOR with plaintext
            block_start = i * self._BLOCK_SIZE
            block_end = block_start + block_size
            X_block = X[block_start:block_end]
            
            Y_block = bytes(x ^ y for x, y in zip(X_block, encrypted_cb[:block_size]))
            Y_blocks.append(Y_block)
            
            # Increment counter
            cb = self._inc32(cb)
        
        return b''.join(Y_blocks)
    
    def encrypt(self, plaintext: bytes, associated_data: bytes = b'') -> Tuple[bytes, bytes]:
        """
        Encrypt plaintext with authenticated encryption.
        
        Args:
            plaintext: Data to encrypt
            associated_data: Associated data to authenticate (but not encrypt)
        
        Returns:
            Tuple of (ciphertext, tag)
        """
        # Generate initial counter block
        if len(self.nonce) == 12:
            # For 96-bit nonce: J0 = nonce || 0^31 || 1
            icb = self.nonce + b'\x00\x00\x00\x01'
        else:
            # For other nonce lengths
            s = (16 - (len(self.nonce) % 16)) % 16
            nonce_padded = self.nonce + bytes(s) + b'\x00\x00\x00\x00\x00\x00\x00\x00' + struct.pack('>Q', len(self.nonce) * 8)
            icb = self._ghash(nonce_padded)
        
        # Increment ICB for first data block
        cb = self._inc32(icb)
        
        # Encrypt plaintext using GCTR
        ciphertext = self._gctr(cb, plaintext)
        
        # Compute authentication tag
        tag = self._compute_tag(ciphertext, associated_data)
        
        return ciphertext, tag
    
    def decrypt(self, ciphertext: bytes, tag: bytes, associated_data: bytes = b'') -> Optional[bytes]:
        """
        Decrypt ciphertext with authentication.
        
        Args:
            ciphertext: Data to decrypt
            tag: Authentication tag
            associated_data: Associated data
        
        Returns:
            Decrypted plaintext or None if authentication fails
        """
        # Verify tag
        expected_tag = self._compute_tag(ciphertext, associated_data)
        
        # Constant-time comparison
        if not self._constant_time_compare(tag, expected_tag):
            return None
        
        # Generate initial counter block (same as encryption)
        if len(self.nonce) == 12:
            icb = self.nonce + b'\x00\x00\x00\x01'
        else:
            s = (16 - (len(self.nonce) % 16)) % 16
            nonce_padded = self.nonce + bytes(s) + b'\x00\x00\x00\x00\x00\x00\x00\x00' + struct.pack('>Q', len(self.nonce) * 8)
            icb = self._ghash(nonce_padded)
        
        # Increment ICB for first data block
        cb = self._inc32(icb)
        
        # Decrypt ciphertext using GCTR (same as encryption)
        plaintext = self._gctr(cb, ciphertext)
        
        return plaintext
    
    def _constant_time_compare(self, a: bytes, b: bytes) -> bool:
        """
        Constant-time comparison to prevent timing attacks.
        
        Args:
            a: First byte string
            b: Second byte string
        
        Returns:
            True if strings are equal, False otherwise
        """
        if len(a) != len(b):
            return False
        
        result = 0
        for x, y in zip(a, b):
            result |= x ^ y
        
        return result == 0

# =========================
# ANUBIS-GCM WRAPPER FOR CLI
# =========================

def anubis_encrypt(key_hex: str, infile: Optional[str] = None, 
                   aad: Optional[str] = None, outfile: Optional[str] = None,
                   tag_size: int = 16, nonce: Optional[str] = None):
    """Encrypt with Anubis-GCM - FIXED to match standard GCM format"""
    try:
        key = bytes.fromhex(key_hex)
        
        # Check key sizes for Anubis
        if len(key) * 8 not in [128, 160, 192, 224, 256, 288, 320]:
            raise ValueError(f"Anubis key must be 128, 160, 192, 224, 256, 288, or 320 bits, got {len(key)*8} bits")
        
        cipher = Anubis(key)
        
        if infile:
            with open(infile, "rb") as f:
                plaintext = f.read()
            data_source = f"file: {infile}"
        else:
            # Read from stdin
            plaintext = sys.stdin.buffer.read()
            data_source = "stdin"
        
        if len(plaintext) == 0:
            raise ValueError("No plaintext data to encrypt")
        
        # Use provided nonce or generate
        if nonce:
            nonce_bytes = bytes.fromhex(nonce)
        else:
            nonce_bytes = None
        
        gcm = AnubisGCM(cipher, nonce_bytes, tag_size)
        
        # Convert AAD
        if aad is None:
            aad_bytes = b''
        elif isinstance(aad, str):
            aad_bytes = aad.encode('utf-8')
        else:
            aad_bytes = aad
        
        # Encrypt - this returns (ciphertext, tag)
        ciphertext, tag = gcm.encrypt(plaintext, aad_bytes)
        
        # FIXED: Output format: nonce + ciphertext + tag (like standard GCM)
        # This matches the PHP and Go implementations
        output = gcm.nonce + ciphertext + tag
        
        if outfile:
            with open(outfile, "wb") as f:
                f.write(output)
            print(f"✔ Encrypted to {outfile}", file=sys.stderr)
            print(f"Data source: {data_source}", file=sys.stderr)
            print(f"Key size: {len(key)*8} bits", file=sys.stderr)
            print(f"Nonce: {gcm.nonce.hex()}", file=sys.stderr)
            print(f"Nonce size: {len(gcm.nonce)} bytes", file=sys.stderr)
            print(f"Ciphertext length: {len(ciphertext)} bytes", file=sys.stderr)
            print(f"Tag ({tag_size} bytes): {tag.hex()}", file=sys.stderr)
            print(f"Total output: {len(output)} bytes", file=sys.stderr)
        else:
            sys.stdout.buffer.write(output)
        
        return output
        
    except Exception as e:
        print(f"✖ Encryption failed: {e}", file=sys.stderr)
        sys.exit(1)

def anubis_decrypt(key_hex: str, infile: Optional[str] = None, 
                   aad: Optional[str] = None, outfile: Optional[str] = None,
                   tag_size: int = 16):
    """Decrypt with Anubis-GCM - FIXED to match standard GCM format"""
    try:
        key = bytes.fromhex(key_hex)
        
        # Check key sizes for Anubis
        if len(key) * 8 not in [128, 160, 192, 224, 256, 288, 320]:
            raise ValueError(f"Anubis key must be 128, 160, 192, 224, 256, 288, or 320 bits, got {len(key)*8} bits")
        
        cipher = Anubis(key)
        
        if infile:
            with open(infile, "rb") as f:
                data = f.read()
            data_source = f"file: {infile}"
        else:
            # Read from stdin
            print("Reading ciphertext from stdin...", file=sys.stderr)
            data = sys.stdin.buffer.read()
            data_source = "stdin"
        
        # Minimum data needed: nonce (12) + tag (tag_size)
        min_size = 12 + tag_size
        if len(data) < min_size:
            print(f"✖ Data too short, need at least {min_size} bytes for nonce + tag", file=sys.stderr)
            sys.exit(1)
        
        # FIXED: Parse input: nonce (12 bytes) + ciphertext + tag (tag_size bytes)
        # This matches the format: nonce + ciphertext + tag
        nonce = data[:12]
        tag = data[-tag_size:]  # Last tag_size bytes
        ciphertext = data[12:-tag_size]  # Everything between nonce and tag
        
        # Initialize GCM with the nonce
        gcm = AnubisGCM(cipher, nonce, tag_size)
        
        # Convert AAD
        if aad is None:
            aad_bytes = b''
        elif isinstance(aad, str):
            aad_bytes = aad.encode('utf-8')
        else:
            aad_bytes = aad
        
        # Decrypt
        plaintext = gcm.decrypt(ciphertext, tag, aad_bytes)
        
        if plaintext is None:
            raise ValueError("Authentication failed! Invalid tag or corrupted data")
        
        if outfile:
            with open(outfile, "wb") as f:
                f.write(plaintext)
            print(f"✔ Decrypted to {outfile}", file=sys.stderr)
            print(f"Data source: {data_source}", file=sys.stderr)
            print(f"Key size: {len(key)*8} bits", file=sys.stderr)
            print(f"Nonce: {nonce.hex()}", file=sys.stderr)
            print(f"Nonce size: {len(nonce)} bytes", file=sys.stderr)
            print(f"Tag ({tag_size} bytes): {tag.hex()}", file=sys.stderr)
            print(f"Ciphertext length: {len(ciphertext)} bytes", file=sys.stderr)
        else:
            sys.stdout.buffer.write(plaintext)
        
        return plaintext
        
    except Exception as e:
        print(f"✖ Decryption failed: {e}", file=sys.stderr)
        sys.exit(1)

# =========================
# CURUPIRA BLOCK CIPHER IN AEAD MODE LETTERSOUP
# =========================

class KeySizeError(Exception):
    def __init__(self, size: int):
        self.size = size
        super().__init__(f"curupira1: invalid key size {size}")

class Curupira1:
    BLOCK_SIZE = 12
    
    def __init__(self, key: bytes):
        self.key = key
        self.key_size = len(key)
        
        if self.key_size not in [12, 18, 24]:
            raise KeySizeError(self.key_size)
        
        self._init_xtimes_table()
        self._init_sbox_table()
        self._expand_key()
    
    def _init_xtimes_table(self):
        """Initialize xTimes table (multiplication by 2 in GF(2^8))"""
        self.xtimes_table = [0] * 256
        for u in range(256):
            d = u << 1
            if d >= 0x100:
                d = d ^ 0x14D
            self.xtimes_table[u] = d & 0xFF
    
    def _init_sbox_table(self):
        """Initialize S-Box table according to Curupira algorithm"""
        P = [0x3, 0xF, 0xE, 0x0, 0x5, 0x4, 0xB, 0xC,
             0xD, 0xA, 0x9, 0x6, 0x7, 0x8, 0x2, 0x1]
        Q = [0x9, 0xE, 0x5, 0x6, 0xA, 0x2, 0x3, 0xC,
             0xF, 0x0, 0x4, 0xD, 0x7, 0xB, 0x1, 0x8]
        
        self.sbox_table = [0] * 256
        
        for u in range(256):
            uh1 = P[(u >> 4) & 0xF]
            ul1 = Q[u & 0xF]
            uh2 = Q[((uh1 & 0xC) ^ ((ul1 >> 2) & 0x3)) & 0xF]
            ul2 = P[(((uh1 << 2) & 0xC) ^ (ul1 & 0x3)) & 0xF]
            uh1 = P[((uh2 & 0xC) ^ ((ul2 >> 2) & 0x3)) & 0xF]
            ul1 = Q[(((uh2 << 2) & 0xC) ^ (ul2 & 0x3)) & 0xF]
            
            self.sbox_table[u] = ((uh1 << 4) ^ ul1) & 0xFF
    
    def xtimes(self, u: int) -> int:
        """Multiplication by 2 in GF(2^8)"""
        return self.xtimes_table[u & 0xFF]
    
    def ctimes(self, u: int) -> int:
        """cTimes transformation as per specification"""
        return self.xtimes(
            self.xtimes(
                self.xtimes(
                    self.xtimes(u) ^ u
                ) ^ u
            )
        )
    
    def sbox(self, u: int) -> int:
        """Apply S-Box"""
        return self.sbox_table[u & 0xFF]
    
    def _dtimesa(self, a: List[int], j: int, b: List[int]):
        """dTimes transformation for linear diffusion layer"""
        d = 3 * j
        v = self.xtimes(a[0 + d] ^ a[1 + d] ^ a[2 + d])
        w = self.xtimes(v)
        
        b[0 + d] = a[0 + d] ^ v
        b[1 + d] = a[1 + d] ^ w
        b[2 + d] = a[2 + d] ^ v ^ w
    
    def _etimesa(self, a: List[int], j: int, b: List[int], e: bool):
        """eTimes transformation for key expansion"""
        d = 3 * j
        v = a[0 + d] ^ a[1 + d] ^ a[2 + d]
        
        if e:
            v = self.ctimes(v)
        else:
            v = self.ctimes(v) ^ v
        
        b[0 + d] = a[0 + d] ^ v
        b[1 + d] = a[1 + d] ^ v
        b[2 + d] = a[2 + d] ^ v
    
    def _apply_nonlinear_layer(self, a: List[int]) -> List[int]:
        """Apply nonlinear layer (S-Box)"""
        return [self.sbox(x) for x in a]
    
    def _apply_permutation_layer(self, a: List[int]) -> List[int]:
        """Apply permutation layer"""
        b = [0] * 12
        
        for i in range(3):
            for j in range(4):
                b[i + 3 * j] = a[i + 3 * (i ^ j)]
        
        return b
    
    def _apply_linear_diffusion_layer(self, a: List[int]) -> List[int]:
        """Apply linear diffusion layer"""
        b = [0] * 12
        
        for j in range(4):
            self._dtimesa(a, j, b)
        
        return b
    
    def _apply_key_addition(self, a: List[int], kr: List[int]) -> List[int]:
        """Key addition (XOR)"""
        return [a[i] ^ kr[i] for i in range(12)]
    
    def _calculate_schedule_constant(self, s: int, key_bits: int) -> List[int]:
        """Calculate constant for key expansion"""
        t = key_bits // 48
        q = [0] * (3 * 2 * t)
        
        if s == 0:
            return q
        
        for j in range(2 * t):
            q[3 * j] = self.sbox(2 * t * (s - 1) + j)
        
        return q
    
    def _apply_constant_addition(self, Kr: List[int], subkey_rank: int, 
                                 key_bits: int, t: int) -> List[int]:
        """Constant addition in key expansion"""
        b = Kr.copy()
        q = self._calculate_schedule_constant(subkey_rank, key_bits)
        
        for i in range(3):
            for j in range(2 * t):
                idx = i + 3 * j
                b[idx] ^= q[idx]
        
        return b
    
    def _apply_cyclic_shift(self, a: List[int], t: int) -> List[int]:
        """Apply cyclic shift in key expansion"""
        length = 3 * 2 * t
        b = [0] * length
        
        for j in range(2 * t):
            b[3 * j] = a[3 * j]
            b[1 + 3 * j] = a[1 + 3 * ((j + 1) % (2 * t))]
            
            if j > 0:
                b[2 + 3 * j] = a[2 + 3 * ((j - 1) % (2 * t))]
            else:
                b[2] = a[2 + 3 * (2 * t - 1)]
        
        return b
    
    def _apply_linear_diffusion(self, a: List[int], t: int) -> List[int]:
        """Apply linear diffusion in key expansion"""
        length = 3 * 2 * t
        b = [0] * length
        
        for j in range(2 * t):
            self._etimesa(a, j, b, True)
        
        return b
    
    def _calculate_next_subkey(self, Kr: List[int], subkey_rank: int,
                              key_bits: int, t: int) -> List[int]:
        """Calculate next subkey"""
        return self._apply_linear_diffusion(
            self._apply_cyclic_shift(
                self._apply_constant_addition(Kr, subkey_rank, key_bits, t),
                t
            ),
            t
        )
    
    def _select_round_key(self, Kr: List[int]) -> List[int]:
        """Select round key"""
        kr = [0] * 12
        
        for j in range(4):
            kr[3 * j] = self.sbox(Kr[3 * j])
        
        for i in range(1, 3):
            for j in range(4):
                kr[i + 3 * j] = Kr[i + 3 * j]
        
        return kr
    
    def _expand_key(self):
        """Expand key and generate encryption and decryption subkeys"""
        key_bits = self.key_size * 8
        
        if key_bits == 96:
            self.R = 10
        elif key_bits == 144:
            self.R = 14
        elif key_bits == 192:
            self.R = 18
        
        self.key_bits = key_bits
        self.t = key_bits // 48
        
        Kr = list(self.key)
        
        self.encryption_round_keys = [None] * (self.R + 1)
        self.decryption_round_keys = [None] * (self.R + 1)
        
        kr = self._select_round_key(Kr)
        self.encryption_round_keys[0] = kr
        
        for r in range(1, self.R + 1):
            Kr = self._calculate_next_subkey(Kr, r, self.key_bits, self.t)
            kr = self._select_round_key(Kr)
            
            self.encryption_round_keys[r] = kr
            self.decryption_round_keys[self.R - r] = self._apply_linear_diffusion_layer(kr)
        
        self.decryption_round_keys[0] = self.encryption_round_keys[self.R]
        self.decryption_round_keys[self.R] = self.encryption_round_keys[0]
    
    def _perform_whitening_round(self, a: List[int], k0: List[int]) -> List[int]:
        """Whitening round (only key addition)"""
        return self._apply_key_addition(a, k0)
    
    def _perform_last_round(self, a: List[int], kR: List[int]) -> List[int]:
        """Last round (without linear diffusion)"""
        return self._apply_key_addition(
            self._apply_permutation_layer(
                self._apply_nonlinear_layer(a)
            ),
            kR
        )
    
    def _perform_round(self, a: List[int], kr: List[int]) -> List[int]:
        """Normal round"""
        return self._apply_key_addition(
            self._apply_linear_diffusion_layer(
                self._apply_permutation_layer(
                    self._apply_nonlinear_layer(a)
                )
            ),
            kr
        )
    
    def _process_block(self, data: bytes, round_keys: List[List[int]]) -> bytes:
        """Process a block of data"""
        tmp = list(data)
        tmp = self._perform_whitening_round(tmp, round_keys[0])
        
        for r in range(1, self.R):
            tmp = self._perform_round(tmp, round_keys[r])
        
        tmp = self._perform_last_round(tmp, round_keys[self.R])
        return bytes(tmp)
    
    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt a block of 12 bytes"""
        if len(plaintext) != self.BLOCK_SIZE:
            raise ValueError(f"Plaintext must be {self.BLOCK_SIZE} bytes")
        return self._process_block(plaintext, self.encryption_round_keys)
    
    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt a block of 12 bytes"""
        if len(ciphertext) != self.BLOCK_SIZE:
            raise ValueError(f"Ciphertext must be {self.BLOCK_SIZE} bytes")
        return self._process_block(ciphertext, self.decryption_round_keys)
    
    def sct(self, data: bytes) -> bytes:
        """Square-Complete Transform (4 rounds without key)"""
        if len(data) != self.BLOCK_SIZE:
            raise ValueError(f"Data must be {self.BLOCK_SIZE} bytes")
        
        tmp = list(data)
        
        def _unkeyed_round(a: List[int]) -> List[int]:
            return self._apply_linear_diffusion_layer(
                self._apply_permutation_layer(
                    self._apply_nonlinear_layer(a)
                )
            )
        
        tmp = _unkeyed_round(tmp)
        for _ in range(3):
            tmp = _unkeyed_round(tmp)
        
        return bytes(tmp)
    
    def Encrypt(self, dst: bytearray, src: bytes):
        """Encrypt like Go: Encrypt(dst, src)"""
        if len(src) != self.BLOCK_SIZE:
            raise ValueError(f"Source must be {self.BLOCK_SIZE} bytes")
        result = self.encrypt(src)
        dst[:len(result)] = result
    
    def Decrypt(self, dst: bytearray, src: bytes):
        """Decrypt like Go: Decrypt(dst, src)"""
        if len(src) != self.BLOCK_SIZE:
            raise ValueError(f"Source must be {self.BLOCK_SIZE} bytes")
        result = self.decrypt(src)
        dst[:len(result)] = result
    
    def Sct(self, dst: bytearray, src: bytes):
        """Sct like Go: Sct(dst, src)"""
        if len(src) != self.BLOCK_SIZE:
            raise ValueError(f"Source must be {self.BLOCK_SIZE} bytes")
        result = self.sct(src)
        dst[:len(result)] = result
    
    def BlockSize(self) -> int:
        """Block size like Go"""
        return self.BLOCK_SIZE

class Marvin:
    """Marvin MAC implementation compatible with Go"""
    C = 0x2A
    
    def __init__(self, cipher: Curupira1, R: Optional[bytes] = None, letter_soup_mode: bool = False):
        self.cipher = cipher
        self.block_bytes = cipher.BLOCK_SIZE
        self.letter_soup_mode = letter_soup_mode
        
        if R is not None:
            self.InitWithR(R)
        else:
            self.Init()
    
    def _xor(self, a: bytearray, b: bytes) -> None:
        """XOR in-place between bytearray and bytes"""
        for i in range(min(len(a), len(b))):
            a[i] ^= b[i]
    
    def Init(self):
        """Step 2 of Algorithm 1 - Page 4"""
        self.buffer = bytearray(self.block_bytes)
        self.R = bytearray(self.block_bytes)
        self.O = bytearray(self.block_bytes)
        
        left_padded_c = bytearray(self.block_bytes)
        left_padded_c[self.block_bytes - 1] = self.C
        
        encrypted = self.cipher.encrypt(bytes(left_padded_c))
        self.R[:] = encrypted
        self._xor(self.R, left_padded_c)
        self.O[:] = self.R[:]
    
    def InitWithR(self, R: bytes):
        """Initialize with provided R"""
        self.buffer = bytearray(self.block_bytes)
        self.R = bytearray(self.block_bytes)
        self.O = bytearray(self.block_bytes)
        
        self.R[:] = R[:self.block_bytes]
        self.O[:] = R[:self.block_bytes]
    
    def updateOffset(self):
        """Algorithm 6 - Page 19 (w = 8, k1 = 11, k2 = 13, k3 = 16)"""
        O0 = self.O[0]
        
        for i in range(11):
            self.O[i] = self.O[i + 1]
        
        self.O[9] = (self.O[9] ^ O0 ^ (O0 >> 3) ^ (O0 >> 5)) & 0xFF
        self.O[10] = (self.O[10] ^ ((O0 << 5) & 0xFF) ^ ((O0 << 3) & 0xFF)) & 0xFF
        self.O[11] = O0
    
    def Update(self, a_data: bytes):
        """Update MAC with associated data"""
        a_length = len(a_data)
        block_bytes = self.block_bytes
        
        M = bytearray(block_bytes)
        A = bytearray(block_bytes)
        
        q = a_length // block_bytes
        r = a_length % block_bytes
        
        self._xor(self.buffer, self.R)
        
        for i in range(q):
            M[:] = a_data[i * block_bytes:(i + 1) * block_bytes]
            self.updateOffset()
            self._xor(M, self.O)
            self.cipher.Sct(A, bytes(M))
            self._xor(self.buffer, A)
        
        if r != 0:
            M[:r] = a_data[q * block_bytes:q * block_bytes + r]
            for i in range(r, block_bytes):
                M[i] = 0
            
            self.updateOffset()
            self._xor(M, self.O)
            self.cipher.Sct(A, bytes(M))
            self._xor(self.buffer, A)
        
        self.m_length = a_length
    
    def GetTag(self, tag: Optional[bytearray] = None, tag_bits: int = 96):
        """Get MAC tag"""
        if tag is None:
            tag = bytearray(tag_bits // 8)
        
        block_bytes = self.block_bytes
        
        if self.letter_soup_mode:
            tag[:block_bytes] = self.buffer[:block_bytes]
            return bytes(tag[:tag_bits // 8])
        
        A = bytearray(block_bytes)
        encrypted_a = bytearray(block_bytes)
        aux_value1 = bytearray(block_bytes)
        aux_value2 = bytearray(block_bytes)
        
        diff = self.cipher.BLOCK_SIZE * 8 - tag_bits
        
        if diff == 0:
            aux_value1[0] = 0x80
            aux_value1[1] = 0x00
        elif diff < 0:
            aux_value1[0] = diff & 0xFF
            aux_value1[1] = 0x80
        else:
            diff = (diff << 1) | 0x01
            while diff > 0 and (diff & 0x80) == 0:
                diff = (diff << 1) & 0xFF
            aux_value1[0] = diff & 0xFF
            aux_value1[1] = 0x00
        
        processed_bits = 8 * self.m_length
        for i in range(4):
            aux_value2[block_bytes - i - 1] = (processed_bits >> (8 * i)) & 0xFF
        
        A[:] = self.buffer[:]
        self._xor(A, aux_value1)
        self._xor(A, aux_value2)
        
        self.cipher.Encrypt(encrypted_a, bytes(A))
        
        tag_bytes = tag_bits // 8
        tag[:tag_bytes] = encrypted_a[:tag_bytes]
        return bytes(tag[:tag_bytes])

class LetterSoup:
    """AEAD LetterSoup mode implementation exactly like in Go"""
    
    def __init__(self, cipher: Curupira1):
        self.cipher = cipher
        self.block_bytes = cipher.BLOCK_SIZE
        self.mac = Marvin(cipher, None, True)
        
        self.m_length = 0
        self.h_length = 0
        self.iv = bytearray()
        self.A = bytearray()
        self.D = bytearray()
        self.R = bytearray()
        self.L = bytearray()
    
    def SetIV(self, iv: bytes):
        """Set initialization vector"""
        iv_length = len(iv)
        block_bytes = self.block_bytes
        
        self.iv = bytearray(iv_length)
        self.iv[:] = iv
        
        self.L = bytearray()
        
        self.R = bytearray(block_bytes)
        left_padded_n = bytearray(block_bytes)
        
        start_idx = block_bytes - iv_length
        if start_idx < 0:
            start_idx = 0
        copy_len = min(iv_length, block_bytes)
        left_padded_n[start_idx:start_idx + copy_len] = iv[:copy_len]
        
        self.cipher.Encrypt(self.R, bytes(left_padded_n))
        
        for i in range(block_bytes):
            self.R[i] ^= left_padded_n[i]
    
    def Update(self, a_data: bytes):
        """Update with associated data (AAD)"""
        a_length = len(a_data)
        block_bytes = self.block_bytes
        
        self.L = bytearray(block_bytes)
        self.D = bytearray(block_bytes)
        
        empty = bytes(block_bytes)
        
        self.h_length = a_length
        self.cipher.Encrypt(self.L, empty)
        
        self.mac.InitWithR(bytes(self.L))
        self.mac.Update(a_data)
        self.mac.GetTag(self.D, self.cipher.BLOCK_SIZE * 8)
    
    def _xor(self, a: bytearray, b: bytes):
        """XOR in-place"""
        for i in range(min(len(a), len(b))):
            a[i] ^= b[i]
    
    def updateOffset(self, O: bytearray):
        """Algorithm 6 - Page 19 (w = 8, k1 = 11, k2 = 13, k3 = 16)"""
        O0 = O[0]
        
        for i in range(11):
            O[i] = O[i + 1]
        
        O[9] = (O[9] ^ O0 ^ (O0 >> 3) ^ (O0 >> 5)) & 0xFF
        O[10] = (O[10] ^ ((O0 << 5) & 0xFF) ^ ((O0 << 3) & 0xFF)) & 0xFF
        O[11] = O0
    
    def LFSRC(self, m_data: bytes, c_data: bytearray):
        """Algorithm 8 - Page 20"""
        m_length = len(m_data)
        block_bytes = self.block_bytes
        
        M = bytearray(block_bytes)
        C = bytearray(block_bytes)
        O = bytearray(block_bytes)
        O[:] = self.R[:]
        
        q = m_length // block_bytes
        r = m_length % block_bytes
        
        for i in range(q):
            M[:] = m_data[i * block_bytes:(i + 1) * block_bytes]
            self.updateOffset(O)
            self.cipher.Encrypt(C, bytes(O))
            self._xor(C, M)
            c_data[i * block_bytes:(i + 1) * block_bytes] = C[:block_bytes]
        
        if r != 0:
            M[:r] = m_data[q * block_bytes:q * block_bytes + r]
            for i in range(r, block_bytes):
                M[i] = 0
            
            self.updateOffset(O)
            self.cipher.Encrypt(C, bytes(O))
            self._xor(C, M)
            c_data[q * block_bytes:q * block_bytes + r] = C[:r]
    
    def Encrypt(self, dst: bytearray, src: bytes):
        """Encrypt data"""
        m_length = len(src)
        block_bytes = self.block_bytes
        
        self.A = bytearray(block_bytes)
        self.m_length = m_length
        
        if dst is None or len(dst) == 0:
            dst = bytearray(block_bytes)
        
        self.LFSRC(src, dst)
        
        self.mac.InitWithR(bytes(self.R))
        self.mac.Update(bytes(dst))
        self.mac.GetTag(self.A, self.cipher.BLOCK_SIZE * 8)
    
    def Decrypt(self, dst: bytearray, src: bytes):
        """Decrypt data"""
        self.LFSRC(src, dst)
    
    def GetTag(self, tag: Optional[bytearray] = None, tag_bits: int = 96):
        """Get authentication tag"""
        if tag is None:
            tag = bytearray(tag_bits // 8)
        
        block_bytes = self.block_bytes
        
        Atemp = bytearray(block_bytes)
        copy_len = min(len(self.A), block_bytes)
        Atemp[:copy_len] = self.A[:copy_len]
        
        aux_value1 = bytearray(block_bytes)
        aux_value2 = bytearray(block_bytes)
        
        diff = self.cipher.BLOCK_SIZE * 8 - tag_bits
        
        if diff == 0:
            aux_value1[0] = 0x80
            aux_value1[1] = 0x00
        elif diff < 0:
            aux_value1[0] = diff & 0xFF
            aux_value1[1] = 0x80
        else:
            diff = (diff << 1) | 0x01
            while diff > 0 and (diff & 0x80) == 0:
                diff = (diff << 1) & 0xFF
            aux_value1[0] = diff & 0xFF
            aux_value1[1] = 0x00
        
        for i in range(4):
            aux_value2[block_bytes - i - 1] = ((self.m_length * 8) >> (8 * i)) & 0xFF
        
        self._xor(Atemp, aux_value1)
        self._xor(Atemp, aux_value2)
        
        if len(self.L) != 0:
            aux_value2 = bytearray(block_bytes)
            for i in range(4):
                aux_value2[block_bytes - i - 1] = ((self.h_length * 8) >> (8 * i)) & 0xFF
            
            Dtemp = bytearray(block_bytes)
            copy_len = min(len(self.D), block_bytes)
            Dtemp[:copy_len] = self.D[:copy_len]
            
            self._xor(Dtemp, aux_value1)
            self._xor(Dtemp, aux_value2)
            self.cipher.Sct(aux_value1, bytes(Dtemp))
            self._xor(Atemp, aux_value1)
        
        self.cipher.Encrypt(aux_value1, bytes(Atemp))
        
        tag_bytes = tag_bits // 8
        tag[:tag_bytes] = aux_value1[:tag_bytes]
        return bytes(tag[:tag_bytes])

# =========================
# ED521 IMPLEMENTATION
# =========================

P = int("6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151")
N = int("1716199415032652428745475199770348304317358825035826352348615864796385795849413675475876651663657849636693659065234142604319282948702542317993421293670108523")
D = int("-376014")
Gx = int("1571054894184995387535939749894317568645297350402905821437625181152304994381188529632591196067604100772673927915114267193389905003276673749012051148356041324")
Gy = int("12")
H = 4
BIT_SIZE = 521
ED521_BYTE_LEN = (BIT_SIZE + 7) // 8

ED521_OID = b'\x06\x0a\x2b\x06\x01\x04\x01\x83\xa6\x7a\x02\x01'

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

def ed521_is_on_curve(x: int, y: int) -> bool:
    return (x*x + y*y) % P == (1 + D*x*x*y*y) % P

def ed521_add_points(x1: int, y1: int, x2: int, y2: int) -> Tuple[int, int]:
    if x1 == 0 and y1 == 1:
        return x2, y2
    if x2 == 0 and y2 == 1:
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
    
    result_x, result_y = 0, 1
    temp_x, temp_y = x, y
    
    while scalar > 0:
        if scalar & 1:
            result_x, result_y = ed521_add_points(result_x, result_y, temp_x, temp_y)
        temp_x, temp_y = ed521_double_point(temp_x, temp_y)
        scalar >>= 1
    
    return result_x, result_y

def ed521_scalar_base_mult(k_bytes: bytes) -> Tuple[int, int]:
    return ed521_scalar_mult(Gx, Gy, k_bytes)

def ed521_compress_point(x: int, y: int) -> bytes:
    """Comprime ponto conforme RFC 8032"""
    y_bytes = little_int_to_bytes(y, ED521_BYTE_LEN)
    
    x_bytes = little_int_to_bytes(x, ED521_BYTE_LEN)
    sign_bit = x_bytes[0] & 1
    
    compressed = bytearray(y_bytes)
    compressed[-1] |= (sign_bit << 7)
    
    return bytes(compressed)

def ed521_decompress_point(data: bytes) -> Tuple[Optional[int], Optional[int]]:
    """Descomprime ponto conforme RFC 8032"""
    if len(data) != ED521_BYTE_LEN:
        return None, None
    
    sign_bit = (data[-1] >> 7) & 1
    
    y_bytes = bytearray(data)
    y_bytes[-1] &= 0x7F
    y = bytes_to_little_int(y_bytes)
    
    y2 = (y * y) % P
    
    numerator = (1 - y2) % P
    denominator = (1 - D * y2) % P
    
    try:
        inv_den = pow(denominator, -1, P)
    except ValueError:
        return None, None
    
    x2 = (numerator * inv_den) % P
    
    x = pow(x2, (P + 1)//4, P)
    
    x_bytes = little_int_to_bytes(x, ED521_BYTE_LEN)
    if (x_bytes[0] & 1) != sign_bit:
        x = (-x) % P
    
    return x, y

def ed521_dom5(phflag: int, context: bytes) -> bytes:
    """Implementa dom5 conforme especificação"""
    if len(context) > 255:
        raise ValueError("context too long for dom5")
    
    dom = b"SigEd521" + bytes([phflag, len(context)]) + context
    return dom

def ed521_hash(phflag: int, context: bytes, x: bytes) -> bytes:
    """H(x) = SHAKE256(dom5(phflag,context)||x, 132)"""
    from hashlib import shake_256
    
    dom = ed521_dom5(phflag, context)
    
    h = shake_256()
    h.update(dom)
    h.update(x)
    
    return h.digest(132)

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

def ed521_sign(private_key: int, message: bytes) -> bytes:
    """Cria assinatura PureEdDSA conforme especificação"""
    byte_len = ED521_BYTE_LEN
    
    prefix = ed521_hash(0x00, b'', little_int_to_bytes(private_key, byte_len))
    
    r_bytes = ed521_hash(0x00, b'', prefix + message)
    r = bytes_to_little_int(r_bytes[:byte_len]) % N
    
    Rx, Ry = ed521_scalar_base_mult(little_int_to_bytes(r, byte_len))
    R_compressed = ed521_compress_point(Rx, Ry)
    
    Ax, Ay = ed521_get_public_key(private_key)
    A_compressed = ed521_compress_point(Ax, Ay)
    
    hram_input = R_compressed + A_compressed + message
    hram_hash = ed521_hash(0x00, b'', hram_input)
    h = bytes_to_little_int(hram_hash[:byte_len]) % N
    
    s = (r + h * private_key) % N
    
    s_bytes = little_int_to_bytes(s, byte_len)
    signature = R_compressed + s_bytes
    
    return signature

def ed521_verify(pub_x: int, pub_y: int, message: bytes, signature: bytes) -> bool:
    """Verifica assinatura PureEdDSA conforme especificação"""
    byte_len = ED521_BYTE_LEN
    
    if len(signature) != 2 * byte_len:
        return False
    
    R_compressed = signature[:byte_len]
    s_bytes = signature[byte_len:]
    
    Rx, Ry = ed521_decompress_point(R_compressed)
    if Rx is None or Ry is None:
        return False
    
    s = bytes_to_little_int(s_bytes)
    if s >= N:
        return False
    
    A_compressed = ed521_compress_point(pub_x, pub_y)
    
    hram_input = R_compressed + A_compressed + message
    hram_hash = ed521_hash(0x00, b'', hram_input)
    h = bytes_to_little_int(hram_hash[:byte_len]) % N
    
    sGx, sGy = ed521_scalar_base_mult(little_int_to_bytes(s, byte_len))
    
    hAx, hAy = ed521_scalar_mult(pub_x, pub_y, little_int_to_bytes(h, byte_len))
    
    rhaX, rhaY = ed521_add_points(Rx, Ry, hAx, hAy)
    
    return sGx == rhaX and sGy == rhaY

# =========================
# HKDF FUNCTIONS (RFC 5869)
# =========================

def hkdf_extract(salt, ikm, hash_algo='sha256'):
    """
    HKDF-Extract(salt, IKM) -> PRK
    """
    if salt is None:
        hash_len = hashlib.new(hash_algo).digest_size
        salt = b'\x00' * hash_len
    
    if isinstance(salt, str):
        salt = salt.encode('utf-8')
    if isinstance(ikm, str):
        ikm = ikm.encode('utf-8')
    
    return hmac_lib.new(salt, ikm, digestmod=hash_algo).digest()

def hkdf_expand(prk, info, length, hash_algo='sha256'):
    """
    HKDF-Expand(PRK, info, L) -> OKM
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
    
    n = (length + hash_len - 1) // hash_len
    t = b''
    okm = b''
    
    for i in range(1, n + 1):
        t = hmac_lib.new(prk, t + info + bytes([i]), digestmod=hash_algo).digest()
        okm += t
    
    return okm[:length]

def hkdf(salt, ikm, info=None, length=32, hash_algo='sha256'):
    """
    HKDF(salt, IKM, info, L) -> OKM
    """
    prk = hkdf_extract(salt, ikm, hash_algo)
    return hkdf_expand(prk, info, length, hash_algo)

def hkdf_calc(salt=None, ikm=None, info=None, length=32, hash_algo='sha256'):
    """
    Calculate HKDF from command line
    """
    if salt is None:
        salt_input = getpass.getpass("Salt (string, empty for none): ").strip()
        salt = salt_input if salt_input else None
    
    if ikm is None:
        ikm = getpass.getpass("Input Key Material (string): ").strip()
    
    if info is None:
        info_input = input("Info (string, empty for none): ").strip()
        info = info_input if info_input else None
    
    try:
        okm = hkdf(salt, ikm, info, length, hash_algo)
        
        print(f"{okm.hex()}")
        
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
    if salt is None:
        salt_input = input("Salt (string, enter for none): ").strip()
        salt = salt_input if salt_input else None
    
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
                ikm = f.readline().strip()  # Apenas primeira linha
        else:
            print("✖ Invalid choice", file=sys.stderr)
            sys.exit(1)
    
    if info is None:
        info_input = input("Info (string, enter for none): ").strip()
        info = info_input if info_input else None
    
    if length is None:
        try:
            length = int(input(f"Output length in bytes [32]: ").strip() or "32")
        except:
            length = 32
    
    okm = hkdf(salt, ikm, info, length, hash_algo)
    
    print(f"\n✓ HKDF-{hash_algo} derived {length} bytes")
    print(f"\nOutput Key Material:")
    print(f"Hex: {okm.hex()}")
    
    save = input("\nSave to file? (y/N): ").strip().lower()
    if save == 'y':
        filename = input("Filename: ").strip()
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(okm.hex())
            print(f"✓ Saved to {filename}")
        except Exception as e:
            print(f"✖ Error saving file: {e}", file=sys.stderr)
    
    return okm

def hkdf_compare():
    """
    Re-derive HKDF and compare with expected value
    """
    print("HKDF Comparison")
    print("Enter parameters to re-derive and compare:")
    
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
    
    okm = hkdf(salt, ikm, info, length, hash_algo)
    
    print(f"\nComparison:")
    print(f"  Expected: {expected.hex()}")
    print(f"  Actual:   {okm.hex()}")
    
    if okm == expected:
        print("\n✓ HKDF outputs match!")
        return True
    else:
        print("\n✓ HKDF outputs DO NOT match!")
        return False

def list_hkdf_algorithms():
    """List all available algorithms for HKDF"""
    print("Available algorithms for HKDF:")
    print("-" * 60)
    
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
  
    print("\nAdditional algorithms available via hashlib.new():")
    other_algs = sorted([alg for alg in hashlib.algorithms_available 
                        if alg not in [a[0] for a in hkdf_algs]])
    for alg in other_algs[:12]:
        print(f"  {alg:15}")
      
    print("\nSecurity recommendations:")
    print("  • Use SHA-256 or SHA-512 for general purposes")
    print("  • Use SHA-3 family for post-quantum security")
    print("  • Minimum recommended output: 32 bytes (256 bits)")
    print("  • Salt should be random or pseudo-random")
    print("  • Info can be used for key separation")
    print("  • Default: sha256")

# =========================
# SIMPLE KEY PARSING FUNCTIONS
# =========================

def x25519_parse_key(key_file: str, debug: bool = False):
    """
    Parse X25519 key file and display raw key information.
    """
    try:
        with open(key_file, 'r') as f:
            pem_data = f.read()
        
        lines = pem_data.strip().split('\n')
        
        # Check if encrypted
        is_encrypted = False
        for line in lines:
            if line.startswith("Proc-Type:") and "ENCRYPTED" in line:
                is_encrypted = True
                break
        
        # Parse private key
        if "PRIVATE KEY" in pem_data:
            if is_encrypted:
                password = getpass.getpass("Enter password to decrypt private key: ")
                try:
                    # Decrypt and get DER data
                    der_data = decrypt_private_key_pem(pem_data, password)
                    print("✓ Key decrypted successfully")
                    
                    # Convert decrypted DER back to PEM for display
                    b64_der = base64.b64encode(der_data).decode('ascii')
                    pem_lines = [b64_der[i:i+64] for i in range(0, len(b64_der), 64)]
                    
                    # Print decrypted PEM
                    print("-----BEGIN PRIVATE KEY-----")
                    for line in pem_lines:
                        print(line)
                    print("-----END PRIVATE KEY-----")
                    
                except Exception as e:
                    print(f"✖ Decryption failed: {e}")
                    return
            else:
                # Print original PEM (not encrypted)
                print(pem_data.strip())
                b64_data = ''.join([line.strip() for line in lines if line and not line.startswith('-----')])
                der_data = base64.b64decode(b64_data)
            
            if debug:
                print(f"\nDEBUG: DER data ({len(der_data)} bytes):")
                print(der_data.hex())
            
            # Find the private key pattern (0x04 0x20 = OCTET STRING of 32 bytes)
            for i in range(len(der_data) - 33):
                if der_data[i] == 0x04 and der_data[i+1] == 0x20:  # OCTET STRING of 32 bytes
                    private_key_bytes = der_data[i+2:i+34]  # Skip 0x04 0x20
                    
                    if len(private_key_bytes) == 32:
                        print(f"Private-Key: ({len(private_key_bytes)*8}-bit)")
                        print("priv: ")
                        hex_str = private_key_bytes.hex()
                        # Break every 15 hex chars (ends with :)
                        for i in range(0, len(hex_str), 30):
                            line_hex = hex_str[i:i+30]
                            formatted = ':'.join(line_hex[j:j+2] for j in range(0, len(line_hex), 2))
                            print(f"    {formatted}")
                        
                        # Calculate and show public key
                        public_key = x25519_get_public_key(private_key_bytes)
                        print("pub: ")
                        hex_str = public_key.hex()
                        for i in range(0, len(hex_str), 30):
                            line_hex = hex_str[i:i+30]
                            formatted = ':'.join(line_hex[j:j+2] for j in range(0, len(line_hex), 2))
                            print(f"    {formatted}")
                        
                        print(f"Curve: X25519")
                        print(f"OID: 1.3.101.110")
                        
                        return private_key_bytes, public_key
        
        # Parse public key
        elif "PUBLIC KEY" in pem_data:
            # Public keys are never encrypted in this format
            print(pem_data.strip())
            
            # Extract base64 data
            b64_data = ''.join([line.strip() for line in lines 
                              if line and not line.startswith('-----')])
            der_data = base64.b64decode(b64_data)
            
            if debug:
                print(f"\nDEBUG: DER data ({len(der_data)} bytes):")
                print(der_data.hex())
            
            # For public key, look for BIT STRING (0x03) then skip unused bits (0x00)
            for i in range(len(der_data) - 33):
                if der_data[i] == 0x03:  # BIT STRING
                    # Skip length and unused bits (0x00)
                    bitstring_len = der_data[i+1]
                    if bitstring_len & 0x80:
                        # Long form, skip it for simplicity
                        continue
                    
                    if i+2 < len(der_data) and der_data[i+2] == 0x00:  # Unused bits = 0
                        # The 32-byte public key starts at i+3
                        public_key_bytes = der_data[i+3:i+35]
                        
                        if len(public_key_bytes) == 32:
                            print(f"Public-Key: ({len(public_key_bytes)*8}-bit)")
                            hex_str = public_key_bytes.hex()
                            for i in range(0, len(hex_str), 30):
                                line_hex = hex_str[i:i+30]
                                formatted = ':'.join(line_hex[j:j+2] for j in range(0, len(line_hex), 2))
                                print(f"    {formatted}")
                            
                            print(f"Curve: X25519")
                            print(f"OID: 1.3.101.110")
                            
                            return None, public_key_bytes
        
        else:
            print("✖ Unknown key format")
            
    except FileNotFoundError:
        print(f"✖ File not found: {key_file}")
    except Exception as e:
        print(f"✖ Error: {e}")

def x448_parse_key(key_file: str, debug: bool = False):
    """
    Parse X448 key file and display raw key information.
    Compatível com chaves criptografadas via Curupira-192-CBC.
    """
    try:
        with open(key_file, 'r') as f:
            pem_data = f.read()
        
        lines = pem_data.strip().split('\n')
        
        # Check if encrypted
        is_encrypted = False
        for line in lines:
            if line.startswith("Proc-Type:") and "ENCRYPTED" in line:
                is_encrypted = True
                break
        
        # Parse private key
        if "X448 PRIVATE KEY" in pem_data or ("PRIVATE KEY" in pem_data and "X448" in pem_data):
            if is_encrypted:
                password = getpass.getpass("Enter password to decrypt private key: ")
                try:
                    # Decrypt and get DER data
                    der_data = decrypt_private_key_pem(pem_data, password)
                    print("✓ Key decrypted successfully")
                    
                    # Convert decrypted DER back to PEM for display
                    b64_der = base64.b64encode(der_data).decode('ascii')
                    pem_lines = [b64_der[i:i+64] for i in range(0, len(b64_der), 64)]
                    
                    # Print decrypted PEM
                    print("-----BEGIN X448 PRIVATE KEY-----")
                    for line in pem_lines:
                        print(line)
                    print("-----END X448 PRIVATE KEY-----")
                    
                except Exception as e:
                    print(f"✖ Decryption failed: {e}")
                    return
            else:
                # Print original PEM (not encrypted)
                print(pem_data.strip())
                b64_data = ''.join([line.strip() for line in lines if line and not line.startswith('-----')])
                der_data = base64.b64decode(b64_data)
            
            if debug:
                print(f"\nDEBUG: DER data ({len(der_data)} bytes):")
                print(der_data.hex())
            
            # Find the private key pattern (0x04 0x38 = OCTET STRING of 56 bytes)
            for i in range(len(der_data) - 57):
                if der_data[i] == 0x04 and der_data[i+1] == 0x38:  # OCTET STRING of 56 bytes
                    private_key_bytes = der_data[i+2:i+58]  # Skip 0x04 0x38
                    
                    if len(private_key_bytes) == 56:
                        print(f"Private-Key: ({len(private_key_bytes)*8}-bit)")
                        print("priv: ")
                        hex_str = private_key_bytes.hex()
                        # Break every 15 hex chars (ends with :)
                        for i in range(0, len(hex_str), 30):
                            line_hex = hex_str[i:i+30]
                            formatted = ':'.join(line_hex[j:j+2] for j in range(0, len(line_hex), 2))
                            print(f"    {formatted}")
                        
                        # Check clamping (RFC 7748)
                        print(f"Clamping check:")
                        print(f"  Byte 0: 0x{private_key_bytes[0]:02x} (bits 0-1: {private_key_bytes[0] & 0x03:02b} - should be 00)")
                        print(f"  Byte 55: 0x{private_key_bytes[55]:02x} (bit 447: {(private_key_bytes[55] >> 7) & 1} - should be 1)")
                        
                        # Calculate and show public key
                        public_key = x448_get_public_key(private_key_bytes)
                        print("pub: ")
                        hex_str = public_key.hex()
                        for i in range(0, len(hex_str), 30):
                            line_hex = hex_str[i:i+30]
                            formatted = ':'.join(line_hex[j:j+2] for j in range(0, len(line_hex), 2))
                            print(f"    {formatted}")
                        
                        print(f"Curve: X448")
                        print(f"OID: 1.3.101.111")
                        
                        return private_key_bytes, public_key
            
            # Fallback: try to find 56 bytes directly
            if len(der_data) >= 56:
                for i in range(len(der_data) - 55):
                    candidate = der_data[i:i+56]
                    if len(candidate) == 56:
                        print(f"Private-Key: (448-bit) [extracted from offset {i}]")
                        print("priv: ")
                        hex_str = candidate.hex()
                        for i in range(0, len(hex_str), 30):
                            line_hex = hex_str[i:i+30]
                            formatted = ':'.join(line_hex[j:j+2] for j in range(0, len(line_hex), 2))
                            print(f"    {formatted}")
                        
                        # Check clamping
                        print(f"Clamping check:")
                        print(f"  Byte 0: 0x{candidate[0]:02x} (bits 0-1: {candidate[0] & 0x03:02b})")
                        print(f"  Byte 55: 0x{candidate[55]:02x} (bit 447: {(candidate[55] >> 7) & 1})")
                        
                        # Calculate public key
                        public_key = x448_get_public_key(candidate)
                        print("pub: ")
                        hex_str = public_key.hex()
                        for i in range(0, len(hex_str), 30):
                            line_hex = hex_str[i:i+30]
                            formatted = ':'.join(line_hex[j:j+2] for j in range(0, len(line_hex), 2))
                            print(f"    {formatted}")
                        
                        print(f"Curve: X448")
                        print(f"OID: 1.3.101.111")
                        
                        return candidate, public_key
        
        # Parse public key
        elif "X448 PUBLIC KEY" in pem_data or ("PUBLIC KEY" in pem_data and "X448" in pem_data):
            # Public keys are never encrypted in this format
            print(pem_data.strip())
            
            # Extract base64 data
            b64_data = ''.join([line.strip() for line in lines 
                              if line and not line.startswith('-----')])
            der_data = base64.b64decode(b64_data)
            
            if debug:
                print(f"\nDEBUG: DER data ({len(der_data)} bytes):")
                print(der_data.hex())
            
            # For public key, look for BIT STRING (0x03) then skip unused bits (0x00)
            for i in range(len(der_data) - 57):
                if der_data[i] == 0x03:  # BIT STRING
                    # Skip length and unused bits (0x00)
                    bitstring_len = der_data[i+1]
                    if bitstring_len & 0x80:
                        # Long form, handle it
                        num_bytes = bitstring_len & 0x7F
                        bitstring_len = int.from_bytes(der_data[i+2:i+2+num_bytes], 'big')
                        offset = i + 2 + num_bytes
                    else:
                        offset = i + 2
                    
                    if offset < len(der_data) and der_data[offset] == 0x00:  # Unused bits = 0
                        # The 56-byte public key starts at offset+1
                        public_key_bytes = der_data[offset+1:offset+57]
                        
                        if len(public_key_bytes) == 56:
                            print(f"Public-Key: ({len(public_key_bytes)*8}-bit)")
                            hex_str = public_key_bytes.hex()
                            for i in range(0, len(hex_str), 30):
                                line_hex = hex_str[i:i+30]
                                formatted = ':'.join(line_hex[j:j+2] for j in range(0, len(line_hex), 2))
                                print(f"    {formatted}")
                            
                            print(f"Curve: X448")
                            print(f"OID: 1.3.101.111")
                            
                            return None, public_key_bytes
            
            # Fallback: try to find 56 bytes directly
            if len(der_data) >= 56:
                for i in range(len(der_data) - 55):
                    candidate = der_data[i:i+56]
                    if len(candidate) == 56:
                        print(f"Public-Key: (448-bit) [extracted from offset {i}]")
                        hex_str = candidate.hex()
                        for i in range(0, len(hex_str), 30):
                            line_hex = hex_str[i:i+30]
                            formatted = ':'.join(line_hex[j:j+2] for j in range(0, len(line_hex), 2))
                            print(f"    {formatted}")
                        
                        print(f"Curve: X448")
                        print(f"OID: 1.3.101.111")
                        
                        return None, candidate
        
        else:
            print("✖ Unknown key format")
            
    except FileNotFoundError:
        print(f"✖ File not found: {key_file}")
    except Exception as e:
        print(f"✖ Error: {e}")

def ed521_parse_key(key_file: str, debug: bool = False):
    """
    Parse Ed521 key file and display raw key information.
    """
    try:
        with open(key_file, 'r') as f:
            pem_data = f.read()
    except FileNotFoundError:
        print(f"✖ File not found: {key_file}")
        return None, None
    
    lines = pem_data.strip().split('\n')
    
    # Check if encrypted
    is_encrypted = False
    for line in lines:
        if line.startswith("Proc-Type:") and "ENCRYPTED" in line:
            is_encrypted = True
            break
    
    # Parse private key
    if "PRIVATE KEY" in pem_data or ("E-521" in pem_data and "PRIVATE" in pem_data):
        if is_encrypted:
            # Se estiver encriptada, pedir senha e descriptografar
            password = getpass.getpass("Enter password to decrypt private key: ")
            try:
                der_data = decrypt_private_key_pem(pem_data, password)
                print("✓ Key decrypted successfully")
                
                # Converter DER descriptografado de volta para PEM
                b64_der = base64.b64encode(der_data).decode('ascii')
                pem_lines = [b64_der[i:i+64] for i in range(0, len(b64_der), 64)]
                
                # Exibir PEM descriptografado
                print("-----BEGIN E-521 PRIVATE KEY-----")
                for line in pem_lines:
                    print(line)
                print("-----END E-521 PRIVATE KEY-----")
                
                # Agora parsear o DER descriptografado diretamente
                # (não chamar parse_ed521_pem_private_key pois ela pediria senha novamente)
                private_key = parse_ed521_private_key_from_der(der_data, debug)
                
            except Exception as e:
                print(f"✖ Decryption failed: {e}")
                return None, None
        else:
            # Se não estiver encriptada, exibir o PEM original
            print(pem_data.strip())
            
            # Parsear a chave normalmente
            try:
                private_key = parse_ed521_pem_private_key(pem_data, debug)
            except Exception as e:
                print(f"✖ Failed to parse private key: {e}")
                return None, None
        
        # Extrair bytes da chave para exibição
        if is_encrypted:
            # Para chaves encriptadas, usar bytes da chave já extraída
            key_bytes = little_int_to_bytes(private_key, 66)
        else:
            # Para chaves não-encriptadas, tentar extrair do DER
            b64_data = ''.join([line.strip() for line in lines if line and not line.startswith('-----')])
            try:
                der_data = base64.b64decode(b64_data)
                
                # Procurar pelos 66 bytes da chave no DER
                key_bytes = None
                for i in range(len(der_data) - 67):
                    if der_data[i] == 0x04 and der_data[i+1] == 0x42:
                        key_bytes = der_data[i+2:i+2+66]
                        if debug:
                            print(f"DEBUG: Found key at offset {i}: {key_bytes.hex()}")
                        break
                
                if key_bytes is None:
                    key_bytes = little_int_to_bytes(private_key, 66)
                    
            except binascii.Error:
                key_bytes = little_int_to_bytes(private_key, 66)
        
        # Inverter a ordem dos bytes para exibição no formato edgetk
        key_bytes_be = bytes(reversed(key_bytes))
        
        # REMOVER ZEROS DO INÍCIO se houver
        while len(key_bytes_be) > 0 and key_bytes_be[0] == 0:
            key_bytes_be = key_bytes_be[1:]
        
        # ADICIONAR ZEROS AO FINAL para ter 66 bytes
        if len(key_bytes_be) < 66:
            key_bytes_be = key_bytes_be + b'\x00' * (66 - len(key_bytes_be))
        
        if debug:
            print(f"DEBUG: Original bytes (little): {key_bytes.hex()}")
            print(f"DEBUG: After reverse: {bytes(reversed(key_bytes)).hex()}")
            print(f"DEBUG: Final display bytes: {key_bytes_be.hex()}")
        
        print(f"Private-Key: ({(len(key_bytes_be)*8)}-bit)")
        print("priv: ")
        hex_str = key_bytes_be.hex()
        for i in range(0, len(hex_str), 30):
            line_hex = hex_str[i:i+30]
            formatted = ':'.join(line_hex[j:j+2] for j in range(0, len(line_hex), 2))
            print(f"    {formatted}")
        
        # Calculate and show public key
        try:
            pub_x, pub_y = ed521_get_public_key(private_key)
            compressed_pub = ed521_compress_point(pub_x, pub_y)
        except Exception as e:
            print(f"✖ Failed to calculate public key: {e}")
            return None, None
        
        print("pub: ")
        hex_str = compressed_pub.hex()
        for i in range(0, len(hex_str), 30):
            line_hex = hex_str[i:i+30]
            formatted = ':'.join(line_hex[j:j+2] for j in range(0, len(line_hex), 2))
            print(f"    {formatted}")
        
        print(f"Curve: E-521")
        print(f"OID: 1.3.6.1.4.1.44588.2.1")
        
        return private_key, (pub_x, pub_y)
    
    # Parse public key
    elif "PUBLIC KEY" in pem_data or ("E-521" in pem_data and "PUBLIC" in pem_data):
        # Public keys are never encrypted
        print(pem_data.strip())
        
        # Parse public key
        try:
            pub_x, pub_y = parse_ed521_pem_public_key(pem_data, debug)
        except Exception as e:
            print(f"✖ Failed to parse public key: {e}")
            return None, None
        
        compressed_pub = ed521_compress_point(pub_x, pub_y)
        
        print(f"\nPublic-Key: ({len(compressed_pub)*8}-bit)")
        hex_str = compressed_pub.hex()
        for i in range(0, len(hex_str), 30):
            line_hex = hex_str[i:i+30]
            formatted = ':'.join(line_hex[j:j+2] for j in range(0, len(line_hex), 2))
            print(f"    {formatted}")
        
        print(f"Curve: E-521")
        print(f"OID: 1.3.6.1.4.1.44588.2.1")
        
        return None, (pub_x, pub_y)
    
    else:
        print("✖ Unknown key format")
        return None, None

def parse_ed521_private_key_from_der(der_data, debug=False):
    """Parse Ed521 private key directly from DER data"""
    if debug:
        print(f"DEBUG: Parsing DER data length: {len(der_data)} bytes")
        print(f"DEBUG: DER hex: {der_data.hex()}")
    
    try:
        idx = 0
        
        # SEQUENCE
        if der_data[idx] != 0x30:
            raise ValueError("Expected SEQUENCE (0x30)")
        idx += 1
        
        # Length
        seq_len = der_data[idx]
        idx += 1
        if seq_len & 0x80:  # Long form
            num_bytes = seq_len & 0x7F
            seq_len = int.from_bytes(der_data[idx:idx+num_bytes], 'big')
            idx += num_bytes
        
        # Version (INTEGER 0)
        if der_data[idx] != 0x02:
            raise ValueError(f"Expected INTEGER (0x02), got 0x{der_data[idx]:02x}")
        idx += 1
        
        ver_len = der_data[idx]
        idx += 1
        version = int.from_bytes(der_data[idx:idx+ver_len], 'big')
        if version != 0:
            raise ValueError(f"Expected version 0, got {version}")
        idx += ver_len
        
        # AlgorithmIdentifier (SEQUENCE)
        if der_data[idx] != 0x30:
            raise ValueError(f"Expected AlgorithmIdentifier SEQUENCE (0x30), got 0x{der_data[idx]:02x}")
        idx += 1
        
        algo_len = der_data[idx]
        idx += 1
        if algo_len & 0x80:  # Long form
            num_bytes = algo_len & 0x7F
            algo_len = int.from_bytes(der_data[idx:idx+num_bytes], 'big')
            idx += num_bytes
        
        # Skip AlgorithmIdentifier content
        idx += algo_len
        
        # PrivateKey (OCTET STRING)
        if der_data[idx] != 0x04:
            # Tentar formato antigo (tag 0x84) para compatibilidade
            if der_data[idx] == 0x84:
                idx += 1
                priv_len = der_data[idx]
                idx += 1
                private_key_bytes = der_data[idx:idx+priv_len]
                return bytes_to_little_int(private_key_bytes)
            raise ValueError(f"Expected OCTET STRING (0x04), got 0x{der_data[idx]:02x}")
        
        idx += 1
        priv_len = der_data[idx]
        idx += 1
        
        # Handle long length
        if priv_len == 0x81:
            priv_len = der_data[idx]
            idx += 1
        elif priv_len == 0x82:
            priv_len = (der_data[idx] << 8) | der_data[idx+1]
            idx += 2
        
        private_key_bytes = der_data[idx:idx+priv_len]
        
        if debug:
            print(f"DEBUG: Private key bytes length: {len(private_key_bytes)} bytes")
            print(f"DEBUG: Private key hex: {private_key_bytes.hex()}")
        
        # Convert to integer (little-endian)
        return bytes_to_little_int(private_key_bytes)
        
    except Exception as e:
        if debug:
            print(f"DEBUG: ASN.1 parsing failed: {e}")
        
        # Fallback: procurar por 66 bytes no DER
        if len(der_data) == 66:
            key_int = bytes_to_little_int(der_data)
            if 0 < key_int < N:
                if debug:
                    print("DEBUG: Whole data is a valid 66-byte key")
                return key_int
        
        for i in range(len(der_data) - 66 + 1):
            chunk = der_data[i:i+66]
            key_int = bytes_to_little_int(chunk)
            if 0 < key_int < N:
                if debug:
                    print(f"DEBUG: Found 66-byte key at offset {i}")
                return key_int
        
        raise ValueError(f"Cannot parse Ed521 private key: {e}")
        
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
# PEM PKCS8 FUNCTIONS WITH ENCRYPTION SUPPORT
# =========================

def x25519_private_to_pem_pkcs8(private_key_bytes, password=None):
    """
    Convert X25519 private key (32 bytes) to PEM PKCS8 according to RFC 8410
    With optional encryption using RFC 1423 with Curupira-192-CBC
    """
    if len(private_key_bytes) != 32:
        raise ValueError("X25519 private key must be 32 bytes")
    
    x25519_oid = b'\x06\x03\x2b\x65\x6e'  # 1.3.101.110

    inner = b'\x04\x20' + private_key_bytes
    private_key = b'\x04' + bytes([len(inner)]) + inner
    alg_id = b'\x30' + bytes([len(x25519_oid)]) + x25519_oid
    version = b'\x02\x01\x00'

    total_len = len(version + alg_id + private_key)
    pkcs8 = b'\x30' + bytes([total_len]) + version + alg_id + private_key
    
    if password:
        # Encrypt using RFC 1423 with Curupira-192-CBC
        encrypted_pem = encrypt_private_key_pem(pkcs8, password, "CURUPIRA-192-CBC")
        return "-----BEGIN PRIVATE KEY-----\n" + encrypted_pem + "\n-----END PRIVATE KEY-----\n"
    else:
        b64 = base64.b64encode(pkcs8).decode()
        lines = [b64[i:i+64] for i in range(0, len(b64), 64)]
        return "-----BEGIN PRIVATE KEY-----\n" + "\n".join(lines) + "\n-----END PRIVATE KEY-----\n"

def x25519_public_to_pem(public_key_bytes):
    """
    Convert X25519 public key (32 bytes) to PEM SPKI
    """
    if len(public_key_bytes) != 32:
        raise ValueError("X25519 public key must be 32 bytes")
    
    x25519_oid = b'\x06\x03\x2b\x65\x6e'

    alg_id = b'\x30' + bytes([len(x25519_oid)]) + x25519_oid
    bit_string = b'\x03' + bytes([len(public_key_bytes)+1]) + b'\x00' + public_key_bytes

    spki = b'\x30' + bytes([len(alg_id + bit_string)]) + alg_id + bit_string

    b64 = base64.b64encode(spki).decode()
    lines = [b64[i:i+64] for i in range(0, len(b64), 64)]
    return "-----BEGIN PUBLIC KEY-----\n" + "\n".join(lines) + "\n-----END PUBLIC KEY-----\n"

def x448_private_to_pem_pkcs8(private_key_bytes, password=None):
    """
    Convert X448 private key (56 bytes) to PEM PKCS8 according to RFC 8410
    With optional encryption using RFC 1423 with Curupira-192-CBC
    """
    if len(private_key_bytes) != 56:
        raise ValueError("X448 private key must be 56 bytes")
    
    x448_oid = b'\x06\x03\x2b\x65\x6f'  # 1.3.101.111

    inner = b'\x04\x38' + private_key_bytes  # 0x38 = 56 bytes
    private_key = b'\x04' + bytes([len(inner)]) + inner
    alg_id = b'\x30' + bytes([len(x448_oid)]) + x448_oid
    version = b'\x02\x01\x00'

    total_len = len(version + alg_id + private_key)
    pkcs8 = b'\x30' + bytes([total_len]) + version + alg_id + private_key
    
    if password:
        # Encrypt using RFC 1423 with Curupira-192-CBC
        encrypted_pem = encrypt_private_key_pem(pkcs8, password, "CURUPIRA-192-CBC")
        return "-----BEGIN X448 PRIVATE KEY-----\n" + encrypted_pem + "\n-----END X448 PRIVATE KEY-----\n"
    else:
        b64 = base64.b64encode(pkcs8).decode()
        lines = [b64[i:i+64] for i in range(0, len(b64), 64)]
        return "-----BEGIN X448 PRIVATE KEY-----\n" + "\n".join(lines) + "\n-----END X448 PRIVATE KEY-----\n"

def x448_public_to_pem(public_key_bytes):
    """
    Convert X448 public key (56 bytes) to PEM SPKI
    """
    if len(public_key_bytes) != 56:
        raise ValueError("X448 public key must be 56 bytes")
    
    x448_oid = b'\x06\x03\x2b\x65\x6f'  # 1.3.101.111

    alg_id = b'\x30' + bytes([len(x448_oid)]) + x448_oid
    bit_string = b'\x03' + bytes([len(public_key_bytes)+1]) + b'\x00' + public_key_bytes

    spki = b'\x30' + bytes([len(alg_id + bit_string)]) + alg_id + bit_string

    b64 = base64.b64encode(spki).decode()
    lines = [b64[i:i+64] for i in range(0, len(b64), 64)]
    return "-----BEGIN X448 PUBLIC KEY-----\n" + "\n".join(lines) + "\n-----END X448 PUBLIC KEY-----\n"

def ed521_private_to_pem_pkcs8(private_key_int, password=None):
    """Convert Ed521 private key to PEM PKCS8 with optional encryption"""
    private_bytes = little_int_to_bytes(private_key_int, 66)

    # ED521 OID: 1.3.6.1.4.1.44588.2.1
    # Codificado corretamente para corresponder ao Go
    encoded_oid = bytes([
        0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xdc, 0x2c, 0x02, 0x01
    ])
    
    # AlgorithmIdentifier: SEQUENCE { OID, NULL }
    oid_der = b'\x06\x0a' + encoded_oid  # OID tag + length + value
    algorithm_id = b'\x30\x0e' + oid_der + b'\x05\x00'  # SEQUENCE (14 bytes)

    version = b'\x02\x01\x00'  # INTEGER version = 0

    # CORREÇÃO: Private key as OCTET STRING (tag 0x04) não 0x84
    # 66 bytes + tag (1) + length (1) = 68 bytes
    # 66 bytes = 0x42 em hexadecimal
    priv_field = b'\x04\x42' + private_bytes  # OCTET STRING tag (0x04), length 66 (0x42)

    content = version + algorithm_id + priv_field
    content_length = len(content)
    
    # CORREÇÃO: Usar comprimento correto para SEQUENCE
    if content_length <= 127:
        seq = b'\x30' + bytes([content_length]) + content
    else:
        # Comprimento longo (2 bytes) - 0x81 indica 1 byte de comprimento
        # Mas como content_length é 84, podemos usar forma curta
        seq = b'\x30\x81' + bytes([content_length]) + content
    
    if password:
        # Encrypt using RFC 1423 with Curupira-192-CBC
        encrypted_pem = encrypt_private_key_pem(seq, password, "CURUPIRA-192-CBC")
        return "-----BEGIN E-521 PRIVATE KEY-----\n" + encrypted_pem + "\n-----END E-521 PRIVATE KEY-----\n"
    else:
        b64 = base64.b64encode(seq).decode()
        lines = [b64[i:i+64] for i in range(0, len(b64), 64)]
        return "-----BEGIN E-521 PRIVATE KEY-----\n" + "\n".join(lines) + "\n-----END E-521 PRIVATE KEY-----\n"

def ed521_public_to_pem(public_key_x, public_key_y):
    """
    Convert Ed521 public key to EXACT edgetk-compatible format
    """
    encoded_oid = bytes([
        0x2b, 0x6, 0x1, 0x4, 0x1, 0x82, 0xdc, 0x2c, 0x2, 0x1
    ])
    oid_der = b'\x06\x0a' + encoded_oid
    algorithm_id = b'\x30\x0e' + oid_der + b'\x05\x00'

    compressed_pub = ed521_compress_point(public_key_x, public_key_y)
    
    bit_string_data = b'\x00' + compressed_pub
    bit_string_len = len(bit_string_data)
    
    if bit_string_len < 128:
        bit_string_header = b'\x03' + bytes([bit_string_len])
    else:
        len_bytes = bit_string_len.to_bytes((bit_string_len.bit_length() + 7) // 8, 'big')
        bit_string_header = b'\x03' + bytes([0x80 | len(len_bytes)]) + len_bytes
    
    bit_string = bit_string_header + bit_string_data
    
    content = algorithm_id + bit_string
    content_len = len(content)
    
    if content_len < 128:
        seq_len = bytes([content_len])
    else:
        len_bytes = content_len.to_bytes((content_len.bit_length() + 7) // 8, 'big')
        seq_len = bytes([0x80 | len(len_bytes)]) + len_bytes
    
    subject_pub_key_info = b'\x30' + seq_len + content
    
    b64_key = base64.b64encode(subject_pub_key_info).decode('ascii')
    lines = [b64_key[i:i+64] for i in range(0, len(b64_key), 64)]
    
    return (
        "-----BEGIN E-521 PUBLIC KEY-----\n" +
        "\n".join(lines) +
        "\n-----END E-521 PUBLIC KEY-----\n"
    )

# =========================
# RFC 1423 IMPLEMENTATION FOR CURUPIRA-192-CBC
# =========================

def rfc1423_derive_key_md5(password: bytes, salt: bytes, key_size: int) -> bytes:
    """
    Derive key according to RFC 1423 section 1.1 (PBKDF1-like)
    Uses MD5 iteratively: D_i = MD5(D_{i-1} || P || S)
    """
    # Use first 8 bytes of salt for key derivation (as per RFC 1423)
    iv_salt = salt[:8]
    
    # RFC 1423 uses MD5 iteratively
    d = b''
    result = b''
    
    while len(result) < key_size:
        md5_hash = hashlib.md5()
        md5_hash.update(d)
        md5_hash.update(password)
        md5_hash.update(iv_salt)
        d = md5_hash.digest()
        result += d
    
    return result[:key_size]

def pad_pkcs7(data: bytes, block_size: int) -> bytes:
    """PKCS#7 padding"""
    padding_len = block_size - (len(data) % block_size)
    if padding_len == 0:
        padding_len = block_size
    return data + bytes([padding_len] * padding_len)

def unpad_pkcs7(data: bytes) -> bytes:
    """Remove PKCS#7 padding"""
    if len(data) == 0:
        raise ValueError("Empty data")
    
    padding_len = data[-1]
    if padding_len > len(data):
        raise ValueError("Invalid padding length")
    
    # Verify padding bytes
    for i in range(padding_len):
        if data[-i-1] != padding_len:
            raise ValueError("Invalid padding bytes")
    
    return data[:-padding_len]

def cbc_encrypt_curupira(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """Encrypt using Curupira in CBC mode"""
    cipher = Curupira1(key)
    block_size = cipher.BLOCK_SIZE
    
    # Pad plaintext
    padded_data = pad_pkcs7(plaintext, block_size)
    
    # CBC encryption
    ciphertext = b''
    prev_block = iv
    
    for i in range(0, len(padded_data), block_size):
        block = padded_data[i:i+block_size]
        # XOR with previous ciphertext (or IV for first block)
        xored_block = bytes(a ^ b for a, b in zip(block, prev_block))
        # Encrypt with Curupira
        encrypted_block = cipher.encrypt(xored_block)
        ciphertext += encrypted_block
        prev_block = encrypted_block
    
    return ciphertext

def cbc_decrypt_curupira(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """Decrypt using Curupira in CBC mode"""
    cipher = Curupira1(key)
    block_size = cipher.BLOCK_SIZE
    
    if len(ciphertext) % block_size != 0:
        raise ValueError("Ciphertext length must be multiple of block size")
    
    # CBC decryption
    plaintext = b''
    prev_block = iv
    
    for i in range(0, len(ciphertext), block_size):
        encrypted_block = ciphertext[i:i+block_size]
        # Decrypt with Curupira
        decrypted_block = cipher.decrypt(encrypted_block)
        # XOR with previous ciphertext (or IV for first block)
        plain_block = bytes(a ^ b for a, b in zip(decrypted_block, prev_block))
        plaintext += plain_block
        prev_block = encrypted_block
    
    # Remove padding
    return unpad_pkcs7(plaintext)

def encrypt_private_key_pem(data: bytes, password: str, cipher_name: str = "CURUPIRA-192-CBC") -> str:
    """
    Encrypt private key data using RFC 1423 format with specified cipher
    Returns PEM formatted encrypted data
    """
    if cipher_name != "CURUPIRA-192-CBC":
        raise ValueError(f"Unsupported cipher: {cipher_name}")
    
    # Generate random IV (12 bytes for Curupira)
    iv = os.urandom(12)
    
    # Derive key using RFC 1423 method (192-bit = 24 bytes)
    key = rfc1423_derive_key_md5(password.encode('utf-8'), iv, 24)
    
    # Encrypt data
    encrypted_data = cbc_encrypt_curupira(key, iv, data)
    
    # Combine IV and encrypted data
    full_data = encrypted_data
    
    # Encode as base64
    b64_data = base64.b64encode(full_data).decode('ascii')
    
    # Format as PEM with RFC 1423 headers
    lines = []
    lines.append("Proc-Type: 4,ENCRYPTED")
    lines.append(f"DEK-Info: {cipher_name},{iv.hex()}")
    lines.append("")
    
    # Split base64 into 64-character lines
    for i in range(0, len(b64_data), 64):
        lines.append(b64_data[i:i+64])
    
    return "\n".join(lines)

def decrypt_private_key_pem(pem_data: str, password: str) -> bytes:
    """
    Decrypt RFC 1423 formatted private key data
    """
    lines = pem_data.strip().split('\n')
    
    # Parse headers
    proc_type = None
    dek_info = None
    b64_lines = []
    
    in_headers = True
    for line in lines:
        line = line.strip()
        if not line:
            if in_headers:
                in_headers = False
            continue
            
        if line.startswith("-----"):
            continue
        
        if in_headers:
            if line.startswith("Proc-Type:"):
                proc_type = line.split(":", 1)[1].strip()
                if proc_type != "4,ENCRYPTED":
                    raise ValueError("Not an encrypted PEM block")
            elif line.startswith("DEK-Info:"):
                dek_info = line.split(":", 1)[1].strip()
            else:
                # Headers continue
                pass
        else:
            b64_lines.append(line)
    
    if not dek_info:
        raise ValueError("Missing DEK-Info header")
    
    # Parse DEK-Info
    dek_parts = dek_info.split(",", 1)
    if len(dek_parts) != 2:
        raise ValueError(f"Invalid DEK-Info format: {dek_info}")
    
    cipher_name, iv_hex = dek_parts
    cipher_name = cipher_name.strip()
    iv_hex = iv_hex.strip()
    
    if cipher_name != "CURUPIRA-192-CBC":
        raise ValueError(f"Unsupported cipher: {cipher_name}")
    
    try:
        iv = bytes.fromhex(iv_hex)
        if len(iv) != 12:
            raise ValueError(f"Invalid IV length: {len(iv)} bytes, expected 12")
    except ValueError as e:
        raise ValueError(f"Invalid IV hex: {e}")
    
    # Decode base64 data
    b64_data = ''.join(b64_lines)
    encrypted_data = base64.b64decode(b64_data)
    
    # Note: IV is included in the encrypted data, but we already have it from header
    ciphertext = encrypted_data  # Skip the IV that's also in the data
    
    # Derive key
    key = rfc1423_derive_key_md5(password.encode('utf-8'), iv, 24)
    
    try:
        # Decrypt data
        decrypted_data = cbc_decrypt_curupira(key, iv, ciphertext)
    except ValueError as e:
        raise ValueError(f"Decryption failed (wrong password?): {e}")
    
    return decrypted_data

# =========================
# PEM READING FUNCTIONS WITH ENCRYPTION SUPPORT
# =========================

def parse_ed521_pem_private_key(pem_data, debug=False):
    """Parse Ed521 private key from PEM PKCS8 format (compatible with edgetk Go implementation)"""
    lines = pem_data.strip().split('\n')
    
    # Check if encrypted
    is_encrypted = False
    for line in lines:
        if line.startswith("Proc-Type:") and "ENCRYPTED" in line:
            is_encrypted = True
            break
    
    if is_encrypted:
        password = getpass.getpass("Enter password to decrypt private key: ")
        try:
            der_data = decrypt_private_key_pem(pem_data, password)
        except ValueError as e:
            print(f"✖ Decryption failed: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        b64_data = ''.join([line.strip() for line in lines if line and not line.startswith('-----')])
        der_data = base64.b64decode(b64_data)
    
    if debug:
        print(f"DEBUG: DER data length: {len(der_data)} bytes")
        print(f"DEBUG: DER hex: {der_data.hex()}")
    
    try:
        idx = 0
        
        # SEQUENCE
        if der_data[idx] != 0x30:
            raise ValueError("Expected SEQUENCE (0x30)")
        idx += 1
        
        # Length
        seq_len = der_data[idx]
        idx += 1
        if seq_len & 0x80:  # Long form
            num_bytes = seq_len & 0x7F
            seq_len = int.from_bytes(der_data[idx:idx+num_bytes], 'big')
            idx += num_bytes
        
        # Version (INTEGER 0)
        if der_data[idx] != 0x02:
            raise ValueError(f"Expected INTEGER (0x02), got 0x{der_data[idx]:02x}")
        idx += 1
        
        ver_len = der_data[idx]
        idx += 1
        version = int.from_bytes(der_data[idx:idx+ver_len], 'big')
        if version != 0:
            raise ValueError(f"Expected version 0, got {version}")
        idx += ver_len
        
        # AlgorithmIdentifier (SEQUENCE)
        if der_data[idx] != 0x30:
            raise ValueError(f"Expected AlgorithmIdentifier SEQUENCE (0x30), got 0x{der_data[idx]:02x}")
        idx += 1
        
        algo_len = der_data[idx]
        idx += 1
        if algo_len & 0x80:  # Long form
            num_bytes = algo_len & 0x7F
            algo_len = int.from_bytes(der_data[idx:idx+num_bytes], 'big')
            idx += num_bytes
        
        # Skip AlgorithmIdentifier content
        idx += algo_len
        
        # PrivateKey (OCTET STRING)
        if der_data[idx] != 0x04:
            # Tentar formato antigo (tag 0x84) para compatibilidade
            if der_data[idx] == 0x84:
                idx += 1
                priv_len = der_data[idx]
                idx += 1
                private_key_bytes = der_data[idx:idx+priv_len]
                return bytes_to_little_int(private_key_bytes)
            raise ValueError(f"Expected OCTET STRING (0x04), got 0x{der_data[idx]:02x}")
        
        idx += 1
        priv_len = der_data[idx]
        idx += 1
        
        # Handle long length
        if priv_len == 0x81:
            priv_len = der_data[idx]
            idx += 1
        elif priv_len == 0x82:
            priv_len = (der_data[idx] << 8) | der_data[idx+1]
            idx += 2
        
        private_key_bytes = der_data[idx:idx+priv_len]
        
        if debug:
            print(f"DEBUG: Private key bytes length: {len(private_key_bytes)} bytes")
            print(f"DEBUG: Private key hex: {private_key_bytes.hex()}")
        
        # Convert to integer (little-endian)
        return bytes_to_little_int(private_key_bytes)
        
    except Exception as e:
        if debug:
            print(f"DEBUG: ASN.1 parsing failed: {e}")
        
        # Fallback: procurar por 66 bytes no DER
        if len(der_data) == 66:
            key_int = bytes_to_little_int(der_data)
            if 0 < key_int < N:
                if debug:
                    print("DEBUG: Whole data is a valid 66-byte key")
                return key_int
        
        for i in range(len(der_data) - 66 + 1):
            chunk = der_data[i:i+66]
            key_int = bytes_to_little_int(chunk)
            if 0 < key_int < N:
                if debug:
                    print(f"DEBUG: Found 66-byte key at offset {i}")
                return key_int
        
        raise ValueError(f"Cannot parse Ed521 private key: {e}")

def parse_ed521_pem_public_key(pem_data, debug=False):
    """Parse Ed521 public key from PEM SPKI format (compatible with edgetk Go implementation)"""
    lines = pem_data.strip().split('\n')
    b64_data = ''.join([line.strip() for line in lines if line and not line.startswith('-----')])
    
    der_data = base64.b64decode(b64_data)
    
    if debug:
        print(f"DEBUG: Public key DER length: {len(der_data)} bytes")
        print(f"DEBUG: Public key DER hex: {der_data.hex()}")
    
    try:
        idx = 0
        
        if der_data[idx] != 0x30:
            raise ValueError("Expected SEQUENCE (0x30)")
        idx += 1
        
        if idx >= len(der_data):
            raise ValueError("Unexpected end of data")
        
        seq_len = der_data[idx]
        idx += 1
        
        if seq_len & 0x80:
            num_bytes = seq_len & 0x7F
            if idx + num_bytes > len(der_data):
                raise ValueError("Incomplete SEQUENCE length")
            seq_len = int.from_bytes(der_data[idx:idx+num_bytes], 'big')
            idx += num_bytes
        
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
        
        if idx < algo_end and der_data[idx] == 0x05:
            idx += 1
            if idx >= len(der_data):
                raise ValueError("Unexpected end of data")
            null_len = der_data[idx]
            idx += 1
            if null_len != 0:
                raise ValueError(f"Expected NULL (0x00), got length {null_len}")
        
        idx = algo_end
        
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
        
        if idx >= len(der_data):
            raise ValueError("Unexpected end of data")
        
        unused_bits = der_data[idx]
        idx += 1
        
        if unused_bits != 0:
            if debug:
                print(f"DEBUG: Warning: BIT STRING has {unused_bits} unused bits")
        
        compressed_pub = der_data[idx:idx + bitstring_len - 1]
        
        if debug:
            print(f"DEBUG: Compressed public key length: {len(compressed_pub)} bytes")
            print(f"DEBUG: Compressed public key hex: {compressed_pub.hex()}")
        
        pub_x, pub_y = ed521_decompress_point(compressed_pub)
        
        if pub_x is None or pub_y is None:
            raise ValueError("Failed to decompress public key")
        
        return pub_x, pub_y
        
    except Exception as e:
        if debug:
            print(f"DEBUG: ASN.1 parsing failed: {e}")
        
        if len(der_data) == ED521_BYTE_LEN:
            pub_x, pub_y = ed521_decompress_point(der_data)
            if pub_x is not None and pub_y is not None:
                if debug:
                    print("DEBUG: Found raw 66-byte compressed public key")
                return pub_x, pub_y
        
        for i in range(len(der_data) - ED521_BYTE_LEN + 1):
            chunk = der_data[i:i+ED521_BYTE_LEN]
            pub_x, pub_y = ed521_decompress_point(chunk)
            if pub_x is not None and pub_y is not None:
                if debug:
                    print(f"DEBUG: Found compressed public key at offset {i}")
                return pub_x, pub_y
        
        raise ValueError(f"Cannot parse Ed521 public key: {e}")

def parse_pem_private_key(pem_data):
    """
    Parse private key from PEM PKCS8 format (for both Ed25519, X25519 and X448)
    Returns the seed/key bytes
    """
    lines = pem_data.strip().split('\n')
    
    # Check if encrypted
    is_encrypted = False
    for line in lines:
        if line.startswith("Proc-Type:") and "ENCRYPTED" in line:
            is_encrypted = True
            break
    
    if is_encrypted:
        password = getpass.getpass("Enter password to decrypt private key: ")
        try:
            der_data = decrypt_private_key_pem(pem_data, password)
        except ValueError as e:
            print(f"✖ Decryption failed: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        b64_data = ''.join([line.strip() for line in lines if line and not line.startswith('-----')])
        der_data = base64.b64decode(b64_data)
    
    idx = 0
    
    if der_data[idx] != 0x30:
        raise ValueError("Invalid PKCS8 format: expected SEQUENCE")
    idx += 1
    
    seq_len = der_data[idx]
    idx += 1
    if seq_len & 0x80:
        num_bytes = seq_len & 0x7F
        seq_len = int.from_bytes(der_data[idx:idx+num_bytes], 'big')
        idx += num_bytes
    
    if der_data[idx] != 0x02:
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
    
    if der_data[idx] != 0x30:
        raise ValueError("Invalid PKCS8 format: expected AlgorithmIdentifier SEQUENCE")
    idx += 1
    
    algo_len = der_data[idx]
    idx += 1
    if algo_len & 0x80:
        num_bytes = algo_len & 0x7F
        algo_len = int.from_bytes(der_data[idx:idx+num_bytes], 'big')
        idx += num_bytes
    
    algo_end = idx + algo_len
    
    if der_data[idx] != 0x06:
        raise ValueError("Invalid PKCS8 format: expected OID")
    idx += 1
    
    oid_len = der_data[idx]
    idx += 1
    if oid_len & 0x80:
        num_bytes = oid_len & 0x7F
        oid_len = int.from_bytes(der_data[idx:idx+num_bytes], 'big')
        idx += num_bytes
    
    idx += oid_len
    
    if idx < algo_end and der_data[idx] == 0x05:
        idx += 1
        if idx >= len(der_data):
            raise ValueError("Invalid PKCS8 format: incomplete NULL")
        null_len = der_data[idx]
        idx += 1
        if null_len != 0:
            raise ValueError(f"Invalid NULL length: expected 0, got {null_len}")
    
    if idx >= len(der_data):
        raise ValueError("Invalid PKCS8 format: no private key data")
    
    if der_data[idx] != 0x04:
        raise ValueError("Invalid PKCS8 format: expected OCTET STRING")
    idx += 1
    
    if idx >= len(der_data):
        raise ValueError("Invalid PKCS8 format: incomplete OCTET STRING")
    
    octet_len = der_data[idx]
    idx += 1
    
    if octet_len & 0x80:
        num_bytes = octet_len & 0x7F
        octet_len = int.from_bytes(der_data[idx:idx+num_bytes], 'big')
        idx += num_bytes
    
    if idx + octet_len > len(der_data):
        raise ValueError(f"Invalid PKCS8 format: OCTET STRING incomplete, need {octet_len} bytes")
    
    private_key_bytes = der_data[idx:idx+octet_len]
    
    # Extract actual key bytes (might have inner OCTET STRING)
    if len(private_key_bytes) > 0 and private_key_bytes[0] == 0x04:
        if len(private_key_bytes) >= 2:
            inner_len = private_key_bytes[1]
            if inner_len & 0x80:
                num_bytes = inner_len & 0x7F
                inner_len = int.from_bytes(private_key_bytes[2:2+num_bytes], 'big')
                private_key_bytes = private_key_bytes[2+num_bytes:2+num_bytes+inner_len]
            else:
                private_key_bytes = private_key_bytes[2:2+inner_len]
    
    return private_key_bytes

def parse_pem_public_key(pem_data):
    """
    Parse public key from PEM SPKI format (for both Ed25519, X25519 and X448)
    Returns the public key bytes
    """
    lines = pem_data.strip().split('\n')
    b64_data = ''.join([line.strip() for line in lines if line and not line.startswith('-----')])
    
    der_data = base64.b64decode(b64_data)
    idx = 0
    
    if der_data[idx] != 0x30:
        raise ValueError("Invalid SPKI format: expected SEQUENCE")
    idx += 1
    
    seq_len = der_data[idx]
    idx += 1
    if seq_len & 0x80:
        num_bytes = seq_len & 0x7F
        seq_len = int.from_bytes(der_data[idx:idx+num_bytes], 'big')
        idx += num_bytes
    
    if der_data[idx] != 0x30:
        raise ValueError("Invalid SPKI format: expected AlgorithmIdentifier SEQUENCE")
    idx += 1
    
    algo_len = der_data[idx]
    idx += 1
    idx += algo_len
    
    if der_data[idx] != 0x03:
        raise ValueError("Invalid SPKI format: expected BIT STRING")
    idx += 1
    
    bitstring_len = der_data[idx]
    idx += 1
    if bitstring_len & 0x80:
        num_bytes = bitstring_len & 0x7F
        bitstring_len = int.from_bytes(der_data[idx:idx+num_bytes], 'big')
        idx += num_bytes
    
    if der_data[idx] != 0x00:
        raise ValueError("Invalid BIT STRING: unused bits should be 0")
    idx += 1
    
    public_key_bytes = der_data[idx:idx+bitstring_len-1]
    
    return public_key_bytes

# =========================
# 2. RECURSIVE HASH FUNCTION 
# =========================

def calculate_file_hash(file_path, hash_algo='sha256'):
    """Calculate file hash with support for modern algorithms"""
    try:
        if hash_algo.startswith('blake2'):
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
                hash_func = hashlib.blake2b()
        
        elif hash_algo.startswith('sha3_'):
            if hash_algo == 'sha3_224':
                hash_func = hashlib.sha3_224()
            elif hash_algo == 'sha3_256':
                hash_func = hashlib.sha3_256()
            elif hash_algo == 'sha3_384':
                hash_func = hashlib.sha3_384()
            elif hash_algo == 'sha3_512':
                hash_func = hashlib.sha3_512()
            else:
                hash_func = hashlib.sha3_256()
        
        elif hash_algo == 'shake_128':
            hash_func = hashlib.shake_128()
        
        elif hash_algo == 'shake_256':
            hash_func = hashlib.shake_256()
        
        else:
            try:
                hash_func = hashlib.new(hash_algo)
            except ValueError:
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
            for chunk in iter(lambda: f.read(4096), b''):
                hash_func.update(chunk)
        
        if hash_algo in ['shake_128']:
            return hash_func.hexdigest(32)
        if hash_algo in ['shake_256']:
            return hash_func.hexdigest(64)
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
    
    print("Standard algorithms:")
    std_algs = ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512']
    for alg in std_algs:
        if alg in hashlib.algorithms_available:
            try:
                hash_obj = hashlib.new(alg)
                print(f"  {alg:15} - {hash_obj.digest_size * 8}-bit")
            except:
                print(f"  {alg:15} - available")
    
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
    
    print("\nBLAKE2 family:")
    blake2_algs = ['blake2b', 'blake2s']
    for alg in blake2_algs:
        if alg in hashlib.algorithms_available:
            try:
                hash_obj = hashlib.new(alg)
                print(f"  {alg:15} - {hash_obj.digest_size * 8}-bit")
            except:
                print(f"  {alg:15} - available")
    
    print("  blake2b_256      - 256-bit BLAKE2b")
    print("  blake2b_512      - 512-bit BLAKE2b")
    print("  blake2s_128      - 128-bit BLAKE2s")
    print("  blake2s_256      - 256-bit BLAKE2s")
    
    print("\nOther available algorithms:")
    other_algs = sorted([alg for alg in hashlib.algorithms_available 
                        if alg not in std_algs + sha3_algs + blake2_algs])
    for alg in other_algs[:15]:
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
    available_algs = list(hashlib.algorithms_available)
    custom_algs = ['blake2b_256', 'blake2b_512', 'blake2s_128', 'blake2s_256']
    
    if hash_algo in custom_algs:
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
    
    if output_file:
        try:
            with open(output_file, 'w') as f:
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
    
    print("-" * 80)
    print(f"Summary:")
    print(f"  Files provided: {files_found}")
    print(f"  Files processed: {files_processed}")
    print(f"  Errors: {errors}")
    
    if files_processed == 0:
        print("⚠ No files were processed. Check file paths and permissions.")

def hashsum_calc(pattern, files=None, recursive=False, hash_algo='sha256', output_file=None):
    """Calculate hashes for files matching pattern"""
    available_algs = list(hashlib.algorithms_available)
    custom_algs = ['blake2b_256', 'blake2b_512', 'blake2s_128', 'blake2s_256']
    
    if hash_algo in custom_algs:
        if 'blake2b' not in hashlib.algorithms_available or 'blake2s' not in hashlib.algorithms_available:
            print(f"✖ BLAKE2 not available in this Python version", file=sys.stderr)
            sys.exit(1)
    elif hash_algo not in available_algs and hash_algo not in custom_algs:
        print(f"✖ Unsupported hash algorithm: {hash_algo}", file=sys.stderr)
        print(f"\nUse 'hashsum list' to see available algorithms")
        sys.exit(1)
    
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
    
    if output_file:
        try:
            with open(output_file, 'w') as f:
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
    
    expected_hashes = {}
    hash_algo = 'sha256'
    
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            if line.startswith('# Algorithm:'):
                hash_algo = line.split(':')[1].strip()
            continue
        
        parts = line.split()
        if len(parts) >= 2:
            file_hash = parts[0]
            file_path = ' '.join(parts[1:])
            
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
# 3. HMAC (standard Python)
# =========================

def generate_hmac(key, data, hash_algo='sha256'):
    """
    Generate HMAC for data using specified hash algorithm
    """
    if isinstance(key, str):
        key = key.encode('utf-8')
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    try:
        hmac_obj = hmac_lib.new(key, data, digestmod=hash_algo)
        return hmac_obj.hexdigest()
    except ValueError as e:
        try:
            hmac_obj = hmac_lib.HMAC(key, data, digestmod=hash_algo)
            return hmac_obj.hexdigest()
        except:
            raise ValueError(f"Unsupported hash algorithm for HMAC: {hash_algo}")

def hmac_calc(key=None, data=None, file_path=None, hash_algo='sha256'):
    """
    Calculate HMAC for data or file
    """
    if key is None:
        key = getpass.getpass("Enter secret key: ")
    
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
    
    try:
        hmac_result = generate_hmac(key, data_bytes, hash_algo)
        
        print(f"HMAC-{hash_algo} calculation:")
        print(f"  Data source: {data_source}")
        print(f"  Key length: {len(key) if isinstance(key, bytes) else len(key.encode('utf-8'))} bytes")
        print(f"  Data length: {len(data_bytes)} bytes")
        print(f"  HMAC (hex): {hmac_result}")
        
        return hmac_result
        
    except Exception as e:
        print(f"✖ HMAC calculation failed: {e}", file=sys.stderr)
        sys.exit(1)

def hmac_verify(key=None, hmac_value=None, data=None, file_path=None, hash_algo='sha256'):
    """
    Verify HMAC for data or file
    """
    if key is None:
        key = getpass.getpass("Enter secret key: ")
    
    if hmac_value is None:
        hmac_value = input("Enter HMAC to verify (hex): ").strip()
    
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
    
    try:
        calculated_hmac = generate_hmac(key, data_bytes, hash_algo)
        
        print(f"HMAC-{hash_algo} verification:")
        print(f"  Data source: {data_source}")
        print(f"  Provided HMAC: {hmac_value}")
        print(f"  Calculated HMAC: {calculated_hmac}")
        
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
    for alg in other_algs[:10]:
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

    print(f"{derived_key.hex()}")

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

def ed521_generate(priv_path, pub_path, password=None):
    """Generate Ed521 keys and save in PEM PKCS8 format with optional encryption"""
    print("Generating Ed521 keys (521-bit curve)...")
    
    private_key = ed521_generate_private_key()
    print(f"Private key generated: {hex(private_key)[:34]}...")
    
    pub_x, pub_y = ed521_get_public_key(private_key)
    print(f"Public key generated: ({hex(pub_x)[:20]}..., {hex(pub_y)[:20]}...)")
    
    if not ed521_is_on_curve(pub_x, pub_y):
        print("✖ Generated public key is not on the curve!", file=sys.stderr)
        sys.exit(1)
    
    private_pem = ed521_private_to_pem_pkcs8(private_key, password)
    public_pem = ed521_public_to_pem(pub_x, pub_y)
    
    with open(priv_path, "w") as f:
        f.write(private_pem)
    print(f"✔ Private key saved in {priv_path} (PEM PKCS8{' - ENCRYPTED' if password else ''})")
    
    with open(pub_path, "w") as f:
        f.write(public_pem)
    print(f"✔ Public key saved in {pub_path} (PEM)")
    
    return private_key, pub_x, pub_y

def ed521_sign_file(priv_path, msg_path):
    """Sign a file with Ed521"""
    try:
        with open(priv_path, "r") as f:
            pem_data = f.read()
        
        private_key = parse_ed521_pem_private_key(pem_data)
        
        with open(msg_path, "rb") as f:
            message = f.read()
        
        signature = ed521_sign(private_key, message)
        
        print(f"{signature.hex()}")
        
        return signature
        
    except Exception as e:
        print(f"✖ Error signing with Ed521: {e}", file=sys.stderr)
        sys.exit(1)

def ed521_verify_file(pub_path, msg_path, sig_hex):
    """Verify Ed521 signature for a file"""
    try:
        with open(pub_path, "r") as f:
            pem_data = f.read()
        
        pub_x, pub_y = parse_ed521_pem_public_key(pem_data)
        
        with open(msg_path, "rb") as f:
            message = f.read()
        
        signature = bytes.fromhex(sig_hex)
        
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
    
    while True:
        r_bytes = os.urandom(byte_len)
        r = bytes_to_little_int(r_bytes)
        if r < N:
            break
    
    Rx, Ry = ed521_scalar_base_mult(little_int_to_bytes(r, byte_len))
    R_comp = ed521_compress_point(Rx, Ry)
    
    Ax, Ay = ed521_get_public_key(priv)
    A_comp = ed521_compress_point(Ax, Ay)
    
    input_data = R_comp + A_comp
    c_bytes = ed521_hash(0x00, b'', input_data)
    c = bytes_to_little_int(c_bytes[:byte_len]) % N
    
    s = (r + c * priv) % N
    
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
    
    Rx, Ry = ed521_decompress_point(R_comp)
    if Rx is None or Ry is None:
        return False
    
    s = bytes_to_little_int(s_bytes)
    
    A_comp = ed521_compress_point(pub_x, pub_y)
    input_data = R_comp + A_comp
    c_bytes = ed521_hash(0x00, b'', input_data)
    c = bytes_to_little_int(c_bytes[:byte_len]) % N
    
    sGx, sGy = ed521_scalar_base_mult(little_int_to_bytes(s, byte_len))
    cAx, cAy = ed521_scalar_mult(pub_x, pub_y, little_int_to_bytes(c, byte_len))
    RpluscAx, RpluscAy = ed521_add_points(Rx, Ry, cAx, cAy)
    
    return sGx == RpluscAx and sGy == RpluscAy
    
def ed521_prove_command(priv_path: str):
    """Generate ZKP proof of private key knowledge"""
    with open(priv_path, "r") as f:
        pem_data = f.read()
    
    try:
        private_key = parse_ed521_pem_private_key(pem_data)
    except Exception as e:
        print(f"✖ Error parsing private key: {e}")
        sys.exit(1)
    
    proof = ed521_prove_knowledge(private_key)
    proof_hex = proof.hex()
    
    print(f"✔ Zero-knowledge proof generated")
    print(f"\nProof (hex): {proof_hex}")
    print(f"Proof length: {len(proof)} bytes ({(len(proof) * 8)} bits)")
    
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
    with open(pub_path, "r") as f:
        pem_data = f.read()
    
    try:
        pub_x, pub_y = parse_ed521_pem_public_key(pem_data)
    except Exception as e:
        print(f"✖ Error parsing public key: {e}")
        sys.exit(1)
    
    if proof_file:
        with open(proof_file, "r") as f:
            proof_hex = f.read().strip()
    
    if not proof_hex:
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
    
    try:
        proof = bytes.fromhex(proof_hex)
    except binascii.Error as e:
        print(f"✖ Invalid hex: {e}")
        sys.exit(1)
    
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
    
    print("1. Key generation test:")
    priv_key = ed521_generate_private_key()
    pub_x, pub_y = ed521_get_public_key(priv_key)
    print(f"   Private key (first 16 bytes): {hex(priv_key)[:34]}...")
    print(f"   Public key on curve: {ed521_is_on_curve(pub_x, pub_y)}")
    
    print("\n2. Point compression test:")
    compressed = ed521_compress_point(pub_x, pub_y)
    decomp_x, decomp_y = ed521_decompress_point(compressed)
    print(f"   Compression successful: {len(compressed)} bytes")
    print(f"   Decompression correct: {decomp_x == pub_x and decomp_y == pub_y}")
    
    print("\n3. Signature test:")
    message = b"Test message for E-521 EdDSA"
    signature = ed521_sign(priv_key, message)
    valid = ed521_verify(pub_x, pub_y, message, signature)
    print(f"   Signature created: {len(signature)} bytes")
    print(f"   Signature valid: {valid}")
    
    wrong_message = b"Wrong message"
    wrong_valid = ed521_verify(pub_x, pub_y, wrong_message, signature)
    print(f"   Wrong message rejected: {not wrong_valid}")
    
    print("\n4. Zero-knowledge proof test:")
    proof = ed521_prove_knowledge(priv_key)
    proof_valid = ed521_verify_knowledge(pub_x, pub_y, proof)
    print(f"   Proof generated: {len(proof)} bytes")
    print(f"   Proof valid: {proof_valid}")
    
    print("\n5. PKCS#8 serialization test:")
    public_pem = ed521_public_to_pem(pub_x, pub_y)
    private_pem = ed521_private_to_pem_pkcs8(priv_key)
    
    parsed_pub_x, parsed_pub_y = parse_ed521_pem_public_key(public_pem)
    parsed_priv = parse_ed521_pem_private_key(private_pem)
    
    print(f"   Public key serialization correct: {parsed_pub_x == pub_x and parsed_pub_y == pub_y}")
    print(f"   Private key serialization correct: {parsed_priv == priv_key}")
    
    print("\n6. Encryption test:")
    password = "testpassword"
    encrypted_pem = ed521_private_to_pem_pkcs8(priv_key, password)
    print(f"   Encryption successful: {'ENCRYPTED' in encrypted_pem}")
    
    print("\n=== All tests passed! ===")

# =========================
# 6. X25519 FUNCTIONS (pure Python)
# =========================

def x25519_generate_keys(priv_path, pub_path, password=None):
    """Generate X25519 key pair with optional encryption"""
    print("Generating X25519 key pair...")
    
    private_key = x25519_generate_private_key()
    public_key = x25519_get_public_key(private_key)
    
    print(f"Private key (raw): {private_key.hex()}")
    print(f"Public key (raw): {public_key.hex()}")
    
    private_pem = x25519_private_to_pem_pkcs8(private_key, password)
    public_pem = x25519_public_to_pem(public_key)
    
    with open(priv_path, "w") as f:
        f.write(private_pem)
    print(f"✔ Private key saved in {priv_path} (PEM PKCS8{' - ENCRYPTED' if password else ''})")
    
    with open(pub_path, "w") as f:
        f.write(public_pem)
    print(f"✔ Public key saved in {pub_path} (PEM)")
    
    return private_key, public_key

def x25519_shared_secret_calc(priv_path, peer_pub_path):
    """Calculate X25519 shared secret"""
    try:
        with open(priv_path, "r") as f:
            priv_pem = f.read()
        sk = parse_pem_private_key(priv_pem)

        with open(peer_pub_path, "r") as f:
            peer_pem = f.read()
        pk = parse_pem_public_key(peer_pem)

        if len(sk) != 32:
            raise ValueError(f"Private key must be 32 bytes, but is {len(sk)}")
        if len(pk) != 32:
            raise ValueError(f"Public key must be 32 bytes, but is {len(pk)}")

        shared = x25519_shared_secret(sk, pk)

        print(f"{shared.hex()}")
        return shared

    except Exception as e:
        print(f"✖ Error: {e}", file=sys.stderr)
        sys.exit(1)

# =========================
# 7. X448 FUNCTIONS (pure Python)
# =========================

def x448_generate_keys(priv_path, pub_path, password=None):
    """Generate X448 key pair with optional encryption"""
    print("Generating X448 key pair (RFC 7748)...")
    
    private_key = x448_generate_private_key()
    public_key = x448_get_public_key(private_key)
    
    print(f"Private key (raw): {private_key.hex()}")
    print(f"Public key (raw): {public_key.hex()}")
    
    # Show clamping details
    print(f"\nClamping details (RFC 7748):")
    print(f"  Byte 0: 0x{private_key[0]:02x} (bits 0-1: {private_key[0] & 0x03:02b} - should be 00)")
    print(f"  Byte 55: 0x{private_key[55]:02x} (bit 447: {(private_key[55] >> 7) & 1} - should be 1)")
    
    private_pem = x448_private_to_pem_pkcs8(private_key, password)
    public_pem = x448_public_to_pem(public_key)
    
    with open(priv_path, "w") as f:
        f.write(private_pem)
    print(f"✔ Private key saved in {priv_path} (PEM PKCS8{' - ENCRYPTED' if password else ''})")
    
    with open(pub_path, "w") as f:
        f.write(public_pem)
    print(f"✔ Public key saved in {pub_path} (PEM)")
    
    return private_key, public_key

def x448_shared_secret_calc(priv_path, peer_pub_path):
    """Calculate X448 shared secret"""
    try:
        with open(priv_path, "r") as f:
            priv_pem = f.read()
        sk = parse_pem_private_key(priv_pem)

        with open(peer_pub_path, "r") as f:
            peer_pem = f.read()
        pk = parse_pem_public_key(peer_pem)

        if len(sk) != 56:
            raise ValueError(f"Private key must be 56 bytes, but is {len(sk)}")
        if len(pk) != 56:
            raise ValueError(f"Public key must be 56 bytes, but is {len(pk)}")

        shared = x448_shared_secret(sk, pk)

        print(f"{shared.hex()}")
        return shared

    except Exception as e:
        print(f"✖ Error: {e}", file=sys.stderr)
        sys.exit(1)

# =========================
# 8. CURUPIRA LETTERSOUP FUNCTIONS
# =========================

def curupira_encrypt(key_hex, infile=None, aad=None, outfile=None):
    """Encrypt with Curupira in LetterSoup AEAD mode"""
    try:
        key = bytes.fromhex(key_hex)
        if len(key) not in [12, 18, 24]:
            raise ValueError(f"Key must be 12, 18 or 24 bytes, got {len(key)} bytes")
        
        if infile:
            with open(infile, "rb") as f:
                plaintext = f.read()
            data_source = f"file: {infile}"
        else:
            # Ler de stdin
            plaintext = sys.stdin.buffer.read()
            data_source = "stdin"
        
        if len(plaintext) == 0:
            raise ValueError("No plaintext data to encrypt")
        
        cipher = Curupira1(key)
        aead = LetterSoup(cipher)
        
        nonce = os.urandom(12)
        aead.SetIV(nonce)
        
        # SEMPRE chamar Update, mesmo com AAD vazio
        if aad is None:
            aad_bytes = b''
        elif isinstance(aad, str):
            aad_bytes = aad.encode('utf-8')
        else:
            aad_bytes = aad
        
        aead.Update(aad_bytes)
        
        ciphertext = bytearray(len(plaintext))
        aead.Encrypt(ciphertext, plaintext)
        
        tag = aead.GetTag(None, 96)
        
        output = nonce + tag + bytes(ciphertext)
        
        if outfile:
            with open(outfile, "wb") as f:
                f.write(output)
            print(f"✔ Encrypted to {outfile}", file=sys.stderr)
            print(f"Data source: {data_source}", file=sys.stderr)
            print(f"Nonce: {nonce.hex()}", file=sys.stderr)
            print(f"Tag: {tag.hex()}", file=sys.stderr)
            print(f"Ciphertext length: {len(ciphertext)} bytes", file=sys.stderr)
        else:
            sys.stdout.buffer.write(output)
        
        return output
        
    except Exception as e:
        print(f"✖ Encryption failed: {e}", file=sys.stderr)
        sys.exit(1)

def curupira_decrypt(key_hex, infile=None, aad=None, outfile=None):
    """Decrypt with Curupira in LetterSoup AEAD mode"""
    try:
        key = bytes.fromhex(key_hex)
        if len(key) not in [12, 18, 24]:
            raise ValueError(f"Key must be 12, 18 or 24 bytes, got {len(key)} bytes")
        
        if infile:
            with open(infile, "rb") as f:
                data = f.read()
            data_source = f"file: {infile}"
        else:
            # Ler de stdin
            print("Reading ciphertext from stdin...", file=sys.stderr)
            data = sys.stdin.buffer.read()
            data_source = "stdin"
        
        if len(data) < 24:
            print("✖ Data too short", file=sys.stderr)
            sys.exit(1)
        
        nonce = data[:12]
        tag = data[12:24]
        ciphertext = data[24:]
        
        cipher = Curupira1(key)
        aead = LetterSoup(cipher)
        aead.SetIV(nonce)
        
        # SEMPRE chamar Update, mesmo com AAD vazio
        if aad is None:
            aad_bytes = b''
        elif isinstance(aad, str):
            aad_bytes = aad.encode('utf-8')
        else:
            aad_bytes = aad
        
        aead.Update(aad_bytes)
        
        plaintext = bytearray(len(ciphertext))
        aead.Decrypt(plaintext, ciphertext)
        
        # Verify tag
        test_ciphertext = bytearray(len(plaintext))
        aead_verify = LetterSoup(cipher)
        aead_verify.SetIV(nonce)
        
        # SEMPRE chamar Update, mesmo com AAD vazio
        aead_verify.Update(aad_bytes)
        
        aead_verify.Encrypt(test_ciphertext, bytes(plaintext))
        test_tag = aead_verify.GetTag(None, 96)
        
        if tag != test_tag:
            raise ValueError(f"Authentication failed! Expected tag: {test_tag.hex()}, Received tag: {tag.hex()}")
        
        if outfile:
            with open(outfile, "wb") as f:
                f.write(plaintext)
            print(f"✔ Decrypted to {outfile}", file=sys.stderr)
            print(f"Data source: {data_source}", file=sys.stderr)
        else:
            sys.stdout.buffer.write(plaintext)
        
        return bytes(plaintext)
        
    except Exception as e:
        print(f"✖ Decryption failed: {e}", file=sys.stderr)
        sys.exit(1)

# =========================
# CLI MAIN
# =========================

def main():
    parser = argparse.ArgumentParser(
        description="EDGE Crypto Toolbox (Ed521, Scrypt, X25519, X448, Hashsum, HMAC, HKDF, Curupira LetterSoup, Anubis-GCM)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # File hashes
  python %(prog)s hashsum calc "*.txt"
  python %(prog)s hashsum calc "*.py" -r -a sha256 -o hashes.txt
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
  python %(prog)s hkdf derive   # Interactive mode
  python %(prog)s hkdf compare  # Verify derivation
  python %(prog)s hkdf list     # List algorithms
  
  # Ed521 signatures (always available) (ICP-Brasil Standard)
  python %(prog)s ed521 gen --priv ed521_priv.pem --pub ed521_pub.pem [--password "mypass"]
  python %(prog)s ed521 sign --priv ed521_priv.pem --msg document.txt
  python %(prog)s ed521 verify --pub ed521_pub.pem --msg document.txt --sig SIGNATURE_HEX
  python %(prog)s ed521 prove --priv ed521_priv.pem
  python %(prog)s ed521 verify-proof --pub ed521_pub.pem --proof-file ed521_proof.bin
  python %(prog)s ed521 test
  
  # X25519 key exchange (pure Python)
  python %(prog)s x25519 gen --priv private.pem --pub public.pem [--password "mypass"]
  python %(prog)s x25519 shared --priv alice_priv.pem --peer bob_pub.pem
  python %(prog)s x25519 parse --key key.pem
  
  # X448 key exchange (pure Python)
  python %(prog)s x448 gen --priv x448_private.pem --pub x448_public.pem [--password "mypass"]
  python %(prog)s x448 shared --priv alice_x448.pem --peer bob_x448.pem
  python %(prog)s x448 parse --key x448_key.pem
  
  # Curupira LetterSoup AEAD
  python %(prog)s curupira encrypt --key KEY_HEX --infile secret.txt [--aad metadata] [--outfile encrypted.bin]
  cat encrypted.bin | python %(prog)s curupira decrypt --key KEY_HEX [--aad metadata] [--outfile decrypted.txt]
  
  # Anubis-GCM AEAD
  python %(prog)s anubis encrypt --key KEY_HEX --infile secret.txt [--aad metadata] [--outfile encrypted.bin]
  cat encrypted.bin | python %(prog)s anubis decrypt --key KEY_HEX [--aad metadata] [--outfile decrypted.txt]
        """
    )
    
    sub = parser.add_subparsers(dest="tool", title="Tools", required=True)

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
    sc_d.add_argument("--keylen", type=int, default=24, help="Derived key length (bytes)")

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
    hk_calc.add_argument("--length", type=int, default=24, help="Output length in bytes")
    hk_calc.add_argument("--algo", default="sha256", help="Hash algorithm")
    
    hk_derive = hksub.add_parser("derive", help="Derive key with HKDF (interactive)")
    hk_derive.add_argument("--salt", help="Salt (string)")
    hk_derive.add_argument("--ikm", help="Input Key Material (string)")
    hk_derive.add_argument("--info", help="Context info (string)")
    hk_derive.add_argument("--length", type=int, default=24, help="Output length in bytes")
    hk_derive.add_argument("--algo", default="sha256", help="Hash algorithm")
    
    hk_compare = hksub.add_parser("compare", help="Compare HKDF output")
    
    hk_list = hksub.add_parser("list", help="List HKDF algorithms")

    # ======================
    # Ed521
    # ======================
    ed521 = sub.add_parser("ed521", help="Ed521 signatures (521-bit curve)")
    ed521sub = ed521.add_subparsers(dest="cmd", required=True)
    
    ed521_gen = ed521sub.add_parser("gen", help="Generate Ed521 keys")
    ed521_gen.add_argument("--priv", default="ed521_private.pem", help="Private key PEM")
    ed521_gen.add_argument("--pub", default="ed521_public.pem", help="Public key PEM")
    ed521_gen.add_argument("--password", help="Password to encrypt private key (optional)")
    
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
    
    ed521_parse = ed521sub.add_parser("parse", help="Parse Ed521 key file and display info")
    ed521_parse.add_argument("key_file", help="PEM key file to parse")
    ed521_parse.add_argument("--debug", action="store_true", help="Debug output")

    ed521_test_cmd = ed521sub.add_parser("test", help="Test Ed521 implementation")

    # ======================
    # X25519
    # ======================
    x25519 = sub.add_parser("x25519", help="X25519 key exchange (pure Python)")
    x25519sub = x25519.add_subparsers(dest="cmd", required=True)
    x25519_gen = x25519sub.add_parser("gen", help="Generate keys")
    x25519_gen.add_argument("--priv", default="x25519_private.pem", help="Private key PEM")
    x25519_gen.add_argument("--pub", default="x25519_public.pem", help="Public key PEM")
    x25519_gen.add_argument("--password", help="Password to encrypt private key (optional)")
    
    x25519_sh = x25519sub.add_parser("shared", help="Shared secret")
    x25519_sh.add_argument("--priv", required=True, help="Your private key PEM")
    x25519_sh.add_argument("--peer", required=True, help="Peer public key PEM")

    x25519_parse = x25519sub.add_parser("parse", help="Parse X25519 key file and display info")
    x25519_parse.add_argument("key_file", help="PEM key file to parse")
    x25519_parse.add_argument("--debug", action="store_true", help="Debug output")

    # ======================
    # X448
    # ======================
    x448 = sub.add_parser("x448", help="X448 key exchange (pure Python)")
    x448sub = x448.add_subparsers(dest="cmd", required=True)
    x448_gen = x448sub.add_parser("gen", help="Generate keys")
    x448_gen.add_argument("--priv", default="x448_private.pem", help="Private key PEM")
    x448_gen.add_argument("--pub", default="x448_public.pem", help="Public key PEM")
    x448_gen.add_argument("--password", help="Password to encrypt private key (optional)")
    
    x448_sh = x448sub.add_parser("shared", help="Shared secret")
    x448_sh.add_argument("--priv", required=True, help="Your private key PEM")
    x448_sh.add_argument("--peer", required=True, help="Peer public key PEM")

    x448_parse = x448sub.add_parser("parse", help="Parse X448 key file and display info")
    x448_parse.add_argument("key_file", help="PEM key file to parse")
    x448_parse.add_argument("--debug", action="store_true", help="Debug output")

    # ======================
    # Curupira LetterSoup
    # ======================
    cur = sub.add_parser("curupira", help="Curupira block cipher in LetterSoup AEAD mode")
    cursub = cur.add_subparsers(dest="cmd", required=True)

    c_enc = cursub.add_parser("encrypt", help="Encrypt")
    c_enc.add_argument("--key", required=True, help="Key hex (12, 18, or 24 bytes)")
    c_enc.add_argument("--infile", help="Input file (optional, uses stdin if not provided)")
    c_enc.add_argument("--aad", help="Additional authenticated data (AAD)")
    c_enc.add_argument("--outfile", help="Output file (default: stdout)")

    c_dec = cursub.add_parser("decrypt", help="Decrypt")
    c_dec.add_argument("--key", required=True, help="Key hex (12, 18, or 24 bytes)")
    c_dec.add_argument("--infile", help="Input file (optional, uses stdin if not provided)")
    c_dec.add_argument("--aad", help="Additional authenticated data (AAD)")
    c_dec.add_argument("--outfile", help="Output file (default: stdout)")

    # ======================
    # Anubis-GCM
    # ======================
    anubis_parser = sub.add_parser("anubis", help="Anubis block cipher in GCM AEAD mode")
    anubissub = anubis_parser.add_subparsers(dest="cmd", required=True)

    a_enc = anubissub.add_parser("encrypt", help="Encrypt with Anubis-GCM")
    a_enc.add_argument("--key", required=True, help="Key hex (16, 20, 24, 28, 32, 36, 40 bytes)")
    a_enc.add_argument("--infile", help="Input file (optional, uses stdin if not provided)")
    a_enc.add_argument("--aad", help="Additional authenticated data (AAD)")
    a_enc.add_argument("--outfile", help="Output file (default: stdout)")
    a_enc.add_argument("--tag-size", type=int, default=16, choices=range(12, 17), 
                       help="Tag size in bytes (12-16, default: 16)")
    a_enc.add_argument("--nonce", help="Nonce/IV in hex (12 bytes, optional, random if not provided)")

    a_dec = anubissub.add_parser("decrypt", help="Decrypt with Anubis-GCM")
    a_dec.add_argument("--key", required=True, help="Key hex (16, 20, 24, 28, 32, 36, 40 bytes)")
    a_dec.add_argument("--infile", help="Input file (optional, uses stdin if not provided)")
    a_dec.add_argument("--aad", help="Additional authenticated data (AAD)")
    a_dec.add_argument("--outfile", help="Output file (default: stdout)")
    a_dec.add_argument("--tag-size", type=int, default=16, choices=range(12, 17), 
                       help="Tag size in bytes (12-16, default: 16)")

    args = parser.parse_args()

    # ======================
    # Dispatcher
    # ======================
    if args.tool == "hashsum":
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
    
    elif args.tool == "ed521":
        if args.cmd == "gen":
            ed521_generate(args.priv, args.pub, args.password)
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
        elif args.cmd == "parse":
            ed521_parse_key(args.key_file, args.debug)
        
    elif args.tool == "x25519":
        if args.cmd == "gen":
            x25519_generate_keys(args.priv, args.pub, args.password)
        elif args.cmd == "shared":
            x25519_shared_secret_calc(args.priv, args.peer)
        elif args.cmd == "parse":
            x25519_parse_key(args.key_file, args.debug)
    
    elif args.tool == "x448":
        if args.cmd == "gen":
            x448_generate_keys(args.priv, args.pub, args.password)
        elif args.cmd == "shared":
            x448_shared_secret_calc(args.priv, args.peer)
        elif args.cmd == "parse":
            x448_parse_key(args.key_file, args.debug)
    
    elif args.tool == "curupira":
        if args.cmd == "encrypt":
            curupira_encrypt(args.key, args.infile, args.aad, args.outfile)
        elif args.cmd == "decrypt":
            curupira_decrypt(args.key, args.infile, args.aad, args.outfile)
    
    elif args.tool == "anubis":
        if args.cmd == "encrypt":
            anubis_encrypt(args.key, args.infile, args.aad, args.outfile, 
                          args.tag_size, args.nonce)
        elif args.cmd == "decrypt":
            anubis_decrypt(args.key, args.infile, args.aad, args.outfile, 
                          args.tag_size)

if __name__ == "__main__":
    main()
