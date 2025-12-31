#!/usr/bin/env python3
"""
EDGE Crypto Toolbox - Android Version (standard libraries + pysodium)
Contains: Argon2, ChaCha20-Poly1305, Ed25519, Scrypt, X25519, Hashsum, HMAC
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
# PEM PKCS8 FUNCTIONS (using only pysodium)
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
# PEM READING FUNCTIONS (fixed)
# =========================

def parse_pem_private_key(pem_data):
    """Parse private key from PEM PKCS8 format"""
    # Remove headers/footers and whitespace
    lines = pem_data.strip().split('\n')
    b64_data = ''.join([line.strip() for line in lines if line and not line.startswith('-----')])
    
    # Decode Base64
    der_data = base64.b64decode(b64_data)
    
    # PKCS8 structure: SEQUENCE { version, AlgorithmIdentifier, PrivateKey }
    # PrivateKey is an OCTET STRING containing the 32-byte key
    idx = 0
    
    # Skip SEQUENCE tag and length
    if der_data[idx] != 0x30:  # SEQUENCE
        raise ValueError("Invalid PKCS8 format: expected SEQUENCE")
    idx += 1
    
    # Skip length
    seq_len = der_data[idx]
    idx += 1
    if seq_len & 0x80:  # Long form length
        num_bytes = seq_len & 0x7F
        seq_len = int.from_bytes(der_data[idx:idx+num_bytes], 'big')
        idx += num_bytes
    
    # Skip version (INTEGER 0)
    if der_data[idx:idx+3] != b'\x02\x01\x00':
        raise ValueError("Invalid PKCS8 format: expected version 0")
    idx += 3
    
    # Skip AlgorithmIdentifier (SEQUENCE + OID)
    if der_data[idx] != 0x30:  # SEQUENCE
        raise ValueError("Invalid PKCS8 format: expected AlgorithmIdentifier SEQUENCE")
    idx += 1
    
    algo_len = der_data[idx]
    idx += 1
    idx += algo_len  # Skip entire AlgorithmIdentifier
    
    # Now we're at PrivateKey (OCTET STRING)
    if der_data[idx] != 0x04:  # OCTET STRING
        raise ValueError("Invalid PKCS8 format: expected OCTET STRING")
    idx += 1
    
    # OCTET STRING length (should be 32 + tag+length = 34 bytes)
    octet_len = der_data[idx]
    idx += 1
    
    # Private key is in the next 32 bytes
    # Expect inner OCTET STRING
    if der_data[idx] != 0x04:
        raise ValueError("Expected inner OCTET STRING")

    idx += 1
    inner_len = der_data[idx]
    idx += 1

    private_key = der_data[idx:idx+inner_len]
    
    if len(private_key) != 32:
        raise ValueError(f"Invalid private key length: {len(private_key)} bytes, expected 32")
    
    return private_key

def parse_pem_public_key(pem_data):
    """Parse public key from PEM SPKI format"""
    # Remove headers/footers and whitespace
    lines = pem_data.strip().split('\n')
    b64_data = ''.join([line.strip() for line in lines if line and not line.startswith('-----')])
    
    # Decode Base64
    der_data = base64.b64decode(b64_data)
    
    # SPKI structure: SEQUENCE { AlgorithmIdentifier, SubjectPublicKeyInfo }
    # SubjectPublicKeyInfo is a BIT STRING containing the 32-byte key
    idx = 0
    
    # Skip SEQUENCE tag and length
    if der_data[idx] != 0x30:  # SEQUENCE
        raise ValueError("Invalid SPKI format: expected SEQUENCE")
    idx += 1
    
    # Skip length
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
    
    # Public key is in the next 32 bytes
    public_key = der_data[idx:idx+32]
    
    if len(public_key) != 32:
        raise ValueError(f"Invalid public key length: {len(public_key)} bytes, expected 32")
    
    return public_key

# =========================
# RECURSIVE HASH FUNCTION 
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
# 2. HASHSUM (recursive like second code)
# =========================

# Functions already defined above

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
# 5. FUNCTIONS WITH PYSODIUM (if available)
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
        description="EDGE Crypto Toolbox (Argon2, ChaCha20, Ed25519, Scrypt, X25519, Hashsum, HMAC)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples (basic features always available):
  # Argon2 password hash
  python %(prog)s argon2 hash
  python %(prog)s argon2 hash --password "mypassword"
  python %(prog)s argon2 verify --hash "$HASH" --password "mypassword"
  
  # File hashes
  python %(prog)s hashsum calc "*.txt"
  python %(prog)s hashsum calc "*.py" -r -a sha256 -o hashes.txt
  python %(prog)s hashsum calc *.py  # With shell expansion
  python %(prog)s hashsum check hashes.txt
  python %(prog)s hashsum list
  
  # HMAC
  python %(prog)s hmac calc --key "mykey" --data "message"
  python %(prog)s hmac verify --hmac "abc123" --key "mykey" --data "message"
  python %(prog)s hmac list
  
  # Scrypt KDF
  python %(prog)s scrypt derive
  python %(prog)s scrypt compare
  
Advanced features (require pysodium):
  # Argon2 password hashing
  python %(prog)s argon2 hash
  python %(prog)s argon2 verify --hash "$HASH"
  
  # ChaCha20 encryption
  python %(prog)s chacha20 encrypt --key $(openssl rand -hex 32) --infile secret.txt
  cat encrypted.bin | python %(prog)s chacha20 decrypt --key $(openssl rand -hex 32)
  
  # Ed25519 signatures
  python %(prog)s ed25519 gen --priv private.pem --pub public.pem
  python %(prog)s ed25519 sign --priv private.pem --msg message.txt
  python %(prog)s ed25519 verify --pub public.pem --msg message.txt --sig SIGNATURE_HEX
  
  # Scrypt key derivation
  python %(prog)s scrypt derive
  python %(prog)s scrypt compare --derived DERIVED_HEX
  
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
