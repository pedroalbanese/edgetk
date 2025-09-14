## Abstract

### Proposed Title:
*EDGETk: A Comprehensive Toolkit for Cryptographic Primitives and Protocols*

This paper introduces the EDGE Toolkit (EDGETk), a hybrid, cross-platform environment for symmetric and asymmetric cryptography and related protocols, designed for secure use in small-scale or embedded systems. EDGETk implements over 150 cryptographic algorithms, including symmetric ciphers, message authentication, password-based key derivation, recursive hashing, digital signatures, X.509 certificate chains, and secure communication layers (TLS 1.3, TLCP). It also supports elliptic curves in Weierstrass, Twisted Edwards, and Montgomery forms, along with both classical and modern cryptographic schemes (RSA, ECDSA, EdDSA, GOST, BLS12‑381 curves, etc.).

The toolkit has been evaluated across various platforms (Windows, Linux, FreeBSD, ARM, x86), with a focus on performance requirements, formal security (e.g., zero-knowledge proofs, verified cryptographic relations), and compliance with international standards.

### Key Contributions:

- Development of a non-interactive Schnorr-like zero-knowledge proof of private key knowledge, integrated into the toolkit and usable with bilinear pairings as a building block for IBE/IBS schemes and authentication mechanisms.

- Full implementation of over 150 cryptographic primitives—ranging from basic to advanced—including symmetric and asymmetric encryption, hashing, authentication, key derivation, and digital signatures, providing flexibility for a wide range of security scenarios.

- Support for multiple families of elliptic curves (Weierstrass, Twisted Edwards, Montgomery), including parameter sets aligned with international standards (BLS12‑381, GOST R 34.10, SM2), enabling global adoption and interoperability.

- Cross-platform design optimized for constrained environments (embedded/IoT), with integrated secure communication layers (TLS 1.3, TLCP) and support for standard certificate formats (X.509, CSRs, CRLs).

- Open licensing and accessible documentation, with a public repository, allowing for third-party audits, community contributions, and future certification under ISO/IEC, NIST, or other standards.

---

## 1. Introduction

With the growing demand for secure communication in connected devices—especially in embedded systems—comes the need for lightweight, auditable cryptographic toolkits that align with modern security standards. EDGETk emerges in this context as a practical and robust solution, consolidating a wide range of cryptographic primitives and protocols into a single, cross-platform suite focused on interoperability, performance, and formal security.

---

## 2. Methodology

EDGETk has been analyzed and validated through:

- Testing across multiple platforms (Windows, Linux, FreeBSD, ARM);
- Cross-verification for interoperability with OpenSSL, LibreSSL, GmSSL, etc.;
- Manual and automated formal verification of cryptographic correctness;
- Performance benchmarking on 32- and 64-bit architectures;
- Compliance verification with cryptographic standards (RFCs, ISO, NIST).

---

## 3. Toolkit Architecture

EDGETk is structured as a single command-line executable with minimal external dependencies. It provides:

- Multiple I/O formats (raw, hex, PEM, DER);
- Granular algorithm and mode selection;
- Shell scripting and automation support;
- Offline or real-time operation (via embedded server);
- POSIX-compatible APIs suitable for embedded systems.

---

## 4. Implemented Cryptographic Primitives

### 4.1 Symmetric Cryptography

#### Stream Ciphers
- **AEAD:** Ascon, ChaCha20Poly1305, ZUC-128/256, Grain128a.
- **Classic:** Salsa20, HC-128/256, RC4, Rabbit, Spritz, Trivium.

#### Block Ciphers
- **128-bit:** AES, Camellia, ARIA, Twofish, Serpent, SM4.
- **256-bit and above:** Kalyna256/512, SHACAL-2, Threefish (256, 512, 1024).
- **Modes:** GCM, OCB, CCM, MGM, EAX, CBC, CFB, CTR, IGE, SIV.

---

### 4.2 Asymmetric Cryptography

- **Digital Signatures:** ECDSA, EdDSA, BIP0340, GOST R 34.10, SM2, RSA, SLH-DSA.
- **Key Exchange:** X25519, Curve448, ECDH, SM2, NUMS, BLS12-381.
- **Public-key Encryption:** RSA, SM2, ElGamal, EC-ElGamal.

---

### 4.3 Elliptic Curves

- **Weierstrass:** secp256r1, secp384r1, brainpool, SM2, GOST.
- **Twisted Edwards:** Ed25519, GOST-A.
- **Montgomery:** Curve25519/X25519.
- **Pairing-Friendly:** BLS12-381, BN256.
- **Others:** NUMS, Tom256/384, Koblitz (secp256k1), ANSSI, BP.

---

### 4.4 Hash Functions

- **SHA Family:** SHA-1, SHA-2, SHA-3, SHAKE.
- **Modern Hashes:** BLAKE2b/s, BLAKE3, Streebog, Skein, Kupyna, Whirlpool, MD6.
- **Legacy (compatibility only):** MD5, RIPEMD, GOST94, HAS-160.

---

### 4.5 Key Derivation and Storage

- **Key Derivation:** PBKDF2, HKDF, Argon2, scrypt, Lyra2.
- **MACs and Authenticated Hashes:** HMAC, Poly1305, SipHash, Xoodyak.

---

## 5. Supported Cryptographic Protocols

### 5.1 TLS 1.3 and TLCP

- Built-in support for full handshake clients and servers.
- TLS/TLCP available via command-line interface.
- Compatible with SM2/SM3/SM4 and standard NIST curves.

### 5.2 Public Key Infrastructure (PKI)

- Generation and parsing of:
  - X.509 certificates (PEM/DER);
  - Certificate Revocation Lists (CRLs);
  - Certificate Signing Requests (CSRs).
- Compatible with OpenSSL and other PKI tools.

### 5.3 Identity- and Signature-Based on Bilinear Pairings

EDGETk implements several IBE/IBS schemes:

| Scheme             | Type | Private Group | Public Group |
|--------------------|:----:|:-------------:|:------------:|
| Boneh-Franklin     | IBE  | G1            | G2           |
| Boneh-Boyen        | IBE  | G2            | G1           |
| Sakai-Kasahara     | IBE  | G2            | G1           |
| Barreto et al.     | IBS  | G1            | G2           |
| Cha-Cheon          | IBS  | G1            | G2           |
| Galindo-Garcia     | IBS  | G1            | G1           |
| Hess (default)     | IBS  | G1            | G2           |
| ShangMi            | IBS  | G1            | G2           |

Additionally, EDGETk features:

- **Non-interactive Schnorr-like Zero-Knowledge Proofs** of private key knowledge over pairing groups;
- Reusable components for authentication systems and decentralized identity (DID).

---

## 6. Experimental Evaluation

EDGETk’s performance was benchmarked across:

- **Platforms:** Windows, Linux, FreeBSD, ARMv7, ARM Cortex-M, x86_64;
- **Metrics:** execution time, memory usage, cryptographic throughput;
- **Results:** excellent performance on embedded devices (e.g., Raspberry Pi Zero), with a binary footprint under 1.5MB on ARM systems.

---

## 7. Use Cases

- **End-to-end encryption in embedded systems** (e.g., IoT sensors using TLS 1.3);
- **Decentralized infrastructures** using identity-based signatures;
- **Cryptographic audits** of curves, hashes, and certificates;
- **Compliance with national and international standards** (Chinese SMx, Russian GOST, NIST, etc.).

---

## 8. Conclusion

EDGETk stands out as a powerful and flexible toolkit for developers, researchers, and security engineers who require a reliable environment to test, integrate, or validate cryptographic primitives. Its cross-platform architecture, extensive algorithmic support, and emphasis on formal correctness make it well-suited for modern applications demanding high assurance, performance, and compliance.

---

## References

   - Africacrypt 2009: Galindo-Garcia Identity-Based Signature (IBS)
   - Anubis Involutional SPN 128-bit block cipher (Barreto, ESAT/COSIC)
   - Asiacrypt 2001: Short Signatures from the Weil Pairing (BLS)
   - Asi­acrypt 2005: Barreto Identity-Based Signature (IBS)
   - BSI TR-03111 Elliptic Curve Cryptography (ECC) Technical Guideline
   - CHASKEY Message Authentication Code (Nicky Mouha, ESAT/COSIC)
   - CubeHash and SipHash64/128 (Daniel J. Bernstein & JP Aumasson)
   - CRYPTO 1999: IND-CCA2 Fujisaki-Okamoto Transformation (IBE)
   - CRYPTO 2001: Boneh-Franklin Identity-Based Encryption (IBE)
   - DSTU 7564:2014 A New Standard of Ukraine: The Kupyna Hash Function
   - DSTU 7624:2014 A Encryption Standard of Ukraine: Kalyna Block Cipher
   - Eurocrypt 1996: Security Proofs for Signature Schemes (EUF-CMA ElGamal)
   - Eurocrypt 2004: Boneh-Boyen Identity-Based Encryption (IBE)
   - GB/T 32907-2016 - SM4 128-bit Block Cipher
   - GB/T 32918.4-2016 SM2 Elliptic Curve Asymmetric Encryption
   - GB/T 38636-2020 - Transport Layer Cryptography Protocol (TLCP)
   - GM/T 0001-2012 ZUC Zu Chongzhi Stream cipher 128/256-bit key
   - GM/T 0002-2012 SM4 Block cipher with 128-bit key
   - GM/T 0003-2012 SM2 Public key algorithm 256-bit
   - GM/T 0004-2012 SM3 Message digest algorithm 256-bit hash value
   - GM/T 0044-2016 SM9 Public key algorithm 256-bit
   - GM/T 0086-2020 Specification of key management system based on SM9
   - GOST 28147-89 64-bit block cipher (RFC 5830)
   - GOST R 34.10-2012 VKO key agreement function (RFC 7836)
   - GOST R 34.10-2012 public key signature function (RFC 7091)
   - GOST R 34.11-2012 Streebog hash function (RFC 6986)
   - GOST R 34.11-94 CryptoPro hash function (RFC 5831)
   - GOST R 34.12-2015 128-bit block cipher Kuznechik (RFC 7801)
   - GOST R 34.12-2015 64-bit block cipher Magma (RFC 8891)
   - GOST R 50.1.114-2016 GOST R 34.10-2012 and GOST R 34.11-2012
   - HC-128 Stream Cipher simplified version of HC-256 (Wu, ESAT/COSIC)
   - IGE (Infinite Garble Extension) Mode of Operation for Block ciphers
   - ISO/IEC 10118-3:2003 RIPEMD128/160/256 and Whirlpool (ESAT/COSIC)
   - ISO/IEC 18033-3:2010 HIGHT, SEED, Camellia and MISTY1 Block ciphers
   - ISO/IEC 18033-4:2011 KCipher-2 stream cipher (RFC 7008)
   - ISO/IEC 29192-3:2012 Trivium Stream cipher with 80-bit key
   - ISO/IEC 18033-5:2015 IBE - Identity-based Encryption Mechanisms
   - ISO/IEC 18033-5:2015/Amd.1:2021(E) SM9 Mechanism
   - ISO/IEC 14888-3:2018 EC-SDSA Schnorr-based Signature Scheme
   - ISO/IEC 29192-2:2019 PRESENT, CLEFIA and LEA block ciphers
   - ISO/IEC 15946-5:2022 Barreto-Naehrig and Barreto-Lynn-Scott Curves
   - KS X 1213-1 ARIA 128-bit block cipher with 128/192/256-bit keys
   - KS X 3246 LEA - Lightweight Encryption Algorithm (TTAK.KO-12.0223)
   - KS X 3262 LSH - A New Fast Secure Hash Function Family (in Korean)
   - LNCS 1838 - A One Round Protocol for Tripartite Diffie-Hellman
   - NIST SP800-186 X25519 Diffie-Hellman (OpenSSL compliant)
   - NIST SP800-38D GCM AEAD mode for 128-bit block ciphers (RFC 5288)
   - NIST SP800-232 Ascon-Based Lightweight Cryptography Standard
   - PKC 2003: Cha-Cheon Identity-Based Signature (IBS)
   - RFC 1423: Privacy Enhancement for Internet Electronic Mail
   - RFC 2104: HMAC - Keyed-Hashing for Message Authentication
   - RFC 2144: CAST-128 64-bit Block cipher with 128-bit key
   - RFC 2612: The CAST-256 Encryption Algorithm
   - RFC 3610: Counter with CBC-MAC Mode of Operation (CCM Mode)
   - RFC 4009: The SEED Encryption Algorithm (KISA)
   - RFC 4253: Serpent 128-bit Block cipher with 128/192/256-bit keys
   - RFC 4493: Cipher-based Message Authentication Code (CMAC)
   - RFC 4503: Rabbit Stream Cipher Algorithm with 128-bit key
   - RFC 4543: Galois Message Authentication Code (GMAC)
   - RFC 4764: EAX Authenticated-Encryption Mode of Operation
   - RFC 4648: Base16, Base32, and Base64 Data Encodings
   - RFC 5246: Transport Layer Security (TLS) Protocol Version 1.2
   - RFC 5280: Internet X.509 PKI Certificate Revocation List (CRL)
   - RFC 5297: Synthetic Initialization Vector (SIV Mode)
   - RFC 5639: Elliptic Curve Cryptography (ECC) Brainpool Standard Curves
   - RFC 5869: HMAC-based Key Derivation Function (HKDF)
   - RFC 6114: The 128-Bit Blockcipher CLEFIA (Sony)
   - RFC 7008: KCipher-2 Encryption Algorithm (KDDI R&D Laboratories)
   - RFC 7253: OCB3 Offset Codebook Authenticated-Encryption Algorithm
   - RFC 7292: PKCS #12 Personal Information Exchange Syntax v1.1
   - RFC 7539: ChaCha20-Poly1305 AEAD Stream cipher
   - RFC 7693: The BLAKE2 Cryptographic Hash and MAC (JP Aumasson)
   - RFC 7748: Curve25519 and Curve448: Elliptic Curves for Security
   - RFC 7914: The Scrypt Password-Based Key Derivation Function
   - RFC 8032: Ed25519 Signature a.k.a. EdDSA (Daniel J. Bernstein)
   - RFC 8446: Transport Layer Security (TLS) Protocol Version 1.3
   - RFC 9058: MGM AEAD mode for 64 and 128 bit ciphers (E. Griboedova)
   - RFC 9367: GOST Cipher Suites for Transport Layer Security (TLS 1.3)
   - SAC 2002: Hess Efficient Identity Based Signature (IBS)
   - SBRC 2007: Curupira 96-bit block cipher with 96/144/192-bit keys
   - STB 34.101.31-2011 Belarusian standard (Bel-T) block cipher
   - STB 34.101.45-2013 Belarusian BignV1 public key algorithhm
   - STB 34.101.77-2020 Belarusian standard BASH hash function
   - TTAS.KO-12.0004/R1 128-bit Block Cipher SEED (ISO/IEC 18033-3:2010)
   - TTAS.KO-12.0040/R1 64-bit Block Cipher HIGHT (ISO/IEC 18033-3:2010)
   - TTAS.KO-12.0011/R2 HAS-160 Korean-standardized hash algorithm
   - TTAK.KO-12.0015/R3 EC-KCDSA Korean Digital Signature Algorithm
   - TTAK.KO-12.0223 LEA 128-bit block cipher (ISO/IEC 29192-2:2019)
   - TTAK.KO-12.0276 LSH Message digest algorithm (KS X 3262)
   - US FIPS 197 Advanced Encryption Standard (AES)
   - US FIPS 180-2 Secure Hash Standard (SHS) SHA1 and SHA2 Algorithms
   - US FIPS 202 SHA-3 Permutation-Based Hash (instance of the Keccak)
   - US FIPS 203 Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM)
   - US FIPS 204 Module-Lattice-Based Digital Signature Standard (ML-DSA)
   - US FIPS 205 Stateless Hash-Based Digital Signature Standard (SLH-DSA)

<h2>Security Assurance</h2>

<p>
  The EDGETk toolkit was developed by a cryptography practitioner and includes over 150 widely recognized cryptographic algorithms. Although it has not yet undergone a formal third-party audit, there are several indicators suggesting that its implementation is sound and its security posture is solid.
</p>

<ul>
  <li>
    <strong>Interoperability with Standard Tools:</strong>
    EDGETk is fully compatible with widely used cryptographic toolkits such as OpenSSL, LibreSSL, and GmSSL. This ensures that its key formats, ciphertexts, hashes, and digital signatures can be validated against independent implementations.
  </li>
  <li>
    <strong>Initialization Vector and Parameter Compatibility:</strong>
    All implemented algorithms conform to the expected behavior defined in standard documentation. EDGETk consistently produces correct outputs when tested against standardized test vectors (e.g., NIST, ISO, GOST, SM series), demonstrating adherence to cryptographic specifications.
  </li>
  <li>
    <strong>Cross-Platform Determinism:</strong>
    The toolkit has been tested on multiple architectures (x86, ARM) and operating systems (Linux, Windows, FreeBSD), consistently yielding identical outputs for the same inputs, which strongly supports implementation correctness.
  </li>
  <li>
    <strong>Protocol-Level Validation:</strong>
    The TLS 1.3 and TLCP implementations have been tested in real-world scenarios and communicate successfully with compliant clients and servers, further reinforcing protocol-level correctness.
  </li>
</ul>

<p>
  While independent auditing remains an important future milestone, the high degree of compatibility, adherence to international standards, and deterministic behavior across platforms provide strong practical evidence of correctness and reliability in EDGETk's cryptographic implementations.
</p>
