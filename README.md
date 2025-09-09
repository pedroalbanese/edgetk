# EDGE Toolkit
[![ISC License](http://img.shields.io/badge/license-ISC-blue.svg)](https://github.com/pedroalbanese/edgetk/blob/master/LICENSE.md) 
[![GoDoc](https://godoc.org/github.com/pedroalbanese/edgetk?status.png)](http://godoc.org/github.com/pedroalbanese/edgetk)
[![GitHub downloads](https://img.shields.io/github/downloads/pedroalbanese/edgetk/total.svg?logo=github&logoColor=white)](https://github.com/pedroalbanese/edgetk/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/pedroalbanese/edgetk)](https://goreportcard.com/report/github.com/pedroalbanese/edgetk)
[![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/pedroalbanese/edgetk)](https://golang.org)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/pedroalbanese/edgetk)](https://github.com/pedroalbanese/edgetk/releases)

Multi-purpose cross-platform hybrid cryptography tool for symmetric and asymmetric encryption, cipher-based message authentication code (CMAC|PMAC|GMAC|VMAC), recursive hash digest, hash-based message authentication code (HMAC), HMAC-based key derivation function (HKDF), password-based key derivation function (PBKDF2|Argon2|Lyra2|Scrypt), password-hashing scheme (Bcrypt|Argon2|Lyra2|Makwa), shared key agreement (ECDH|VKO|X25519|X448|ML-KEM), digital signature (RSA|ECDSA|EdDSA|GOST|SLH-DSA|ML-DSA), X.509 CSRs, CRLs and Certificates, and TCP instant server with TLS 1.3 and TLCP encryption layers for small or embedded systems. 

***Fully OpenSSL/LibreSSL/GmSSL/Botan/libsodium/RHash/Mcrypt compliant***

<details><summary>Implements</summary>  
    
1. Africacrypt 2009: Galindo-Garcia Identity-Based Signature (IBS)
3. Anubis Involutional SPN 128-bit block cipher (Barreto, ESAT/COSIC)
4. Asiacrypt 2001: Short Signatures from the Weil Pairing (BLS)
5. Asi­acrypt 2005: Barreto Identity-Based Signature (IBS)
6. BSI TR-03111 Elliptic Curve Cryptography (ECC) Technical Guideline
7. CHASKEY Message Authentication Code (Nicky Mouha, ESAT/COSIC)
8. CubeHash and SipHash64/128 (Daniel J. Bernstein & JP Aumasson)
9. CRYPTO 1999: IND-CCA2 Fujisaki-Okamoto Transformation (IBE)
10. CRYPTO 2001: Boneh-Franklin Identity-Based Encryption (IBE)
11. DSTU 7564:2014 A New Standard of Ukraine: The Kupyna Hash Function
12. DSTU 7624:2014 A Encryption Standard of Ukraine: Kalyna Block Cipher
13. Eurocrypt 1996: Security Proofs for Signature Schemes (EUF-CMA ElGamal)
14. Eurocrypt 2004: Boneh-Boyen Identity-Based Encryption (IBE)
15. GB/T 32907-2016 - SM4 128-bit Block Cipher
16. GB/T 32918.4-2016 SM2 Elliptic Curve Asymmetric Encryption
17. GB/T 38636-2020 - Transport Layer Cryptography Protocol (TLCP)
18. GM/T 0001-2012 ZUC Zu Chongzhi Stream cipher 128/256-bit key
19. GM/T 0002-2012 SM4 Block cipher with 128-bit key
20. GM/T 0003-2012 SM2 Public key algorithm 256-bit
21. GM/T 0004-2012 SM3 Message digest algorithm 256-bit hash value
22. GM/T 0044-2016 SM9 Public key algorithm 256-bit
23. GM/T 0086-2020 Specification of key management system based on SM9
24. GOST 28147-89 64-bit block cipher (RFC 5830)
25. GOST R 34.10-2012 VKO key agreement function (RFC 7836)
26. GOST R 34.10-2012 public key signature function (RFC 7091)
27. GOST R 34.11-2012 Streebog hash function (RFC 6986)
28. GOST R 34.11-94 CryptoPro hash function (RFC 5831)
29. GOST R 34.12-2015 128-bit block cipher Kuznechik (RFC 7801)
30. GOST R 34.12-2015 64-bit block cipher Magma (RFC 8891)
31. GOST R 50.1.114-2016 GOST R 34.10-2012 and GOST R 34.11-2012
32. HC-128 Stream Cipher simplified version of HC-256 (Wu, ESAT/COSIC)
33. IGE (Infinite Garble Extension) Mode of Operation for Block ciphers
34. ISO/IEC 10118-3:2003 RIPEMD128/160/256 and Whirlpool (ESAT/COSIC)
35. ISO/IEC 18033-3:2010 HIGHT, SEED, Camellia and MISTY1 Block ciphers
36. ISO/IEC 18033-4:2011 KCipher-2 stream cipher (RFC 7008)
37. ISO/IEC 29192-3:2012 Trivium Stream cipher with 80-bit key
38. ISO/IEC 18033-5:2015 IBE - Identity-based Encryption Mechanisms
39. ISO/IEC 18033-5:2015/Amd.1:2021(E) SM9 Mechanism
40. ISO/IEC 14888-3:2018 EC-SDSA Schnorr-based Signature Scheme
41. ISO/IEC 29192-2:2019 PRESENT, CLEFIA and LEA block ciphers
42. ISO/IEC 15946-5:2022 Barreto-Naehrig and Barreto-Lynn-Scott Curves
43. KS X 1213-1 ARIA 128-bit block cipher with 128/192/256-bit keys
44. KS X 3246 LEA - Lightweight Encryption Algorithm (TTAK.KO-12.0223)
45. KS X 3262 LSH - A New Fast Secure Hash Function Family (in Korean)
46. LNCS 1838 - A One Round Protocol for Tripartite Diffie-Hellman
47. NIST SP800-186 X25519 Diffie-Hellman (OpenSSL compliant)
48. NIST SP800-38D GCM AEAD mode for 128-bit block ciphers (RFC 5288)
49. NIST SP800-232 Ascon-Based Lightweight Cryptography Standard
50. PKC 2003: Cha-Cheon Identity-Based Signature (IBS)
51. RFC 1423: Privacy Enhancement for Internet Electronic Mail
52. RFC 2104: HMAC - Keyed-Hashing for Message Authentication
53. RFC 2144: CAST-128 64-bit Block cipher with 128-bit key
54. RFC 2612: The CAST-256 Encryption Algorithm
55. RFC 3610: Counter with CBC-MAC Mode of Operation (CCM Mode)
56. RFC 4009: The SEED Encryption Algorithm (KISA)
57. RFC 4253: Serpent 128-bit Block cipher with 128/192/256-bit keys
58. RFC 4493: Cipher-based Message Authentication Code (CMAC)
59. RFC 4503: Rabbit Stream Cipher Algorithm with 128-bit key
60. RFC 4543: Galois Message Authentication Code (GMAC)
61. RFC 4764: EAX Authenticated-Encryption Mode of Operation
62. RFC 4648: Base16, Base32, and Base64 Data Encodings
63. RFC 5246: Transport Layer Security (TLS) Protocol Version 1.2
64. RFC 5280: Internet X.509 PKI Certificate Revocation List (CRL)
50. RFC 5297: Synthetic Initialization Vector (SIV Mode)
51. RFC 5639: Elliptic Curve Cryptography (ECC) Brainpool Standard Curves
53. RFC 5869: HMAC-based Key Derivation Function (HKDF)
54. RFC 6114: The 128-Bit Blockcipher CLEFIA (Sony)
55. RFC 7008: KCipher-2 Encryption Algorithm (KDDI R&D Laboratories)
56. RFC 7253: OCB3 Offset Codebook Authenticated-Encryption Algorithm
57. RFC 7292: PKCS #12 Personal Information Exchange Syntax v1.1
58. RFC 7539: ChaCha20-Poly1305 AEAD Stream cipher
59. RFC 7693: The BLAKE2 Cryptographic Hash and MAC (JP Aumasson)
60. RFC 7748: Curve25519 and Curve448: Elliptic Curves for Security
61. RFC 7914: The Scrypt Password-Based Key Derivation Function
62. RFC 8032: Ed25519 Signature a.k.a. EdDSA (Daniel J. Bernstein)
63. RFC 8446: Transport Layer Security (TLS) Protocol Version 1.3
64. RFC 9058: MGM AEAD mode for 64 and 128 bit ciphers (E. Griboedova)
65. RFC 9367: GOST Cipher Suites for Transport Layer Security (TLS 1.3)
13. SAC 2002: Hess Efficient Identity Based Signature (IBS)
66. SBRC 2007: Curupira 96-bit block cipher with 96/144/192-bit keys
67. STB 34.101.31-2011 Belarusian standard (Bel-T) block cipher
68. STB 34.101.45-2013 Belarusian BignV1 public key algorithhm
69. STB 34.101.77-2020 Belarusian standard BASH hash function
70. TTAS.KO-12.0004/R1 128-bit Block Cipher SEED (ISO/IEC 18033-3:2010)
71. TTAS.KO-12.0040/R1 64-bit Block Cipher HIGHT (ISO/IEC 18033-3:2010)
72. TTAS.KO-12.0011/R2 HAS-160 Korean-standardized hash algorithm
73. TTAK.KO-12.0015/R3 EC-KCDSA Korean Digital Signature Algorithm
74. TTAK.KO-12.0223 LEA 128-bit block cipher (ISO/IEC 29192-2:2019)
75. TTAK.KO-12.0276 LSH Message digest algorithm (KS X 3262)
76. US FIPS 197 Advanced Encryption Standard (AES)
77. US FIPS 180-2 Secure Hash Standard (SHS) SHA1 and SHA2 Algorithms
78. US FIPS 202 SHA-3 Permutation-Based Hash (instance of the Keccak)
79. US FIPS 203 Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM)
80. US FIPS 204 Module-Lattice-Based Digital Signature Standard (ML-DSA)
81. US FIPS 205 Stateless Hash-Based Digital Signature Standard (SLH-DSA)

</details>


<details><summary>National Cryptographic Standards</summary>
 
#### 🇨🇳 SM2, SM3, SM4, SM9 — Chinese national cryptographic standards  
Defined by the **State Cryptography Administration (SCA)** and standardized under **GB/T** and **GM/T** series. Widely used in Chinese government, banking, and telecom infrastructure.

---

#### 🇷🇺 GOST R 34.10, Kuznechik, Streebog — Russian Federation cryptographic standards  
Approved by **FSTEC** and **Federal Security Service (FSB)**, standardized under **GOST R** series. Used across official and military systems in Russia.

---

#### 🇺🇦 Kalyna, Kupyna — Ukrainian national cryptographic standards  
Standardized as **DSTU 7624:2014** (Kalyna block cipher) and **DSTU 7564:2014** (Kupyna hash function) by the **Ukrainian State Service for Special Communications and Information Protection**.

---

#### 🇰🇷 SEED, LEA, LSH, KCDSA — Korean national cryptographic algorithms  
Developed under **TTAS.KO** and **KS X** standards. Used in public sector systems and Korean financial institutions. Published by **KISA** and **TTA**.

---

#### 🇧🇾 BignV1, Bel-T, BASH — Belarusian cryptographic standards  
Standardized by the **STB 34.101** series. Designed for public key encryption (**BignV1**), block cipher encryption (**Bel-T**), and hashing (**BASH**), primarily for use within Belarusian national security frameworks.

---

#### 🇫🇷 ANSSI FRP256v1 — French national elliptic curve for digital signatures  
Developed by the **ANSSI** (Agence nationale de la sécurité des systèmes d'information). Used for secure digital signature implementations within French governmental and critical infrastructure systems.

---

#### 🇯🇵 KCIPHER-2, Camellia — Japanese national cryptographic algorithms  
**KCIPHER-2** is a lightweight stream cipher standardized under **ISO/IEC 18033-4:2011**.  
**Camellia** is a block cipher developed by Mitsubishi and NTT, internationally adopted and widely used in Japan for various secure communications.

---

#### 🇧🇷 SENAI NBR ISO/IEC 18033-2 — Brazilian local standards for symmetric ciphers  
Adoption of international standards for block ciphers as specified by **ISO/IEC 18033-2**, guiding the use of algorithms such as AES, Blowfish, and others in Brazilian cryptographic applications.

---

#### 🇺🇸 AES, SHA-1, SHA-2, SHA-3, X25519, Ed25519, Ascon, Scrypt, GCM, CCM, OCB, PKCS, HMAC — United States federal cryptographic standards  
Includes **AES (FIPS 197)** for symmetric encryption, **SHA-1 and SHA-2 (FIPS 180-2)** and **SHA-3 (FIPS 202)** for hashing, and elliptic curve algorithms like **X25519** and **Ed25519** (NIST SP800-186, RFC 8032) for key exchange and digital signatures.  
Lightweight authenticated encryption (**Ascon**, NIST SP800-232) and password-based key derivation (**Scrypt**, RFC 7914) are also standardized.  
Authenticated encryption modes such as **GCM (RFC 5288)**, **CCM (RFC 3610)**, and **OCB3 (RFC 7253)** are widely used.  
Includes message authentication codes like **HMAC (RFC 2104)** and personal information exchange standards (**PKCS #12**, RFC 7292).  
All maintained and published primarily by **NIST** for U.S. government and private sector adoption.
</details>

## Command-line Integrated Security Suite

### Asymmetric

- **Public key algorithms:**  

    |  Algorithm          | 256 | 512 |ECDH |Signature|Encryption| PKI |
    |:--------------------|:---:|:---:|:---:|:-------:|:--------:|:---:|
    | ECDSA               | O   | O   | O   | O       | O        | O   |
    | EC-GDSA             | O   | O   |     | O       |          |     |
    | EC-KCDSA            | O   | O   |     | O       |          |     |
    | EC-SDSA             | O   | O   | O   | O       |          |     |
    | BignV1              | O   | O   | O   | O       |          |     |
    | BIP 340             | O   | O   | O   | O       |          |     |
    | BLS12-381           | O   |     | O   | O       | O        | O   |
    | BN256               | O   |     | O   | O       | O        | O   |
    | Curve25519          | O   |     | O   | O       |          | O   |
    | Curve448            |     |     | O   | O       |          |     |
    | GOST2012            | O   | O   | O   | O       |          | O   |
    | RSA                 |     |     |     | O       | O        | O   |
    | SM2                 | O   |     | O   | O       | O        | O   |
    | SM9                 | O   |     | O   | O       | O        |     |
    | NUMS                | O   | O   | O   | O       | O        |     |
    | ElGamal             |     |     |     | O       | O        |     |
    | EC-ElGamal          | O   | O   |     |         | O        |     |
    | Schnorr             |     |     |     | O       |          |     |
    | ML-DSA/KEM          |     |     |     | O       | O        | O   |
    | SLH-DSA             | O   |     |     | O       |          | O   |

- **Subjacent Elliptic Curves:**

    |  Curve                |  ECDSA  | EC-S/GDSA |  EC-KCDSA  |  ECKA-EG  |
    |:----------------------|:-------:|:---------:|:----------:|:---------:|
    | P-224 (secp224r1)     | O       | O         | O          | O         |
    | P-256 (secp256r1)     | O       | O         | O          | O         |
    | P-384 (secp384r1)     | O       | O         | O          | O         |
    | P-521 (secp521r1)     | O       | O         | O          | O         |
    | B-283 (sect283r1)     |         | O         | O          |           |
    | B-409 (sect409r1)     |         | O         | O          |           |
    | B-571 (sect571r1)     |         | O         | O          |           |
    | K-283 (sect283k1)     |         | O         | O          |           |
    | K-409 (sect409k1)     |         | O         | O          |           |
    | K-571 (sect571k1)     |         | O         | O          |           |
    | BP (brainpoolp256r1)  |         | O         |            | O         |
    | BP (brainpoolp384r1)  |         | O         |            | O         |
    | BP (brainpoolp512r1)  |         | O         |            | O         |
    | BP (brainpoolp256t1)  |         | O         |            | O         |
    | BP (brainpoolp384t1)  |         | O         |            | O         |
    | BP (brainpoolp512t1)  |         | O         |            | O         |
    | NUMS (numsp256d1)     | O       | O         |            | O         |
    | NUMS (numsp384d1)     | O       | O         |            | O         |
    | NUMS (numsp512d1)     | O       | O         |            | O         |
    | NUMS (numsp256t1)     | O       | O         |            | O         |
    | NUMS (numsp384t1)     | O       | O         |            | O         |
    | NUMS (numsp512t1)     | O       | O         |            | O         |
    | Tom-256 (tom256)      | O       | O         |            | O         |
    | Tom-384 (tom384)      | O       | O         |            | O         |
    | ANSSI (frp256v1)      | O       | O         |            | O         |
    | Koblitz (secp256k1)   | O       | O         |            | O         |
    | SM2 (sm2p256v1)       | O       |           |            | O         |

- **Subjacent Identity-Based Theorems:**
    | Scheme Name          | Type | Private Key Group | Public Key Group |
    |:---------------------|:----:|:-----------------:|:----------------:|
    | Boneh-Franklin (BF)  | IBE  | G1                | G2               |
    | Boneh-Boyen (BB)     | IBE  | G2                | G1               |
    | Sakai-Kasahara (SK)  | IBE  | G2                | G1               |
    | Barreto et al. (BR)  | IBS  | G1                | G2               |
    | Cha-Cheon (CC)       | IBS  | G1                | G2               |
    | Galindo-Garcia (GG)  | IBS  | G1                | G1               |
    | Hess (default)       | IBS  | G1                | G2               |
    | ShangMi (SM)         | IBS  | G1                | G2               |

- **Supported ParamSets:**

    |  Algorithm          |  A  |  B  |  C  |  D  |
    |:--------------------|:---:|:---:|:---:|:---:|
    | GOST R 34.10-2012 256-bit | O   | O   | O   | O   |
    | GOST R 34.10-2012 512-bit | O   | O   | O   |     |

### Symmetric

- **Stream ciphers:**

    |      Cipher      |  Key Size  |  IV  |         Modes         |
    |:-----------------|:----------:|:----:|:---------------------:|
    | Ascon 1.2        | 128        |  128 | AEAD Stream Cipher  |
    | Chacha20Poly1305 | 256        | 96/192 | AEAD Stream Cipher  |
    | Grain128a        | 128        | 40-96  | AEAD Stream Cipher  |
    | HC-128           | 128        |  128 | XOR Stream            |
    | HC-256           | 256        |  256 | XOR Stream            |
    | KCipher-2        | 128        |  128 | XOR Stream            |
    | Rabbit           | 128        |   64 | XOR Stream            |
    | RC4 [Obsolete]   | 40/128     |    - | XOR Stream            |
    | Salsa20          | 256        | 64/192 | XOR Stream            |
    | Skein512         | Any        |  Any | MAC + XOR Stream      |
    | Spritz           | Any        |  Any | XOR Stream            |
    | Trivium          | 80         |   80 | XOR Stream            |
    | ZUC-128 Zu Chongzhi | 128     |  128 | MAC + XOR Stream      |
    | ZUC-256 Zu Chongzhi | 256     |  184 | MAC + XOR Stream      |

- **Permutation ciphers:**

    |     Cipher    |  Key |  IV  |         Mode          |
    |:--------------|:----:|:----:|:---------------------:|
    | Xoodyak       |  128 |  128 |Lightweight AEAD Permutation Cipher|

- **256-bit> block ciphers:**

    |      Cipher      | Block Size |  Key Size   |          Modes          |
    |:-----------------|:----------:|:-----------:|:-----------------------:|
    | Kalyna256        |        256 |     256/512 | EAX, SIV, CTR, OFB, IGE |
    | Kalyna512        |        512 |         512 | EAX, SIV, CTR, OFB, IGE |
    | SHACAL-2         |        256 |  128 to 512 | EAX, SIV, CTR, OFB, IGE |
    | Threefish256     |        256 |         256 | EAX, SIV, CTR, OFB, IGE |
    | Threefish512     |        512 |         512 | EAX, SIV, CTR, OFB, IGE |
    | Threefish1024    |       1024 |        1024 | EAX, SIV, CTR, OFB, IGE |
  
- **128-bit block ciphers:**

    |      Cipher      | Block Size |  Key Size   |         Modes           |
    |:-----------------|:----------:|:-----------:|:-----------------------:|
    | AES (Rijndael)   |        128 | 128/192/256 | All modes supported     |
    | Anubis           |        128 |  128 to 320 | All modes supported     |
    | ARIA             |        128 | 128/192/256 | All modes supported     |
    | Bel-T            |        128 | 128/192/256 | All modes supported     |
    | Camellia         |        128 | 128/192/256 | All modes supported     |
    | CAST256          |        128 | 128/192/256 | All modes supported     |
    | CLEFIA           |        128 | 128/192/256 | All modes supported     |
    | CRYPTON          |        128 | 128/192/256 | All modes supported     |
    | E2               |        128 | 128/192/256 | All modes supported     |
    | Kalyna128        |        128 |     128/256 | All modes supported     |
    | Kuznechik        |        128 |         256 | All modes supported     |
    | LEA              |        128 | 128/192/256 | All modes supported     |
    | LOKI97           |        128 | 128/192/256 | All modes supported     |
    | MAGENTA          |        128 | 128/192/256 | All modes supported     |
    | MARS             |        128 |  128 to 448 | All modes supported     |
    | NOEKEON          |        128 |         128 | All modes supported     |
    | RC6              |        128 | 128/192/256 | All modes supported     |
    | SEED             |        128 |         128 | All modes supported     |
    | Serpent          |        128 | 128/192/256 | All modes supported     |
    | SM4              |        128 |         128 | All modes supported     |
    | Twofish          |        128 | 128/192/256 | All modes supported     |
   
- **96-bit block ciphers:**

    |      Cipher    | Block Size |  Key Size    |    Modes    |
    |:--------------|:----:|:----:|:---------------------:|
    | Curupira      |   96 |  96/144/192 |EAX, LETTERSOUP, CTR, IGE|

- **64-bit block ciphers:**

    |      Cipher      | Block Size |  Key Size    |    Modes    |
    |:-----------------|:----------:|:------------:|:-----------:|
    | DES [Obsolete]   |          64|            64|EAX, CFB-8, CTR, OFB|
    | 3DES [Obsolete]  |          64|           192|EAX, CFB-8, CTR, OFB|
    | Blowfish         |          64|           128|EAX, CFB-8, CTR, OFB|
    | CAST5            |          64|           128|EAX, CFB-8, CTR, OFB|
    | GOST89 (TC26)    |          64|           256|EAX, MGM, CFB-8, CTR|
    | HIGHT            |          64|           128|EAX, CFB-8, CTR, OFB|
    | IDEA [Obsolete]  |          64|           128|EAX, CFB-8, CTR, OFB|
    | Khazad           |          64|           128|EAX, MGM, CFB-8, CTR|
    | Magma            |          64|           256|EAX, CFB-8, CTR, OFB|
    | MISTY1           |          64|           128|EAX, CFB-8, CTR, OFB|
    | PRESENT          |          64|        80/128|EAX, MGM, CFB-8, CTR|
    | RC2 [Obsolete]   |          64|           128|EAX, CFB-8, CTR, OFB|
    | RC5 [Obsolete]   |          64|           128|EAX, CFB-8, CTR, OFB|
    | SAFER+           |          64|        64/128|EAX, CFB-8, CTR, OFB|
    | TWINE            |          64|        80/128|EAX, MGM, CFB-8, CTR|

- **Modes of Operation:**

    |Mode |                                | Blocks     |  Keys     |
    |:---:|:-------------------------------|:----------:|:---------:|
    | EAX | Encrypt-Authenticate-Translate |All         |Any        |
    | GCM | Galois/Counter Mode (AEAD)     |128         |128/192/256|
    | OCB1| Offset Codebook v1 (AEAD)      |128         |128/192/256|
    | OCB3| Offset Codebook v3 (AEAD)      |128         |128/192/256|
    | MGM | Multilinear Galois Mode (AEAD) |64/128      |Any        |
    | CCM | Counter with CBC-MAC (AEAD)    |128         |128/192/256|
    | SIV | Synthetic IV Mode (AEAD)       |All        |Any        |
    | CBC | Cipher-Block Chaining          |All         |Any        |
    | CFB | Cipher Feedback Mode           |All         |Any        |
    |CFB-8| Cipher Feedback Mode 8-bit     |All         |Any        |
    | CTR | Counter Mode (default)         |All         |Any        |
    | ECB | Eletronic Codebook Mode        |All         |Any        |
    | IGE | Infinite Garble Extension      |All         |Any        |
    | OFB | Output Feedback Mode           |All         |Any        | 
   
- **Message Digest Algorithms:**

    |    Algorithm    | 128 | 160 | 192 | 256 | 512 | MAC |
    |:----------------|:---:|:---:|:---:|:---:|:---:|:---:|
    | BASH            |     |     |     | O   | O   |     |
    | Bel-T           |     |     |     | O   |     |     |
    | BLAKE-2B        |     |     |     | O   | O   | O   |
    | BLAKE-2S        | O   |     |     | O   |     | O   |
    | BLAKE-3         |     |     |     | O   |     | O   |
    | BMW             |     |     |     | O   | O   |     |
    | Chaskey         | O   |     |     |     |     | O   |
    | CubeHash        |     |     |     | O   | O   |     |
    | ECHO            |     |     |     | O   | O   |     | 
    | ESCH            |     |     |     | O   |     |     | 
    | Fugue           |     |     |     | O   | O   |     |
    | GOST94 CryptoPro      |     |     |     | O   |     |     |
    | Grøstl          |     |     |     | O   | O   |     |
    | Hamsi           |     |     |     | O   | O   |     |
    | Haraka v2       |     |     |     | O   |     |     |
    | HAS-160 [Obsolete]|     | O   |     |     |     |     |
    | JH              |     |     |     | O   | O   |     |
    | Kupyna          |     |     |     | O   | O   | O   |
    | Legacy Keccak   |     |     |     | O   | O   |     |
    | LSH             |     |     |     | O   | O   |     |
    | Luffa           |     |     |     | O   | O   |     |
    | MD4 [Obsolete]  | O   |     |     |     |     |     |
    | MD5 [Obsolete]  | O   |     |     |     |     |     |
    | MD6             |     |     |     | O   | O   |     |
    | Poly1305        | O   |     |     |     |     | O   |
    | Radio-Gatun     |     |     |     | O   |     |     |
    | RIPEMD          | O   | O   |     | O   |     |     |
    | SHA1 [Obsolete] |     | O   |     |     |     |     |
    | SHA2 (default)  |     |     |     | O   | O   |     | 
    | SHA3            |     |     |     | O   | O   |     |
    | SHAKE           |     |     |     | O   | O   |     |
    | SHAvite-3       |     |     |     | O   | O   |     |
    | SIMD            |     |     |     | O   | O   |     |
    | SipHash         | O   |     |     |     |     | O   |
    | Skein           |     |     |     | O   | O   | O   | 
    | SM3             |     |     |     | O   |     |     |
    | Streebog        |     |     |     | O   | O   |     | 
    | Tiger           |     |     | O   |     |     |     | 
    | Whirlpool       |     |     |     |     | O   |     | 
    | Xoodyak         |     |     |     | O   |     | O   |
    | ZUC-256 Zu Chongzhi|  O   |     |     |     |     | O   |
    
    - MAC refers to keyed hash function, like HMAC. 

### AEAD

Authenticated encryption (AE) and authenticated encryption with associated data (AEAD) are forms of encryption which simultaneously assure the confidentiality and authenticity of data. Provides both authenticated encryption (confidentiality and authentication) and the ability to check the integrity and authentication of additional authenticated data (AAD) that is sent in the clear.

<details>
  <summary>AEAD OpenSSL-PHP and libsodium compliance</summary>  

OpenSSL-PHP
  ```php
  <?php
  function encrypt($plaintext, $key, $aad = '') {
      $nonceSize = 12; // Chacha20-Poly1305 standard nonce size
  
      $nonce = random_bytes($nonceSize);
      $ciphertext = openssl_encrypt(
          $plaintext,
          'chacha20-poly1305',
          $key,
          OPENSSL_RAW_DATA,
          $nonce,
          $tag,
          $aad
      );
      return $nonce . $ciphertext . $tag;
  }
  
  function decrypt($ciphertext, $key, $aad = '') {
      $nonceSize = 12; // Chacha20-Poly1305 standard nonce size
      $tagSize = 16;   // Assuming a 16-byte tag
  
      $nonce = substr($ciphertext, 0, $nonceSize);
      $tag = substr($ciphertext, -$tagSize);
      $ciphertext = substr($ciphertext, $nonceSize, -$tagSize);
  
      return openssl_decrypt(
          $ciphertext,
          'chacha20-poly1305',
          $key,
          OPENSSL_RAW_DATA,
          $nonce,
          $tag,
          $aad
      );
  }
  
  // Example usage:
  $keyHex = ''; // Provide your key in hexadecimal format
  $key = hex2bin($keyHex);
  $plaintext = "Hello, Chacha20-Poly1305!";
  
  // Encrypt
  $ciphertext = encrypt($plaintext, $key);
  echo "Encrypted: " . bin2hex($ciphertext) . PHP_EOL;
  
  // Decrypt
  $decrypted = decrypt($ciphertext, $key);
  echo "Decrypted: " . $decrypted . PHP_EOL;
  ?>
```

libsodium Python 
  ```python
import nacl.bindings
import binascii

# Fixed key (32 bytes)
key_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
key = binascii.unhexlify(key_hex)

# Open the file generated by EDGETk (nonce + ciphertext + tag)
with open("ciphertext.bin", "rb") as f:
    data = f.read()

# Extract the nonce (12 bytes), and ciphertext + tag (remaining bytes)
nonce = data[:12]
ciphertext_and_tag = data[12:]

# Decrypt using libsodium (via PyNaCl bindings)
try:
    plaintext = nacl.bindings.crypto_aead_chacha20poly1305_ietf_decrypt(
        ciphertext_and_tag,  # ciphertext + tag
        aad=None,            # no AAD (Additional Authenticated Data) was used
        nonce=nonce,
        key=key
    )
    print("Decrypted message:", plaintext.decode())
except Exception as e:
    print("Decryption failed:", e)
```
</details>

### ANSSI 
Parameters for the [ANSSI FRP256v1](https://www.alvestrand.no/objectid/1.2.250.1.223.101.256.1.html) Elliptic curve, Agence nationale de la sécurité des systèmes d'information. "Publication d'un paramétrage de courbe elliptique visant des applications de passeport électronique et de l'administration électronique française." 21 November 2011.

### BignV1

The Bign algorithm is a Schnorr-type signature scheme adopted as the standard in Belarus (STB 34.101.45). Below are the equations and descriptions associated with the signing and verification phases of Bign.

<details><summary>BignV1 Theory</summary>

#### Parameters

- $l \in \{128, 192, 256\}$ — Security level.
- $q$ — A $2l$-bit prime number.
- $G$ — A generator of an Abelian group $\langle G \rangle$ of order $q$.
- $H$ — An external hash function: $H: \{0, 1\}^* \to \{0, 1\}^{2l}$.
- $OID(H)$ — An identifier uniquely identifying the hash function $H$ (an ASN.1 object identifier).
- $h$ — An internal hash function: $h: \{0, 1\}^* \to \{0, 1\}^l$.

##### Private Key

- $d$ — A secret random/pseudorandom element from $\{1, 2, \dots, q-1\}$.

##### Public Key

- $Q = dG$ — The public key associated with the private key $d$.

##### Message to be signed

- $X \in \{0, 1\}^*$.

#### Signing

The signature $s$ of a message $X$ is generated as follows:

1. Choose $k$:  
   Select a random (or pseudorandom) value $k$ from $\{1, 2, \dots, q-1\}$.

2. Calculate $R$:  
   $R = kG$ — The point $R$ is calculated by multiplying the random value $k$ by the generator $G$.

3. Calculate $s_0$:  
   $s_0 = h(OID(H) \| R \| H(X))$ — Here, $s_0$ is computed by the internal hash function $h$, which involves the identifier of $H$, $R$, and the hash of the message $H(X)$.

4. Calculate $s_1$:  
   $s_1 = (k - H(X) - (s_0 + 2^l) d) \mod q$ — The value $s_1$ is computed using $k$, $H(X)$, $s_0$, and the private key $d$, with a modular operation based on the prime $q$.

5. Final signature:  
   $s = s_0 \| s_1$ — The final signature $s$ is the concatenation of $s_0$ and $s_1$.

6. Return the signature:  
   The signature $s$ is returned.

#### Verification

To verify the signature $s = s_0 \| s_1$ of a message $X$ with public key $Q$:

1. Verify the length of $s$:  
   If $|s| \neq 3l$, return 0 (invalid signature).

2. Extract $s_0$ and $s_1$:  
   Split $s = s_0 \| s_1$, where $|s_0| = l$ and $|s_1| = 2l$.

3. Verify $s_1$:  
   If $s_1 \geq q$, return 0 (invalid signature).

4. Calculate $R$:  
   Compute $R = (s_1 + H(X))G + (s_0 + 2^l)Q$.

5. Verify $R$:  
   If $R = O$ (the identity element of the group), return 0 (invalid signature).

6. Verify the hash:  
   If $h(OID(H) \| R \| H(X)) \neq s_0$, return 0 (invalid signature).

7. Valid signature:  
   If all checks pass, return 1 (valid signature).

#### Design Rationale

1. Short signatures:  
   The algorithm uses Schnorr's compression and reduces the length of $s_0$ from $2l$ to $l$ bits, resulting in shorter signatures and faster verification (1.5 exponentiations instead of 2).

2. Pre-hashing:  
   Instead of directly using $h(R \| X)$, the algorithm uses pre-hashing: $s_0 = h(OID(H) \| R \| H(X))$. This protects against multiple-target preimage attacks and facilitates integration with existing APIs and data formats.

3. "Whitening" the signature:  
   The second part of the signature ($s_1$) is "whitened" by using $Y = H(X)$. This makes finding collisions more difficult, providing security with strength $2^l$.

4. Use of $Q$ during verification:  
   While hashing $Q$ during signature generation could help protect against certain attacks, this approach is rejected, as key distribution should already provide protection, and hashing $Q$ would duplicate the proof of possession during key distribution.

5. Deterministic signature:  
   The generation of the ephemeral public key $k$ can be made deterministic using a special key generation algorithm $genk$. This involves hashing and symmetric encryption of data such as $OID(H)$, $d$, and $H(X)$ to produce a unique $k$.

</details>

### BN256 (Barreto-Naehrig)

The BN256 (ISO/IEC 15946-5:2022) is an elliptic curve used in cryptography, particularly for pairing-based cryptographic protocols like identity-based encryption and short signatures. It was introduced by Paulo S. L. M. Barreto and Michael Naehrig as part of their work on constructing efficient elliptic curves for pairings. 

<details><summary>BN256 Theory</summary>
  
#### Key Generation  
1. Private Key (sk): Randomly selected from $r \in \mathbb{Z}_n$, where $n$ is the curve order. It must remain secret.  
2. Public Key (pk): $pk = sk * G2$, where $G2$ is the generator point of the curve.

#### Signing  
1. Choose $k \in \mathbb{Z}_n$, keep it secret, and ensure it's never reused.
2. Compute $\sigma = k \cdot H(M)$, where $H(M)$ is the hash of the message $M$.
3. The final signature is $\sigma = sk \cdot H(M)$, where $sk$ is the private key and $H(M)$ is the hash of the message.

#### Verification  
1. Verify the signature: $e(σ, G2) = e(H(M), pk)$, where $e$ is the bilinear pairing.  
2. If the pairing holds, the signature is valid; otherwise, it’s invalid.

#### Verification Equation:  
$e(sk * H(M), G2) = e(H(M), sk * G2)$, or equivalently, $e(H(M), pk) = e(H(M), pk)$. If true, the signature is valid.

</details>

### Curupira

Curupira is a 96-bit block cipher, with keys of 96, 144 or 192 bits, and variable number of rounds, an algorithm described at [SBRC 2007](http://albanese.atwebpages.com/documentation/Curupira1_SBRC_2007.pdf) by Paulo S. L. M. Barreto and Marcos A. Simplício Jr., from Escola Politécnica da Universidade de São Paulo (USP), São Paulo, Brazil.

$$
\text{Curupira}[K] \equiv \sigma[\kappa^{(R)}] \circ \pi \circ \gamma \circ \left( \prod_{r=1}^{R-1} \sigma[\kappa^{(r)}] \circ \theta \circ \pi \circ \gamma \right) \circ \sigma[\kappa^{(0)}]
$$

### Digital Signature Algorithms

#### ElGamal-based algorithms

Here are the main differences between ECDSA, ECGDSA, and ECKCDSA:

$\text{ECDSA: Compute } r = x([k]B); \text{ s must be a root of } H(m)s^{-1} + rs^{-1}a - k \text{ modulo } n,$
$\text{ so compute } s \equiv k^{-1} \left( H(m) + ra \right) \pmod{n}.$

$\text{EC-GDSA: Compute } r = x([k]B); \text{ s must be a root of } r^{-1}H(m) + r^{-1}sa - k \text{ modulo } n,$
$\text{ so compute } s \equiv a^{-1} \left( kr - H(m) \right) \pmod{n}.$

$\text{EC-KCDSA: Compute } r = H(x([k]G));$  
$\text{ so compute } s \equiv a \cdot \left( k - (r \oplus H(cQ \parallel M)) \bmod n \right) \bmod n.$

$\text{GOST: Compute } r = x([k]G) \mod q;$  
$\text{ so compute } s \equiv (r \cdot d + k \cdot H(m)) \mod q.$

#### Schnorr-based algorithms

$\text{BignV1: Compute }  R = [k]G; s_0 \text{ must be a root of } h(OID(H) \parallel R \parallel H(X)),$ 
$\text{ so compute } s_1 \equiv (k - H(X) - (s_0 + 2^l)d) \mod q.$

$\text{EC-SDSA: Compute } W = k \cdot G, r = H(W_x \parallel W_y \parallel m) \mod q,$
$\text{ so compute } e = \text{OS2I}(r) \mod q, \text{ and } s = (k + e \cdot d) \mod q.$

$\text{EdDSA: Compute } R = [k] G; S \equiv k + H(R \parallel m) \cdot d \mod q, \text{where } H \text{ is a hash function and } d \text{ is the private key}.$

#### Boneh–Lynn–Shacham Signatures

$\text{BLS: Compute } \sigma = H(m) \cdot x, \text{ where } H(m) \text{ is the message hash and } x \text{ is the private key.}$

#### Notes
1. $H(m)$ represents the hash value of the message.
2. $k^{-1}$ denotes the modular multiplicative inverse of $k$ modulo $(p-1)$.
3. $\equiv$ indicates congruence.
4. $\oplus$ represents the XOR operation.

### ElGamal
The ElGamal algorithm is a public-key cryptography system that enables secure communication between two parties, involving asymmetric keypair generation and cryptographic operations. Initially, a large prime number $p$ and a generator $g$ for a finite cyclic group are generated. Each entity possesses a private key $x$, kept secret, and a public key $Y$, derived from $g^x \mod p$. To encrypt a symmetric key, the sender uses the session key, computes two components \(a\) and \(b\), and sends $g^k \mod p$ and $Y^k \cdot \text{key} \mod p$ to the recipient. The recipient, using their private key, decrypts the symmetric key. The ElGamal algorithm is known for its security based on the difficulty of solving the discrete logarithm problem and provides confidentiality and authentication properties. It was described by Taher A. Elgamal in 1985. 

<details>
  <summary>ElGamal Theory</summary>  

#### Key Generation

1. Generate a large prime number $p$.
2. Select a generator $g \in [2, p-2]$.
3. Generate a private key $x$ randomly.
4. Compute the public key $Y = g^x \mod p$.

#### Digital Signature

1. Select a random value $k$ such that $1 < k < p-1$, $\text{gcd}(k, p-1) = 1$.
2. Compute the first signature component: $r = g^k \mod p$.
3. Compute the second signature component: $s \equiv (H(m) - x \cdot r) \cdot k^{-1} \mod (p-1)$.

#### Digital Signature Verification

1. Receive the message $m$ and the signature components $(r, s)$.
2. Compute $w \equiv s^{-1} \mod (p-1)$.
3. Compute $u_1 \equiv H(m) \cdot w \mod (p-1)$.
4. Compute $u_2 \equiv r \cdot w \mod (p-1)$.
5. Compute $v \equiv g^{u_1} \cdot Y^{u_2} \mod p$.
6. The signature is valid if $v \equiv r \mod p$.

#### Key Agreement

1. Bob generates his key pair $(x_B, Y_B)$.
2. Bob shares his public key $Y_B$ with Alice.
3. Alice generates a random symmetric key $K_{\text{sym}}$.
4. Alice encrypts $K_{\text{sym}}$ using Bob's public key: 
   $a = g^{k_A} \mod p, \\
   b = Y_B^{k_A} \cdot K_{\text{sym}} \mod p$.
5. Alice sends the ciphertext $(a, b)$ to Bob.
6. Bob decrypts the received ciphertext using his private key to obtain:
   $K_{\text{sym}} = (b \cdot a^{-x_B}) \mod p$.
7. Now, both Alice and Bob have the shared symmetric key $K_{\text{sym}}$ for further communication.
</details>

### EC-ElGamal

The EC-ElGamal algorithm is a cryptographic scheme based on elliptic curves that enables the encryption of messages between two parties using a shared public key.  Is a cryptographic scheme that allows secure message transmission over an insecure channel. The algorithm relies on the mathematical properties of elliptic curves to ensure the confidentiality of messages.

<details>
  <summary>Pure EC-ElGamal</summary> 
EC-ElGamal encryption using elliptic curves allows secure message transmission by having Alice generate a private key $y$ and a public key $Y = y \cdot G$, while Bob encrypts a message $M$ with a random value $r$, computing $C_1 = r \cdot G$ and $C_2 = r \cdot Y + M$, and Alice decrypts using $M = C_2 - y \cdot C_1$.

First, Alice generates a private key $y$ and a public key of:  

$Y = y \cdot G$

where $G$ is the base point on the curve. She can share this public key $Y$ with Bob. When Bob wants to encrypt something for Alice, he generates a random value $r$ and the message value $M$, and then computes:

$C_1 = r \cdot G$

$C_2 = r \cdot Y + M$

To decrypt, Alice takes her private key $y$ and computes:

$M = C_2 - y \cdot C_1$

This works because:

$M = C_2 - y \cdot C_1 = r \cdot y \cdot G + M - y \cdot r \cdot G = M$  
</details>

### GOST (GOvernment STandard of Russian Federation)
GOST refers to a set of technical standards maintained by the Euro-Asian Council for Standardization, Metrology and Certification (EASC), a regional standards organization operating under the auspices of the Commonwealth of Independent States (CIS).

### Key sizes
- **Bit-length Equivalence**

    | Symmetric Key Size  | RSA and EG Key Size   | ECC Key Size   | 
    |:-------------------:|:---------------------:|:--------------:| 
    | 80                  | 1024                  | 160            | 
    | 112                 | 2048                  | 224            | 
    | 128                 | 3072                  | 256            | 
    | 192                 | 7680                  | 384            | 
    | 256                 | 15360                 | 512            |  

### IBE
Identity-Based Encryption (IBE) is a cryptographic scheme that enables users to encrypt and decrypt messages using easily memorable and publicly known information, such as an email address or user identity, as the public key. In IBE, the sender encrypts a message with the recipient's identity, and the recipient, possessing a private key generated by a trusted authority known as Key Generation Authority (KGA), can decrypt the message. Unlike traditional public-key cryptography, IBE eliminates the need for a centralized public key directory, as the user's identity itself serves as the public key. This convenience in key management makes IBE particularly suitable for secure communication in decentralized or large-scale systems, where distributing and managing individual public keys may be impractical.

<details><summary>IBE Key Management System (KMS)</summary>  
    
**Figure 1** 
<pre> +---------------------------------------------------------------+
 |                  IBE Key Management System                    |
 |      +---------------------------+  +-------------------+     |
 |      |  Private Key Generation   |--|                   |     |
 |      |      Center (PKG)         |  |                   |     |
 |      +---------------------------+  |                   |     |
 |                  |  Revoke/Update   |                   |     |
 |                  |                  |                   |     |
 |      +---------------------------+  |      Public       |     |
 |      |       Registration        |  |     Parameter     |     |
 |      |       Service (RA)        |  |      Service      |     |
 |      +---------------------------+  |       (PPS)       |     |
 |                  |  Registration    |                   |     |
 |                  |  Application     |                   |     |
 |      +---------------------------+  |                   |     |
 |      |         Terminal          |  |                   |     |
 |      |    Entity (User/Client)   |--|                   |     |
 |      +---------------------------+  +-------------------+     |
 +---------------------------------------------------------------+</pre>
  
The **IBE's Key Management System (KMS)** consists of the **Private Key Generator (PKG)**, **Registration Agency (RA)**, **Public Parameter Server (PPS)**, and **User Terminal Entity (User/Client)**. The system architecture is illustrated in **Figure 1**. The functions of each entity are described below.

#### 1. **Private Key Generation Center (PKG):**
   - **Function:** Uses the system master key and related parameters to generate private keys for users. Provides related management and query services.

#### 2. **Registration Service (RA):**
   - **Functions:**
     - Undertakes tasks related to user key application registration, authentication, management, and business communication with PKG.
     - Provides symmetric, asymmetric, and hash cryptographic services.
     - Receives key data returned by PKG and writes it into the key carrier of the terminal entity.

#### 3. **Public Parameter Service (PPS):**
   - **Function:** A user-oriented information service system, providing publicly accessible addresses for secure query and distribution of public parameters and policies. Public parameters include password parameters and user ID status directories that can be shared publicly.

#### 4. **User Terminal Entity (User/Client):**
   - **Functions:**
     - Terminal application system of the user information service system.
     - Applies for keys directly from PKG or through a local agent.
     - Realizes the storage and use of its own private keys.

**IBE Key Management System Architecture:**
- **Secure Channels:** The generation and distribution of user keys mainly involve entities such as PKG, RA, and User/Client. This is achieved by establishing secure channels between PKG and RA, and between RA and User/Client, ensuring secure transfer and download of keys.

**Summary:**
The architecture of the IBE Key Management System ensures secure generation of private keys by PKG, tasks of key registration and application are carried out by RA, public parameters are provided by PPS, and users interact with the system through the User/Client terminal. Secure channels facilitate the transfer and download of keys between these entities, ensuring the overall security of the key management system.</details>

### IKM (input key material value)
Keying material is in general to include things like shared Diffie-Hellman secrets (which are not suitable as symmetric keys), which have more structure than normal keys.

### Lyra2
Lyra2 is a Password Hashing Scheme (PHS) that can function as a Key Derivation Function (KDF). The Lyra2REv2 chained is an enhanced version of the Lyra2REv2 hash algorithm used in cryptocurrency mining, such as Vertcoin. It involves chaining multiple hash functions in sequential steps, increasing the complexity and security of the mining process. This design makes the algorithm more resistant to ASIC mining, encouraging the use of GPUs and maintaining network decentralization. Additionally, the chaining of functions improves cryptographic security, making it harder to execute attacks like collisions or preimage attacks, ensuring that transaction validation and block creation are more robust and secure. Designed by Marcos A. Simplicio Jr., Leonardo C. Almeida, Ewerton R. Andrade, Paulo C. F. dos Santos e Paulo S. L. M. Barreto from Escola Politécnica da Universidade de São Paulo.

<details><summary>Lyra2REv2 Chained</summary>  
<pre>-----------  ------------  --------------
|BLAKE-256|->|Keccak-256|->|CubeHash-256|
-----------  ------------  --------------
                                      \
                                       v
                                    -------
                                    |Lyra2|
                                    -------
                                       /
                                      v
-----------  --------------  ------------
|Skein-256|<-|CubeHash-256|<-|  BMW-256 |
-----------  --------------  ------------
</pre>

Fig. 1. The Lyra2REv2 chained hashing algorithm.
</details>

### MAC
MAC (Message Authentication Code) is a cryptographic function used to ensure the integrity and authenticity of a message. It takes a message and a secret key as inputs and produces a fixed-size authentication tag, which is appended to the message. The receiver can then verify the authenticity of the message by recomputing the MAC using the shared secret key and comparing it to the received tag. If they match, the message is deemed authentic and unaltered.

### ML-KEM, ML-DSA
Module-lattice-based algorithms, such as KEM (Key Encapsulation Mechanism) and DSA (Digital Signature Algorithm), are promising solutions in post-quantum cryptography that provide security against attacks from quantum computers. KEM facilitates secure key exchange by encapsulating a secret key in an object, leveraging complex mathematical problems like the Shortest Vector Problem (SVP) or Learning With Errors (LWE) to ensure security and efficiency. Meanwhile, DSA generates and verifies digital signatures, ensuring the authenticity and integrity of messages while also using lattice structures for protection against quantum algorithms. Together, these approaches represent a significant advancement for information security in the future.

### NUMS
**Microsoft Nothing Up My Sleeve Elliptic curves**  
[NUMS](http://www.ietf.org/archive/id/draft-black-numscurves-01.txt) (Nothing Up My Sleeve) curves, which are supported in the MSRElliptic Curve Cryptography Library (a.k.a. MSR ECCLib).

These curves are elliptic curves over a prime field, just like the NIST or Brainpool curves. However, the domain-parameters are choosen using a VERY TIGHT DESIGN SPACE to ensure, that the introduction of a backdoor is infeasable. For a desired size of $s$ bits the prime $p$ is choosen as $p = 2^s - c$ with the smallest $c$ where $c>0$ and $p$ mod 4 = 3 and $p$ being prime.

### PBKDF2
PBKDF2 (Password-Based Key Derivation Function 2) is a widely used cryptographic function designed to derive secure cryptographic keys from weak passwords or passphrases. It applies a pseudorandom function, such as HMAC-SHA1, HMAC-SHA256, or HMAC-SHA512, multiple times in a loop, with a salt and a user-defined number of iterations, effectively increasing the computational cost of key generation. This technique enhances the resilience against brute-force attacks, making it more difficult and time-consuming for attackers to obtain the original password from the derived key.

### Post-Quantum Cryptography (PQC)
Quantum computing is in an early stage of development and faces significant challenges, including the control and correction of quantum errors. Predictions vary, but many experts agree that we are still several years, or even decades, away from having the ability to build a quantum computer large enough to threaten public key cryptography algorithms currently considered secure. Scalable, sufficiently powerful quantum computers have not yet been constructed. Therefore, post-quantum cryptography is more of a precautionary measure, as classical algorithms remain secure for most everyday applications. Understand which algorithms have been compromised with the advent of quantum algorithms like Shor and Grover:

- **Security Level**

    |Name           | Function      |pre-quantum    | post-quantum   |
    |:--------------|:--------------|:-------------:|:--------------:|
    |AES-128        | block cipher  | 128           | 64 (Grover)    |
    |AES-256        | block cipher  | 256           | 128 (Grover)   |
    |Salsa20        | stream cipher | 256           | 128 (Grover)   |
    |GMAC           | MAC           | 128           | 128            |
    |Poly1305       | MAC           | 128           | 128            |
    |SHA-256        | hash function | 256           | 128 (Grover)   |
    |SHA-3          | hash function | 256           | 128 (Grover)   |
    |RSA-3072       | encryption    | 128           | broken (Shor)  |
    |RSA-3072       | signature     | 128           | broken (Shor)  |
    |256-bit ECDH   | key exchange  | 128           | broken (Shor)  |
    |256-bit ECDSA  | signature     | 128           | broken (Shor)  |

### Schnorr Signatures
The key generation process begins with generating a safe prime $p = 2q + 1$, where both $p$ and $q$ are prime numbers. Then, a generator $g$ of a subgroup of order $q$ is computed. The private key $x$ is a randomly chosen integer in $[0, q - 1]$, and the public key is $y = g^x \mod p$. These values form the basis of the Schnorr signature system. Parameters $(p, q, g)$ are shared across users, while keys $x$ and $y$ are individual-specific. The Schnorr signature is generated by selecting a random nonce $k$, then computing a commitment $r = g^k \mod p$. A challenge $e$ is computed by hashing $r$ concatenated with the message. The response $s$ is then calculated using the formula $s = (k + e \cdot x) \mod q$. The final signature is the pair $(e, s)$, which is compact and secure under the discrete logarithm assumption. To verify a Schnorr signature, the verifier recomputes a value $r'$ from the response $s$ and the challenge $e$, using the public key. A hash is then computed from $r'$ and the message to produce $e'$. If $e' = e$, the signature is valid.

<details>
  <summary>Schnorr Signature Scheme</summary>  

#### Key Generation

1. Generate a prime $q$ of the desired bit length.
2. Compute $p = 2q + 1$, and verify that $p$ is prime.
3. Find a generator $g$ of the subgroup of order $q$ in $\mathbb{Z}_p^*$.
4. Choose a private key $x \in [0, q - 1]$.
5. Compute the public key $y = g^x \mod p$.

#### Signing

1. Select a random $k \in [0, q - 1]$.
2. Compute $r = g^k \mod p$.
3. Compute the challenge $e = H(r \parallel m) \mod q$.
4. Compute the response $s = (k + e \cdot x) \mod q$.
5. The signature is the pair $(e, s)$.

#### Verification

1. Receive the message $m$, and signature $(e, s)$.
2. Compute $g^s \mod p$.
3. Compute $y^e \mod p$ and its modular inverse.
4. Compute $r' = g^s \cdot (y^e)^{-1} \mod p$.
5. Compute $e' = H(r' \parallel m) \mod q$.
6. The signature is valid if $e' = e$.

#### Notes

1. $H(m)$ represents a cryptographic hash function (e.g., SHA-256).
2. $k$ must be freshly generated for each signature and kept secret.
3. $\parallel$ denotes byte-wise concatenation.
4. The group $\mathbb{Z}_p^*$ must have a known subgroup of prime order $q$.
5. The hash function must be collision-resistant and preimage-resistant.

</details>

### ShangMi (SM) National secret SM2/SM3/SM4 algorithms
SM2 is a public key cryptographic algorithm based on elliptic curves, used for e.g. generation and verification of digital signatures; SM3, a hashing algorithm comparable to SHA-256; and SM4, a block cipher algorithm for symmetric cryptography comparable to AES-128. These standards are becoming widely used in Chinese commercial applications such as banking and telecommunications and are sometimes made mandatory for products procured by Chinese government agencies. SM4 is part of the ARMv8.4-A expansion to the ARM architecture.

### SM9 GM/T 0044-2016 Public key algorithm 256-bit
Parameters for the sm9p256v1 Elliptic curve

SM9 is a Chinese National Identity Based Cryptography Standard and was originally published using a 256-bit Barreto-Naehrig Curve as its primary example. The new paper suggests that because attacks against some Barreto-Naehrig curves have improved that the SM9 standard should adopt a 384-bit Barreto-Naehrig Curve. The authors go on to suggest that this curve offers roughly 118 bits of security.

### XOR
XOR (Exclusive OR) is a logical operator that works on bits. Let’s denote it by ^. If the two bits it takes as input are the same, the result is 0, otherwise it is 1. This implements an exclusive or operation, i.e. exactly one argument has to be 1 for the final result to be 1. We can show this using a truth table:

- **exclusive or**

    |x    |y    | x^y |
    |:---:|:---:|:---:|
    |0    |0    |0    |
    |0    |1    |1    |
    |1    |0    |1    |
    |1    |1    |0    |

### Zero-Knowledge Proof (ZKP)

The ZKP for bilinear curves (like BLS12-381) is a non-interactive protocol (NIZK) that enables a prover (user) to demonstrate possession of a valid private key ($sk_{user}$) associated with a public key ($pk_{user}$) without revealing the private key. The proof is verifiable by any party using bilinear pairing properties ($e$). Here's the detailed description:

<details>
  <summary>Zero-Knowledge Proof (ZKP) for Bilinear Curves</summary>  
  
- **Zero-Knowledge Proof (ZKP)**
  1. Commitment: $C = r \cdot G_2$, where $r$ is a secure random number, $G_2$ is the elliptic curve base point.
  2. Challenge: $\chi = H(C \parallel m)$, where $H$ is a cryptographic hash function, $m$ is the message/context. 
  3. Response: $s = r + \chi \cdot sk_{user}$, where $sk_{user}$ is the user's private key and $\chi$ is the computed challenge.
  4. Verification: Check if $e(s \cdot G_1, G_2) = e(G_1, C + (\chi \cdot pk_{user}))$, where $e$ is the bilinear pairing. 
  5. Validation: If the equality holds, the proof is valid.  

- **Verification relies on the properties of bilinear pairing:**  
  1. Linearity: $e(s \cdot G_1, G_2) = e(G_1, G_2)^{s} = e(G_1, G_2)^{r + \chi \cdot sk_{user}}$  
  2. Substitution: $e(G_1, G_2)^{r + \chi \cdot sk_{user}} = e(G_1, C + \chi \cdot pk_{user})$  
  3. Expansion: $e(G_1, C + \chi \cdot pk_{user}) = e(G_1, r \cdot G_2 + \chi \cdot sk_{user} \cdot G_2) = e(G_1, G_2)^{r + \chi \cdot sk_{user}}$  
</details>
    
### ZUC (Zu Chongzhi cipher)

  The ZUC-256 cipher is a symmetric key encryption algorithm widely used in 5G communication technologies, providing robust and efficient security. The ZUC-256 algorithm is based on the original ZUC cipher, developed by the Chinese Academy of Sciences and adopted by the 3rd Generation Partnership Project (3GPP) standard to ensure data integrity and confidentiality in fifth-generation mobile networks. Its name pays tribute to Zu Chongzhi, a 5th-century Chinese mathematician and astronomer, renowned for his contributions to mathematics, astronomy, and hydraulic engineering. His remarkable approximation of the value of π (pi) enabled more precise calculations in various scientific fields. 

## Features
* **Cryptographic Functions:**

   * Asymmetric Encryption
   * Symmetric Encryption + AEAD Modes
   * Digital Signature
   * Recursive Hash Digest + Check
   * ECDH (Shared Key Agreement)
   * CMAC (Cipher-based message authentication code)
   * HMAC (Hash-based message authentication code)
   * HKDF (HMAC-based key derivation function)
   * PBKDF2 (Password-based key derivation function)
   * PHS (Password-hashing scheme)
   * TLS (Transport Layer Security v1.2 and 1.3)
   * TLCP (Transport Layer Cryptography Protocol v1.1)
   * PKCS12 (Personal Information Exchange Syntax v1.1)
   * X.509 CSRs, CRLs and Certificates
  
* **Non-cryptographic Functions:**

   * Hex string encoder/dump/decoder (xxd-like)
   * Base32 encoder/decoder
   * Base64 encoder/decoder
   * Base85 encoder/decoder
   * Zlib compression
   * Privacy-Enhanced Mail (PEM format)
   * RandomArt (OpenSSH-like)

## Usage
<pre>Usage of edgetk:
  -algorithm string
        Public key algorithm: EC, Ed25519, GOST2012, SM2. (default "RSA")
  -base32 string
        Encode binary string to Base32 format and vice-versa. [enc|dec]
  -base64 string
        Encode binary string to Base64 format and vice-versa. [enc|dec]
  -base85 string
        Encode binary string to Base85 format and vice-versa. [enc|dec]
  -bits int
        Key length. (for keypair generation and symmetric encryption)
  -blind-factor string
        Blind Factor in hexadecimal. (for Blind Signatures)
  -cacert string
        CA Certificate path. (for TLCP Protocol)
  -cakey string
        CA Private key. (for TLCP Protocol)
  -candidates string
        List of candidates, separated by commas.
  -cert string
        Certificate path.
  -challenge string
        Challenge for the proof. (for Zero-Knowledge Proof ZKP)
  -change
        Change Passphrase of a Private Key.
  -check
        Check hashsum file. ('-' for STDIN)
  -cipher string
        Symmetric algorithm: aes, blowfish, magma or sm4. (default "aes")
  -commitment string
        Commitment for the proof. (for Zero-Knowledge Proof ZKP)
  -crl string
        Certificate Revocation List path.
  -crypt string
        Bulk Encryption with Stream and Block ciphers. [enc|dec|help]
  -curve string
        Subjacent curve (secp256r1, secp256k1, bls12381g1/g2.)
  -days int
        Defines the validity of the certificate from the date of creation.
  -digest
        Target file/wildcard to generate hashsum list. ('-' for STDIN)
  -factorp string
        Makwa private Factor P. (for Makwa Password-hashing Scheme)
  -factorq string
        Makwa private Factor Q. (for Makwa Password-hashing Scheme)
  -hex string
        Encode binary string to hex format and vice-versa. [enc|dump|dec]
  -hid uint
        Hierarchy Identifier. (for SM9 User Private Key) (default 1)
  -id string
        User Identifier. (for SM9 User Private Key operations)
  -info string
        Additional info. (for HKDF command and AEAD bulk encryption)
  -ipport string
        Local Port/remote's side Public IP:Port.
  -isca
        The requested CSR is for a Certificate Authority (CA).
  -iter int
        Iter. (for Password-based key derivation function) (default 1)
  -iv string
        Initialization Vector. (for symmetric encryption)
  -kdf string
        Key derivation function. [pbkdf2|hkdf|scrypt|argon2|lyra2re2]
  -key string
        Asymmetric key, symmetric key or HMAC key, depending on operation.
  -mac string
        Compute Hash/Cipher-based message authentication code.
  -master string
        Master key path. (for sm9 setup) (default "Master.pem")
  -md string
        Hash algorithm: sha256, sha3-256 or whirlpool. (default "sha256")
  -mode string
        Mode of operation: GCM, MGM, CBC, CFB8, OCB, OFB. (default "CTR")
  -modulus string
        Makwa modulus. (Makwa hash Public Parameter)
  -msgs value
        Messages to be verified. (can be passed multiple times)
  -nopad
        No padding. (for Base64 and Base32 encoding)
  -params string
        ElGamal Public Parameters path.
  -paramset string
        Elliptic curve ParamSet: A, B, C, D. (for GOST2012) (default "A")
  -pass string
        Password/Passphrase. (for Private key PEM encryption)
  -passout string
        User Password. (for SM9 User Private Key PEM encryption)
  -peerid string
        Remote's side User Identifier. (for SM9 Key Exchange)
  -pkey string
        Subcommands: keygen|certgen, sign|verify|derive, text|modulus.
  -prv string
        Private key path. (for keypair generation) (default "Private.pem")
  -pub string
        Public key path. (for keypair generation) (default "Public.pem")
  -pub2 string
        Public key 2 path. (for keypair generation)
  -pubs value
        Paths to the public keys. (can be passed multiple times)
  -rand int
        Generate random cryptographic key with given bit length.
  -recover
        Recover Passphrase from Makwa hash with Private Parameters.
  -recursive
        Process directories recursively. (for DIGEST command only)
  -response string
        Response for the proof. (for Zero-Knowledge Proof ZKP)
  -root string
        Root CA Certificate path.
  -salt string
        Salt. (for HKDF and PBKDF2 commands)
  -signature string
        Input signature. (for VERIFY command and MAC verification)
  -subj string
        Subject: Identity. (Example: "/CN=/OU=/O=/ST=/L=/C=/emailAddress=")
  -tcp string
        Encrypted TCP/IP Transfer Protocol. [server|ip|client]
  -token string
        Token containing an encrypted symmetric key.
  -tweak string
        Additional 128-bit parameter input. (for THREEFISH encryption)
  -version
        Print version info.
  -votes string
        Comma-separated list of vote counters.
  -wrap int
        Wrap lines after N columns. (for Base64/32 encoding) (default 64)</pre>

## Examples

#### Post-Quantum Digital Signature with ML-DSA or SLH-DSA:
```sh
edgetk -pkey keygen -algorithm [ml-dsa|slh-dsa] -prv Private.pem -pub Public.pem
edgetk -pkey sign -key Private.pem -pass "pass" -signature sign.txt FILE
edgetk -pkey verify -key Public.pem -signature sign.txt FILE
```
#### Post-Quantum Key Encapsulation Mechanism (ML-KEM):
```sh
edgetk -pkey keygen -algorithm ml-kem -prv Private.pem -pub Public.pem
edgetk -pkey wrapkey -key Public.pem -cipher cipher.txt
edgetk -pkey unwrapkey -key Private.pem -pass "pass" -cipher cipher.txt
```

<details><summary>PQC Public Key Infrastructure (PKI)</summary>  

#### Key Generation:
```sh
edgetk -pkey keygen -algorithm [ml-dsa|slh-dsa] -prv CAPrivate.pem -pub CAPublic.pem
```
#### Self-Signed Certificate Generation:
```sh
edgetk -pkey certgen -key CAPrivate.pem -pub CAPublic.pem -cert CACert.crt
```
#### Check Certificate Authenticity:
```sh
edgetk -pkey check -cert CACert.crt -key CAPublic.pem
echo $?
```
#### Certificate Signing Request (CSR):
```sh
edgetk -pkey req -key Private.pem -pub Public.pem -cert Cert.csr
```
#### Display CSR Information:
```sh
edgetk -pkey text -cert Cert.csr
```
#### X.509 Certificate Signing:
```sh
edgetk -pkey x509 -key CAPrivate.pem -root CACert.crt -cert Cert.csr Cert.crt
```
#### Display Certificate Information:
```sh
edgetk -pkey text -cert Cert.crt
echo $?
```
#### Check Certificate Authenticity:
```sh
edgetk -pkey check -cert Cert.crt -key CAPublic.pem
echo $?
```
#### Generate Certificate Revocation List (CRL):
```sh
edgetk -pkey crl -key CAPrivate.pem pub CAPublic.pem -cert CACert.crt serials.txt NewCRL.pem
```
#### Display CRL Information:
```sh
edgetk -pkey text -crl NewCRL.pem
```
#### Check CRL Authenticity:
```sh
edgetk -pkey check -crl NewCRL.pem -cert CACert.crt
echo $?
```
#### Validate Certificate Against CRL:
```sh
edgetk -pkey validate -cert Cert.crt -crl NewCRL.pem
echo $?
```

For non-interactive scripts, you must use the flags -pass, -days and -subj:
```
-pass "passphrase"
-days 365
-subj "/CN=Test/OU=/O=/ST=/L=/C=/emailAddress=test@test.com"
```
</details>

#### Asymmetric EG keypair generation:
```sh
./edgetk -pkey setup -algorithm elgamal [-bits 4096] > ElGamalParams.pem
./edgetk -pkey keygen -algorithm elgamal -params ElGamalParams.pem [-pass "passphrase"] [-prv Private.pem] [-pub Public.pem]
```
#### EG Digital signature:
```sh
./edgetk -pkey sign -algorithm elgamal [-theorem dsa] -key Private.pem [-pass "passphrase"] < file.ext > sign.txt
sign=$(cat sign.txt|awk '{print $2}')
./edgetk -pkey verify -algorithm elgamal [-theorem dsa] -key Public.pem -signature $sign < file.ext
echo $?
```
#### EG Encryption scheme:
```sh
./edgetk -pkey wrapkey -algorithm elgamal -key Public.pem > cipher.txt
ciphertext=$(cat cipher.txt|grep "Cipher"|awk '{print $2}')
./edgetk -pkey unwrapkey -algorithm elgamal -key Private.pem [-pass "passphrase"] -cipher $ciphertext
```
#### EG Zero-Knowledge Proof (ZKP):
```sh
./edgetk -pkey proof -key Private.pem file.ext > proof.txt
commit=$(grep "Commitment" proof.txt | awk '{print $2}')
chall=$(grep "Challenge" proof.txt | awk '{print $2}')
resp=$(grep "Response" proof.txt | awk '{print $2}')
./edgetk -pkey verify-proof -key Public.pem -commitment $commit -challenge $chall -response $resp file.ext
echo $? 
```
#### Asymmetric RSA keypair generation:
```sh
./edgetk -pkey keygen -bits 4096 [-pass "passphrase"] [-prv Private.pem] [-pub Public.pem]
```
#### Parse keys info:
```sh
./edgetk -pkey [text|modulus] [-pass "passphrase"] -key Private.pem
./edgetk -pkey [text|modulus|randomart|fingerprint] -key Public.pem
```
#### Digital signature:
```sh
./edgetk -pkey sign -key Private.pem [-pass "passphrase"] < file.ext > sign.txt
sign=$(cat sign.txt|awk '{print $2}')
./edgetk -pkey verify -key Public.pem -signature $sign < file.ext
echo $?
```
#### Encryption/decryption with RSA algorithm:
```sh
./edgetk -pkey encrypt -key Public.pem < plaintext.ext > ciphertext.ext
./edgetk -pkey decrypt -key Private.pem < ciphertext.ext > plaintext.ext
```
#### Asymmetric EC keypair generation (256-bit):
```sh
./edgetk -pkey keygen -bits 256 -algorithm EC [-pass "passphrase"] [-prv Private.pem] [-pub Public.pem]
```
#### EC Diffie-Hellman:
```sh
./edgetk -pkey derive -algorithm EC -key Private.pem -pub Peerkey.pem
```
#### EC-ElGamal scheme:
```sh
./edgetk -pkey wrapkey -algorithm EC -key Public.pem > cipher.txt
ciphertext=$(cat cipher.txt|grep "Cipher"|awk '{print $2}')
./edgetk -pkey unwrapkey -algorithm EC -key Private.pem [-pass "passphrase"] -cipher $ciphertext
```
#### Generate Self Signed Certificate:
```sh
./edgetk -pkey certgen -key Private.pem [-pass "passphrase"] [-cert "output.crt"]
```
#### Generate Certificate Signing Request:
```sh
./edgetk -pkey req -key Private.pem [-pass "passphrase"] [-cert Certificate.csr]
```
#### Sign CSR with CA Certificate:
```sh
./edgetk -pkey x509 -key Private.pem -root CACert.pem -cert Certificate.csr > Certificate.crt
```
#### Parse Certificate info:
```sh
./edgetk -pkey [text|modulus] -cert Certificate.pem
```
#### Generate Certificate Revocation List:
```sh
./edgetk -pkey crl -cert CACert.pem -key Private.pem -crl old.crl serials.txt > NewCRL.crl
```
For non-interactive scripts, you must use the flags -pass, -days and -subj:
```
-pass "passphrase"
-days 365
-subj "/CN=Test/OU=/O=/ST=/L=/C=/emailAddress=test@test.com"
```
#### TLS Layer (TCP/IP):
```sh
./edgetk -tcp ip > MyExternalIP.txt
./edgetk -tcp server -cert Certificate.pem -key Private.pem [-ipport "8081"]
./edgetk -tcp client -cert Certificate.pem -key Private.pem [-ipport "127.0.0.1:8081"]
```
Or IPv6
```sh
./edgetk -tcp server -cert Certificate.pem -key Private.pem [-ipport "8081"]
./edgetk -tcp client -cert Certificate.pem -key Private.pem [-ipport "[2001:db8::1]:8081"]
```

#### Symmetric key generation (256-bit):
```sh
./edgetk -rand 256
```
#### Encryption/decryption with block cipher:
```sh
./edgetk -crypt enc -key $256bitkey < plaintext.ext > ciphertext.ext
./edgetk -crypt dec -key $256bitkey < ciphertext.ext > plaintext.ext
```
#### Message digest:
```sh
./edgetk -digest [-recursive] "*.*" > hash.txt
./edgetk -check hash.txt
echo $?
or
./edgetk -check hash.txt|grep FAILED^|Not found!
```
#### Bcrypt:
```sh
./edgetk -digest -md bcrypt -key "yourkey" [-iter 10] > key.bcrypt
./edgetk -check -md bcrypt -key "yourkey" < key.bcrypt
echo $?
```
#### HMAC:
```sh
./edgetk -mac hmac -key "secret" < file.ext
./edgetk -mac hmac -key "secret" -signature $256bitmac < file.ext
echo $?
```
#### HKDF (HMAC-based key derivation function) (128-bit):
```sh
./edgetk -kdf hkdf -bits 128 -key "IKM" [-salt "salt"] [-info "AD"]
```
#### IBE (Identity-Based Encryption)
##### Master Key Pair Generation:

- Generate a master key pair for BLS12-381.
```sh
./edgetk -pkey setup -algorithm bls12381 -master "Master.pem" [-pass "passphrase"] -pub "MasterPublic.pem"
```

##### User's Private Key Generation:

- Generate a private key for a user, associated with their UID and HID.
```sh
./edgetk -pkey keygen -algorithm bls12381 -master "Master.pem" [-pass "pass"] -prv "Private.pem" [-passout "pass"] -id "UID" -hid 3
```

##### Key Parsing:

- Parse the master key, user private key, or master public key to view their details.
```sh
./edgetk -pkey text -key "Master.pem" [-pass "passphrase"]
./edgetk -pkey text -key "Private.pem" [-pass "passphrase"]
./edgetk -pkey text -key "MasterPublic.pem"
```

##### Message Encryption with User Public Key:

- Encrypt a message using the master public key and the user’s UID.
```sh
./edgetk -pkey encrypt -algorithm bls12381 -key "MasterPublic.pem" -id "UID" -hid 3 "plaintext.ext" > "ciphertext.enc"
```

##### Message Decryption with User Private Key:

- Decrypt a message using the user’s private key.
```sh
./edgetk -pkey decrypt -algorithm bls12381 -key "Private.pem" [-pass "passphrase"] "ciphertext.enc"
echo $?
```

##### Digital Signature Generation:

- Generate a digital signature for a file using the user's private key, and verify the signature using the master public key and the UID of the signer.
```sh
./edgetk -pkey sign -algorithm bls12381 -key "Private.pem" FILE > sign.txt
sign=$(cat sign.txt | awk '{print $2}')
./edgetk -pkey verify -algorithm bls12381 -key "MasterPublic.pem" -id "UID" -hid 3 -signature $sign FILE
echo $?
```

##### User's Private Key Generation for Digital Signature Theorems:

- Generate a private key for a user, associated with their UID.
```sh
./edgetk -pkey keygen -algorithm bls12381sign -theorem [shangmi|barreto] -master "Master.pem" [-pass "pass"] -prv "PrivateSign.pem" [-passout "pass"] -id "UID" -hid 1
```

##### Digital Signature Generation:

- Generate a digital signature for a file using the user's private key, and verify the signature using the master public key and the UID of the signer.
```sh
./edgetk -pkey sign -algorithm bls12381 -theorem [shangmi|barreto] -key "PrivateSign.pem" FILE > sign.txt
sign=$(cat sign.txt | awk '{print $2}')
./edgetk -pkey verify -algorithm bls12381 -theorem [shangmi|barreto] -key "MasterPublic.pem" -id "UID" -hid 1 -signature $sign FILE
echo $?
```

#### SM9 (Chinese IBE Standard)
##### Private Key Generation:

- Generate a master key
```sh
./edgetk -pkey setup -algorithm <sm9encrypt|sm9sign> [-master "Master.pem"] [-pub "Public.pem"]
```
- Generate a private key and a UID (User ID) and an HID (Hierarchy ID).
```sh
./edgetk -pkey keygen -algorithm <sm9encrypt|sm9sign> [-master "Master.pem"] [-prv "Private.pem"] [-id "uid"] [-hid 1]
```

##### Message Encryption:

- To encrypt a message:
  - Use the master public key.
  - Include the UID and HID associated with the private key.
  - Perform the encryption process.
```sh
./edgetk -pkey encrypt -algorithm sm9encrypt [-key "Public.pem"] [-id "uid"] [-hid 1] < FILE
```
##### Message Decryption:

- To decrypt a message:
  - Use the associated private key.
  - Use the corresponding UID.
  - Perform the decryption process.
```sh
./edgetk -pkey decrypt -algorithm sm9encrypt [-key "Private.pem"] [-id "uid"] < FILE
```
##### Digital Signature:

- To sign a message:
  - Use the private key (UID and HID are associated).
  - Perform the signature process.
```sh
./edgetk -pkey sign -algorithm sm9sign [-key "Private.pem"] < FILE
```
##### Digital Signature Verification:

- To verify the signature of a message:
  - Use the master public key.
  - Use the UID and HID associated with the private key that performed the signature.
  - Perform the signature verification process.
```sh
./edgetk -pkey verify -algorithm sm9sign [-key "Public.pem"] [-id "uid"] [-hid 1] [signature "sign"] < FILE
```
#### Hex Encoder/Decoder:
```sh
./edgetk -hex enc < file.ext > file.hex
./edgetk -hex dec < file.hex > file.ext
./edgetk -hex dump < file.ext
```
#### Base32/64 Encoder/Decoder:
```sh
./edgetk -base32 enc [-wrap 0] [-nopad] < file.ext > file.b32
./edgetk -base32 dec [-nopad] < file.b32 > file.ext
```
#### Try:
```
./edgetk -crypt help   // Describes bulk encryption usage and arguments
./edgetk -kdf help     // Describes key derivation function usage
./edgetk -mac help     // Describes message authentication code usage
./edgetk -pkey help    // Describes public key cryptography usage
./edgetk -tcp help     // Describes TLS 1.3 Protocol parameters and usage
./edgetk -help,-h      // Full list of the flags and their defaults
./edgetk -version      // Print version info
```

## Acknowledgments

- [Sergey Matveev](http://www.cypherpunks.su/) (GoGOST Library Author)
- [RyuaNerin](http://github.com/RyuaNerin) (go-krypto Library Author)
- [Sun Yimin](https://github.com/emmansun) (GMSM Library Author)
- [Damian Gryski](https://github.com/dgryski) (Anubis, SipHash, Misty1 Libraries Author)
- [Dana Booth](https://sourceforge.net/u/danabooth/profile/) (Main Contributor)
- [Deatil](https://github.com/deatil) (go-cryptobin, go-hash Libraries Author)

## Contribute
**Use issues for everything**
- You can help and get help by:
  - Reporting doubts and questions
- You can contribute by:
  - Reporting issues
  - Suggesting new features or enhancements
  - Improve/fix documentation

## License

This project is licensed under the ISC License.

#### Copyright (c) 2020-2025 Pedro F. Albanese - ALBANESE Research Lab.  
Todos os direitos de propriedade intelectual sobre este software pertencem ao autor, Pedro F. Albanese. Vide Lei 9.610/98, Art. 7º, inciso XII.
