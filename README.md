# EDGE Toolkit
[![ISC License](http://img.shields.io/badge/license-ISC-blue.svg)](https://github.com/pedroalbanese/edgetk/blob/master/LICENSE.md) 
[![GoDoc](https://godoc.org/github.com/pedroalbanese/edgetk?status.png)](http://godoc.org/github.com/pedroalbanese/edgetk)
[![GitHub downloads](https://img.shields.io/github/downloads/pedroalbanese/edgetk/total.svg?logo=github&logoColor=white)](https://github.com/pedroalbanese/edgetk/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/pedroalbanese/edgetk)](https://goreportcard.com/report/github.com/pedroalbanese/edgetk)
[![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/pedroalbanese/edgetk)](https://golang.org)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/pedroalbanese/edgetk)](https://github.com/pedroalbanese/edgetk/releases)

Multi-purpose cross-platform hybrid cryptography tool for symmetric and asymmetric encryption, cipher-based message authentication code (CMAC/PMAC/GMAC/VMAC), recursive hash digest, hash-based message authentication code (HMAC), HMAC-based key derivation function (HKDF), password-based key derivation function (PBKDF2/Argon2/Scrypt), password-hashing scheme (Bcrypt/Argon2/Makwa), shared key agreement (ECDH/VKO/X25519), digital signature (RSA/ECDSA/EdDSA/GOST/SPHINCS+), X.509 CSRs, CRLs and Certificates, and TCP instant server with TLS 1.3 and TLCP encryption layers for small or embedded systems. 

***Fully OpenSSL/LibreSSL/GmSSL/RHash/Mcrypt compliant***

<details><summary>Implements</summary>  
    
1. Anubis Involutional SPN 128-bit block cipher (Barreto, ESAT/COSIC)
2. BSI TR-03111 ECKA-EG (Elliptic Curve Key Agreement based on ElGamal)
3. CHASKEY Message Authentication Code (Nicky Mouha, ESAT/COSIC)
4. CubeHash and SipHash64/128 (Daniel J. Bernstein & JP Aumasson)
5. DSTU 7564:2014 A New Standard of Ukraine: The Kupyna Hash Function
6. DSTU 7624:2014 A Encryption Standard of Ukraine: Kalyna Block Cipher
7. GB/T 32907-2016 - SM4 128-bit Block Cipher
8. GB/T 32918.4-2016 SM2 Elliptic Curve Asymmetric Encryption
9. GB/T 38636-2020 - Transport Layer Cryptography Protocol (TLCP)
10. GM/T 0001-2012 ZUC Zu Chongzhi Stream cipher 128/256-bit key
11. GM/T 0002-2012 SM4 Block cipher with 128-bit key
12. GM/T 0003-2012 SM2 Public key algorithm 256-bit
13. GM/T 0004-2012 SM3 Message digest algorithm 256-bit hash value
14. GM/T 0044-2016 SM9 Public key algorithm 256-bit
15. GM/T 0086-2020 Specification of key management system based on SM9
16. GOST 28147-89 64-bit block cipher (RFC 5830)
17. GOST R 34.10-2012 VKO key agreement function (RFC 7836)
18. GOST R 34.10-2012 public key signature function (RFC 7091)
19. GOST R 34.11-2012 Streebog hash function (RFC 6986)
20. GOST R 34.11-94 CryptoPro hash function (RFC 5831)
21. GOST R 34.12-2015 128-bit block cipher Kuznechik (RFC 7801)
22. GOST R 34.12-2015 64-bit block cipher Magma (RFC 8891)
23. GOST R 50.1.114-2016 GOST R 34.10-2012 and GOST R 34.11-2012
24. HC-128 Stream Cipher simplified version of HC-256 (Wu, ESAT/COSIC)
25. IGE (Infinite Garble Extension) Mode of Operation for Block ciphers
26. ISO/IEC 10118-3:2003 RIPEMD128/160/256 and Whirlpool (ESAT/COSIC)
27. ISO/IEC 18033-3:2010 HIGHT, SEED, Camellia and MISTY1 Block ciphers
28. ISO/IEC 18033-4:2011 KCipher-2 stream cipher (RFC 7008)
29. ISO/IEC 29192-3:2012 Trivium Stream cipher with 80-bit key
30. ISO/IEC 18033-5:2015 IBE - Identity-based Encryption Mechanisms
31. ISO/IEC 18033-5:2015/Amd.1:2021(E) SM9 Mechanism
32. ISO/IEC 29192-2:2019 PRESENT, CLEFIA and LEA block ciphers
33. ISO/IEC 15946-5:2022 Barreto-Naehrig and Barreto-Lynn-Scott Curves
34. KS X 1213-1 ARIA 128-bit block cipher with 128/192/256-bit keys
35. KS X 3246 LEA - Lightweight Encryption Algorithm (TTAK.KO-12.0223)
36. KS X 3262 LSH - A New Fast Secure Hash Function Family (in Korean)
37. NIST SP800-186 X25519 Diffie-Hellman (OpenSSL compliant)
38. NIST SP800-38D GCM AEAD mode for 128-bit block ciphers (RFC 5288)
39. RFC 2104: HMAC - Keyed-Hashing for Message Authentication
40. RFC 2144: CAST-128 64-bit Block cipher with 128-bit key
41. RFC 2612: The CAST-256 Encryption Algorithm
42. RFC 3610: Counter with CBC-MAC Mode of Operation (CCM Mode)
43. RFC 4009: The SEED Encryption Algorithm (KISA)
44. RFC 4253: Serpent 128-bit Block cipher with 128/192/256-bit keys
45. RFC 4493: Cipher-based Message Authentication Code (CMAC)
46. RFC 4503: Rabbit Stream Cipher Algorithm with 128-bit key
47. RFC 4543: Galois Message Authentication Code (GMAC)
48. RFC 4764: EAX Authenticated-Encryption Mode of Operation
49. RFC 5246: Transport Layer Security (TLS) Protocol Version 1.2
50. RFC 5280: Internet X.509 PKI Certificate Revocation List (CRL)
51. RFC 5869: HMAC-based Key Derivation Function (HKDF)
52. RFC 6114: The 128-Bit Blockcipher CLEFIA (Sony)
53. RFC 7008: KCipher-2 Encryption Algorithm (KDDI R&D Laboratories)
54. RFC 7253: OCB (and PMAC) Authenticated-Encryption Algorithm
55. RFC 7292: PKCS #12 Personal Information Exchange Syntax v1.1
56. RFC 7539: ChaCha20-Poly1305 AEAD Stream cipher
57. RFC 7693: The BLAKE2 Cryptographic Hash and MAC (JP Aumasson)
58. RFC 7748: Curve25519 and Curve448: Elliptic Curves for Security
59. RFC 7914: The Scrypt Password-Based Key Derivation Function
60. RFC 8032: Ed25519 Signature a.k.a. EdDSA (Daniel J. Bernstein)
61. RFC 8446: Transport Layer Security (TLS) Protocol Version 1.3
62. RFC 9058: MGM AEAD mode for 64 and 128 bit ciphers (E. Griboedova)
63. RFC 9367: GOST Cipher Suites for Transport Layer Security (TLS 1.3)
64. SBRC 2007: Curupira 96-bit block cipher with 96/144/192-bit keys
65. TTAS.KO-12.0004/R1 128-bit Block Cipher SEED (ISO/IEC 18033-3:2010)
66. TTAS.KO-12.0040/R1 64-bit Block Cipher HIGHT (ISO/IEC 18033-3:2010)
67. TTAS.KO-12.0011/R2 HAS-160 Korean-standardized hash algorithm
68. TTAK.KO-12.0223 LEA 128-bit block cipher (ISO/IEC 29192-2:2019)
69. TTAK.KO-12.0276 LSH Message digest algorithm (KS X 3262)
70. US FIPS 197 Advanced Encryption Standard (AES)
71. US FIPS 180-2 Secure Hash Standard (SHS) SHA1 and SHA2 Algorithms
72. US FIPS 202 SHA-3 Permutation-Based Hash (instance of the Keccak)

</details>

## Command-line Integrated Security Suite

### Asymmetric

- **Public key algorithms:**  

    |  Algorithm          | 256 | 512 |ECDH |Sign |Encryption| TLS |
    |:--------------------|:---:|:---:|:---:|:---:|:--------:|:---:|
    | ECDSA               | O   | O   | O   | O   | O        | O   |
    | ECGDSA              | O   | O   |     | O   |          |     |
    | EC-KCDSA            | O   | O   |     | O   |          |     |
    | Curve25519          | O   |     | O   | O   |          | O   |
    | Curve448            |     |     | O   | O   |          |     |
    | GOST2012            | O   | O   | O   | O   |          | O   |
    | RSA                 |     |     |     | O   | O        | O   |
    | SM2                 | O   |     | O   | O   | O        | O   |
    | SM9                 | O   |     | O   | O   | O        |     |
    | NUMS                | O   | O   | O   | O   | O        |     |
    | CRYSTALS            |     |     |     | O   | O        |     |
    | ElGamal             |     |     |     | O   | O        |     |
    | EC-ElGamal          | O   |     |     |     | O        |     |
    | SPHINCS+            | O   |     |     | O   |          |     |

- **Supported ParamSets:**

    |  Algorithm          |  A  |  B  |  C  |  D  |
    |:--------------------|:---:|:---:|:---:|:---:|
    | GOST R 34.10-2012 256-bit | O   | O   | O   | O   |
    | GOST R 34.10-2012 512-bit | O   | O   | O   |     |

### Symmetric

- **Stream ciphers:**

    |      Cipher      |  Key Size  |  IV  |         Modes         |
    |:-----------------|:----------:|:----:|:---------------------:|
    | Chacha20Poly1305 | 256        | 96/192 | AEAD Stream Cipher  |
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

- **Experimental:**

    |     Cipher    |  Key |  IV  |         Mode          |
    |:--------------|:----:|:----:|:---------------------:|
    | Xoodyak       |  128 |  128 |Lightweight AEAD Permutation Cipher|
    | Ascon 1.2     |  128 |  128 |NIST Lightweight AEAD Stream Cipher|
    | Grain128a     |  128 |40-96 |NIST Lightweight AEAD Stream Cipher|

- **256-bit> block ciphers:**

    |      Cipher      | Block Size |  Key Size   |          Modes          |
    |:-----------------|:----------:|:-----------:|:-----------------------:|
    | Kalyna256        |        256 |     256/512 | EAX, SIV, CTR, OFB, IGE |
    | Kalyna512        |        512 |         512 | EAX, SIV, CTR, OFB, IGE |
    | Threefish256     |        256 |         256 | EAX, SIV, CTR, OFB, IGE |
    | Threefish512     |        512 |         512 | EAX, SIV, CTR, OFB, IGE |
    | Threefish1024    |       1024 |        1024 | EAX, SIV, CTR, OFB, IGE |
  
- **128-bit block ciphers:**

    |      Cipher      | Block Size |  Key Size   |         Modes           |
    |:-----------------|:----------:|:-----------:|:-----------------------:|
    | AES (Rijndael)   |        128 | 128/192/256 | All modes supported     |
    | Anubis           |        128 |  128 to 320 | All modes supported     |
    | ARIA             |        128 | 128/192/256 | All modes supported     |
    | Camellia         |        128 | 128/192/256 | All modes supported     |
    | CAST256          |        128 | 128/192/256 | All modes supported     |
    | CLEFIA           |        128 | 128/192/256 | All modes supported     |
    | CRYPTON          |        128 | 128/192/256 | All modes supported     |
    | E2               |        128 | 128/192/256 | All modes supported     |
    | Kalyna128        |        128 |     128/256 | All modes supported     |
    | Kuznechik        |        128 |         256 | All modes supported     |
    | LEA              |        128 | 128/192/256 | All modes supported     |
    | LOKI97           |        128 | 128/192/256 | All modes supported     |
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
    | HAS-160         |     | O   |     |     |     |     |
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
  <summary>AEAD OpenSSL-PHP compliance</summary>
  
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
</details>

### Curupira

Curupira is a 96-bit block cipher, with keys of 96, 144 or 192 bits, and variable number of rounds, an algorithm described at SBRC 2007 by Paulo S. L. M. Barreto and Marcos A. Simplício Jr.

$$
\text{Curupira}[K] \equiv \sigma[\kappa(R)] \circ \pi \circ \gamma \circ \left( \prod_{r=1}^{R-1} \sigma[\kappa(r)] \circ \theta \circ \pi \circ \gamma \right) \circ \sigma[\kappa(0)]
$$

### Digital Signature Algorithms

Here are the main differences between ECDSA, ECGDSA, and ECKCDSA:

$\text{ECDSA: Compute } r = x([k]B); \text{ s must be a root of } H(m)s^{-1} + rs^{-1}a - k \text{ modulo } n,$
$\text{ so compute } s \equiv k^{-1} \left( H(m) + ra \right) \pmod{n}.$

$\text{ECGDSA: Compute } r = x([k]B); \text{ s must be a root of } r^{-1}H(m) + r^{-1}sa - k \text{ modulo } n,$
$\text{ so compute } s \equiv a^{-1} \left( kr - H(m) \right) \pmod{n}.$

$\text{ECKCDSA: Compute } r = H(x([k]B)); \text{ s must be a root of } r \oplus H(m,h) + sa - k \text{ modulo } n,$
$\text{ so compute } s \equiv a^{-1} \left( k - r \oplus H(m,h) \right) \pmod{n}.$

### ElGamal
The ElGamal algorithm is a public-key cryptography system that enables secure communication between two parties, involving asymmetric keypair generation and cryptographic operations. Initially, a large prime number $p$ and a generator $g$ for a finite cyclic group are generated. Each entity possesses a private key $x$, kept secret, and a public key $Y$, derived from $g^x \mod p$. To encrypt a symmetric key, the sender uses the session key, computes two components \(a\) and \(b\), and sends $g^k \mod p$ and $Y^k \cdot \text{key} \mod p$ to the recipient. The recipient, using their private key, decrypts the symmetric key. The ElGamal algorithm is known for its security based on the difficulty of solving the discrete logarithm problem and provides confidentiality and authentication properties.

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
The EC-ElGamal algorithm is a cryptographic scheme based on elliptic curves that enables the encryption of messages between two parties using a shared public key. Initially, each party generates its private key as a random number $x$ and computes its corresponding public key $Q = x \cdot G$, where $G$ is a base point on the elliptic curve. To encrypt a message $M$, the sender selects a random value $r$ and computes $t = r \cdot Q$ and $C2 = M \cdot H + r \cdot Q$, where $H$ is another point on the elliptic curve. These values are then combined to form the additional authentication data (AAD), which is used along with the message for symmetric encryption. A nonce value is also generated to ensure randomness in the cipher. The receiver uses their private key $x$ to derive $t = x \cdot C1$ and from it, the symmetric key used to decrypt the message. The algorithm also includes a zero-knowledge proof (ZKP) mechanism based on Schnorr, allowing the receiver to verify the authenticity of the received message without revealing their private key.

<details>
  <summary>EC-ElGamal Theory</summary>    

We initially create a private key as a random number $x$ and a public key of:  

$Q = x \cdot G$

With standard ElGamal encryption, we generate a random value $r$ to give:

$t = r \cdot Q$

We then create a symmetric key from this elliptic curve point:

$AEADKey = \text{Derive}(t)$

and where $\text{Derive}$ just converts a point on the curve to a byte array value that is the length of the required symmetric encryption key (such as for 32 bytes in the case of 256-bit Anubis).

Next, we compute the ciphertext values of:

$C1 = r \cdot G$  
$C2 = M \cdot H + r \cdot Q$

and where $M$ is the $msg$ value converted into a scalar value. We then append these together to create the additional data that will be used for the symmetric key encryption of the message:

$AAD = C1 || C2$

We then generate a nonce value ($\text{Nonce}$) and then perform symmetric key encryption on the message:

$cipher = \text{EncAEADKey}(\text{msg}, \text{Nonce}, \text{AAD})$

The ciphertext then has values of $C1$, $C2$, $\text{Nonce}$, and $\text{cipher}$. $C1$, $C2$ are points on the curve, and the $\text{Nonce}$ value and $\text{cipher}$ are byte array values. To decrypt, we take the private key ($x$) and derive:

$t = x \cdot C1$  
$AEADKey = \text{Derive}(t)$  
$AAD = C1 || C2$  
$msg = \text{DecAEADKey}(\text{cipher}, \text{Nonce}, \text{AAD})$

Here is an overview of the method:

To generate the proof, we generate a random value ($r$) and a blinding factor ($b$) to give two points on the elliptic curve:

$R1 = r \cdot G$  
$R2 = r \cdot Q + b \cdot H$

Next, we create the challenge bytes with:

$chall = C1 || C2 || R1 || R2 || \text{Nonce}$

We take this value and hash it ($H$()), and create a scalar value with ($ek$) to produce:

$c = H(\text{chall}) \cdot ek$

We then create two Schnorr proof values:

$S1 = b - c \cdot m$  
$S2 = r - c \cdot b$

To verify the proof, we reconstruct $R1$:

$R1 = c \cdot C1 + S2 \cdot G$

We reconstruct $R2$:

$R2 = c \cdot C2 + S1 \cdot Q + S1 \cdot H$

This works because:

$R2 = c \cdot C2 + S1 \cdot Q + S1 \cdot H$  
$\quad = c \cdot (b \cdot Q + m \cdot H) + (r - cb) \cdot Q + (b - cm) \cdot H$  
$\quad = (cb + r - cb) \cdot Q + (cm + b - cm) \cdot H$  
$\quad = r \cdot Q + b \cdot H$

We then reconstruct the challenge with:

$chall = C1 || C2 || R1 || R2 || \text{Nonce}$

We take this value and hash it ($H$()), and create a scalar value with ($ek$) to produce:

$c = H(\text{chall}) \cdot ek$

This value is then checked against the challenge in the proof, and if they are the same, the proof is verified.
</details>

### GOST (GOvernment STandard of Russian Federation)
GOST refers to a set of technical standards maintained by the Euro-Asian Council for Standardization, Metrology and Certification (EASC), a regional standards organization operating under the auspices of the Commonwealth of Independent States (CIS).

### Key sizes
- **Bit-length Equivalence**

    | Symmetric Key Size  | RSA and DSA Key Size  | ECC Key Size   | 
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

### MAC
MAC (Message Authentication Code) is a cryptographic function used to ensure the integrity and authenticity of a message. It takes a message and a secret key as inputs and produces a fixed-size authentication tag, which is appended to the message. The receiver can then verify the authenticity of the message by recomputing the MAC using the shared secret key and comparing it to the received tag. If they match, the message is deemed authentic and unaltered.

### NUMS

These curves are elliptic curves over a prime field, just like the NIST or Brainpool curves. However, the domain-parameters are choosen using a VERY TIGHT DESIGN SPACE to ensure, that the introduction of a backdoor is infeasable. For a desired size of s bits the prime p is choosen as p = 2^s - c with the smallest c where c>0 and p mod 4 = 3 and p being prime.

**Microsoft Nothing Up My Sleeve Elliptic curves**  
[NUMS](http://www.watersprings.org/pub/id/draft-black-numscurves-01.html) (Nothing Up My Sleeve) curves, which are supported in the MSRElliptic Curve Cryptography Library (a.k.a. MSR ECCLib).

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

### ShangMi (SM) National secret SM2/SM3/SM4 algorithms
SM2 is a public key cryptographic algorithm based on elliptic curves, used for e.g. generation and verification of digital signatures; SM3, a hashing algorithm comparable to SHA-256; and SM4, a block cipher algorithm for symmetric cryptography comparable to AES-128. These standards are becoming widely used in Chinese commercial applications such as banking and telecommunications and are sometimes made mandatory for products procured by Chinese government agencies. SM4 is part of the ARMv8.4-A expansion to the ARM architecture.

### XOR
XOR (Exclusive OR) is a logical operator that works on bits. Let’s denote it by ^. If the two bits it takes as input are the same, the result is 0, otherwise it is 1. This implements an exclusive or operation, i.e. exactly one argument has to be 1 for the final result to be 1. We can show this using a truth table:

- **exclusive or**

    |x    |y    | x^y |
    |:---:|:---:|:---:|
    |0    |0    |0    |
    |0    |1    |1    |
    |1    |0    |1    |
    |1    |1    |0    |

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
   * Privacy-Enhanced Mail (PEM format)
   * RandomArt (OpenSSH-like)

## Usage
<pre>Usage of ./edgetk:
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
  -cacert string
    	CA Certificate path. (for TLCP Protocol)
  -cakey string
    	CA Private key. (for TLCP Protocol)
  -cert string
    	Certificate path.
  -check
    	Check hashsum file. ('-' for STDIN)
  -cipher string
    	Symmetric algorithm: aes, blowfish, magma or sm4. (default "aes")
  -crl string
    	Certificate Revocation List path.
  -crypt string
    	Bulk Encryption with Stream and Block ciphers. [enc|dec|help]
  -curve string
    	Subjacent curve (ECDSA, BLS12381G1 and G2.) (default "ecdsa")
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
  -rand int
    	Generate random cryptographic key with given bit length.
  -recover
    	Recover Passphrase from Makwa hash with Private Parameters.
  -recursive
    	Process directories recursively. (for DIGEST command only)
  -root string
    	Root CA Certificate path.
  -salt string
    	Salt. (for HKDF and PBKDF2 commands)
  -signature string
    	Input signature. (for VERIFY command and MAC verification)
  -subj string
    	Subject: Identity for which a digital certificate.
  -tcp string
    	Encrypted TCP/IP Transfer Protocol. [server|ip|client]
  -tweak string
    	Additional 128-bit parameter input. (for THREEFISH encryption)
  -version
    	Print version info.
  -wrap int
    	Wrap lines after N columns. (for Base64/32 encoding) (default 64)</pre>

## Examples

#### Asymmetric EG keypair generation:
```sh
./edgetk -pkey setup -algorithm elgamal [-bits 4096] > ElGamalParams.pem
./edgetk -pkey keygen -algorithm elgamal -params ElGamalParams.pem [-pass "passphrase"] [-prv Private.pem] [-pub Public.pem]
```
#### EG Digital signature:
```sh
./edgetk -pkey sign -algorithm elgamal -key private.pem [-pass "passphrase"] < file.ext > sign.txt
sign=$(cat sign.txt|awk '{print $2}')
./edgetk -pkey verify -algorithm elgamal -key public.pem -signature $sign < file.ext
echo $?
```
#### EG Encryption scheme:
```sh
./edgetk -pkey wrapkey -algorithm elgamal -key public.pem > cipher.txt
ciphertext=$(cat cipher.txt|grep "Cipher"|awk '{print $2}')
./edgetk -pkey unwrapkey -algorithm elgamal -key private.pem [-pass "passphrase"] -cipher $ciphertext
```
#### Asymmetric RSA keypair generation:
```sh
./edgetk -pkey keygen -bits 4096 [-pass "passphrase"] [-prv Private.pem] [-pub Public.pem]
```
#### Parse keys info:
```sh
./edgetk -pkey [text|modulus] [-pass "passphrase"] -key private.pem
./edgetk -pkey [text|modulus|randomart|fingerprint] -key public.pem
```
#### Digital signature:
```sh
./edgetk -pkey sign -key private.pem [-pass "passphrase"] < file.ext > sign.txt
sign=$(cat sign.txt|awk '{print $2}')
./edgetk -pkey verify -key public.pem -signature $sign < file.ext
echo $?
```
#### Encryption/decryption with RSA algorithm:
```sh
./edgetk -pkey encrypt -key public.pem < plaintext.ext > ciphertext.ext
./edgetk -pkey decrypt -key private.pem < ciphertext.ext > plaintext.ext
```
#### Asymmetric EC keypair generation (256-bit):
```sh
./edgetk -pkey keygen -bits 256 -algorithm EC [-pass "passphrase"]
```
#### EC Diffie-Hellman:
```sh
./edgetk -pkey derive -algorithm EC -key private.pem -pub peerkey.pem
```
#### Generate Self Signed Certificate:
```sh
./edgetk -pkey certgen -key private.pem [-pass "passphrase"] [-cert "output.crt"]
```
#### Generate Certificate Signing Request:
```sh
./edgetk -pkey req -key private.pem [-pass "passphrase"] [-cert certificate.csr]
```
#### Sign CSR with CA Certificate:
```sh
./edgetk -pkey x509 -key private.pem -root cacert.pem -cert cert.csr > cert.crt
```
#### Parse Certificate info:
```sh
./edgetk -pkey [text|modulus] -cert certificate.pem
```
#### Generate Certificate Revocation List:
```sh
./edgetk -pkey crl -cert cacert.pem -key private.pem -crl old.crl serials.txt > NewCRL.crl
```
#### TLS Layer (TCP/IP):
```sh
./edgetk -tcp ip > MyExternalIP.txt
./edgetk -tcp server -cert certificate.pem -key private.pem [-ipport "8081"]
./edgetk -tcp client -cert certificate.pem -key private.pem [-ipport "127.0.0.1:8081"]
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

#### SM9 (Chinese IBE Standard)
##### Private Key Generation:

- Generate a master key
```sh
./edgetk -pkey setup -algorithm [sm9encrypt|sm9sign] [-master "Master.pem"] [-pub "Public.pem"]
```
- Generate a private key and a UID (User ID) and an HID (Hierarchy ID).
```sh
./edgetk -pkey keygen -algorithm [sm9encrypt|sm9sign] [-master "Master.pem"] [-prv "Private.pem"] [-id "uid"] [-hid 1]
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

- [Sergey Matveev](http://www.cypherpunks.ru/) (GoGOST Library Author)
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

#### Copyright (c) 2020-2024 Pedro F. Albanese - ALBANESE Research Lab.
