# EDGE Toolkit
[![ISC License](http://img.shields.io/badge/license-ISC-blue.svg)](https://github.com/pedroalbanese/edgetk/blob/master/LICENSE.md) 
[![GoDoc](https://godoc.org/github.com/pedroalbanese/edgetk?status.png)](http://godoc.org/github.com/pedroalbanese/edgetk)
[![GitHub downloads](https://img.shields.io/github/downloads/pedroalbanese/edgetk/total.svg?logo=github&logoColor=white)](https://github.com/pedroalbanese/edgetk/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/pedroalbanese/edgetk)](https://goreportcard.com/report/github.com/pedroalbanese/edgetk)
[![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/pedroalbanese/edgetk)](https://golang.org)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/pedroalbanese/edgetk)](https://github.com/pedroalbanese/edgetk/releases)

Multi-purpose cross-platform hybrid cryptography tool for symmetric and asymmetric encryption, cipher-based message authentication code (CMAC/PMAC/GMAC/VMAC), recursive hash digest, hash-based message authentication code (HMAC), HMAC-based key derivation function (HKDF), password-based key derivation function (PBKDF2/Argon2/Scrypt), password-hashing scheme (Bcrypt/Argon2/Makwa), shared key agreement (ECDH/VKO/X25519), digital signature (RSA/ECDSA/EdDSA/GOST/SPHINCS+), X.509 CSRs, CRLs and Certificates, and TCP instant server with TLS 1.3 and TLCP encryption layers for small or embedded systems. 

***Fully OpenSSL/LibreSSL/GmSSL/RHash/Mcrypt compliant***
## Command-line Integrated Security Suite

### Asymmetric

- **Public key algorithms:**  

    |  Algorithm          | 256 | 512 |ECDH |Sign |Encryption| TLS |
    |:--------------------|:---:|:---:|:---:|:---:|:--------:|:---:|
    | ECDSA               | O   | O   | O   | O   | O        | O   |
    | Ed25519             | O   |     | O   | O   |          | O   |
    | GOST2012            | O   | O   | O   | O   |          | O   |
    | RSA                 |     |     |     | O   | O        | O   |
    | SM2                 | O   |     | O   | O   | O        | O   |
    | SPHINCS+            |     | O   |     | O   |          |     |

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
    | Skein512         | 256        |  256 | MAC + XOR Stream      |
    | ZUC-128 Zu Chongzhi | 128     |  128 | MAC + XOR Stream      |
    | ZUC-256 Zu Chongzhi | 256     |  184 | MAC + XOR Stream      |

- **Experimental:**

    |     Cipher    |  Key |  IV  |         Mode          |
    |:--------------|:----:|:----:|:---------------------:|
    | Xoodyak       |  128 |  128 |Lightweight AEAD Permutation Cipher|
    | Ascon 1.2     |  128 |  128 |NIST Lightweight AEAD Stream Cipher|
    | Grain128a     |  128 |40-96 |NIST Lightweight AEAD Stream Cipher|

- **256-bit> block ciphers:**

    |      Cipher      | Block Size |  Key Size   |          Modes           |
    |:-----------------|:----------:|:-----------:|:------------------------:|
    | Threefish256     |        256 |         256 | CBC, CFB8, CTR, OFB, IGE |
    | Threefish512     |        512 |         512 | CBC, CFB8, CTR, OFB, IGE |
    | Threefish1024    |       1024 |        1024 | CBC, CFB8, CTR, OFB, IGE |
  
- **128-bit block ciphers:**

    |      Cipher      | Block Size |  Key Size   |         Modes           |
    |:-----------------|:----------:|:-----------:|:-----------------------:|
    | AES (Rijndael)   |        128 | 128/192/256 | All modes supported     |
    | Anubis           |        128 |  128 to 320 | All modes supported     |
    | ARIA             |        128 | 128/192/256 | All modes supported     |
    | Camellia         |        128 | 128/192/256 | All modes supported     |
    | Kuznechik        |        128 |         256 | All modes supported     |
    | LEA              |        128 | 128/192/256 | All modes supported     |
    | SEED             |        128 |         128 | All modes supported     |
    | Serpent          |        128 | 128/192/256 | All modes supported     |
    | SM4              |        128 |         128 | All modes supported     |
    | Twofish          |        128 | 128/192/256 | All modes supported     |
   
- **64-bit block ciphers:**


    |      Cipher      | Block Size |  Key Size    |    Modes    |
    |:-----------------|:----------:|:------------:|:-----------:|
    | DES [Obsolete]   |          64|            64|CBC, CFB-8, CTR, OFB|
    | 3DES [Obsolete]  |          64|           192|CBC, CFB-8, CTR, OFB|
    | Blowfish         |          64|           128|CBC, CFB-8, CTR, OFB|
    | CAST5            |          64|           128|CBC, CFB-8, CTR, OFB|
    | GOST89 (TC26)    |          64|           256|MGM, CFB-8, CTR, OFB|
    | HIGHT            |          64|           128|CBC, CFB-8, CTR, OFB|
    | IDEA [Obsolete]  |          64|           128|CBC, CFB-8, CTR, OFB|
    | Magma            |          64|           256|MGM, CFB-8, CTR, OFB|
    | MISTY1           |          64|           128|CBC, CFB-8, CTR, OFB|
    | RC2 [Obsolete]   |          64|           128|CBC, CFB-8, CTR, OFB|
    | RC5 [Obsolete]   |          64|           128|CBC, CFB-8, CTR, OFB|

- **Modes of Operation:**

    |Mode |                                | Blocks     |  Keys     |
    |:---:|:-------------------------------|:----------:|:---------:|
    | EAX | Encrypt-Authenticate-Translate |128         |128/192/256|
    | GCM | Galois/Counter Mode (AEAD)     |128         |128/192/256|
    | OCB1| Offset Codebook v1 (AEAD)      |128         |128/192/256|
    | OCB3| Offset Codebook v3 (AEAD)      |128         |128/192/256|
    | MGM | Multilinear Galois Mode (AEAD) |64/128      |Any        |
    | CCM | Counter with CBC-MAC (AEAD)    |128         |128/192/256|
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
    | BLAKE-3         |     |     |     | O   |     |     |
    | Chaskey         | O   |     |     |     |     | O   |
    | Cubehash        |     |     |     |     | O   |     |
    | GOST94 CryptoPro      |     |     |     | O   |     |     |
    | Grøstl          |     |     |     | O   |     |     |
    | HAS-160         |     | O   |     |     |     |     |
    | JH              |     |     |     | O   |     |     |
    | Legacy Keccak   |     |     |     | O   | O   |     |
    | LSH             |     |     |     | O   | O   |     |
    | MD4 [Obsolete]  | O   |     |     |     |     |     |
    | MD5 [Obsolete]  | O   |     |     |     |     |     |
    | Poly1305        | O   |     |     |     |     | O   |
    | RIPEMD          | O   | O   |     | O   |     |     |
    | SHA1 [Obsolete] |     | O   |     |     |     |     |
    | SHA2 (default)  |     |     |     | O   | O   |     | 
    | SHA3            |     |     |     | O   | O   |     |
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

### IKM (input key material value)
Keying material is in general to include things like shared Diffie-Hellman secrets (which are not suitable as symmetric keys), which have more structure than normal keys.

### MAC
MAC (Message Authentication Code) is a cryptographic function used to ensure the integrity and authenticity of a message. It takes a message and a secret key as inputs and produces a fixed-size authentication tag, which is appended to the message. The receiver can then verify the authenticity of the message by recomputing the MAC using the shared secret key and comparing it to the received tag. If they match, the message is deemed authentic and unaltered.

### PBKDF2
PBKDF2 (Password-Based Key Derivation Function 2) is a widely used cryptographic function designed to derive secure cryptographic keys from weak passwords or passphrases. It applies a pseudorandom function, such as HMAC-SHA1, HMAC-SHA256, or HMAC-SHA512, multiple times in a loop, with a salt and a user-defined number of iterations, effectively increasing the computational cost of key generation. This technique enhances the resilience against brute-force attacks, making it more difficult and time-consuming for attackers to obtain the original password from the derived key.

### Post-Quantum Cryptography (PQC)

- **Security Level**

    |Name           | Function      |pre-quantum    | post-quantum   |
    |:-------------:|:-------------:|:-------------:|:--------------:|
    |AES-128        | block cipher  | 128           | 64 (Grover)    |
    |AES-256        | block cipher  | 256           | 128 (Grover)   |
    |Salsa20        | stream cipher | 256           | 128 (Grover)   |
    |GMAC           | MAC           | 128           | 128 (no impact)|
    |Poly1305       | MAC           | 128           | 128 (no impact)|
    |SHA-256        | hash function | 256           | 128 (Grover)   |
    |SHA-3          | hash function | 256           | 128 (Grover)   |
    |RSA-3072       | encryption    | 128           | broken (Shor)  |
    |RSA-3072       | signature     | 128           | broken (Shor)  |
    |DH-3072        | key exchange  | 128           | broken (Shor)  |
    |DSA-3072       | signature     | 128           | broken (Shor)  |
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
   * GMAC (Galois message authentication code)
   * PMAC (Parallelizable message authentication code)
   * VMAC (Variable message authentication code)
   * HMAC (Hash-based message authentication code)
   * HKDF (HMAC-based key derivation function)
   * PBKDF2 (Password-based key derivation function)
   * Scrypt (Password-based key derivation function)
   * Bcrypt (Password-hashing scheme)
   * Makwa (Password-hashing scheme)
   * Argon2 (Password-hashing scheme and KDF)
   * TLS (Transport Layer Security v1.2 and 1.3)
   * TLCP (Transport Layer Cryptography Protocol v1.1)
   * PKCS12 (Personal Information Exchange Syntax v1.1)
   * X.509 CSRs, CRLs and Certificates
  
* **Non-cryptographic Functions:**

   * Hex string encoder/dump/decoder (xxd-like)
   * Privacy-Enhanced Mail (PEM format)
   * RandomArt (OpenSSH-like)

## Usage
<pre> -algorithm string
       Public key algorithm: EC, Ed25519, GOST2012, SM2. (default "RSA")
 -bits int
       Key length. (for keypair generation and symmetric encryption)
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
 -digest
       Target file/wildcard to generate hashsum list. ('-' for STDIN)
 -hex string
       Encode binary string to hex format and vice-versa. [enc|dump|dec]
 -info string
       Additional info. (for HKDF command and AEAD bulk encryption)
 -ipport string
       Local Port/remote's side Public IP:Port.
 -iter int
       Iter. (for Password-based key derivation function) (default 1)
 -iv string
       Initialization Vector. (for symmetric encryption)
 -kdf string
       Key derivation function. [pbkdf2|hkdf|scrypt]
 -key string
       Asymmetric key, symmetric key or HMAC key, depending on operation.
 -mac string
       Compute Hash/Cipher-based message authentication code.
 -md string
       Hash algorithm: sha256, sha3-256 or whirlpool. (default "sha256")
 -mode string
       Mode of operation: GCM, MGM, CBC, CFB8, OCB, OFB. (default "CTR")
 -paramset string
       Elliptic curve ParamSet: A, B, C, D. (for GOST2012) (default "A")
 -pkey string
       Subcommands: keygen|certgen, sign|verify|derive, text|modulus.
 -priv string
       Private key path. (for keypair generation) (default "Private.pem")
 -pub string
       Public key path. (for keypair generation) (default "Public.pem")
 -pwd string
       Password. (for Private key PEM encryption)
 -rand int
       Generate random cryptographic key with given bit length.
 -recursive
       Process directories recursively. (for DIGEST command only)
 -root string
       Root CA Certificate path.
 -salt string
       Salt. (for HKDF and PBKDF2 commands)
 -signature string
       Input signature. (for VERIFY command and MAC verification)
 -tcp string
       Encrypted TCP/IP Transfer Protocol. [server|ip|client]</pre>

## Examples

#### Asymmetric RSA keypair generation:
```sh
./edgetk -pkey keygen -bits 4096 [-pwd "pass"] [-priv Private.pem] [-pub Public.pem]
```
#### Parse keys info:
```sh
./edgetk -pkey [text|modulus] [-pwd "pass"] -key private.pem
./edgetk -pkey [text|modulus|randomart|fingerprint] -key public.pem
```
#### Digital signature:
```sh
./edgetk -pkey sign -key private.pem [-pwd "pass"] < file.ext > sign.txt
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
./edgetk -pkey keygen -bits 256 -algorithm EC [-pwd "pass"]
```
#### EC Diffie-Hellman:
```sh
./edgetk -pkey derive -algorithm EC -key private.pem -pub peerkey.pem
```
#### Generate Self Signed Certificate:
```sh
./edgetk -pkey certgen -key private.pem [-pwd "pass"] [-cert "output.crt"]
```
#### Generate Certificate Signing Request:
```sh
./edgetk -pkey req -key private.pem [-pwd "pass"] [-cert certificate.csr]
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
#### Hex Encoder/Decoder:
```sh
./edgetk -hex enc < file.ext > file.hex
./edgetk -hex dec < file.hex > file.ext
./edgetk -hex dump < file.ext
```
#### Try:
```
./edgetk -crypt help   // Describes bulk encryption usage and arguments
./edgetk -kdf help     // Describes key derivation function usage
./edgetk -mac help     // Describes message authentication code usage
./edgetk -pkey help    // Describes public key cryptography usage
./edgetk -tcp help     // Describes TLS 1.3 Protocol parameters and usage
./edgetk -help,-h      // Full list of the flags and their defaults
```

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

#### Copyright (c) 2020-2023 Pedro F. Albanese - ALBANESE Research Lab.
