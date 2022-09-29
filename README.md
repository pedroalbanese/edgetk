# EDGE Toolkit
[![ISC License](http://img.shields.io/badge/license-ISC-blue.svg)](https://github.com/pedroalbanese/edgetk/blob/master/LICENSE.md) 
[![GoDoc](https://godoc.org/github.com/pedroalbanese/edgetk?status.png)](http://godoc.org/github.com/pedroalbanese/edgetk)
[![GitHub downloads](https://img.shields.io/github/downloads/pedroalbanese/edgetk/total.svg?logo=github&logoColor=white)](https://github.com/pedroalbanese/edgetk/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/pedroalbanese/edgetk)](https://goreportcard.com/report/github.com/pedroalbanese/edgetk)
[![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/pedroalbanese/edgetk)](https://golang.org)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/pedroalbanese/edgetk)](https://github.com/pedroalbanese/edgetk/releases)

Multi-purpose cross-platform cryptography tool for symmetric and asymmetric encryption, recursive hash digest, hash-based message authentication code (HMAC), HMAC-based key derivation function (HKDF), Password-based key derivation function (PBKDF2), shared key agreement (ECDH), digital signature (RSA/ECDSA) and TLS 1.2 for small or embedded systems. 

***Fully OpenSSL compliant***

## Command-line Security Suite

### Asymmetric
* ECDSA 224/256/384/521-bit
* Ed25519 (256-bit)
* RSA Cryptosystem
* SM2 (256-bit)

### Symmetric

- **Stream ciphers:**
   - Chacha20 (256-bit)
   - RC4 128-bit [Obsolete]
   
- **128-bit block ciphers:**
   - AES (Rijndael) 128/192/256-bit (Default)
   - ARIA 128/192/256-bit
   - Camellia 128/192/256-bit
   - Grasshopper (256-bit)
   - SEED 128-bit
   - SM4 (128-bit)
   
- **64-bit block ciphers:**
   - DES (64-bit) [Obsolete]
   - 3DES (192-bit) [Almost Obsolete]
   - Blowfish 128-bit
   - CAST5 (128-bit)
   - GOST89 (256-bit)
   - IDEA (128-bit) [Obsolete]
   - Magma (256-bit)
   - RC2 (128-bit) [Obsolete]
   - RC5 (128-bit) [Obsolete]

- **Modes of Operation:**
   - CFB8: Cipher Feedback 8-bit
   - CFB: Cipher Feedback
   - CTR: Counter Mode (a.k.a. CNT)
   - OFB: Output Feedback
   
- **Message Digest Algorithms:**
   - BLAKE-2B 512-bit
   - BLAKE-2S 256-bit
   - GOST94 (256-bit)
   - MD4 (128-bit) [Obsolete]
   - MD5 (128-bit) [Obsolete]
   - RIPEMD (160-bit)
   - SHA1 (160-bit) [Obsolete]
   - SHA2 224/256/384/512-bit (default) 
   - SHA3 224/256/384/512-bit
   - SM3 (256-bit)
   - Streebog 256/512-bit
   - Whirlpool (512-bit)

- **Message Authentication Code Algorithms:**
   - Poly1305 (128-bit)
   
## Features
* **Cryptographic Functions:**

   * Asymmetric Encryption
   * Symmetric Encryption
   * Digital Signature
   * Recursive Hash Digest + Check
   * ECDH (Shared Key Agreement)
   * CMAC (Cipher-based message authentication code)
   * HMAC (Hash-based message authentication code)
   * HKDF (HMAC-based key derivation function)
   * PBKDF2 (Password-based key derivation function)
   * TLS 1.2 (Transport Layer Security)
   
* **Non-cryptographic Functions:**

   * Hex string encoder/dump/decoder (as xxd)
   * RandomArt (as OpenSSH)

## Usage
<pre> -algorithm string
       Public key algorithm: RSA, EC (ECDSA) or SM2. (default "RSA")
 -bits int
       Key length. (for keypair generation and symmetric encryption)
 -cert string
       Certificate path. (default "Certificate.pem")
 -check string
       Check hashsum file. ('-' for STDIN)
 -cipher string
       Symmetric algorithm: aes, blowfish, magma or sm4. (default "aes")
 -crypt string
       Encrypt/Decrypt with block ciphers.
 -digest string
       Target file/wildcard to generate hashsum list. ('-' for STDIN)
 -hex string
       Encode binary string to hex format and vice-versa. [enc|dec]
 -hkdf int
       HMAC-based key derivation function with given bit length.
 -info string
       Additional info. (for HKDF command)
 -ipport string
       Local Port/remote's side Public IP:Port.
 -iter int
       Iter. (for Password-based key derivation function) (default 1)
 -iv string
       Initialization Vector. (for symmetric encryption)
 -key string
       Asymmetric key, symmetric key or HMAC key, depending on operation.
 -mac string
       Compute Hash-based message authentication code.
 -md string
       Hash algorithm: sha256, sha3-256 or whirlpool. (default "sha256")
 -mode string
       Mode of operation: CFB8, CFB, CTR or OFB. (default "CTR")
 -pbkdf2
       Password-based key derivation function.
 -pkey string
       Generate keypair, Sign/Verify with RSA/ECDSA keypair.
 -private string
       Private key path. (for keypair generation) (default "Private.pem")
 -public string
       Public key path. (for keypair generation) (default "Public.pem")
 -pwd string
       Password. (for Private key PEM encryption)
 -rand int
       Generate random cryptographic key with given bit length.
 -recursive
       Process directories recursively. (for DIGEST command only)
 -salt string
       Salt. (for KDF only)
 -signature string
       Input signature. (verification only)
 -tcp string
       Encrypted TCP/IP Transfer Protocol. [server|ip|client]</pre>

## Examples
#### Asymmetric RSA keypair generation:
```sh
./edgetk -pkey keygen -bits 4096 [-pwd "pass"]
```
#### Asymmetric EC keypair generation (256-bit):
```sh
./edgetk -pkey keygen -bits 256 -algorithm EC [-pwd "pass"]
```
#### Parse keys info:
```sh
./edgetk -pkey [text|modulus] [-pwd "pass"] -key private.pem
./edgetk -pkey [text|modulus] -key public.pem
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
#### Generate Certificate:
```sh
./edgetk -pkey certgen -key private.pem [-pwd "pass"] [-cert "output.ext"]
```
#### Parse Certificate info:
```sh
./edgetk -pkey [text|modulus] -cert certificate.pem
```
#### TLS Layer (TCP/IP):
```sh
./edgetk -tcp ip > PubIP.txt
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
#### HMAC:
```sh
./edgetk -mac hmac -key "secret" < file.ext
```
#### HKDF (HMAC-based key derivation function) (128-bit):
```sh
./edgetk -hkdf 128 -key "IKM" [-salt "salt"] [-info "AD"]
```
#### Hex Encoder/Decoder:
```sh
./edgetk -hex enc < file.ext > file.hex
./edgetk -hex dec < file.hex > file.ext
./edgetk -hex dump < file.ext
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

#### Copyright (c) 2020-2022 Pedro F. Albanese - ALBANESE Research Lab.
