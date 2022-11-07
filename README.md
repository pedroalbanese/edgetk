# EDGE Toolkit
[![ISC License](http://img.shields.io/badge/license-ISC-blue.svg)](https://github.com/pedroalbanese/edgetk/blob/master/LICENSE.md) 
[![GoDoc](https://godoc.org/github.com/pedroalbanese/edgetk?status.png)](http://godoc.org/github.com/pedroalbanese/edgetk)
[![GitHub downloads](https://img.shields.io/github/downloads/pedroalbanese/edgetk/total.svg?logo=github&logoColor=white)](https://github.com/pedroalbanese/edgetk/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/pedroalbanese/edgetk)](https://goreportcard.com/report/github.com/pedroalbanese/edgetk)
[![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/pedroalbanese/edgetk)](https://golang.org)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/pedroalbanese/edgetk)](https://github.com/pedroalbanese/edgetk/releases)

Multi-purpose hybrid cross-platform cryptography tool for symmetric and asymmetric encryption, cipher-based message authentication code (CMAC), recursive hash digest, hash-based message authentication code (HMAC), HMAC-based key derivation function (HKDF), Password-based key derivation function (PBKDF2), shared key agreement (ECDH), digital signature (RSA/ECDSA/EdDSA) and TLS 1.2 for small or embedded systems. 

***Fully OpenSSL compliant***

## Command-line Integrated Security Suite

### Asymmetric

- **Public key algorithms:**  

    |  Algorithm          | 256 | 512 |ECDH |DSA  |Encryption| TLS |
    |:--------------------|:---:|:---:|:---:|:---:|:--------:|:---:|
    | ECDSA               | O   | O   | O   | O   |          | O   |
    | Ed25519             | O   |     |     | O   |          | O   |
    | GOST2012            | O   | O   | O   | O   |          | O   |
    | RSA                 |     |     |     | O   | O        | O   |
    | SM2                 | O   |     | O   | O   | O        |     |

### Symmetric

- **Stream ciphers:**

    |      Cipher      |  Key Size  |  IV  |         Modes         |
    |:-----------------|:----------:|:----:|:---------------------:|
    | Chacha20Poly1305 | 256        |   96 | AEAD Stream Cipher    |
    | RC4 [Obsolete]   | 40/128     |    - | XOR Stream            |
    | ZUC-128 Zu Chunghzi  | 128     |  128 | XOR Stream            |
    | ZUC-256 Zu Chunghzi  | 256     |  184 | XOR Stream            |

- **128-bit block ciphers:**

    |      Cipher      | Block Size |  Key Size   |         Modes           |
    |:-----------------|:----------:|:-----------:|:-----------------------:|
    | AES (Rijndael)   |        128 | 128/192/256 | All modes supported     |
    | Anubis           |        128 |         128 | All modes supported     |
    | ARIA             |        128 | 128/192/256 | All modes supported     |
    | Camellia         |        128 | 128/192/256 | All modes supported     |
    | Grasshopper      |        128 |         256 | All modes supported     |
    | SEED             |        128 |         128 | All modes supported     |
    | SM4              |        128 |         128 | All modes supported     |
   
- **64-bit block ciphers:**


    |      Cipher      | Block Size |  Key Size    |    Modes    |
    |:-----------------|:----------:|:------------:|:-----------:|
    | DES [Obsolete]   |          64|            64|CFB8, CFB, CTR, OFB|
    | 3DES [Obsolete]  |          64|           192|CFB8, CFB, CTR, OFB|
    | Blowfish         |          64|           128|CFB8, CFB, CTR, OFB|
    | CAST5            |          64|           128|CFB8, CFB, CTR, OFB|
    | GOST89 (TC26)    |          64|           256|MGM, CFB, CTR, OFB|
    | IDEA [Obsolete]  |          64|           128|CFB8, CFB, CTR, OFB|
    | Magma            |          64|           256|MGM, CFB, CTR, OFB|
    | RC2 [Obsolete]   |          64|           128|CFB8, CFB, CTR, OFB|
    | RC5 [Obsolete]   |          64|           128|CFB8, CFB, CTR, OFB|

- **Modes of Operation:**

    |Mode |                                | Blocks     |  Keys     |
    |:---:|:-------------------------------|:----------:|:---------:|
    | GCM | Galois/Counter Mode (AEAD)     |128         |128/192/256| 
    | MGM | Multilinear Galois Mode (AEAD) |64/128      |Any        | 
    |CFB-8| Cipher Feedback Mode 8-bit     |All         |Any        |
    | CFB | Cipher Feedback Mode           |All         |Any        |
    | CTR | Counter Mode (default)         |All         |Any        |
    | OFB | Output Feedback Mode           |All         |Any        |
   
- **Message Digest Algorithms:**

    |    Algorithm    | 128 | 160 | 256 | 512 | MAC |
    |:----------------|:---:|:---:|:---:|:---:|:---:|
    | BLAKE-2B        |     |     | O   | O   | O   |
    | BLAKE-2S        | O   |     | O   |     | O   |
    | GOST94 CryptoPro      |     |     | O   |     |     |
    | MD4 [Obsolete]  | O   |     |     |     |     |
    | MD5 [Obsolete]  | O   |     |     |     |     |
    | Poly1305        | O   |     |     |     | O   |
    | RIPEMD          | [O](https://thomaspeyrin.github.io/web/assets/docs/slides/Landelle-Peyrin-EUROCRYPT2013_slides.pdf)   | O   | O   |     |     |
    | SHA1 [Obsolete] |     | O   |     |     |     |
    | SHA2 (default)  |     |     | O   | O   |     | 
    | SHA3            |     |     | O   | O   |     |
    | SM3             |     |     | O   |     |     |
    | Streebog        |     |     | O   | O   |     | 
    | ZUC (Zu Chongzhi)| O   |     |     |     | O   |
    | Whirlpool       |     |     |     | O   |     | 
    
    - MAC refers to keyed hash function, like HMAC. 

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
   * TLS 1.2 (Transport Layer Security)
   
* **Non-cryptographic Functions:**

   * Hex string encoder/dump/decoder (xxd-like)
   * Privacy-Enhanced Mail (PEM format)
   * RandomArt (OpenSSH-like)

## Usage
<pre> -algorithm string
       Public key algorithm: RSA, ECDSA, Ed25519 or SM2. (default "RSA")
 -bits int
       Key length. (for keypair generation and symmetric encryption)
 -cert string
       Certificate path. (default "Certificate.pem")
 -check string
       Check hashsum file. ('-' for STDIN)
 -cipher string
       Symmetric algorithm: aes, blowfish, magma or sm4. (default "aes")
 -crypt string
       Encrypt/Decrypt with bulk ciphers. [enc|dec]
 -digest string
       Target file/wildcard to generate hashsum list. ('-' for STDIN)
 -hex string
       Encode binary string to hex format and vice-versa. [enc|dec]
 -hkdf int
       HMAC-based key derivation function with given bit length.
 -info string
       Additional info. (for HKDF command and AEAD bulk encryption)
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
       Mode of operation: GCM, MGM, CFB8, CFB, CTR, OFB. (default "CTR")
 -pbkdf2
       Password-based key derivation function.
 -pkey string
       Subcommands: keygen|certgen, sign|verify|derive, text|modulus.
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
       Salt. (for HKDF and PBKDF2 commands)
 -signature string
       Input signature. (for VERIFY command and MAC verification)
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
./edgetk -pkey [text|modulus|randomart] -key public.pem
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
#### HMAC:
```sh
./edgetk -mac hmac -key "secret" < file.ext
./edgetk -mac hmac -key "secret" -signature $256bitmac < file.ext
echo $?
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
