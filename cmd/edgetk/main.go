/*
   EDGE Toolkit -- Pure Go Command-line Unique Integrated Security Suite
   Copyright (C) 2020-2024 Pedro F. Albanese <pedroalbanese@hotmail.com>

   This program is free software: you can redistribute it and/or modify it
   under the terms of the ISC License.

   THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
   WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
   MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
   ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
   WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
   ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
   OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/

package main

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/ascii85"
	"encoding/asn1"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/gob"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/blowfish"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/md4"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/poly1305"
	"golang.org/x/crypto/ripemd160"
	"golang.org/x/crypto/salsa20"
	"golang.org/x/crypto/sha3"
	"golang.org/x/crypto/twofish"
	"hash"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"math/bits"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"crypto/go.cypherpunks.ru/gogost/v5/gost3410"
	"gitee.com/Trisia/gotlcp/tlcp"
	"github.com/RyuaNerin/go-krypto/aria"
	"github.com/RyuaNerin/go-krypto/has160"
	"github.com/RyuaNerin/go-krypto/lea"
	"github.com/RyuaNerin/go-krypto/lsh256"
	"github.com/RyuaNerin/go-krypto/lsh512"
	"github.com/deatil/go-cryptobin/cipher/clefia"
	"github.com/deatil/go-cryptobin/cipher/crypton1"
	"github.com/deatil/go-cryptobin/cipher/e2"
	"github.com/deatil/go-cryptobin/cipher/khazad"
	"github.com/deatil/go-cryptobin/cipher/mars"
	"github.com/deatil/go-cryptobin/cipher/mars2"
	"github.com/deatil/go-cryptobin/cipher/noekeon"
	"github.com/deatil/go-cryptobin/cipher/panama"
	"github.com/deatil/go-cryptobin/cipher/present"
	"github.com/emmansun/certinfo"
	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm3"
	"github.com/emmansun/gmsm/sm4"
	"github.com/emmansun/gmsm/sm9"
	"github.com/emmansun/gmsm/sm9/bn256"
	"github.com/emmansun/gmsm/smx509"
	"github.com/emmansun/gmsm/zuc"
	"github.com/emmansun/go-pkcs12"
	"github.com/kasperdi/SPHINCSPLUS-golang/parameters"
	"github.com/kasperdi/SPHINCSPLUS-golang/sphincs"
	"github.com/pedroalbanese/IGE-go/ige"
	"github.com/pedroalbanese/anubis"
	"github.com/pedroalbanese/camellia"
	"github.com/pedroalbanese/cast5"
	"github.com/pedroalbanese/ccm"
	"github.com/pedroalbanese/cfb8"
	"github.com/pedroalbanese/cmac"
	"github.com/pedroalbanese/crypto/hc128"
	"github.com/pedroalbanese/crypto/hc256"
	"github.com/pedroalbanese/crypto/serpent"
	"github.com/pedroalbanese/cubehash"
	"github.com/pedroalbanese/eax"
	"github.com/pedroalbanese/ecb"
	"github.com/pedroalbanese/ecka-eg/core/curves"
	"github.com/pedroalbanese/ecka-eg/elgamal"
	elgamalAlt "github.com/pedroalbanese/ecka-eg/elgamal-alt"
	"github.com/pedroalbanese/gmac"
	"github.com/pedroalbanese/go-chaskey"
	"github.com/pedroalbanese/go-external-ip"
	"github.com/pedroalbanese/go-idea"
	"github.com/pedroalbanese/go-kcipher2"
	"github.com/pedroalbanese/go-krcrypt"
	"github.com/pedroalbanese/go-misty1"
	"github.com/pedroalbanese/go-rc5"
	"github.com/pedroalbanese/go-ripemd"
	"github.com/pedroalbanese/go-twine"
	"github.com/pedroalbanese/gogost/gost28147"
	"github.com/pedroalbanese/gogost/gost34112012256"
	"github.com/pedroalbanese/gogost/gost34112012512"
	"github.com/pedroalbanese/gogost/gost341194"
	"github.com/pedroalbanese/gogost/gost341264"
	"github.com/pedroalbanese/gogost/mgm"
	"github.com/pedroalbanese/golang-rc6"
	"github.com/pedroalbanese/gopass"
	"github.com/pedroalbanese/groestl-1"
	"github.com/pedroalbanese/haraka"
	"github.com/pedroalbanese/jh"
	"github.com/pedroalbanese/kuznechik"
	"github.com/pedroalbanese/lwcrypto/ascon2"
	"github.com/pedroalbanese/lwcrypto/grain"
	"github.com/pedroalbanese/lyra2re"
	"github.com/pedroalbanese/makwa-go"
	"github.com/pedroalbanese/ocb"
	"github.com/pedroalbanese/ocb3"
	"github.com/pedroalbanese/pmac"
	"github.com/pedroalbanese/rabbitio"
	"github.com/pedroalbanese/randomart"
	"github.com/pedroalbanese/rc2"
	"github.com/pedroalbanese/siphash"
	"github.com/pedroalbanese/skein"
	skeincipher "github.com/pedroalbanese/skein-1"
	"github.com/pedroalbanese/spritz"
	"github.com/pedroalbanese/threefish"
	"github.com/pedroalbanese/tiger"
	"github.com/pedroalbanese/trivium"
	"github.com/pedroalbanese/vmac"
	"github.com/pedroalbanese/whirlpool"
	"github.com/pedroalbanese/xoodoo/xoodyak"
	"github.com/zeebo/blake3"
)

var (
	alg        = flag.String("algorithm", "RSA", "Public key algorithm: EC, Ed25519, GOST2012, SM2.")
	cacert     = flag.String("cacert", "", "CA Certificate path. (for TLCP Protocol)")
	cakey      = flag.String("cakey", "", "CA Private key. (for TLCP Protocol)")
	cert       = flag.String("cert", "", "Certificate path.")
	check      = flag.Bool("check", false, "Check hashsum file. ('-' for STDIN)")
	cph        = flag.String("cipher", "aes", "Symmetric algorithm: aes, blowfish, magma or sm4.")
	crl        = flag.String("crl", "", "Certificate Revocation List path.")
	crypt      = flag.String("crypt", "", "Bulk Encryption with Stream and Block ciphers. [enc|dec|help]")
	curveFlag  = flag.String("curve", "ecdsa", "Subjacent curve (ECDSA, BLS12381G1 and G2.)")
	digest     = flag.Bool("digest", false, "Target file/wildcard to generate hashsum list. ('-' for STDIN)")
	encode     = flag.String("hex", "", "Encode binary string to hex format and vice-versa. [enc|dump|dec]")
	b85        = flag.String("base85", "", "Encode binary string to Base85 format and vice-versa. [enc|dec]")
	b64        = flag.String("base64", "", "Encode binary string to Base64 format and vice-versa. [enc|dec]")
	b32        = flag.String("base32", "", "Encode binary string to Base32 format and vice-versa. [enc|dec]")
	factorPStr = flag.String("factorp", "", "Makwa private Factor P. (for Makwa Password-hashing Scheme)")
	factorQStr = flag.String("factorq", "", "Makwa private Factor Q. (for Makwa Password-hashing Scheme)")
	hierarchy  = flag.Uint("hid", 0x01, "Hierarchy Identifier. (for SM9 User Private Key)")
	id         = flag.String("id", "", "User Identifier. (for SM9 User Private Key operations)")
	id2        = flag.String("peerid", "", "Remote's side User Identifier. (for SM9 Key Exchange)")
	info       = flag.String("info", "", "Additional info. (for HKDF command and AEAD bulk encryption)")
	iport      = flag.String("ipport", "", "Local Port/remote's side Public IP:Port.")
	iter       = flag.Int("iter", 1, "Iter. (for Password-based key derivation function)")
	kdf        = flag.String("kdf", "", "Key derivation function. [pbkdf2|hkdf|scrypt|argon2]")
	key        = flag.String("key", "", "Asymmetric key, symmetric key or HMAC key, depending on operation.")
	length     = flag.Int("bits", 0, "Key length. (for keypair generation and symmetric encryption)")
	mac        = flag.String("mac", "", "Compute Hash/Cipher-based message authentication code.")
	master     = flag.String("master", "Master.pem", "Master key path. (for sm9 setup)")
	md         = flag.String("md", "sha256", "Hash algorithm: sha256, sha3-256 or whirlpool.")
	mode       = flag.String("mode", "CTR", "Mode of operation: GCM, MGM, CBC, CFB8, OCB, OFB.")
	modulusStr = flag.String("modulus", "", "Makwa modulus. (Makwa hash Public Parameter)")
	paramset   = flag.String("paramset", "A", "Elliptic curve ParamSet: A, B, C, D. (for GOST2012)")
	params     = flag.String("params", "", "ElGamal Public Parameters path.")
	pkey       = flag.String("pkey", "", "Subcommands: keygen|certgen, sign|verify|derive, text|modulus.")
	priv       = flag.String("priv", "Private.pem", "Private key path. (for keypair generation)")
	pub        = flag.String("pub", "Public.pem", "Public key path. (for keypair generation)")
	pwd        = flag.String("pass", "", "Password/Passphrase. (for Private key PEM encryption)")
	pwd2       = flag.String("passout", "", "User Password. (for SM9 User Private Key PEM encryption)")
	random     = flag.Int("rand", 0, "Generate random cryptographic key with given bit length.")
	recover    = flag.Bool("recover", false, "Recover Passphrase from Makwa hash with Private Parameters.")
	recursive  = flag.Bool("recursive", false, "Process directories recursively. (for DIGEST command only)")
	root       = flag.String("root", "", "Root CA Certificate path.")
	salt       = flag.String("salt", "", "Salt. (for HKDF and PBKDF2 commands)")
	sig        = flag.String("signature", "", "Input signature. (for VERIFY command and MAC verification)")
	tcpip      = flag.String("tcp", "", "Encrypted TCP/IP Transfer Protocol. [server|ip|client]")
	vector     = flag.String("iv", "", "Initialization Vector. (for symmetric encryption)")
	col        = flag.Int("wrap", 64, "Wrap lines after N columns. (for Base64/32 encoding)")
	pad        = flag.Bool("nopad", false, "No padding. (for Base64 and Base32 encoding)")
	version    = flag.Bool("version", false, "Print version info.")
)

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *sm2.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	case *ecdh.PrivateKey:
		return k.Public().(*ecdh.PublicKey)
	case *gost3410.PrivateKey:
		return k.Public().(*gost3410.PublicKey)
	case ed25519.PrivateKey:
		return k.Public().(ed25519.PublicKey)
	case *rsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

var (
	oidEmailAddress                 = []int{1, 2, 840, 113549, 1, 9, 1}
	oidDomainComponent              = []int{0, 9, 2342, 19200300, 100, 1, 25}
	oidUserID                       = []int{0, 9, 2342, 19200300, 100, 1, 1}
	oidExtensionAuthorityInfoAccess = []int{1, 3, 6, 1, 5, 5, 7, 1, 1}
	oidNSComment                    = []int{2, 16, 840, 1, 113730, 1, 13}
	oidStepProvisioner              = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37476, 9000, 64, 1}
	oidStepCertificateAuthority     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37476, 9000, 64, 2}
)

func handleConnectionTLS(c net.Conn) {
	log.Printf("Client(TLS) %v connected via secure channel.", c.RemoteAddr())
}

func handleConnectionTLCP(c net.Conn) {
	log.Printf("Client(TLCP) %v connected via secure channel.", c.RemoteAddr())
}

func main() {
	flag.Parse()

	if *version {
		fmt.Println("EDGE Toolkit v1.4.3  11 Mar 2024")
	}

	if len(os.Args) < 2 {
		fmt.Println(`Standard Commands:
  crypt             digest            check             kdf
  mac               pkey              rand              tcp

Public Key Subcommands:
  keygen            check             text              derive
  setup             pkcs12            fingerprint       vko
  certgen           crl               modulus           x25519
  recover           req               randomart         wrapkey
  encrypt           validate          sign              unwrapkey
  decrypt           x509              verify            help

Public Key Algorithms:
  ecdsa             elgamal           sm2               gost2012
  ed25519           ec-elgamal        sm9encrypt        sphincs
  ed25519ph         rsa (default)     sm9sign           x25519

Stream Ciphers:
  ascon (aead)      grain128a         rabbit            spritz
  chacha20          hc128             rc4 [obsolete]    trivium
  chacha20poly1305  hc256             salsa20           zuc128
  grain (aead)      kcipher2          skein             zuc256

Modes of Operation:
  eax (aead)        ocb3 (aead)       cbc               ecb [obsolete]
  gcm (aead)        mgm (aead)        cfb/cfb8          ige
  ocb (aead)        ccm (aead)        ctr (default)     ofb

Block Ciphers:
  3des              crypton           magma             seed
  aes (default)     e2                mars[2]           serpent
  anubis            gost89            misty1            sm4
  aria              hight             noekeon           threefish
  blowfish          idea [obsolete]   present           threefish512
  camellia          khazad            rc2 [obsolete]    threefish1024
  cast5             kuznechik         rc5               twine
  clefia            lea               rc6               twofish

Key Derivation Functions:
  hkdf              pbkdf2            scrypt            bcrypt (phs)
  argon2 (phs/kdf)  lyra2 (phs/kdf)   makwa (phs)       help

Message Athentication Code:
  chaskey           hmac              siphash           xoodyak
  cmac              mgmac             siphash64         zuc128/eia128
  gmac              pmac              skein             zuc256/eia256
  gost              poly1305          vmac              help

Message Digests:
  blake2b256        keccak256         rmd256            shake128
  blake2b512        keccak512         rmd320            shake256
  blake2s128 (MAC)  lsh224            sha1 [obsolete]   siphash
  blake2s256        lsh256            sha224            siphash64
  blake3            lsh384            sha256 (default)  skein256
  cubehash          lsh512            sha384            skein512
  gost94            lsh512-224        sha512            sm3
  groestl           lsh512-256        sha512-256        streebog256
  haraka256         md4 [obsolete]    sha3-224          streebog512
  haraka512         md5 [obsolete]    sha3-256          tiger
  has160 [obsolete] rmd128            sha3-384          whirlpool
  jh                rmd160            sha3-512          xoodyak`)
		os.Exit(3)
	}

	if *crypt == "help" {
		fmt.Println(`Syntax:
  edgetk -crypt <enc|dec> [-cipher <cipher>] [-iv <iv>] [-key <key>] FILE

 PBKDF2 Subcommand Parameters:
  [...] -kdf pbkdf2 [-md <hash>] [-iter N] [-salt <salt>] -key "PASS" [...]

  Example:
  edgetk -crypt enc -kdf pbkdf2 -key "PASSPHRASE" -iter 32768 FILE > OUTPUT

 AEAD Modes Subcommand Parameters:
  [...] -mode gcm [-info "ADDITIONAL AUTHENTICATED DATA"] [...] 

  Example:
  edgetk -crypt enc -key "HEXKEY" -mode gcm -info "AAD" FILE > OUTPUT`)
		os.Exit(3)
	}

	if *mac == "help" {
		fmt.Println(`Syntax:
  edgetk -mac <method> [-md <hash>] [-cipher <ciph>] [-key <secret>] FILE

Methods: 
  cmac, pmac, hmac, chaskey, gost, poly1305, eia128/256, siphash, xoodyak

 HMAC:
  edgetk -mac hmac [-md sha256] -key <secret> FILE
  edgetk -mac hmac [-md sha256] -key <secret> -signature $256bitmac FILE
  echo $?

 CMAC:
  edgetk -mac cmac [-cipher aes] -key <secret> FILE
  edgetk -mac cmac [-cipher aes] -key <secret> -signature $128bitmac FILE
  echo $?`)
		os.Exit(3)
	}

	if *kdf == "help" {
		fmt.Println(`Syntax:
  edgetk -kdf <method> [-bits N] [-md <hash>] [-key <secret>] [-salt <salt>]

Methods: 
  hkdf, pbkdf2, scrypt, argon2, lyra2

 HKDF:
  edgetk -kdf hkdf [-bits N] [-salt "SALT"] [-info "AAD"] [-key "IKM"]

 Argon2:
  edgetk -kdf argon2 [-bits N] [-salt "SALT"] [-iter N] [-key "PASSPHRASE"]

 Lyra2:
  edgetk -kdf lyra2 [-bits N] [-salt "SALT"] [-iter N] [-key "PASSPHRASE"]

 PBKDF2:
  edgetk -kdf pbkdf2 [-bits N] [-salt "SALT"] [-iter N] [-key "PASSPHRASE"]

 Scrypt[*]:
  edgetk -kdf scrypt [-bits N] [-salt "SALT"] [-iter N] [-key "PASSPHRASE"]

 [*] scrypt iter must be greater than 1 and a power of 2:
  2^10 = 1.024
  2^11 = 2.048 
  2^12 = 4.096 (Minimum Recommended)
  2^13 = 8.192 
  2^14 = 16.384 
  2^15 = 32.768
  2^16 = 65.536
  2^17 = 131.072
  2^18 = 262.144 
  2^19 = 524.288
  2^20 = 1.048.576`)
		os.Exit(3)
	}

	if *pkey == "help" {
		fmt.Println(`Syntax:
  edgetk -pkey <command> [-algorithm <alg>] [-key <private>] [-pub <public>]
  [-root <cacert>] [-cert <certificate>] [-signature <sign>] [-bits N] FILE

Subcommands: 
  keygen, certgen, req, x509, check, pkcs12, encrypt, decrypt
  derive, x25519, vko, text, modulus, randomart, sign, verify

 Generate Key Pair:
  edgetk -pkey keygen [-algorithm <alg>] [-priv <private>] [-pub <public>]

 Generate Self-Signed Certificate:
  edgetk -pkey certgen [-algorithm <alg>] [-key <priv>] [-cert <cert.crt>] 

 Generate Certificate Sign Request:
  edgetk -pkey req [-algorithm <alg>] [-key <private>] [-cert <cert.csr>]

 Sign the Certificate Sign Request:
  edgetk -pkey x509 [-algorithm <alg>] [-root <cacert>] [-key <private>]
  [-cert <certificate.csr>] CERTIFICATE.crt

 Generate Certificate Revocation List:
  edgetk -pkey crl [-algorithm <alg>] [-cert <cacert>] [-key <private>]
  [-crl <old.crl>] [serials.txt] NewCRL.crl

 Parse Keypair:
  edgetk -pkey <text|modulus> [-pass "passphrase"] [-key <private.pem>]
  edgetk -pkey <text|modulus|randomart> [-key <public.pem>]

 Parse Certificate/CRL:
  edgetk -pkey <text|modulus> [-cert <certificate.pem>]
  edgetk -pkey <text> [-crl <crl.pem>]
  echo $?

 Check Certificate Signature:
  edgetk -pkey check [-cert <certificate.pem>] [-key <capublic.pem>]
  echo $?

 Check CRL Authenticity:
  edgetk -pkey check [-cert <cacert.pem>] [-crl <crl.pem>]
  echo $?

 Validate a Certificate against the CRL:
  edgetk -pkey validate [-cert <certificate.pem>] [-crl <crl.pem>]
  echo $?

 Derive Shared Secret:
  edgetk -pkey <derive|vko|x25519> [-key <privatekey>] [-pub <peerkey>]

 Digital Signature:
  edgetk -pkey <sign|verify> [-algorithm <alg>] [-key <private|public>]
  [-signature <signature>] FILE.ext

  Example:
  edgetk -pkey sign -key private.pem [-pass "pass"] FILE.ext > sign.txt
  sign=$(cat sign.txt|awk '{print $2}')
  edgetk -pkey verify -key public.pem -signature $sign FILE.ext
  echo $?`)
		os.Exit(3)
	}

	if *tcpip == "help" {
		fmt.Println(`Syntax:
  edgetk -tcp <server|client> [-cert <cert>] [-key <private>] [-ipport "IP"]

  Examples:
  edgetk -tcp ip > MyExternalIP.txt
  edgetk -tcp server -cert cert.pem -key priv.pem [-ipport "8081"]
  edgetk -tcp client -cert cert.pem -key priv.pem [-ipport "127.0.0.1:8081"]`)
		os.Exit(3)
	}

	if (*pkey == "keygen") && (*alg != "sm9encrypt" && *alg != "sm9sign") && *pwd == "" {
		print("Passphrase: ")
		pass, _ := gopass.GetPasswdMasked()
		*pwd = string(pass)
	} else if (*pkey == "keygen") && (*alg != "sm9encrypt" && *alg != "sm9sign") && *pwd == "nil" {
		*pwd = ""
	}

	if (*pkey == "setup") && *pwd == "" && strings.ToUpper(*alg) != "ELGAMAL" {
		print("Passphrase: ")
		pass, _ := gopass.GetPasswdMasked()
		*pwd = string(pass)
	}

	if (*pkey == "keygen") && (*alg == "sm9encrypt" || *alg == "sm9sign") && *pwd == "" {
		file, err := os.Open(*master)
		if err != nil {
			log.Fatal(err)
		}
		info, err := file.Stat()
		if err != nil {
			log.Fatal(err)
		}
		buf := make([]byte, info.Size())
		file.Read(buf)
		var block *pem.Block
		block, _ = pem.Decode(buf)
		if block == nil {
			errors.New("no valid private key found")
		}
		if IsEncryptedPEMBlock(block) {
			print("MasterKey Passphrase: ")
			pass, _ := gopass.GetPasswd()
			*pwd = string(pass)
		}
	}

	if (*pkey == "keygen") && (*alg == "sm9encrypt" || *alg == "sm9sign") && *pwd2 == "" {
		print("UserKey Passphrase: ")
		pass, _ := gopass.GetPasswdMasked()
		*pwd2 = string(pass)
	}

	if (*pkey == "sign" || *pkey == "decrypt" || *pkey == "derive" || *pkey == "derivea" || *pkey == "unwrapkey" || *pkey == "deriveb" || *pkey == "certgen" || *pkey == "text" || *pkey == "modulus" || *tcpip == "server" || *tcpip == "client" || *pkey == "pkcs12" || *pkey == "req" || *pkey == "x509" || *pkey == "x25519" || *pkey == "vko" || *pkey == "crl") && (*key != "") && *pwd == "" {
		file, err := os.Open(*key)
		if err != nil {
			log.Fatal(err)
		}
		info, err := file.Stat()
		if err != nil {
			log.Fatal(err)
		}
		buf := make([]byte, info.Size())
		file.Read(buf)
		var block *pem.Block
		block, _ = pem.Decode(buf)
		if block == nil {
			errors.New("no valid private key found")
		}
		if IsEncryptedPEMBlock(block) {
			print("Passphrase: ")
			pass, _ := gopass.GetPasswd()
			*pwd = string(pass)
		}
	}

	if (*pkey == "pkcs12") && *key == "" && *pwd == "" {
		pfxBytes, err := os.ReadFile(*cert)
		if err != nil {
			log.Fatal(err)
		}
		_, _, err = pkcs12.Decode(pfxBytes, *pwd)
		if err != nil {
			print("Passphrase: ")
			pass, _ := gopass.GetPasswd()
			*pwd = string(pass)
		}
	}

	var myHash func() hash.Hash
	if *md == "sha224" {
		myHash = sha256.New224
	} else if *md == "sha256" {
		myHash = sha256.New
	} else if *md == "sha384" {
		myHash = sha512.New384
	} else if *md == "sha512" {
		myHash = sha512.New
	} else if *md == "sha512-256" {
		myHash = sha512.New512_256
	} else if *md == "sha1" {
		myHash = sha1.New
	} else if *md == "rmd160" {
		myHash = ripemd160.New
	} else if *md == "rmd128" {
		myHash = ripemd.New128
	} else if *md == "rmd256" {
		myHash = ripemd.New256
	} else if *md == "rmd320" {
		myHash = ripemd.New320
	} else if *md == "sha3-224" {
		myHash = sha3.New224
	} else if *md == "sha3-256" {
		myHash = sha3.New256
	} else if *md == "sha3-384" {
		myHash = sha3.New384
	} else if *md == "sha3-512" {
		myHash = sha3.New512
	} else if *md == "keccak" || *md == "keccak256" {
		myHash = sha3.NewLegacyKeccak256
	} else if *md == "keccak512" {
		myHash = sha3.NewLegacyKeccak512
	} else if *md == "shake128" {
		myHash = func() hash.Hash {
			return sha3.NewShake128()
		}
	} else if *md == "shake256" {
		myHash = func() hash.Hash {
			return sha3.NewShake256()
		}
	} else if *md == "lsh224" || *md == "lsh256-224" {
		myHash = lsh256.New224
	} else if *md == "lsh" || *md == "lsh256" || *md == "lsh256-256" {
		myHash = lsh256.New
	} else if *md == "lsh512-256" {
		myHash = lsh512.New256
	} else if *md == "lsh512-224" {
		myHash = lsh512.New224
	} else if *md == "lsh384" || *md == "lsh512-384" {
		myHash = lsh512.New384
	} else if *md == "lsh512" {
		myHash = lsh512.New
	} else if *md == "has160" {
		myHash = has160.New
	} else if *md == "whirlpool" {
		myHash = whirlpool.New
	} else if *md == "blake2b256" {
		myHash = crypto.BLAKE2b_256.New
	} else if *md == "blake2b512" {
		myHash = crypto.BLAKE2b_512.New
	} else if *md == "blake2s256" {
		myHash = crypto.BLAKE2s_256.New
	} else if *md == "blake3" {
		myHash = func() hash.Hash {
			return blake3.New()
		}
	} else if *md == "md5" {
		myHash = md5.New
	} else if *md == "gost94" {
		myHash = func() hash.Hash {
			return gost341194.New(&gost28147.SboxIdGostR341194CryptoProParamSet)
		}
	} else if *md == "streebog" || *md == "streebog256" {
		myHash = gost34112012256.New
	} else if *md == "streebog512" {
		myHash = gost34112012512.New
	} else if *md == "sm3" {
		myHash = sm3.New
	} else if *md == "md4" {
		myHash = md4.New
	} else if *md == "cubehash" {
		myHash = cubehash.New
	} else if *md == "xoodyak" || *md == "xhash" {
		myHash = xoodyak.NewXoodyakHash
	} else if *md == "skein" || *md == "skein256" {
		myHash = func() hash.Hash {
			return skein.New256(nil)
		}
	} else if *md == "skein512" {
		myHash = func() hash.Hash {
			return skein.New512(nil)
		}
	} else if *md == "jh" {
		myHash = jh.New256
	} else if *md == "groestl" {
		myHash = groestl.New256
	} else if *md == "tiger" {
		myHash = tiger.New
	} else if *md == "tiger2" {
		myHash = tiger.New2
	}

	if *random != 0 {
		var key []byte
		var err error
		key = make([]byte, *random/8)
		_, err = io.ReadFull(rand.Reader, key)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(hex.EncodeToString(key))
		os.Exit(0)
	}

	Files := strings.Join(flag.Args(), " ")
	var inputfile io.Reader
	var inputdesc string
	var err error
	if Files == "-" || Files == "" || strings.Contains(Files, "*") {
		inputfile = os.Stdin
		inputdesc = "stdin"
	} else if *pkey != "x509" && *pkey != "req" && *pkey != "wrapkey" {
		inputfile, err = os.Open(flag.Arg(0))
		if err != nil {
			log.Fatalf("failed opening file: %s", err)
		}
		inputdesc = flag.Arg(0)
	}

	if *encode == "enc" {
		b, err := ioutil.ReadAll(inputfile)
		if len(b) == 0 {
			os.Exit(0)
		}
		if err != nil {
			log.Fatal(err)
		}
		o := make([]byte, hex.EncodedLen(len(b)))
		hex.Encode(o, b)
		os.Stdout.Write(o)
		os.Exit(0)
	} else if *encode == "dec" {
		var err error
		buf := bytes.NewBuffer(nil)
		data := inputfile
		io.Copy(buf, data)
		b := strings.TrimSuffix(string(buf.Bytes()), "\r\n")
		b = strings.TrimSuffix(string(b), "\n")
		if !isHexDump(b) {
			data, err := decodeHexDump(b)
			if err != nil {
				log.Fatal(err)
			}
			os.Stdout.Write(data)
			os.Exit(0)
		}
		if len(b) == 0 {
			os.Exit(0)
		}
		if len(b) < 2 {
			os.Exit(0)
		}
		if (len(b)%2 != 0) || (err != nil) {
			log.Fatal(err)
		}
		o := make([]byte, hex.DecodedLen(len(b)))
		_, err = hex.Decode(o, []byte(b))
		if err != nil {
			log.Fatal(err)
		}
		os.Stdout.Write(o)
		os.Exit(0)
	} else if *encode == "dump" {
		buf := bytes.NewBuffer(nil)
		data := inputfile
		io.Copy(buf, data)
		dump := hex.Dump(buf.Bytes())
		os.Stdout.Write([]byte(dump))
		os.Exit(0)
	} else if *encode == "split" {
		data, _ := ioutil.ReadAll(inputfile)
		b := strings.TrimSuffix(string(data), "\r\n")
		b = strings.TrimSuffix(b, "\n")
		print(len(b)/2, " bytes ", len(b)*4, " bits\n")
		splitx := SplitSubN(b, 4)
		for _, chunk := range split(strings.Trim(fmt.Sprint(splitx), "[]"), 40) {
			fmt.Println(strings.ToUpper(chunk))
		}
	} else if *encode == "split+" {
		data, _ := ioutil.ReadAll(inputfile)
		b := strings.TrimSuffix(string(data), "\r\n")
		b = strings.TrimSuffix(b, "\n")
		print(len(b)/2, " bytes ", len(b)*4, " bits\n")
		splitx := SplitSubN(b, 4)
		for _, chunk := range split(strings.Trim(fmt.Sprint(splitx), "[]"), 80) {
			fmt.Println(strings.ToUpper(chunk))
		}
	} else if *encode == "join" {
		data, _ := ioutil.ReadAll(inputfile)
		join := strings.ReplaceAll(string(data), " ", "")
		join = strings.ReplaceAll(join, "\r\n", "")
		join = strings.ReplaceAll(join, "\n", "")
		fmt.Println(strings.ToLower(join))
	}

	if *b85 == "enc" || *b85 == "dec" {
		if *col == 0 && len(flag.Args()) > 0 {
			inputFile := flag.Arg(0)

			data, err := ioutil.ReadFile(inputFile)
			if err != nil {
				fmt.Println("Error reading the file:", err)
				os.Exit(1)
			}

			inputData := string(data)

			if *b85 == "enc" {
				fmt.Print(encodeAscii85([]byte(inputData)))
			} else {
				decoder := ascii85.NewDecoder(strings.NewReader(inputData))
				decodedData, err := ioutil.ReadAll(decoder)
				if err != nil {
					fmt.Println("Error decoding data:", err)
					os.Exit(1)
				}
				fmt.Print(string(decodedData))
			}
		} else {
			var inputData string

			if len(flag.Args()) == 0 {
				data, _ := ioutil.ReadAll(os.Stdin)
				inputData = string(data)
			} else {
				inputFile := flag.Arg(0)

				data, err := ioutil.ReadFile(inputFile)
				if err != nil {
					fmt.Println("Error reading the file:", err)
					os.Exit(1)
				}
				inputData = string(data)
			}

			if *col != 0 {
				if *b85 == "enc" {
					printChunks(encodeAscii85([]byte(inputData)), *col)
				} else {
					decoder := ascii85.NewDecoder(strings.NewReader(inputData))
					decodedData, err := ioutil.ReadAll(decoder)
					if err != nil {
						fmt.Println("Error decoding data:", err)
						os.Exit(1)
					}
					fmt.Print(string(decodedData))
				}
			} else {
				if *b85 == "enc" {
					fmt.Print(encodeAscii85([]byte(inputData)))
				} else {
					decoder := ascii85.NewDecoder(strings.NewReader(inputData))
					decodedData, err := ioutil.ReadAll(decoder)
					if err != nil {
						fmt.Println("Error decoding data:", err)
						os.Exit(1)
					}
					fmt.Print(string(decodedData))
				}
			}
		}
	}

	if *b64 == "enc" || *b64 == "dec" {
		if *col == 0 && len(flag.Args()) > 0 {
			inputFile := flag.Arg(0)

			data, err := ioutil.ReadFile(inputFile)
			if err != nil {
				fmt.Println("Error reading the file:", err)
				os.Exit(1)
			}

			inputData := string(data)

			if *b64 == "enc" && *pad == false {
				sEnc := base64.StdEncoding.EncodeToString([]byte(inputData))
				fmt.Println(sEnc)
			} else if *b64 == "enc" && *pad == true {
				sEnc := base64.StdEncoding.WithPadding(-1).EncodeToString([]byte(inputData))
				fmt.Println(sEnc)
			}
		} else {
			var inputData string

			if len(flag.Args()) == 0 {
				data, _ := ioutil.ReadAll(os.Stdin)
				inputData = string(data)
			} else {
				inputFile := flag.Arg(0)

				data, err := ioutil.ReadFile(inputFile)
				if err != nil {
					fmt.Println("Error reading the file:", err)
					os.Exit(1)
				}
				inputData = string(data)
			}

			if *col != 0 {
				if *b64 == "enc" && *pad == false {
					sEnc := base64.StdEncoding.EncodeToString([]byte(inputData))
					for _, chunk := range split(sEnc, *col) {
						fmt.Println(chunk)
					}
				} else if *b64 == "dec" && *pad == false {
					sDec, _ := base64.StdEncoding.DecodeString(inputData)
					os.Stdout.Write(sDec)
				}

				if *b64 == "enc" && *pad == true {
					sEnc := base64.StdEncoding.WithPadding(-1).EncodeToString([]byte(inputData))
					for _, chunk := range split(sEnc, *col) {
						fmt.Println(chunk)
					}
				} else if *b64 == "dec" && *pad == true {
					sDec, _ := base64.StdEncoding.WithPadding(-1).DecodeString(inputData)
					os.Stdout.Write(sDec)
				}
			} else {
				if *b64 == "enc" && *pad == false {
					sEnc := base64.StdEncoding.EncodeToString([]byte(inputData))
					fmt.Println(sEnc)
				} else if *b64 == "dec" && *pad == false {
					sDec, _ := base64.StdEncoding.DecodeString(inputData)
					os.Stdout.Write(sDec)
				}

				if *b64 == "enc" && *pad == true {
					sEnc := base64.StdEncoding.WithPadding(-1).EncodeToString([]byte(inputData))
					fmt.Println(sEnc)
				} else if *b64 == "dec" && *pad == true {
					sDec, _ := base64.StdEncoding.WithPadding(-1).DecodeString(inputData)
					os.Stdout.Write(sDec)
				}
			}
		}
	}

	if *b32 == "enc" || *b32 == "dec" {
		if *col == 0 && len(flag.Args()) > 0 {
			inputFile := flag.Arg(0)

			data, err := ioutil.ReadFile(inputFile)
			if err != nil {
				fmt.Println("Error reading the file:", err)
				os.Exit(1)
			}

			inputData := string(data)

			if *b32 == "enc" && *pad == false {
				sEnc := base32.StdEncoding.EncodeToString([]byte(inputData))
				fmt.Println(sEnc)
			} else if *b32 == "enc" && *pad == true {
				sEnc := base32.StdEncoding.WithPadding(-1).EncodeToString([]byte(inputData))
				fmt.Println(sEnc)
			}
		} else {
			var inputData string

			if len(flag.Args()) == 0 {
				data, _ := ioutil.ReadAll(os.Stdin)
				inputData = string(data)
			} else {
				inputFile := flag.Arg(0)

				data, err := ioutil.ReadFile(inputFile)
				if err != nil {
					fmt.Println("Error reading the file:", err)
					os.Exit(1)
				}
				inputData = string(data)
			}

			if *col != 0 {
				if *b32 == "enc" && *pad == false {
					sEnc := base32.StdEncoding.EncodeToString([]byte(inputData))
					for _, chunk := range split(sEnc, *col) {
						fmt.Println(chunk)
					}
				} else if *b32 == "dec" && *pad == false {
					sDec, _ := base32.StdEncoding.DecodeString(inputData)
					os.Stdout.Write(sDec)
				}

				if *b32 == "enc" && *pad == true {
					sEnc := base32.StdEncoding.WithPadding(-1).EncodeToString([]byte(inputData))
					for _, chunk := range split(sEnc, *col) {
						fmt.Println(chunk)
					}
				} else if *b32 == "dec" && *pad == true {
					sDec, _ := base32.StdEncoding.WithPadding(-1).DecodeString(inputData)
					os.Stdout.Write(sDec)
				}
			} else {
				if *b32 == "enc" && *pad == false {
					sEnc := base32.StdEncoding.EncodeToString([]byte(inputData))
					fmt.Println(sEnc)
				} else if *b32 == "dec" && *pad == false {
					sDec, _ := base32.StdEncoding.DecodeString(inputData)
					os.Stdout.Write(sDec)
				}

				if *b32 == "enc" && *pad == true {
					sEnc := base32.StdEncoding.WithPadding(-1).EncodeToString([]byte(inputData))
					fmt.Println(sEnc)
				} else if *b32 == "dec" && *pad == true {
					sDec, _ := base32.StdEncoding.WithPadding(-1).DecodeString(inputData)
					os.Stdout.Write(sDec)
				}
			}
		}
	}

	if (*cph == "aes" || *cph == "aria" || *cph == "mars" || *cph == "mars2" || *cph == "clefia" || *cph == "crypton" || *cph == "e2" || *cph == "grasshopper" || *cph == "kuznechik" || *cph == "magma" || *cph == "gost89" || *cph == "camellia" || *cph == "chacha20poly1305" || *cph == "chacha20" || *cph == "salsa20" || *cph == "twofish" || *cph == "lea" || *cph == "hc256" || *cph == "eea256" || *cph == "zuc256" || *cph == "skein" || *cph == "serpent" || *cph == "rc6") && *pkey != "keygen" && (*length != 256 && *length != 192 && *length != 128) && *crypt != "" {
		*length = 256
	}

	if *mac == "skein" && *length == 0 {
		*length = 256
	}

	if *cph == "3des" && *pkey != "keygen" && *length != 192 && *crypt != "" {
		*length = 192
	}

	if (*cph == "blowfish" || *cph == "cast5" || *cph == "idea" || *cph == "rc2" || *cph == "rc5" || *cph == "rc4" || *cph == "sm4" || *cph == "seed" || *cph == "hight" || *cph == "misty1" || *cph == "khazad" || *cph == "present" || *cph == "twine" || *cph == "noekeon" || *cph == "xoodyak" || *cph == "hc128" || *cph == "eea128" || *cph == "zuc128" || *cph == "ascon" || *cph == "grain128a" || *cph == "grain128aead" || *cph == "kcipher2" || *cph == "rabbit") && *pkey != "keygen" && (*length != 128) && *crypt != "" {
		*length = 128
	}

	if (*cph == "present" || *cph == "twine") && *pkey != "keygen" && (*length != 80) && *crypt != "" {
		*length = 80
	}

	if (*cph == "anubis") && *pkey != "keygen" && (*length < 128 || *length > 320) && *crypt != "" {
		*length = 128
	}

	if (*cph == "threefish" || *cph == "threefish256") && *pkey != "keygen" && (*length != 256) && *crypt != "" {
		*length = 256
	}

	if (*cph == "threefish512") && *pkey != "keygen" && (*length != 512) && *crypt != "" {
		*length = 512
	}

	if (*cph == "threefish1024") && *pkey != "keygen" && (*length != 1024) && *crypt != "" {
		*length = 1024
	}

	if (*mac == "eia256" || *mac == "zuc256") && (*length != 32 && *length != 64 && *length != 128) {
		*length = 128
	}

	if *cph == "des" && *pkey != "keygen" && *length != 64 && *crypt != "" {
		*length = 64
	}

	if strings.ToUpper(*alg) == "RSA" && *pkey == "keygen" && *length == 0 {
		*length = 3072
	}

	if strings.ToUpper(*alg) == "MAKWA" && *length == 0 {
		*length = 2048
	}

	if strings.ToUpper(*alg) == "MAKWA" && *iter == 1 {
		*iter = 4096
	}

	if (strings.ToUpper(*alg) == "ELGAMAL" && *pkey != "wrapkey" && *pkey != "unwrapkey") && *length == 0 {
		*length = 3072
	}

	if (strings.ToUpper(*alg) == "ELGAMAL" || strings.ToUpper(*alg) == "EC-ELGAMAL") && strings.ToUpper(*mode) == "CTR" {
		*mode = "GCM"
	}

	if *digest && *md == "spritz" && *length == 0 {
		*length = 256
	}

	if *pkey == "keygen" && strings.ToUpper(*alg) == "SPHINCS" && *iter == 1 {
		*iter = 16384
	}

	if (*pkey == "wrapkey" || *pkey == "unwrapkey") && *length == 0 {
		*length = 128
	}

	if (*pkey == "derivea" || *pkey == "deriveb") && *length == 0 {
		*length = 128
	}

	if (strings.ToUpper(*md) == "ARGON2" || strings.ToUpper(*kdf) == "ARGON2" || strings.ToUpper(*kdf) == "SCRYPT" || strings.ToUpper(*kdf) == "PBKDF2" || strings.ToUpper(*kdf) == "HKDF" || strings.ToUpper(*kdf) == "LYRA2") && *length == 0 {
		*length = 256
	}

	if (strings.ToUpper(*alg) == "GOST2012" || strings.ToUpper(*alg) == "EC" || strings.ToUpper(*alg) == "ECDSA") && *pkey == "keygen" && *length == 0 {
		*length = 256
	}

	if strings.ToUpper(*mac) == "VMAC" && *length == 0 {
		*length = 128
	}

	if *kdf == "pbkdf2" {
		if *md == "jh" {
			*salt = fmt.Sprintf("%-64s", *salt)
		}
		keyRaw := pbkdf2.Key([]byte(*key), []byte(*salt), *iter, *length/8, myHash)
		*key = hex.EncodeToString(keyRaw)
		if *crypt == "" {
			fmt.Println(*key)
			os.Exit(0)
		}
	}

	if *kdf == "scrypt" {
		if *md == "jh" {
			*salt = fmt.Sprintf("%-64s", *salt)
		}
		keyRaw, err := Scrypt([]byte(*key), []byte(*salt), *iter, 8, 1, *length/8)
		if err != nil {
			log.Fatal(err)
		}
		*key = hex.EncodeToString(keyRaw)
		if *crypt == "" {
			fmt.Println(*key)
			os.Exit(0)
		}
	}

	if *kdf == "argon2" {
		hash := argon2.IDKey([]byte(*key), []byte(*salt), uint32(*iter), 64*1024, 4, uint32(*length/8))
		*key = hex.EncodeToString(hash)

		if *crypt == "" {
			fmt.Println(*key)
			return
		}
	}

	if *kdf == "lyra2" {
		data := []byte(*key + *salt)
		for i := 0; i < *iter; i++ {
			hash, _ := lyra2re.Sum(data)
			if err != nil {
				log.Fatal(err)
			}
			data = hash
		}

		derivedKey := data[:*length/8]
		*key = hex.EncodeToString(derivedKey)

		if *crypt == "" {
			fmt.Println(*key)
			return
		}
	}

	if *crypt != "" && (*cph == "rc4") {
		var keyHex string
		keyHex = *key
		var key []byte
		var err error
		if keyHex == "" {
			key = make([]byte, 16)
			_, err = io.ReadFull(rand.Reader, key)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Fprintln(os.Stderr, "Key=", hex.EncodeToString(key))
		} else {
			key, err = hex.DecodeString(keyHex)
			if err != nil {
				log.Fatal(err)
			}
			if len(key) != 32 && len(key) != 16 && len(key) != 5 {
				log.Fatal("Invalid key size.")
			}
		}
		ciph, _ := rc4.NewCipher(key)
		buf := make([]byte, 64*1<<10)
		var n int
		for {
			n, err = inputfile.Read(buf)
			if err != nil && err != io.EOF {
				log.Fatal(err)
			}
			ciph.XORKeyStream(buf[:n], buf[:n])
			if _, err := os.Stdout.Write(buf[:n]); err != nil {
				log.Fatal(err)
			}
			if err == io.EOF {
				break
			}
		}
		os.Exit(0)
	}

	if *crypt != "" && *cph == "spritz" {
		var keyHex string
		keyHex = *key
		var key []byte
		var err error
		if keyHex == "" {
			key = make([]byte, 32)
			_, err = io.ReadFull(rand.Reader, key)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Fprintln(os.Stderr, "Key=", hex.EncodeToString(key))
		} else {
			key, err = hex.DecodeString(keyHex)
			if err != nil {
				log.Fatal(err)
			}
		}

		var nonce []byte
		if *vector != "" {
			nonce, _ = hex.DecodeString(*vector)
		} else {
			nonce = make([]byte, 32)
			fmt.Fprintf(os.Stderr, "IV= %x\n", nonce)
		}

		buf := bytes.NewBuffer(nil)
		var data io.Reader
		data = inputfile
		io.Copy(buf, data)
		msg := buf.Bytes()

		if flag.NArg() > 0 {
			file, err := os.Open(flag.Arg(0))
			if err != nil {
				log.Fatal(err)
			}
			defer file.Close()
			inputfile = file
		} else {
			inputfile = os.Stdin
		}

		if *crypt == "enc" {
			out := spritz.EncryptWithIV(key, nonce, msg)
			fmt.Printf("%s", out)
			os.Exit(0)
		}

		if *crypt == "dec" {
			out := spritz.DecryptWithIV(key, nonce, msg)
			fmt.Printf("%s", out)
			os.Exit(0)
		}
		os.Exit(0)
	}

	if *digest && *md == "spritz" {
		buf := bytes.NewBuffer(nil)
		var data io.Reader
		data = inputfile
		io.Copy(buf, data)
		msg := buf.Bytes()

		out := spritz.Hash(msg, byte(*length/8))
		fmt.Printf("%x\n", out)
		os.Exit(0)
	}

	if *crypt != "" && *cph == "trivium" {
		var keyHex string
		keyHex = *key
		var keyRaw []byte
		var key = [10]byte{}
		var err error
		if keyHex != "" {
			raw, err := hex.DecodeString(keyHex)
			if err != nil {
				log.Fatal(err)
			}
			key = *byte10(raw)
			if err != nil {
				log.Fatal(err)
			}
			if len(key) != trivium.KeyLength {
				log.Fatal(err)
			}
		} else {
			keyRaw = make([]byte, 10)
			_, err = io.ReadFull(rand.Reader, keyRaw)
			if err != nil {
				log.Fatal(err)
			}
			key = *byte10(keyRaw)
			fmt.Fprintln(os.Stderr, "Key=", hex.EncodeToString(key[:]))
		}

		var iv = [10]byte{}

		if *vector == "" {
			fmt.Fprintf(os.Stderr, "IV= %x\n", iv)
		} else {
			raw, err := hex.DecodeString(*vector)
			if err != nil {
				log.Fatal(err)
			}
			iv = *byte10(raw)
			if err != nil {
				log.Fatal(err)
			}
		}

		var trivium = trivium.NewTrivium(key, iv)
		reader := bufio.NewReader(inputfile)
		writer := bufio.NewWriter(os.Stdout)
		defer writer.Flush()

		var b byte
		for b, err = reader.ReadByte(); err == nil; b, err = reader.ReadByte() {
			kb := trivium.NextByte()
			err := writer.WriteByte(b ^ kb)
			if err != nil {
				log.Fatalf("error writing")
			}
		}
		if err != io.EOF {
			log.Fatalf("error reading")
		}
	}

	if *crypt != "" && *cph == "panama" {
		var keyHex string
		keyHex = *key
		var key []byte
		var err error
		if keyHex == "" {
			key = make([]byte, 32)
			_, err = io.ReadFull(rand.Reader, key)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Fprintln(os.Stderr, "Key=", hex.EncodeToString(key))
		} else {
			key, err = hex.DecodeString(keyHex)
			if err != nil {
				log.Fatal(err)
			}
			if len(key) != 32 {
				log.Fatal("Invalid key size.")
			}
		}
		ciph, _ := panama.NewCipher(key)
		buf := make([]byte, 64*1<<10)
		var n int
		for {
			n, err = inputfile.Read(buf)
			if err != nil && err != io.EOF {
				log.Fatal(err)
			}
			ciph.XORKeyStream(buf[:n], buf[:n])
			if _, err := os.Stdout.Write(buf[:n]); err != nil {
				log.Fatal(err)
			}
			if err == io.EOF {
				break
			}
		}
		os.Exit(0)
	}

	if *crypt != "" && *cph == "rabbit" {
		var keyHex string
		keyHex = *key
		var key []byte
		var err error
		if keyHex == "" {
			key = make([]byte, 16)
			_, err = io.ReadFull(rand.Reader, key)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Fprintln(os.Stderr, "Key=", hex.EncodeToString(key))
		} else {
			key, err = hex.DecodeString(keyHex)
			if err != nil {
				log.Fatal(err)
			}
			if len(key) != 16 {
				log.Fatal("Invalid key size.")
			}
		}
		var nonce []byte
		if *vector != "" {
			nonce, _ = hex.DecodeString(*vector)
		} else {
			nonce = make([]byte, 8)
			fmt.Fprintf(os.Stderr, "IV= %x\n", nonce)
		}
		ciph, _ := rabbitio.NewCipher(key, nonce)
		buf := make([]byte, 64*1<<10)
		var n int
		for {
			n, err = inputfile.Read(buf)
			if err != nil && err != io.EOF {
				log.Fatal(err)
			}
			ciph.XORKeyStream(buf[:n], buf[:n])
			if _, err := os.Stdout.Write(buf[:n]); err != nil {
				log.Fatal(err)
			}
			if err == io.EOF {
				break
			}
		}
		os.Exit(0)
	}

	if *crypt != "" && (*cph == "kcipher2") {
		var keyHex string
		keyHex = *key
		var key []byte
		var err error
		if keyHex == "" {
			key = make([]byte, 16)
			_, err = io.ReadFull(rand.Reader, key)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Fprintln(os.Stderr, "Key=", hex.EncodeToString(key))
		} else {
			key, err = hex.DecodeString(keyHex)
			if err != nil {
				log.Fatal(err)
			}
			if len(key) != 16 {
				log.Fatal("Invalid key size.")
			}
		}
		var iv []byte
		iv = make([]byte, 16)
		if *vector != "" {
			iv, _ = hex.DecodeString(*vector)
		} else {
			fmt.Fprintf(os.Stderr, "IV= %x\n", iv)
		}
		ciph, _ := kcipher2.New(iv, key)
		buf := make([]byte, 64*1<<10)
		var n int
		for {
			n, err = inputfile.Read(buf)
			if err != nil && err != io.EOF {
				log.Fatal(err)
			}
			ciph.XORKeyStream(buf[:n], buf[:n])
			if _, err := os.Stdout.Write(buf[:n]); err != nil {
				log.Fatal(err)
			}
			if err == io.EOF {
				break
			}
		}
		os.Exit(0)
	}

	if *crypt != "" && (*cph == "xoodyak") {
		var keyHex string
		keyHex = *key
		var key []byte
		var err error
		if keyHex == "" {
			key = make([]byte, 16)
			_, err = io.ReadFull(rand.Reader, key)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Fprintln(os.Stderr, "Key=", hex.EncodeToString(key))
		} else {
			key, err = hex.DecodeString(keyHex)
			if err != nil {
				log.Fatal(err)
			}
			if len(key) != 16 {
				log.Fatal("Invalid key size.")
			}
		}

		buf := bytes.NewBuffer(nil)
		var data io.Reader
		data = inputfile
		io.Copy(buf, data)
		msg := buf.Bytes()

		aead, err := xoodyak.NewXoodyakAEAD(key)
		if err != nil {
			panic(err)
		}

		if *crypt == "enc" {
			nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(msg)+aead.Overhead())

			if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
				log.Fatal(err)
			}

			out := aead.Seal(nonce, nonce, msg, []byte(*info))
			fmt.Printf("%s", out)

			os.Exit(0)
		}

		if *crypt == "dec" {
			nonce, msg := msg[:aead.NonceSize()], msg[aead.NonceSize():]

			out, err := aead.Open(nil, nonce, msg, []byte(*info))
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("%s", out)

			os.Exit(0)
		}
	}

	if *crypt != "" && *cph == "grain128a" {
		var keyHex string
		keyHex = *key
		var key []byte
		var err error
		if keyHex == "" {
			key = make([]byte, 16)
			_, err = io.ReadFull(rand.Reader, key)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Fprintln(os.Stderr, "Key=", hex.EncodeToString(key))
		} else {
			key, err = hex.DecodeString(keyHex)
			if err != nil {
				log.Fatal(err)
			}
			if len(key) != 16 {
				log.Fatal("Invalid key size.")
			}
		}
		var nonce []byte
		nonce = make([]byte, 12)
		var iv []byte
		iv = make([]byte, 12)

		if *vector != "" {
			iv, _ = hex.DecodeString(*vector)
			copy(nonce[:], iv)
		} else {
			fmt.Fprintf(os.Stderr, "IV= %x\n", iv)
		}

		ciph, err := grain.NewUnauthenticated(key, iv)
		if err != nil {
			log.Fatal(err)
		}

		buf := make([]byte, 64*1<<10)
		var n int
		for {
			n, err = inputfile.Read(buf)
			if err != nil && err != io.EOF {
				log.Fatal(err)
			}
			ciph.XORKeyStream(buf[:n], buf[:n])
			if _, err := os.Stdout.Write(buf[:n]); err != nil {
				log.Fatal(err)
			}
			if err == io.EOF {
				break
			}
		}
		os.Exit(0)
	}

	if *crypt != "" && (*cph == "ascon" || *cph == "grain128aead" || *cph == "grain") {
		var keyHex string
		keyHex = *key
		var key []byte
		var err error
		if keyHex == "" {
			key = make([]byte, 16)
			_, err = io.ReadFull(rand.Reader, key)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Fprintln(os.Stderr, "Key=", hex.EncodeToString(key))
		} else {
			key, err = hex.DecodeString(keyHex)
			if err != nil {
				log.Fatal(err)
			}
			if len(key) != 16 {
				log.Fatal("Invalid key size.")
			}
		}

		buf := bytes.NewBuffer(nil)
		var data io.Reader
		data = inputfile
		io.Copy(buf, data)
		msg := buf.Bytes()

		var aead cipher.AEAD
		if *cph == "ascon" {
			aead, err = ascon.New128a(key)
		} else if *cph == "grain128aead" || *cph == "grain" {
			aead, err = grain.New(key)
		}
		if err != nil {
			log.Fatal(err)
		}

		if *crypt == "enc" {
			nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(msg)+aead.Overhead())

			if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
				log.Fatal(err)
			}

			out := aead.Seal(nonce, nonce, msg, []byte(*info))
			fmt.Printf("%s", out)

			os.Exit(0)
		}

		if *crypt == "dec" {
			nonce, msg := msg[:aead.NonceSize()], msg[aead.NonceSize():]

			out, err := aead.Open(nil, nonce, msg, []byte(*info))
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("%s", out)

			os.Exit(0)
		}
	}

	if *crypt != "" && (*cph == "chacha20poly1305") {
		var keyHex string
		keyHex = *key
		var key []byte
		var err error
		if keyHex == "" {
			key = make([]byte, 32)
			_, err = io.ReadFull(rand.Reader, key)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Fprintln(os.Stderr, "Key=", hex.EncodeToString(key))
		} else {
			key, err = hex.DecodeString(keyHex)
			if err != nil {
				log.Fatal(err)
			}
			if len(key) != 32 {
				log.Fatal("Invalid key size.")
			}
		}

		aead, err := chacha20poly1305.New(key)
		if err != nil {
			log.Fatal(err)
		}
		buf := bytes.NewBuffer(nil)
		io.Copy(buf, inputfile)
		msg := buf.Bytes()

		if *crypt == "enc" {
			nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(msg)+aead.Overhead())

			if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
				log.Fatal(err)
			}

			out := aead.Seal(nonce, nonce, msg, []byte(*info))
			fmt.Printf("%s", out)

			os.Exit(0)
		}

		if *crypt == "dec" {
			nonce, msg := msg[:aead.NonceSize()], msg[aead.NonceSize():]

			out, err := aead.Open(nil, nonce, msg, []byte(*info))
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("%s", out)

			os.Exit(0)
		}
		os.Exit(0)
	}

	if *crypt != "" && (*cph == "chacha20") {
		var keyHex string
		keyHex = *key
		var key []byte
		var err error
		if keyHex == "" {
			key = make([]byte, 32)
			_, err = io.ReadFull(rand.Reader, key)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Fprintln(os.Stderr, "Key=", hex.EncodeToString(key))
		} else {
			key, err = hex.DecodeString(keyHex)
			if err != nil {
				log.Fatal(err)
			}
			if len(key) != 32 {
				log.Fatal("Invalid key size.")
			}
		}
		var nonce []byte
		nonce = make([]byte, 12)
		var iv []byte
		iv = make([]byte, 12)

		if *vector != "" {
			iv, _ = hex.DecodeString(*vector)
			copy(nonce[:], iv)
		} else {
			fmt.Fprintf(os.Stderr, "IV= %x\n", iv)
		}

		ciph, _ := chacha20.NewUnauthenticatedCipher(key, nonce)
		buf := make([]byte, 64*1<<10)
		var n int
		for {
			n, err = inputfile.Read(buf)
			if err != nil && err != io.EOF {
				log.Fatal(err)
			}
			ciph.XORKeyStream(buf[:n], buf[:n])
			if _, err := os.Stdout.Write(buf[:n]); err != nil {
				log.Fatal(err)
			}
			if err == io.EOF {
				break
			}
		}
		os.Exit(0)
	}

	if *crypt != "" && (*cph == "salsa20") {
		var keyHex string
		keyHex = *key
		var err error
		var key = [32]byte{}
		var raw []byte
		if keyHex == "" {
			raw := make([]byte, 32)
			_, err = io.ReadFull(rand.Reader, raw)
			if err != nil {
				log.Fatal(err)
			}
			key = *byte32(raw)
			fmt.Fprintln(os.Stderr, "Key=", hex.EncodeToString(key[:]))
		} else {
			raw, _ = hex.DecodeString(keyHex)
			copy(key[:], raw)
		}
		var nonce []byte
		nonce = make([]byte, 24)
		var iv []byte
		iv = make([]byte, 24)

		if *vector != "" {
			iv, _ = hex.DecodeString(*vector)
			copy(nonce[:], iv)
		} else {
			fmt.Fprintf(os.Stderr, "IV= %x\n", iv)
		}

		buf := make([]byte, 64*1<<10)
		var n int
		for {
			n, err = inputfile.Read(buf)
			if err != nil && err != io.EOF {
				log.Fatal(err)
			}
			salsa20.XORKeyStream(buf[:n], buf[:n], nonce[:], &key)
			if _, err := os.Stdout.Write(buf[:n]); err != nil {
				log.Fatal(err)
			}
			if err == io.EOF {
				break
			}
		}
		os.Exit(0)
	}

	if *crypt != "" && (*cph == "skein") {
		var keyHex string
		keyHex = *key
		var key []byte
		var err error
		if keyHex == "" {
			key = make([]byte, 32)
			_, err = io.ReadFull(rand.Reader, key)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Fprintln(os.Stderr, "Key=", hex.EncodeToString(key))
		} else {
			key, err = hex.DecodeString(keyHex)
			if err != nil {
				log.Fatal(err)
			}

		}
		var nonce []byte
		nonce = make([]byte, 32)
		var iv []byte
		iv = make([]byte, 32)

		if *vector != "" {
			iv, _ = hex.DecodeString(*vector)
			copy(nonce[:], iv)
		} else {
			fmt.Fprintf(os.Stderr, "IV= %x\n", iv)
		}

		ciph := skeincipher.NewStream(key, nonce)
		buf := make([]byte, 64*1<<10)
		var n int
		for {
			n, err = inputfile.Read(buf)
			if err != nil && err != io.EOF {
				log.Fatal(err)
			}
			ciph.XORKeyStream(buf[:n], buf[:n])
			if _, err := os.Stdout.Write(buf[:n]); err != nil {
				log.Fatal(err)
			}
			if err == io.EOF {
				break
			}
		}
		os.Exit(0)
	}

	if *crypt != "" && (*cph == "hc128" || *cph == "hc256") {
		var keyHex string
		var keyRaw []byte
		var err error
		keyHex = *key

		var ciph cipher.Stream
		if *cph == "hc256" {
			var key [32]byte
			if keyHex != "" {
				raw, _ := hex.DecodeString(keyHex)
				key = *byte32(raw)
			} else {
				keyRaw = make([]byte, 32)
				_, err = io.ReadFull(rand.Reader, keyRaw)
				if err != nil {
					log.Fatal(err)
				}
				key = *byte32(keyRaw)
				fmt.Fprintln(os.Stderr, "Key=", hex.EncodeToString(key[:]))
			}
			var nonce [32]byte
			var iv []byte
			iv = make([]byte, 32)
			if *vector != "" {
				iv, _ = hex.DecodeString(*vector)
				copy(nonce[:], iv)
			} else {
				fmt.Fprintf(os.Stderr, "IV= %x\n", nonce)
			}
			ciph = hc256.NewCipher(&nonce, &key)
			if len(key) != 32 {
				log.Fatal(err)
			}
		} else if *cph == "hc128" {
			var key [16]byte
			var raw []byte
			if keyHex != "" {
				raw, _ = hex.DecodeString(keyHex)
				key = *byte16(raw)
			} else {
				keyRaw = make([]byte, 16)
				_, err = io.ReadFull(rand.Reader, keyRaw)
				if err != nil {
					log.Fatal(err)
				}
				key = *byte16(keyRaw)
				fmt.Fprintln(os.Stderr, "Key=", hex.EncodeToString(key[:]))
			}
			var iv []byte
			iv = make([]byte, 16)
			var nonce [16]byte
			if *vector != "" {
				iv, _ = hex.DecodeString(*vector)
				copy(nonce[:], iv)
			} else {
				fmt.Fprintf(os.Stderr, "IV= %x\n", nonce)
			}
			copy(key[:], raw)
			ciph = hc128.NewCipher(&nonce, &key)
			if len(key) != 16 {
				log.Fatal(err)
			}
		}
		buf := make([]byte, 128*1<<10)
		var n int

		for {
			n, err = inputfile.Read(buf)
			if err != nil && err != io.EOF {
				log.Fatal(err)
			}
			ciph.XORKeyStream(buf[:n], buf[:n])
			if _, err := os.Stdout.Write(buf[:n]); err != nil {
				log.Fatal(err)
			}
			if err == io.EOF {
				break
			}
		}
		os.Exit(0)
	}

	if *crypt == "eea256" || (*crypt != "" && *cph == "zuc256") {
		var keyHex string
		keyHex = *key
		var key []byte
		var err error
		if keyHex == "" {
			key = make([]byte, 32)
			_, err = io.ReadFull(rand.Reader, key)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Fprintln(os.Stderr, "Key=", hex.EncodeToString(key))
		} else {
			key, err = hex.DecodeString(keyHex)
			if err != nil {
				log.Fatal(err)
			}
			if len(key) != 32 {
				log.Fatal("Invalid key size.")
			}
		}
		var nonce []byte
		if *vector != "" {
			nonce, _ = hex.DecodeString(*vector)
		} else {
			nonce = make([]byte, 23)
			fmt.Fprintf(os.Stderr, "IV= %x\n", nonce)
		}
		ciph, _ := zuc.NewCipher(key, nonce)
		buf := make([]byte, 64*1<<10)
		var n int
		for {
			n, err = inputfile.Read(buf)
			if err != nil && err != io.EOF {
				log.Fatal(err)
			}
			ciph.XORKeyStream(buf[:n], buf[:n])
			if _, err := os.Stdout.Write(buf[:n]); err != nil {
				log.Fatal(err)
			}
			if err == io.EOF {
				break
			}
		}
		os.Exit(0)
	}

	if *crypt == "eea128" || (*crypt != "" && *cph == "zuc128") {
		var keyHex string
		keyHex = *key
		var key []byte
		var err error
		if keyHex == "" {
			key = make([]byte, 16)
			_, err = io.ReadFull(rand.Reader, key)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Fprintln(os.Stderr, "Key=", hex.EncodeToString(key))
		} else {
			key, err = hex.DecodeString(keyHex)
			if err != nil {
				log.Fatal(err)
			}
			if len(key) != 16 {
				log.Fatal("Invalid key size.")
			}
		}
		var nonce []byte
		if *vector != "" {
			nonce, _ = hex.DecodeString(*vector)
		} else {
			nonce = make([]byte, 16)
			fmt.Fprintf(os.Stderr, "IV= %x\n", nonce)
		}
		ciph, _ := zuc.NewCipher(key, nonce)
		buf := make([]byte, 64*1<<10)
		var n int
		for {
			n, err = inputfile.Read(buf)
			if err != nil && err != io.EOF {
				log.Fatal(err)
			}
			ciph.XORKeyStream(buf[:n], buf[:n])
			if _, err := os.Stdout.Write(buf[:n]); err != nil {
				log.Fatal(err)
			}
			if err == io.EOF {
				break
			}
		}
		os.Exit(0)
	}

	if *mac == "eia256" || *mac == "zuc256" {
		var keyHex string
		var keyRaw []byte
		keyHex = *key
		var err error
		if keyHex == "" {
			keyRaw = make([]byte, 256/8)
			fmt.Fprintln(os.Stderr, "Key=", hex.EncodeToString(keyRaw))
		} else {
			keyRaw, err = hex.DecodeString(keyHex)
			if err != nil {
				log.Fatal(err)
			}
			if len(keyRaw) != 32 {
				log.Fatal("Invalid key size.")
			}
		}
		var nonce []byte
		if *vector != "" {
			nonce, err = hex.DecodeString(*vector)
			if err != nil {
				log.Fatal(err)
			}
		} else {
			nonce = make([]byte, 184/8)
			fmt.Fprintln(os.Stderr, "IV=", hex.EncodeToString(nonce))
		}
		h, _ := zuc.NewHash256(keyRaw, nonce, *length/8)
		if _, err := io.Copy(h, inputfile); err != nil {
			log.Fatal(err)
		}
		var verify bool
		if *sig != "" {
			mac := hex.EncodeToString(h.Sum(nil))
			if mac != *sig {
				verify = false
				fmt.Println(verify)
				os.Exit(1)
			} else {
				verify = true
				fmt.Println(verify)
				os.Exit(0)
			}
		}
		fmt.Printf("MAC-%s= %x\n", strings.ToUpper(*mac)+"("+inputdesc+")", h.Sum(nil))
		os.Exit(0)
	}

	if *mac == "eia128" || *mac == "zuc128" {
		var keyHex string
		var keyRaw []byte
		keyHex = *key
		var err error
		if keyHex == "" {
			keyRaw = make([]byte, 128/8)
			fmt.Fprintln(os.Stderr, "Key=", hex.EncodeToString(keyRaw))
		} else {
			keyRaw, err = hex.DecodeString(keyHex)
			if err != nil {
				log.Fatal(err)
			}
			if len(keyRaw) != 16 {
				log.Fatal("Invalid key size.")
			}
		}
		var nonce []byte
		if *vector != "" {
			nonce, err = hex.DecodeString(*vector)
			if err != nil {
				log.Fatal(err)
			}
		} else {
			nonce = make([]byte, 128/8)
			fmt.Fprintln(os.Stderr, "IV=", hex.EncodeToString(nonce))
		}
		h, _ := zuc.NewHash(keyRaw, nonce)
		if _, err := io.Copy(h, inputfile); err != nil {
			log.Fatal(err)
		}
		var verify bool
		if *sig != "" {
			mac := hex.EncodeToString(h.Sum(nil))
			if mac != *sig {
				verify = false
				fmt.Println(verify)
				os.Exit(1)
			} else {
				verify = true
				fmt.Println(verify)
				os.Exit(0)
			}
		}
		fmt.Printf("MAC-%s= %x\n", strings.ToUpper(*mac)+"("+inputdesc+")", h.Sum(nil))
		os.Exit(0)
	}

	if *mac == "chaskey" {
		var keyRaw []byte
		if *key == "" {
			keyRaw = []byte("0000000000000000")
			fmt.Fprintf(os.Stderr, "Key= %s\n", keyRaw)
		} else {
			keyRaw = []byte(*key)
		}
		if len([]byte(keyRaw)) != 16 {
			log.Fatal("CHASKEY secret key must have 16 bytes.")
		}
		xkey := [4]uint32{binary.LittleEndian.Uint32([]byte(keyRaw)[:]),
			binary.LittleEndian.Uint32([]byte(keyRaw)[4:]),
			binary.LittleEndian.Uint32([]byte(keyRaw)[8:]),
			binary.LittleEndian.Uint32([]byte(keyRaw)[12:]),
		}
		var t [32]byte
		h := chaskey.New(xkey)
		line, _ := ioutil.ReadAll(inputfile)
		var verify bool
		if *sig != "" {
			mac := hex.EncodeToString(h.MAC(line, t[:]))
			if mac != *sig {
				verify = false
				fmt.Println(verify)
				os.Exit(1)
			} else {
				verify = true
				fmt.Println(verify)
				os.Exit(0)
			}
		}
		fmt.Printf("MAC-CHASKEY("+inputdesc+")= %s\n", hex.EncodeToString(h.MAC(line, t[:])))
		os.Exit(0)
	}

	if *crypt != "" && (*cph == "aes" || *cph == "anubis" || *cph == "aria" || *cph == "lea" || *cph == "seed" || *cph == "lea" || *cph == "sm4" || *cph == "camellia" || *cph == "grasshopper" || *cph == "kuznechik" || *cph == "magma" || *cph == "gost89" || *cph == "twofish" || *cph == "serpent" || *cph == "rc6" || *cph == "khazad" || *cph == "present" || *cph == "twine" || *cph == "mars" || *cph == "mars2" || *cph == "noekeon" || *cph == "clefia" || *cph == "crypton" || *cph == "e2") && (strings.ToUpper(*mode) == "GCM" || strings.ToUpper(*mode) == "MGM" || strings.ToUpper(*mode) == "OCB" || strings.ToUpper(*mode) == "OCB1" || strings.ToUpper(*mode) == "OCB3" || strings.ToUpper(*mode) == "EAX" || strings.ToUpper(*mode) == "CCM") {
		var keyHex string
		keyHex = *key
		var key []byte
		var err error
		if keyHex == "" {
			key = make([]byte, *length/8)
			_, err = io.ReadFull(rand.Reader, key)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Fprintln(os.Stderr, "Key=", hex.EncodeToString(key))
		} else {
			key, err = hex.DecodeString(keyHex)
			if err != nil {
				log.Fatal(err)
			}
			if len(key) != 40 && len(key) != 32 && len(key) != 24 && len(key) != 16 {
				log.Fatal("Invalid key size.")
			}
		}
		var ciph cipher.Block
		var n int
		if *cph == "aes" {
			ciph, err = aes.NewCipher(key)
			n = 16
		} else if *cph == "twofish" {
			ciph, err = twofish.NewCipher(key)
			n = 16
		} else if *cph == "aria" {
			ciph, err = aria.NewCipher(key)
			n = 16
		} else if *cph == "lea" {
			ciph, err = lea.NewCipher(key)
			n = 16
		} else if *cph == "camellia" {
			ciph, err = camellia.NewCipher(key)
			n = 16
		} else if *cph == "serpent" {
			ciph, err = serpent.NewCipher(key)
			n = 16
		} else if *cph == "grasshopper" || *cph == "kuznechik" {
			ciph, err = kuznechik.NewCipher(key)
			n = 16
		} else if *cph == "sm4" {
			ciph, err = sm4.NewCipher(key)
			n = 16
		} else if *cph == "seed" {
			ciph, err = krcrypt.NewSEED(key)
			n = 16
		} else if *cph == "anubis" {
			ciph, err = anubis.NewWithKeySize(key, len(key))
			n = 16
		} else if *cph == "magma" {
			ciph = gost341264.NewCipher(key)
			n = 8
		} else if *cph == "gost89" {
			ciph = gost28147.NewCipher(key, &gost28147.SboxIdtc26gost28147paramZ)
			n = 8
		} else if *cph == "rc6" {
			ciph, err = rc6.NewCipher(key)
			n = 16
		} else if *cph == "khazad" {
			ciph, err = khazad.NewCipher(key)
			n = 8
		} else if *cph == "present" {
			ciph, err = present.NewCipher(key)
			n = 8
		} else if *cph == "twine" {
			ciph, err = twine.New(key)
			n = 8
		} else if *cph == "mars" {
			ciph, err = mars.NewCipher(key)
			n = 16
		} else if *cph == "mars2" {
			ciph, err = mars2.NewCipher(key)
			n = 16
		} else if *cph == "noekeon" {
			ciph, err = noekeon.NewCipher(key)
			n = 16
		} else if *cph == "clefia" {
			ciph, err = clefia.NewCipher(key)
			n = 16
		} else if *cph == "crypton" {
			ciph, err = crypton1.NewCipher(key)
			n = 16
		} else if *cph == "e2" {
			ciph, err = e2.NewCipher(key)
			n = 16
		}
		if err != nil {
			log.Fatal(err)
		}

		var aead cipher.AEAD
		if strings.ToUpper(*mode) == "GCM" {
			aead, err = cipher.NewGCMWithTagSize(ciph, 16)
		} else if strings.ToUpper(*mode) == "MGM" {
			aead, err = mgm.NewMGM(ciph, n)
		} else if strings.ToUpper(*mode) == "OCB" || strings.ToUpper(*mode) == "OCB1" {
			aead, err = ocb.NewOCB(ciph)
		} else if strings.ToUpper(*mode) == "OCB3" {
			aead, err = ocb3.New(ciph)
		} else if strings.ToUpper(*mode) == "EAX" {
			aead, err = eax.NewEAX(ciph)
		} else if strings.ToUpper(*mode) == "CCM" {
			aead, err = ccm.NewCCM(ciph, 16, 12)
		}
		if err != nil {
			log.Fatal(err)
		}

		buf := bytes.NewBuffer(nil)
		io.Copy(buf, inputfile)
		msg := buf.Bytes()

		if *crypt == "enc" {
			nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(msg)+aead.Overhead())

			if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
				log.Fatal(err)
			}
			nonce[0] &= 0x7F

			out := aead.Seal(nonce, nonce, msg, []byte(*info))
			fmt.Printf("%s", out)

			os.Exit(0)
		}

		if *crypt == "dec" {
			nonce, msg := msg[:aead.NonceSize()], msg[aead.NonceSize():]

			out, err := aead.Open(nil, nonce, msg, []byte(*info))
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("%s", out)

			os.Exit(0)
		}
		os.Exit(0)
	}

	if *crypt != "" && (strings.ToUpper(*mode) == "ECB" || strings.ToUpper(*mode) == "CBC" || strings.ToUpper(*mode) == "IGE") {
		var keyHex string
		keyHex = *key
		var err error
		var key []byte

		if keyHex == "" {
			key = make([]byte, *length/8)
			if *cph == "3des" {
				key = make([]byte, 24)
			}
			_, err = io.ReadFull(rand.Reader, key)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Fprintln(os.Stderr, "Key=", hex.EncodeToString(key))
		} else {
			key, err = hex.DecodeString(keyHex)
			if err != nil {
				log.Fatal(err)
			}
			if len(key) != 128 && len(key) != 64 && len(key) != 40 && len(key) != 32 && len(key) != 24 && len(key) != 16 && len(key) != 10 && len(key) != 8 {
				log.Fatal("Invalid key size.")
			}
		}

		var ciph cipher.Block
		var n int
		var tweak []byte
		tweak = make([]byte, 16)
		if *cph == "aes" {
			ciph, err = aes.NewCipher(key)
			n = 16
		} else if *cph == "twofish" {
			ciph, err = twofish.NewCipher(key)
			n = 16
		} else if *cph == "aria" {
			ciph, err = aria.NewCipher(key)
			n = 16
		} else if *cph == "lea" {
			ciph, err = lea.NewCipher(key)
			n = 16
		} else if *cph == "camellia" {
			ciph, err = camellia.NewCipher(key)
			n = 16
		} else if *cph == "serpent" {
			ciph, err = serpent.NewCipher(key)
			n = 16
		} else if *cph == "grasshopper" || *cph == "kuznechik" {
			ciph, err = kuznechik.NewCipher(key)
			n = 16
		} else if *cph == "sm4" {
			ciph, err = sm4.NewCipher(key)
			n = 16
		} else if *cph == "seed" {
			ciph, err = krcrypt.NewSEED(key)
			n = 16
		} else if *cph == "hight" {
			ciph, err = krcrypt.NewHIGHT(key)
			n = 8
		} else if *cph == "anubis" {
			ciph, err = anubis.NewWithKeySize(key, len(key))
			n = 16
		} else if *cph == "magma" {
			ciph = gost341264.NewCipher(key)
			n = 8
		} else if *cph == "gost89" {
			ciph = gost28147.NewCipher(key, &gost28147.SboxIdtc26gost28147paramZ)
			n = 8
		} else if *cph == "3des" {
			ciph, err = des.NewTripleDESCipher(key)
			n = 8
		} else if *cph == "des" {
			ciph, err = des.NewCipher(key)
			n = 8
		} else if *cph == "rc2" {
			ciph, err = rc2.NewCipher(key)
			n = 8
		} else if *cph == "rc5" {
			ciph, err = rc5.New(key)
			n = 8
		} else if *cph == "rc6" {
			ciph, err = rc6.NewCipher(key)
			n = 16
		} else if *cph == "idea" {
			ciph, _ = idea.NewCipher(key)
			n = 8
		} else if *cph == "blowfish" {
			ciph, err = blowfish.NewCipher(key)
			n = 8
		} else if *cph == "cast5" {
			ciph, err = cast5.NewCipher(key)
			n = 8
		} else if *cph == "misty1" {
			ciph, err = misty1.New(key)
			n = 8
		} else if *cph == "threefish256" || *cph == "threefish" {
			if *info != "" {
				tweak = []byte(*info)
			}
			n = 32
			ciph, err = threefish.New256(key, tweak)
		} else if *cph == "threefish512" {
			if *info != "" {
				tweak = []byte(*info)
			}
			n = 64
			ciph, err = threefish.New512(key, tweak)
		} else if *cph == "threefish1024" {
			if *info != "" {
				tweak = []byte(*info)
			}
			n = 128
			ciph, err = threefish.New1024(key, tweak)
		} else if *cph == "khazad" {
			ciph, err = khazad.NewCipher(key)
			n = 8
		} else if *cph == "present" {
			ciph, err = present.NewCipher(key)
			n = 8
		} else if *cph == "twine" {
			ciph, err = twine.New(key)
			n = 8
		} else if *cph == "mars" {
			ciph, err = mars.NewCipher(key)
			n = 16
		} else if *cph == "mars2" {
			ciph, err = mars2.NewCipher(key)
			n = 16
		} else if *cph == "noekeon" {
			ciph, err = noekeon.NewCipher(key)
			n = 16
		} else if *cph == "clefia" {
			ciph, err = clefia.NewCipher(key)
			n = 16
		} else if *cph == "crypton" {
			ciph, err = crypton1.NewCipher(key)
			n = 16
		} else if *cph == "e2" {
			ciph, err = e2.NewCipher(key)
			n = 16
		}
		if err != nil {
			log.Fatal(err)
		}

		var iv []byte
		if strings.ToUpper(*mode) == "CBC" || strings.ToUpper(*mode) == "ECB" {
			iv = make([]byte, n)
		} else {
			iv = make([]byte, n*2)
		}

		if *vector != "" {
			iv, _ = hex.DecodeString(*vector)
		} else if strings.ToUpper(*mode) == "CBC" || strings.ToUpper(*mode) == "IGE" {
			fmt.Fprintf(os.Stderr, "IV= %x\n", iv)
		}
		if err != nil {
			log.Fatal(err)
		}
		if *crypt == "enc" {
			buf := bytes.NewBuffer(nil)
			io.Copy(buf, inputfile)
			plaintext := buf.Bytes()
			plaintext = PKCS7Padding(plaintext)
			ciphertext := make([]byte, len(plaintext))
			var blockmode cipher.BlockMode
			if strings.ToUpper(*mode) == "ECB" {
				blockmode = ecb.NewECBEncrypter(ciph)
			} else if strings.ToUpper(*mode) == "CBC" {
				blockmode = cipher.NewCBCEncrypter(ciph, iv)
			} else if strings.ToUpper(*mode) == "IGE" {
				blockmode = ige.NewIGEEncrypter(ciph, iv)
			}
			blockmode.CryptBlocks(ciphertext, plaintext)
			fmt.Printf("%s", ciphertext)
		} else if *crypt == "dec" {
			buf := bytes.NewBuffer(nil)
			io.Copy(buf, inputfile)
			ciphertext := buf.Bytes()
			plaintext := make([]byte, len(ciphertext))
			var blockmode cipher.BlockMode
			if strings.ToUpper(*mode) == "ECB" {
				blockmode = ecb.NewECBDecrypter(ciph)
			} else if strings.ToUpper(*mode) == "CBC" {
				blockmode = cipher.NewCBCDecrypter(ciph, iv)
			} else if strings.ToUpper(*mode) == "IGE" {
				blockmode = ige.NewIGEDecrypter(ciph, iv)
			}
			blockmode.CryptBlocks(plaintext, ciphertext)
			plaintext = PKCS7UnPadding(plaintext)
			fmt.Printf("%s", plaintext)
		}
		os.Exit(0)
	}

	if *crypt != "" && (*cph == "aes" || *cph == "aria" || *cph == "lea" || *cph == "camellia" || *cph == "magma" || *cph == "grasshopper" || *cph == "kuznechik" || *cph == "gost89" || *cph == "twofish" || *cph == "serpent" || *cph == "rc6" || *cph == "threefish" || *cph == "threefish256" || *cph == "threefish512" || *cph == "threefish1024" || *cph == "mars" || *cph == "mars2" || *cph == "noekeon" || *cph == "clefia" || *cph == "crypton" || *cph == "e2") {
		var keyHex string
		keyHex = *key
		var err error
		var key []byte

		if keyHex == "" {
			key = make([]byte, *length/8)
			_, err = io.ReadFull(rand.Reader, key)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Fprintln(os.Stderr, "Key=", hex.EncodeToString(key))
		} else {
			key, err = hex.DecodeString(keyHex)
			if err != nil {
				log.Fatal(err)
			}
			if len(key) != 40 && len(key) != 32 && len(key) != 24 && len(key) != 16 {
				log.Fatal("Invalid key size.")
			}
		}
		var ciph cipher.Block
		var iv []byte
		var tweak []byte
		tweak = make([]byte, 16)
		if *cph == "aes" {
			ciph, err = aes.NewCipher(key)
			iv = make([]byte, 16)
		} else if *cph == "twofish" {
			ciph, err = twofish.NewCipher(key)
			iv = make([]byte, 16)
		} else if *cph == "aria" {
			ciph, err = aria.NewCipher(key)
			iv = make([]byte, 16)
		} else if *cph == "lea" {
			ciph, err = lea.NewCipher(key)
			iv = make([]byte, 16)
		} else if *cph == "camellia" {
			ciph, err = camellia.NewCipher(key)
			iv = make([]byte, 16)
		} else if *cph == "serpent" {
			ciph, err = serpent.NewCipher(key)
			iv = make([]byte, 16)
		} else if *cph == "rc6" {
			ciph, err = rc6.NewCipher(key)
			iv = make([]byte, 16)
		} else if *cph == "magma" {
			ciph = gost341264.NewCipher(key)
			iv = make([]byte, 8)
		} else if *cph == "gost89" {
			ciph = gost28147.NewCipher(key, &gost28147.SboxIdtc26gost28147paramZ)
			iv = make([]byte, 8)
		} else if *cph == "grasshopper" || *cph == "kuznechik" {
			ciph, err = kuznechik.NewCipher(key)
			iv = make([]byte, 16)
		} else if *cph == "threefish256" || *cph == "threefish" {
			if *info != "" {
				tweak = []byte(*info)
			}
			iv = make([]byte, 32)
			ciph, err = threefish.New256(key, tweak)
		} else if *cph == "threefish512" {
			if *info != "" {
				tweak = []byte(*info)
			}
			iv = make([]byte, 64)
			ciph, err = threefish.New512(key, tweak)
		} else if *cph == "threefish1024" {
			if *info != "" {
				tweak = []byte(*info)
			}
			iv = make([]byte, 128)
			ciph, err = threefish.New1024(key, tweak)
		} else if *cph == "mars" {
			ciph, err = mars.NewCipher(key)
			iv = make([]byte, 16)
		} else if *cph == "mars2" {
			ciph, err = mars2.NewCipher(key)
			iv = make([]byte, 16)
		} else if *cph == "noekeon" {
			ciph, err = noekeon.NewCipher(key)
			iv = make([]byte, 16)
		} else if *cph == "clefia" {
			ciph, err = clefia.NewCipher(key)
			iv = make([]byte, 16)
		} else if *cph == "crypton" {
			ciph, err = crypton1.NewCipher(key)
			iv = make([]byte, 16)
		} else if *cph == "e2" {
			ciph, err = e2.NewCipher(key)
			iv = make([]byte, 16)
		}
		if err != nil {
			log.Fatal(err)
		}
		if *vector != "" {
			iv, _ = hex.DecodeString(*vector)
		} else {
			fmt.Fprintf(os.Stderr, "IV= %x\n", iv)
		}
		var stream cipher.Stream
		if strings.ToUpper(*mode) == "CTR" {
			stream = cipher.NewCTR(ciph, iv)
		} else if strings.ToUpper(*mode) == "OFB" {
			stream = cipher.NewOFB(ciph, iv)
		} else if *crypt == "enc" && strings.ToUpper(*mode) == "CFB8" {
			stream = CFB8.NewCFB8Encrypt(ciph, iv)
		} else if *crypt == "dec" && strings.ToUpper(*mode) == "CFB8" {
			stream = CFB8.NewCFB8Decrypt(ciph, iv)
		} else if *crypt == "enc" && strings.ToUpper(*mode) == "CFB" {
			stream = cipher.NewCFBEncrypter(ciph, iv)
		} else if *crypt == "dec" && strings.ToUpper(*mode) == "CFB" {
			stream = cipher.NewCFBDecrypter(ciph, iv)
		}
		buf := make([]byte, 128*1<<10)
		var n int
		for {
			n, err = inputfile.Read(buf)
			if err != nil && err != io.EOF {
				log.Fatal(err)
			}
			stream.XORKeyStream(buf[:n], buf[:n])
			if _, err := os.Stdout.Write(buf[:n]); err != nil {
				log.Fatal(err)
			}
			if err == io.EOF {
				break
			}
		}
		os.Exit(0)
	}

	if *crypt != "" && (*cph == "blowfish" || *cph == "idea" || *cph == "cast5" || *cph == "rc2" || *cph == "rc5" || *cph == "sm4" || *cph == "des" || *cph == "3des" || *cph == "seed" || *cph == "hight" || *cph == "misty1" || *cph == "anubis" || *cph == "khazad" || *cph == "present" || *cph == "twine") {
		var keyHex string
		keyHex = *key
		var key []byte
		var err error
		if keyHex == "" {
			key = make([]byte, *length/8)
			if *cph == "3des" {
				key = make([]byte, 24)
			}
			_, err = io.ReadFull(rand.Reader, key)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Fprintln(os.Stderr, "Key=", hex.EncodeToString(key))
		} else {
			key, err = hex.DecodeString(keyHex)
			if err != nil {
				log.Fatal(err)
			}
			if len(key) != 32 && len(key) != 40 && len(key) != 16 && len(key) != 10 && len(key) != 24 {
				log.Fatal("Invalid key size.")
			}
		}
		var ciph cipher.Block
		var iv []byte
		if *cph == "blowfish" {
			ciph, err = blowfish.NewCipher(key)
			iv = make([]byte, 8)
		} else if *cph == "idea" {
			ciph, err = idea.NewCipher(key)
			iv = make([]byte, 8)
		} else if *cph == "cast5" {
			ciph, err = cast5.NewCipher(key)
			iv = make([]byte, 8)
		} else if *cph == "rc5" {
			ciph, err = rc5.New(key)
			iv = make([]byte, 8)
		} else if *cph == "sm4" {
			ciph, err = sm4.NewCipher(key)
			iv = make([]byte, 16)
		} else if *cph == "seed" {
			ciph, err = krcrypt.NewSEED(key)
			iv = make([]byte, 16)
		} else if *cph == "hight" {
			ciph, err = krcrypt.NewHIGHT(key)
			iv = make([]byte, 8)
		} else if *cph == "anubis" {
			ciph, err = anubis.NewWithKeySize(key, len(key))
			iv = make([]byte, 16)
		} else if *cph == "rc2" {
			ciph, err = rc2.NewCipher(key)
			iv = make([]byte, 8)
		} else if *cph == "des" {
			ciph, err = des.NewCipher(key)
			iv = make([]byte, 8)
		} else if *cph == "3des" {
			ciph, err = des.NewTripleDESCipher(key)
			iv = make([]byte, 8)
		} else if *cph == "misty1" {
			ciph, err = misty1.New(key)
			iv = make([]byte, 8)
		} else if *cph == "khazad" {
			ciph, err = khazad.NewCipher(key)
			iv = make([]byte, 8)
		} else if *cph == "present" {
			ciph, err = present.NewCipher(key)
			iv = make([]byte, 8)
		} else if *cph == "twine" {
			ciph, err = twine.New(key)
			iv = make([]byte, 8)
		}
		if err != nil {
			log.Fatal(err)
		}
		if *vector != "" {
			iv, _ = hex.DecodeString(*vector)
		} else {
			fmt.Fprintf(os.Stderr, "IV= %x\n", iv)
		}
		var stream cipher.Stream
		if strings.ToUpper(*mode) == "CTR" {
			stream = cipher.NewCTR(ciph, iv)
		} else if strings.ToUpper(*mode) == "OFB" {
			stream = cipher.NewOFB(ciph, iv)
		} else if *crypt == "enc" && strings.ToUpper(*mode) == "CFB8" {
			stream = CFB8.NewCFB8Encrypt(ciph, iv)
		} else if *crypt == "dec" && strings.ToUpper(*mode) == "CFB8" {
			stream = CFB8.NewCFB8Decrypt(ciph, iv)
		} else if *crypt == "enc" && strings.ToUpper(*mode) == "CFB" {
			stream = cipher.NewCFBEncrypter(ciph, iv)
		} else if *crypt == "dec" && strings.ToUpper(*mode) == "CFB" {
			stream = cipher.NewCFBDecrypter(ciph, iv)
		}
		buf := make([]byte, 128*1<<10)
		var n int
		for {
			n, err = inputfile.Read(buf)
			if err != nil && err != io.EOF {
				log.Fatal(err)
			}
			stream.XORKeyStream(buf[:n], buf[:n])
			if _, err := os.Stdout.Write(buf[:n]); err != nil {
				log.Fatal(err)
			}
			if err == io.EOF {
				break
			}
		}
		os.Exit(0)
	}

	if *digest && (*md == "bcrypt") && !*check {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(*key), *iter)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(string(hashedPassword))
		os.Exit(0)
	}

	if *md == "bcrypt" && *check {
		hashedPassword, err := ioutil.ReadAll(inputfile)
		if err != nil {
			log.Fatal(err)
		}
		err = bcrypt.CompareHashAndPassword(hashedPassword, []byte(*key))
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("Verify: true")
		os.Exit(0)
	}

	if *digest && *md == "argon2" && !*check {
		hash := argon2.IDKey([]byte(*key), []byte(*salt), uint32(*iter), 64*1024, 4, uint32(*length/8))
		fmt.Println(hex.EncodeToString(hash))
		os.Exit(0)
	}

	if *md == "argon2" && *check {
		hashedPassword, err := ioutil.ReadAll(inputfile)
		if err != nil {
			log.Fatal(err)
		}
		hashedPasswordString := strings.TrimSpace(string(hashedPassword))
		computedHash := argon2.IDKey([]byte(*key), []byte(*salt), uint32(*iter), 64*1024, 4, uint32(*length/8))
		computedHashString := hex.EncodeToString(computedHash)

		if computedHashString == hashedPasswordString {
			fmt.Println("Verify: true")
		} else {
			fmt.Println("Verify: false")
			os.Exit(1)
		}
		os.Exit(0)
	}

	if *digest && *md == "lyra2" && !*check {
		passwordBytes := []byte(*key + *salt)
		hash, err := lyra2re.Sum(passwordBytes)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(hex.EncodeToString(hash))
		os.Exit(0)
	}

	if *md == "lyra2" && *check {
		passwordBytes := []byte(*key + *salt)
		hash, err := lyra2re.Sum(passwordBytes)
		if err != nil {
			log.Fatal(err)
		}
		computedHashString := hex.EncodeToString(hash)

		hashedPassword, err := ioutil.ReadAll(inputfile)
		if err != nil {
			log.Fatal(err)
		}
		hashedPasswordString := strings.TrimSpace(string(hashedPassword))

		if computedHashString == hashedPasswordString {
			fmt.Println("Verify: true")
		} else {
			fmt.Println("Verify: false")
			os.Exit(1)
		}
		os.Exit(0)
	}

	/*
		if *digest && *alg == "makwa" && !*check {
			var params makwa.PublicParameters
			bits := *length
			privateParams, err := makwa.GenerateParameters(bits)
			if err != nil {
				log.Fatal(err)
			}
			params.N = privateParams.N
			params.Hash = myHash

			fmt.Println("Modulus=", params.N)
			fmt.Println("FactorP=", privateParams.P)
			fmt.Println("FactorQ=", privateParams.Q)

			digest, err := makwa.Hash(params, []byte(*key), []byte(*salt), *iter, false, 0)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Println("Digest=", digest)
			os.Exit(0)
		}

		if *alg == "makwa" && *check {
			var params makwa.PublicParameters
			hashedPassword, err := ioutil.ReadAll(inputfile)
			if err != nil {
				log.Fatal(err)
			}
			hashedPasswordString := strings.TrimSpace(string(hashedPassword))
			modulus := new(big.Int)
			_, success := modulus.SetString(*modulusStr, 10)
			if !success {
				log.Fatal("Failed to parse modulus")
			}

			params.N = modulus
			params.Hash = myHash

			digest := &makwa.Digest{}
			err = digest.UnmarshalText([]byte(hashedPasswordString))
			if err != nil {
				log.Fatal(err)
			}
			isValid := makwa.CheckPassword(params, digest, []byte(*key))
			if isValid == nil {
				fmt.Println("Verified: true")
				os.Exit(0)
			} else {
				fmt.Println("Verified: false")
				os.Exit(1)
			}
		}

		if *recover {
			hashedPassword, err := ioutil.ReadAll(inputfile)
			if err != nil {
				log.Fatal(err)
			}
			hashedPasswordString := strings.TrimSpace(string(hashedPassword))
			modulus := new(big.Int)
			_, success := modulus.SetString(*modulusStr, 10)
			if !success {
				log.Fatal("Failed to parse modulus")
			}
			factor1 := new(big.Int)
			factor1, success = factor1.SetString(*factorPStr, 10)
			if !success {
				log.Fatal("Failed to parse factor1")
			}
			factor2 := new(big.Int)
			factor2, success = factor2.SetString(*factorQStr, 10)
			if !success {
				log.Fatal("Failed to parse factor2")
			}
			digest := &makwa.Digest{}
			err = digest.UnmarshalText([]byte(hashedPasswordString))
			if err != nil {
				log.Fatal(err)
			}

			params := makwa.PrivateParameters{
				PublicParameters: makwa.PublicParameters{
					N:    modulus,
					Hash: myHash,
				},
				P: factor1,
				Q: factor2,
			}

			originalKey, err := makwa.Recover(params, digest)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("%s\n", originalKey)
			os.Exit(0)
		}
	*/
	if *digest && *alg == "makwa" && !*check {
		var params makwa.PublicParameters
		bits := *length
		privateParams, err := makwa.GenerateParameters(bits)
		if err != nil {
			log.Fatal(err)
		}
		params.N = privateParams.N
		params.Hash = myHash

		fmt.Printf("Modulus= %x\n", params.N)
		fmt.Printf("FactorP= %x\n", privateParams.P)
		fmt.Printf("FactorQ= %x\n", privateParams.Q)

		digest, err := makwa.Hash(params, []byte(*key), []byte(*salt), *iter, false, 0)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("Digest=", digest)
		os.Exit(0)
	}

	if *alg == "makwa" && *check {
		var params makwa.PublicParameters
		hashedPassword, err := ioutil.ReadAll(inputfile)
		if err != nil {
			log.Fatal(err)
		}
		hashedPasswordString := strings.TrimSpace(string(hashedPassword))
		modulus := new(big.Int)
		_, success := modulus.SetString(*modulusStr, 16)
		if !success {
			log.Fatal("Failed to parse modulus")
		}

		params.N = modulus
		params.Hash = myHash

		digest := &makwa.Digest{}
		err = digest.UnmarshalText([]byte(hashedPasswordString))
		if err != nil {
			log.Fatal(err)
		}
		isValid := makwa.CheckPassword(params, digest, []byte(*key))
		if isValid == nil {
			fmt.Println("Verified: true")
			os.Exit(0)
		} else {
			fmt.Println("Verified: false")
			os.Exit(1)
		}
	}

	if *recover {
		hashedPassword, err := ioutil.ReadAll(inputfile)
		if err != nil {
			log.Fatal(err)
		}
		hashedPasswordString := strings.TrimSpace(string(hashedPassword))
		modulus := new(big.Int)
		_, success := modulus.SetString(*modulusStr, 16)
		if !success {
			log.Fatal("Failed to parse modulus")
		}
		factor1 := new(big.Int)
		factor1, success = factor1.SetString(*factorPStr, 16)
		if !success {
			log.Fatal("Failed to parse factor1")
		}
		factor2 := new(big.Int)
		factor2, success = factor2.SetString(*factorQStr, 16)
		if !success {
			log.Fatal("Failed to parse factor2")
		}
		digest := &makwa.Digest{}
		err = digest.UnmarshalText([]byte(hashedPasswordString))
		if err != nil {
			log.Fatal(err)
		}

		params := makwa.PrivateParameters{
			PublicParameters: makwa.PublicParameters{
				N:    modulus,
				Hash: myHash,
			},
			P: factor1,
			Q: factor2,
		}

		originalKey, err := makwa.Recover(params, digest)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s\n", originalKey)
		os.Exit(0)
	}

	if *digest && (*md == "haraka" || *md == "haraka256") {
		xkey := new([32]byte)
		gkey := new([32]byte)
		b, err := ioutil.ReadAll(inputfile)
		if err != nil {
			log.Fatal(err)
		}
		if len(b)*8 > 256 {
			fmt.Fprintf(os.Stderr, "Alert: The plain text exceeds 256 bits!\n")
		}
		copy(xkey[:], b)
		haraka.Haraka256(gkey, xkey)
		fmt.Printf("%x\n", gkey[:])
		os.Exit(0)
	}

	if *digest && *md == "haraka512" {
		xkey := new([64]byte)
		gkey := new([32]byte)
		b, err := ioutil.ReadAll(inputfile)
		if err != nil {
			log.Fatal(err)
		}
		if len(b)*8 > 512 {
			fmt.Fprintf(os.Stderr, "Alert: The plain text exceeds 512 bits!\n")
		}
		copy(xkey[:], b)
		haraka.Haraka512(gkey, xkey)
		fmt.Printf("%x\n", gkey[:])
		os.Exit(0)
	}

	if *digest && (Files == "-" || Files == "") {
		var h hash.Hash
		if *md == "sha224" {
			h = sha256.New224()
		} else if *md == "sha256" {
			h = sha256.New()
		} else if *md == "sha384" {
			h = sha512.New384()
		} else if *md == "sha512-256" {
			h = sha512.New512_256()
		} else if *md == "sha512" {
			h = sha512.New()
		} else if *md == "sha1" {
			h = sha1.New()
		} else if *md == "rmd160" {
			h = ripemd160.New()
		} else if *md == "rmd128" {
			h = ripemd.New128()
		} else if *md == "rmd256" {
			h = ripemd.New256()
		} else if *md == "rmd320" {
			h = ripemd.New320()
		} else if *md == "sha3-224" {
			h = sha3.New224()
		} else if *md == "sha3-256" {
			h = sha3.New256()
		} else if *md == "sha3-384" {
			h = sha3.New384()
		} else if *md == "sha3-512" {
			h = sha3.New512()
		} else if *md == "shake128" {
			h = sha3.NewShake128()
		} else if *md == "shake256" {
			h = sha3.NewShake256()
		} else if *md == "lsh224" || *md == "lsh256-224" {
			h = lsh256.New224()
		} else if *md == "lsh" || *md == "lsh256" || *md == "lsh256-256" {
			h = lsh256.New()
		} else if *md == "lsh512-224" {
			h = lsh512.New224()
		} else if *md == "lsh512-256" {
			h = lsh512.New256()
		} else if *md == "lsh384" || *md == "lsh512-384" {
			h = lsh512.New384()
		} else if *md == "lsh512" {
			h = lsh512.New()
		} else if *md == "has160" {
			h = has160.New()
		} else if *md == "keccak" || *md == "keccak256" {
			h = sha3.NewLegacyKeccak256()
		} else if *md == "keccak512" {
			h = sha3.NewLegacyKeccak512()
		} else if *md == "whirlpool" {
			h = whirlpool.New()
		} else if *md == "blake2b256" {
			h, _ = blake2b.New256([]byte(*key))
		} else if *md == "blake2b512" {
			h, _ = blake2b.New512([]byte(*key))
		} else if *md == "blake2s128" {
			h, _ = blake2s.New128([]byte(*key))
		} else if *md == "blake2s256" {
			h, _ = blake2s.New256([]byte(*key))
		} else if *md == "blake3" {
			h = blake3.New()
		} else if *md == "md5" {
			h = md5.New()
		} else if *md == "gost94" {
			h = gost341194.New(&gost28147.SboxIdGostR341194CryptoProParamSet)
		} else if *md == "streebog" || *md == "streebog256" {
			h = gost34112012256.New()
		} else if *md == "streebog512" {
			h = gost34112012512.New()
		} else if *md == "sm3" {
			h = sm3.New()
		} else if *md == "md4" {
			h = md4.New()
		} else if *md == "siphash" || *md == "siphash128" {
			var xkey [16]byte
			copy(xkey[:], []byte(*key))
			h, _ = siphash.New128(xkey[:])
		} else if *md == "siphash64" {
			var xkey [16]byte
			copy(xkey[:], []byte(*key))
			h, _ = siphash.New64(xkey[:])
		} else if *md == "cubehash" {
			h = cubehash.New()
		} else if *md == "xoodyak" || *md == "xhash" {
			h = xoodyak.NewXoodyakHash()
		} else if *md == "skein" || *md == "skein256" {
			h = skein.New256([]byte(*key))
		} else if *md == "skein512" {
			h = skein.New512([]byte(*key))
		} else if *md == "jh" {
			h = jh.New256()
		} else if *md == "groestl" {
			h = groestl.New256()
		} else if *md == "tiger" {
			h = tiger.New()
		} else if *md == "tiger2" {
			h = tiger.New2()
		}
		io.Copy(h, os.Stdin)
		fmt.Println(hex.EncodeToString(h.Sum(nil)), "(stdin)")
		os.Exit(0)
	}

	if *digest && *recursive == false {
		for _, wildcard := range flag.Args() {
			files, err := filepath.Glob(wildcard)
			if err != nil {
				log.Fatal(err)
			}
			for _, match := range files {
				var h hash.Hash
				if *md == "sha224" {
					h = sha256.New224()
				} else if *md == "sha256" {
					h = sha256.New()
				} else if *md == "sha512-256" {
					h = sha512.New512_256()
				} else if *md == "sha384" {
					h = sha512.New384()
				} else if *md == "sha512" {
					h = sha512.New()
				} else if *md == "sha1" {
					h = sha1.New()
				} else if *md == "rmd160" {
					h = ripemd160.New()
				} else if *md == "rmd128" {
					h = ripemd.New128()
				} else if *md == "rmd256" {
					h = ripemd.New256()
				} else if *md == "rmd320" {
					h = ripemd.New320()
				} else if *md == "sha3-224" {
					h = sha3.New224()
				} else if *md == "sha3-256" {
					h = sha3.New256()
				} else if *md == "sha3-384" {
					h = sha3.New384()
				} else if *md == "sha3-512" {
					h = sha3.New512()
				} else if *md == "shake128" {
					h = sha3.NewShake128()
				} else if *md == "shake256" {
					h = sha3.NewShake256()
				} else if *md == "lsh224" || *md == "lsh256-224" {
					h = lsh256.New224()
				} else if *md == "lsh" || *md == "lsh256" || *md == "lsh256-256" {
					h = lsh256.New()
				} else if *md == "lsh512-224" {
					h = lsh512.New224()
				} else if *md == "lsh512-256" {
					h = lsh512.New256()
				} else if *md == "lsh384" || *md == "lsh512-384" {
					h = lsh512.New384()
				} else if *md == "lsh512" {
					h = lsh512.New()
				} else if *md == "has160" {
					h = has160.New()
				} else if *md == "keccak" || *md == "keccak256" {
					h = sha3.NewLegacyKeccak256()
				} else if *md == "keccak512" {
					h = sha3.NewLegacyKeccak512()
				} else if *md == "whirlpool" {
					h = whirlpool.New()
				} else if *md == "blake2b256" {
					h, _ = blake2b.New256([]byte(*key))
				} else if *md == "blake2b512" {
					h, _ = blake2b.New512([]byte(*key))
				} else if *md == "blake2s128" {
					h, _ = blake2s.New128([]byte(*key))
				} else if *md == "blake2s256" {
					h, _ = blake2s.New256([]byte(*key))
				} else if *md == "blake3" {
					h = blake3.New()
				} else if *md == "md5" {
					h = md5.New()
				} else if *md == "gost94" {
					h = gost341194.New(&gost28147.SboxIdGostR341194CryptoProParamSet)
				} else if *md == "streebog" || *md == "streebog256" {
					h = gost34112012256.New()
				} else if *md == "streebog512" {
					h = gost34112012512.New()
				} else if *md == "sm3" {
					h = sm3.New()
				} else if *md == "md4" {
					h = md4.New()
				} else if *md == "siphash" || *md == "siphash128" {
					var xkey [16]byte
					copy(xkey[:], []byte(*key))
					h, _ = siphash.New128(xkey[:])
				} else if *md == "siphash64" {
					var xkey [16]byte
					copy(xkey[:], []byte(*key))
					h, _ = siphash.New64(xkey[:])
				} else if *md == "cubehash" {
					h = cubehash.New()
				} else if *md == "xoodyak" || *md == "xhash" {
					h = xoodyak.NewXoodyakHash()
				} else if *md == "skein" || *md == "skein256" {
					h = skein.New256([]byte(*key))
				} else if *md == "skein512" {
					h = skein.New512([]byte(*key))
				} else if *md == "jh" {
					h = jh.New256()
				} else if *md == "groestl" {
					h = groestl.New256()
				} else if *md == "tiger" {
					h = tiger.New()
				} else if *md == "tiger2" {
					h = tiger.New2()
				}
				f, err := os.Open(match)
				if err != nil {
					log.Fatal(err)
				}
				file, err := os.Stat(match)
				if err != nil {
					log.Fatal(err)
				}
				if file.IsDir() {
				} else {
					if _, err := io.Copy(h, f); err != nil {
						log.Fatal(err)
					}
					fmt.Println(hex.EncodeToString(h.Sum(nil)), "*"+f.Name())
				}
				f.Close()
			}
		}
		os.Exit(0)
	}

	if *digest && *recursive == true {
		err := filepath.Walk(filepath.Dir(Files),
			func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				file, err := os.Stat(path)
				if file.IsDir() {
				} else {
					for _, match := range flag.Args() {
						filename := filepath.Base(path)
						pattern := filepath.Base(match)
						matched, err := filepath.Match(pattern, filename)
						if err != nil {
							log.Fatal(err)
						}
						if matched {
							var h hash.Hash
							if *md == "sha224" {
								h = sha256.New224()
							} else if *md == "sha256" {
								h = sha256.New()
							} else if *md == "sha512-256" {
								h = sha512.New512_256()
							} else if *md == "sha384" {
								h = sha512.New384()
							} else if *md == "sha512" {
								h = sha512.New()
							} else if *md == "sha1" {
								h = sha1.New()
							} else if *md == "rmd160" {
								h = ripemd160.New()
							} else if *md == "rmd128" {
								h = ripemd.New128()
							} else if *md == "rmd256" {
								h = ripemd.New256()
							} else if *md == "rmd320" {
								h = ripemd.New320()
							} else if *md == "sha3-224" {
								h = sha3.New224()
							} else if *md == "sha3-256" {
								h = sha3.New256()
							} else if *md == "sha3-384" {
								h = sha3.New384()
							} else if *md == "sha3-512" {
								h = sha3.New512()
							} else if *md == "shake128" {
								h = sha3.NewShake128()
							} else if *md == "shake256" {
								h = sha3.NewShake256()
							} else if *md == "lsh224" || *md == "lsh256-224" {
								h = lsh256.New224()
							} else if *md == "lsh" || *md == "lsh256" || *md == "lsh256-256" {
								h = lsh256.New()
							} else if *md == "lsh512-224" {
								h = lsh512.New224()
							} else if *md == "lsh512-256" {
								h = lsh512.New256()
							} else if *md == "lsh384" || *md == "lsh512-384" {
								h = lsh512.New384()
							} else if *md == "lsh512" {
								h = lsh512.New()
							} else if *md == "has160" {
								h = has160.New()
							} else if *md == "keccak" || *md == "keccak256" {
								h = sha3.NewLegacyKeccak256()
							} else if *md == "keccak512" {
								h = sha3.NewLegacyKeccak512()
							} else if *md == "whirlpool" {
								h = whirlpool.New()
							} else if *md == "blake2b256" {
								h, _ = blake2b.New256([]byte(*key))
							} else if *md == "blake2b512" {
								h, _ = blake2b.New512([]byte(*key))
							} else if *md == "blake2s128" {
								h, _ = blake2s.New128([]byte(*key))
							} else if *md == "blake2s256" {
								h, _ = blake2s.New256([]byte(*key))
							} else if *md == "blake3" {
								h = blake3.New()
							} else if *md == "md5" {
								h = md5.New()
							} else if *md == "gost94" {
								h = gost341194.New(&gost28147.SboxIdGostR341194CryptoProParamSet)
							} else if *md == "streebog" || *md == "streebog256" {
								h = gost34112012256.New()
							} else if *md == "streebog512" {
								h = gost34112012512.New()
							} else if *md == "sm3" {
								h = sm3.New()
							} else if *md == "md4" {
								h = md4.New()
							} else if *md == "siphash" || *md == "siphash128" {
								var xkey [16]byte
								copy(xkey[:], []byte(*key))
								h, _ = siphash.New128(xkey[:])
							} else if *md == "siphash64" {
								var xkey [16]byte
								copy(xkey[:], []byte(*key))
								h, _ = siphash.New64(xkey[:])
							} else if *md == "cubehash" {
								h = cubehash.New()
							} else if *md == "xoodyak" || *md == "xhash" {
								h = xoodyak.NewXoodyakHash()
							} else if *md == "skein" || *md == "skein256" {
								h = skein.New256([]byte(*key))
							} else if *md == "skein512" {
								h = skein.New512([]byte(*key))
							} else if *md == "jh" {
								h = jh.New256()
							} else if *md == "groestl" {
								h = groestl.New256()
							} else if *md == "tiger" {
								h = tiger.New()
							} else if *md == "tiger2" {
								h = tiger.New2()
							}
							f, err := os.Open(path)
							if err != nil {
								log.Fatal(err)
							}
							if _, err := io.Copy(h, f); err != nil {
								log.Fatal(err)
							}
							f.Close()
							fmt.Println(hex.EncodeToString(h.Sum(nil)), "*"+f.Name())
						}
					}
				}
				return nil
			})
		if err != nil {
			log.Println(err)
		}
	}

	if *check {
		scanner := bufio.NewScanner(inputfile)
		scanner.Split(bufio.ScanLines)
		var txtlines []string

		for scanner.Scan() {
			txtlines = append(txtlines, scanner.Text())
		}
		var exit int
		for _, eachline := range txtlines {
			lines := strings.Split(string(eachline), " *")
			if strings.Contains(string(eachline), " *") {
				var h hash.Hash
				if *md == "sha224" {
					h = sha256.New224()
				} else if *md == "sha256" {
					h = sha256.New()
				} else if *md == "sha512-256" {
					h = sha512.New512_256()
				} else if *md == "sha384" {
					h = sha512.New384()
				} else if *md == "sha512" {
					h = sha512.New()
				} else if *md == "sha1" {
					h = sha1.New()
				} else if *md == "rmd160" {
					h = ripemd160.New()
				} else if *md == "rmd128" {
					h = ripemd.New128()
				} else if *md == "rmd256" {
					h = ripemd.New256()
				} else if *md == "rmd320" {
					h = ripemd.New320()
				} else if *md == "sha3-224" {
					h = sha3.New224()
				} else if *md == "sha3-256" {
					h = sha3.New256()
				} else if *md == "sha3-384" {
					h = sha3.New384()
				} else if *md == "sha3-512" {
					h = sha3.New512()
				} else if *md == "shake128" {
					h = sha3.NewShake128()
				} else if *md == "shake256" {
					h = sha3.NewShake256()
				} else if *md == "lsh224" || *md == "lsh256-224" {
					h = lsh256.New224()
				} else if *md == "lsh" || *md == "lsh256" || *md == "lsh256-256" {
					h = lsh256.New()
				} else if *md == "lsh512-224" {
					h = lsh512.New224()
				} else if *md == "lsh512-256" {
					h = lsh512.New256()
				} else if *md == "lsh384" || *md == "lsh512-384" {
					h = lsh512.New384()
				} else if *md == "lsh512" {
					h = lsh512.New()
				} else if *md == "has160" {
					h = has160.New()
				} else if *md == "keccak" || *md == "keccak256" {
					h = sha3.NewLegacyKeccak256()
				} else if *md == "keccak512" {
					h = sha3.NewLegacyKeccak512()
				} else if *md == "whirlpool" {
					h = whirlpool.New()
				} else if *md == "blake2b256" {
					h, _ = blake2b.New256([]byte(*key))
				} else if *md == "blake2b512" {
					h, _ = blake2b.New512([]byte(*key))
				} else if *md == "blake2s128" {
					h, _ = blake2s.New128([]byte(*key))
				} else if *md == "blake2s256" {
					h, _ = blake2s.New256([]byte(*key))
				} else if *md == "blake3" {
					h = blake3.New()
				} else if *md == "md5" {
					h = md5.New()
				} else if *md == "gost94" {
					h = gost341194.New(&gost28147.SboxIdGostR341194CryptoProParamSet)
				} else if *md == "streebog" || *md == "streebog256" {
					h = gost34112012256.New()
				} else if *md == "streebog512" {
					h = gost34112012512.New()
				} else if *md == "sm3" {
					h = sm3.New()
				} else if *md == "md4" {
					h = md4.New()
				} else if *md == "siphash" || *md == "siphash128" {
					var xkey [16]byte
					copy(xkey[:], []byte(*key))
					h, _ = siphash.New128(xkey[:])
				} else if *md == "siphash64" {
					var xkey [16]byte
					copy(xkey[:], []byte(*key))
					h, _ = siphash.New64(xkey[:])
				} else if *md == "cubehash" {
					h = cubehash.New()
				} else if *md == "xoodyak" || *md == "xhash" {
					h = xoodyak.NewXoodyakHash()
				} else if *md == "skein" || *md == "skein256" {
					h = skein.New256([]byte(*key))
				} else if *md == "skein512" {
					h = skein.New512([]byte(*key))
				} else if *md == "jh" {
					h = jh.New256()
				} else if *md == "groestl" {
					h = groestl.New256()
				} else if *md == "tiger" {
					h = tiger.New()
				} else if *md == "tiger2" {
					h = tiger.New2()
				}
				_, err := os.Stat(lines[1])
				if err == nil {
					f, err := os.Open(lines[1])
					if err != nil {
						log.Fatal(err)
					}
					io.Copy(h, f)

					if hex.EncodeToString(h.Sum(nil)) == lines[0] {
						fmt.Println(lines[1]+"\t", "OK")
					} else {
						fmt.Println(lines[1]+"\t", "FAILED")
						exit = 1
					}
				} else {
					fmt.Println(lines[1]+"\t", "Not found!")
					exit = 1
				}
			}
		}
		os.Exit(exit)
	}

	if *mac == "gost" {
		var keyRaw []byte
		if *key == "" {
			keyRaw = []byte("00000000000000000000000000000000")
			fmt.Fprintf(os.Stderr, "Key= %s\n", keyRaw)
		} else {
			keyRaw = []byte(*key)
		}
		if len(keyRaw) != 256/8 {
			fmt.Println("Secret key must have 128-bit.")
			os.Exit(1)
		}
		var iv [8]byte
		if *vector == "" {
			fmt.Fprintf(os.Stderr, "IV= %x\n", iv)
		} else {
			raw, err := hex.DecodeString(*vector)
			if err != nil {
				log.Fatal(err)
			}
			iv = *byte8(raw)
			if err != nil {
				log.Fatal(err)
			}
		}
		c := gost28147.NewCipher([]byte(keyRaw), &gost28147.SboxIdtc26gost28147paramZ)
		h, _ := c.NewMAC(8, iv[:])
		io.Copy(h, inputfile)

		var verify bool
		if *sig != "" {
			mac := hex.EncodeToString(h.Sum(nil))
			if mac != *sig {
				verify = false
				fmt.Println(verify)
				os.Exit(1)
			} else {
				verify = true
				fmt.Println(verify)
				os.Exit(0)
			}
		}
		fmt.Println("MAC-GOST("+inputdesc+")=", hex.EncodeToString(h.Sum(nil)))
		os.Exit(0)
	}

	if *mac == "poly1305" {
		var keyx [32]byte
		copy(keyx[:], []byte(*key))
		h := poly1305.New(&keyx)
		io.Copy(h, inputfile)
		var verify bool
		if *sig != "" {
			mac := hex.EncodeToString(h.Sum(nil))
			if mac != *sig {
				verify = false
				fmt.Println(verify)
				os.Exit(1)
			} else {
				verify = true
				fmt.Println(verify)
				os.Exit(0)
			}
		}
		fmt.Println("MAC-POLY1305("+inputdesc+")=", hex.EncodeToString(h.Sum(nil)))
		os.Exit(0)
	}

	if *mac == "siphash" {
		var xkey [16]byte
		copy(xkey[:], []byte(*key))
		h, _ := siphash.New128(xkey[:])
		io.Copy(h, inputfile)
		var verify bool
		if *sig != "" {
			mac := hex.EncodeToString(h.Sum(nil))
			if mac != *sig {
				verify = false
				fmt.Println(verify)
				os.Exit(1)
			} else {
				verify = true
				fmt.Println(verify)
				os.Exit(0)
			}
		}
		fmt.Println("MAC-SIPHASH("+inputdesc+")=", hex.EncodeToString(h.Sum(nil)))
		os.Exit(0)
	}

	if *mac == "siphash64" {
		var xkey [16]byte
		copy(xkey[:], []byte(*key))
		h, _ := siphash.New64(xkey[:])
		io.Copy(h, inputfile)
		var verify bool
		if *sig != "" {
			mac := hex.EncodeToString(h.Sum(nil))
			if mac != *sig {
				verify = false
				fmt.Println(verify)
				os.Exit(1)
			} else {
				verify = true
				fmt.Println(verify)
				os.Exit(0)
			}
		}
		fmt.Println("MAC-SIPHASH("+inputdesc+")=", hex.EncodeToString(h.Sum(nil)))
		os.Exit(0)
	}

	if *mac == "skein" {
		var err error
		h := skeincipher.NewMAC(uint64(*length/8), []byte(*key))
		if _, err = io.Copy(h, inputfile); err != nil {
			log.Fatal(err)
		}
		var verify bool
		if *sig != "" {
			mac := hex.EncodeToString(h.Sum(nil))
			if mac != *sig {
				verify = false
				fmt.Println(verify)
				os.Exit(1)
			} else {
				verify = true
				fmt.Println(verify)
				os.Exit(0)
			}
		}
		fmt.Println("MAC-SKEIN("+inputdesc+")=", hex.EncodeToString(h.Sum(nil)))
		os.Exit(0)
	}

	if *mac == "hmac" && *md == "haraka" {
		key := []byte(*key)
		b, err := ioutil.ReadAll(inputfile)
		if err != nil {
			log.Fatal(err)
		}
		if len(b)*8 > 512 {
			fmt.Fprintf(os.Stderr, "Alert: The plain text exceeds 512 bits!\n")
		}

		if len(key) > 64 {
			log.Fatal("Key length exceeds 64 bytes")
		}
		if len(key) < 32 {
			padKey := make([]byte, 32)
			copy(padKey, key)
			key = padKey
		}

		innerPad := make([]byte, 32)
		outerPad := make([]byte, 32)

		for i := 0; i < 32; i++ {
			innerPad[i] = key[i] ^ 0x36
			outerPad[i] = key[i] ^ 0x5C
		}

		var innerHashInput [64]byte
		copy(innerHashInput[:], innerPad)
		copy(innerHashInput[0:], b)

		var innerHash [32]byte
		haraka.Haraka512(&innerHash, &innerHashInput)

		var outerInput [64]byte
		copy(outerInput[:32], outerPad)
		copy(outerInput[32:], innerHash[:])

		var outerHash [32]byte
		haraka.Haraka512(&outerHash, &outerInput)

		fmt.Println("HMAC-HARAKA("+inputdesc+")=", hex.EncodeToString(outerHash[:]))
		os.Exit(0)
	}

	if *mac == "hmac" {
		var err error
		h := hmac.New(myHash, []byte(*key))
		if _, err = io.Copy(h, inputfile); err != nil {
			log.Fatal(err)
		}
		var verify bool
		if *sig != "" {
			mac := hex.EncodeToString(h.Sum(nil))
			if mac != *sig {
				verify = false
				fmt.Println(verify)
				os.Exit(1)
			} else {
				verify = true
				fmt.Println(verify)
				os.Exit(0)
			}
		}
		fmt.Println("HMAC-"+strings.ToUpper(*md)+"("+inputdesc+")=", hex.EncodeToString(h.Sum(nil)))
		os.Exit(0)
	}

	if *mac == "cmac" {
		var c cipher.Block
		var err error
		if *cph == "blowfish" {
			c, err = blowfish.NewCipher([]byte(*key))
		} else if *cph == "idea" {
			c, err = idea.NewCipher([]byte(*key))
		} else if *cph == "cast5" {
			c, err = cast5.NewCipher([]byte(*key))
		} else if *cph == "rc5" {
			c, err = rc5.New([]byte(*key))
		} else if *cph == "sm4" {
			c, err = sm4.NewCipher([]byte(*key))
		} else if *cph == "seed" {
			c, err = krcrypt.NewSEED([]byte(*key))
		} else if *cph == "hight" {
			c, err = krcrypt.NewHIGHT([]byte(*key))
		} else if *cph == "rc2" {
			c, err = rc2.NewCipher([]byte(*key))
		} else if *cph == "des" {
			c, err = des.NewCipher([]byte(*key))
		} else if *cph == "3des" {
			c, err = des.NewTripleDESCipher([]byte(*key))
		} else if *cph == "aes" {
			c, err = aes.NewCipher([]byte(*key))
		} else if *cph == "twofish" {
			c, err = twofish.NewCipher([]byte(*key))
		} else if *cph == "aria" {
			c, err = aria.NewCipher([]byte(*key))
		} else if *cph == "lea" {
			c, err = lea.NewCipher([]byte(*key))
		} else if *cph == "camellia" {
			c, err = camellia.NewCipher([]byte(*key))
		} else if *cph == "serpent" {
			c, err = serpent.NewCipher([]byte(*key))
		} else if *cph == "rc6" {
			c, err = rc6.NewCipher([]byte(*key))
		} else if *cph == "misty1" {
			c, err = misty1.New([]byte(*key))
		} else if *cph == "magma" {
			if len(*key) != 32 {
				log.Fatal("MAGMA invalid key size ", len(*key))
			}
			c = gost341264.NewCipher([]byte(*key))
		} else if *cph == "grasshopper" || *cph == "kuznechik" {
			if len(*key) != 32 {
				log.Fatal("KUZNECHIK: invalid key size ", len(*key))
			}
			c, err = kuznechik.NewCipher([]byte(*key))
		} else if *cph == "gost89" {
			if len(*key) != 32 {
				log.Fatal("GOST89: invalid key size ", len(*key))
			}
			c = gost28147.NewCipher([]byte(*key), &gost28147.SboxIdtc26gost28147paramZ)
		} else if *cph == "anubis" {
			if len(*key) != 16 && len(*key) != 24 && len(*key) != 32 && len(*key) != 40 {
				log.Fatal("ANUBIS: invalid key size ", len(*key))
			}
			c, err = anubis.NewWithKeySize([]byte(*key), len(*key))
		} else if *cph == "khazad" {
			c, err = khazad.NewCipher([]byte(*key))
		} else if *cph == "mars" {
			c, err = mars.NewCipher([]byte(*key))
		} else if *cph == "mars2" {
			c, err = mars2.NewCipher([]byte(*key))
		} else if *cph == "noekeon" {
			c, err = noekeon.NewCipher([]byte(*key))
		} else if *cph == "clefia" {
			c, err = clefia.NewCipher([]byte(*key))
		} else if *cph == "e2" {
			c, err = e2.NewCipher([]byte(*key))
		} else if *cph == "crypton" {
			c, err = crypton1.NewCipher([]byte(*key))
		} else if *cph == "present" {
			c, err = present.NewCipher([]byte(*key))
		} else if *cph == "twine" {
			c, err = twine.New([]byte(*key))
		}
		if err != nil {
			log.Fatal(err)
		}

		h, _ := cmac.New(c)
		io.Copy(h, inputfile)
		var verify bool
		if *sig != "" {
			mac := hex.EncodeToString(h.Sum(nil))
			if mac != *sig {
				verify = false
				fmt.Println(verify)
				os.Exit(1)
			} else {
				verify = true
				fmt.Println(verify)
				os.Exit(0)
			}
		}
		fmt.Println("CMAC-"+strings.ToUpper(*cph)+"("+inputdesc+")=", hex.EncodeToString(h.Sum(nil)))
		os.Exit(0)
	}

	if *mac == "pmac" {
		var c cipher.Block
		var err error
		if *cph == "sm4" {
			c, err = sm4.NewCipher([]byte(*key))
		} else if *cph == "seed" {
			c, err = krcrypt.NewSEED([]byte(*key))
		} else if *cph == "aes" {
			c, err = aes.NewCipher([]byte(*key))
		} else if *cph == "twofish" {
			c, err = twofish.NewCipher([]byte(*key))
		} else if *cph == "aria" {
			c, err = aria.NewCipher([]byte(*key))
		} else if *cph == "lea" {
			c, err = lea.NewCipher([]byte(*key))
		} else if *cph == "camellia" {
			c, err = camellia.NewCipher([]byte(*key))
		} else if *cph == "serpent" {
			c, err = serpent.NewCipher([]byte(*key))
		} else if *cph == "rc6" {
			c, err = rc6.NewCipher([]byte(*key))
		} else if *cph == "grasshopper" || *cph == "kuznechik" {
			c, err = kuznechik.NewCipher([]byte(*key))
		} else if *cph == "anubis" {
			if len(*key) != 16 && len(*key) != 24 && len(*key) != 32 && len(*key) != 40 {
				log.Fatal("ANUBIS: invalid key size ", len(*key))
			}
			c, err = anubis.NewWithKeySize([]byte(*key), len(*key))
		} else if *cph == "mars" {
			c, err = mars.NewCipher([]byte(*key))
		} else if *cph == "mars2" {
			c, err = mars2.NewCipher([]byte(*key))
		} else if *cph == "noekeon" {
			c, err = noekeon.NewCipher([]byte(*key))
		} else if *cph == "clefia" {
			c, err = clefia.NewCipher([]byte(*key))
		} else if *cph == "e2" {
			c, err = e2.NewCipher([]byte(*key))
		} else if *cph == "crypton" {
			c, err = crypton1.NewCipher([]byte(*key))
		}
		if err != nil {
			log.Fatal(err)
		}

		h := pmac.New(c)
		io.Copy(h, inputfile)
		var verify bool
		if *sig != "" {
			mac := hex.EncodeToString(h.Sum(nil))
			if mac != *sig {
				verify = false
				fmt.Println(verify)
				os.Exit(1)
			} else {
				verify = true
				fmt.Println(verify)
				os.Exit(0)
			}
		}
		fmt.Println("PMAC-"+strings.ToUpper(*cph)+"("+inputdesc+")=", hex.EncodeToString(h.Sum(nil)))
		os.Exit(0)
	}

	if *mac == "gmac" {
		var c cipher.Block
		var err error

		key := []byte(*key)

		if *cph == "sm4" {
			c, err = sm4.NewCipher(key)
		} else if *cph == "seed" {
			c, err = krcrypt.NewSEED(key)
		} else if *cph == "aes" {
			c, err = aes.NewCipher(key)
		} else if *cph == "twofish" {
			c, err = twofish.NewCipher(key)
		} else if *cph == "aria" {
			c, err = aria.NewCipher(key)
		} else if *cph == "lea" {
			c, err = lea.NewCipher(key)
		} else if *cph == "camellia" {
			c, err = camellia.NewCipher(key)
		} else if *cph == "serpent" {
			c, err = serpent.NewCipher(key)
		} else if *cph == "rc6" {
			c, err = rc6.NewCipher(key)
		} else if *cph == "grasshopper" || *cph == "kuznechik" {
			c, err = kuznechik.NewCipher(key)
		} else if *cph == "anubis" {
			c, err = anubis.NewWithKeySize(key, len(key))
		} else if *cph == "mars" {
			c, err = mars.NewCipher(key)
		} else if *cph == "mars2" {
			c, err = mars2.NewCipher(key)
		} else if *cph == "noekeon" {
			c, err = noekeon.NewCipher(key)
		} else if *cph == "clefia" {
			c, err = clefia.NewCipher(key)
		} else if *cph == "e2" {
			c, err = e2.NewCipher(key)
		} else if *cph == "crypton" {
			c, err = crypton1.NewCipher(key)
		}
		if err != nil {
			log.Fatal(err)
		}

		message, err := ioutil.ReadAll(inputfile)
		if err != nil {
			log.Fatal(err)
		}
		if *vector == "" || len(*vector) != 256/8 {
			log.Fatal("Invalid IV size. GMAC nonce must be the same length of the block.")
		}
		var nonce []byte
		nonce, err = hex.DecodeString(*vector)
		if err != nil {
			log.Fatal(err)
		}
		h, err := gmac.New(c, nonce, message)
		if err != nil {
			log.Fatal(err)
		}
		var verify bool
		if *sig != "" {
			mac := hex.EncodeToString(h)
			if mac != *sig {
				verify = false
				fmt.Println(verify)
				os.Exit(1)
			} else {
				verify = true
				fmt.Println(verify)
				os.Exit(0)
			}
		}
		fmt.Println("GMAC-"+strings.ToUpper(*cph)+"("+inputdesc+")=", hex.EncodeToString(h))
		os.Exit(0)
	}

	if *mac == "mgmac" {
		var c cipher.Block
		var err error

		key := []byte(*key)
		var n int

		if *cph == "sm4" {
			c, err = sm4.NewCipher(key)
			n = 16
		} else if *cph == "seed" {
			c, err = krcrypt.NewSEED(key)
			n = 16
		} else if *cph == "aes" {
			c, err = aes.NewCipher(key)
			n = 16
		} else if *cph == "twofish" {
			c, err = twofish.NewCipher(key)
			n = 16
		} else if *cph == "aria" {
			c, err = aria.NewCipher(key)
			n = 16
		} else if *cph == "lea" {
			c, err = lea.NewCipher(key)
			n = 16
		} else if *cph == "camellia" {
			c, err = camellia.NewCipher(key)
			n = 16
		} else if *cph == "serpent" {
			c, err = serpent.NewCipher(key)
			n = 16
		} else if *cph == "rc6" {
			c, err = rc6.NewCipher(key)
			n = 16
		} else if *cph == "magma" {
			c = gost341264.NewCipher(key)
			n = 8
		} else if *cph == "gost89" {
			c = gost28147.NewCipher(key, &gost28147.SboxIdtc26gost28147paramZ)
			n = 8
		} else if *cph == "grasshopper" || *cph == "kuznechik" {
			c, err = kuznechik.NewCipher(key)
			n = 16
		} else if *cph == "anubis" {
			c, err = anubis.NewWithKeySize(key, len(key))
			n = 16
		} else if *cph == "blowfish" {
			c, err = blowfish.NewCipher(key)
			n = 8
		} else if *cph == "idea" {
			c, err = idea.NewCipher(key)
			n = 8
		} else if *cph == "cast5" {
			c, err = cast5.NewCipher(key)
			n = 8
		} else if *cph == "rc5" {
			c, err = rc5.New(key)
			n = 8
		} else if *cph == "sm4" {
			c, err = sm4.NewCipher(key)
			n = 8
		} else if *cph == "seed" {
			c, err = krcrypt.NewSEED(key)
			n = 8
		} else if *cph == "hight" {
			c, err = krcrypt.NewHIGHT(key)
			n = 8
		} else if *cph == "rc2" {
			c, err = rc2.NewCipher(key)
			n = 8
		} else if *cph == "des" {
			c, err = des.NewCipher(key)
			n = 8
		} else if *cph == "3des" {
			c, err = des.NewTripleDESCipher(key)
			n = 8
		} else if *cph == "khazad" {
			c, err = khazad.NewCipher(key)
			n = 8
		} else if *cph == "present" {
			c, err = present.NewCipher(key)
			n = 8
		} else if *cph == "twine" {
			c, err = twine.New(key)
			n = 8
		} else if *cph == "mars" {
			c, err = mars.NewCipher(key)
			n = 16
		} else if *cph == "mars2" {
			c, err = mars2.NewCipher(key)
			n = 16
		} else if *cph == "noekeon" {
			c, err = noekeon.NewCipher(key)
			n = 16
		} else if *cph == "clefia" {
			c, err = clefia.NewCipher(key)
			n = 16
		} else if *cph == "e2" {
			c, err = e2.NewCipher(key)
			n = 16
		} else if *cph == "crypton" {
			c, err = crypton1.NewCipher(key)
			n = 16
		}
		if err != nil {
			log.Fatal(err)
		}

		message, err := ioutil.ReadAll(inputfile)
		if err != nil {
			log.Fatal(err)
		}
		if *vector == "" || (len(*vector) != 256/8 && len(*vector) != 128/8) {
			log.Fatal("Invalid IV size. MGMAC nonce must be the same length of the block.")
		}
		var nonce []byte
		nonce, err = hex.DecodeString(*vector)
		if err != nil {
			log.Fatal(err)
		}
		h, err := NewMGMAC(c, n, nonce, message)
		if err != nil {
			log.Fatal(err)
		}
		var verify bool
		if *sig != "" {
			mac := hex.EncodeToString(h)
			if mac != *sig {
				verify = false
				fmt.Println(verify)
				os.Exit(1)
			} else {
				verify = true
				fmt.Println(verify)
				os.Exit(0)
			}
		}
		fmt.Println("MGMAC-"+strings.ToUpper(*cph)+"("+inputdesc+")=", hex.EncodeToString(h))
		os.Exit(0)
	}

	if *mac == "vmac" {
		var c cipher.Block
		var err error
		if *cph == "blowfish" {
			c, err = blowfish.NewCipher([]byte(*key))
		} else if *cph == "idea" {
			c, err = idea.NewCipher([]byte(*key))
		} else if *cph == "cast5" {
			c, err = cast5.NewCipher([]byte(*key))
		} else if *cph == "rc5" {
			c, err = rc5.New([]byte(*key))
		} else if *cph == "sm4" {
			c, err = sm4.NewCipher([]byte(*key))
		} else if *cph == "seed" {
			c, err = krcrypt.NewSEED([]byte(*key))
		} else if *cph == "hight" {
			c, err = krcrypt.NewHIGHT([]byte(*key))
		} else if *cph == "rc2" {
			c, err = rc2.NewCipher([]byte(*key))
		} else if *cph == "des" {
			c, err = des.NewCipher([]byte(*key))
		} else if *cph == "3des" {
			c, err = des.NewTripleDESCipher([]byte(*key))
		} else if *cph == "aes" {
			c, err = aes.NewCipher([]byte(*key))
		} else if *cph == "twofish" {
			c, err = twofish.NewCipher([]byte(*key))
		} else if *cph == "aria" {
			c, err = aria.NewCipher([]byte(*key))
		} else if *cph == "lea" {
			c, err = lea.NewCipher([]byte(*key))
		} else if *cph == "camellia" {
			c, err = camellia.NewCipher([]byte(*key))
		} else if *cph == "serpent" {
			c, err = serpent.NewCipher([]byte(*key))
		} else if *cph == "rc6" {
			c, err = rc6.NewCipher([]byte(*key))
		} else if *cph == "misty1" {
			c, err = misty1.New([]byte(*key))
		} else if *cph == "magma" {
			if len(*key) != 32 {
				log.Fatal("MAGMA invalid key size ", len(*key))
			}
			c = gost341264.NewCipher([]byte(*key))
		} else if *cph == "grasshopper" || *cph == "kuznechik" {
			if len(*key) != 32 {
				log.Fatal("KUZNECHIK: invalid key size ", len(*key))
			}
			c, err = kuznechik.NewCipher([]byte(*key))
		} else if *cph == "gost89" {
			if len(*key) != 32 {
				log.Fatal("GOST89: invalid key size ", len(*key))
			}
			c = gost28147.NewCipher([]byte(*key), &gost28147.SboxIdtc26gost28147paramZ)
		} else if *cph == "anubis" {
			if len(*key) != 16 && len(*key) != 24 && len(*key) != 32 && len(*key) != 40 {
				log.Fatal("ANUBIS: invalid key size ", len(*key))
			}
			c, err = anubis.NewWithKeySize([]byte(*key), len(*key))
		} else if *cph == "threefish256" || *cph == "threefish" {
			var tweak []byte
			tweak = make([]byte, 16)
			if *info != "" {
				tweak = []byte(*info)
			}
			c, err = threefish.New256([]byte(*key), tweak)
			if err != nil {
				log.Fatal(err)
			}
		} else if *cph == "threefish512" {
			var tweak []byte
			tweak = make([]byte, 16)
			if *info != "" {
				tweak = []byte(*info)
			}
			c, err = threefish.New512([]byte(*key), tweak)
			if err != nil {
				log.Fatal(err)
			}
		} else if *cph == "threefish1024" {
			var tweak []byte
			tweak = make([]byte, 16)
			if *info != "" {
				tweak = []byte(*info)
			}
			c, err = threefish.New1024([]byte(*key), tweak)
			if err != nil {
				log.Fatal(err)
			}
		} else if *cph == "khazad" {
			c, err = khazad.NewCipher([]byte(*key))
		} else if *cph == "mars" {
			c, err = mars.NewCipher([]byte(*key))
		} else if *cph == "mars2" {
			c, err = mars2.NewCipher([]byte(*key))
		} else if *cph == "noekeon" {
			c, err = noekeon.NewCipher([]byte(*key))
		} else if *cph == "clefia" {
			c, err = clefia.NewCipher([]byte(*key))
		} else if *cph == "e2" {
			c, err = e2.NewCipher([]byte(*key))
		} else if *cph == "crypton" {
			c, err = crypton1.NewCipher([]byte(*key))
		} else if *cph == "present" {
			c, err = present.NewCipher([]byte(*key))
		} else if *cph == "twine" {
			c, err = twine.New([]byte(*key))
		}
		if err != nil {
			log.Fatal(err)
		}
		if *vector == "" {
			log.Fatal("Invalid IV size. VMAC nonce must be from 1 to block length -1.")
		}
		nonce, err := hex.DecodeString(*vector)
		if err != nil {
			log.Fatal(err)
		}
		h, err := vmac.New(c, []byte(*key), nonce, *length/8)
		if err != nil {
			log.Fatal(err)
		}
		io.Copy(h, inputfile)
		var verify bool
		if *sig != "" {
			mac := hex.EncodeToString(h.Sum())
			if mac != *sig {
				verify = false
				fmt.Println(verify)
				os.Exit(1)
			} else {
				verify = true
				fmt.Println(verify)
				os.Exit(0)
			}
		}
		fmt.Println("VMAC-"+strings.ToUpper(*cph)+"("+inputdesc+")=", hex.EncodeToString(h.Sum()))
		os.Exit(0)
	}

	if *mac == "xmac" || *mac == "xoodyak" {
		var err error
		var file io.Reader
		file = inputfile
		h := xoodyak.NewXoodyakMac([]byte(*key))
		if _, err = io.Copy(h, file); err != nil {
			log.Fatal(err)
		}
		fmt.Println("MAC-XOODYAK("+inputdesc+")=", hex.EncodeToString(h.Sum(nil)))
		os.Exit(0)
	}

	if *kdf == "hkdf" {
		if *md == "jh" {
			*info = fmt.Sprintf("%-64s", *info)
		}
		hash, err := Hkdf([]byte(*key), []byte(*salt), []byte(*info))
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%x\n", hash[:*length/8])
	}

	var pubkey ecdsa.PublicKey
	var public *ecdsa.PublicKey
	var pubkeyCurve elliptic.Curve

	if *pkey == "keygen" && *length == 224 {
		pubkeyCurve = elliptic.P224()
	} else if *pkey == "keygen" && *length == 256 {
		pubkeyCurve = elliptic.P256()
	} else if *pkey == "keygen" && *length == 384 {
		pubkeyCurve = elliptic.P384()
	} else if *pkey == "keygen" && *length == 521 {
		pubkeyCurve = elliptic.P521()
	}

	if *pkey == "keygen" && (strings.ToUpper(*alg) == "EC" || strings.ToUpper(*alg) == "ECDSA") && (*length == 224 || *length == 256 || *length == 384 || *length == 521) {
		var privatekey *ecdsa.PrivateKey
		if *key != "" {
			file, err := ioutil.ReadFile(*key)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			privatekey, err = DecodePrivateKey(file)
			if err != nil {
				log.Fatal(err)
			}
		} else {
			privatekey = new(ecdsa.PrivateKey)
			privatekey, err = ecdsa.GenerateKey(pubkeyCurve, rand.Reader)

			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		}
		pubkey = privatekey.PublicKey
		pripem, _ := EncodePrivateKey(privatekey)
		ioutil.WriteFile(*priv, pripem, 0644)

		pubpem, _ := EncodePublicKey(&pubkey)
		ioutil.WriteFile(*pub, pubpem, 0644)

		absPrivPath, err := filepath.Abs(*priv)
		if err != nil {
			log.Fatal("Failed to get absolute path for private key:", err)
		}
		absPubPath, err := filepath.Abs(*pub)
		if err != nil {
			log.Fatal("Failed to get absolute path for public key:", err)
		}
		println("Private key saved to:", absPrivPath)
		println("Public key saved to:", absPubPath)

		file, err := os.Open(*pub)
		if err != nil {
			log.Fatal(err)
		}
		info, err := file.Stat()
		if err != nil {
			log.Fatal(err)
		}
		block, _ := pem.Decode(pubpem)
		if block == nil {
			log.Fatal(err)
		}
		buf := make([]byte, info.Size())
		file.Read(buf)
		fingerprint := calculateFingerprint(buf)
		print("Fingerprint: ")
		println(fingerprint)
		printKeyDetails(block)
		randomArt := randomart.FromString(string(buf))
		println(randomArt)

		os.Exit(0)
	}

	if *pkey == "encrypt" && (strings.ToUpper(*alg) == "EC" || strings.ToUpper(*alg) == "ECDSA") {
		file, err := ioutil.ReadFile(*key)
		if err != nil {
			log.Fatal(err)
		}
		public, err = DecodePublicKey(file)
		if err != nil {
			log.Fatal(err)
		}
		buf := bytes.NewBuffer(nil)
		data := inputfile
		io.Copy(buf, data)
		scanner := string(buf.Bytes())
		ciphertxt, err := public.EncryptAsn1([]byte(scanner), rand.Reader)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s", ciphertxt)
		os.Exit(0)
	}

	if *pkey == "decrypt" && (strings.ToUpper(*alg) == "EC" || strings.ToUpper(*alg) == "ECDSA") {
		var privatekey *ecdsa.PrivateKey
		file, err := ioutil.ReadFile(*key)
		if err != nil {
			log.Fatal(err)
		}
		privatekey, err = DecodePrivateKey(file)
		if err != nil {
			log.Fatal(err)
		}
		buf := bytes.NewBuffer(nil)
		data := inputfile
		io.Copy(buf, data)
		scanner := string(buf.Bytes())
		str := string(scanner)
		plaintxt, err := privatekey.DecryptAsn1([]byte(str))
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s", plaintxt)
		os.Exit(0)
	}

	if *pkey == "keygen" && (strings.ToUpper(*alg) == "SM2") {
		var privatekey *sm2.PrivateKey
		if *key != "" {
			file, err := ioutil.ReadFile(*key)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			privatekey, err = DecodeSM2PrivateKey(file)
			if err != nil {
				log.Fatal(err)
			}
		} else {
			privatekey = new(sm2.PrivateKey)
			privatekey, err = sm2.GenerateKey(rand.Reader)

			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		}
		pubkey = privatekey.PublicKey
		pripem, _ := EncodeSM2PrivateKey(privatekey)
		ioutil.WriteFile(*priv, pripem, 0644)

		pubpem, _ := EncodePublicKey(&pubkey)
		ioutil.WriteFile(*pub, pubpem, 0644)

		absPrivPath, err := filepath.Abs(*priv)
		if err != nil {
			log.Fatal("Failed to get absolute path for private key:", err)
		}
		absPubPath, err := filepath.Abs(*pub)
		if err != nil {
			log.Fatal("Failed to get absolute path for public key:", err)
		}
		println("Private key saved to:", absPrivPath)
		println("Public key saved to:", absPubPath)

		file, err := os.Open(*pub)
		if err != nil {
			log.Fatal(err)
		}
		info, err := file.Stat()
		if err != nil {
			log.Fatal(err)
		}
		block, _ := pem.Decode(pubpem)
		if block == nil {
			log.Fatal(err)
		}
		buf := make([]byte, info.Size())
		file.Read(buf)
		fingerprint := calculateFingerprint(buf)
		print("Fingerprint: ")
		println(fingerprint)
		printKeyDetails(block)
		randomArt := randomart.FromString(string(buf))
		println(randomArt)

		os.Exit(0)
	}

	if *pkey == "encrypt" && (strings.ToUpper(*alg) == "SM2") {
		file, err := ioutil.ReadFile(*key)
		if err != nil {
			log.Fatal(err)
		}
		public, err = DecodePublicKey(file)
		if err != nil {
			log.Fatal(err)
		}
		buf := bytes.NewBuffer(nil)
		data := inputfile
		io.Copy(buf, data)
		scanner := string(buf.Bytes())
		ciphertxt, err := sm2.EncryptASN1(rand.Reader, public, []byte(scanner))
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s", ciphertxt)
		os.Exit(0)
	}

	if *pkey == "decrypt" && (strings.ToUpper(*alg) == "SM2") {
		var privatekey *sm2.PrivateKey
		file, err := ioutil.ReadFile(*key)
		if err != nil {
			log.Fatal(err)
		}
		privatekey, err = DecodeSM2PrivateKey(file)
		if err != nil {
			log.Fatal(err)
		}
		buf := bytes.NewBuffer(nil)
		data := inputfile
		io.Copy(buf, data)
		scanner := string(buf.Bytes())
		str := string(scanner)
		plaintxt, err := sm2.Decrypt(privatekey, []byte(str))
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s", plaintxt)
		os.Exit(0)
	}

	if *pkey == "keygen" && (strings.ToUpper(*alg) == "ED25519") {
		var privatekey ed25519.PrivateKey
		var public ed25519.PublicKey
		public, privatekey, err = ed25519.GenerateKey(rand.Reader)

		if err != nil {
			log.Fatal(err)
		}

		privateStream, err := x509.MarshalPKCS8PrivateKey(privatekey)
		if err != nil {
			log.Fatal(err)
		}
		block := &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: privateStream,
		}
		file, err := os.Create(*priv)
		if err != nil {
			log.Fatal(err)
		}
		if *pwd != "" {
			if *cph == "aes128" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherAES128)
			} else if *cph == "aes192" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherAES192)
			} else if *cph == "aes" || *cph == "aes256" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherAES256)
			} else if *cph == "3des" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipher3DES)
			} else if *cph == "des" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherDES)
			} else if *cph == "sm4" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherSM4)
			} else if *cph == "gost" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherGOST)
			} else if *cph == "idea" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherIDEA)
			} else if *cph == "camellia128" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherCAMELLIA128)
			} else if *cph == "camellia192" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherCAMELLIA192)
			} else if *cph == "camellia" || *cph == "camellia256" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherCAMELLIA256)
			} else if *cph == "aria128" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherARIA128)
			} else if *cph == "aria192" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherARIA192)
			} else if *cph == "aria" || *cph == "aria256" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherARIA256)
			} else if *cph == "lea128" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherLEA128)
			} else if *cph == "lea192" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherLEA192)
			} else if *cph == "lea" || *cph == "lea256" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherLEA256)
			} else if *cph == "seed" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherSEED)
			} else if *cph == "cast5" {
				block, _ = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherCAST)
			} else if *cph == "anubis" {
				block, _ = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherANUBIS)
			} else if *cph == "serpent128" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherSERPENT128)
			} else if *cph == "serpent192" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherSERPENT192)
			} else if *cph == "serpent" || *cph == "serpent256" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherSERPENT256)
			} else if *cph == "rc6128" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherRC6128)
			} else if *cph == "rc6192" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherRC6192)
			} else if *cph == "rc6" || *cph == "rc6256" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherRC6256)
			}
			if err != nil {
				log.Fatal(err)
			}
			err = pem.Encode(file, block)
			if err != nil {
				log.Fatal(err)
			}
		} else {
			err = pem.Encode(file, block)
			if err != nil {
				log.Fatal(err)
			}
		}
		publicStream, err := x509.MarshalPKIXPublicKey(public)
		if err != nil {
			log.Fatal(err)
		}
		pubblock := &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: publicStream,
		}
		pubfile, err := os.Create(*pub)
		if err != nil {
			log.Fatal(err)
		}
		err = pem.Encode(pubfile, pubblock)
		if err != nil {
			log.Fatal(err)
		}

		absPrivPath, err := filepath.Abs(*priv)
		if err != nil {
			log.Fatal("Failed to get absolute path for private key:", err)
		}
		absPubPath, err := filepath.Abs(*pub)
		if err != nil {
			log.Fatal("Failed to get absolute path for public key:", err)
		}
		println("Private key saved to:", absPrivPath)
		println("Public key saved to:", absPubPath)

		file, err = os.Open(*pub)
		if err != nil {
			log.Fatal(err)
		}
		info, err := file.Stat()
		if err != nil {
			log.Fatal(err)
		}
		buf := make([]byte, info.Size())
		file.Read(buf)
		fingerprint := calculateFingerprint(buf)
		print("Fingerprint: ")
		println(fingerprint)
		printKeyDetails(pubblock)
		randomArt := randomart.FromString(string(buf))
		println(randomArt)
	}

	if *pkey == "setup" && (strings.ToUpper(*alg) == "SM9SIGN") {
		masterKey, err := sm9.GenerateSignMasterKey(rand.Reader)
		if err != nil {
			fmt.Println("Error generating SM9 master key:", err)
			return
		}

		masterKeyBytes, err := smx509.MarshalPKCS8PrivateKey(masterKey)
		if err != nil {
			fmt.Println("Error marshaling master key:", err)
			return
		}

		block := &pem.Block{
			Type:  "SM9 SIGN MASTER KEY",
			Bytes: masterKeyBytes,
		}
		file, err := os.Create(*master)
		if err != nil {
			log.Fatal(err)
		}
		if *pwd != "" {
			if *cph == "aes128" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherAES128)
			} else if *cph == "aes192" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherAES192)
			} else if *cph == "aes" || *cph == "aes256" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherAES256)
			} else if *cph == "3des" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipher3DES)
			} else if *cph == "des" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherDES)
			} else if *cph == "sm4" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherSM4)
			} else if *cph == "gost" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherGOST)
			} else if *cph == "idea" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherIDEA)
			} else if *cph == "camellia128" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherCAMELLIA128)
			} else if *cph == "camellia192" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherCAMELLIA192)
			} else if *cph == "camellia" || *cph == "camellia256" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherCAMELLIA256)
			} else if *cph == "aria128" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherARIA128)
			} else if *cph == "aria192" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherARIA192)
			} else if *cph == "aria" || *cph == "aria256" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherARIA256)
			} else if *cph == "lea128" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherLEA128)
			} else if *cph == "lea192" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherLEA192)
			} else if *cph == "lea" || *cph == "lea256" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherLEA256)
			} else if *cph == "seed" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherSEED)
			} else if *cph == "cast5" {
				block, _ = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherCAST)
			} else if *cph == "anubis" {
				block, _ = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherANUBIS)
			} else if *cph == "serpent128" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherSERPENT128)
			} else if *cph == "serpent192" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherSERPENT192)
			} else if *cph == "serpent" || *cph == "serpent256" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherSERPENT256)
			} else if *cph == "rc6128" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherRC6128)
			} else if *cph == "rc6192" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherRC6192)
			} else if *cph == "rc6" || *cph == "rc6256" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherRC6256)
			}
			if err != nil {
				log.Fatal(err)
			}
			err = pem.Encode(file, block)
			if err != nil {
				log.Fatal(err)
			}
		} else {
			err = pem.Encode(file, block)
			if err != nil {
				log.Fatal(err)
			}
		}
		pubKey, err := masterKey.Public().MarshalASN1()
		if err != nil {
			fmt.Println("Error marshaling master key:", err)
			return
		}

		pubblock := &pem.Block{
			Type:  "SM9 SIGN PUBLIC KEY",
			Bytes: pubKey,
		}
		pubfile, err := os.Create(*pub)
		if err != nil {
			log.Fatal(err)
		}
		err = pem.Encode(pubfile, pubblock)
		if err != nil {
			log.Fatal(err)
		}

		absPrivPath, err := filepath.Abs(*priv)
		if err != nil {
			log.Fatal("Failed to get absolute path for private key:", err)
		}
		absPubPath, err := filepath.Abs(*pub)
		if err != nil {
			log.Fatal("Failed to get absolute path for public key:", err)
		}
		println("Master key saved to:", absPrivPath)
		println("Public key saved to:", absPubPath)

		file, err = os.Open(*pub)
		if err != nil {
			log.Fatal(err)
		}
		info, err := file.Stat()
		if err != nil {
			log.Fatal(err)
		}
		buf := make([]byte, info.Size())
		file.Read(buf)
		fingerprint := calculateFingerprint(buf)
		print("Fingerprint: ")
		println(fingerprint)
		fmt.Fprintln(os.Stderr, "SM9 Sign Master Public Key (256-bit)")
		randomArt := randomart.FromString(string(buf))
		println(randomArt)
	}

	if *pkey == "setup" && (strings.ToUpper(*alg) == "SM9ENCRYPT") {
		masterKey, err := sm9.GenerateEncryptMasterKey(rand.Reader)
		if err != nil {
			fmt.Println("Error generating SM9 master key:", err)
			return
		}

		masterKeyBytes, err := smx509.MarshalPKCS8PrivateKey(masterKey)
		if err != nil {
			fmt.Println("Error marshaling master key:", err)
			return
		}

		block := &pem.Block{
			Type:  "SM9 ENC MASTER KEY",
			Bytes: masterKeyBytes,
		}
		file, err := os.Create(*master)
		if err != nil {
			log.Fatal(err)
		}
		if *pwd != "" {
			if *cph == "aes128" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherAES128)
			} else if *cph == "aes192" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherAES192)
			} else if *cph == "aes" || *cph == "aes256" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherAES256)
			} else if *cph == "3des" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipher3DES)
			} else if *cph == "des" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherDES)
			} else if *cph == "sm4" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherSM4)
			} else if *cph == "gost" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherGOST)
			} else if *cph == "idea" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherIDEA)
			} else if *cph == "camellia128" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherCAMELLIA128)
			} else if *cph == "camellia192" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherCAMELLIA192)
			} else if *cph == "camellia" || *cph == "camellia256" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherCAMELLIA256)
			} else if *cph == "aria128" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherARIA128)
			} else if *cph == "aria192" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherARIA192)
			} else if *cph == "aria" || *cph == "aria256" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherARIA256)
			} else if *cph == "lea128" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherLEA128)
			} else if *cph == "lea192" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherLEA192)
			} else if *cph == "lea" || *cph == "lea256" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherLEA256)
			} else if *cph == "seed" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherSEED)
			} else if *cph == "cast5" {
				block, _ = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherCAST)
			} else if *cph == "anubis" {
				block, _ = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherANUBIS)
			} else if *cph == "serpent128" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherSERPENT128)
			} else if *cph == "serpent192" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherSERPENT192)
			} else if *cph == "serpent" || *cph == "serpent256" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherSERPENT256)
			} else if *cph == "rc6128" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherRC6128)
			} else if *cph == "rc6192" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherRC6192)
			} else if *cph == "rc6" || *cph == "rc6256" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherRC6256)
			}
			if err != nil {
				log.Fatal(err)
			}
			err = pem.Encode(file, block)
			if err != nil {
				log.Fatal(err)
			}
		} else {
			err = pem.Encode(file, block)
			if err != nil {
				log.Fatal(err)
			}
		}
		pubKey, err := masterKey.Public().MarshalASN1()
		if err != nil {
			fmt.Println("Error marshaling master key:", err)
			return
		}

		pubblock := &pem.Block{
			Type:  "SM9 ENC PUBLIC KEY",
			Bytes: pubKey,
		}
		pubfile, err := os.Create(*pub)
		if err != nil {
			log.Fatal(err)
		}
		err = pem.Encode(pubfile, pubblock)
		if err != nil {
			log.Fatal(err)
		}

		absPrivPath, err := filepath.Abs(*priv)
		if err != nil {
			log.Fatal("Failed to get absolute path for private key:", err)
		}
		absPubPath, err := filepath.Abs(*pub)
		if err != nil {
			log.Fatal("Failed to get absolute path for public key:", err)
		}
		println("Master key saved to:", absPrivPath)
		println("Public key saved to:", absPubPath)

		file, err = os.Open(*pub)
		if err != nil {
			log.Fatal(err)
		}
		info, err := file.Stat()
		if err != nil {
			log.Fatal(err)
		}
		buf := make([]byte, info.Size())
		file.Read(buf)
		fingerprint := calculateFingerprint(buf)
		print("Fingerprint: ")
		println(fingerprint)
		fmt.Fprintln(os.Stderr, "SM9 Encrypt Master Public Key (256-bit)")
		randomArt := randomart.FromString(string(buf))
		println(randomArt)
	}

	if *pkey == "keygen" && (strings.ToUpper(*alg) == "SM9ENCRYPT") {
		var privPEM []byte
		file, err := os.Open(*master)
		if err != nil {
			log.Fatal(err)
		}
		fileinfo, err := file.Stat()
		if err != nil {
			log.Fatal(err)
		}
		buf := make([]byte, fileinfo.Size())
		file.Read(buf)
		var block *pem.Block
		block, _ = pem.Decode(buf)
		if block == nil {
			errors.New("no valid private key found")
		}
		var privKeyBytes []byte
		if IsEncryptedPEMBlock(block) {
			privKeyBytes, err = DecryptPEMBlock(block, []byte(*pwd))
			if err != nil {
				log.Fatal(err)
			}
			privPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privKeyBytes})
		} else {
			privPEM = buf
		}

		var privateKeyPemBlock, _ = pem.Decode([]byte(privPEM))

		parsedKey, _ := smx509.ParsePKCS8PrivateKey(privateKeyPemBlock.Bytes)
		if err != nil {
			log.Fatal(err)
		}

		var masterKey *sm9.EncryptMasterPrivateKey
		switch key := parsedKey.(type) {
		case *sm9.EncryptMasterPrivateKey:
			masterKey = key
		default:
			log.Fatal("Invalid private key type. Expected sm9.EncryptMasterPrivateKey.")
		}

		userKey, err := masterKey.GenerateUserKey([]byte(*id), byte(*hierarchy))
		if err != nil {
			fmt.Println("Error generating SM9 user key:", err)
			return
		}

		privKeyBytes, err = smx509.MarshalPKCS8PrivateKey(userKey)

		block = &pem.Block{
			Type:  "SM9 ENC PRIVATE KEY",
			Bytes: privKeyBytes,
		}
		file, err = os.Create(*priv)
		if err != nil {
			log.Fatal(err)
		}
		if *pwd2 != "" {
			if *cph == "aes128" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd2), PEMCipherAES128)
			} else if *cph == "aes192" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd2), PEMCipherAES192)
			} else if *cph == "aes" || *cph == "aes256" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd2), PEMCipherAES256)
			} else if *cph == "3des" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd2), PEMCipher3DES)
			} else if *cph == "des" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd2), PEMCipherDES)
			} else if *cph == "sm4" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd2), PEMCipherSM4)
			} else if *cph == "gost" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd2), PEMCipherGOST)
			} else if *cph == "idea" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd2), PEMCipherIDEA)
			} else if *cph == "camellia128" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd2), PEMCipherCAMELLIA128)
			} else if *cph == "camellia192" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd2), PEMCipherCAMELLIA192)
			} else if *cph == "camellia" || *cph == "camellia256" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd2), PEMCipherCAMELLIA256)
			} else if *cph == "aria128" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd2), PEMCipherARIA128)
			} else if *cph == "aria192" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd2), PEMCipherARIA192)
			} else if *cph == "aria" || *cph == "aria256" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd2), PEMCipherARIA256)
			} else if *cph == "lea128" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd2), PEMCipherLEA128)
			} else if *cph == "lea192" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd2), PEMCipherLEA192)
			} else if *cph == "lea" || *cph == "lea256" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd2), PEMCipherLEA256)
			} else if *cph == "seed" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd2), PEMCipherSEED)
			} else if *cph == "cast5" {
				block, _ = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd2), PEMCipherCAST)
			} else if *cph == "anubis" {
				block, _ = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd2), PEMCipherANUBIS)
			} else if *cph == "serpent128" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd2), PEMCipherSERPENT128)
			} else if *cph == "serpent192" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd2), PEMCipherSERPENT192)
			} else if *cph == "serpent" || *cph == "serpent256" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd2), PEMCipherSERPENT256)
			} else if *cph == "rc6128" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherRC6128)
			} else if *cph == "rc6192" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherRC6192)
			} else if *cph == "rc6" || *cph == "rc6256" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherRC6256)
			}
			if err != nil {
				log.Fatal(err)
			}
			err = pem.Encode(file, block)
			if err != nil {
				log.Fatal(err)
			}
		} else {
			err = pem.Encode(file, block)
			if err != nil {
				log.Fatal(err)
			}
		}
	}

	if *pkey == "encrypt" && (strings.ToUpper(*alg) == "SM9ENCRYPT") {
		fileContent, err := ioutil.ReadFile(*key)
		if err != nil {
			fmt.Println("Erro ao ler o arquivo:", err)
			return
		}

		block, _ := pem.Decode(fileContent)
		if block == nil {
			fmt.Println("Failed to decode PEM block containing the public key.")
			return
		}

		pubKey := new(sm9.EncryptMasterPublicKey)
		err = pubKey.UnmarshalASN1(block.Bytes)
		if err != nil {
			fmt.Println("Error parsing public key with UnmarshalASN1:", err)
			return
		}

		plaintext, err := ioutil.ReadAll(inputfile)
		if err != nil {
			fmt.Println("Error reading input file:", err)
			os.Exit(1)
		}

		ciphertext, err := sm9.EncryptASN1(rand.Reader, pubKey, []byte(*id), byte(*hierarchy), plaintext, sm9.DefaultEncrypterOpts)
		if err != nil {
			fmt.Println("Error encrypting the message:", err)
			return
		}
		fmt.Printf("%s", ciphertext)
	}

	if *pkey == "decrypt" && (strings.ToUpper(*alg) == "SM9ENCRYPT") {
		var privPEM []byte
		file, err := os.Open(*key)
		if err != nil {
			log.Fatal(err)
		}
		fileinfo, err := file.Stat()
		if err != nil {
			log.Fatal(err)
		}
		buf := make([]byte, fileinfo.Size())
		file.Read(buf)
		var block *pem.Block
		block, _ = pem.Decode(buf)
		if block == nil {
			errors.New("no valid private key found")
		}
		var privKeyBytes []byte
		if IsEncryptedPEMBlock(block) {
			privKeyBytes, err = DecryptPEMBlock(block, []byte(*pwd))
			if err != nil {
				log.Fatal(err)
			}
			privPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privKeyBytes})
		} else {
			privPEM = buf
		}

		var privateKeyPemBlock, _ = pem.Decode([]byte(privPEM))

		var privKey, _ = smx509.ParsePKCS8PrivateKey(privateKeyPemBlock.Bytes)
		if err != nil {
			log.Fatal(err)
		}

		encryptPrivateKey, ok := privKey.(*sm9.EncryptPrivateKey)
		if !ok {
			fmt.Println("Invalid private key type. Expected sm9.EncryptPrivateKey.")
			os.Exit(1)
		}

		ciphertext, err := ioutil.ReadAll(inputfile)
		if err != nil {
			fmt.Println("Error reading input file:", err)
			os.Exit(1)
		}

		decryptedText, err := encryptPrivateKey.DecryptASN1([]byte(*id), ciphertext)
		if err != nil {
			fmt.Println("Error decrypting the message:", err)
			return
		}
		fmt.Printf("%s", decryptedText)
	}

	if *pkey == "wrapkey" && (strings.ToUpper(*alg) == "SM9ENCRYPT") {
		fileContent, err := ioutil.ReadFile(*key)
		if err != nil {
			fmt.Println("Erro ao ler o arquivo:", err)
			return
		}

		block, _ := pem.Decode(fileContent)
		if block == nil {
			fmt.Println("Failed to decode PEM block containing the public key.")
			return
		}

		pubKey := new(sm9.EncryptMasterPublicKey)
		err = pubKey.UnmarshalASN1(block.Bytes)
		if err != nil {
			fmt.Println("Error parsing public key with UnmarshalASN1:", err)
			return
		}
		keyPackage, err := pubKey.WrapKeyASN1(rand.Reader, []byte(*id), byte(*hierarchy), *length/8)
		if err != nil {
			log.Fatal(err)
		}
		key, cipher, err := sm9.UnmarshalSM9KeyPackage(keyPackage)
		if err != nil {
			log.Fatal(err)
		}

		cipherMarshaled := cipher.Marshal()

		fmt.Printf("Cipher= %x\n", cipherMarshaled)
		fmt.Printf("Shared= %x\n", key)
	}

	if *pkey == "unwrapkey" && (strings.ToUpper(*alg) == "SM9ENCRYPT") {
		var privPEM []byte
		file, err := os.Open(*key)
		if err != nil {
			log.Fatal(err)
		}
		fileinfo, err := file.Stat()
		if err != nil {
			log.Fatal(err)
		}
		buf := make([]byte, fileinfo.Size())
		file.Read(buf)
		var block *pem.Block
		block, _ = pem.Decode(buf)
		if block == nil {
			errors.New("no valid private key found")
		}
		var privKeyBytes []byte
		if IsEncryptedPEMBlock(block) {
			privKeyBytes, err = DecryptPEMBlock(block, []byte(*pwd))
			if err != nil {
				log.Fatal(err)
			}
			privPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privKeyBytes})
		} else {
			privPEM = buf
		}

		var privateKeyPemBlock, _ = pem.Decode([]byte(privPEM))

		var privKey, _ = smx509.ParsePKCS8PrivateKey(privateKeyPemBlock.Bytes)
		if err != nil {
			log.Fatal(err)
		}

		encryptPrivateKey, ok := privKey.(*sm9.EncryptPrivateKey)
		if !ok {
			fmt.Println("Invalid private key type. Expected sm9.EncryptPrivateKey.")
			os.Exit(1)
		}

		cipherHexString := strings.Replace(*cph, "\r\n", "", -1)
		cipherHexString = strings.Replace(string(cipherHexString), "\n", "", -1)
		cipherHexString = strings.Replace(string(cipherHexString), " ", "", -1)

		cipherMarshaled, err := hex.DecodeString(cipherHexString)

		var cipher bn256.G1
		_, err = cipher.Unmarshal(cipherMarshaled)
		if err != nil {
			log.Fatal(err)
		}

		key, err := sm9.UnwrapKey(encryptPrivateKey, []byte(*id), &cipher, *length/8)
		if err != nil {
			os.Exit(1)
		}
		fmt.Printf("Shared= %x\n", key)
	}

	if (*pkey == "derivea" || *pkey == "deriveb") && (strings.ToUpper(*alg) == "SM9ENCRYPT") {
		var privPEM []byte
		file, err := os.Open(*key)
		if err != nil {
			log.Fatal(err)
		}
		fileinfo, err := file.Stat()
		if err != nil {
			log.Fatal(err)
		}
		buf := make([]byte, fileinfo.Size())
		file.Read(buf)
		var block *pem.Block
		block, _ = pem.Decode(buf)
		if block == nil {
			errors.New("no valid private key found")
		}
		var privKeyBytes []byte
		if IsEncryptedPEMBlock(block) {
			privKeyBytes, err = DecryptPEMBlock(block, []byte(*pwd))
			if err != nil {
				log.Fatal(err)
			}
			privPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privKeyBytes})
		} else {
			privPEM = buf
		}

		var privateKeyPemBlock, _ = pem.Decode([]byte(privPEM))

		var privKey, _ = smx509.ParsePKCS8PrivateKey(privateKeyPemBlock.Bytes)
		if err != nil {
			log.Fatal(err)
		}

		encryptPrivateKey, ok := privKey.(*sm9.EncryptPrivateKey)
		if !ok {
			fmt.Println("Invalid private key type. Expected sm9.EncryptPrivateKey.")
			os.Exit(1)
		}

		if *pkey == "derivea" {
			aExchange := sm9.NewKeyExchange(encryptPrivateKey, []byte(*id), []byte(*id2), *length/8, true)
			defer func() {
				aExchange.Destroy()
			}()
			rA, err := aExchange.InitKeyExchange(rand.Reader, byte(*hierarchy))
			if err != nil {
				log.Fatal("Error during key exchange A: ", err)
			}

			fmt.Println("rA=", hex.EncodeToString(rA.Marshal()))

			var rB, signB string
			fmt.Print("Enter rB: ")
			fmt.Scanln(&rB)
			fmt.Print("Enter signB: ")
			fmt.Scanln(&signB)

			rBBytes, err := hex.DecodeString(rB)
			if err != nil {
				log.Fatal("Error decoding rB: ", err)
			}

			signBBytes, err := hex.DecodeString(signB)
			if err != nil {
				log.Fatal("Error decoding signB: ", err)
			}

			var g1RB bn256.G1
			_, err = g1RB.Unmarshal(rBBytes)
			if err != nil {
				log.Fatal("Error unmarshalling rB:", err)
			}

			key1, _, err := aExchange.ConfirmResponder(&g1RB, signBBytes)
			if err != nil {
				log.Fatal("Error during confirmation A: ", err)
			}

			fmt.Println("Shared=", hex.EncodeToString(key1))
		} else if *pkey == "deriveb" {
			var rA string
			fmt.Print("Enter rA: ")
			fmt.Scanln(&rA)

			rABytes, err := hex.DecodeString(rA)
			if err != nil {
				log.Fatal("Error decoding rA:", err)
			}

			bExchange := sm9.NewKeyExchange(encryptPrivateKey, []byte(*id), []byte(*id2), *length/8, true)
			defer func() {
				bExchange.Destroy()
			}()
			var g1RA bn256.G1
			_, err = g1RA.Unmarshal(rABytes)
			if err != nil {
				log.Fatal("Error unmarshalling rA: ", err)
			}

			rB, sigB, err := bExchange.RepondKeyExchange(rand.Reader, byte(*hierarchy), &g1RA)
			if err != nil {
				log.Fatal("Error during key exchange B: ", err)
			}

			key2, err := bExchange.ConfirmInitiator(nil)
			if err != nil {
				log.Fatal("Error during confirmation B: ", err)
			}

			fmt.Println("rB=", hex.EncodeToString(rB.Marshal()))
			fmt.Println("signB=", hex.EncodeToString(sigB))
			fmt.Println("Shared=", hex.EncodeToString(key2))
		}
	}

	if *pkey == "keygen" && (strings.ToUpper(*alg) == "SM9SIGN") {
		var privPEM []byte
		file, err := os.Open(*master)
		if err != nil {
			log.Fatal(err)
		}
		fileinfo, err := file.Stat()
		if err != nil {
			log.Fatal(err)
		}
		buf := make([]byte, fileinfo.Size())
		file.Read(buf)
		var block *pem.Block
		block, _ = pem.Decode(buf)
		if block == nil {
			errors.New("no valid private key found")
		}
		var privKeyBytes []byte
		if IsEncryptedPEMBlock(block) {
			privKeyBytes, err = DecryptPEMBlock(block, []byte(*pwd))
			if err != nil {
				log.Fatal(err)
			}
			privPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privKeyBytes})
		} else {
			privPEM = buf
		}

		var privateKeyPemBlock, _ = pem.Decode([]byte(privPEM))

		parsedKey, _ := smx509.ParsePKCS8PrivateKey(privateKeyPemBlock.Bytes)
		if err != nil {
			log.Fatal(err)
		}

		var masterKey *sm9.SignMasterPrivateKey
		switch key := parsedKey.(type) {
		case *sm9.SignMasterPrivateKey:
			masterKey = key
		default:
			log.Fatal("Invalid private key type. Expected sm9.SignMasterPrivateKey.")
		}

		userKey, err := masterKey.GenerateUserKey([]byte(*id), byte(*hierarchy))
		if err != nil {
			fmt.Println("Error generating SM9 user key:", err)
			return
		}

		privKeyBytes, err = smx509.MarshalPKCS8PrivateKey(userKey)

		block = &pem.Block{
			Type:  "SM9 SIGN PRIVATE KEY",
			Bytes: privKeyBytes,
		}
		file, err = os.Create(*priv)
		if err != nil {
			log.Fatal(err)
		}
		if *pwd2 != "" {
			if *cph == "aes128" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd2), PEMCipherAES128)
			} else if *cph == "aes192" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd2), PEMCipherAES192)
			} else if *cph == "aes" || *cph == "aes256" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd2), PEMCipherAES256)
			} else if *cph == "3des" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd2), PEMCipher3DES)
			} else if *cph == "des" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd2), PEMCipherDES)
			} else if *cph == "sm4" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd2), PEMCipherSM4)
			} else if *cph == "gost" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd2), PEMCipherGOST)
			} else if *cph == "idea" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd2), PEMCipherIDEA)
			} else if *cph == "camellia128" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd2), PEMCipherCAMELLIA128)
			} else if *cph == "camellia192" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd2), PEMCipherCAMELLIA192)
			} else if *cph == "camellia" || *cph == "camellia256" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd2), PEMCipherCAMELLIA256)
			} else if *cph == "aria128" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd2), PEMCipherARIA128)
			} else if *cph == "aria192" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd2), PEMCipherARIA192)
			} else if *cph == "aria" || *cph == "aria256" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd2), PEMCipherARIA256)
			} else if *cph == "lea128" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd2), PEMCipherLEA128)
			} else if *cph == "lea192" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd2), PEMCipherLEA192)
			} else if *cph == "lea" || *cph == "lea256" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd2), PEMCipherLEA256)
			} else if *cph == "seed" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd2), PEMCipherSEED)
			} else if *cph == "cast5" {
				block, _ = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd2), PEMCipherCAST)
			} else if *cph == "anubis" {
				block, _ = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd2), PEMCipherANUBIS)
			} else if *cph == "serpent128" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd2), PEMCipherSERPENT128)
			} else if *cph == "serpent192" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd2), PEMCipherSERPENT192)
			} else if *cph == "serpent" || *cph == "serpent256" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd2), PEMCipherSERPENT256)
			} else if *cph == "rc6128" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherRC6128)
			} else if *cph == "rc6192" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherRC6192)
			} else if *cph == "rc6" || *cph == "rc6256" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherRC6256)
			}
			if err != nil {
				log.Fatal(err)
			}
			err = pem.Encode(file, block)
			if err != nil {
				log.Fatal(err)
			}
		} else {
			err = pem.Encode(file, block)
			if err != nil {
				log.Fatal(err)
			}
		}
	}

	if *pkey == "sign" && (strings.ToUpper(*alg) == "SM9SIGN") {
		var privPEM []byte
		file, err := os.Open(*key)
		if err != nil {
			log.Fatal(err)
		}
		info, err := file.Stat()
		if err != nil {
			log.Fatal(err)
		}
		buf := make([]byte, info.Size())
		file.Read(buf)
		var block *pem.Block
		block, _ = pem.Decode(buf)
		if block == nil {
			errors.New("no valid private key found")
		}
		var privKeyBytes []byte
		if IsEncryptedPEMBlock(block) {
			privKeyBytes, err = DecryptPEMBlock(block, []byte(*pwd))
			if err != nil {
				log.Fatal(err)
			}
			privPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privKeyBytes})
		} else {
			privPEM = buf
		}

		var privateKeyPemBlock, _ = pem.Decode([]byte(privPEM))

		var privKey, _ = smx509.ParsePKCS8PrivateKey(privateKeyPemBlock.Bytes)
		if err != nil {
			log.Fatal(err)
		}

		signPrivateKey, ok := privKey.(*sm9.SignPrivateKey)
		if !ok {
			fmt.Println("Invalid private key type. Expected sm9.SignPrivateKey.")
			os.Exit(1)
		}

		hashed, err := ioutil.ReadAll(inputfile)
		if err != nil {
			fmt.Println("Error reading input file:", err)
			os.Exit(1)
		}
		signature, err := sm9.SignASN1(rand.Reader, signPrivateKey, hashed)
		if err != nil {
			fmt.Println("Error signing the message:", err)
			os.Exit(1)
		}

		fmt.Printf("PureSM9(%s)= %x\n", inputdesc, signature)
	}

	if *pkey == "verify" && (strings.ToUpper(*alg) == "SM9SIGN") {
		fileContent, err := ioutil.ReadFile(*key)
		if err != nil {
			fmt.Println("Erro ao ler o arquivo:", err)
			return
		}

		block, _ := pem.Decode(fileContent)
		if block == nil {
			fmt.Println("Failed to decode PEM block containing the public key.")
			return
		}

		pubKey := new(sm9.SignMasterPublicKey)
		err = pubKey.UnmarshalASN1(block.Bytes)
		if err != nil {
			fmt.Println("Error parsing public key with UnmarshalASN1:", err)
			return
		}

		hashed, err := ioutil.ReadAll(inputfile)
		if err != nil {
			fmt.Println("Error reading input file:", err)
			os.Exit(1)
		}

		signature, err := hex.DecodeString(*sig)
		if err != nil {
			fmt.Println("Error decoding hex signature:", err)
			os.Exit(1)
		}

		if sm9.VerifyASN1(pubKey, []byte(*id), byte(*hierarchy), hashed, signature) {
			fmt.Println("Verified: true")
			os.Exit(0)
		} else {
			fmt.Println("Verified: false")
			os.Exit(1)
		}
	}

	if *pkey == "sign" && (strings.ToUpper(*alg) == "EC" || strings.ToUpper(*alg) == "ECDSA") {
		var privatekey *ecdsa.PrivateKey
		var h hash.Hash
		if *md == "sha224" {
			h = sha256.New224()
		} else if *md == "sha256" {
			h = sha256.New()
		} else if *md == "sha384" {
			h = sha512.New384()
		} else if *md == "sha512" {
			h = sha512.New()
		} else if *md == "sha3-224" {
			h = sha3.New224()
		} else if *md == "sha3-256" {
			h = sha3.New256()
		} else if *md == "sha3-384" {
			h = sha3.New384()
		} else if *md == "sha3-512" {
			h = sha3.New512()
		} else if *md == "keccak" || *md == "keccak256" {
			h = sha3.NewLegacyKeccak256()
		} else if *md == "keccak512" {
			h = sha3.NewLegacyKeccak512()
		} else if *md == "lsh224" || *md == "lsh256-224" {
			h = lsh256.New224()
		} else if *md == "lsh" || *md == "lsh256" || *md == "lsh256-256" {
			h = lsh256.New()
		} else if *md == "lsh512-256" {
			h = lsh512.New256()
		} else if *md == "lsh384" || *md == "lsh512-384" {
			h = lsh512.New384()
		} else if *md == "lsh512" {
			h = lsh512.New()
		} else if *md == "has160" {
			h = has160.New()
		} else if *md == "gost94" {
			h = gost341194.New(&gost28147.SboxIdGostR341194CryptoProParamSet)
		} else if *md == "streebog" || *md == "streebog256" {
			h = gost34112012256.New()
		} else if *md == "streebog512" {
			h = gost34112012512.New()
		} else if *md == "shake128" {
			h = sha3.NewShake128()
		} else if *md == "shake256" {
			h = sha3.NewShake256()
		} else if *md == "sha1" {
			h = sha1.New()
		} else if *md == "sm3" {
			h = sm3.New()
		} else if *md == "whirlpool" {
			h = whirlpool.New()
		} else if *md == "cubehash" {
			h = cubehash.New()
		} else if *md == "jh" {
			h = jh.New256()
		} else if *md == "groestl" {
			h = groestl.New256()
		} else if *md == "blake2b256" {
			h = crypto.BLAKE2b_256.New()
		} else if *md == "blake2b512" {
			h = crypto.BLAKE2b_512.New()
		} else if *md == "blake2s256" {
			h = crypto.BLAKE2s_256.New()
		} else if *md == "blake3" {
			h = blake3.New()
		}
		if _, err := io.Copy(h, inputfile); err != nil {
			log.Fatal(err)
		}
		file, err := ioutil.ReadFile(*key)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		privatekey, err = DecodePrivateKey(file)
		if err != nil {
			log.Fatal(err)
		}
		signature, err := ecdsa.SignASN1(rand.Reader, privatekey, h.Sum(nil))
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(strings.ToUpper(*alg)+"-"+strings.ToUpper(*md)+"("+inputdesc+")=", hex.EncodeToString(signature))
		os.Exit(0)
	}

	if *pkey == "verify" && (strings.ToUpper(*alg) == "EC" || strings.ToUpper(*alg) == "ECDSA") {
		var h hash.Hash
		if *md == "sha224" {
			h = sha256.New224()
		} else if *md == "sha256" {
			h = sha256.New()
		} else if *md == "sha384" {
			h = sha512.New384()
		} else if *md == "sha512" {
			h = sha512.New()
		} else if *md == "sha3-224" {
			h = sha3.New224()
		} else if *md == "sha3-256" {
			h = sha3.New256()
		} else if *md == "sha3-384" {
			h = sha3.New384()
		} else if *md == "sha3-512" {
			h = sha3.New512()
		} else if *md == "keccak" || *md == "keccak256" {
			h = sha3.NewLegacyKeccak256()
		} else if *md == "keccak512" {
			h = sha3.NewLegacyKeccak512()
		} else if *md == "lsh224" || *md == "lsh256-224" {
			h = lsh256.New224()
		} else if *md == "lsh" || *md == "lsh256" || *md == "lsh256-256" {
			h = lsh256.New()
		} else if *md == "lsh512-256" {
			h = lsh512.New256()
		} else if *md == "lsh384" || *md == "lsh512-384" {
			h = lsh512.New384()
		} else if *md == "lsh512" {
			h = lsh512.New()
		} else if *md == "has160" {
			h = has160.New()
		} else if *md == "gost94" {
			h = gost341194.New(&gost28147.SboxIdGostR341194CryptoProParamSet)
		} else if *md == "streebog" || *md == "streebog256" {
			h = gost34112012256.New()
		} else if *md == "streebog512" {
			h = gost34112012512.New()
		} else if *md == "shake128" {
			h = sha3.NewShake128()
		} else if *md == "shake256" {
			h = sha3.NewShake256()
		} else if *md == "sha1" {
			h = sha1.New()
		} else if *md == "sm3" {
			h = sm3.New()
		} else if *md == "whirlpool" {
			h = whirlpool.New()
		} else if *md == "cubehash" {
			h = cubehash.New()
		} else if *md == "jh" {
			h = jh.New256()
		} else if *md == "groestl" {
			h = groestl.New256()
		} else if *md == "blake2b256" {
			h = crypto.BLAKE2b_256.New()
		} else if *md == "blake2b512" {
			h = crypto.BLAKE2b_512.New()
		} else if *md == "blake2s256" {
			h = crypto.BLAKE2s_256.New()
		} else if *md == "blake3" {
			h = blake3.New()
		}
		if _, err := io.Copy(h, inputfile); err != nil {
			log.Fatal(err)
		}
		file, err := ioutil.ReadFile(*key)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		public, err = DecodePublicKey(file)
		if err != nil {
			log.Fatal(err)
		}
		sig, _ := hex.DecodeString(*sig)
		verifystatus := ecdsa.VerifyASN1(public, h.Sum(nil), sig)
		if verifystatus == true {
			fmt.Printf("Verified: %v\n", verifystatus)
			os.Exit(0)
		} else {
			fmt.Printf("Verified: %v\n", verifystatus)
			os.Exit(1)
		}
		os.Exit(0)
	}

	if *pkey == "sign" && (strings.ToUpper(*alg) == "SM2") {
		var privatekey *sm2.PrivateKey
		file, err := ioutil.ReadFile(*key)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		privatekey, err = DecodeSM2PrivateKey(file)
		if err != nil {
			log.Fatal(err)
		}
		inputBytes, err := ioutil.ReadAll(inputfile)
		if err != nil {
			log.Fatal(err)
		}
		signature, err := privatekey.Sign(rand.Reader, inputBytes, sm2.DefaultSM2SignerOpts)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("PureSM2("+inputdesc+")=", hex.EncodeToString(signature))
		os.Exit(0)
	}

	if *pkey == "verify" && (strings.ToUpper(*alg) == "SM2") {
		file, err := ioutil.ReadFile(*key)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		public, err = DecodePublicKey(file)
		if err != nil {
			log.Fatal(err)
		}
		inputBytes, err := ioutil.ReadAll(inputfile)
		if err != nil {
			log.Fatal(err)
		}
		sigBytes, err := hex.DecodeString(*sig)
		if err != nil {
			log.Fatal(err)
		}
		verifystatus := sm2.VerifyASN1WithSM2(public, nil, inputBytes, sigBytes)
		if verifystatus == true {
			fmt.Printf("Verified: %v\n", verifystatus)
			os.Exit(0)
		} else {
			fmt.Printf("Verified: %v\n", verifystatus)
			os.Exit(1)
		}
		os.Exit(0)
	}

	if *pkey == "sign" && (strings.ToUpper(*alg) == "ED25519PH") {
		var h hash.Hash
		if *md == "sha224" {
			h = sha256.New224()
		} else if *md == "sha256" {
			h = sha256.New()
		} else if *md == "sha384" {
			h = sha512.New384()
		} else if *md == "sha512" {
			h = sha512.New()
		} else if *md == "sha3-224" {
			h = sha3.New224()
		} else if *md == "sha3-256" {
			h = sha3.New256()
		} else if *md == "sha3-384" {
			h = sha3.New384()
		} else if *md == "sha3-512" {
			h = sha3.New512()
		} else if *md == "keccak" || *md == "keccak256" {
			h = sha3.NewLegacyKeccak256()
		} else if *md == "keccak512" {
			h = sha3.NewLegacyKeccak512()
		} else if *md == "shake128" {
			h = sha3.NewShake128()
		} else if *md == "shake256" {
			h = sha3.NewShake256()
		} else if *md == "sha1" {
			h = sha1.New()
		} else if *md == "whirlpool" {
			h = whirlpool.New()
		} else if *md == "blake2b256" {
			h = crypto.BLAKE2b_256.New()
		} else if *md == "blake2b512" {
			h = crypto.BLAKE2b_512.New()
		} else if *md == "blake2s256" {
			h = crypto.BLAKE2s_256.New()
		} else if *md == "cubehash" {
			h = cubehash.New()
		} else if *md == "jh" {
			h = jh.New256()
		} else if *md == "groestl" {
			h = groestl.New256()
		} else if *md == "blake3" {
			h = blake3.New()
		}
		if _, err := io.Copy(h, inputfile); err != nil {
			log.Fatal(err)
		}
		var privPEM []byte
		file, err := os.Open(*key)
		if err != nil {
			log.Fatal(err)
		}
		info, err := file.Stat()
		if err != nil {
			log.Fatal(err)
		}
		buf := make([]byte, info.Size())
		file.Read(buf)
		var block *pem.Block
		block, _ = pem.Decode(buf)
		if block == nil {
			errors.New("no valid private key found")
		}
		var privKeyBytes []byte
		if IsEncryptedPEMBlock(block) {
			privKeyBytes, err = DecryptPEMBlock(block, []byte(*pwd))
			if err != nil {
				log.Fatal(err)
			}
			privPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privKeyBytes})
		} else {
			privPEM = buf
		}

		var privateKeyPemBlock, _ = pem.Decode([]byte(privPEM))

		var privKey, _ = smx509.ParsePKCS8PrivateKey(privateKeyPemBlock.Bytes)
		if err != nil {
			log.Fatal(err)
		}
		edKey := privKey.(ed25519.PrivateKey)

		signature := ed25519.Sign(edKey, h.Sum(nil))

		fmt.Println("ED25519PH-"+strings.ToUpper(*md)+"("+inputdesc+")=", hex.EncodeToString(signature))
		os.Exit(0)
	}

	if *pkey == "verify" && (strings.ToUpper(*alg) == "ED25519PH") {
		var h hash.Hash
		if *md == "sha224" {
			h = sha256.New224()
		} else if *md == "sha256" {
			h = sha256.New()
		} else if *md == "sha384" {
			h = sha512.New384()
		} else if *md == "sha512" {
			h = sha512.New()
		} else if *md == "sha3-224" {
			h = sha3.New224()
		} else if *md == "sha3-256" {
			h = sha3.New256()
		} else if *md == "sha3-384" {
			h = sha3.New384()
		} else if *md == "sha3-512" {
			h = sha3.New512()
		} else if *md == "keccak" || *md == "keccak256" {
			h = sha3.NewLegacyKeccak256()
		} else if *md == "keccak512" {
			h = sha3.NewLegacyKeccak512()
		} else if *md == "shake128" {
			h = sha3.NewShake128()
		} else if *md == "shake256" {
			h = sha3.NewShake256()
		} else if *md == "sha1" {
			h = sha1.New()
		} else if *md == "whirlpool" {
			h = whirlpool.New()
		} else if *md == "blake2b256" {
			h = crypto.BLAKE2b_256.New()
		} else if *md == "blake2b512" {
			h = crypto.BLAKE2b_512.New()
		} else if *md == "blake2s256" {
			h = crypto.BLAKE2s_256.New()
		} else if *md == "cubehash" {
			h = cubehash.New()
		} else if *md == "jh" {
			h = jh.New256()
		} else if *md == "groestl" {
			h = groestl.New256()
		} else if *md == "blake3" {
			h = blake3.New()
		}
		if _, err := io.Copy(h, inputfile); err != nil {
			log.Fatal(err)
		}
		file, err := os.Open(*key)
		if err != nil {
			log.Fatal(err)
		}
		info, err := file.Stat()
		if err != nil {
			log.Fatal(err)
		}
		buf := make([]byte, info.Size())
		file.Read(buf)
		block, _ := pem.Decode(buf)
		publicInterface, err := smx509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			log.Fatal(err)
		}
		publicKey := publicInterface.(ed25519.PublicKey)
		sig, _ := hex.DecodeString(*sig)
		verifystatus := ed25519.Verify(publicKey, h.Sum(nil), sig)
		if verifystatus == true {
			fmt.Printf("Verified: %v\n", verifystatus)
			os.Exit(0)
		} else {
			fmt.Printf("Verified: %v\n", verifystatus)
			os.Exit(1)
		}
		os.Exit(0)
	}

	if *pkey == "sign" && (strings.ToUpper(*alg) == "ED25519") {
		data := bytes.NewBuffer(nil)
		if _, err := io.Copy(data, inputfile); err != nil {
			log.Fatal(err)
		}
		var privPEM []byte
		file, err := os.Open(*key)
		if err != nil {
			log.Fatal(err)
		}
		info, err := file.Stat()
		if err != nil {
			log.Fatal(err)
		}
		buf := make([]byte, info.Size())
		file.Read(buf)
		var block *pem.Block
		block, _ = pem.Decode(buf)
		if block == nil {
			errors.New("no valid private key found")
		}
		var privKeyBytes []byte
		if IsEncryptedPEMBlock(block) {
			privKeyBytes, err = DecryptPEMBlock(block, []byte(*pwd))
			if err != nil {
				log.Fatal(err)
			}
			privPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privKeyBytes})
		} else {
			privPEM = buf
		}

		var privateKeyPemBlock, _ = pem.Decode([]byte(privPEM))

		var privKey, _ = smx509.ParsePKCS8PrivateKey(privateKeyPemBlock.Bytes)
		if err != nil {
			log.Fatal(err)
		}
		edKey := privKey.(ed25519.PrivateKey)

		signature := ed25519.Sign(edKey, data.Bytes())

		fmt.Println("PureED25519("+inputdesc+")=", hex.EncodeToString(signature))
		os.Exit(0)
	}

	if *pkey == "verify" && (strings.ToUpper(*alg) == "ED25519") {
		data := bytes.NewBuffer(nil)
		if _, err := io.Copy(data, inputfile); err != nil {
			log.Fatal(err)
		}
		file, err := os.Open(*key)
		if err != nil {
			log.Fatal(err)
		}
		info, err := file.Stat()
		if err != nil {
			log.Fatal(err)
		}
		buf := make([]byte, info.Size())
		file.Read(buf)
		block, _ := pem.Decode(buf)
		publicInterface, err := smx509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			log.Fatal(err)
		}
		publicKey := publicInterface.(ed25519.PublicKey)
		sig, _ := hex.DecodeString(*sig)
		verifystatus := ed25519.Verify(publicKey, data.Bytes(), sig)
		if verifystatus == true {
			fmt.Printf("Verified: %v\n", verifystatus)
			os.Exit(0)
		} else {
			fmt.Printf("Verified: %v\n", verifystatus)
			os.Exit(1)
		}
		os.Exit(0)
	}

	if *pkey == "keygen" && (strings.ToUpper(*alg) == "X25519") {
		var privateKey *ecdh.PrivateKey

		privateKey, err = ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			log.Fatal(err)
		}
		publicKey := privateKey.Public()

		privateKey, err := ecdh.X25519().NewPrivateKey(privateKey.Bytes())
		if err != nil {
			log.Fatal(err)
		}

		privateStream, err := x509.MarshalPKCS8PrivateKey(privateKey)
		if err != nil {
			log.Fatal(err)
		}

		block := &pem.Block{
			Type:  "X25519 PRIVATE KEY",
			Bytes: privateStream,
		}
		file, err := os.Create(*priv)
		if err != nil {
			log.Fatal(err)
		}
		if *pwd != "" {
			if *cph == "aes128" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherAES128)
			} else if *cph == "aes192" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherAES192)
			} else if *cph == "aes" || *cph == "aes256" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherAES256)
			} else if *cph == "3des" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipher3DES)
			} else if *cph == "des" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherDES)
			} else if *cph == "sm4" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherSM4)
			} else if *cph == "gost" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherGOST)
			} else if *cph == "idea" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherIDEA)
			} else if *cph == "camellia128" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherCAMELLIA128)
			} else if *cph == "camellia192" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherCAMELLIA192)
			} else if *cph == "camellia" || *cph == "camellia256" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherCAMELLIA256)
			} else if *cph == "aria128" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherARIA128)
			} else if *cph == "aria192" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherARIA192)
			} else if *cph == "aria" || *cph == "aria256" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherARIA256)
			} else if *cph == "lea128" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherLEA128)
			} else if *cph == "lea192" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherLEA192)
			} else if *cph == "lea" || *cph == "lea256" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherLEA256)
			} else if *cph == "seed" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherSEED)
			} else if *cph == "cast5" {
				block, _ = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherCAST)
			} else if *cph == "anubis" {
				block, _ = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherANUBIS)
			} else if *cph == "serpent128" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherSERPENT128)
			} else if *cph == "serpent192" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherSERPENT192)
			} else if *cph == "serpent" || *cph == "serpent256" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherSERPENT256)
			} else if *cph == "rc6128" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherRC6128)
			} else if *cph == "rc6192" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherRC6192)
			} else if *cph == "rc6" || *cph == "rc6256" {
				block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherRC6256)
			}
			if err != nil {
				log.Fatal(err)
			}
			err = pem.Encode(file, block)
			if err != nil {
				log.Fatal(err)
			}
		} else {
			err = pem.Encode(file, block)
			if err != nil {
				log.Fatal(err)
			}
		}

		publicStream, err := x509.MarshalPKIXPublicKey(publicKey)
		if err != nil {
			log.Fatal(err)
		}
		pubblock := &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: publicStream,
		}
		pubfile, err := os.Create(*pub)
		if err != nil {
			log.Fatal(err)
		}
		err = pem.Encode(pubfile, pubblock)
		if err != nil {
			log.Fatal(err)
		}

		absPrivPath, err := filepath.Abs(*priv)
		if err != nil {
			log.Fatal("Failed to get absolute path for private key:", err)
		}
		absPubPath, err := filepath.Abs(*pub)
		if err != nil {
			log.Fatal("Failed to get absolute path for public key:", err)
		}
		println("Private key saved to:", absPrivPath)
		println("Public key saved to:", absPubPath)

		file, err = os.Open(*pub)
		if err != nil {
			log.Fatal(err)
		}
		info, err := file.Stat()
		if err != nil {
			log.Fatal(err)
		}
		buf := make([]byte, info.Size())
		file.Read(buf)
		fingerprint := calculateFingerprint(buf)
		print("Fingerprint: ")
		println(fingerprint)
		printKeyDetails(pubblock)
		randomArt := randomart.FromString(string(buf))
		println(randomArt)

		os.Exit(0)
	}

	if (*pkey == "derive" && strings.ToUpper(*alg) == "X25519") || strings.ToUpper(*pkey) == "X25519" {
		var privPEM []byte
		file, err := os.Open(*key)
		if err != nil {
			log.Fatal(err)
		}
		info, err := file.Stat()
		if err != nil {
			log.Fatal(err)
		}
		buf := make([]byte, info.Size())
		file.Read(buf)
		var block *pem.Block
		block, _ = pem.Decode(buf)
		if block == nil {
			errors.New("no valid private key found")
		}
		var privKeyBytes []byte
		if IsEncryptedPEMBlock(block) {
			privKeyBytes, err = DecryptPEMBlock(block, []byte(*pwd))
			if err != nil {
				log.Fatal(err)
			}
			privPEM = pem.EncodeToMemory(&pem.Block{Type: "X25519 PRIVATE KEY", Bytes: privKeyBytes})
		} else {
			privPEM = buf
		}

		var privateKeyPemBlock, _ = pem.Decode([]byte(privPEM))

		var privKey, _ = x509.ParsePKCS8PrivateKey(privateKeyPemBlock.Bytes)
		if err != nil {
			log.Fatal(err)
		}
		XKey := privKey.(*ecdh.PrivateKey)

		file, err = os.Open(*pub)
		if err != nil {
			log.Fatal(err)
		}
		info, err = file.Stat()
		if err != nil {
			log.Fatal(err)
		}
		buf = make([]byte, info.Size())
		file.Read(buf)
		block, _ = pem.Decode(buf)
		publicInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			log.Fatal(err)
		}
		publicKey := publicInterface.(*ecdh.PublicKey)

		var secret []byte
		secret, err = XKey.ECDH(publicKey)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%x\n", secret[:])
		os.Exit(0)
	}

	if *pkey == "derive" && strings.ToUpper(*alg) != "GOST2012" {
		var privatekey *ecdsa.PrivateKey
		file, err := ioutil.ReadFile(*pub)
		if err != nil {
			log.Fatal(err)
		}
		public, err = DecodePublicKey(file)
		if err != nil {
			log.Fatal(err)
		}
		file2, err := ioutil.ReadFile(*key)
		if err != nil {
			log.Fatal(err)
			os.Exit(1)
		}
		privatekey, err = DecodePrivateKey(file2)
		if err != nil {
			log.Fatal(err)
		}
		b, _ := public.Curve.ScalarMult(public.X, public.Y, privatekey.D.Bytes())
		fmt.Printf("%x", b.Bytes())
		os.Exit(0)
	}

	if *pkey == "keygen" && strings.ToUpper(*alg) == "GOST2012" {
		var gost341012PrivRaw []byte
		var curve *gost3410.Curve
		if *length == 256 && (*paramset == "A" || *paramset == "B" || *paramset == "C" || *paramset == "D") {
			if strings.ToUpper(*paramset) == "A" {
				curve = gost3410.CurveIdtc26gost341012256paramSetA()
			} else if *length == 256 && strings.ToUpper(*paramset) == "B" {
				curve = gost3410.CurveIdtc26gost341012256paramSetB()
			} else if *length == 256 && strings.ToUpper(*paramset) == "C" {
				curve = gost3410.CurveIdtc26gost341012256paramSetC()
			} else if *length == 256 && strings.ToUpper(*paramset) == "D" {
				curve = gost3410.CurveIdtc26gost341012256paramSetD()
			}
			gost341012PrivRaw = make([]byte, 32)
		} else if *length == 512 && (*paramset == "A" || *paramset == "B" || *paramset == "C") {
			if strings.ToUpper(*paramset) == "A" {
				curve = gost3410.CurveIdtc26gost341012512paramSetA()
			} else if strings.ToUpper(*paramset) == "B" {
				curve = gost3410.CurveIdtc26gost341012512paramSetB()
			} else if strings.ToUpper(*paramset) == "C" {
				curve = gost3410.CurveIdtc26gost341012512paramSetC()
			}
			gost341012PrivRaw = make([]byte, 64)
		}
		if _, err = io.ReadFull(rand.Reader, gost341012PrivRaw); err != nil {
			log.Fatalf("Failed to read random for GOST private key: %s", err)
		}
		gost341012256Priv, err := gost3410.NewPrivateKey(
			curve,
			gost341012PrivRaw,
		)
		if err != nil {
			log.Fatalf("Failed to create GOST private key: %s", err)
		}
		gost341012256Pub := gost341012256Priv.Public()

		privateStream, err := x509.MarshalPKCS8PrivateKey(gost341012256Priv)
		if err != nil {
			log.Fatal(err)
		}
		block := &pem.Block{
			Type:  "GOST PRIVATE KEY",
			Bytes: privateStream,
		}
		file, err := os.Create(*priv)
		if err != nil {
			log.Fatal(err)
		}
		if *pwd != "" {
			block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherGOST)
			if err != nil {
				log.Fatal(err)
			}
			err = pem.Encode(file, block)
			if err != nil {
				log.Fatal(err)
			}
		} else {
			err = pem.Encode(file, block)
			if err != nil {
				log.Fatal(err)
			}
		}
		publicStream, err := x509.MarshalPKIXPublicKey(gost341012256Pub)
		if err != nil {
			log.Fatal(err)
		}
		pubblock := &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: publicStream,
		}
		pubfile, err := os.Create(*pub)
		if err != nil {
			log.Fatal(err)
		}
		err = pem.Encode(pubfile, pubblock)
		if err != nil {
			log.Fatal(err)
		}

		absPrivPath, err := filepath.Abs(*priv)
		if err != nil {
			log.Fatal("Failed to get absolute path for private key:", err)
		}
		absPubPath, err := filepath.Abs(*pub)
		if err != nil {
			log.Fatal("Failed to get absolute path for public key:", err)
		}
		println("Private key saved to:", absPrivPath)
		println("Public key saved to:", absPubPath)

		file, err = os.Open(*pub)
		if err != nil {
			log.Fatal(err)
		}
		info, err := file.Stat()
		if err != nil {
			log.Fatal(err)
		}
		buf := make([]byte, info.Size())
		file.Read(buf)
		fingerprint := calculateFingerprintGOST(buf)
		print("Fingerprint: ")
		println(fingerprint)
		printKeyDetails(pubblock)
		randomArt := randomart.FromString(string(buf))
		println(randomArt)
	}

	if (*pkey == "derive" && strings.ToUpper(*alg) == "GOST2012") || strings.ToUpper(*pkey) == "VKO" {
		var privPEM []byte
		file, err := os.Open(*key)
		if err != nil {
			log.Println(err)
		}
		info, err := file.Stat()
		if err != nil {
			log.Println(err)
		}
		buf := make([]byte, info.Size())
		file.Read(buf)
		var block *pem.Block
		block, _ = pem.Decode(buf)
		if block == nil {
			errors.New("no valid private key found")
		}
		var privKeyBytes []byte
		if IsEncryptedPEMBlock(block) {
			privKeyBytes, err = DecryptPEMBlock(block, []byte(*pwd))
			if err != nil {
				log.Fatal(err)
			}
			privPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privKeyBytes})
		} else {
			privPEM = buf
		}
		var privateKeyPemBlock, _ = pem.Decode([]byte(privPEM))
		var privKey, _ = x509.ParsePKCS8PrivateKey(privateKeyPemBlock.Bytes)
		if err != nil {
			log.Println(err)
		}
		privateKey := privKey.(*gost3410.PrivateKey)

		file, err = os.Open(*pub)
		if err != nil {
			log.Fatal(err)
		}
		info, err = file.Stat()
		if err != nil {
			log.Fatal(err)
		}
		buf = make([]byte, info.Size())
		file.Read(buf)
		block, _ = pem.Decode(buf)
		publicInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			log.Fatal(err)
		}
		publicKey := publicInterface.(*gost3410.PublicKey)

		var shared []byte
		if *length == 512 {
			shared, err = privateKey.KEK2012512(publicKey, big.NewInt(1))
		} else {
			shared, err = privateKey.KEK2012256(publicKey, big.NewInt(1))
		}
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(hex.EncodeToString(shared))
	}

	if *pkey == "sign" && strings.ToUpper(*alg) == "GOST2012" {
		var privPEM []byte
		var h hash.Hash
		if *length == 512 {
			h = gost34112012512.New()
		} else {
			h = gost34112012256.New()
		}
		if _, err := io.Copy(h, inputfile); err != nil {
			log.Fatal(err)
		}
		file, err := os.Open(*key)
		if err != nil {
			log.Println(err)
		}
		info, err := file.Stat()
		if err != nil {
			log.Println(err)
		}
		buf := make([]byte, info.Size())
		file.Read(buf)
		var block *pem.Block
		block, _ = pem.Decode(buf)
		if block == nil {
			errors.New("no valid private key found")
		}
		var privKeyBytes []byte
		if IsEncryptedPEMBlock(block) {
			privKeyBytes, err = DecryptPEMBlock(block, []byte(*pwd))
			if err != nil {
				log.Fatal(err)
			}
			privPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privKeyBytes})
		} else {
			privPEM = buf
		}
		var privateKeyPemBlock, _ = pem.Decode([]byte(privPEM))
		var privKey, _ = x509.ParsePKCS8PrivateKey(privateKeyPemBlock.Bytes)
		if err != nil {
			log.Println(err)
		}
		gostKey := privKey.(*gost3410.PrivateKey)
		signature, err := gostKey.Sign(rand.Reader, h.Sum(nil), nil)
		if err != nil {
			log.Fatal(err)
		}
		if *length == 512 {
			fmt.Println("GOST2012-STREEBOG512("+inputdesc+")=", hex.EncodeToString(signature))
		} else {
			fmt.Println("GOST2012-STREEBOG256("+inputdesc+")=", hex.EncodeToString(signature))
		}
		os.Exit(0)
	}

	if *pkey == "verify" && strings.ToUpper(*alg) == "GOST2012" {
		var h hash.Hash
		if *length == 512 {
			h = gost34112012512.New()
		} else {
			h = gost34112012256.New()
		}
		if _, err := io.Copy(h, inputfile); err != nil {
			log.Fatal(err)
		}
		file, err := os.Open(*key)
		if err != nil {
			log.Fatal(err)
		}
		info, err := file.Stat()
		if err != nil {
			log.Fatal(err)
		}
		buf := make([]byte, info.Size())
		file.Read(buf)
		block, _ := pem.Decode(buf)
		publicInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			log.Fatal(err)
		}
		publicKey := publicInterface.(*gost3410.PublicKey)
		inputsig, err := hex.DecodeString(*sig)
		if err != nil {
			log.Fatal(err)
		}
		isValid, err := publicKey.VerifyDigest(h.Sum(nil), inputsig)
		if err != nil {
			log.Fatal(err)
		}
		if !isValid {
			fmt.Println("Verified: false")
			os.Exit(1)
		}
		fmt.Println("Verified: true")
		os.Exit(0)
	}

	var PEM string
	var b []byte
	if (*pkey == "text" || *pkey == "modulus" || *pkey == "check" || *pkey == "randomart" || *pkey == "fingerprint" || *pkey == "info") && *crl == "" && *params == "" {
		if *key != "" {
			b, err = ioutil.ReadFile(*key)
			if err != nil {
				log.Fatal(err)
			}
		} else if *key == "" {
			b, err = ioutil.ReadFile(*cert)
			if err != nil {
				log.Fatal(err)
			}
		}
		s := string(b)
		if strings.Contains(s, "PRIVATE") {
			PEM = "Private"
		} else if strings.Contains(s, "MASTER") {
			PEM = "Master"
		} else if strings.Contains(s, "PUBLIC") {
			PEM = "Public"
		} else if strings.Contains(s, "CERTIFICATE REQUEST") {
			PEM = "CertificateRequest"
		} else if strings.Contains(s, "CERTIFICATE") {
			PEM = "Certificate"
		}

		if strings.Contains(s, "RSA PRIVATE") {
			*alg = "RSA"
		} else if strings.Contains(s, "EC PRIVATE") {
			*alg = "EC"
		} else if strings.Contains(s, "GOST PRIVATE") {
			*alg = "GOST2012"
		} else if strings.Contains(s, "X25519 PRIVATE") {
			*alg = "X25519"
		} else if strings.Contains(s, "SM9 ENC") {
			*alg = "SM9ENCRYPT"
		} else if strings.Contains(s, "SM9 SIGN") {
			*alg = "SM9SIGN"
		} else if strings.Contains(s, "SPHINCS") {
			*alg = "SPHINCS"
		} else if strings.Contains(s, "EC-ELGAMAL") {
			*alg = "EC-ELGAMAL"
		} else if strings.Contains(s, "ELGAMAL") {
			*alg = "ELGAMAL"
		} else if strings.Contains(s, "PRIVATE") {
			*alg = "ED25519"
		}
	}

	if strings.ToUpper(*alg) == "SPHINCS" && *pkey == "keygen" {
		generateKeyPair(*priv, *pub)
	}

	if strings.ToUpper(*alg) == "SPHINCS" && *pkey == "sign" {
		signMessage(inputfile, *key)
	}

	if strings.ToUpper(*alg) == "SPHINCS" && *pkey == "verify" {
		verifySignature(inputfile, *key, *sig)
	}

	if *pkey == "modulus" && strings.ToUpper(*alg) == "SPHINCS" {
		file, err := os.Open(*key)
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()

		pemData, err := ioutil.ReadAll(file)
		if err != nil {
			log.Fatal(err)
		}

		block, _ := pem.Decode(pemData)
		if block == nil {
			log.Fatal("failed to parse PEM block containing the key")
		}

		isPrivateKey := block.Type == "SPHINCS SECRET KEY"

		loadedKeyBytes, err := loadPEMKey(*key, *pwd)
		if err := printKeyParams(loadedKeyBytes, isPrivateKey); err != nil {
			log.Fatal(err)
		}
	}

	if *pkey == "text" && strings.ToUpper(*alg) == "SPHINCS" {
		file, err := os.Open(*key)
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()

		pemData, err := ioutil.ReadAll(file)
		if err != nil {
			log.Fatal(err)
		}

		block, _ := pem.Decode(pemData)
		if block == nil {
			log.Fatal("failed to parse PEM block containing the key")
		}

		isPrivateKey := block.Type == "SPHINCS SECRET KEY"

		loadedKeyBytes, err := loadPEMKey(*key, *pwd)
		if err := printKeyParamsFull(loadedKeyBytes, isPrivateKey); err != nil {
			log.Fatal(err)
		}
	}

	if *pkey == "randomart" && strings.ToUpper(*alg) == "SPHINCS" {
		file, err := os.Open(*key)
		if err != nil {
			log.Fatal(err)
		}
		info, err := file.Stat()
		if err != nil {
			log.Fatal(err)
		}
		buf := make([]byte, info.Size())
		file.Read(buf)
		println("SPHINCS+ (256-bit)")
		randomArt := randomart.FromString(string(buf))
		println(randomArt)
		os.Exit(0)
	}

	if *pkey == "fingerprint" && strings.ToUpper(*alg) == "SPHINCS" {
		file, err := os.Open(*key)
		if err != nil {
			log.Fatal(err)
		}
		info, err := file.Stat()
		if err != nil {
			log.Fatal(err)
		}
		buf := make([]byte, info.Size())
		file.Read(buf)
		fingerprint := calculateFingerprint(buf)
		print("Fingerprint= ")
		println(fingerprint)
		os.Exit(0)
	}

	if (strings.ToUpper(*alg) == "ELGAMAL" || strings.ToUpper(*alg) == "EG" && strings.ToUpper(*alg) != "EC-ELGAMAL" || *params != "") && (*pkey == "keygen" || *pkey == "setup" || *pkey == "wrapkey" || *pkey == "unwrapkey" || *pkey == "text" || *pkey == "modulus" || *pkey == "sign" || *pkey == "verify") {
		if *pkey == "setup" {
			setParams, err := generateElGamalParams()
			err = saveElGamalParamsToPEM(*params, setParams)
			if err != nil {
				log.Fatal("Error saving ElGamal parameters to PEM file:", err)
				return
			}
			os.Exit(0)
		}
		var blockType string
		if *key != "" {
			pemData, err := ioutil.ReadFile(*key)
			if err != nil {
				fmt.Println("Error reading PEM file:", err)
				os.Exit(1)
			}
			block, _ := pem.Decode(pemData)
			if block == nil {
				fmt.Println("Error decoding PEM block")
				os.Exit(1)
			}
			blockType = block.Type
		}
		if *pkey == "text" && *key != "" && blockType == "ELGAMAL PRIVATE KEY" {
			priv, err := readPrivateKeyFromPEM(*key)
			if err != nil {
				fmt.Println("Error reading private key:", err)
				return
			}
			privPEM := &PrivateKey{
				X: priv.X,
				P: priv.P,
				G: priv.G,
			}

			privBytes, err := encodePrivateKeyPEM(privPEM)
			if err != nil {
				log.Fatal(err)
			}
			pemBlock := &pem.Block{
				Type:  "ELGAMAL PRIVATE KEY",
				Bytes: privBytes,
			}
			publicKey := setup(priv.X, priv.G, priv.P)

			pemData := pem.EncodeToMemory(pemBlock)
			fmt.Print(string(pemData))
			xval := new(big.Int).Set(priv.X)
			fmt.Println("PrivateKey(x):")
			x := fmt.Sprintf("%x", xval)
			splitz := SplitSubN(x, 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}
			fmt.Println("Prime(p):")
			p := fmt.Sprintf("%x", priv.P)
			splitz = SplitSubN(p, 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}
			fmt.Println("Generator(g in the range [2, p-2]):")
			g := fmt.Sprintf("%x", priv.G)
			splitz = SplitSubN(g, 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}
			fmt.Println("PublicKey(Y = g^x mod p):")
			pub := fmt.Sprintf("%x", publicKey)
			splitz = SplitSubN(pub, 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}
			os.Exit(0)
		}
		if *pkey == "text" && *key != "" && blockType == "ELGAMAL PUBLIC KEY" {
			pemData, err := ioutil.ReadFile(*key)
			if err != nil {
				fmt.Println("Error reading PEM file:", err)
				os.Exit(1)
			}
			fmt.Print(string(pemData))
			publicKeyVal, err := readPublicKeyFromPEM(*key)
			if err != nil {
				fmt.Println("Error: Invalid public key value")
				os.Exit(1)
			}
			fmt.Println("Public Key Parameters:")
			fmt.Println("Prime(p):")
			p := fmt.Sprintf("%x", publicKeyVal.P)
			splitz := SplitSubN(p, 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}
			fmt.Println("Generator(g):")
			g := fmt.Sprintf("%x", publicKeyVal.G)
			splitz = SplitSubN(g, 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}
			fmt.Println("PublicKey(Y):")
			y := fmt.Sprintf("%x", publicKeyVal.Y)
			splitz = SplitSubN(y, 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}
			return
		}
		if *pkey == "modulus" && blockType == "ELGAMAL PRIVATE KEY" {
			privKey, err := readPrivateKeyFromPEM(*key)
			if err != nil {
				fmt.Println("Error reading private key:", err)
				os.Exit(1)
			}
			publicKey := setup(privKey.X, privKey.G, privKey.P)
			fmt.Printf("Y=%X\n", publicKey)
			return
		}
		if *pkey == "modulus" && blockType == "ELGAMAL PUBLIC KEY" {
			publicKey, err := readPublicKeyFromPEM(*key)
			if err != nil {
				fmt.Println("Error reading public key:", err)
				os.Exit(1)
			}
			fmt.Printf("Y=%X\n", publicKey.Y)
			return
		}
		if *pkey == "wrapkey" {
			publicKeyVal, err := readPublicKeyFromPEM(*key)
			if err != nil {
				fmt.Println("Error: Invalid public key value")
				os.Exit(1)
			}

			pub := &PublicKey{
				G: publicKeyVal.G,
				P: publicKeyVal.P,
				Y: publicKeyVal.Y,
			}

			messageBytes := make([]byte, *length/8)
			_, err = rand.Read(messageBytes)
			if err != nil {
				fmt.Println("Error generating random key:", err)
				os.Exit(1)
			}
			c, err := encrypt(rand.Reader, pub, messageBytes)
			if err != nil {
				fmt.Println("Error encrypting message:", err)
				os.Exit(1)
			}

			fmt.Printf("Cipher= %s\n", c)
			fmt.Printf("Shared= %x\n", messageBytes)
			os.Exit(0)
		}
		if *pkey == "unwrapkey" {
			if *key == "" {
				fmt.Println("Error: Private key file not provided for unwrapping.")
				os.Exit(1)
			}

			priv, err := readPrivateKeyFromPEM(*key)
			if err != nil {
				fmt.Println("Error reading private key:", err)
				os.Exit(1)
			}

			ciphertext := *cph
			message, err := decrypt(priv, ciphertext)
			if err != nil {
				fmt.Println("Error decrypting message:", err)
				os.Exit(1)
			}
			fmt.Printf("Shared= %x\n", message)
		}
		if *pkey == "text" {
			readParams, err := readElGamalParamsFromPEM(*params)
			if err != nil {
				fmt.Println("Error reading ElGamal parameters from PEM file:", err)
				os.Exit(1)
			}

			pemData, err := ioutil.ReadFile(*params)
			if err != nil {
				fmt.Println("Error reading PEM file:", err)
				os.Exit(1)
			}
			fmt.Print(string(pemData))
			fmt.Println("ElGamal Parameters:")
			fmt.Println("Prime(p):")
			p := fmt.Sprintf("%x", readParams.P)
			splitz := SplitSubN(p, 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}
			fmt.Println("Generator(g):")
			g := fmt.Sprintf("%x", readParams.G)
			splitz = SplitSubN(g, 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}
			os.Exit(0)
		}
		if *pkey == "keygen" {
			var xval *big.Int
			var path string

			readParams, err := readElGamalParamsFromPEM(*params)
			if err != nil {
				log.Fatal("Error reading ElGamal parameters from PEM file:", err)
				os.Exit(1)
			}

			if *key == "" {
				xval, err = generateRandomX(readParams.P)
				if err != nil {
					log.Fatal("Error generating x:", err)
					os.Exit(1)
				}
				path, err = filepath.Abs(*priv)
				privateKey := &PrivateKey{
					X: xval,
					P: readParams.P,
					G: readParams.G,
				}
				if err := savePrivateKeyToPEM(*priv, privateKey); err != nil {
					log.Fatal("Error saving private key:", err)
					os.Exit(1)
				}
				fmt.Fprintf(os.Stderr, "Private Key save to: %s\n", path)
			} else {
				priv, err := readPrivateKeyFromPEM(*key)
				if err != nil {
					log.Fatal("Error reading private key:", err)
					os.Exit(1)
				}
				xval = new(big.Int).Set(priv.X)
			}

			publicKey := setup(xval, readParams.G, readParams.P)

			path, err = filepath.Abs(*pub)
			fmt.Fprintf(os.Stderr, "Public Key save to: %s\n", path)
			if err := savePublicKeyToPEM(*pub, &PublicKey{Y: publicKey, G: readParams.G, P: readParams.P}); err != nil {
				log.Fatal("Error saving public key:", err)
				os.Exit(1)
			}

			fingerprint := calculateFingerprint(publicKey.Bytes())
			fmt.Fprintf(os.Stderr, "Fingerprint: %s\n", fingerprint)

			primeBitLength := readParams.P.BitLen()
			fmt.Fprintf(os.Stderr, "ElGamal (%d-bits)\n", primeBitLength)

			file, err := os.Open(*pub)
			if err != nil {
				log.Fatal(err)
			}

			info, err := file.Stat()
			if err != nil {
				log.Fatal(err)
			}

			buf := make([]byte, info.Size())
			file.Read(buf)
			randomArt := randomart.FromString(string(buf))
			fmt.Fprintln(os.Stderr, randomArt)

			return
		}
		if *pkey == "sign" {
			message, err := ioutil.ReadAll(inputfile)
			if err != nil {
				fmt.Println("Error reading file:", err)
				os.Exit(1)
			}

			priv, err := readPrivateKeyFromPEM(*key)
			if err != nil {
				fmt.Println("Error reading private key:", err)
				os.Exit(1)
			}

			sign, err := sign(priv, message, myHash)
			if err != nil {
				log.Fatal("Error signing message:", err)
				os.Exit(1)
			}

			fmt.Println("EG-"+strings.ToUpper(*md)+"("+inputdesc+")=", sign)
		}
		if *pkey == "verify" {
			message, err := ioutil.ReadAll(inputfile)
			if err != nil {
				fmt.Println("Error reading file:", err)
				os.Exit(1)
			}

			if *key == "" {
				fmt.Println("Error: Public key file not provided for verification.")
				os.Exit(3)
			}

			publicKeyVal, err := readPublicKeyFromPEM(*key)
			if err != nil {
				fmt.Println("Error: Invalid public key value")
				os.Exit(1)
			}

			pub := &PublicKey{
				G: publicKeyVal.G,
				P: publicKeyVal.P,
				Y: publicKeyVal.Y,
			}

			isValid := verify(pub, message, *sig, myHash)
			fmt.Println("Verified:", isValid)
			if isValid {
				os.Exit(0)
			} else {
				os.Exit(1)
			}
		}
	}

	if (strings.ToUpper(*alg) == "EC-ELGAMAL") && (*pkey == "keygen" || *pkey == "wrapkey" || *pkey == "unwrapkey" || *pkey == "text" || *pkey == "modulus" || *pkey == "fingerprint" || *pkey == "randomart") {
		var blockType string
		if *key != "" {
			pemData, err := ioutil.ReadFile(*key)
			if err != nil {
				fmt.Println("Error reading PEM file:", err)
				os.Exit(1)
			}
			block, _ := pem.Decode(pemData)
			if block == nil {
				fmt.Println("Error decoding PEM block")
				os.Exit(1)
			}
			blockType = block.Type
		}
		if *pkey == "text" && *key != "" && blockType == "EC-ELGAMAL ENCRYPTION KEY" {
			keyBytes, err := readKeyFromPEM(*key, false)
			if err != nil {
				fmt.Println("Error reading key from PEM:", err)
				os.Exit(1)
			}
			pubKeyPEM := pem.Block{Type: "EC-ELGAMAL ENCRYPTION KEY", Bytes: keyBytes}
			keyPEMText := string(pem.EncodeToMemory(&pubKeyPEM))
			fmt.Print(keyPEMText)
			fmt.Println("EncryptionKey:")
			p := fmt.Sprintf("%x", keyBytes)
			splitz := SplitSubN(p, 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}
			os.Exit(0)
		} else if *pkey == "text" && *key != "" && blockType == "EC-ELGAMAL DECRYPTION KEY" {
			keyBytes, err := ioutil.ReadFile(*key)
			if err != nil {
				log.Fatal(err)
			}

			block, _ := pem.Decode(keyBytes)
			if block == nil {
				log.Fatal(err)
			}

			curve, ok := block.Headers["Curve"]
			if !ok {
				fmt.Println("Curve not found in headers.")
			}

			keyBytes, err = readKeyFromPEM(*key, true)
			if err != nil {
				fmt.Println("Error reading key from PEM:", err)
				os.Exit(1)
			}
			privKeyPEM := pem.Block{
				Type:  "EC-ELGAMAL DECRYPTION KEY",
				Bytes: keyBytes,
				Headers: map[string]string{
					"Curve": curve,
				},
			}
			keyPEMText := string(pem.EncodeToMemory(&privKeyPEM))
			fmt.Print(keyPEMText)

			dk := new(elgamal.DecryptionKey)

			err = dk.UnmarshalBinary(keyBytes)
			if err != nil {
				fmt.Println("Error decoding private key:", err)
				os.Exit(1)
			}
			ek := dk.EncryptionKey()
			pubBytes, _ := ek.MarshalBinary()

			fmt.Println("DecryptionKey:")
			prv := fmt.Sprintf("%x", keyBytes)
			splitz := SplitSubN(prv, 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}
			fmt.Println("EncryptionKey:")
			pub := fmt.Sprintf("%x", pubBytes)
			splitz = SplitSubN(pub, 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}
			os.Exit(0)
		}
		if *pkey == "modulus" && *key != "" && blockType == "EC-ELGAMAL ENCRYPTION KEY" {
			keyBytes, err := readKeyFromPEM(*key, false)
			if err != nil {
				fmt.Println("Error reading key from PEM:", err)
				os.Exit(1)
			}
			fmt.Printf("Public=%X\n", keyBytes)
			os.Exit(0)
		}
		if *pkey == "modulus" && *key != "" && blockType == "EC-ELGAMAL DECRYPTION KEY" {
			keyBytes, err := readKeyFromPEM(*key, true)
			if err != nil {
				fmt.Println("Error reading key from PEM:", err)
				os.Exit(1)
			}
			dk := new(elgamal.DecryptionKey)
			err = dk.UnmarshalBinary(keyBytes)
			if err != nil {
				fmt.Println("Error decoding private key:", err)
				os.Exit(1)
			}
			ek := dk.EncryptionKey()
			pubBytes, _ := ek.MarshalBinary()
			fmt.Printf("Public=%X\n", pubBytes)
			os.Exit(0)
		}
		if *pkey == "fingerprint" && *key != "" {
			keyBytes, err := readKeyFromPEM(*key, false)
			if err != nil {
				fmt.Println("Error reading key from PEM:", err)
				os.Exit(1)
			}
			fingerprint := calculateFingerprint(keyBytes)
			fmt.Printf("Fingerprint: %s\n", fingerprint)
			os.Exit(0)
		}
		if *pkey == "randomart" && *key != "" {
			keyBytes, err := readKeyFromPEM(*key, false)
			if err != nil {
				fmt.Println("Error reading key from PEM:", err)
				return
			}
			keySize := len(keyBytes) * 8
			if keySize != 320 {
				fmt.Println("EC-ElGamal (381-bit)")
			} else {
				fmt.Println("EC-ElGamal (256-bit)")
			}
			pubFile, err := os.Open(*pub)
			if err != nil {
				fmt.Println("Error opening public key file:", err)
				os.Exit(1)
			}
			defer pubFile.Close()

			pubInfo, err := pubFile.Stat()
			if err != nil {
				fmt.Println("Error getting public key file info:", err)
				os.Exit(1)
			}

			pubBuf := make([]byte, pubInfo.Size())
			pubFile.Read(pubBuf)
			randomArt := randomart.FromString(string(pubBuf))
			fmt.Println(randomArt)
			os.Exit(0)
		}
		if *pkey == "keygen" {
			var curve *curves.Curve
			switch strings.ToUpper(*curveFlag) {
			case "BLS12381G1":
				curve = curves.BLS12381G1()
			case "BLS12381G2":
				curve = curves.BLS12381G2()
			case "P256", "ECDSA", "EC", "SECP256R1":
				curve = curves.P256()
			default:
				fmt.Println("Unsupported curve:", *curveFlag)
				os.Exit(3)
			}
			ek, dk, _ := elgamal.NewKeys(curve)

			privBytes, _ := dk.MarshalBinary()
			pubBytes, _ := ek.MarshalBinary()

			privKeyPEM := pem.Block{Type: "EC-ELGAMAL DECRYPTION KEY", Bytes: privBytes}
			privKeyPEM.Headers = map[string]string{"Curve": strings.ToUpper(*curveFlag)}

			pubKeyPEM := pem.Block{Type: "EC-ELGAMAL ENCRYPTION KEY", Bytes: pubBytes}

			savePEMToFile(*priv, &privKeyPEM, true)
			privPath, err := filepath.Abs(*priv)
			if err != nil {
				fmt.Println("Error getting absolute path for private key:", err)
				os.Exit(1)
			}
			fmt.Printf("Private Key saved to: %s\n", privPath)

			savePEMToFile(*pub, &pubKeyPEM, false)
			pubPath, err := filepath.Abs(*pub)
			if err != nil {
				fmt.Println("Error getting absolute path for public key:", err)
				os.Exit(1)
			}
			fmt.Printf("Public Key saved to: %s\n", pubPath)

			fingerprint := calculateFingerprint(pubBytes)
			fmt.Printf("Fingerprint: %s\n", fingerprint)

			keySize := len(pubBytes) * 8
			if keySize != 320 {
				fmt.Println("EC-ElGamal (381-bit)")
			} else {
				fmt.Println("EC-ElGamal (256-bit)")
			}

			pubFile, err := os.Open(*pub)
			if err != nil {
				fmt.Println("Error opening public key file:", err)
				os.Exit(1)
			}
			defer pubFile.Close()

			pubInfo, err := pubFile.Stat()
			if err != nil {
				fmt.Println("Error getting public key file info:", err)
				os.Exit(1)
			}

			pubBuf := make([]byte, pubInfo.Size())
			pubFile.Read(pubBuf)
			randomArt := randomart.FromString(string(pubBuf))
			fmt.Println(randomArt)

			os.Exit(0)
		} else {
			if *pkey == "unwrapkey" {
				if *key == "" {
					fmt.Println("A key is required for decryption.")
					os.Exit(3)
				}

				keyBytes, err := readKeyFromPEM(*key, true)
				if err != nil {
					fmt.Println("Error reading key from PEM:", err)
					os.Exit(1)
				}

				domain := []byte(*id)
				dk := new(elgamal.DecryptionKey)

				err = dk.UnmarshalBinary(keyBytes)
				if err != nil {
					fmt.Println("Error decoding private key:", err)
					return
				}

				ciphertextBytes, err := hex.DecodeString(*cph)
				if err != nil {
					fmt.Println("Error decoding ciphertext:", err)
					os.Exit(1)
				}

				cs := new(elgamal.CipherText)

				err = cs.UnmarshalBinary(ciphertextBytes)
				if err != nil {
					fmt.Println("Error decoding ciphertext:", err)
					os.Exit(1)
				}

				dbytes, _, err := dk.VerifiableDecryptWithDomain(domain, cs)
				if err != nil {
					fmt.Println("Error decrypting:", err)
					os.Exit(1)
				}
				fmt.Printf("Shared= %x\n", dbytes)
				os.Exit(0)
			} else {
				if *key == "" {
					fmt.Println("A key is required for encryption.")
					return
				}

				keyBytes, err := readKeyFromPEM(*key, false)
				if err != nil {
					fmt.Println("Error reading key from PEM:", err)
					return
				}

				domain := []byte(*id)
				ek := new(elgamal.EncryptionKey)

				err = ek.UnmarshalBinary(keyBytes)
				if err != nil {
					fmt.Println("Error decoding public key:", err)
					return
				}

				msgBytes := make([]byte, *length/8)
				_, err = rand.Read(msgBytes)
				if err != nil {
					return
				}

				cs, proof, err := ek.VerifiableEncrypt(msgBytes, &elgamal.EncryptParams{
					Domain:          domain,
					MessageIsHashed: true,
					GenProof:        true,
					ProofNonce:      domain,
				})

				if err != nil {
					fmt.Println("Error encrypting:", err)
					return
				}

				res3, _ := cs.MarshalBinary()

				fmt.Fprint(os.Stderr, "Verified: ")
				rtn := ek.VerifyDomainEncryptProof(domain, cs, proof)
				if rtn == nil {
					fmt.Fprintln(os.Stderr, "true")
				} else {
					fmt.Fprintln(os.Stderr, "false")
				}
				fmt.Printf("Cipher= %x\n", res3)
				fmt.Printf("Shared= %x\n", msgBytes)
				os.Exit(0)
			}
		}
	}

	if (strings.ToUpper(*alg) == "EC-ELGAMAL-ALT") && (*pkey == "wrapkey" || *pkey == "unwrapkey") {
		if *pkey == "unwrapkey" {
			if *key == "" {
				fmt.Println("A key is required for decryption.")
				os.Exit(3)
			}

			keyBytes, err := readKeyFromPEM(*key, true)
			if err != nil {
				fmt.Println("Error reading key from PEM:", err)
				os.Exit(1)
			}

			domain := []byte(*id)
			dk := new(elgamalAlt.DecryptionKey)

			err = dk.UnmarshalBinary(keyBytes)
			if err != nil {
				fmt.Println("Error decoding private key:", err)
				return
			}

			ciphertextBytes, err := hex.DecodeString(*cph)
			if err != nil {
				fmt.Println("Error decoding ciphertext:", err)
				os.Exit(1)
			}

			cs := new(elgamalAlt.CipherText)

			err = cs.UnmarshalBinary(ciphertextBytes)
			if err != nil {
				fmt.Println("Error decoding ciphertext:", err)
				os.Exit(1)
			}

			dbytes, _, err := dk.VerifiableDecryptWithDomain(domain, cs)
			if err != nil {
				fmt.Println("Error decrypting:", err)
				os.Exit(1)
			}
			fmt.Printf("Shared= %x\n", dbytes)
			os.Exit(0)
		} else {
			if *key == "" {
				fmt.Println("A key is required for encryption.")
				return
			}

			keyBytes, err := readKeyFromPEM(*key, false)
			if err != nil {
				fmt.Println("Error reading key from PEM:", err)
				return
			}

			domain := []byte(*id)
			ek := new(elgamalAlt.EncryptionKey)

			err = ek.UnmarshalBinary(keyBytes)
			if err != nil {
				fmt.Println("Error decoding public key:", err)
				return
			}

			msgBytes := make([]byte, *length/8)
			_, err = rand.Read(msgBytes)
			if err != nil {
				return
			}

			cs, proof, err := ek.VerifiableEncrypt(msgBytes, &elgamalAlt.EncryptParams{
				Domain:          domain,
				MessageIsHashed: true,
				GenProof:        true,
				ProofNonce:      domain,
			})

			if err != nil {
				fmt.Println("Error encrypting:", err)
				return
			}

			res3, _ := cs.MarshalBinary()

			fmt.Fprint(os.Stderr, "Verified: ")
			rtn := ek.VerifyDomainEncryptProof(domain, cs, proof)
			if rtn == nil {
				fmt.Fprintln(os.Stderr, "true")
			} else {
				fmt.Fprintln(os.Stderr, "false")
			}
			fmt.Printf("Cipher= %x\n", res3)
			fmt.Printf("Shared= %x\n", msgBytes)
			os.Exit(0)
		}
	}

	if *pkey == "modulus" && (strings.ToUpper(*alg) == "SM9SIGN" || strings.ToUpper(*alg) == "SM9ENCRYPT") && (PEM == "Master" || PEM == "Private") {
		keyFileContent, err := ioutil.ReadFile(*key)
		if err != nil {
			log.Fatal("Error reading key file:", err)
		}

		keyBlock, _ := pem.Decode(keyFileContent)
		if keyBlock == nil {
			log.Fatal("Failed to decode PEM block containing the private key.")
		}

		var privPEM []byte

		if IsEncryptedPEMBlock(keyBlock) {
			privKeyBytes, err := DecryptPEMBlock(keyBlock, []byte(*pwd))
			if err != nil {
				log.Fatal("Error decrypting private key:", err)
			}
			privPEM = pem.EncodeToMemory(&pem.Block{Type: "SM9 PRIVATE KEY", Bytes: privKeyBytes})
		} else {
			privPEM = keyFileContent
		}

		var privateKeyPemBlock *pem.Block
		privateKeyPemBlock, _ = pem.Decode(privPEM)

		privateKey, err := smx509.ParsePKCS8PrivateKey(privateKeyPemBlock.Bytes)
		if err != nil {
			log.Fatal("Error parsing private key:", err)
		}

		switch keyType := privateKey.(type) {
		case *sm9.EncryptPrivateKey:
			fmt.Printf("Public=%X\n", keyType.MasterPublicKey.Marshal())
		case *sm9.SignPrivateKey:
			fmt.Printf("Public=%X\n", keyType.MasterPublicKey.Marshal())
		case *sm9.EncryptMasterPrivateKey:
			fmt.Printf("Public=%X\n", keyType.MasterPublicKey.Marshal())
		case *sm9.SignMasterPrivateKey:
			fmt.Printf("Public=%X\n", keyType.MasterPublicKey.Marshal())
		default:
			log.Fatal("Invalid private key type. Expected sm9.EncryptPrivateKey, or sm9.SignPrivateKey.")
		}
	}

	if *pkey == "modulus" && (strings.ToUpper(*alg) == "SM9SIGN") && (PEM == "Public") {
		keyFileContent, err := ioutil.ReadFile(*key)
		if err != nil {
			log.Fatal("Error reading key file:", err)
		}

		keyBlock, _ := pem.Decode(keyFileContent)
		if keyBlock == nil {
			log.Fatal("Failed to decode PEM block containing the public key.")
		}

		pubKey := new(sm9.SignMasterPublicKey)
		err = pubKey.UnmarshalASN1(keyBlock.Bytes)
		if err != nil {
			fmt.Println("Error parsing public key with UnmarshalASN1:", err)
			return
		}

		fmt.Printf("Public=%X\n", pubKey.MasterPublicKey.Marshal())
		os.Exit(0)
	}

	if *pkey == "modulus" && (strings.ToUpper(*alg) == "SM9ENCRYPT") && (PEM == "Public") {
		keyFileContent, err := ioutil.ReadFile(*key)
		if err != nil {
			log.Fatal("Error reading key file:", err)
		}

		keyBlock, _ := pem.Decode(keyFileContent)
		if keyBlock == nil {
			log.Fatal("Failed to decode PEM block containing the public key.")
		}

		pubKey := new(sm9.EncryptMasterPublicKey)
		err = pubKey.UnmarshalASN1(keyBlock.Bytes)
		if err != nil {
			fmt.Println("Error parsing public key with UnmarshalASN1:", err)
			return
		}

		fmt.Printf("Public=%X\n", pubKey.MasterPublicKey.Marshal())
		os.Exit(0)
	}

	if *pkey == "text" && (strings.ToUpper(*alg) == "SM9SIGN" || strings.ToUpper(*alg) == "SM9ENCRYPT") && (PEM == "Master" || PEM == "Private") {
		keyFileContent, err := ioutil.ReadFile(*key)
		if err != nil {
			log.Fatal("Error reading key file:", err)
		}

		keyBlock, _ := pem.Decode(keyFileContent)
		if keyBlock == nil {
			log.Fatal("Failed to decode PEM block containing the private key.")
		}

		var privPEM []byte
		var privateKeyPemBlock *pem.Block

		var privKeyBytes []byte
		if IsEncryptedPEMBlock(keyBlock) {
			privKeyBytes, err = DecryptPEMBlock(keyBlock, []byte(*pwd))
			if err != nil {
				log.Fatal(err)
			}
			if PEM == "Master" && strings.ToUpper(*alg) == "SM9ENCRYPT" {
				privPEM = pem.EncodeToMemory(&pem.Block{Type: "SM9 ENC MASTER KEY", Bytes: privKeyBytes})
			} else if PEM == "Master" && strings.ToUpper(*alg) == "SM9SIGN" {
				privPEM = pem.EncodeToMemory(&pem.Block{Type: "SM9 SIGN MASTER KEY", Bytes: privKeyBytes})
			} else if PEM == "Private" && strings.ToUpper(*alg) == "SM9ENCRYPT" {
				privPEM = pem.EncodeToMemory(&pem.Block{Type: "SM9 ENC PRIVATE KEY", Bytes: privKeyBytes})
			} else if PEM == "Private" && strings.ToUpper(*alg) == "SM9SIGN" {
				privPEM = pem.EncodeToMemory(&pem.Block{Type: "SM9 SIGN PRIVATE KEY", Bytes: privKeyBytes})
			}
		} else {
			privPEM = keyFileContent
		}
		privateKeyPemBlock, _ = pem.Decode(privPEM)

		privateKey, err := smx509.ParsePKCS8PrivateKey(privateKeyPemBlock.Bytes)
		if err != nil {
			log.Fatal("Error parsing private key:", err)
		}

		fmt.Print(string(privPEM))
		switch keyType := privateKey.(type) {
		case *sm9.EncryptPrivateKey:
			fmt.Println("Encrypt Private-Key: (256-bit)")
			fmt.Println("pub:")
			pubKeyHex := fmt.Sprintf("%x", keyType.MasterPublicKey.Marshal())
			splitz := SplitSubN(pubKeyHex, 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}
			fmt.Println("Curve: sm9p256v1")
		case *sm9.SignPrivateKey:
			fmt.Println("Sign Private-Key: (256-bit)")
			fmt.Println("pub:")
			pubKeyHex := fmt.Sprintf("%x", keyType.MasterPublicKey.Marshal())
			splitz := SplitSubN(pubKeyHex, 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}
			fmt.Println("Curve: sm9p256v1")
		case *sm9.EncryptMasterPrivateKey:
			fmt.Println("Encrypt Master-Key: (256-bit)")
			fmt.Println("pub:")
			pubKeyHex := fmt.Sprintf("%x", keyType.MasterPublicKey.Marshal())
			splitz := SplitSubN(pubKeyHex, 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}
			fmt.Println("Curve: sm9p256v1")
		case *sm9.SignMasterPrivateKey:
			fmt.Println("Sign Master-Key: (256-bit)")
			fmt.Println("pub:")
			pubKeyHex := fmt.Sprintf("%x", keyType.MasterPublicKey.Marshal())
			splitz := SplitSubN(pubKeyHex, 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}
			fmt.Println("Curve: sm9p256v1")
		default:
			log.Fatal("Invalid private key type. Expected sm9.EncryptPrivateKey, or sm9.SignPrivateKey.")
		}
	}

	if *pkey == "text" && (strings.ToUpper(*alg) == "SM9SIGN") && (PEM == "Public") {
		keyFileContent, err := ioutil.ReadFile(*key)
		if err != nil {
			log.Fatal("Error reading key file:", err)
		}

		keyBlock, _ := pem.Decode(keyFileContent)
		if keyBlock == nil {
			log.Fatal("Failed to decode PEM block containing the public key.")
		}

		pubKey := new(sm9.SignMasterPublicKey)
		err = pubKey.UnmarshalASN1(keyBlock.Bytes)
		if err != nil {
			fmt.Println("Error parsing public key with UnmarshalASN1:", err)
			return
		}

		fmt.Print(string(keyFileContent))
		fmt.Println("Sign Public-Key: (256-bit)")
		fmt.Println("pub:")
		pubKeyHex := fmt.Sprintf("%x", pubKey.MasterPublicKey.Marshal())
		splitz := SplitSubN(pubKeyHex, 2)
		for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
			fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
		}
		fmt.Println("Curve: sm9p256v1")
		os.Exit(0)
	}

	if *pkey == "text" && (strings.ToUpper(*alg) == "SM9ENCRYPT") && (PEM == "Public") {
		keyFileContent, err := ioutil.ReadFile(*key)
		if err != nil {
			log.Fatal("Error reading key file:", err)
		}

		keyBlock, _ := pem.Decode(keyFileContent)
		if keyBlock == nil {
			log.Fatal("Failed to decode PEM block containing the public key.")
		}

		pubKey := new(sm9.EncryptMasterPublicKey)
		err = pubKey.UnmarshalASN1(keyBlock.Bytes)
		if err != nil {
			fmt.Println("Error parsing public key with UnmarshalASN1:", err)
			return
		}

		fmt.Print(string(keyFileContent))
		fmt.Println("Encrypt Public-Key: (256-bit)")
		fmt.Println("pub:")
		pubKeyHex := fmt.Sprintf("%x", pubKey.MasterPublicKey.Marshal())
		splitz := SplitSubN(pubKeyHex, 2)
		for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
			fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
		}
		fmt.Println("Curve: sm9p256v1")
		os.Exit(0)
	}

	if *pkey == "randomart" && (strings.ToUpper(*alg) == "SM9SIGN") && (PEM == "Public") {
		file, err := os.Open(*key)
		if err != nil {
			log.Fatal(err)
		}
		info, err := file.Stat()
		if err != nil {
			log.Fatal(err)
		}
		buf := make([]byte, info.Size())
		file.Read(buf)
		randomArt := randomart.FromString(string(buf))
		fmt.Fprintln(os.Stderr, "SM9 Sign (256-bit)")
		println(randomArt)
		os.Exit(0)
	}

	if *pkey == "randomart" && (strings.ToUpper(*alg) == "SM9ENCRYPT") && (PEM == "Public") {
		file, err := os.Open(*key)
		if err != nil {
			log.Fatal(err)
		}
		info, err := file.Stat()
		if err != nil {
			log.Fatal(err)
		}
		buf := make([]byte, info.Size())
		file.Read(buf)
		randomArt := randomart.FromString(string(buf))
		fmt.Fprintln(os.Stderr, "SM9 Enc (256-bit)")
		println(randomArt)
		os.Exit(0)
	}

	if *pkey == "fingerprint" && (strings.ToUpper(*alg) == "SM9SIGN") && (PEM == "Public") {
		file, err := os.Open(*key)
		if err != nil {
			log.Fatal(err)
		}
		info, err := file.Stat()
		if err != nil {
			log.Fatal(err)
		}
		buf := make([]byte, info.Size())
		file.Read(buf)
		fingerprint := calculateFingerprint(buf)
		print("Fingerprint= ")
		println(fingerprint)
		os.Exit(0)
	}

	if *pkey == "fingerprint" && (strings.ToUpper(*alg) == "SM9ENCRYPT") && (PEM == "Public") {
		file, err := os.Open(*key)
		if err != nil {
			log.Fatal(err)
		}
		info, err := file.Stat()
		if err != nil {
			log.Fatal(err)
		}
		buf := make([]byte, info.Size())
		file.Read(buf)
		fingerprint := calculateFingerprint(buf)
		print("Fingerprint= ")
		println(fingerprint)
		os.Exit(0)
	}

	if *pkey == "certgen" && strings.ToUpper(*alg) == "GOST2012" {
		file, err := os.Open(*key)
		if err != nil {
			log.Fatal(err)
		}
		info, err := file.Stat()
		if err != nil {
			log.Fatal(err)
		}
		buf := make([]byte, info.Size())
		file.Read(buf)

		var priv interface{}

		var block *pem.Block
		block, _ = pem.Decode(buf)

		var privKeyBytes []byte
		if IsEncryptedPEMBlock(block) {
			privKeyBytes, err = DecryptPEMBlock(block, []byte(*pwd))
			if err != nil {
				log.Fatal(err)
			}
			priv, err = x509.ParsePKCS8PrivateKey(privKeyBytes)
			if err != nil {
				log.Fatal(err)
			}
		} else {
			priv, err = x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				log.Fatal(err)
			}
		}

		gost341012256Priv := priv.(*gost3410.PrivateKey)
		gost341012256Pub := gost341012256Priv.Public()

		keyUsage := x509.KeyUsageDigitalSignature

		serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 160)
		serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
		if err != nil {
			log.Fatalf("Failed to generate serial number: %v", err)
		}

		println("You are about to be asked to enter information \nthat will be incorporated into your certificate.")

		scanner := bufio.NewScanner(os.Stdin)

		print("Common Name: ")
		scanner.Scan()
		name := scanner.Text()

		print("Country Name (2 letter code) [AU]: ")
		scanner.Scan()
		country := scanner.Text()

		print("State or Province Name (full name) [Some-State]: ")
		scanner.Scan()
		province := scanner.Text()

		print("Locality Name (eg, city): ")
		scanner.Scan()
		locality := scanner.Text()

		print("Organization Name (eg, company) [Internet Widgits Pty Ltd]: ")
		scanner.Scan()
		organization := scanner.Text()

		print("Organizational Unit Name (eg, section): ")
		scanner.Scan()
		organizationunit := scanner.Text()

		print("Email Address []: ")
		scanner.Scan()
		email := scanner.Text()

		print("StreetAddress: ")
		scanner.Scan()
		street := scanner.Text()

		print("PostalCode: ")
		scanner.Scan()
		postalcode := scanner.Text()

		print("SerialNumber: ")
		scanner.Scan()
		number := scanner.Text()

		print("Validity (in Days): ")
		scanner.Scan()
		validity := scanner.Text()

		intVar, err := strconv.Atoi(validity)
		NotAfter := time.Now().AddDate(0, 0, intVar)

		hasher := gost34112012256.New()
		if _, err = hasher.Write(gost341012256Pub.(*gost3410.PublicKey).Raw()); err != nil {
			log.Fatalln(err)
		}
		spki := hasher.Sum(nil)
		spki = spki[:20]

		template := x509.Certificate{
			SerialNumber: serialNumber,
			Subject: pkix.Name{
				CommonName:         name,
				SerialNumber:       number,
				Country:            []string{country},
				Province:           []string{province},
				Locality:           []string{locality},
				Organization:       []string{organization},
				OrganizationalUnit: []string{organizationunit},
				StreetAddress:      []string{street},
				PostalCode:         []string{postalcode},
			},
			EmailAddresses: []string{email},
			SubjectKeyId:   spki,
			AuthorityKeyId: spki,

			NotBefore: time.Now(),
			NotAfter:  NotAfter,

			KeyUsage:                    keyUsage,
			ExtKeyUsage:                 []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid:       true,
			IsCA:                        true,
			PermittedDNSDomainsCritical: true,
			DNSNames:                    []string{name},

			/*
				PermittedDNSDomainsCritical: true,
				DNSNames:                    []string{ip.String()},
				IPAddresses:                 []net.IP{net.IPv4(127, 0, 0, 1).To4(), net.ParseIP("2001:4860:0:2001::68")},
			*/
		}

		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageContentCommitment | x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment | x509.KeyUsageKeyAgreement | x509.KeyUsageCertSign | x509.KeyUsageCRLSign

		derBytes, err := x509.CreateCertificate(
			rand.Reader,
			&template, &template,
			gost341012256Pub, &gost3410.PrivateKeyReverseDigest{Prv: gost341012256Priv},
		)
		if err != nil {
			log.Println(err)
		}

		certfile, err := os.Create(*cert)
		if err != nil {
			log.Println(err)
		}
		pem.Encode(certfile, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
		os.Exit(0)
	}

	if *pkey == "req" && *key != "" && strings.ToUpper(*alg) == "GOST2012" {
		file, err := os.Open(*key)
		if err != nil {
			log.Fatal(err)
		}
		info, err := file.Stat()
		if err != nil {
			log.Fatal(err)
		}
		buf := make([]byte, info.Size())
		file.Read(buf)

		var block *pem.Block
		block, _ = pem.Decode(buf)

		var priva interface{}
		var privKeyBytes []byte
		if IsEncryptedPEMBlock(block) {
			privKeyBytes, err = DecryptPEMBlock(block, []byte(*pwd))
			if err != nil {
				log.Fatal(err)
			}
			priva, err = x509.ParsePKCS8PrivateKey(privKeyBytes)
			if err != nil {
				log.Fatal(err)
			}
		} else {
			priva, err = x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				log.Fatal(err)
			}
		}

		println("You are about to be asked to enter information that \nwill be incorporated into your certificate request.")

		scanner := bufio.NewScanner(os.Stdin)

		print("Common Name: ")
		scanner.Scan()
		name := scanner.Text()

		print("Country Name (2 letter code) [AU]: ")
		scanner.Scan()
		country := scanner.Text()

		print("State or Province Name (full name) [Some-State]: ")
		scanner.Scan()
		province := scanner.Text()

		print("Locality Name (eg, city): ")
		scanner.Scan()
		locality := scanner.Text()

		print("Organization Name (eg, company) [Internet Widgits Pty Ltd]: ")
		scanner.Scan()
		organization := scanner.Text()

		print("Organizational Unit Name (eg, section): ")
		scanner.Scan()
		organizationunit := scanner.Text()

		print("Email Address []: ")
		scanner.Scan()
		email := scanner.Text()

		print("StreetAddress: ")
		scanner.Scan()
		street := scanner.Text()

		print("PostalCode: ")
		scanner.Scan()
		postalcode := scanner.Text()

		print("SerialNumber: ")
		scanner.Scan()
		number := scanner.Text()

		var sigalg x509.SignatureAlgorithm
		if *length == 512 {
			sigalg = x509.GOST512
		} else {
			sigalg = x509.GOST256
		}

		emailAddress := email
		subj := pkix.Name{
			CommonName:         name,
			SerialNumber:       number,
			Country:            []string{country},
			Province:           []string{province},
			Locality:           []string{locality},
			Organization:       []string{organization},
			OrganizationalUnit: []string{organizationunit},
			StreetAddress:      []string{street},
			PostalCode:         []string{postalcode},
		}
		rawSubj := subj.ToRDNSequence()
		rawSubj = append(rawSubj, []pkix.AttributeTypeAndValue{
			{Type: oidEmailAddress, Value: emailAddress},
		})

		asn1Subj, _ := asn1.Marshal(rawSubj)
		var template x509.CertificateRequest

		template = x509.CertificateRequest{
			RawSubject:         asn1Subj,
			EmailAddresses:     []string{emailAddress},
			SignatureAlgorithm: sigalg,
		}

		var output *os.File
		if *cert == "" {
			output = os.Stdout
		} else {
			file, err := os.Create(*cert)
			if err != nil {
				log.Fatal(err)
			}
			defer file.Close()
			output = file
		}
		csrBytes, _ := x509.CreateCertificateRequest(rand.Reader, &template, &gost3410.PrivateKeyReverseDigest{Prv: priva.(*gost3410.PrivateKey)})
		pem.Encode(output, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
		os.Exit(0)
	}

	if (*tcpip == "server" || *tcpip == "client") && strings.ToUpper(*alg) == "GOST2012" {
		var certPEM []byte
		var privPEM []byte

		tls.GOSTInstall()

		file, err := os.Open(*key)
		if err != nil {
			log.Println(err)
		}
		info, err := file.Stat()
		if err != nil {
			log.Println(err)
		}
		buf := make([]byte, info.Size())
		file.Read(buf)

		var block *pem.Block
		block, _ = pem.Decode(buf)

		if block == nil {
			errors.New("no valid private key found")
		}

		var privKeyBytes []byte
		if IsEncryptedPEMBlock(block) {
			privKeyBytes, err = DecryptPEMBlock(block, []byte(*pwd))
			if err != nil {
				log.Println(err)
			}
			privPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privKeyBytes})
		} else {
			privPEM = buf
		}

		file, err = os.Open(*cert)
		if err != nil {
			log.Println(err)
		}
		info, err = file.Stat()
		if err != nil {
			log.Println(err)
		}
		buf = make([]byte, info.Size())
		file.Read(buf)
		certPEM = buf

		if *tcpip == "server" {
			cert, err := tls.X509KeyPair(certPEM, privPEM)
			cfg := tls.Config{Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAnyClientCert, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
			cfg.Rand = rand.Reader

			port := "8081"
			if *iport != "" {
				port = *iport
			}

			ln, err := tls.Listen("tcp", ":"+port, &cfg)
			if err != nil {
				log.Fatal(err)
			}

			fmt.Fprintln(os.Stderr, "Server(TLS) up and listening on port "+port)

			conn, err := ln.Accept()
			if err != nil {
				log.Println(err)
			}
			defer ln.Close()

			tlscon := conn.(*tls.Conn)
			err = tlscon.Handshake()
			if err != nil {
				log.Fatalf("server: handshake failed: %s", err)
			} else {
				log.Print("server: conn: Handshake completed")
			}
			state := tlscon.ConnectionState()

			for _, v := range state.PeerCertificates {
				derBytes, err := x509.MarshalPKIXPublicKey(v.PublicKey)
				if err != nil {
					log.Fatal(err)
				}
				pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: derBytes})
				fmt.Printf("%s\n", pubPEM)
			}

			go handleConnectionTLS(conn)
			fmt.Println("Connection accepted")

			for {
				message, err := bufio.NewReader(conn).ReadString('\n')
				if err != nil {
					fmt.Println(err)
					os.Exit(3)
				}
				fmt.Print("Client response: " + string(message))

				reader := bufio.NewReader(os.Stdin)
				fmt.Print("Text to be sent: ")
				text, err := reader.ReadString('\n')
				if err != nil {
					fmt.Println(err)
					os.Exit(3)
				}
				fmt.Fprintf(conn, text+"\n")
			}
		}

		if *tcpip == "client" {
			cert, err := tls.X509KeyPair(certPEM, privPEM)
			cfg := tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true}

			ipport := "127.0.0.1:8081"
			if *iport != "" {
				ipport = *iport
			}

			conn, err := tls.Dial("tcp", ipport, &cfg)
			if err != nil {
				log.Fatal(err)
			}
			certs := conn.ConnectionState().PeerCertificates
			for _, cert := range certs {
				fmt.Printf("Issuer: \n\t%s\n", cert.Issuer)
				fmt.Printf("Subject: \n\t%s\n", cert.Subject)
				fmt.Printf("Expiry: %s \n", cert.NotAfter.Format("Monday, 02-Jan-06 15:04:05 MST"))
			}
			if err != nil {
				log.Fatal(err)
			}
			defer conn.Close()

			var b bytes.Buffer
			for _, cert := range conn.ConnectionState().PeerCertificates {
				err := pem.Encode(&b, &pem.Block{
					Type:  "CERTIFICATE",
					Bytes: cert.Raw,
				})
				if err != nil {
					log.Println(err)
				}
			}
			fmt.Println(b.String())

			for {
				reader := bufio.NewReader(os.Stdin)
				fmt.Print("Text to be sent: ")
				text, err := reader.ReadString('\n')
				if err != nil {
					fmt.Println(err)
					os.Exit(3)
				}
				fmt.Fprintf(conn, text+"\n")

				message, err := bufio.NewReader(conn).ReadString('\n')
				if err != nil {
					fmt.Println(err)
					os.Exit(3)
				}
				fmt.Print("Server response: " + message)
			}
		}
		os.Exit(0)
	}

	if *pkey == "keygen" && strings.ToUpper(*alg) == "RSA" {
		GenerateRsaKey(*length)
		os.Exit(0)
	}

	if *pkey == "pkcs12" && *key != "" {
		err := PfxGen()
		if err != nil {
			log.Fatal(err)
		}
		os.Exit(0)
	}

	if *pkey == "pkcs12" && *key == "" {
		err := PfxParse()
		if err != nil {
			log.Fatal(err)
		}
		os.Exit(0)
	}

	if *pkey == "x509" && strings.ToUpper(*alg) != "GOST2012" {
		err := csrToCrt()
		if err != nil {
			log.Fatal(err)
		}
		os.Exit(0)
	}

	if *pkey == "x509" && strings.ToUpper(*alg) == "GOST2012" {
		err := csrToCrt2()
		if err != nil {
			log.Fatal(err)
		}
		os.Exit(0)
	}

	if *pkey == "sign" && *key == "" && strings.ToUpper(*alg) == "RSA" {
		fmt.Fprintln(os.Stderr, "Usage:")
		fmt.Fprintln(os.Stderr, os.Args[0]+" -pkey sign -key <privatekey.pem>")
		os.Exit(1)
	} else if *pkey == "sign" && *key != "" && strings.ToUpper(*alg) == "RSA" {
		buf := bytes.NewBuffer(nil)
		data := inputfile
		io.Copy(buf, data)
		Data := string(buf.Bytes())
		sourceData := []byte(Data)
		signData, err := SignatureRSA(sourceData)
		if err != nil {
			fmt.Println("cryption error:", err)
			os.Exit(1)
		}
		fmt.Println("RSA-"+strings.ToUpper(*md)+"("+inputdesc+")=", hex.EncodeToString(signData))
		os.Exit(0)
	}

	if *pkey == "verify" && (*key == "" || *sig == "") && strings.ToUpper(*alg) == "RSA" {
		fmt.Fprintln(os.Stderr, "Usage:")
		fmt.Fprintln(os.Stderr, os.Args[0]+" -pkey verify -key <publickey.pem> -signature <$signature>")
		os.Exit(1)
	} else if *pkey == "verify" && (*key != "" || *sig != "") && strings.ToUpper(*alg) == "RSA" {
		buf := bytes.NewBuffer(nil)
		data := inputfile
		io.Copy(buf, data)
		Data := string(buf.Bytes())
		Signature, err := hex.DecodeString(*sig)
		err = VerifyRSA([]byte(Data), Signature)
		if err != nil {
			fmt.Println("Checksum error:", err)
			os.Exit(1)
		}
		fmt.Println("Verify correct.")
	}

	if *pkey == "encrypt" && (*key != "") && strings.ToUpper(*alg) == "RSA" {
		file, err := os.Open(*key)
		if err != nil {
			log.Fatal(err)
		}
		info, err := file.Stat()
		if err != nil {
			log.Fatal(err)
		}
		buf := make([]byte, info.Size())
		file.Read(buf)
		block, _ := pem.Decode(buf)
		publicInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			log.Fatal(err)
		}
		publicKey := publicInterface.(*rsa.PublicKey)

		buffer := bytes.NewBuffer(nil)
		data := inputfile
		io.Copy(buffer, data)

		ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, buffer.Bytes())
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error from encryption: %s\n", err)
			return
		}
		fmt.Printf("%s", ciphertext)
	}

	if *pkey == "decrypt" && (*key != "") && strings.ToUpper(*alg) == "RSA" {
		file, err := os.Open(*key)
		if err != nil {
			log.Fatal(err)
		}
		info, err := file.Stat()
		if err != nil {
			log.Fatal(err)
		}
		buf := make([]byte, info.Size())
		file.Read(buf)

		var block *pem.Block
		block, _ = pem.Decode(buf)

		var privateKey *rsa.PrivateKey
		var privKeyBytes []byte
		if IsEncryptedPEMBlock(block) {
			privKeyBytes, err = DecryptPEMBlock(block, []byte(*pwd))
			if err != nil {
				log.Fatal(err)
			}
			privateKey, err = x509.ParsePKCS1PrivateKey(privKeyBytes)
			if err != nil {
				log.Fatal(err)
			}
		} else {
			privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				log.Fatal(err)
			}
		}

		buffer := bytes.NewBuffer(nil)
		data := inputfile
		io.Copy(buffer, data)

		plaintext, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, buffer.Bytes())
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error from decryption: %s\n", err)
			return
		}
		fmt.Printf("%s", plaintext)
	}

	if (*pkey == "text" || *pkey == "modulus") && PEM == "Private" && strings.ToUpper(*alg) == "GOST2012" {
		var privPEM []byte
		file, err := os.Open(*key)
		if err != nil {
			log.Println(err)
		}
		info, err := file.Stat()
		if err != nil {
			log.Println(err)
		}
		buf := make([]byte, info.Size())
		file.Read(buf)
		var block *pem.Block
		block, _ = pem.Decode(buf)
		if block == nil {
			errors.New("no valid private key found")
		}
		var privKeyBytes []byte
		if IsEncryptedPEMBlock(block) {
			privKeyBytes, err = DecryptPEMBlock(block, []byte(*pwd))
			if err != nil {
				log.Fatal(err)
			}
			privPEM = pem.EncodeToMemory(&pem.Block{Type: "GOST PRIVATE KEY", Bytes: privKeyBytes})
		} else {
			privPEM = buf
		}
		var privateKeyPemBlock, _ = pem.Decode([]byte(privPEM))
		var privKey, _ = x509.ParsePKCS8PrivateKey(privateKeyPemBlock.Bytes)
		if err != nil {
			log.Println(err)
		}
		gostKey := privKey.(*gost3410.PrivateKey)
		pubKey := gostKey.Public()
		if *pkey == "modulus" {
			var publicKey = pubKey.(*gost3410.PublicKey)
			fmt.Printf("Public.X=%X\n", publicKey.X)
			fmt.Printf("Public.Y=%X\n", publicKey.Y)
			os.Exit(0)
		}
		fmt.Printf(string(privPEM))
		/*
			derBytes, err := x509.MarshalPKIXPublicKey(gostKey.Public())
			if err != nil {
				log.Fatal(err)
			}
		*/
		p := fmt.Sprintf("%X", gostKey.Raw())
		fmt.Println("Private key:", p)

		fmt.Printf("Public key: \n")
		var publicKey = pubKey.(*gost3410.PublicKey)
		fmt.Printf("   X:%X\n", publicKey.X)
		fmt.Printf("   Y:%X\n", publicKey.Y)
		/*
			var spki struct {
				Algorithm        pkix.AlgorithmIdentifier
				SubjectPublicKey asn1.BitString
			}
			_, err = asn1.Unmarshal(derBytes, &spki)
			if err != nil {
				log.Println(err)
			}
			skid := sha1.Sum(spki.SubjectPublicKey.Bytes)
			fmt.Printf("\nKeyID: %x \n", skid)
		*/

		fmt.Printf("Curve: %s\n", publicKey.C.Name)

		hasher := gost34112012256.New()
		if _, err = hasher.Write(publicKey.Raw()); err != nil {
			log.Fatalln(err)
		}
		spki := hasher.Sum(nil)
		spki = spki[:20]
		fmt.Printf("\nKeyID: %x \n", spki)
		os.Exit(0)
	}

	if *pkey == "fingerprint" && (strings.ToUpper(*alg) == "ELGAMAL") && (PEM == "Public") {
		publicKeyVal, err := readPublicKeyFromPEM(*key)
		if err != nil {
			fmt.Println("Error reading PEM file:", err)
			return
		}

		fingerprint := calculateFingerprint(publicKeyVal.Y.Bytes())
		fmt.Println("Fingerprint=", fingerprint)
		os.Exit(0)
	}
	if *pkey == "randomart" && (strings.ToUpper(*alg) == "ELGAMAL") && (PEM == "Public") {
		publicKeyVal, err := readPublicKeyFromPEM(*key)
		if err != nil {
			fmt.Println("Error reading PEM file:", err)
			return
		}

		primeBitLength := publicKeyVal.P.BitLen()
		fmt.Fprintf(os.Stderr, "ElGamal (%d-bits)\n", primeBitLength)

		file, err := os.Open(*key)
		if err != nil {
			log.Fatal(err)
		}

		info, err := file.Stat()
		if err != nil {
			log.Fatal(err)
		}

		buf := make([]byte, info.Size())
		file.Read(buf)
		randomArt := randomart.FromString(string(buf))
		fmt.Println(randomArt)
		os.Exit(0)
	}

	if (*pkey == "randomart") && PEM == "Public" {
		file, err := os.Open(*key)
		if err != nil {
			log.Fatal(err)
		}
		info, err := file.Stat()
		if err != nil {
			log.Fatal(err)
		}
		buf := make([]byte, info.Size())
		file.Read(buf)
		block, _ := pem.Decode(buf)
		publicInterface, err := smx509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			publicInterface, err = x509.ParsePKIXPublicKey(block.Bytes)
		}
		switch publicInterface.(type) {
		case *rsa.PublicKey:
			publicKey := publicInterface.(*rsa.PublicKey)
			fmt.Printf("RSA (%v-bit)\n", publicKey.N.BitLen())
		case *ecdsa.PublicKey:
			publicKey := publicInterface.(*ecdsa.PublicKey)
			fmt.Printf("ECDSA (%v-bit)\n", publicKey.Curve.Params().BitSize)
		case *ecdh.PublicKey:
			fmt.Println("X25519 (256-bit)")
		case ed25519.PublicKey:
			fmt.Println("Ed25519 (256-bit)")
		case *gost3410.PublicKey:
			publicKey := publicInterface.(*gost3410.PublicKey)
			fmt.Printf("GOST2012 (%v-bit)\n", len(publicKey.Raw())*4)
		default:
			log.Fatal("unknown type of public key")
		}
		fmt.Println(randomart.FromString(strings.ReplaceAll(string(buf), "\r\n", "\n")))
	}

	if (*pkey == "fingerprint") && PEM == "Public" {
		file, err := os.Open(*key)
		if err != nil {
			log.Fatal(err)
		}
		info, err := file.Stat()
		if err != nil {
			log.Fatal(err)
		}
		buf := make([]byte, info.Size())
		file.Read(buf)
		block, _ := pem.Decode(buf)
		publicInterface, err := smx509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			publicInterface, err = x509.ParsePKIXPublicKey(block.Bytes)
		}
		var fingerprint string
		switch publicInterface.(type) {
		case *rsa.PublicKey, *ecdsa.PublicKey, *ecdh.PublicKey, ed25519.PublicKey:
			fingerprint = calculateFingerprint(buf)
		case *gost3410.PublicKey:
			fingerprint = calculateFingerprintGOST(buf)
		default:
			log.Fatal("unknown type of public key")
		}
		fmt.Print("Fingerprint= ")
		fmt.Println(fingerprint)
	}

	if (*pkey == "text" || *pkey == "modulus") && PEM == "Public" {
		file, err := os.Open(*key)
		if err != nil {
			log.Fatal(err)
		}
		info, err := file.Stat()
		if err != nil {
			log.Fatal(err)
		}
		buf := make([]byte, info.Size())
		file.Read(buf)
		block, _ := pem.Decode(buf)

		publicInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			publicInterface, err = smx509.ParsePKIXPublicKey(block.Bytes)
		}
		switch publicInterface.(type) {
		case *ecdh.PublicKey:
			*alg = "X25519"
		case ed25519.PublicKey:
			*alg = "ED25519"
		case *rsa.PublicKey:
			*alg = "RSA"
		case *ecdsa.PublicKey:
			*alg = "EC"
		case *gost3410.PublicKey:
			*alg = "GOST2012"
		default:
			log.Fatal("unknown type of public key")
		}

		if *pkey == "modulus" && strings.ToUpper(*alg) == "RSA" {
			var publicKey = publicInterface.(*rsa.PublicKey)
			fmt.Printf("Modulus=%X\n", publicKey.N)
			os.Exit(0)
		} else if *pkey == "modulus" && (strings.ToUpper(*alg) == "EC" || strings.ToUpper(*alg) == "SM2") {
			var publicKey = publicInterface.(*ecdsa.PublicKey)
			fmt.Printf("Public.X=%X\n", publicKey.X)
			fmt.Printf("Public.Y=%X\n", publicKey.Y)
			os.Exit(0)
		} else if *pkey == "modulus" && (strings.ToUpper(*alg) == "ED25519") {
			var publicKey = publicInterface.(ed25519.PublicKey)
			fmt.Printf("Public=%X\n", publicKey)
			os.Exit(0)
		} else if *pkey == "modulus" && (strings.ToUpper(*alg) == "GOST2012") {
			var publicKey = publicInterface.(*gost3410.PublicKey)
			fmt.Printf("Public.X=%X\n", publicKey.X)
			fmt.Printf("Public.Y=%X\n", publicKey.Y)
			os.Exit(0)
		}

		if strings.ToUpper(*alg) == "RSA" {
			publicKey := publicInterface.(*rsa.PublicKey)
			derBytes, err := x509.MarshalPKIXPublicKey(publicKey)
			if err != nil {
				log.Fatal(err)
			}
			block := &pem.Block{
				Type:  "PUBLIC KEY",
				Bytes: derBytes,
			}
			public := pem.EncodeToMemory(block)
			fmt.Printf(string(public))
			fmt.Printf("RSA Public-Key: (%v-bit)\n", publicKey.N.BitLen())
			fmt.Printf("Modulus: \n")
			m := publicKey.N.Bytes()
			b, _ := hex.DecodeString("00")
			c := []byte{}
			c = append(c, b...)
			c = append(c, m...)
			splitz := SplitSubN(hex.EncodeToString(c), 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}
			fmt.Printf("Exponent: %d (0x%X)\n", publicKey.E, publicKey.E)
		} else if strings.ToUpper(*alg) == "ED25519" {
			publicKey := publicInterface.(ed25519.PublicKey)
			derBytes, err := smx509.MarshalPKIXPublicKey(publicKey)
			if err != nil {
				log.Fatal(err)
			}
			block := &pem.Block{
				Type:  "PUBLIC KEY",
				Bytes: derBytes,
			}
			public := pem.EncodeToMemory(block)
			fmt.Printf(string(public))

			fmt.Printf("ED25519 Public-Key:\n")
			fmt.Printf("pub: \n")
			splitz := SplitSubN(hex.EncodeToString(derBytes)[24:], 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}
			var spki struct {
				Algorithm        pkix.AlgorithmIdentifier
				SubjectPublicKey asn1.BitString
			}
			_, err = asn1.Unmarshal(derBytes, &spki)
			if err != nil {
				log.Fatal(err)
			}
			skid := sha1.Sum(spki.SubjectPublicKey.Bytes)
			fmt.Printf("\nKeyID: %x \n", skid)
		} else if strings.ToUpper(*alg) == "X25519" {
			publicKey := publicInterface.(*ecdh.PublicKey)
			derBytes, err := x509.MarshalPKIXPublicKey(publicKey)
			if err != nil {
				log.Fatal(err)
			}
			block := &pem.Block{
				Type:  "PUBLIC KEY",
				Bytes: derBytes,
			}
			public := pem.EncodeToMemory(block)
			fmt.Printf(string(public))

			fmt.Printf("X25519 Public-Key:\n")
			fmt.Printf("pub: \n")
			splitz := SplitSubN(hex.EncodeToString(derBytes)[24:], 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}
			var spki struct {
				Algorithm        pkix.AlgorithmIdentifier
				SubjectPublicKey asn1.BitString
			}
			_, err = asn1.Unmarshal(derBytes, &spki)
			if err != nil {
				log.Fatal(err)
			}
			skid := sha1.Sum(spki.SubjectPublicKey.Bytes)
			fmt.Printf("\nKeyID: %x \n", skid)
		} else if strings.ToUpper(*alg) == "EC" {
			publicKey := publicInterface.(*ecdsa.PublicKey)
			derBytes, err := smx509.MarshalPKIXPublicKey(publicKey)
			if err != nil {
				log.Fatal(err)
			}
			block := &pem.Block{
				Type:  "PUBLIC KEY",
				Bytes: derBytes,
			}
			public := pem.EncodeToMemory(block)
			fmt.Printf(string(public))

			fmt.Printf("Public-Key: (%v-bit)\n", publicKey.Curve.Params().BitSize)
			x := publicKey.X.Bytes()
			if n := len(x); n < 24 && n < 32 && n < 48 && n < 64 {
				x = append(zeroByteSlice()[:(publicKey.Curve.Params().BitSize/8)-n], x...)
			}
			c := []byte{}
			c = append(c, x...)
			fmt.Printf("pub.X: \n")
			splitz := SplitSubN(hex.EncodeToString(c), 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}
			y := publicKey.Y.Bytes()
			if n := len(y); n < 24 && n < 32 && n < 48 && n < 64 {
				y = append(zeroByteSlice()[:(publicKey.Curve.Params().BitSize/8)-n], y...)
			}
			c = []byte{}
			c = append(c, y...)
			fmt.Printf("pub.Y: \n")
			splitz = SplitSubN(hex.EncodeToString(c), 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}
			fmt.Printf("pub: \n")
			x = publicKey.X.Bytes()
			y = publicKey.Y.Bytes()
			if n := len(x); n < 24 && n < 32 && n < 48 && n < 64 {
				x = append(zeroByteSlice()[:(publicKey.Curve.Params().BitSize/8)-n], x...)
			}
			if n := len(y); n < 24 && n < 32 && n < 48 && n < 64 {
				y = append(zeroByteSlice()[:(publicKey.Curve.Params().BitSize/8)-n], y...)
			}
			c = []byte{}
			c = append(c, x...)
			c = append(c, y...)
			c = append([]byte{0x04}, c...)
			splitz = SplitSubN(hex.EncodeToString(c), 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}
			fmt.Printf("Curve: %s\n", publicKey.Params().Name)
		} else if strings.ToUpper(*alg) == "GOST2012" {
			publicKey := publicInterface.(*gost3410.PublicKey)
			derBytes, err := x509.MarshalPKIXPublicKey(publicKey)
			if err != nil {
				log.Println(err)
			}
			block = &pem.Block{
				Type:  "PUBLIC KEY",
				Bytes: derBytes,
			}
			public := pem.EncodeToMemory(block)
			fmt.Printf(string(public))
			fmt.Printf("Public key:\n")
			fmt.Printf("   X:%X\n", publicKey.X)
			fmt.Printf("   Y:%X\n", publicKey.Y)
			fmt.Printf("Curve: %s\n", publicKey.C.Name)
		}
	}

	if (*pkey == "text" || *pkey == "modulus") && PEM == "Private" {
		var privPEM []byte
		file, err := os.Open(*key)
		if err != nil {
			log.Fatal(err)
		}
		info, err := file.Stat()
		if err != nil {
			log.Fatal(err)
		}
		buf := make([]byte, info.Size())
		file.Read(buf)
		var block *pem.Block
		block, _ = pem.Decode(buf)
		if block == nil {
			errors.New("no valid private key found")
		}
		var privKeyBytes []byte
		if IsEncryptedPEMBlock(block) {
			privKeyBytes, err = DecryptPEMBlock(block, []byte(*pwd))
			if err != nil {
				log.Fatal(err)
			}
			privPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privKeyBytes})
		} else {
			privPEM = buf
		}
		var privateKeyPemBlock, _ = pem.Decode([]byte(privPEM))
		if strings.ToUpper(*alg) == "EC" || strings.ToUpper(*alg) == "SM2" {
			var privKey, err = smx509.ParseECPrivateKey(privateKeyPemBlock.Bytes)
			if err != nil {
				log.Fatal(err)
			}
			derBytes, err := smx509.MarshalPKIXPublicKey(&privKey.PublicKey)
			if err != nil {
				log.Fatal(err)
			}
			if *pkey == "modulus" {
				fmt.Printf("Public.X=%X\n", privKey.PublicKey.X)
				fmt.Printf("Public.Y=%X\n", privKey.PublicKey.Y)
				os.Exit(0)
			}
			fmt.Printf(string(privPEM))
			d := privKey.D.Bytes()
			if n := len(d); n < 24 && n < 32 && n < 48 && n < 64 {
				d = append(zeroByteSlice()[:(privKey.Curve.Params().BitSize/8)-n], d...)
			}
			c := []byte{}
			c = append(c, d...)
			fmt.Printf("Private-Key: (%v-bit)\n", privKey.Curve.Params().BitSize)
			fmt.Printf("priv: \n")
			splitz := SplitSubN(hex.EncodeToString(c), 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}

			publicKey := privKey.PublicKey
			fmt.Printf("pub: \n")
			x := publicKey.X.Bytes()
			y := publicKey.Y.Bytes()
			if n := len(x); n < 24 && n < 32 && n < 48 && n < 64 {
				x = append(zeroByteSlice()[:(publicKey.Curve.Params().BitSize/8)-n], x...)
			}
			if n := len(y); n < 24 && n < 32 && n < 48 && n < 64 {
				y = append(zeroByteSlice()[:(publicKey.Curve.Params().BitSize/8)-n], y...)
			}
			c = []byte{}
			c = append(c, x...)
			c = append(c, y...)
			c = append([]byte{0x04}, c...)
			splitz = SplitSubN(hex.EncodeToString(c), 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}
			var spki struct {
				Algorithm        pkix.AlgorithmIdentifier
				SubjectPublicKey asn1.BitString
			}
			_, err = asn1.Unmarshal(derBytes, &spki)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("Curve: %s\n", publicKey.Params().Name)
			skid := sha1.Sum(spki.SubjectPublicKey.Bytes)
			fmt.Printf("\nKeyID: %x \n", skid)
		} else if strings.ToUpper(*alg) == "ED25519" {
			var privKey, _ = smx509.ParsePKCS8PrivateKey(privateKeyPemBlock.Bytes)
			if err != nil {
				log.Fatal(err)
			}
			edKey := privKey.(ed25519.PrivateKey)

			if *pkey == "modulus" {
				fmt.Printf("Public=%X\n", edKey.Public())
				os.Exit(0)
			}

			fmt.Printf(string(privPEM))
			derBytes, err := smx509.MarshalPKIXPublicKey(edKey.Public())
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("ED25519 Private-Key:\n")
			p := fmt.Sprintf("%x", privKey)
			fmt.Printf("priv: \n")
			splitz := SplitSubN(p[:64], 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}
			fmt.Printf("pub: \n")
			splitz = SplitSubN(p[64:], 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}

			var spki struct {
				Algorithm        pkix.AlgorithmIdentifier
				SubjectPublicKey asn1.BitString
			}
			_, err = asn1.Unmarshal(derBytes, &spki)
			if err != nil {
				log.Fatal(err)
			}
			skid := sha1.Sum(spki.SubjectPublicKey.Bytes)
			fmt.Printf("\nKeyID: %x \n", skid)
		} else if strings.ToUpper(*alg) == "X25519" {
			var privKey, _ = smx509.ParsePKCS8PrivateKey(privateKeyPemBlock.Bytes)
			if err != nil {
				log.Fatal(err)
			}
			edKey := privKey.(*ecdh.PrivateKey)
			fmt.Printf(string(privPEM))
			derBytes, err := x509.MarshalPKIXPublicKey(edKey.Public())
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("X25519 Private-Key:\n")
			p := fmt.Sprintf("%x", edKey.Bytes())
			fmt.Printf("priv: \n")
			splitz := SplitSubN(p, 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}
			p = fmt.Sprintf("%x", edKey.PublicKey().Bytes())
			fmt.Printf("pub: \n")
			splitz = SplitSubN(p, 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}

			var spki struct {
				Algorithm        pkix.AlgorithmIdentifier
				SubjectPublicKey asn1.BitString
			}
			_, err = asn1.Unmarshal(derBytes, &spki)
			if err != nil {
				log.Fatal(err)
			}
			skid := sha1.Sum(spki.SubjectPublicKey.Bytes)
			fmt.Printf("\nKeyID: %x \n", skid)
		} else if strings.ToUpper(*alg) == "RSA" {
			var privKey, _ = x509.ParsePKCS1PrivateKey(privateKeyPemBlock.Bytes)
			if err := privKey.Validate(); err != nil {
				panic("error validating the private key: " + err.Error())
			}
			var privKeyPublicKey = privKey.PublicKey

			if *pkey == "modulus" {
				fmt.Printf("Modulus=%X\n", privKey.N)
				os.Exit(0)
			}
			fmt.Printf(string(privPEM))
			fmt.Printf("RSA Private-Key: (%v-bit)\n", privKey.N.BitLen())

			fmt.Printf("Modulus (N): \n")
			m := privKeyPublicKey.N.Bytes()
			b, _ := hex.DecodeString("00")
			c := []byte{}
			c = append(c, b...)
			c = append(c, m...)
			splitz := SplitSubN(hex.EncodeToString(c), 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}
			fmt.Printf("Public Exponent (E): %d (0x%X)\n", privKeyPublicKey.E, privKeyPublicKey.E)
			derBytes, err := x509.MarshalPKIXPublicKey(&privKeyPublicKey)
			if err != nil {
				log.Fatal(err)
			}

			fmt.Printf("Private Exponent (D): \n")
			splitz = SplitSubN(hex.EncodeToString(privKey.D.Bytes()), 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}

			fmt.Printf("Prime 1 (P): \n")
			splitz = SplitSubN(hex.EncodeToString(privKey.Primes[0].Bytes()), 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}

			fmt.Printf("Prime 2 (Q): \n")
			splitz = SplitSubN(hex.EncodeToString(privKey.Primes[1].Bytes()), 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}

			fmt.Printf("Exponent 1 (D mod (P-1)): \n")
			splitz = SplitSubN(hex.EncodeToString(privKey.Precomputed.Dp.Bytes()), 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}

			fmt.Printf("Exponent 2 (D mod (Q-1)): \n")
			splitz = SplitSubN(hex.EncodeToString(privKey.Precomputed.Dq.Bytes()), 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}

			fmt.Printf("Coefficient (Q^-1 mod P): \n")
			splitz = SplitSubN(hex.EncodeToString(privKey.Precomputed.Qinv.Bytes()), 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}

			var spki struct {
				Algorithm        pkix.AlgorithmIdentifier
				SubjectPublicKey asn1.BitString
			}
			_, err = asn1.Unmarshal(derBytes, &spki)
			if err != nil {
				log.Fatal(err)
			}
			skid := sha1.Sum(spki.SubjectPublicKey.Bytes)
			fmt.Printf("\nKeyID: %x \n", skid)
		}
	}

	if (*pkey == "text" || *pkey == "modulus" || *pkey == "info") && (PEM == "Certificate") {
		var certPEM []byte
		file, err := os.Open(*cert)
		if err != nil {
			log.Fatal(err)
		}
		info, err := file.Stat()
		if err != nil {
			log.Fatal(err)
		}
		buf := make([]byte, info.Size())
		file.Read(buf)
		certPEM = buf
		var certPemBlock, _ = pem.Decode([]byte(certPEM))
		var certa, _ = smx509.ParseCertificate(certPemBlock.Bytes)

		signature := fmt.Sprintf("%s", certa.SignatureAlgorithm)
		if signature == "ECDSA-SHA256" || signature == "ECDSA-SHA384" || signature == "ECDSA-SHA512" {
			*alg = "EC"
		} else if signature == "99" {
			*alg = "SM2"
		} else if signature == "Ed25519" {
			*alg = "ED25519"
		} else if signature == "SHA256-RSA" || signature == "SHA384-RSA" || signature == "SHA512-RSA" {
			*alg = "RSA"
		} else {
			*alg = "GOST2012"
		}

		if *pkey == "modulus" && strings.ToUpper(*alg) == "RSA" {
			var certaPublicKey = certa.PublicKey.(*rsa.PublicKey)
			fmt.Printf("Modulus=%X\n", certaPublicKey.N)
			os.Exit(0)
		} else if *pkey == "modulus" && (strings.ToUpper(*alg) == "EC" || strings.ToUpper(*alg) == "SM2") {
			var certaPublicKey = certa.PublicKey.(*ecdsa.PublicKey)
			fmt.Printf("Public.X=%X\n", certaPublicKey.X)
			fmt.Printf("Public.Y=%X\n", certaPublicKey.Y)
			os.Exit(0)
		} else if *pkey == "modulus" && (strings.ToUpper(*alg) == "ED25519") {
			var certaPublicKey = certa.PublicKey.(ed25519.PublicKey)
			fmt.Printf("Public=%X\n", certaPublicKey)
			os.Exit(0)
		} else if *pkey == "modulus" && (strings.ToUpper(*alg) == "GOST2012") {
			var certa, _ = x509.ParseCertificate(certPemBlock.Bytes)
			var certaPublicKey = certa.PublicKey.(*gost3410.PublicKey)
			fmt.Printf("Public.X=%X\n", certaPublicKey.X)
			fmt.Printf("Public.Y=%X\n", certaPublicKey.Y)
			os.Exit(0)
		}

		if *pkey == "info" {
			fmt.Printf("Expiry:         %s \n", certa.NotAfter.Format("Monday, 02-Jan-06 15:04:05 MST"))
			fmt.Printf("Common Name:    %s \n", certa.Issuer.CommonName)
			fmt.Printf("EmailAddresses: %s \n", certa.EmailAddresses)
			fmt.Printf("IP Address:     %s \n", certa.IPAddresses)
			fmt.Printf("DNSNames:       %s \n", certa.DNSNames)
			fmt.Printf("SerialNumber:   %x \n", certa.SerialNumber)
			fmt.Printf("SubjectKeyId:   %x \n", certa.SubjectKeyId)
			fmt.Printf("AuthorityKeyId: %x \n", certa.AuthorityKeyId)
			os.Exit(0)
		}

		if *alg == "GOST2012" {
			var certPEM []byte
			file, err := os.Open(*cert)
			if err != nil {
				log.Println(err)
			}
			info, err := file.Stat()
			if err != nil {
				log.Println(err)
			}
			buf := make([]byte, info.Size())
			file.Read(buf)
			certPEM = buf
			var certPemBlock, _ = pem.Decode([]byte(certPEM))
			var certa, _ = x509.ParseCertificate(certPemBlock.Bytes)

			if *pkey == "modulus" {
				var certaPublicKey = certa.PublicKey.(*gost3410.PublicKey)
				fmt.Printf("Public.X=%X\n", certaPublicKey.X)
				fmt.Printf("Public.Y=%X\n", certaPublicKey.Y)
				os.Exit(0)
			}

			var buf2 bytes.Buffer
			buf2.Grow(4096)

			buf2.WriteString(fmt.Sprintf("Certificate:\n"))
			buf2.WriteString(fmt.Sprintf("%4sData:\n", ""))
			printVersion(certa.Version, &buf2)
			buf2.WriteString(fmt.Sprintf("%8sSerial Number : %d (%X)\n", "", certa.SerialNumber, certa.SerialNumber))
			buf2.WriteString(fmt.Sprintf("%8sCommonName    : %s \n", "", certa.Subject.CommonName))
			buf2.WriteString(fmt.Sprintf("%8sEmailAddresses: %s \n", "", certa.EmailAddresses))
			buf2.WriteString(fmt.Sprintf("%8sIsCA          : %v \n", "", certa.IsCA))

			buf2.WriteString(fmt.Sprintf("%8sCurve         : %s \n", "", certa.PublicKey.(*gost3410.PublicKey).C.Name))

			buf2.WriteString(fmt.Sprintf("%8sIssuer\n            ", ""))
			printName(certa.Issuer.Names, &buf2)
			buf2.WriteString(fmt.Sprintf("%8sSubject\n            ", ""))
			printName(certa.Subject.Names, &buf2)

			buf2.WriteString(fmt.Sprintf("%8sValidity\n", ""))
			buf2.WriteString(fmt.Sprintf("%12sNot Before: %s\n", "", certa.NotBefore.Format("Jan 2 15:04:05 2006 MST")))
			buf2.WriteString(fmt.Sprintf("%12sNot After : %s\n", "", certa.NotAfter.Format("Jan 2 15:04:05 2006 MST")))

			var certaPublicKey = certa.PublicKey.(*gost3410.PublicKey)
			x := certaPublicKey.X.Bytes()
			c := []byte{}
			c = append(c, x...)
			buf2.WriteString(fmt.Sprintf("%8sPub.X\n", ""))
			splitz := SplitSubN(hex.EncodeToString(c), 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				buf2.WriteString(fmt.Sprintf("            %-10s            \n", strings.ReplaceAll(chunk, " ", ":")))
			}
			y := certaPublicKey.Y.Bytes()
			c = []byte{}
			c = append(c, y...)
			buf2.WriteString(fmt.Sprintf("%8sPub.Y\n", ""))
			splitz = SplitSubN(hex.EncodeToString(c), 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				buf2.WriteString(fmt.Sprintf("            %-10s            \n", strings.ReplaceAll(chunk, " ", ":")))
			}

			buf2.WriteString(fmt.Sprintf("%8sSubjectKeyId  : %x \n", "", certa.SubjectKeyId))
			buf2.WriteString(fmt.Sprintf("%8sAuthorityKeyId: %x \n", "", certa.AuthorityKeyId))

			printSignature(certa.SignatureAlgorithm, certa.Signature, &buf2)
			fmt.Print(buf2.String())

			ok := time.Now().Before(certa.NotAfter)
			fmt.Println("IsValid:", ok)

			if ok {
				os.Exit(0)
			} else {
				os.Exit(1)
			}
		}

		pemData, err := ioutil.ReadFile(*cert)
		if err != nil {
			log.Fatal(err)
		}
		block, rest := pem.Decode([]byte(pemData))
		if block == nil || len(rest) > 0 {
			log.Fatal("Certificate decoding error")
		}

		result, err := certinfo.CertificateText(certa.ToX509())
		if err != nil {
			log.Fatal(err)
		}
		fmt.Print(result)

		ok := time.Now().Before(certa.NotAfter)
		fmt.Println("IsValid:", ok)

		if ok {
			os.Exit(0)
		} else {
			os.Exit(1)
		}
	}

	if *pkey == "check" && *crl == "" {
		var certPEM []byte
		file, err := os.Open(*cert)
		if err != nil {
			log.Fatal(err)
		}
		info, err := file.Stat()
		if err != nil {
			log.Fatal(err)
		}
		buf := make([]byte, info.Size())
		file.Read(buf)
		certPEM = buf
		var certPemBlock, _ = pem.Decode([]byte(certPEM))
		var certa, _ = smx509.ParseCertificate(certPemBlock.Bytes)

		pemData, err := ioutil.ReadFile(*cert)
		if err != nil {
			log.Fatal(err)
		}
		block, rest := pem.Decode([]byte(pemData))
		if block == nil || len(rest) > 0 {
			log.Fatal("Certificate decoding error")
		}

		signature := fmt.Sprintf("%s", certa.SignatureAlgorithm)
		if signature == "ECDSA-SHA256" || signature == "ECDSA-SHA384" || signature == "ECDSA-SHA512" {
			*alg = "EC"
		} else if signature == "99" {
			*alg = "SM2"
		} else if signature == "Ed25519" {
			*alg = "ED25519"
		} else if signature == "SHA256-RSA" || signature == "SHA384-RSA" || signature == "SHA512-RSA" {
			*alg = "RSA"
		} else if signature == "0" {
			*alg = "GOST2012"
		}

		var h hash.Hash
		h = sha256.New()
		if signature == "ECDSA-SHA256" {
			h = sha256.New()
		} else if signature == "ECDSA-SHA384" {
			h = sha512.New384()
		} else if signature == "ECDSA-SHA512" {
			h = sha512.New()
		} else if signature == "SHA384-RSA" {
			h = sha512.New384()
		} else if signature == "SHA512-RSA" {
			h = sha512.New()
		} else if signature == "SHA1-RSA" {
			h = sha1.New()
		}

		var verifystatus bool
		h.Write(certa.RawTBSCertificate)
		hash_data := h.Sum(nil)

		file, err = os.Open(*key)
		if err != nil {
			log.Fatal(err)
		}
		info, err = file.Stat()
		if err != nil {
			log.Fatal(err)
		}
		buf = make([]byte, info.Size())
		file.Read(buf)
		block, _ = pem.Decode(buf)

		publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			publicKey, err = smx509.ParsePKIXPublicKey(block.Bytes)
		}
		if *alg == "EC" {
			verifystatus = ecdsa.VerifyASN1(publicKey.(*ecdsa.PublicKey), hash_data, certa.Signature)
		} else if *alg == "RSA" {
			if signature == "SHA256-RSA" {
				err = rsa.VerifyPKCS1v15(publicKey.(*rsa.PublicKey), crypto.SHA256, hash_data, certa.Signature)
			} else if signature == "SHA384-RSA" {
				err = rsa.VerifyPKCS1v15(publicKey.(*rsa.PublicKey), crypto.SHA384, hash_data, certa.Signature)
				h = sha512.New384()
			} else if signature == "SHA512-RSA" {
				err = rsa.VerifyPKCS1v15(publicKey.(*rsa.PublicKey), crypto.SHA512, hash_data, certa.Signature)
				h = sha512.New()
			} else if signature == "SHA1-RSA" {
				err = rsa.VerifyPKCS1v15(publicKey.(*rsa.PublicKey), crypto.SHA1, hash_data, certa.Signature)
				h = sha1.New()
			}
			if err != nil {
				verifystatus = false
			} else {
				verifystatus = true
			}
		} else if *alg == "SM2" {
			verifystatus = sm2.VerifyASN1WithSM2(publicKey.(*ecdsa.PublicKey), nil, certa.RawTBSCertificate, certa.Signature)
		} else if *alg == "ED25519" {
			verifystatus = ed25519.Verify(publicKey.(ed25519.PublicKey), certa.RawTBSCertificate, certa.Signature)
		} else if *alg == "GOST2012" {
			var certa, _ = x509.ParseCertificate(certPemBlock.Bytes)
			signature := fmt.Sprintf("%s", certa.SignatureAlgorithm)
			if signature == "GOST512" {
				h = gost34112012512.New()
			} else {
				h = gost34112012256.New()
			}
			h.Write(certa.RawTBSCertificate)
			hash_data := h.Sum(nil)
			reverseBytes(hash_data)
			verifystatus, err = publicKey.(*gost3410.PublicKey).VerifyDigest(hash_data, certa.Signature)
			if err != nil {
				log.Fatal(err)
			}
		}

		fmt.Println("Verified:", verifystatus)
		if verifystatus {
			os.Exit(0)
		} else {
			os.Exit(1)
		}
	}

	if *pkey == "certgen" {
		file, err := os.Open(*key)
		if err != nil {
			log.Fatal(err)
		}
		info, err := file.Stat()
		if err != nil {
			log.Fatal(err)
		}
		buf := make([]byte, info.Size())
		file.Read(buf)

		var priv interface{}

		var block *pem.Block
		block, _ = pem.Decode(buf)

		if strings.ToUpper(*alg) == "ED25519" {
			var priva interface{}
			var privKeyBytes []byte
			if IsEncryptedPEMBlock(block) {
				privKeyBytes, err = DecryptPEMBlock(block, []byte(*pwd))
				if err != nil {
					log.Fatal(err)
				}
				priva, err = x509.ParsePKCS8PrivateKey(privKeyBytes)
				if err != nil {
					log.Fatal(err)
				}
			} else {
				priva, err = x509.ParsePKCS8PrivateKey(block.Bytes)
				if err != nil {
					log.Fatal(err)
				}
			}
			priv = priva
		} else if strings.ToUpper(*alg) == "EC" || strings.ToUpper(*alg) == "ECDSA" {
			var privateKey *ecdsa.PrivateKey
			var privKeyBytes []byte
			if IsEncryptedPEMBlock(block) {
				privKeyBytes, err = DecryptPEMBlock(block, []byte(*pwd))
				if err != nil {
					log.Fatal(err)
				}
				privateKey, err = smx509.ParseECPrivateKey(privKeyBytes)
				if err != nil {
					log.Fatal(err)
				}
			} else {
				privateKey, err = smx509.ParseECPrivateKey(block.Bytes)
				if err != nil {
					log.Fatal(err)
				}
			}
			priv = privateKey
		} else if strings.ToUpper(*alg) == "SM2" {
			var privateKey *sm2.PrivateKey
			var privKeyBytes []byte
			if IsEncryptedPEMBlock(block) {
				privKeyBytes, err = DecryptPEMBlock(block, []byte(*pwd))
				if err != nil {
					log.Fatal(err)
				}
				privateKey, err = smx509.ParseSM2PrivateKey(privKeyBytes)
				if err != nil {
					log.Fatal(err)
				}
			} else {
				privateKey, err = smx509.ParseSM2PrivateKey(block.Bytes)
				if err != nil {
					log.Fatal(err)
				}
			}
			priv = privateKey
		} else if strings.ToUpper(*alg) == "RSA" {
			var privateKey *rsa.PrivateKey
			var privKeyBytes []byte
			if IsEncryptedPEMBlock(block) {
				privKeyBytes, err = DecryptPEMBlock(block, []byte(*pwd))
				if err != nil {
					log.Fatal(err)
				}
				privateKey, err = x509.ParsePKCS1PrivateKey(privKeyBytes)
				if err != nil {
					log.Fatal(err)
				}
			} else {
				privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
				if err != nil {
					log.Fatal(err)
				}
			}
			priv = privateKey
		}

		keyUsage := smx509.KeyUsageDigitalSignature

		serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 160)
		serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
		if err != nil {
			log.Fatalf("Failed to generate serial number: %v", err)
		}

		println("You are about to be asked to enter information \nthat will be incorporated into your certificate.")

		scanner := bufio.NewScanner(os.Stdin)

		print("Common Name: ")
		scanner.Scan()
		name := scanner.Text()

		print("Country Name (2 letter code) [AU]: ")
		scanner.Scan()
		country := scanner.Text()

		print("State or Province Name (full name) [Some-State]: ")
		scanner.Scan()
		province := scanner.Text()

		print("Locality Name (eg, city): ")
		scanner.Scan()
		locality := scanner.Text()

		print("Organization Name (eg, company) [Internet Widgits Pty Ltd]: ")
		scanner.Scan()
		organization := scanner.Text()

		print("Organizational Unit Name (eg, section): ")
		scanner.Scan()
		organizationunit := scanner.Text()

		print("Email Address []: ")
		scanner.Scan()
		email := scanner.Text()

		print("StreetAddress: ")
		scanner.Scan()
		street := scanner.Text()

		print("PostalCode: ")
		scanner.Scan()
		postalcode := scanner.Text()

		print("SerialNumber: ")
		scanner.Scan()
		number := scanner.Text()

		print("Validity (in Days): ")
		scanner.Scan()
		validity := scanner.Text()

		intVar, err := strconv.Atoi(validity)
		NotAfter := time.Now().AddDate(0, 0, intVar)

		template := x509.Certificate{
			SerialNumber: serialNumber,
			Subject: pkix.Name{
				CommonName:         name,
				SerialNumber:       number,
				Country:            []string{country},
				Province:           []string{province},
				Locality:           []string{locality},
				Organization:       []string{organization},
				OrganizationalUnit: []string{organizationunit},
				StreetAddress:      []string{street},
				PostalCode:         []string{postalcode},
			},
			EmailAddresses: []string{email},

			NotBefore: time.Now(),
			NotAfter:  NotAfter,

			KeyUsage:              keyUsage,
			ExtKeyUsage:           []smx509.ExtKeyUsage{smx509.ExtKeyUsageClientAuth, smx509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
			IsCA:                  true,

			PermittedDNSDomainsCritical: true,
		}

		template.IsCA = true
		template.KeyUsage |= smx509.KeyUsageCertSign | smx509.KeyUsageCRLSign | x509.KeyUsageContentCommitment | x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment | x509.KeyUsageKeyAgreement

		if strings.ToUpper(*alg) == "RSA" {
			if *md == "sha256" {
				template.SignatureAlgorithm = smx509.SHA256WithRSA
			} else if *md == "sha384" {
				template.SignatureAlgorithm = smx509.SHA384WithRSA
			} else if *md == "sha512" {
				template.SignatureAlgorithm = smx509.SHA512WithRSA
			} else if *md == "sha1" {
				template.SignatureAlgorithm = smx509.SHA1WithRSA
			}
		}

		derBytes, err := smx509.CreateCertificate(rand.Reader, &template, &template, publicKey(priv), priv)
		if err != nil {
			log.Fatalf("Failed to create certificate: %v", err)
		}

		certfile, err := os.Create(*cert)
		if err != nil {
			log.Fatal(err)
		}
		pem.Encode(certfile, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
		os.Exit(0)
	}

	if *pkey == "req" && *key != "" {
		file, err := os.Open(*key)
		if err != nil {
			log.Fatal(err)
		}
		info, err := file.Stat()
		if err != nil {
			log.Fatal(err)
		}
		buf := make([]byte, info.Size())
		file.Read(buf)

		var keyBytes interface{}

		var block *pem.Block
		block, _ = pem.Decode(buf)

		if strings.ToUpper(*alg) == "ED25519" {
			var priva interface{}
			var privKeyBytes []byte
			if IsEncryptedPEMBlock(block) {
				privKeyBytes, err = DecryptPEMBlock(block, []byte(*pwd))
				if err != nil {
					log.Fatal(err)
				}
				priva, err = x509.ParsePKCS8PrivateKey(privKeyBytes)
				if err != nil {
					log.Fatal(err)
				}
			} else {
				priva, err = x509.ParsePKCS8PrivateKey(block.Bytes)
				if err != nil {
					log.Fatal(err)
				}
			}
			keyBytes = priva
		} else if strings.ToUpper(*alg) == "EC" || strings.ToUpper(*alg) == "ECDSA" {
			var privateKey *ecdsa.PrivateKey
			var privKeyBytes []byte
			if IsEncryptedPEMBlock(block) {
				privKeyBytes, err = DecryptPEMBlock(block, []byte(*pwd))
				if err != nil {
					log.Fatal(err)
				}
				privateKey, err = smx509.ParseECPrivateKey(privKeyBytes)
				if err != nil {
					log.Fatal(err)
				}
			} else {
				privateKey, err = smx509.ParseECPrivateKey(block.Bytes)
				if err != nil {
					log.Fatal(err)
				}
			}
			keyBytes = privateKey
		} else if strings.ToUpper(*alg) == "SM2" {
			var privateKey *sm2.PrivateKey
			var privKeyBytes []byte
			if IsEncryptedPEMBlock(block) {
				privKeyBytes, err = DecryptPEMBlock(block, []byte(*pwd))
				if err != nil {
					log.Fatal(err)
				}
				privateKey, err = smx509.ParseSM2PrivateKey(privKeyBytes)
				if err != nil {
					log.Fatal(err)
				}
			} else {
				privateKey, err = smx509.ParseSM2PrivateKey(block.Bytes)
				if err != nil {
					log.Fatal(err)
				}
			}
			keyBytes = privateKey
		} else if strings.ToUpper(*alg) == "RSA" {
			var privateKey *rsa.PrivateKey
			var privKeyBytes []byte
			if IsEncryptedPEMBlock(block) {
				privKeyBytes, err = DecryptPEMBlock(block, []byte(*pwd))
				if err != nil {
					log.Fatal(err)
				}
				privateKey, err = x509.ParsePKCS1PrivateKey(privKeyBytes)
				if err != nil {
					log.Fatal(err)
				}
			} else {
				privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
				if err != nil {
					log.Fatal(err)
				}
			}
			keyBytes = privateKey
		}

		println("You are about to be asked to enter information that \nwill be incorporated into your certificate request.")

		scanner := bufio.NewScanner(os.Stdin)

		print("Common Name: ")
		scanner.Scan()
		name := scanner.Text()

		print("Country Name (2 letter code) [AU]: ")
		scanner.Scan()
		country := scanner.Text()

		print("State or Province Name (full name) [Some-State]: ")
		scanner.Scan()
		province := scanner.Text()

		print("Locality Name (eg, city): ")
		scanner.Scan()
		locality := scanner.Text()

		print("Organization Name (eg, company) [Internet Widgits Pty Ltd]: ")
		scanner.Scan()
		organization := scanner.Text()

		print("Organizational Unit Name (eg, section): ")
		scanner.Scan()
		organizationunit := scanner.Text()

		print("Email Address []: ")
		scanner.Scan()
		email := scanner.Text()

		print("StreetAddress: ")
		scanner.Scan()
		street := scanner.Text()

		print("PostalCode: ")
		scanner.Scan()
		postalcode := scanner.Text()

		print("SerialNumber: ")
		scanner.Scan()
		number := scanner.Text()

		emailAddress := email
		subj := pkix.Name{
			CommonName:         name,
			SerialNumber:       number,
			Country:            []string{country},
			Province:           []string{province},
			Locality:           []string{locality},
			Organization:       []string{organization},
			OrganizationalUnit: []string{organizationunit},
			StreetAddress:      []string{street},
			PostalCode:         []string{postalcode},
		}
		rawSubj := subj.ToRDNSequence()
		rawSubj = append(rawSubj, []pkix.AttributeTypeAndValue{
			{Type: oidEmailAddress, Value: emailAddress},
		})

		asn1Subj, _ := asn1.Marshal(rawSubj)
		var template x509.CertificateRequest
		if strings.ToUpper(*alg) == "RSA" {
			template = x509.CertificateRequest{
				RawSubject:         asn1Subj,
				EmailAddresses:     []string{emailAddress},
				SignatureAlgorithm: x509.SHA256WithRSA,
			}
		} else if strings.ToUpper(*alg) == "ECDSA" || strings.ToUpper(*alg) == "EC" {
			template = x509.CertificateRequest{
				RawSubject:         asn1Subj,
				EmailAddresses:     []string{emailAddress},
				SignatureAlgorithm: x509.ECDSAWithSHA256,
			}
		} else if strings.ToUpper(*alg) == "SM2" {
			template = x509.CertificateRequest{
				RawSubject:         asn1Subj,
				EmailAddresses:     []string{emailAddress},
				SignatureAlgorithm: smx509.SM2WithSM3,
			}
		} else if strings.ToUpper(*alg) == "ED25519" {
			template = x509.CertificateRequest{
				RawSubject:         asn1Subj,
				EmailAddresses:     []string{emailAddress},
				SignatureAlgorithm: x509.PureEd25519,
			}
		}
		var output *os.File
		if *cert == "" {
			output = os.Stdout
		} else {
			file, err := os.Create(*cert)
			if err != nil {
				log.Fatal(err)
			}
			defer file.Close()
			output = file
		}
		csrBytes, _ := smx509.CreateCertificateRequest(rand.Reader, &template, keyBytes)
		pem.Encode(output, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
	}

	if (*pkey == "crl") && *key != "" && *cert != "" && strings.ToUpper(*alg) != "SM2" {
		revokedCerts := make([]pkix.RevokedCertificate, 0)

		scanner := bufio.NewScanner(inputfile)
		existingSerialNumbers := make(map[string]bool)
		for scanner.Scan() {
			serialStr := strings.TrimSpace(scanner.Text())
			serialNumber, success := new(big.Int).SetString(serialStr, 16)
			if !success {
				log.Fatalf("Invalid serial number: %s", serialStr)
			}
			serialKey := serialNumber.String()
			if existingSerialNumbers[serialKey] {
				continue
			}
			revocationTime := time.Now()

			revokedCert := pkix.RevokedCertificate{
				SerialNumber:   serialNumber,
				RevocationTime: revocationTime,
			}
			revokedCerts = append(revokedCerts, revokedCert)
			existingSerialNumbers[serialKey] = true
		}

		if err := scanner.Err(); err != nil {
			log.Fatal("Failed to read serials list:", err)
		}

		if *crl != "" {
			existingCRLData, err := ioutil.ReadFile(*crl)
			if err != nil {
				log.Fatal("Failed to read the existing CRL file:", err)
			}
			existingCRLBlock, _ := pem.Decode(existingCRLData)
			if existingCRLBlock == nil {
				log.Fatal("Failed to decode the PEM block of the existing CRL")
			}
			existingCRL, err := x509.ParseRevocationList(existingCRLBlock.Bytes)
			if err != nil {
				log.Fatal("Failed to parse the existing CRL:", err)
			}
			for _, revokedCert := range existingCRL.RevokedCertificates {
				serialKey := revokedCert.SerialNumber.String()
				if existingSerialNumbers[serialKey] {
					continue
				}
				revokedCerts = append(revokedCerts, revokedCert)
				existingSerialNumbers[serialKey] = true
			}
		}

		desiredLength := 80
		randomNumber, err := rand.Int(rand.Reader, new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(desiredLength)), nil))
		if err != nil {
			log.Fatal("Failed to generate a random number:", err)
		}

		issuanceTime := time.Now()
		nextUpdateTime := time.Now().Add(time.Hour * 24 * 365)

		issuerKeyPEM, err := os.ReadFile(*key)
		if err != nil {
			log.Fatal("Failed to read private key file:", err)
		}

		issuerCertPEM, err := os.ReadFile(*cert)
		if err != nil {
			log.Fatal("Failed to read certificate file:", err)
		}

		issuerKey, issuerCert, err := parsePrivateKeyAndCert(issuerKeyPEM, issuerCertPEM)
		if err != nil {
			log.Fatal("Failed to parse private key and certificate:", err)
		}

		revocationListTemplate := &x509.RevocationList{
			RevokedCertificates: revokedCerts,
			Number:              randomNumber,
			ThisUpdate:          issuanceTime,
			NextUpdate:          nextUpdateTime,
		}

		var crlBytes []byte
		if strings.ToUpper(*alg) == "GOST2012" {
			crlBytes, err = x509.CreateRevocationList(rand.Reader, revocationListTemplate, issuerCert, &gost3410.PrivateKeyReverseDigest{Prv: issuerKey.(*gost3410.PrivateKey)})
		} else {
			crlBytes, err = x509.CreateRevocationList(rand.Reader, revocationListTemplate, issuerCert, issuerKey)
		}
		if err != nil {
			log.Fatal("Failed to create new CRL:", err)
		}

		pemBlock := &pem.Block{
			Type:  "X509 CRL",
			Bytes: crlBytes,
		}

		var output *os.File
		if flag.Arg(1) == "" {
			output = os.Stdout
		} else {
			file, err := os.Create(flag.Arg(1))
			if err != nil {
				log.Fatal(err)
			}
			defer file.Close()
			output = file
		}
		pem.Encode(output, pemBlock)
	}

	if (*pkey == "crl") && *key != "" && *cert != "" && strings.ToUpper(*alg) == "SM2" {
		revokedCerts := make([]pkix.RevokedCertificate, 0)

		scanner := bufio.NewScanner(inputfile)
		existingSerialNumbers := make(map[string]bool)
		for scanner.Scan() {
			serialStr := strings.TrimSpace(scanner.Text())
			serialNumber, success := new(big.Int).SetString(serialStr, 16)
			if !success {
				log.Fatalf("Invalid serial number: %s", serialStr)
			}
			serialKey := serialNumber.String()
			if existingSerialNumbers[serialKey] {
				continue
			}
			revocationTime := time.Now()

			revokedCert := pkix.RevokedCertificate{
				SerialNumber:   serialNumber,
				RevocationTime: revocationTime,
			}
			revokedCerts = append(revokedCerts, revokedCert)
			existingSerialNumbers[serialKey] = true
		}

		if err := scanner.Err(); err != nil {
			log.Fatal("Failed to read serials.txt:", err)
		}

		if *crl != "" {
			existingCRLData, err := ioutil.ReadFile(*crl)
			if err != nil {
				log.Fatal("Failed to read the existing CRL file:", err)
			}
			existingCRLBlock, _ := pem.Decode(existingCRLData)
			if existingCRLBlock == nil {
				log.Fatal("Failed to decode the PEM block of the existing CRL")
			}
			existingCRL, err := x509.ParseRevocationList(existingCRLBlock.Bytes)
			if err != nil {
				log.Fatal("Failed to parse the existing CRL:", err)
			}
			for _, revokedCert := range existingCRL.RevokedCertificates {
				serialKey := revokedCert.SerialNumber.String()
				if existingSerialNumbers[serialKey] {
					continue
				}
				revokedCerts = append(revokedCerts, revokedCert)
				existingSerialNumbers[serialKey] = true
			}
		}

		desiredLength := 80
		randomNumber, err := rand.Int(rand.Reader, new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(desiredLength)), nil))
		if err != nil {
			log.Fatal("Failed to generate a random number:", err)
		}

		issuanceTime := time.Now()
		nextUpdateTime := time.Now().Add(time.Hour * 24 * 365)

		revocationListTemplate := &x509.RevocationList{
			RevokedCertificates: revokedCerts,
			Number:              randomNumber,
			ThisUpdate:          issuanceTime,
			NextUpdate:          nextUpdateTime,
		}

		issuerKeyPEM, err := os.ReadFile(*key)
		if err != nil {
			log.Fatal("Failed to read private key file:", err)
		}

		issuerCertPEM, err := os.ReadFile(*cert)
		if err != nil {
			log.Fatal("Failed to read certificate file:", err)
		}

		issuerKey, issuerCert, err := parsePrivateKeyAndCertSM2(issuerKeyPEM, issuerCertPEM)
		if err != nil {
			log.Fatal("Failed to parse private key and certificate:", err)
		}

		var crlBytes []byte
		crlBytes, err = smx509.CreateRevocationList(rand.Reader, revocationListTemplate, issuerCert, issuerKey)

		if err != nil {
			log.Fatal("Failed to create new CRL:", err)
		}

		pemBlock := &pem.Block{
			Type:  "X509 CRL",
			Bytes: crlBytes,
		}

		var output *os.File
		if flag.Arg(1) == "" {
			output = os.Stdout
		} else {
			file, err := os.Create(flag.Arg(1))
			if err != nil {
				log.Fatal(err)
			}
			defer file.Close()
			output = file
		}
		pem.Encode(output, pemBlock)
	}

	if *pkey == "validate" {
		crlBytes, err := ioutil.ReadFile(*crl)
		if err != nil {
			log.Fatal("Failed to read CRL file:", err)
		}

		pemBlock, _ := pem.Decode(crlBytes)
		if pemBlock == nil {
			log.Fatal("Failed to decode CRL PEM block")
		}
		crl, err := x509.ParseDERCRL(pemBlock.Bytes)
		if err != nil {
			log.Fatal("Failed to parse CRL:", err)
		}

		certBytes, err := ioutil.ReadFile(*cert)
		if err != nil {
			log.Fatal("Failed to read certificate file:", err)
		}

		pemBlock, _ = pem.Decode(certBytes)
		if pemBlock == nil {
			log.Fatal("Failed to decode certificate PEM block")
		}

		cert, err := x509.ParseCertificate(pemBlock.Bytes)
		if err != nil {
			cert, err := smx509.ParseCertificate(pemBlock.Bytes)
			if err != nil {
				log.Fatal("Failed to parse certificate:", err)
			}
			isRevoked, revocationTime := isCertificateRevokedSM2(cert, crl)
			if isRevoked {
				fmt.Println("The certificate is revoked")
				fmt.Println("Revocation Time:", revocationTime)
				os.Exit(1)
			} else {
				fmt.Println("The certificate is not revoked")
				os.Exit(0)
			}
		}

		isRevoked, revocationTime := isCertificateRevoked(cert, crl)
		if isRevoked {
			fmt.Println("The certificate is revoked")
			fmt.Println("Revocation Time:", revocationTime)
			os.Exit(1)
		} else {
			fmt.Println("The certificate is not revoked")
			os.Exit(0)
		}
	}

	if (*pkey == "check") && *crl != "" {
		crlBytes, err := ioutil.ReadFile(*crl)
		if err != nil {
			log.Fatal("Failed to read CRL file:", err)
		}

		pemBlock, _ := pem.Decode(crlBytes)
		if pemBlock == nil {
			log.Fatal("Failed to decode CRL PEM block")
		}

		revocationList, err := x509.ParseDERCRL(pemBlock.Bytes)
		if err != nil {
			log.Fatal("Failed to parse CRL:", err)
		}

		issuerCertBytes, err := ioutil.ReadFile(*cert)
		if err != nil {
			log.Fatal("Failed to read issuer's certificate file:", err)
		}

		issuerCertBlock, _ := pem.Decode(issuerCertBytes)
		if issuerCertBlock == nil {
			log.Fatal("Failed to decode PEM block of issuer's certificate")
		}

		issuerCert, err := x509.ParseCertificate(issuerCertBlock.Bytes)
		if err != nil {
			issuerCert, err := smx509.ParseCertificate(issuerCertBlock.Bytes)
			if err != nil {
				log.Fatal("Failed to parse issuer's certificate:", err)
			}

			err = issuerCert.CheckCRLSignature(revocationList)
			if err != nil {
				log.Fatal("Verified: false: ", err)
			}

			fmt.Println("Verified: true")
			os.Exit(0)
		}

		err = issuerCert.CheckCRLSignature(revocationList)
		if err != nil {
			log.Fatal("Verified: false: ", err)
		}

		fmt.Println("Verified: true")
	}

	if (*pkey == "text") && *crl != "" {
		pemData, err := ioutil.ReadFile(*crl)
		if err != nil {
			log.Fatal("Failed to read the CRL file:", err)
		}

		pemBlock, _ := pem.Decode(pemData)
		if pemBlock == nil {
			log.Fatal("Failed to decode the PEM block")
		}

		revocationList, err := x509.ParseRevocationList(pemBlock.Bytes)
		if err != nil {
			log.Fatal("Failed to parse the CRL:", err)
		}

		akid := getAuthorityKeyIdentifierFromCRL(revocationList)

		crl, err := x509.ParseDERCRL(pemBlock.Bytes)
		if err != nil {
			log.Fatal("Failed to parse the CRL:", err)
		}

		fmt.Println("CRL:")
		fmt.Println("  Data:")
		fmt.Printf("    Number             : %d (%X)\n", revocationList.Number, revocationList.Number)
		fmt.Println("    Last Update        :", crl.TBSCertList.ThisUpdate)
		fmt.Println("    Next Update        :", crl.TBSCertList.NextUpdate)

		fmt.Println("    Issuer")
		fmt.Println("       ", crl.TBSCertList.Issuer)

		fmt.Printf("    Authority Key ID   : %x\n", akid)

		algoName := getAlgorithmName(crl.SignatureAlgorithm.Algorithm.String())
		fmt.Println("    Signature Algorithm:", algoName)

		splitz := SplitSubN(hex.EncodeToString(crl.SignatureValue.Bytes), 2)
		for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
			fmt.Printf("        %-10s            \n", strings.ReplaceAll(chunk, " ", ":"))
		}

		fmt.Println("  Revoked Certificates:")
		for _, revokedCert := range revocationList.RevokedCertificates {
			fmt.Printf("  - Serial Number: %X\n", revokedCert.SerialNumber)
			fmt.Println("    Revocation Time:", revokedCert.RevocationTime)
		}
	}

	if (*pkey == "text" || *pkey == "modulus") && PEM == "CertificateRequest" {
		var certPEM []byte
		file, err := os.Open(*cert)
		if err != nil {
			log.Fatal(err)
		}
		info, err := file.Stat()
		if err != nil {
			log.Fatal(err)
		}
		buf := make([]byte, info.Size())
		file.Read(buf)
		certPEM = buf
		var certPemBlock, _ = pem.Decode([]byte(certPEM))
		var certa, _ = smx509.ParseCertificateRequest(certPemBlock.Bytes)

		signature := fmt.Sprintf("%s", certa.SignatureAlgorithm)
		if signature == "ECDSA-SHA256" || signature == "ECDSA-SHA384" || signature == "ECDSA-SHA512" {
			*alg = "EC"
		} else if signature == "99" {
			*alg = "SM2"
		} else if signature == "Ed25519" {
			*alg = "ED25519"
		} else if signature == "SHA256-RSA" || signature == "SHA384-RSA" || signature == "SHA512-RSA" {
			*alg = "RSA"
		} else if signature == "0" {
			*alg = "GOST2012"
		}

		if *pkey == "modulus" && strings.ToUpper(*alg) == "RSA" {
			var certaPublicKey = certa.PublicKey.(*rsa.PublicKey)
			fmt.Printf("Modulus=%X\n", certaPublicKey.N)
			os.Exit(0)
		} else if *pkey == "modulus" && (strings.ToUpper(*alg) == "EC" || strings.ToUpper(*alg) == "SM2") {
			var certaPublicKey = certa.PublicKey.(*ecdsa.PublicKey)
			fmt.Printf("Public.X=%X\n", certaPublicKey.X)
			fmt.Printf("Public.Y=%X\n", certaPublicKey.Y)
			os.Exit(0)
		} else if *pkey == "modulus" && (strings.ToUpper(*alg) == "ED25519") {
			var certaPublicKey = certa.PublicKey.(ed25519.PublicKey)
			fmt.Printf("Public=%X\n", certaPublicKey)
			os.Exit(0)
		} else if *pkey == "modulus" && (strings.ToUpper(*alg) == "GOST2012") {
			var certa, _ = x509.ParseCertificateRequest(certPemBlock.Bytes)
			var certaPublicKey = certa.PublicKey.(*gost3410.PublicKey)
			fmt.Printf("Public.X=%X\n", certaPublicKey.X)
			fmt.Printf("Public.Y=%X\n", certaPublicKey.Y)
			os.Exit(0)
		}

		if *alg == "GOST2012" {
			var certPEM []byte
			file, err := os.Open(*cert)
			if err != nil {
				log.Fatal(err)
			}
			info, err := file.Stat()
			if err != nil {
				log.Fatal(err)
			}
			buf := make([]byte, info.Size())
			file.Read(buf)
			certPEM = buf
			var certPemBlock, _ = pem.Decode([]byte(certPEM))

			certa, _ := x509.ParseCertificateRequest(certPemBlock.Bytes)

			if *pkey == "modulus" && (strings.ToUpper(*alg) == "GOST2012") {
				var certaPublicKey = certa.PublicKey.(*gost3410.PublicKey)
				fmt.Printf("Public.X=%X\n", certaPublicKey.X)
				fmt.Printf("Public.Y=%X\n", certaPublicKey.Y)
				os.Exit(0)
			}

			var certaPublicKey = certa.PublicKey.(*gost3410.PublicKey)
			var buf2 bytes.Buffer
			buf2.Grow(4096)

			buf2.WriteString(fmt.Sprintf("Certificate:\n"))
			buf2.WriteString(fmt.Sprintf("%4sData:\n", ""))
			printVersion(certa.Version, &buf2)
			buf2.WriteString(fmt.Sprintf("%8sCommonName    : %s \n", "", certa.Subject.CommonName))
			buf2.WriteString(fmt.Sprintf("%8sEmailAddresses: %s \n", "", certa.EmailAddresses))

			buf2.WriteString(fmt.Sprintf("%8sCurve         : %s \n", "", certa.PublicKey.(*gost3410.PublicKey).C.Name))

			buf2.WriteString(fmt.Sprintf("%8sSubject\n            ", ""))
			printName(certa.Subject.Names, &buf2)

			x := certaPublicKey.X.Bytes()
			c := []byte{}
			c = append(c, x...)
			buf2.WriteString(fmt.Sprintf("%8sPub.X\n", ""))
			splitz := SplitSubN(hex.EncodeToString(c), 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				buf2.WriteString(fmt.Sprintf("            %-10s            \n", strings.ReplaceAll(chunk, " ", ":")))
			}
			y := certaPublicKey.Y.Bytes()
			c = []byte{}
			c = append(c, y...)
			buf2.WriteString(fmt.Sprintf("%8sPub.Y\n", ""))
			splitz = SplitSubN(hex.EncodeToString(c), 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				buf2.WriteString(fmt.Sprintf("            %-10s            \n", strings.ReplaceAll(chunk, " ", ":")))
			}

			printSignature(certa.SignatureAlgorithm, certa.Signature, &buf2)
			fmt.Print(buf2.String())

			os.Exit(0)
		}

		result, err := certinfo.CertificateRequestText(certa.ToX509())
		if err != nil {
			log.Fatal(err)
		}
		fmt.Print(result)
	}

	if (*tcpip == "server" || *tcpip == "client") && (strings.ToUpper(*alg) != "SM2" && strings.ToUpper(*alg) != "GOST2012") {
		var certPEM []byte
		var privPEM []byte
		if *key == "" {
			var priv interface{}
			var err error
			if strings.ToUpper(*alg) == "ED25519" {
				_, priv, err = ed25519.GenerateKey(rand.Reader)
			} else if strings.ToUpper(*alg) == "EC" || strings.ToUpper(*alg) == "ECDSA" {
				priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			} else if strings.ToUpper(*alg) == "SM2" {
				priv, err = sm2.GenerateKey(rand.Reader)
			} else if strings.ToUpper(*alg) == "RSA" {
				priv, err = rsa.GenerateKey(rand.Reader, 2048)
			}
			if err != nil {
				log.Fatalf("Failed to generate private key: %v", err)
			}

			keyUsage := smx509.KeyUsageDigitalSignature

			serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
			serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
			if err != nil {
				log.Fatalf("Failed to generate serial number: %v", err)
			}

			consensus := externalip.DefaultConsensus(nil, nil)
			ip, _ := consensus.ExternalIP()

			Mins := 12
			NotAfter := time.Now().Local().Add(time.Minute * time.Duration(Mins))

			template := x509.Certificate{
				SerialNumber: serialNumber,
				Subject: pkix.Name{
					CommonName:         "",
					Country:            []string{""},
					Province:           []string{""},
					Locality:           []string{""},
					Organization:       []string{""},
					OrganizationalUnit: []string{""},
				},
				EmailAddresses: []string{"pedroalbanese@hotmail.com"},

				NotBefore: time.Now(),
				NotAfter:  NotAfter,

				KeyUsage:              keyUsage,
				ExtKeyUsage:           []smx509.ExtKeyUsage{smx509.ExtKeyUsageClientAuth, smx509.ExtKeyUsageServerAuth},
				BasicConstraintsValid: true,
				IsCA:                  true,

				PermittedDNSDomainsCritical: true,
				DNSNames:                    []string{ip.String()},
				IPAddresses:                 []net.IP{net.IPv4(127, 0, 0, 1).To4(), net.ParseIP("2001:4860:0:2001::68")},
			}

			template.IsCA = true
			template.KeyUsage |= smx509.KeyUsageCertSign

			derBytes, err := smx509.CreateCertificate(rand.Reader, &template, &template, publicKey(priv), priv)
			if err != nil {
				log.Fatalf("Failed to create certificate: %v", err)
			}

			certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
			privBytes, err := smx509.MarshalPKCS8PrivateKey(priv)
			if err != nil {
				log.Fatalf("Unable to marshal private key: %v", err)
			}
			privPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
		} else {
			file, err := os.Open(*key)
			if err != nil {
				log.Fatal(err)
			}
			info, err := file.Stat()
			if err != nil {
				log.Fatal(err)
			}
			buf := make([]byte, info.Size())
			file.Read(buf)

			var block *pem.Block
			block, _ = pem.Decode(buf)

			if block == nil {
				errors.New("no valid private key found")
			}

			var privKeyBytes []byte
			if IsEncryptedPEMBlock(block) {
				privKeyBytes, err = DecryptPEMBlock(block, []byte(*pwd))
				if err != nil {
					log.Fatal(err)
				}
				privPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privKeyBytes})
			} else {
				privPEM = buf
			}

			file, err = os.Open(*cert)
			if err != nil {
				log.Fatal(err)
			}
			info, err = file.Stat()
			if err != nil {
				log.Fatal(err)
			}
			buf = make([]byte, info.Size())
			file.Read(buf)
			certPEM = buf
		}

		if *tcpip == "server" {
			cert, err := tls.X509KeyPair(certPEM, privPEM)
			cfg := tls.Config{Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAnyClientCert, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS13}
			cfg.Rand = rand.Reader

			port := "8081"
			if *iport != "" {
				port = *iport
			}

			ln, err := tls.Listen("tcp", ":"+port, &cfg)
			if err != nil {
				log.Fatal(err)
			}

			fmt.Fprintln(os.Stderr, "Server(TLS) up and listening on port "+port)

			conn, err := ln.Accept()
			if err != nil {
				log.Fatal(err)
			}
			defer ln.Close()

			tlscon := conn.(*tls.Conn)
			err = tlscon.Handshake()
			if err != nil {
				log.Fatalf("server: handshake failed: %s", err)
			} else {
				log.Print("server: conn: Handshake completed")
			}

			state := tlscon.ConnectionState()

			for _, v := range state.PeerCertificates {
				derBytes, err := smx509.MarshalPKIXPublicKey(v.PublicKey)
				if err != nil {
					log.Fatal(err)
				}
				pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: derBytes})
				fmt.Printf("%s\n", pubPEM)
			}

			go handleConnectionTLS(conn)
			fmt.Println("Connection accepted")

			for {
				message, err := bufio.NewReader(conn).ReadString('\n')
				if err != nil {
					fmt.Println(err)
					os.Exit(3)
				}
				fmt.Print("Client response: " + string(message))

				reader := bufio.NewReader(os.Stdin)
				fmt.Print("Text to be sent: ")
				text, err := reader.ReadString('\n')
				if err != nil {
					fmt.Println(err)
					os.Exit(3)
				}
				fmt.Fprintf(conn, text+"\n")
			}
		}

		if *tcpip == "client" {
			cert, err := tls.X509KeyPair(certPEM, privPEM)
			cfg := tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true}

			ipport := "127.0.0.1:8081"
			if *iport != "" {
				ipport = *iport
			}

			conn, err := tls.Dial("tcp", ipport, &cfg)
			if err != nil {
				log.Fatal(err)
			}
			certs := conn.ConnectionState().PeerCertificates
			for _, cert := range certs {
				fmt.Printf("Issuer: \n\t%s\n", cert.Issuer)
				fmt.Printf("Subject: \n\t%s\n", cert.Subject)
				fmt.Printf("Expiry: %s \n", cert.NotAfter.Format("Monday, 02-Jan-06 15:04:05 MST"))
			}
			if err != nil {
				log.Fatal(err)
			}
			if conn.ConnectionState().Version == 771 {
				fmt.Println("Protocol: TLS v1.2")
			} else if conn.ConnectionState().Version == 772 {
				fmt.Println("Protocol: TLS v1.3")
			}
			if conn.ConnectionState().CipherSuite == 0x1301 {
				fmt.Println("CipherSuite: TLS_AES_128_GCM_SHA256")
			} else if conn.ConnectionState().CipherSuite == 0x1302 {
				fmt.Println("CipherSuite: TLS_AES_256_GCM_SHA384")
			} else if conn.ConnectionState().CipherSuite == 0x1303 {
				fmt.Println("CipherSuite: TLS_CHACHA20_POLY1305_SHA256")
			}
			if conn.ConnectionState().CipherSuite == 0x0005 {
				fmt.Println("CipherSuite: TLS_RSA_WITH_RC4_128_SHA")
			} else if conn.ConnectionState().CipherSuite == 0x000a {
				fmt.Println("CipherSuite: TLS_RSA_WITH_3DES_EDE_CBC_SHA")
			} else if conn.ConnectionState().CipherSuite == 0x002f {
				fmt.Println("CipherSuite: TLS_RSA_WITH_AES_128_CBC_SHA")
			} else if conn.ConnectionState().CipherSuite == 0x0035 {
				fmt.Println("CipherSuite: TLS_RSA_WITH_AES_256_CBC_SHA")
			} else if conn.ConnectionState().CipherSuite == 0x003c {
				fmt.Println("CipherSuite: TLS_RSA_WITH_AES_128_CBC_SHA256")
			} else if conn.ConnectionState().CipherSuite == 0x009c {
				fmt.Println("CipherSuite: TLS_RSA_WITH_AES_128_GCM_SHA256")
			} else if conn.ConnectionState().CipherSuite == 0x009d {
				fmt.Println("CipherSuite: TLS_RSA_WITH_AES_256_GCM_SHA384")
			} else if conn.ConnectionState().CipherSuite == 0xc007 {
				fmt.Println("CipherSuite: TLS_ECDHE_ECDSA_WITH_RC4_128_SHA")
			} else if conn.ConnectionState().CipherSuite == 0xc009 {
				fmt.Println("CipherSuite: TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA")
			} else if conn.ConnectionState().CipherSuite == 0xc00a {
				fmt.Println("CipherSuite: TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA")
			} else if conn.ConnectionState().CipherSuite == 0xc011 {
				fmt.Println("CipherSuite: TLS_ECDHE_RSA_WITH_RC4_128_SHA")
			} else if conn.ConnectionState().CipherSuite == 0xc012 {
				fmt.Println("CipherSuite: TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA")
			} else if conn.ConnectionState().CipherSuite == 0xc013 {
				fmt.Println("CipherSuite: TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA")
			} else if conn.ConnectionState().CipherSuite == 0xc014 {
				fmt.Println("CipherSuite: TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA")
			} else if conn.ConnectionState().CipherSuite == 0xc023 {
				fmt.Println("CipherSuite: TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256")
			} else if conn.ConnectionState().CipherSuite == 0xc027 {
				fmt.Println("CipherSuite: TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256")
			} else if conn.ConnectionState().CipherSuite == 0xc02f {
				fmt.Println("CipherSuite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
			} else if conn.ConnectionState().CipherSuite == 0xc02b {
				fmt.Println("CipherSuite: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256")
			} else if conn.ConnectionState().CipherSuite == 0xc030 {
				fmt.Println("CipherSuite: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")
			} else if conn.ConnectionState().CipherSuite == 0xc02c {
				fmt.Println("CipherSuite: TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384")
			} else if conn.ConnectionState().CipherSuite == 0xcca8 {
				fmt.Println("CipherSuite: TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256")
			} else if conn.ConnectionState().CipherSuite == 0xcca9 {
				fmt.Println("CipherSuite: TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256")
			}

			defer conn.Close()

			var b bytes.Buffer
			for _, cert := range conn.ConnectionState().PeerCertificates {
				err := pem.Encode(&b, &pem.Block{
					Type:  "CERTIFICATE",
					Bytes: cert.Raw,
				})
				if err != nil {
					log.Fatal(err)
				}
			}
			fmt.Println(b.String())

			for {
				reader := bufio.NewReader(os.Stdin)
				fmt.Print("Text to be sent: ")
				text, err := reader.ReadString('\n')
				if err != nil {
					fmt.Println(err)
					os.Exit(3)
				}
				fmt.Fprintf(conn, text+"\n")

				message, err := bufio.NewReader(conn).ReadString('\n')
				if err != nil {
					fmt.Println(err)
					os.Exit(3)
				}
				fmt.Print("Server response: " + message)
			}
		}
		os.Exit(0)
	}

	if (*tcpip == "server" || *tcpip == "client") && strings.ToUpper(*alg) == "SM2" && *root != "" {
		var sigcertPEM []byte
		var sigprivPEM []byte
		var enccertPEM []byte
		var encprivPEM []byte
		var rootPEM []byte

		file, err := os.Open(*key)
		if err != nil {
			log.Fatal(err)
		}
		info, err := file.Stat()
		if err != nil {
			log.Fatal(err)
		}
		buf := make([]byte, info.Size())
		file.Read(buf)

		var block *pem.Block
		block, _ = pem.Decode(buf)

		if block == nil {
			errors.New("no valid private key found")
		}

		var privKeyBytes []byte
		if IsEncryptedPEMBlock(block) {
			privKeyBytes, err = DecryptPEMBlock(block, []byte(*pwd))
			if err != nil {
				log.Fatal(err)
			}
			sigprivPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privKeyBytes})
		} else {
			sigprivPEM = buf
		}

		file, err = os.Open(*cert)
		if err != nil {
			log.Fatal(err)
		}
		info, err = file.Stat()
		if err != nil {
			log.Fatal(err)
		}
		buf = make([]byte, info.Size())
		file.Read(buf)
		sigcertPEM = buf

		if *tcpip == "server" {
			file, err = os.Open(*cakey)
			if err != nil {
				log.Fatal(err)
			}
			info, err = file.Stat()
			if err != nil {
				log.Fatal(err)
			}
			buf = make([]byte, info.Size())
			file.Read(buf)

			block, _ = pem.Decode(buf)

			if block == nil {
				errors.New("no valid private key found")
			}

			var privKeyBytes2 []byte
			if IsEncryptedPEMBlock(block) {
				privKeyBytes2, err = DecryptPEMBlock(block, []byte(*pwd))
				if err != nil {
					log.Fatal(err)
				}
				encprivPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privKeyBytes2})
			} else {
				encprivPEM = buf
			}

			file, err = os.Open(*cacert)
			if err != nil {
				log.Fatal(err)
			}
			info, err = file.Stat()
			if err != nil {
				log.Fatal(err)
			}
			buf = make([]byte, info.Size())
			file.Read(buf)
			enccertPEM = buf
		}

		file, err = os.Open(*root)
		if err != nil {
			log.Fatal(err)
		}
		info, err = file.Stat()
		if err != nil {
			log.Fatal(err)
		}
		buf = make([]byte, info.Size())
		file.Read(buf)
		rootPEM = buf

		if *tcpip == "server" {
			var sigcert tlcp.Certificate
			var enccert tlcp.Certificate
			sigcert, err = tlcp.X509KeyPair(sigcertPEM, sigprivPEM)
			enccert, err = tlcp.X509KeyPair(enccertPEM, encprivPEM)

			rootCert, err := smx509.ParseCertificatePEM([]byte(rootPEM))
			if err != nil {
				panic(err)
			}
			pool := smx509.NewCertPool()
			pool.AddCert(rootCert)

			cfg := tlcp.Config{
				Certificates: []tlcp.Certificate{sigcert, enccert},
				ClientAuth:   tlcp.RequireAndVerifyClientCert,
				ClientCAs:    pool,
				CipherSuites: []uint16{
					tlcp.ECC_SM4_GCM_SM3,
					tlcp.ECC_SM4_CBC_SM3,
				},
			}
			cfg.Rand = rand.Reader

			port := "8081"
			if *iport != "" {
				port = *iport
			}

			ln, err := tlcp.Listen("tcp", ":"+port, &cfg)
			if err != nil {
				log.Fatal(err)
			}

			fmt.Fprintln(os.Stderr, "Server(TLCP) up and listening on port "+port)

			conn, err := ln.Accept()
			if err != nil {
				log.Fatal(err)
			}
			defer ln.Close()

			tlcpcon := conn.(*tlcp.Conn)
			err = tlcpcon.Handshake()
			if err != nil {
				log.Fatalf("server: handshake failed: %s", err)
			} else {
				log.Print("server: conn: Handshake completed")
			}

			state := tlcpcon.ConnectionState()

			for _, v := range state.PeerCertificates {
				derBytes, err := smx509.MarshalPKIXPublicKey(v.PublicKey)
				if err != nil {
					log.Fatal(err)
				}
				pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: derBytes})
				fmt.Printf("%s\n", pubPEM)
			}

			go handleConnectionTLCP(conn)
			fmt.Println("Connection accepted")

			for {
				message, err := bufio.NewReader(conn).ReadString('\n')
				if err != nil {
					fmt.Println(err)
					os.Exit(3)
				}
				fmt.Print("Client response: " + string(message))

				reader := bufio.NewReader(os.Stdin)
				fmt.Print("Text to be sent: ")
				text, err := reader.ReadString('\n')
				if err != nil {
					fmt.Println(err)
					os.Exit(3)
				}
				fmt.Fprintf(conn, text+"\n")
			}
		}

		if *tcpip == "client" {
			var cert tlcp.Certificate
			cert, err = tlcp.X509KeyPair(sigcertPEM, sigprivPEM)

			rootCert, err := smx509.ParseCertificatePEM([]byte(rootPEM))
			if err != nil {
				panic(err)
			}
			pool := smx509.NewCertPool()
			pool.AddCert(rootCert)

			cfg := tlcp.Config{
				RootCAs:      pool,
				Certificates: []tlcp.Certificate{cert},
				CipherSuites: []uint16{
					tlcp.ECC_SM4_GCM_SM3,
					tlcp.ECC_SM4_CBC_SM3,
				},
			}

			ipport := "127.0.0.1:8081"
			if *iport != "" {
				ipport = *iport
			}

			conn, err := tlcp.Dial("tcp", ipport, &cfg)
			if err != nil {
				log.Fatal(err)
			}

			certa := conn.ConnectionState().PeerCertificates
			for _, cert := range certa {
				fmt.Printf("Issuer: \n\t%s\n", cert.Issuer)
				fmt.Printf("Subject: \n\t%s\n", cert.Subject)
				fmt.Printf("Expiry: %s \n", cert.NotAfter.Format("Monday, 02-Jan-06 15:04:05 MST"))
			}

			defer conn.Close()

			fmt.Println("Protocol: TLCP")
			if conn.ConnectionState().CipherSuite == 57427 {
				fmt.Println("CipherSuite: ECC_SM4_GCM_SM3")
			} else if conn.ConnectionState().CipherSuite == 57363 {
				fmt.Println("CipherSuite: ECC_SM4_CBC_SM3")
			}

			var b bytes.Buffer
			for _, cert := range conn.ConnectionState().PeerCertificates {
				err := pem.Encode(&b, &pem.Block{
					Type:  "CERTIFICATE",
					Bytes: cert.Raw,
				})
				if err != nil {
					log.Fatal(err)
				}
			}
			fmt.Println(b.String())

			for {
				reader := bufio.NewReader(os.Stdin)
				fmt.Print("Text to be sent: ")
				text, err := reader.ReadString('\n')
				if err != nil {
					fmt.Println(err)
					os.Exit(3)
				}
				fmt.Fprintf(conn, text+"\n")

				message, err := bufio.NewReader(conn).ReadString('\n')
				if err != nil {
					fmt.Println(err)
					os.Exit(3)
				}
				fmt.Print("Server response: " + message)
			}
		}
		os.Exit(0)
	}

	if (*tcpip == "server" || *tcpip == "client") && strings.ToUpper(*alg) == "SM2" && *root == "" {
		if *tcpip == "server" {
			sigcert, err := tlcp.LoadX509KeyPair(*cert, *key)
			enccert, err := tlcp.LoadX509KeyPair(*cacert, *cakey)

			cfg := tlcp.Config{
				Certificates: []tlcp.Certificate{sigcert, enccert},
				CipherSuites: []uint16{
					tlcp.ECC_SM4_GCM_SM3,
					tlcp.ECC_SM4_CBC_SM3,
				},
			}
			cfg.Rand = rand.Reader

			port := "8081"
			if *iport != "" {
				port = *iport
			}

			ln, err := tlcp.Listen("tcp", ":"+port, &cfg)
			if err != nil {
				log.Fatal(err)
			}

			fmt.Fprintln(os.Stderr, "Server(TLCP) up and listening on port "+port)

			conn, err := ln.Accept()
			if err != nil {
				log.Fatal(err)
			}
			defer ln.Close()

			tlcpcon := conn.(*tlcp.Conn)
			err = tlcpcon.Handshake()
			if err != nil {
				log.Fatalf("server: handshake failed: %s", err)
			} else {
				log.Print("server: conn: Handshake completed")
			}

			state := tlcpcon.ConnectionState()

			for _, v := range state.PeerCertificates {
				derBytes, err := smx509.MarshalPKIXPublicKey(v.PublicKey)
				if err != nil {
					log.Fatal(err)
				}
				pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: derBytes})
				fmt.Printf("%s\n", pubPEM)
			}

			go handleConnectionTLCP(conn)
			fmt.Println("Connection accepted")

			for {
				message, err := bufio.NewReader(conn).ReadString('\n')
				if err != nil {
					fmt.Println(err)
					os.Exit(3)
				}
				fmt.Print("Client response: " + string(message))

				reader := bufio.NewReader(os.Stdin)
				fmt.Print("Text to be sent: ")
				text, err := reader.ReadString('\n')
				if err != nil {
					fmt.Println(err)
					os.Exit(3)
				}
				fmt.Fprintf(conn, text+"\n")
			}
		}

		if *tcpip == "client" {
			cfg := tlcp.Config{InsecureSkipVerify: true}
			cfg.Rand = rand.Reader

			ipport := "127.0.0.1:8081"
			if *iport != "" {
				ipport = *iport
			}

			conn, err := tlcp.Dial("tcp", ipport, &cfg)
			if err != nil {
				log.Fatal(err)
			}

			certa := conn.ConnectionState().PeerCertificates
			for _, cert := range certa {
				fmt.Printf("Issuer: \n\t%s\n", cert.Issuer)
				fmt.Printf("Subject: \n\t%s\n", cert.Subject)
				fmt.Printf("Expiry: %s \n", cert.NotAfter.Format("Monday, 02-Jan-06 15:04:05 MST"))
			}

			defer conn.Close()

			fmt.Println("Protocol: TLCP")
			if conn.ConnectionState().CipherSuite == 57427 {
				fmt.Println("CipherSuite: ECC_SM4_GCM_SM3")
			} else if conn.ConnectionState().CipherSuite == 57363 {
				fmt.Println("CipherSuite: ECC_SM4_CBC_SM3")
			}

			var b bytes.Buffer
			for _, cert := range conn.ConnectionState().PeerCertificates {
				err := pem.Encode(&b, &pem.Block{
					Type:  "CERTIFICATE",
					Bytes: cert.Raw,
				})
				if err != nil {
					log.Fatal(err)
				}
			}
			fmt.Println(b.String())

			for {
				reader := bufio.NewReader(os.Stdin)
				fmt.Print("Text to be sent: ")
				text, err := reader.ReadString('\n')
				if err != nil {
					fmt.Println(err)
					os.Exit(3)
				}
				fmt.Fprintf(conn, text+"\n")

				message, err := bufio.NewReader(conn).ReadString('\n')
				if err != nil {
					fmt.Println(err)
					os.Exit(3)
				}
				fmt.Print("Server response: " + message)
			}
		}
		os.Exit(0)
	}

	if *tcpip == "ip" {
		consensus := externalip.DefaultConsensus(nil, nil)
		ip, _ := consensus.ExternalIP()
		fmt.Println(ip.String())
		os.Exit(0)
	}
}

func SignatureRSA(sourceData []byte) ([]byte, error) {
	msg := []byte("")
	file, err := os.Open(*key)
	if err != nil {
		return msg, err
	}
	info, err := file.Stat()
	if err != nil {
		return msg, err
	}
	buf := make([]byte, info.Size())
	file.Read(buf)

	var block *pem.Block
	block, _ = pem.Decode(buf)

	if block == nil {
		return nil, errors.New("no valid private key found")
	}
	var privateKey *rsa.PrivateKey
	var privKeyBytes []byte
	if IsEncryptedPEMBlock(block) {
		privKeyBytes, err = DecryptPEMBlock(block, []byte(*pwd))
		if err != nil {
			return nil, errors.New("could not decrypt private key")
		}
		privateKey, err = x509.ParsePKCS1PrivateKey(privKeyBytes)
		if err != nil {
			return nil, fmt.Errorf("could not parse DER encoded key: %v", err)
		}
	} else {
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return msg, err
		}
	}

	var myHash hash.Hash
	if *md == "md5" {
		myHash = md5.New()
	} else if *md == "sha224" {
		myHash = sha256.New224()
	} else if *md == "sha256" {
		myHash = sha256.New()
	} else if *md == "sha384" {
		myHash = sha512.New384()
	} else if *md == "sha512" {
		myHash = sha512.New()
	} else if *md == "sha1" {
		myHash = sha1.New()
	} else if *md == "rmd160" {
		myHash = ripemd160.New()
	}

	myHash.Write(sourceData)
	hashRes := myHash.Sum(nil)
	var res []byte
	if *md == "md5" {
		res, err = rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.MD5, hashRes)
		if err != nil {
			return msg, err
		}
	} else if *md == "rmd160" {
		res, err = rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.RIPEMD160, hashRes)
		if err != nil {
			return msg, err
		}
	} else if *md == "sha1" {
		res, err = rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA1, hashRes)
		if err != nil {
			return msg, err
		}
	} else if *md == "sha224" {
		res, err = rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA224, hashRes)
		if err != nil {
			return msg, err
		}
	} else if *md == "sha256" {
		res, err = rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashRes)
		if err != nil {
			return msg, err
		}
	} else if *md == "sha384" {
		res, err = rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA384, hashRes)
		if err != nil {
			return msg, err
		}
	} else if *md == "sha512" {
		res, err = rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA512, hashRes)
		if err != nil {
			return msg, err
		}
	}
	defer file.Close()
	return res, nil
}

func VerifyRSA(sourceData, signedData []byte) error {
	file, err := os.Open(*key)
	if err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil {
		return err
	}
	buf := make([]byte, info.Size())
	file.Read(buf)
	block, _ := pem.Decode(buf)
	publicInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}
	publicKey := publicInterface.(*rsa.PublicKey)
	var mySha hash.Hash
	if *md == "md5" {
		mySha = md5.New()
	} else if *md == "sha224" {
		mySha = sha256.New224()
	} else if *md == "sha256" {
		mySha = sha256.New()
	} else if *md == "sha384" {
		mySha = sha512.New384()
	} else if *md == "sha512" {
		mySha = sha512.New()
	} else if *md == "sha1" {
		mySha = sha1.New()
	} else if *md == "rmd160" {
		mySha = ripemd160.New()
	}
	mySha.Write(sourceData)
	res := mySha.Sum(nil)
	if *md == "md5" {
		err = rsa.VerifyPKCS1v15(publicKey, crypto.MD5, res, signedData)
		if err != nil {
			return err
		}
	} else if *md == "rmd160" {
		err = rsa.VerifyPKCS1v15(publicKey, crypto.RIPEMD160, res, signedData)
		if err != nil {
			return err
		}
	} else if *md == "sha1" {
		err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA1, res, signedData)
		if err != nil {
			return err
		}
	} else if *md == "sha224" {
		err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA224, res, signedData)
		if err != nil {
			return err
		}
	} else if *md == "sha256" {
		err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, res, signedData)
		if err != nil {
			return err
		}
	} else if *md == "sha384" {
		err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA384, res, signedData)
		if err != nil {
			return err
		}
	} else if *md == "sha512" {
		err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA512, res, signedData)
		if err != nil {
			return err
		}
	}
	defer file.Close()
	return nil
}

func GenerateRsaKey(bit int) error {
	private, err := rsa.GenerateKey(rand.Reader, bit)
	if err != nil {
		return err
	}
	privateStream := x509.MarshalPKCS1PrivateKey(private)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateStream,
	}
	file, err := os.Create(*priv)
	if err != nil {
		return err
	}
	if *pwd != "" {
		if *cph == "aes128" {
			block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherAES128)
		} else if *cph == "aes192" {
			block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherAES192)
		} else if *cph == "aes" || *cph == "aes256" {
			block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherAES256)
		} else if *cph == "3des" {
			block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipher3DES)
		} else if *cph == "des" {
			block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherDES)
		} else if *cph == "sm4" {
			block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherSM4)
		} else if *cph == "seed" {
			block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherSEED)
		} else if *cph == "gost" {
			block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherGOST)
		} else if *cph == "idea" {
			block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherIDEA)
		} else if *cph == "camellia128" {
			block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherCAMELLIA128)
		} else if *cph == "camellia192" {
			block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherCAMELLIA192)
		} else if *cph == "camellia" || *cph == "camellia256" {
			block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherCAMELLIA256)
		} else if *cph == "aria128" {
			block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherARIA128)
		} else if *cph == "aria192" {
			block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherARIA192)
		} else if *cph == "aria" || *cph == "aria256" {
			block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherARIA256)
		} else if *cph == "lea128" {
			block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherLEA128)
		} else if *cph == "lea192" {
			block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherLEA192)
		} else if *cph == "lea" || *cph == "lea256" {
			block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherLEA256)
		} else if *cph == "cast5" {
			block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherCAST)
		} else if *cph == "anubis" {
			block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherANUBIS)
		} else if *cph == "serpent128" {
			block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherSERPENT128)
		} else if *cph == "serpent192" {
			block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherSERPENT192)
		} else if *cph == "serpent" || *cph == "serpent256" {
			block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherSERPENT256)
		} else if *cph == "rc6128" {
			block, _ = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherRC6128)
		} else if *cph == "rc6192" {
			block, _ = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherRC6192)
		} else if *cph == "rc6" || *cph == "rc6256" {
			block, _ = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherRC6256)
		}
		if err != nil {
			return err
		}
		err = pem.Encode(file, block)
		if err != nil {
			return err
		}
	} else {
		err = pem.Encode(file, block)
		if err != nil {
			return err
		}
	}
	public := private.PublicKey
	publicStream, err := x509.MarshalPKIXPublicKey(&public)
	if err != nil {
		return err
	}

	pubblock := pem.Block{Type: "PUBLIC KEY", Bytes: publicStream}
	pubfile, err := os.Create(*pub)
	if err != nil {
		return err
	}
	err = pem.Encode(pubfile, &pubblock)
	if err != nil {
		return err
	}

	absPrivPath, err := filepath.Abs(*priv)
	if err != nil {
		log.Fatal("Failed to get absolute path for private key:", err)
	}
	absPubPath, err := filepath.Abs(*pub)
	if err != nil {
		log.Fatal("Failed to get absolute path for public key:", err)
	}
	println("Private key saved to:", absPrivPath)
	println("Public key saved to:", absPubPath)

	file, err = os.Open(*pub)
	if err != nil {
		log.Fatal(err)
	}
	info, err := file.Stat()
	if err != nil {
		log.Fatal(err)
	}
	buf := make([]byte, info.Size())
	file.Read(buf)
	fingerprint := calculateFingerprint(buf)
	print("Fingerprint: ")
	println(fingerprint)
	printKeyDetails(&pubblock)
	randomArt := randomart.FromString(string(buf))
	println(randomArt)
	return nil
}

func EncodeSM2PrivateKey(key *sm2.PrivateKey) ([]byte, error) {
	derKey, err := smx509.MarshalSM2PrivateKey(key)
	if err != nil {
		return nil, err
	}
	keyBlock := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: derKey,
	}
	if *pwd != "" {
		if *cph == "aes128" {
			keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, keyBlock.Bytes, []byte(*pwd), PEMCipherAES128)
		} else if *cph == "aes192" {
			keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, keyBlock.Bytes, []byte(*pwd), PEMCipherAES192)
		} else if *cph == "aes" || *cph == "aes256" {
			keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, keyBlock.Bytes, []byte(*pwd), PEMCipherAES256)
		} else if *cph == "3des" {
			keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, keyBlock.Bytes, []byte(*pwd), PEMCipher3DES)
		} else if *cph == "des" {
			keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, keyBlock.Bytes, []byte(*pwd), PEMCipherDES)
		} else if *cph == "sm4" {
			keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, keyBlock.Bytes, []byte(*pwd), PEMCipherSM4)
		} else if *cph == "seed" {
			keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, keyBlock.Bytes, []byte(*pwd), PEMCipherSEED)
		} else if *cph == "gost" {
			keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, keyBlock.Bytes, []byte(*pwd), PEMCipherGOST)
		} else if *cph == "idea" {
			keyBlock, err = EncryptPEMBlock(rand.Reader, keyBlock.Type, keyBlock.Bytes, []byte(*pwd), PEMCipherIDEA)
		} else if *cph == "camellia128" {
			keyBlock, err = EncryptPEMBlock(rand.Reader, keyBlock.Type, keyBlock.Bytes, []byte(*pwd), PEMCipherCAMELLIA128)
		} else if *cph == "camellia192" {
			keyBlock, err = EncryptPEMBlock(rand.Reader, keyBlock.Type, keyBlock.Bytes, []byte(*pwd), PEMCipherCAMELLIA192)
		} else if *cph == "camellia" || *cph == "camellia256" {
			keyBlock, err = EncryptPEMBlock(rand.Reader, keyBlock.Type, keyBlock.Bytes, []byte(*pwd), PEMCipherCAMELLIA256)
		} else if *cph == "aria128" {
			keyBlock, err = EncryptPEMBlock(rand.Reader, keyBlock.Type, keyBlock.Bytes, []byte(*pwd), PEMCipherARIA128)
		} else if *cph == "aria192" {
			keyBlock, err = EncryptPEMBlock(rand.Reader, keyBlock.Type, keyBlock.Bytes, []byte(*pwd), PEMCipherARIA192)
		} else if *cph == "aria" || *cph == "aria256" {
			keyBlock, err = EncryptPEMBlock(rand.Reader, keyBlock.Type, keyBlock.Bytes, []byte(*pwd), PEMCipherARIA256)
		} else if *cph == "lea128" {
			keyBlock, err = EncryptPEMBlock(rand.Reader, keyBlock.Type, keyBlock.Bytes, []byte(*pwd), PEMCipherLEA128)
		} else if *cph == "lea192" {
			keyBlock, err = EncryptPEMBlock(rand.Reader, keyBlock.Type, keyBlock.Bytes, []byte(*pwd), PEMCipherLEA192)
		} else if *cph == "lea" || *cph == "lea256" {
			keyBlock, err = EncryptPEMBlock(rand.Reader, keyBlock.Type, keyBlock.Bytes, []byte(*pwd), PEMCipherLEA256)
		} else if *cph == "cast5" {
			keyBlock, err = EncryptPEMBlock(rand.Reader, keyBlock.Type, keyBlock.Bytes, []byte(*pwd), PEMCipherCAST)
		} else if *cph == "anubis" {
			keyBlock, err = EncryptPEMBlock(rand.Reader, keyBlock.Type, keyBlock.Bytes, []byte(*pwd), PEMCipherANUBIS)
		} else if *cph == "serpent128" {
			keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, keyBlock.Bytes, []byte(*pwd), PEMCipherSERPENT128)
		} else if *cph == "serpent192" {
			keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, keyBlock.Bytes, []byte(*pwd), PEMCipherSERPENT192)
		} else if *cph == "serpent" || *cph == "serpent256" {
			keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, keyBlock.Bytes, []byte(*pwd), PEMCipherSERPENT256)
		} else if *cph == "rc6128" {
			keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, keyBlock.Bytes, []byte(*pwd), PEMCipherRC6128)
		} else if *cph == "rc6192" {
			keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, keyBlock.Bytes, []byte(*pwd), PEMCipherRC6192)
		} else if *cph == "rc6" || *cph == "rc6256" {
			keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, keyBlock.Bytes, []byte(*pwd), PEMCipherRC6256)
		}
		return pem.EncodeToMemory(keyBlock), nil
	} else {
		return pem.EncodeToMemory(keyBlock), nil
	}
}

func DecodeSM2PrivateKey(encodedKey []byte) (*sm2.PrivateKey, error) {
	var skippedTypes []string
	var block *pem.Block
	for {
		block, encodedKey = pem.Decode(encodedKey)
		if block == nil {
			return nil, fmt.Errorf("failed to find EC PRIVATE KEY in PEM data after skipping types %v", skippedTypes)
		}

		if block.Type == "EC PRIVATE KEY" {
			break
		} else {
			skippedTypes = append(skippedTypes, block.Type)
			continue
		}
	}
	var privKey *sm2.PrivateKey
	var privKeyBytes []byte
	var err error
	if IsEncryptedPEMBlock(block) {
		privKeyBytes, err = DecryptPEMBlock(block, []byte(*pwd))
		if err != nil {
			return nil, errors.New("could not decrypt private key")
		}
		privKey, _ = smx509.ParseSM2PrivateKey(privKeyBytes)
	} else {
		privKey, _ = smx509.ParseSM2PrivateKey(block.Bytes)
	}
	return privKey, nil
}

func EncodePrivateKey(key *ecdsa.PrivateKey) ([]byte, error) {
	derKey, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	keyBlock := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: derKey,
	}
	if *pwd != "" {
		if *cph == "aes128" {
			keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, keyBlock.Bytes, []byte(*pwd), PEMCipherAES128)
		} else if *cph == "aes192" {
			keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, keyBlock.Bytes, []byte(*pwd), PEMCipherAES192)
		} else if *cph == "aes" || *cph == "aes256" {
			keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, keyBlock.Bytes, []byte(*pwd), PEMCipherAES256)
		} else if *cph == "3des" {
			keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, keyBlock.Bytes, []byte(*pwd), PEMCipher3DES)
		} else if *cph == "des" {
			keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, keyBlock.Bytes, []byte(*pwd), PEMCipherDES)
		} else if *cph == "sm4" {
			keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, keyBlock.Bytes, []byte(*pwd), PEMCipherSM4)
		} else if *cph == "seed" {
			keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, keyBlock.Bytes, []byte(*pwd), PEMCipherSEED)
		} else if *cph == "gost" {
			keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, keyBlock.Bytes, []byte(*pwd), PEMCipherGOST)
		} else if *cph == "idea" {
			keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, keyBlock.Bytes, []byte(*pwd), PEMCipherIDEA)
		} else if *cph == "camellia128" {
			keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, keyBlock.Bytes, []byte(*pwd), PEMCipherCAMELLIA128)
		} else if *cph == "camellia192" {
			keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, keyBlock.Bytes, []byte(*pwd), PEMCipherCAMELLIA192)
		} else if *cph == "camellia256" || *cph == "camellia" {
			keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, keyBlock.Bytes, []byte(*pwd), PEMCipherCAMELLIA256)
		} else if *cph == "aria128" {
			keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, keyBlock.Bytes, []byte(*pwd), PEMCipherARIA128)
		} else if *cph == "aria192" {
			keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, keyBlock.Bytes, []byte(*pwd), PEMCipherARIA192)
		} else if *cph == "aria" || *cph == "aria256" {
			keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, keyBlock.Bytes, []byte(*pwd), PEMCipherARIA256)
		} else if *cph == "lea128" {
			keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, keyBlock.Bytes, []byte(*pwd), PEMCipherLEA128)
		} else if *cph == "lea192" {
			keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, keyBlock.Bytes, []byte(*pwd), PEMCipherLEA192)
		} else if *cph == "lea" || *cph == "lea256" {
			keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, keyBlock.Bytes, []byte(*pwd), PEMCipherLEA256)
		} else if *cph == "cast5" {
			keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, keyBlock.Bytes, []byte(*pwd), PEMCipherCAST)
		} else if *cph == "anubis" {
			keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, keyBlock.Bytes, []byte(*pwd), PEMCipherANUBIS)
		} else if *cph == "serpent128" {
			keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, keyBlock.Bytes, []byte(*pwd), PEMCipherSERPENT128)
		} else if *cph == "serpent192" {
			keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, keyBlock.Bytes, []byte(*pwd), PEMCipherSERPENT192)
		} else if *cph == "serpent" || *cph == "serpent256" {
			keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, keyBlock.Bytes, []byte(*pwd), PEMCipherSERPENT256)
		} else if *cph == "rc6128" {
			keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, keyBlock.Bytes, []byte(*pwd), PEMCipherRC6128)
		} else if *cph == "rc6192" {
			keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, keyBlock.Bytes, []byte(*pwd), PEMCipherRC6192)
		} else if *cph == "rc6" || *cph == "rc6256" {
			keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, keyBlock.Bytes, []byte(*pwd), PEMCipherRC6256)
		}
		return pem.EncodeToMemory(keyBlock), nil
	} else {
		return pem.EncodeToMemory(keyBlock), nil
	}
}

func DecodePrivateKey(encodedKey []byte) (*ecdsa.PrivateKey, error) {
	var skippedTypes []string
	var block *pem.Block
	for {
		block, encodedKey = pem.Decode(encodedKey)
		if block == nil {
			return nil, fmt.Errorf("failed to find EC PRIVATE KEY in PEM data after skipping types %v", skippedTypes)
		}

		if block.Type == "EC PRIVATE KEY" {
			break
		} else {
			skippedTypes = append(skippedTypes, block.Type)
			continue
		}
	}
	var privKey *ecdsa.PrivateKey
	var privKeyBytes []byte
	var err error
	if IsEncryptedPEMBlock(block) {
		privKeyBytes, err = DecryptPEMBlock(block, []byte(*pwd))
		if err != nil {
			return nil, errors.New("could not decrypt private key")
		}
		privKey, _ = smx509.ParseECPrivateKey(privKeyBytes)
	} else {
		privKey, _ = smx509.ParseECPrivateKey(block.Bytes)
	}
	return privKey, nil
}

func EncodePublicKey(key *ecdsa.PublicKey) ([]byte, error) {
	derBytes, err := smx509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, err
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derBytes,
	}
	return pem.EncodeToMemory(block), nil
}

func DecodePublicKey(encodedKey []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(encodedKey)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("marshal: could not decode PEM block type %s", block.Type)

	}
	public, err := smx509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ecdsaPub, ok := public.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("marshal: data was not an ECDSA public key")
	}
	return ecdsaPub, nil
}

func Hkdf(master, salt, info []byte) ([128]byte, error) {
	var myHash func() hash.Hash
	if *md == "sha256" {
		myHash = sha256.New
	} else if *md == "sha512" {
		myHash = sha512.New
	} else if *md == "sha512-256" {
		myHash = sha512.New512_256
	} else if *md == "sha384" {
		myHash = sha512.New384
	} else if *md == "sha1" {
		myHash = sha1.New
	} else if *md == "rmd160" {
		myHash = ripemd160.New
	} else if *md == "rmd128" {
		myHash = ripemd.New128
	} else if *md == "rmd256" {
		myHash = ripemd.New256
	} else if *md == "rmd320" {
		myHash = ripemd.New320
	} else if *md == "sha3-256" {
		myHash = sha3.New256
	} else if *md == "sha3-512" {
		myHash = sha3.New512
	} else if *md == "keccak" || *md == "keccak256" {
		myHash = sha3.NewLegacyKeccak256
	} else if *md == "keccak512" {
		myHash = sha3.NewLegacyKeccak512
	} else if *md == "shake128" {
		myHash = func() hash.Hash {
			return sha3.NewShake128()
		}
	} else if *md == "shake256" {
		myHash = func() hash.Hash {
			return sha3.NewShake256()
		}
	} else if *md == "lsh224" || *md == "lsh256-224" {
		myHash = lsh256.New224
	} else if *md == "lsh" || *md == "lsh256" || *md == "lsh256-256" {
		myHash = lsh256.New
	} else if *md == "lsh512-224" {
		myHash = lsh512.New224
	} else if *md == "lsh512-256" {
		myHash = lsh512.New256
	} else if *md == "lsh384" || *md == "lsh512-384" {
		myHash = lsh512.New384
	} else if *md == "lsh512" {
		myHash = lsh512.New
	} else if *md == "has160" {
		myHash = has160.New
	} else if *md == "whirlpool" {
		myHash = whirlpool.New
	} else if *md == "blake2b256" {
		myHash = crypto.BLAKE2b_256.New
	} else if *md == "blake2b512" {
		myHash = crypto.BLAKE2b_512.New
	} else if *md == "blake2s256" {
		myHash = crypto.BLAKE2s_256.New
	} else if *md == "blake3" {
		myHash = func() hash.Hash {
			return blake3.New()
		}
	} else if *md == "md4" {
		myHash = md4.New
	} else if *md == "md5" {
		myHash = md5.New
	} else if *md == "gost94" {
		myHash = func() hash.Hash {
			return gost341194.New(&gost28147.SboxIdGostR341194CryptoProParamSet)
		}
	} else if *md == "streebog" || *md == "streebog256" {
		myHash = gost34112012256.New
	} else if *md == "streebog512" {
		myHash = gost34112012512.New
	} else if *md == "sm3" {
		myHash = sm3.New
	} else if *md == "cubehash" {
		myHash = cubehash.New
	} else if *md == "xoodyak" || *md == "xhash" {
		myHash = xoodyak.NewXoodyakHash
	} else if *md == "skein" || *md == "skein256" {
		myHash = func() hash.Hash {
			return skein.New256(nil)
		}
	} else if *md == "skein512" {
		myHash = func() hash.Hash {
			return skein.New512(nil)
		}
	} else if *md == "jh" {
		myHash = jh.New256
	} else if *md == "groestl" {
		myHash = groestl.New256
	}
	hkdf := hkdf.New(myHash, master, salt, info)

	key := make([]byte, *length/8)
	_, err := io.ReadFull(hkdf, key)

	var result [128]byte
	copy(result[:], key)

	return result, err
}

func Scrypt(password, salt []byte, N, r, p, keyLen int) ([]byte, error) {
	if N <= 1 || N&(N-1) != 0 {
		return nil, errors.New("scrypt: N must be > 1 and a power of 2")
	}
	if uint64(r)*uint64(p) >= 1<<30 || r > maxInt/128/p || r > maxInt/256 || N > maxInt/128/r {
		return nil, errors.New("scrypt: parameters are too large")
	}

	var myHash func() hash.Hash
	if *md == "sha256" {
		myHash = sha256.New
	} else if *md == "sha512" {
		myHash = sha512.New
	} else if *md == "sha512-256" {
		myHash = sha512.New512_256
	} else if *md == "sha384" {
		myHash = sha512.New384
	} else if *md == "sha1" {
		myHash = sha1.New
	} else if *md == "rmd160" {
		myHash = ripemd160.New
	} else if *md == "rmd128" {
		myHash = ripemd.New128
	} else if *md == "rmd256" {
		myHash = ripemd.New256
	} else if *md == "rmd320" {
		myHash = ripemd.New320
	} else if *md == "sha3-256" {
		myHash = sha3.New256
	} else if *md == "sha3-512" {
		myHash = sha3.New512
	} else if *md == "keccak" || *md == "keccak256" {
		myHash = sha3.NewLegacyKeccak256
	} else if *md == "keccak512" {
		myHash = sha3.NewLegacyKeccak512
	} else if *md == "shake128" {
		myHash = func() hash.Hash {
			return sha3.NewShake128()
		}
	} else if *md == "shake256" {
		myHash = func() hash.Hash {
			return sha3.NewShake256()
		}
	} else if *md == "lsh224" || *md == "lsh256-224" {
		myHash = lsh256.New224
	} else if *md == "lsh" || *md == "lsh256" || *md == "lsh256-256" {
		myHash = lsh256.New
	} else if *md == "lsh512-224" {
		myHash = lsh512.New224
	} else if *md == "lsh512-256" {
		myHash = lsh512.New256
	} else if *md == "lsh384" || *md == "lsh512-384" {
		myHash = lsh512.New384
	} else if *md == "lsh512" {
		myHash = lsh512.New
	} else if *md == "has160" {
		myHash = has160.New
	} else if *md == "whirlpool" {
		myHash = whirlpool.New
	} else if *md == "blake2b256" {
		myHash = crypto.BLAKE2b_256.New
	} else if *md == "blake2b512" {
		myHash = crypto.BLAKE2b_512.New
	} else if *md == "blake2s256" {
		myHash = crypto.BLAKE2s_256.New
	} else if *md == "blake3" {
		myHash = func() hash.Hash {
			return blake3.New()
		}
	} else if *md == "md4" {
		myHash = md4.New
	} else if *md == "md5" {
		myHash = md5.New
	} else if *md == "gost94" {
		myHash = func() hash.Hash {
			return gost341194.New(&gost28147.SboxIdGostR341194CryptoProParamSet)
		}
	} else if *md == "streebog" || *md == "streebog256" {
		myHash = gost34112012256.New
	} else if *md == "streebog512" {
		myHash = gost34112012512.New
	} else if *md == "sm3" {
		myHash = sm3.New
	} else if *md == "cubehash" {
		myHash = cubehash.New
	} else if *md == "xoodyak" || *md == "xhash" {
		myHash = xoodyak.NewXoodyakHash
	} else if *md == "skein" || *md == "skein256" {
		myHash = func() hash.Hash {
			return skein.New256(nil)
		}
	} else if *md == "skein512" {
		myHash = func() hash.Hash {
			return skein.New512(nil)
		}
	} else if *md == "jh" {
		myHash = jh.New256
	} else if *md == "groestl" {
		myHash = groestl.New256
	}

	xy := make([]uint32, 64*r)
	v := make([]uint32, 32*N*r)
	b := pbkdf2.Key(password, salt, 1, p*128*r, myHash)

	for i := 0; i < p; i++ {
		smix(b[i*128*r:], r, N, v, xy)
	}

	return pbkdf2.Key(password, b, 1, keyLen, myHash), nil
}

const maxInt = int(^uint(0) >> 1)

func blockCopy(dst, src []uint32, n int) {
	copy(dst, src[:n])
}

func blockXOR(dst, src []uint32, n int) {
	for i, v := range src[:n] {
		dst[i] ^= v
	}
}

func salsaXOR(tmp *[16]uint32, in, out []uint32) {
	w0 := tmp[0] ^ in[0]
	w1 := tmp[1] ^ in[1]
	w2 := tmp[2] ^ in[2]
	w3 := tmp[3] ^ in[3]
	w4 := tmp[4] ^ in[4]
	w5 := tmp[5] ^ in[5]
	w6 := tmp[6] ^ in[6]
	w7 := tmp[7] ^ in[7]
	w8 := tmp[8] ^ in[8]
	w9 := tmp[9] ^ in[9]
	w10 := tmp[10] ^ in[10]
	w11 := tmp[11] ^ in[11]
	w12 := tmp[12] ^ in[12]
	w13 := tmp[13] ^ in[13]
	w14 := tmp[14] ^ in[14]
	w15 := tmp[15] ^ in[15]

	x0, x1, x2, x3, x4, x5, x6, x7, x8 := w0, w1, w2, w3, w4, w5, w6, w7, w8
	x9, x10, x11, x12, x13, x14, x15 := w9, w10, w11, w12, w13, w14, w15

	for i := 0; i < 8; i += 2 {
		x4 ^= bits.RotateLeft32(x0+x12, 7)
		x8 ^= bits.RotateLeft32(x4+x0, 9)
		x12 ^= bits.RotateLeft32(x8+x4, 13)
		x0 ^= bits.RotateLeft32(x12+x8, 18)

		x9 ^= bits.RotateLeft32(x5+x1, 7)
		x13 ^= bits.RotateLeft32(x9+x5, 9)
		x1 ^= bits.RotateLeft32(x13+x9, 13)
		x5 ^= bits.RotateLeft32(x1+x13, 18)

		x14 ^= bits.RotateLeft32(x10+x6, 7)
		x2 ^= bits.RotateLeft32(x14+x10, 9)
		x6 ^= bits.RotateLeft32(x2+x14, 13)
		x10 ^= bits.RotateLeft32(x6+x2, 18)

		x3 ^= bits.RotateLeft32(x15+x11, 7)
		x7 ^= bits.RotateLeft32(x3+x15, 9)
		x11 ^= bits.RotateLeft32(x7+x3, 13)
		x15 ^= bits.RotateLeft32(x11+x7, 18)

		x1 ^= bits.RotateLeft32(x0+x3, 7)
		x2 ^= bits.RotateLeft32(x1+x0, 9)
		x3 ^= bits.RotateLeft32(x2+x1, 13)
		x0 ^= bits.RotateLeft32(x3+x2, 18)

		x6 ^= bits.RotateLeft32(x5+x4, 7)
		x7 ^= bits.RotateLeft32(x6+x5, 9)
		x4 ^= bits.RotateLeft32(x7+x6, 13)
		x5 ^= bits.RotateLeft32(x4+x7, 18)

		x11 ^= bits.RotateLeft32(x10+x9, 7)
		x8 ^= bits.RotateLeft32(x11+x10, 9)
		x9 ^= bits.RotateLeft32(x8+x11, 13)
		x10 ^= bits.RotateLeft32(x9+x8, 18)

		x12 ^= bits.RotateLeft32(x15+x14, 7)
		x13 ^= bits.RotateLeft32(x12+x15, 9)
		x14 ^= bits.RotateLeft32(x13+x12, 13)
		x15 ^= bits.RotateLeft32(x14+x13, 18)
	}
	x0 += w0
	x1 += w1
	x2 += w2
	x3 += w3
	x4 += w4
	x5 += w5
	x6 += w6
	x7 += w7
	x8 += w8
	x9 += w9
	x10 += w10
	x11 += w11
	x12 += w12
	x13 += w13
	x14 += w14
	x15 += w15

	out[0], tmp[0] = x0, x0
	out[1], tmp[1] = x1, x1
	out[2], tmp[2] = x2, x2
	out[3], tmp[3] = x3, x3
	out[4], tmp[4] = x4, x4
	out[5], tmp[5] = x5, x5
	out[6], tmp[6] = x6, x6
	out[7], tmp[7] = x7, x7
	out[8], tmp[8] = x8, x8
	out[9], tmp[9] = x9, x9
	out[10], tmp[10] = x10, x10
	out[11], tmp[11] = x11, x11
	out[12], tmp[12] = x12, x12
	out[13], tmp[13] = x13, x13
	out[14], tmp[14] = x14, x14
	out[15], tmp[15] = x15, x15
}

func blockMix(tmp *[16]uint32, in, out []uint32, r int) {
	blockCopy(tmp[:], in[(2*r-1)*16:], 16)
	for i := 0; i < 2*r; i += 2 {
		salsaXOR(tmp, in[i*16:], out[i*8:])
		salsaXOR(tmp, in[i*16+16:], out[i*8+r*16:])
	}
}

func integer(b []uint32, r int) uint64 {
	j := (2*r - 1) * 16
	return uint64(b[j]) | uint64(b[j+1])<<32
}

func smix(b []byte, r, N int, v, xy []uint32) {
	var tmp [16]uint32
	R := 32 * r
	x := xy
	y := xy[R:]

	j := 0
	for i := 0; i < R; i++ {
		x[i] = binary.LittleEndian.Uint32(b[j:])
		j += 4
	}
	for i := 0; i < N; i += 2 {
		blockCopy(v[i*R:], x, R)
		blockMix(&tmp, x, y, r)

		blockCopy(v[(i+1)*R:], y, R)
		blockMix(&tmp, y, x, r)
	}
	for i := 0; i < N; i += 2 {
		j := int(integer(x, r) & uint64(N-1))
		blockXOR(x, v[j*R:], R)
		blockMix(&tmp, x, y, r)

		j = int(integer(y, r) & uint64(N-1))
		blockXOR(y, v[j*R:], R)
		blockMix(&tmp, y, x, r)
	}
	j = 0
	for _, v := range x[:R] {
		binary.LittleEndian.PutUint32(b[j:], v)
		j += 4
	}
}

func PfxGen() error {
	var certPEM []byte
	file, err := os.Open(*cert)
	if err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil {
		return err
	}
	buf := make([]byte, info.Size())
	file.Read(buf)
	certPEM = buf
	var certPemBlock, _ = pem.Decode([]byte(certPEM))
	var certificate, _ = smx509.ParseCertificate(certPemBlock.Bytes)

	var privPEM []byte
	file, err = os.Open(*key)
	if err != nil {
		return err
	}
	info, err = file.Stat()
	if err != nil {
		return err
	}
	buf = make([]byte, info.Size())
	file.Read(buf)
	var block *pem.Block
	block, _ = pem.Decode(buf)
	if block == nil {
		errors.New("no valid private key found")
	}
	var privKeyBytes []byte

	if IsEncryptedPEMBlock(block) {
		privKeyBytes, err = DecryptPEMBlock(block, []byte(*pwd))
		if err != nil {
			return err
		}
		privPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privKeyBytes})
	} else {
		privPEM = buf
	}
	var privateKeyPemBlock, _ = pem.Decode([]byte(privPEM))

	scanner := bufio.NewScanner(os.Stdin)
	print("PFX Certificate Passphrase: ")
	scanner.Scan()
	psd := scanner.Text()

	var pfxBytes []byte
	if strings.ToUpper(*alg) == "RSA" {
		var privKey, _ = smx509.ParsePKCS1PrivateKey(privateKeyPemBlock.Bytes)
		if err := privKey.Validate(); err != nil {
			panic("error validating the private key: " + err.Error())
		}
		pfxBytes, err = pkcs12.Encode(rand.Reader, privKey, certificate, []*smx509.Certificate{}, psd)
	} else if strings.ToUpper(*alg) == "EC" || strings.ToUpper(*alg) == "ECDSA" {
		var privKey, _ = smx509.ParseECPrivateKey(privateKeyPemBlock.Bytes)
		pfxBytes, err = pkcs12.Encode(rand.Reader, privKey, certificate, []*smx509.Certificate{}, psd)
	} else if strings.ToUpper(*alg) == "SM2" {
		var privKey, _ = smx509.ParseSM2PrivateKey(privateKeyPemBlock.Bytes)
		pfxBytes, err = pkcs12.Encode(rand.Reader, privKey, certificate, []*smx509.Certificate{}, psd)
	}

	if err != nil {
		return err
	}
	if _, _, err := pkcs12.Decode(pfxBytes, psd); err != nil {
		return err
	}

	certname := strings.Split(*cert, ".")
	if err := ioutil.WriteFile(
		certname[0]+".pfx",
		pfxBytes,
		os.ModePerm,
	); err != nil {
		return err
	}
	fmt.Printf("The certificate has been generated: %s\n", certname[0]+".pfx")
	return nil
}

func PfxParse() error {
	pfxBytes, err := os.ReadFile(*cert)
	if err != nil {
		return err
	}
	_, certificate, err := pkcs12.Decode(pfxBytes, *pwd)
	if err != nil {
		return err
	}

	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	fmt.Printf("%s", pemCert)

	PEM, err := pkcs12.ToPEM(pfxBytes, *pwd)
	if err != nil {
		return err
	}

	_, err = smx509.ParsePKCS1PrivateKey(PEM[1].Bytes)
	if err != nil {
		ecdsaPublicKey := certificate.PublicKey.(*ecdsa.PublicKey)
		publicStream, err := smx509.MarshalPKIXPublicKey(ecdsaPublicKey)
		if err != nil {
			return err
		}
		pubblock := pem.Block{Type: "PUBLIC KEY", Bytes: publicStream}
		fmt.Printf("%s", pem.EncodeToMemory(&pubblock))
	} else {
		rsaPublicKey := certificate.PublicKey.(*rsa.PublicKey)
		publicStream, err := smx509.MarshalPKIXPublicKey(rsaPublicKey)
		if err != nil {
			return err
		}
		pubblock := pem.Block{Type: "PUBLIC KEY", Bytes: publicStream}
		fmt.Printf("%s", pem.EncodeToMemory(&pubblock))
	}

	fmt.Printf("Expiry:         %s \n", certificate.NotAfter.Format("Monday, 02-Jan-06 15:04:05 MST"))
	fmt.Printf("Common Name:    %s \n", certificate.Subject.CommonName)
	fmt.Printf("Issuer:         %s \n", certificate.Issuer)
	fmt.Printf("Subject:        %s \n", certificate.Subject)
	fmt.Printf("EmailAddresses: %s \n", certificate.EmailAddresses)
	fmt.Printf("SerialNumber:   %x \n", certificate.SerialNumber)
	fmt.Printf("AuthorityKeyId: %x \n", certificate.AuthorityKeyId)

	print("Enter PEM Passphrase: ")
	pass, _ := gopass.GetPasswd()
	psd := string(pass)

	_, err = smx509.ParsePKCS1PrivateKey(PEM[1].Bytes)
	if err != nil {
		keyBlock := &pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: PEM[1].Bytes,
		}
		if psd != "" {
			if *cph == "aes128" {
				keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, PEM[1].Bytes, []byte(psd), PEMCipherAES128)
			} else if *cph == "aes192" {
				keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, PEM[1].Bytes, []byte(psd), PEMCipherAES192)
			} else if *cph == "aes" || *cph == "aes256" {
				keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, PEM[1].Bytes, []byte(psd), PEMCipherAES256)
			} else if *cph == "3des" {
				keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, PEM[1].Bytes, []byte(psd), PEMCipher3DES)
			} else if *cph == "des" {
				keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, PEM[1].Bytes, []byte(psd), PEMCipherDES)
			} else if *cph == "sm4" {
				keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, PEM[1].Bytes, []byte(psd), PEMCipherSM4)
			} else if *cph == "seed" {
				keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, PEM[1].Bytes, []byte(psd), PEMCipherSEED)
			} else if *cph == "gost" {
				keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, PEM[1].Bytes, []byte(psd), PEMCipherGOST)
			} else if *cph == "idea" {
				keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, PEM[1].Bytes, []byte(psd), PEMCipherIDEA)
			} else if *cph == "camellia128" {
				keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, PEM[1].Bytes, []byte(psd), PEMCipherCAMELLIA128)
			} else if *cph == "camellia192" {
				keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, PEM[1].Bytes, []byte(psd), PEMCipherCAMELLIA192)
			} else if *cph == "camellia256" || *cph == "camellia" {
				keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, PEM[1].Bytes, []byte(psd), PEMCipherCAMELLIA256)
			} else if *cph == "aria128" {
				keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, PEM[1].Bytes, []byte(psd), PEMCipherARIA128)
			} else if *cph == "aria192" {
				keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, PEM[1].Bytes, []byte(psd), PEMCipherARIA192)
			} else if *cph == "aria" || *cph == "aria256" {
				keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, PEM[1].Bytes, []byte(psd), PEMCipherARIA256)
			} else if *cph == "cast5" {
				keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, PEM[1].Bytes, []byte(psd), PEMCipherCAST)
			} else if *cph == "anubis" {
				keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, PEM[1].Bytes, []byte(psd), PEMCipherANUBIS)
			} else if *cph == "lea128" {
				keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, PEM[1].Bytes, []byte(*pwd), PEMCipherLEA128)
			} else if *cph == "lea192" {
				keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, PEM[1].Bytes, []byte(*pwd), PEMCipherLEA192)
			} else if *cph == "lea" || *cph == "lea256" {
				keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, PEM[1].Bytes, []byte(*pwd), PEMCipherLEA256)
			} else if *cph == "serpent128" {
				keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, PEM[1].Bytes, []byte(*pwd), PEMCipherSERPENT128)
			} else if *cph == "serpent192" {
				keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, PEM[1].Bytes, []byte(*pwd), PEMCipherSERPENT192)
			} else if *cph == "serpent" || *cph == "serpent256" {
				keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, PEM[1].Bytes, []byte(*pwd), PEMCipherSERPENT256)
			} else if *cph == "rc6128" {
				keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, PEM[1].Bytes, []byte(psd), PEMCipherRC6128)
			} else if *cph == "rc6192" {
				keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, PEM[1].Bytes, []byte(psd), PEMCipherRC6192)
			} else if *cph == "rc6" || *cph == "rc6256" {
				keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, PEM[1].Bytes, []byte(psd), PEMCipherRC6256)
			}
		}
		fmt.Printf("%s", pem.EncodeToMemory(keyBlock))
	} else {
		keyBlock := &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: PEM[1].Bytes,
		}
		if psd != "" {
			if *cph == "aes128" {
				keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, PEM[1].Bytes, []byte(psd), PEMCipherAES128)
			} else if *cph == "aes192" {
				keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, PEM[1].Bytes, []byte(psd), PEMCipherAES192)
			} else if *cph == "aes" || *cph == "aes256" {
				keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, PEM[1].Bytes, []byte(psd), PEMCipherAES256)
			} else if *cph == "3des" {
				keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, PEM[1].Bytes, []byte(psd), PEMCipher3DES)
			} else if *cph == "des" {
				keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, PEM[1].Bytes, []byte(psd), PEMCipherDES)
			} else if *cph == "sm4" {
				keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, PEM[1].Bytes, []byte(psd), PEMCipherSM4)
			} else if *cph == "seed" {
				keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, PEM[1].Bytes, []byte(psd), PEMCipherSEED)
			} else if *cph == "gost" {
				keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, PEM[1].Bytes, []byte(psd), PEMCipherGOST)
			} else if *cph == "idea" {
				keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, PEM[1].Bytes, []byte(psd), PEMCipherIDEA)
			} else if *cph == "camellia128" {
				keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, PEM[1].Bytes, []byte(psd), PEMCipherCAMELLIA128)
			} else if *cph == "camellia192" {
				keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, PEM[1].Bytes, []byte(psd), PEMCipherCAMELLIA192)
			} else if *cph == "camellia256" || *cph == "camellia" {
				keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, PEM[1].Bytes, []byte(psd), PEMCipherCAMELLIA256)
			} else if *cph == "aria128" {
				keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, PEM[1].Bytes, []byte(psd), PEMCipherARIA128)
			} else if *cph == "aria192" {
				keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, PEM[1].Bytes, []byte(psd), PEMCipherARIA192)
			} else if *cph == "aria" || *cph == "aria256" {
				keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, PEM[1].Bytes, []byte(psd), PEMCipherARIA256)
			} else if *cph == "cast5" {
				keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, PEM[1].Bytes, []byte(psd), PEMCipherCAST)
			} else if *cph == "anubis" {
				keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, PEM[1].Bytes, []byte(psd), PEMCipherANUBIS)
			} else if *cph == "lea128" {
				keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, PEM[1].Bytes, []byte(psd), PEMCipherLEA128)
			} else if *cph == "lea192" {
				keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, PEM[1].Bytes, []byte(psd), PEMCipherLEA192)
			} else if *cph == "lea" || *cph == "lea256" {
				keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, PEM[1].Bytes, []byte(psd), PEMCipherLEA256)
			} else if *cph == "serpent128" {
				keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, PEM[1].Bytes, []byte(psd), PEMCipherSERPENT128)
			} else if *cph == "serpent192" {
				keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, PEM[1].Bytes, []byte(psd), PEMCipherSERPENT192)
			} else if *cph == "serpent" || *cph == "serpent256" {
				keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, PEM[1].Bytes, []byte(psd), PEMCipherSERPENT256)
			} else if *cph == "rc6128" {
				keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, PEM[1].Bytes, []byte(psd), PEMCipherRC6128)
			} else if *cph == "rc6192" {
				keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, PEM[1].Bytes, []byte(psd), PEMCipherRC6192)
			} else if *cph == "rc6" || *cph == "rc6256" {
				keyBlock, _ = EncryptPEMBlock(rand.Reader, keyBlock.Type, PEM[1].Bytes, []byte(psd), PEMCipherRC6256)
			}
		}
		fmt.Printf("%s", pem.EncodeToMemory(keyBlock))
	}
	return nil
}

func csrToCrt() error {
	caPublicKeyFile, err := ioutil.ReadFile(*root)
	if err != nil {
		return err
	}
	pemBlock, _ := pem.Decode(caPublicKeyFile)
	if pemBlock == nil {
		panic("pem.Decode failed")
	}
	caCRT, err := smx509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		return err
	}

	caPrivateKeyFile, err := ioutil.ReadFile(*key)
	if err != nil {
		return err
	}
	pemBlock, _ = pem.Decode(caPrivateKeyFile)
	if pemBlock == nil {
		panic("pem.Decode failed")
	}

	var der []byte
	if IsEncryptedPEMBlock(pemBlock) {
		der, err = DecryptPEMBlock(pemBlock, []byte(*pwd))
		if err != nil {
			return err
		}
	} else {
		der = pemBlock.Bytes
	}

	clientCSRFile, err := ioutil.ReadFile(*cert)
	if err != nil {
		return err
	}
	pemBlock, _ = pem.Decode(clientCSRFile)
	if pemBlock == nil {
		panic("pem.Decode failed")
	}
	clientCSR, err := smx509.ParseCertificateRequest(pemBlock.Bytes)
	if err != nil {
		return err
	}
	if err = clientCSR.CheckSignature(); err != nil {
		return err
	}

	scanner := bufio.NewScanner(os.Stdin)
	println("Digital certificates are valid for up to three years:")
	print("Validity (in Days): ")
	scanner.Scan()
	validity := scanner.Text()

	intVar, err := strconv.Atoi(validity)
	NotAfter := time.Now().AddDate(0, 0, intVar)

	var spki struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}

	derBytes, err := smx509.MarshalPKIXPublicKey(clientCSR.PublicKey)
	if err != nil {
		log.Fatal(err)
	}
	_, err = asn1.Unmarshal(derBytes, &spki)
	if err != nil {
		return err
	}
	skid := sha1.Sum(spki.SubjectPublicKey.Bytes)

	clientCRTTemplate := x509.Certificate{
		Signature:          clientCSR.Signature,
		SignatureAlgorithm: clientCSR.SignatureAlgorithm,

		PublicKeyAlgorithm: clientCSR.PublicKeyAlgorithm,
		PublicKey:          clientCSR.PublicKey,

		SerialNumber:   caCRT.SerialNumber,
		Issuer:         caCRT.Subject,
		Subject:        clientCSR.Subject,
		SubjectKeyId:   skid[:],
		EmailAddresses: clientCSR.EmailAddresses,
		NotBefore:      time.Now(),
		NotAfter:       NotAfter,
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}

	if strings.ToUpper(*alg) == "RSA" {
		if *md == "sha256" {
			clientCRTTemplate.SignatureAlgorithm = smx509.SHA256WithRSA
		} else if *md == "sha384" {
			clientCRTTemplate.SignatureAlgorithm = smx509.SHA384WithRSA
		} else if *md == "sha512" {
			clientCRTTemplate.SignatureAlgorithm = smx509.SHA512WithRSA
		} else if *md == "sha1" {
			clientCRTTemplate.SignatureAlgorithm = smx509.SHA1WithRSA
		}
	}

	var clientCRTRaw []byte
	if strings.ToUpper(*alg) == "RSA" {
		caPrivateKey, err := x509.ParsePKCS1PrivateKey(der)
		if err != nil {
			return err
		}
		clientCRTRaw, err = x509.CreateCertificate(rand.Reader, &clientCRTTemplate, caCRT.ToX509(), clientCSR.PublicKey, caPrivateKey)
	} else if strings.ToUpper(*alg) == "ED25519" {
		caPrivateKey, err := x509.ParsePKCS8PrivateKey(der)
		if err != nil {
			return err
		}
		clientCRTRaw, err = x509.CreateCertificate(rand.Reader, &clientCRTTemplate, caCRT.ToX509(), clientCSR.PublicKey, caPrivateKey)
	} else if strings.ToUpper(*alg) == "ECDSA" || strings.ToUpper(*alg) == "EC" {
		caPrivateKey, err := x509.ParseECPrivateKey(der)
		if err != nil {
			return err
		}
		clientCRTRaw, err = x509.CreateCertificate(rand.Reader, &clientCRTTemplate, caCRT.ToX509(), clientCSR.PublicKey, caPrivateKey)
	} else if strings.ToUpper(*alg) == "SM2" {
		caPrivateKey, err := smx509.ParseSM2PrivateKey(der)
		if err != nil {
			return err
		}
		clientCRTRaw, err = smx509.CreateCertificate(rand.Reader, &clientCRTTemplate, caCRT.ToX509(), clientCSR.PublicKey, caPrivateKey)
	}
	if err != nil {
		return err
	}
	var output *os.File
	if flag.Arg(0) == "" {
		output = os.Stdout
	} else {
		file, err := os.Create(flag.Arg(0))
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()
		output = file
	}
	pem.Encode(output, &pem.Block{Type: "CERTIFICATE", Bytes: clientCRTRaw})
	return err
}

func csrToCrt2() error {
	caPublicKeyFile, err := ioutil.ReadFile(*root)
	if err != nil {
		return err
	}
	pemBlock, _ := pem.Decode(caPublicKeyFile)
	if pemBlock == nil {
		panic("pem.Decode failed")
	}
	caCRT, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		return err
	}

	caPrivateKeyFile, err := ioutil.ReadFile(*key)
	if err != nil {
		return err
	}
	pemBlock, _ = pem.Decode(caPrivateKeyFile)
	if pemBlock == nil {
		panic("pem.Decode failed")
	}

	var der []byte
	if IsEncryptedPEMBlock(pemBlock) {
		der, err = DecryptPEMBlock(pemBlock, []byte(*pwd))
		if err != nil {
			return err
		}
	} else {
		der = pemBlock.Bytes
	}

	clientCSRFile, err := ioutil.ReadFile(*cert)
	if err != nil {
		return err
	}
	pemBlock, _ = pem.Decode(clientCSRFile)
	if pemBlock == nil {
		panic("pem.Decode failed")
	}
	clientCSR, err := x509.ParseCertificateRequest(pemBlock.Bytes)
	if err != nil {
		return err
	}
	if err = clientCSR.CheckSignature(); err != nil {
		return err
	}

	scanner := bufio.NewScanner(os.Stdin)
	print("\nValidity (in Days): ")
	scanner.Scan()
	validity := scanner.Text()

	intVar, err := strconv.Atoi(validity)
	NotAfter := time.Now().AddDate(0, 0, intVar)

	hasher := gost34112012256.New()
	if _, err = hasher.Write(clientCSR.PublicKey.(*gost3410.PublicKey).Raw()); err != nil {
		log.Fatalln(err)
	}
	spki := hasher.Sum(nil)
	spki = spki[:20]

	clientCRTTemplate := x509.Certificate{
		Signature:          clientCSR.Signature,
		SignatureAlgorithm: clientCSR.SignatureAlgorithm,

		PublicKeyAlgorithm: clientCSR.PublicKeyAlgorithm,
		PublicKey:          clientCSR.PublicKey,

		SerialNumber:   caCRT.SerialNumber,
		Issuer:         caCRT.Subject,
		Subject:        clientCSR.Subject,
		SubjectKeyId:   spki,
		EmailAddresses: clientCSR.EmailAddresses,
		NotBefore:      time.Now(),
		NotAfter:       NotAfter,
		KeyUsage:       x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment | x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment | x509.KeyUsageKeyAgreement | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}

	var clientCRTRaw []byte

	caPrivateKey, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return err
	}
	clientCRTRaw, err = x509.CreateCertificate(rand.Reader, &clientCRTTemplate, caCRT, clientCSR.PublicKey, &gost3410.PrivateKeyReverseDigest{Prv: caPrivateKey.(*gost3410.PrivateKey)})
	if err != nil {
		return err
	}
	var output *os.File
	if flag.Arg(0) == "" {
		output = os.Stdout
	} else {
		file, err := os.Create(flag.Arg(0))
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()
		output = file
	}
	pem.Encode(output, &pem.Block{Type: "CERTIFICATE", Bytes: clientCRTRaw})
	return err
}

func parsePrivateKeyAndCert(keyPEM, certPEM []byte) (crypto.Signer, *x509.Certificate, error) {
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("Failed to decode private key")
	}
	var decryptedKeyBytes []byte
	var err error
	if x509.IsEncryptedPEMBlock(keyBlock) {
		decryptedKeyBytes, err = DecryptPEMBlock(keyBlock, []byte(*pwd))
		if err != nil {
			return nil, nil, fmt.Errorf("Failed to decrypt private key: %w", err)
		}
		keyBlock.Bytes = decryptedKeyBytes
	}
	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		key, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if err != nil {
			key, err = x509.ParseECPrivateKey(keyBlock.Bytes)
			if err != nil {
				return nil, nil, fmt.Errorf("Failed to parse private key: %w", err)
			}
		}
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, nil, fmt.Errorf("Invalid private key type")
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, nil, fmt.Errorf("Failed to decode certificate")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to parse certificate: %w", err)
	}
	return signer, cert, nil
}

func parsePrivateKeyAndCertSM2(keyPEM, certPEM []byte) (crypto.Signer, *smx509.Certificate, error) {
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("Failed to decode private key")
	}
	var decryptedKeyBytes []byte
	var err error
	if x509.IsEncryptedPEMBlock(keyBlock) {
		decryptedKeyBytes, err = DecryptPEMBlock(keyBlock, []byte(*pwd))
		if err != nil {
			return nil, nil, fmt.Errorf("Failed to decrypt private key: %w", err)
		}
		keyBlock.Bytes = decryptedKeyBytes
	}
	sm2key, err := smx509.ParseSM2PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to parse private key: %w", err)
	}
	var signer crypto.Signer = sm2key
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, nil, fmt.Errorf("Failed to decode certificate")
	}
	cert, err := smx509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to parse certificate: %w", err)
	}
	return signer, cert, nil
}

func isCertificateRevoked(cert *x509.Certificate, crl *pkix.CertificateList) (bool, time.Time) {
	for _, revokedCert := range crl.TBSCertList.RevokedCertificates {
		if revokedCert.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			return true, revokedCert.RevocationTime
		}
	}
	return false, time.Time{}
}

func isCertificateRevokedSM2(cert *smx509.Certificate, crl *pkix.CertificateList) (bool, time.Time) {
	for _, revokedCert := range crl.TBSCertList.RevokedCertificates {
		if revokedCert.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			return true, revokedCert.RevocationTime
		}
	}
	return false, time.Time{}
}

type authorityKeyIdentifier struct {
	Raw                 asn1.RawContent
	ID                  []byte `asn1:"optional,tag:0"`
	KeyIdentifier       []byte `asn1:"optional,tag:1"`
	AuthorityCertIssuer []byte `asn1:"optional,tag:2"`
	AuthorityCertSerial []byte `asn1:"optional,tag:3"`
}

func getAuthorityKeyIdentifierFromCRL(crl *x509.RevocationList) []byte {
	for _, extension := range crl.Extensions {
		if extension.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 35}) {
			var akid authorityKeyIdentifier
			_, err := asn1.Unmarshal(extension.Value, &akid)
			if err == nil {
				return akid.ID
			}
		}
	}
	return nil
}

var oidToAlgo = map[string]string{
	"1.2.643.7.1.1.3.2":     "GOST R 34.11-2012 with GOST R 34.10-2012",
	"1.2.643.7.1.1.3.3":     "GOST R 34.11-2012 with GOST R 34.10-2012 (512 bits)",
	"1.2.840.113549.1.1.11": "RSA",
	"1.3.101.112":           "Ed25519",
	"1.2.840.10045.2.1":     "ECDSA (prime256v1)",
	"1.2.840.10045.4.3.2":   "ECDSA (prime256v1)",
	"1.2.840.10045.3.1.1":   "ECDSA (prime224v1)",
	"1.2.840.10045.4.3.3":   "ECDSA (prime384v1)",
	"1.2.840.10045.4.3.4":   "ECDSA (prime521v1)",
	"1.2.156.10197.1.501":   "SM2 (sm2p256v1)",
}

func printVersion(version int, buf *bytes.Buffer) {
	hexVersion := version - 1
	if hexVersion < 0 {
		hexVersion = 0
	}
	buf.WriteString(fmt.Sprintf("%8sVersion: %d (%#x)\n", "", version, hexVersion))
}

func printName(names []pkix.AttributeTypeAndValue, buf *bytes.Buffer) []string {
	values := []string{}
	for _, name := range names {
		oid := name.Type
		switch {
		case len(oid) == 4 && oid[0] == 2 && oid[1] == 5 && oid[2] == 4:
			switch oid[3] {
			case 3:
				values = append(values, fmt.Sprintf("CN=%s", name.Value))
			case 5:
				values = append(values, fmt.Sprintf("SERIALNUMBER=%s", name.Value))
			case 6:
				values = append(values, fmt.Sprintf("C=%s", name.Value))
			case 7:
				values = append(values, fmt.Sprintf("L=%s", name.Value))
			case 8:
				values = append(values, fmt.Sprintf("ST=%s", name.Value))
			case 9:
				values = append(values, fmt.Sprintf("STREET=%s", name.Value))
			case 10:
				values = append(values, fmt.Sprintf("O=%s", name.Value))
			case 11:
				values = append(values, fmt.Sprintf("OU=%s", name.Value))
			case 17:
				values = append(values, fmt.Sprintf("POSTALCODE=%s", name.Value))
			default:
				values = append(values, fmt.Sprintf("UnknownOID=%s", name.Type.String()))
			}
		case oid.Equal(oidEmailAddress):
			values = append(values, fmt.Sprintf("emailAddress=%s", name.Value))
		case oid.Equal(oidDomainComponent):
			values = append(values, fmt.Sprintf("DC=%s", name.Value))
		case oid.Equal(oidUserID):
			values = append(values, fmt.Sprintf("UID=%s", name.Value))
		default:
			values = append(values, fmt.Sprintf("UnknownOID=%s", name.Type.String()))
		}
	}
	if len(values) > 0 {
		buf.WriteString(values[0])
		for i := 1; i < len(values); i++ {
			buf.WriteString("," + values[i])
		}
		buf.WriteString("\n")
	}
	return values
}

func printSignature(sigAlgo x509.SignatureAlgorithm, sig []byte, buf *bytes.Buffer) {
	buf.WriteString(fmt.Sprintf("%4sSignature Algorithm: %s", "", sigAlgo))
	for i, val := range sig {
		if (i % 18) == 0 {
			buf.WriteString(fmt.Sprintf("\n%9s", ""))
		}
		buf.WriteString(fmt.Sprintf("%02x", val))
		if i != len(sig)-1 {
			buf.WriteString(":")
		}
	}
	buf.WriteString("\n")
}

func getAlgorithmName(oid string) string {
	if algo, ok := oidToAlgo[oid]; ok {
		return algo
	}
	return "Unknown Algorithm"
}

func PKCS7Padding(ciphertext []byte) []byte {
	var padding int
	if *cph == "aes" || *cph == "aria" || *cph == "grasshopper" || *cph == "kuznechik" || *cph == "camellia" || *cph == "twofish" || *cph == "lea" || *cph == "seed" || *cph == "sm4" || *cph == "anubis" || *cph == "serpent" || *cph == "rc6" || *cph == "crypton" || *cph == "mars" {
		padding = 16 - len(ciphertext)%16
	} else if *cph == "blowfish" || *cph == "cast5" || *cph == "des" || *cph == "3des" || *cph == "magma" || *cph == "gost89" || *cph == "idea" || *cph == "rc2" || *cph == "rc5" || *cph == "hight" || *cph == "misty1" || *cph == "khazad" || *cph == "present" || *cph == "twine" {
		padding = 8 - len(ciphertext)%8
	} else if *cph == "threefish" || *cph == "threefish256" {
		padding = 32 - len(ciphertext)%32
	} else if *cph == "threefish512" {
		padding = 64 - len(ciphertext)%64
	} else if *cph == "threefish1024" {
		padding = 128 - len(ciphertext)%128
	}
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS7UnPadding(plantText []byte) []byte {
	length := len(plantText)
	unpadding := int(plantText[length-1])
	return plantText[:(length - unpadding)]
}

func reverseBytes(d []byte) {
	for i, j := 0, len(d)-1; i < j; i, j = i+1, j-1 {
		d[i], d[j] = d[j], d[i]
	}
}

func SplitSubN(s string, n int) []string {
	sub := ""
	subs := []string{}

	runes := bytes.Runes([]byte(s))
	l := len(runes)
	for i, r := range runes {
		sub = sub + string(r)
		if (i+1)%n == 0 {
			subs = append(subs, sub)
			sub = ""
		} else if (i + 1) == l {
			subs = append(subs, sub)
		}
	}

	return subs
}

func split(s string, size int) []string {
	ss := make([]string, 0, len(s)/size+1)
	for len(s) > 0 {
		if len(s) < size {
			size = len(s)
		}
		ss, s = append(ss, s[:size]), s[size:]

	}
	return ss
}

func encodeAscii85(data []byte) string {
	var encoded strings.Builder
	encoder := ascii85.NewEncoder(&encoded)
	encoder.Write(data)
	encoder.Close()
	return encoded.String()
}

func printChunks(s string, size int) {
	for i := 0; i < len(s); i += size {
		end := i + size
		if end > len(s) {
			end = len(s)
		}
		fmt.Println(s[i:end])
	}
}

func byte32(s []byte) (a *[32]byte) {
	if len(a) <= len(s) {
		a = (*[len(a)]byte)(unsafe.Pointer(&s[0]))
	}
	return a
}

func byte16(s []byte) (a *[16]byte) {
	if len(a) <= len(s) {
		a = (*[len(a)]byte)(unsafe.Pointer(&s[0]))
	}
	return a
}

func byte10(s []byte) (a *[10]byte) {
	if len(a) <= len(s) {
		a = (*[len(a)]byte)(unsafe.Pointer(&s[0]))
	}
	return a
}

func byte8(s []byte) (a *[8]byte) {
	if len(a) <= len(s) {
		a = (*[len(a)]byte)(unsafe.Pointer(&s[0]))
	}
	return a
}

func calculateFingerprint(key []byte) string {
	hash := sha256.Sum256(key)
	fingerprint := base64.StdEncoding.EncodeToString(hash[:])
	return fingerprint
}

func calculateFingerprintGOST(key []byte) string {
	hasher := gost34112012256.New()
	if _, err := hasher.Write(key); err != nil {
		log.Fatalln(err)
	}
	hash := hasher.Sum(nil)
	fingerprint := base64.StdEncoding.EncodeToString(hash)
	return fingerprint
}

func NewMGMAC(block cipher.Block, length int, nonce, data []byte) ([]byte, error) {
	aead, err := mgm.NewMGM(block, length)
	if err != nil {
		return nil, err
	}
	mgmac := aead.Seal(nil, nonce, nil, data)
	return mgmac, nil
}

func printKeyDetails(block *pem.Block) {
	publicInterface, err := smx509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		publicInterface, err = x509.ParsePKIXPublicKey(block.Bytes)
	}
	switch publicInterface.(type) {
	case *rsa.PublicKey:
		publicKey := publicInterface.(*rsa.PublicKey)
		fmt.Fprintf(os.Stderr, "RSA (%v-bit)\n", publicKey.N.BitLen())
	case *ecdsa.PublicKey:
		publicKey := publicInterface.(*ecdsa.PublicKey)
		fmt.Fprintf(os.Stderr, "ECDSA (%v-bit)\n", publicKey.Curve.Params().BitSize)
	case *ecdh.PublicKey:
		fmt.Fprintln(os.Stderr, "X25519 (256-bit)")
	case ed25519.PublicKey:
		fmt.Fprintln(os.Stderr, "Ed25519 (256-bit)")
	case *gost3410.PublicKey:
		publicKey := publicInterface.(*gost3410.PublicKey)
		fmt.Fprintf(os.Stderr, "GOST2012 (%v-bit)\n", len(publicKey.Raw())*4)
	default:
		log.Fatal("unknown type of public key")
	}
}

func savePEMKey(filename string, keyBytes []byte, blockType string) error {
	block := &pem.Block{
		Type:  blockType,
		Bytes: keyBytes,
	}

	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	return pem.Encode(file, block)
}

func savePEMPublicKey(filename string, keyBytes []byte) error {
	return savePEMKey(filename, keyBytes, "SPHINCS PUBLIC KEY")
}

/*
func savePEMPrivateKey(filename string, keyBytes []byte, passphrase string) error {
	var blockType string
	if passphrase != "" {
		encryptedSK, err := encryptKey(keyBytes, passphrase)
		if err != nil {
			return err
		}
		keyBytes = encryptedSK
		blockType = "SPHINCS SECRET KEY"
	} else {
		blockType = "SPHINCS SECRET KEY"
	}

	return savePEMKey(filename, keyBytes, blockType)
}
*/

func savePEMPrivateKey(filename string, keyBytes []byte, passphrase string, tweak string) error {
	if passphrase != "" {
		encryptedSK, err := encryptKey(keyBytes, passphrase)
		if err != nil {
			return err
		}
		headers := map[string]string{
			"Proc-Type":      "4,ENCRYPTED",
			"Hash-Algorithm": strings.ToUpper(*md),
			"Scrypt-Itering": strconv.Itoa(*iter),
		}

		if strings.ToUpper(*cph) == "ANUBIS" {
			headers["DEK-Info"] = fmt.Sprintf("ANUBIS")
		} else if strings.ToUpper(*cph) == "AES" {
			headers["DEK-Info"] = fmt.Sprintf("AES")
		}

		privKeyInfo := &pem.Block{
			Type:    "SPHINCS SECRET KEY",
			Headers: headers,
			Bytes:   encryptedSK,
		}

		file, err := os.Create(filename)
		if err != nil {
			return err
		}
		defer file.Close()

		return pem.Encode(file, privKeyInfo)
	} else {
		return savePEMKey(filename, keyBytes, "SPHINCS SECRET KEY")
	}
}

func loadPEMKey(filename string, passphrase string) ([]byte, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	pemData, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the key")
	}

	if !IsEncryptedPEMBlock(block) {
		return block.Bytes, nil
	}

	dekInfo := block.Headers["DEK-Info"]
	if dekInfo != "" {
		parts := strings.Split(dekInfo, ",")
		*cph = strings.TrimSuffix(strings.ToLower(parts[0]), "-cfb")
	}
	*md = strings.ToLower(block.Headers["Hash-Algorithm"])
	*iter, err = strconv.Atoi(block.Headers["Scrypt-Itering"])
	if err != nil {
		return nil, err
	}

	decryptedKey, err := decryptKey(block.Bytes, passphrase)
	if err != nil {
		return nil, err
	}

	return decryptedKey, nil
}

func deriveKey(passphrase string, salt []byte) ([]byte, error) {
	key, err := Scrypt([]byte(passphrase), salt, *iter, 8, 1, 128)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func encryptKey(key []byte, passphrase string) ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	derivedKey, err := deriveKey(passphrase, salt)
	if err != nil {
		return nil, err
	}

	var block cipher.Block
	if *cph == "aes" {
		block, err = aes.NewCipher(derivedKey[:32])
		if err != nil {
			return nil, err
		}
	} else if *cph == "anubis" {
		block, err = anubis.NewWithKeySize(derivedKey, 40)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("Unsupported cipher")
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := aesGCM.Seal(nil, nonce, key, nil)

	return append(salt, append(nonce, ciphertext...)...), nil
}

func decryptKey(ciphertext []byte, passphrase string) ([]byte, error) {
	salt := ciphertext[:16]
	nonce := ciphertext[16 : 16+12]
	encryptedKey := ciphertext[16+12:]

	derivedKey, err := deriveKey(passphrase, salt)
	if err != nil {
		return nil, err
	}

	var block cipher.Block
	if *cph == "aes" {
		block, err = aes.NewCipher(derivedKey[:32])
		if err != nil {
			return nil, err
		}
	} else if *cph == "anubis" {
		block, err = anubis.NewWithKeySize(derivedKey, 40)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("unsupported cipher")
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	decryptedKey, err := aesGCM.Open(nil, nonce, encryptedKey, nil)
	if err != nil {
		return nil, err
	}

	return decryptedKey, nil
}

func generateKeyPair(privPath, pubPath string) {
	params := parameters.MakeSphincsPlusSHAKE256256fRobust(true)
	fmt.Printf("SPHINCS+ Parameters\nN=%d, W=%d, Hprime=%d, H=%d, D=%d, K=%d, T=%d, LogT=%d, A=%d\n", params.N, params.W, params.Hprime,
		params.H, params.D, params.K, params.T, params.LogT, params.A)
	sk, pk := sphincs.Spx_keygen(params)

	serializedSK, err := sk.SerializeSK()
	if err != nil {
		log.Fatal(err)
	}
	serializedPK, err := pk.SerializePK()
	if err != nil {
		log.Fatal(err)
	}

	err = savePEMPrivateKey(privPath, serializedSK, *pwd, *info)
	if err != nil {
		log.Fatal(err)
	}

	err = savePEMPublicKey(pubPath, serializedPK)
	if err != nil {
		log.Fatal(err)
	}

	absPrivPath, err := filepath.Abs(*priv)
	if err != nil {
		log.Fatal("Failed to get absolute path for private key:", err)
	}
	absPubPath, err := filepath.Abs(*pub)
	if err != nil {
		log.Fatal("Failed to get absolute path for public key:", err)
	}
	println("Private key saved to:", absPrivPath)
	println("Public key saved to:", absPubPath)

	file, err := os.Open(*pub)
	if err != nil {
		log.Fatal(err)
	}
	info, err := file.Stat()
	if err != nil {
		log.Fatal(err)
	}
	buf := make([]byte, info.Size())
	file.Read(buf)
	fingerprint := calculateFingerprint(buf)
	print("Fingerprint: ")
	println(fingerprint)
	println("SPHINCS+ (256-bit)")
	randomArt := randomart.FromString(string(buf))
	println(randomArt)
}

func signMessage(input io.Reader, keyPath string) {
	messageBytes, err := ioutil.ReadAll(input)
	if err != nil {
		log.Fatal(err)
	}
	params := parameters.MakeSphincsPlusSHAKE256256fRobust(true)

	privateKeyBytes, err := loadPEMKey(keyPath, *pwd)
	if err != nil {
		log.Fatal(err)
	}

	deserializedSK, err := sphincs.DeserializeSK(params, privateKeyBytes)
	if err != nil {
		log.Fatal(err)
	}

	sk := deserializedSK
	signature := sphincs.Spx_sign(params, messageBytes, sk)

	serializedSignature, err := signature.SerializeSignature()
	if err != nil {
		log.Fatal(err)
	}
	/*
		if *sig != "" {
			base64Signature := base64.StdEncoding.EncodeToString(serializedSignature)
			err = ioutil.WriteFile(*sig, []byte(base64Signature), 0644)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("Signature saved to %s\n", *sig)
		} else {
			base64Signature := base64.StdEncoding.EncodeToString(serializedSignature)
			fmt.Printf("%s\n", base64Signature)
		}
	*/
	block := &pem.Block{
		Type:  "SPHINCS SIGNATURE",
		Bytes: serializedSignature,
	}
	pemSignature := pem.EncodeToMemory(block)
	if *sig != "" {
		err = ioutil.WriteFile(*sig, []byte(pemSignature), 0644)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Signature saved to %s\n", *sig)
	} else {
		fmt.Printf("%s\n", pemSignature)
	}
}

func verifySignature(input io.Reader, keyPath, sigPath string) {
	messageBytes, err := ioutil.ReadAll(input)
	if err != nil {
		log.Fatal(err)
	}
	params := parameters.MakeSphincsPlusSHAKE256256fRobust(true)

	publicKeyBytes, err := loadPEMKey(keyPath, "")
	if err != nil {
		log.Fatal(err)
	}

	deserializedPK, err := sphincs.DeserializePK(params, publicKeyBytes)
	if err != nil {
		log.Fatal(err)
	}

	pk := deserializedPK

	signatureBytes, err := ioutil.ReadFile(sigPath)
	if err != nil {
		log.Fatal(err)
	}
	/*
		decodedSignature, err := base64.StdEncoding.DecodeString(string(signatureBytes))
		if err != nil {
			log.Fatal(err)
		}

		deserializedSignature, err := sphincs.DeserializeSignature(params, decodedSignature)
		if err != nil {
			log.Fatal(err)
		}
	*/
	decodedSignature, _ := pem.Decode(signatureBytes)
	deserializedSignature, err := sphincs.DeserializeSignature(params, decodedSignature.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	signature := deserializedSignature

	if sphincs.Spx_verify(params, messageBytes, signature, pk) {
		fmt.Println("Verified: true")
	} else {
		fmt.Println("Verified: false")
		os.Exit(1)
	}
}

func printPublicKeyParams(pk *sphincs.SPHINCS_PK) {
	fmt.Printf("PKseed=%X\n", pk.PKseed)
	fmt.Printf("PKroot=%X\n", pk.PKroot)
}

func printPrivateKeyParams(sk *sphincs.SPHINCS_SK) {
	fmt.Printf("PKseed=%X\n", sk.PKseed)
	fmt.Printf("PKroot=%X\n", sk.PKroot)
}

func printKeyParams(keyBytes []byte, isPrivateKey bool) error {
	var (
		pk *sphincs.SPHINCS_PK
		sk *sphincs.SPHINCS_SK
	)
	var params = parameters.MakeSphincsPlusSHAKE256256fRobust(true)

	if isPrivateKey {
		var err error
		sk, err = sphincs.DeserializeSK(params, keyBytes)
		if err != nil {
			return err
		}
		printPrivateKeyParams(sk)
		os.Exit(0)
	} else {
		var err error
		pk, err = sphincs.DeserializePK(params, keyBytes)
		if err != nil {
			return err
		}
		printPublicKeyParams(pk)
		os.Exit(0)
	}

	return nil
}

func printPublicKeyParamsFull(pk *sphincs.SPHINCS_PK) {
	serializedPK, err := pk.SerializePK()
	if err != nil {
		log.Fatal(err)
	}

	block := &pem.Block{
		Type:  "SPHINCS PUBLIC KEY",
		Bytes: serializedPK,
	}
	pem.Encode(os.Stdout, block)

	fmt.Printf("PublicKey: (256-bit)\n")

	fmt.Printf("PK: \n")
	splitz := SplitSubN(hex.EncodeToString(serializedPK), 2)
	for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
		fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
	}
	fmt.Printf("PKseed: \n")
	splitz = SplitSubN(hex.EncodeToString(pk.PKseed), 2)
	for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
		fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
	}
	fmt.Printf("PKroot: \n")
	splitz = SplitSubN(hex.EncodeToString(pk.PKroot), 2)
	for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
		fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
	}
	skid := sha3.Sum256(serializedPK)
	fmt.Printf("\nKeyID: %x \n", skid[:20])
}

func printPrivateKeyParamsFull(sk *sphincs.SPHINCS_SK) {
	serializedSK, err := sk.SerializeSK()
	if err != nil {
		log.Fatal(err)
	}

	block := &pem.Block{
		Type:  "SPHINCS SECRET KEY",
		Bytes: serializedSK,
	}
	pem.Encode(os.Stdout, block)

	fmt.Printf("SecretKey: (256-bit)\n")
	/*
		fmt.Printf("SK: \n")
		splitz := SplitSubN(hex.EncodeToString(serializedSK), 2)
		for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
			fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
		}
	*/
	fmt.Printf("SKseed: \n")
	splitz := SplitSubN(hex.EncodeToString(sk.SKseed), 2)
	for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
		fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
	}
	fmt.Printf("SKprf: \n")
	splitz = SplitSubN(hex.EncodeToString(sk.SKprf), 2)
	for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
		fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
	}
	fmt.Printf("PKseed: \n")
	splitz = SplitSubN(hex.EncodeToString(sk.PKseed), 2)
	for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
		fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
	}
	fmt.Printf("PKroot: \n")
	splitz = SplitSubN(hex.EncodeToString(sk.PKroot), 2)
	for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
		fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
	}
	c := append(sk.PKseed, sk.PKroot...)
	skid := sha3.Sum256(c)
	fmt.Printf("\nKeyID: %x \n", skid[:20])
}

func printKeyParamsFull(keyBytes []byte, isPrivateKey bool) error {
	var (
		pk *sphincs.SPHINCS_PK
		sk *sphincs.SPHINCS_SK
	)
	var params = parameters.MakeSphincsPlusSHAKE256256fRobust(true)

	if isPrivateKey {
		var err error
		sk, err = sphincs.DeserializeSK(params, keyBytes)
		if err != nil {
			return err
		}
		printPrivateKeyParamsFull(sk)
		os.Exit(0)
	} else {
		var err error
		pk, err = sphincs.DeserializePK(params, keyBytes)
		if err != nil {
			return err
		}
		printPublicKeyParamsFull(pk)
		os.Exit(0)
	}

	return nil
}

type PEMCipher int

const (
	_ PEMCipher = iota
	PEMCipherDES
	PEMCipher3DES
	PEMCipherAES128
	PEMCipherAES192
	PEMCipherAES256
	PEMCipherSM4
	PEMCipherARIA128
	PEMCipherARIA192
	PEMCipherARIA256
	PEMCipherLEA128
	PEMCipherLEA192
	PEMCipherLEA256
	PEMCipherCAMELLIA128
	PEMCipherCAMELLIA192
	PEMCipherCAMELLIA256
	PEMCipherIDEA
	PEMCipherSEED
	PEMCipherGOST
	PEMCipherCAST
	PEMCipherANUBIS
	PEMCipherSERPENT128
	PEMCipherSERPENT192
	PEMCipherSERPENT256
	PEMCipherRC6128
	PEMCipherRC6192
	PEMCipherRC6256
)

type rfc1423Algo struct {
	cipher     PEMCipher
	name       string
	cipherFunc func(key []byte) (cipher.Block, error)
	keySize    int
	blockSize  int
}

var rfc1423Algos = []rfc1423Algo{{
	cipher:     PEMCipherGOST,
	name:       "KUZNECHIK-CBC",
	cipherFunc: kuznechik.NewCipher,
	keySize:    32,
	blockSize:  kuznechik.BlockSize,
}, {
	cipher:     PEMCipherDES,
	name:       "DES-CBC",
	cipherFunc: des.NewCipher,
	keySize:    8,
	blockSize:  des.BlockSize,
}, {
	cipher:     PEMCipher3DES,
	name:       "DES-EDE3-CBC",
	cipherFunc: des.NewTripleDESCipher,
	keySize:    24,
	blockSize:  des.BlockSize,
}, {
	cipher:     PEMCipherAES128,
	name:       "AES-128-CBC",
	cipherFunc: aes.NewCipher,
	keySize:    16,
	blockSize:  aes.BlockSize,
}, {
	cipher:     PEMCipherAES192,
	name:       "AES-192-CBC",
	cipherFunc: aes.NewCipher,
	keySize:    24,
	blockSize:  aes.BlockSize,
}, {
	cipher:     PEMCipherAES256,
	name:       "AES-256-CBC",
	cipherFunc: aes.NewCipher,
	keySize:    32,
	blockSize:  aes.BlockSize,
}, {
	cipher:     PEMCipherSM4,
	name:       "SM4-CBC",
	cipherFunc: sm4.NewCipher,
	keySize:    16,
	blockSize:  sm4.BlockSize,
}, {
	cipher:     PEMCipherARIA128,
	name:       "ARIA-128-CBC",
	cipherFunc: aria.NewCipher,
	keySize:    16,
	blockSize:  aria.BlockSize,
}, {
	cipher:     PEMCipherARIA192,
	name:       "ARIA-192-CBC",
	cipherFunc: aria.NewCipher,
	keySize:    24,
	blockSize:  aria.BlockSize,
}, {
	cipher:     PEMCipherARIA256,
	name:       "ARIA-256-CBC",
	cipherFunc: aria.NewCipher,
	keySize:    32,
	blockSize:  aria.BlockSize,
}, {
	cipher:     PEMCipherLEA128,
	name:       "LEA-128-CBC",
	cipherFunc: lea.NewCipher,
	keySize:    16,
	blockSize:  lea.BlockSize,
}, {
	cipher:     PEMCipherLEA192,
	name:       "LEA-192-CBC",
	cipherFunc: lea.NewCipher,
	keySize:    24,
	blockSize:  lea.BlockSize,
}, {
	cipher:     PEMCipherLEA256,
	name:       "LEA-256-CBC",
	cipherFunc: lea.NewCipher,
	keySize:    32,
	blockSize:  lea.BlockSize,
}, {
	cipher:     PEMCipherCAMELLIA128,
	name:       "CAMELLIA-128-CBC",
	cipherFunc: camellia.NewCipher,
	keySize:    16,
	blockSize:  camellia.BlockSize,
}, {
	cipher:     PEMCipherCAMELLIA192,
	name:       "CAMELLIA-192-CBC",
	cipherFunc: camellia.NewCipher,
	keySize:    24,
	blockSize:  camellia.BlockSize,
}, {
	cipher:     PEMCipherCAMELLIA256,
	name:       "CAMELLIA-256-CBC",
	cipherFunc: camellia.NewCipher,
	keySize:    32,
	blockSize:  camellia.BlockSize,
}, {
	cipher:     PEMCipherIDEA,
	name:       "IDEA-CBC",
	cipherFunc: idea.NewCipher,
	keySize:    16,
	blockSize:  8,
}, {
	cipher:     PEMCipherSEED,
	name:       "SEED-CBC",
	cipherFunc: krcrypt.NewSEED,
	keySize:    16,
	blockSize:  16,
}, {
	cipher:     PEMCipherSEED,
	name:       "SEED-CBC",
	cipherFunc: krcrypt.NewSEED,
	keySize:    16,
	blockSize:  16,
}, {
	cipher:     PEMCipherCAST,
	name:       "CAST-CBC",
	cipherFunc: cast5.NewCAST,
	keySize:    16,
	blockSize:  8,
}, {
	cipher:     PEMCipherANUBIS,
	name:       "ANUBIS-CBC",
	cipherFunc: anubis.New,
	keySize:    16,
	blockSize:  16,
}, {
	cipher:     PEMCipherSERPENT128,
	name:       "SERPENT-128-CBC",
	cipherFunc: serpent.NewCipher,
	keySize:    16,
	blockSize:  16,
}, {
	cipher:     PEMCipherSERPENT192,
	name:       "SERPENT-192-CBC",
	cipherFunc: serpent.NewCipher,
	keySize:    24,
	blockSize:  16,
}, {
	cipher:     PEMCipherSERPENT256,
	name:       "SERPENT-256-CBC",
	cipherFunc: serpent.NewCipher,
	keySize:    32,
	blockSize:  16,
}, {
	cipher:     PEMCipherRC6128,
	name:       "RC6-128-CBC",
	cipherFunc: rc6.NewCipher,
	keySize:    16,
	blockSize:  16,
}, {
	cipher:     PEMCipherRC6192,
	name:       "RC6-192-CBC",
	cipherFunc: rc6.NewCipher,
	keySize:    24,
	blockSize:  16,
}, {
	cipher:     PEMCipherRC6256,
	name:       "RC6-256-CBC",
	cipherFunc: rc6.NewCipher,
	keySize:    32,
	blockSize:  16,
},
}

func (c rfc1423Algo) deriveKey(password, salt []byte) []byte {
	hash := md5.New()
	out := make([]byte, c.keySize)
	var digest []byte

	for i := 0; i < len(out); i += len(digest) {
		hash.Reset()
		hash.Write(digest)
		hash.Write(password)
		hash.Write(salt)
		digest = hash.Sum(digest[:0])
		copy(out[i:], digest)
	}
	return out
}

func IsEncryptedPEMBlock(b *pem.Block) bool {
	_, ok := b.Headers["DEK-Info"]
	return ok
}

var IncorrectPasswordError = errors.New("x509: decryption password incorrect")

func DecryptPEMBlock(b *pem.Block, password []byte) ([]byte, error) {
	dek, ok := b.Headers["DEK-Info"]
	if !ok {
		return nil, errors.New("x509: no DEK-Info header in block")
	}

	idx := strings.Index(dek, ",")
	if idx == -1 {
		return nil, errors.New("x509: malformed DEK-Info header")
	}

	mode, hexIV := dek[:idx], dek[idx+1:]
	ciph := cipherByName(mode)
	if ciph == nil {
		return nil, errors.New("x509: unknown encryption mode")
	}
	iv, err := hex.DecodeString(hexIV)
	if err != nil {
		return nil, err
	}
	if len(iv) != ciph.blockSize {
		return nil, errors.New("x509: incorrect IV size")
	}

	key := ciph.deriveKey(password, iv[:8])
	block, err := ciph.cipherFunc(key)
	if err != nil {
		return nil, err
	}

	if len(b.Bytes)%block.BlockSize() != 0 {
		return nil, errors.New("x509: encrypted PEM data is not a multiple of the block size")
	}

	data := make([]byte, len(b.Bytes))
	dec := cipher.NewCBCDecrypter(block, iv)
	dec.CryptBlocks(data, b.Bytes)

	dlen := len(data)
	if dlen == 0 || dlen%ciph.blockSize != 0 {
		return nil, errors.New("x509: invalid padding")
	}
	last := int(data[dlen-1])
	if dlen < last {
		return nil, IncorrectPasswordError
	}
	if last == 0 || last > ciph.blockSize {
		return nil, IncorrectPasswordError
	}
	for _, val := range data[dlen-last:] {
		if int(val) != last {
			return nil, IncorrectPasswordError
		}
	}
	return data[:dlen-last], nil
}

func EncryptPEMBlock(rand io.Reader, blockType string, data, password []byte, alg PEMCipher) (*pem.Block, error) {
	ciph := cipherByKey(alg)
	if ciph == nil {
		return nil, errors.New("x509: unknown encryption mode")
	}
	iv := make([]byte, ciph.blockSize)
	if _, err := io.ReadFull(rand, iv); err != nil {
		return nil, errors.New("x509: cannot generate IV: " + err.Error())
	}
	key := ciph.deriveKey(password, iv[:8])
	block, err := ciph.cipherFunc(key)
	if err != nil {
		return nil, err
	}
	enc := cipher.NewCBCEncrypter(block, iv)
	pad := ciph.blockSize - len(data)%ciph.blockSize
	encrypted := make([]byte, len(data), len(data)+pad)
	copy(encrypted, data)
	for i := 0; i < pad; i++ {
		encrypted = append(encrypted, byte(pad))
	}
	enc.CryptBlocks(encrypted, encrypted)

	return &pem.Block{
		Type: blockType,
		Headers: map[string]string{
			"Proc-Type": "4,ENCRYPTED",
			"DEK-Info":  ciph.name + "," + hex.EncodeToString(iv),
		},
		Bytes: encrypted,
	}, nil
}

func cipherByName(name string) *rfc1423Algo {
	for i := range rfc1423Algos {
		alg := &rfc1423Algos[i]
		if alg.name == name {
			return alg
		}
	}
	return nil
}

func cipherByKey(key PEMCipher) *rfc1423Algo {
	for i := range rfc1423Algos {
		alg := &rfc1423Algos[i]
		if alg.cipher == key {
			return alg
		}
	}
	return nil
}

func setup(privateKey *big.Int, g, p *big.Int) *big.Int {
	publicKey := new(big.Int).Exp(g, privateKey, p)
	return publicKey
}

type PublicKey struct {
	G, P, Y *big.Int
}

type PrivateKey struct {
	PublicKey
	P *big.Int
	G *big.Int
	X *big.Int
}

func encrypt(random io.Reader, pub *PublicKey, msg []byte) (ciphertext string, err error) {
	k, err := rand.Int(random, pub.P)
	if err != nil {
		return "", err
	}

	m := new(big.Int).SetBytes(msg)

	a := new(big.Int).Exp(pub.G, k, pub.P)
	s := new(big.Int).Exp(pub.Y, k, pub.P)
	b := s.Mul(s, m)
	b.Mod(b, pub.P)

	aHex := fmt.Sprintf("%0*x", (pub.P.BitLen())/4, a)
	bHex := fmt.Sprintf("%0*x", (pub.P.BitLen())/4, b)
	ciphertext = aHex + bHex

	return ciphertext, nil
}

func decrypt(priv *PrivateKey, ciphertext string) (msg []byte, err error) {
	if len(ciphertext)%2 != 0 {
		return nil, fmt.Errorf("invalid cipher format")
	}

	halfLen := len(ciphertext) / 2
	aHex := ciphertext[:halfLen]
	bHex := ciphertext[halfLen:]

	a, successA := new(big.Int).SetString(aHex, 16)
	b, successB := new(big.Int).SetString(bHex, 16)
	if !successA || !successB {
		return nil, fmt.Errorf("invalid cipher format")
	}

	s := new(big.Int).Exp(a, priv.X, priv.P)
	s.ModInverse(s, priv.P)
	s.Mul(s, b)
	s.Mod(s, priv.P)

	em := s.Bytes()

	return em, nil
}

func sign(privateKey *PrivateKey, message []byte, hashFunc func() hash.Hash) (signature string, err error) {
	for {
		k, err := rand.Int(rand.Reader, new(big.Int).Sub(privateKey.P, big.NewInt(2)))
		if err != nil {
			return "", fmt.Errorf("failed to generate random number: %v", err)
		}

		if k.Sign() == 0 {
			k = big.NewInt(1)
		}

		if new(big.Int).GCD(nil, nil, k, new(big.Int).Sub(privateKey.P, big.NewInt(1))).Cmp(big.NewInt(1)) == 0 {
			rBigInt := new(big.Int).Exp(privateKey.G, k, privateKey.P)
			rBigInt.Mod(rBigInt, privateKey.P)
			rHex := fmt.Sprintf("%x", rBigInt)

			h := hashFunc()
			h.Write(message)
			hash := h.Sum(nil)
			hashInt := new(big.Int).SetBytes(hash)

			kInv := new(big.Int).ModInverse(k, new(big.Int).Sub(privateKey.P, big.NewInt(1)))
			if kInv == nil {
				return "", errors.New("failed to calculate modular inverse: k is not invertible")
			}

			sBigInt := new(big.Int).Mul(kInv, new(big.Int).Sub(hashInt, new(big.Int).Mul(privateKey.X, rBigInt)))
			sBigInt.Mod(sBigInt, new(big.Int).Sub(privateKey.P, big.NewInt(1)))
			sHex := fmt.Sprintf("%x", sBigInt)

			paddingLen := len(fmt.Sprintf("%x", privateKey.P))
			rPadded := fmt.Sprintf("%0*s", paddingLen, rHex)
			sPadded := fmt.Sprintf("%0*s", paddingLen, sHex)

			signature = rPadded + sPadded
			return signature, nil
		}
	}
}

func verify(publicKey *PublicKey, message []byte, signature string, hashFunc func() hash.Hash) bool {
	pLength := len(fmt.Sprintf("%X", publicKey.P))
	if len(signature) != 2*pLength {
		return false
	}

	rHex := signature[:pLength]
	sHex := signature[pLength:]

	r, ok := new(big.Int).SetString(rHex, 16)
	if !ok {
		fmt.Println("Error converting R string to big.Int")
		return false
	}

	s, ok := new(big.Int).SetString(sHex, 16)
	if !ok {
		fmt.Println("Error converting S string to big.Int")
		return false
	}

	if r.Cmp(big.NewInt(1)) == -1 || r.Cmp(new(big.Int).Sub(publicKey.P, big.NewInt(1))) == 1 {
		return false
	}
	if s.Cmp(big.NewInt(1)) == -1 || s.Cmp(new(big.Int).Sub(publicKey.P, big.NewInt(1))) == 1 {
		return false
	}

	h := hashFunc()
	h.Write(message)
	hash := h.Sum(nil)
	hashInt := new(big.Int).SetBytes(hash)
	ghash := new(big.Int).Exp(publicKey.G, hashInt, publicKey.P)

	yr := new(big.Int).Exp(publicKey.Y, r, publicKey.P)
	rs := new(big.Int).Exp(r, s, publicKey.P)
	yrrs := new(big.Int).Mul(yr, rs)
	yrrs.Mod(yrrs, publicKey.P)

	return ghash.Cmp(yrrs) == 0
}

func savePrivateKeyToPEM(fileName string, privKey *PrivateKey) error {
	privPEM := &PrivateKey{
		X: privKey.X,
		P: privKey.P,
		G: privKey.G,
	}

	privBytes, err := encodePrivateKeyPEM(privPEM)
	if err != nil {
		return err
	}

	block := &pem.Block{
		Type:  "ELGAMAL PRIVATE KEY",
		Bytes: privBytes,
	}

	return savePEMToFile(fileName, block, *pwd != "")
}

func encodePrivateKeyPEM(privPEM *PrivateKey) ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(privPEM)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func readPrivateKeyFromPEM(fileName string) (*PrivateKey, error) {
	pemData, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	if block.Type != "ELGAMAL PRIVATE KEY" {
		return nil, errors.New("unexpected PEM block type")
	}

	if block.Headers["Proc-Type"] == "4,ENCRYPTED" {
		if *pwd == "" {
			return nil, fmt.Errorf("private key is encrypted, but no decryption key provided")
		}

		privBytes, err := decryptBlock(block, deriveKeyFromPassword(*pwd))
		if err != nil {
			return nil, err
		}

		var privKey PrivateKey
		buf := bytes.NewReader(privBytes)
		dec := gob.NewDecoder(buf)
		err = dec.Decode(&privKey)
		if err != nil {
			return nil, err
		}

		return &privKey, nil
	}

	var privKey PrivateKey
	buf := bytes.NewReader(block.Bytes)
	dec := gob.NewDecoder(buf)
	err = dec.Decode(&privKey)
	if err != nil {
		return nil, err
	}

	return &privKey, nil
}

func savePublicKeyToPEM(fileName string, pub *PublicKey) error {
	file, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer file.Close()

	pubBytes, err := publicKeyToBytes(pub)
	if err != nil {
		return err
	}

	block := &pem.Block{
		Type:  "ELGAMAL PUBLIC KEY",
		Bytes: pubBytes,
	}

	err = pem.Encode(file, block)
	if err != nil {
		return err
	}

	return nil
}

func readPublicKeyFromPEM(fileName string) (*PublicKey, error) {
	file, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	pemData, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	pub, err := bytesToPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return pub, nil
}

func publicKeyToBytes(pub *PublicKey) ([]byte, error) {
	if pub == nil {
		return nil, errors.New("cannot encode nil PublicKey pointer")
	}

	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(pub)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func bytesToPublicKey(data []byte) (*PublicKey, error) {
	var pub PublicKey
	dec := gob.NewDecoder(bytes.NewReader(data))

	err := dec.Decode(&pub)
	if err != nil {
		return nil, err
	}

	return &pub, nil
}

func generateRandomX(p *big.Int) (*big.Int, error) {
	x, err := rand.Int(rand.Reader, new(big.Int).Sub(p, big.NewInt(2)))
	if err != nil {
		return nil, err
	}
	return x, nil
}

func isPrime(n *big.Int) bool {
	return n.ProbablyPrime(20)
}

func generatePrime(length int) (*big.Int, error) {
	for {
		randomBits := make([]byte, length/8)
		_, err := rand.Read(randomBits)
		if err != nil {
			return nil, err
		}

		randomBits[0] |= 1
		randomBits[len(randomBits)-1] |= 1

		prime := new(big.Int).SetBytes(randomBits)

		prime.SetBit(prime, length-1, 1)

		if isPrime(prime) && prime.BitLen() == length {
			return prime, nil
		}

		print(".")
	}
}

type ElGamalParams struct {
	P *big.Int
	G *big.Int
}

func generateElGamalParams() (*ElGamalParams, error) {
	pSize := *length

	p, err := generatePrime(pSize)
	if err != nil {
		return nil, fmt.Errorf("error generating P: %v", err)
	}

	g, err := generateGenerator(p)
	if err != nil {
		return nil, fmt.Errorf("error generating G: %v", err)
	}

	return &ElGamalParams{
		P: p,
		G: g,
	}, nil
}

func generateGenerator(p *big.Int) (*big.Int, error) {
	two := big.NewInt(2)
	pMinusTwo := new(big.Int).Sub(p, two)

	g, err := rand.Int(rand.Reader, pMinusTwo)
	if err != nil {
		return nil, fmt.Errorf("error generating G: %v", err)
	}
	g.Add(g, two)

	return g, nil
}

func init() {
	gob.Register(&ElGamalParams{})
}

func paramsToBytes(params *ElGamalParams) ([]byte, error) {
	if params == nil {
		return nil, errors.New("cannot encode nil ElGamalParams pointer")
	}

	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(params)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func bytesToParams(data []byte) (*ElGamalParams, error) {
	var params ElGamalParams
	dec := gob.NewDecoder(bytes.NewReader(data))

	err := dec.Decode(&params)
	if err != nil {
		return nil, err
	}

	return &params, nil
}

func saveElGamalParamsToPEM(fileName string, params *ElGamalParams) error {
	var file *os.File
	var err error

	print("\n")
	if fileName == "" {
		file = os.Stdout
	} else {
		file, err = os.Create(fileName)
		if err != nil {
			return err
		}
		defer file.Close()
	}

	paramsBytes, err := paramsToBytes(params)
	if err != nil {
		return err
	}

	err = pem.Encode(file, &pem.Block{
		Type:  "ELGAMAL PARAMETERS",
		Bytes: paramsBytes,
	})
	if err != nil {
		return err
	}

	return nil
}

func readElGamalParamsFromPEM(fileName string) (*ElGamalParams, error) {
	file, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	pemData, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	return bytesToParams(block.Bytes)
}

/*
func savePEMToFile(fileName string, block *pem.Block) error {
	file, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer file.Close()

	err = pem.Encode(file, block)
	if err != nil {
		return err
	}

	return nil
}

func readKeyFromPEM(fileName string) ([]byte, error) {
	fileData, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(fileData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	return block.Bytes, nil
}
*/

func savePEMToFile(fileName string, block *pem.Block, isPrivateKey bool) error {
	file, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer file.Close()

	if isPrivateKey && *pwd != "" {
		key := deriveKeyFromPassword(*pwd)
		encryptedBlock := encryptBlock(block, key)
		block = encryptedBlock
	}

	err = pem.Encode(file, block)
	if err != nil {
		return err
	}

	return nil
}

func readKeyFromPEM(fileName string, isPrivateKey bool) ([]byte, error) {
	fileData, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(fileData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	if isPrivateKey && *pwd != "" {
		key := deriveKeyFromPassword(*pwd)
		bytes, err := decryptBlock(block, key)
		if err != nil {
			return nil, err
		}
		return bytes, nil
	}

	return block.Bytes, nil
}

func deriveKeyFromPassword(password string) []byte {
	key, _ := lyra2re.Sum([]byte(password + *salt))
	return key
}

/*
func encryptBlock(block *pem.Block, key []byte) *pem.Block {
	blockBytes := block.Bytes

	var blockCipher cipher.Block
	var err error

	switch strings.ToUpper(*cph) {
	case "AES":
		blockCipher, err = aes.NewCipher(key)
		if err != nil {
			panic(err.Error())
		}
	case "ANUBIS":
		blockCipher, err = anubis.New(key)
		if err != nil {
			panic(err.Error())
		}
	default:
		log.Fatal("cipher not supported")
	}

	gcm, _ := cipher.NewGCM(blockCipher)

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		panic(err.Error())
	}

	nonceHex := hex.EncodeToString(nonce)
	encryptedBytes := gcm.Seal(nil, nonce, blockBytes, nil)

	newBlock := &pem.Block{
		Type:  block.Type,
		Bytes: encryptedBytes,
		Headers: map[string]string{
			"Proc-Type": "4,ENCRYPTED",
			"DEK-Info":  fmt.Sprintf("%s,%s", strings.ToUpper(*cph), nonceHex),
		},
	}

	if strings.ToUpper(*alg) == "EC-ELGAMAL" {
		newBlock.Headers["Curve"] = strings.ToUpper(*curveFlag)
	}

	return newBlock
}

func decryptBlock(block *pem.Block, key []byte) ([]byte, error) {
	blockBytes := block.Bytes

	dekInfo, ok := block.Headers["DEK-Info"]
	if !ok {
		return nil, fmt.Errorf("missing DEK-Info in PEM block header")
	}

	dekInfoParts := strings.Split(dekInfo, ",")
	if len(dekInfoParts) != 2 {
		return nil, fmt.Errorf("invalid DEK-Info format")
	}

	cipherName := strings.ToUpper(dekInfoParts[0])

	var blockCipher cipher.Block
	var err error

	switch cipherName {
	case "AES":
		blockCipher, err = aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
	case "ANUBIS":
		blockCipher, err = anubis.New(key)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("cipher not supported")
	}

	gcm, _ := cipher.NewGCM(blockCipher)

	nonceHex := dekInfoParts[1]
	nonce, err := hex.DecodeString(nonceHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode nonce: %v", err)
	}

	decryptedBytes, err := gcm.Open(nil, nonce, blockBytes, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt PEM block: %v", err)
	}

	return decryptedBytes, nil
}
*/

func encryptBlock(block *pem.Block, key []byte) *pem.Block {
	blockBytes := block.Bytes

	var blockCipher cipher.Block
	var aead cipher.AEAD
	var err error

	switch strings.ToUpper(*cph) {
	case "AES":
		blockCipher, err = aes.NewCipher(key)
		if err != nil {
			panic(err.Error())
		}
	case "ANUBIS":
		blockCipher, err = anubis.New(key)
		if err != nil {
			panic(err.Error())
		}
	default:
		log.Fatal("cipher not supported")
	}

	switch strings.ToUpper(*mode) {
	case "GCM":
		aead, err = cipher.NewGCM(blockCipher)
	case "MGM":
		aead, err = mgm.NewMGM(blockCipher, 16)
	case "OCB", "OCB1":
		aead, err = ocb.NewOCB(blockCipher)
	case "OCB3":
		aead, err = ocb3.New(blockCipher)
	case "EAX":
		aead, err = eax.NewEAX(blockCipher)
	case "CCM":
		aead, err = ccm.NewCCM(blockCipher, 16, 12)
	default:
		log.Fatal("mode not supported")
	}

	if err != nil {
		log.Fatal(err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		panic(err.Error())
	}

	nonceHex := hex.EncodeToString(nonce)
	encryptedBytes := aead.Seal(nil, nonce, blockBytes, nil)

	newBlock := &pem.Block{
		Type:  block.Type,
		Bytes: encryptedBytes,
		Headers: map[string]string{
			"Proc-Type": "4,ENCRYPTED",
			"DEK-Info":  fmt.Sprintf("%s-%s,%s", strings.ToUpper(*cph), strings.ToUpper(*mode), nonceHex),
		},
	}

	if strings.ToUpper(*alg) == "EC-ELGAMAL" {
		newBlock.Headers["Curve"] = strings.ToUpper(*curveFlag)
	}

	return newBlock
}

func decryptBlock(block *pem.Block, key []byte) ([]byte, error) {
	blockBytes := block.Bytes

	dekInfo, ok := block.Headers["DEK-Info"]
	if !ok {
		return nil, fmt.Errorf("missing DEK-Info in PEM block header")
	}

	dekInfoParts := strings.Split(dekInfo, ",")
	if len(dekInfoParts) != 2 {
		return nil, fmt.Errorf("invalid DEK-Info format")
	}

	cipherModeParts := strings.Split(dekInfoParts[0], "-")
	if len(cipherModeParts) != 2 {
		return nil, fmt.Errorf("invalid cipher mode format in DEK-Info")
	}
	cipherName := cipherModeParts[0]
	mode := cipherModeParts[1]

	var blockCipher cipher.Block
	var err error

	switch cipherName {
	case "AES":
		blockCipher, err = aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
	case "ANUBIS":
		blockCipher, err = anubis.New(key)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("cipher not supported")
	}

	var aead cipher.AEAD

	switch strings.ToUpper(mode) {
	case "GCM":
		aead, err = cipher.NewGCM(blockCipher)
	case "MGM":
		aead, err = mgm.NewMGM(blockCipher, 16)
	case "OCB", "OCB1":
		aead, err = ocb.NewOCB(blockCipher)
	case "OCB3":
		aead, err = ocb3.New(blockCipher)
	case "EAX":
		aead, err = eax.NewEAX(blockCipher)
	case "CCM":
		aead, err = ccm.NewCCM(blockCipher, 16, 12)
	default:
		log.Fatal("mode not supported")
	}

	if err != nil {
		log.Fatal(err)
	}

	nonceHex := dekInfoParts[1]
	nonce, err := hex.DecodeString(nonceHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode nonce: %v", err)
	}

	decryptedBytes, err := aead.Open(nil, nonce, blockBytes, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt PEM block: %v", err)
	}

	return decryptedBytes, nil
}

func isHexDump(input string) bool {
	if strings.Contains(input, "|") {
		return false
	} else {
		return true
	}
}

func decodeHexDump(input string) ([]byte, error) {
	var decoded []byte
	var buffer bytes.Buffer

	lines := strings.Split(input, "\n")

	for _, line := range lines {
		if len(line) < 59 {
			continue
		}

		hexCharsInLine := line[9:58]
		hexCharsInLine = strings.ReplaceAll(hexCharsInLine, " ", "")
		buffer.WriteString(hexCharsInLine)
	}

	decoded, err := hex.DecodeString(buffer.String())
	if err != nil {
		return nil, err
	}

	return decoded, nil
}

func zeroByteSlice() []byte {
	return []byte{
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
	}
}
