/*
   EDGE Toolkit -- Pure Go Command-line Unique Integrated Security Suite
   Copyright (C) 2020-2025 Pedro F. Albanese <pedroalbanese@hotmail.com>

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
	"compress/zlib"
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
	"crypto/subtle"
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
	"golang.org/x/term"
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

	"crypto/go.cypherpunks.su/gogost/v6/gost3410"
	"gitee.com/Trisia/gotlcp/tlcp"
	"github.com/RyuaNerin/elliptic2/nist"
	"github.com/RyuaNerin/go-krypto/aria"
	"github.com/RyuaNerin/go-krypto/eckcdsa"
	"github.com/RyuaNerin/go-krypto/has160"
	"github.com/RyuaNerin/go-krypto/kx509"
	"github.com/RyuaNerin/go-krypto/lea"
	"github.com/RyuaNerin/go-krypto/lsh256"
	"github.com/RyuaNerin/go-krypto/lsh512"
	"github.com/deatil/go-cryptobin/cipher/clefia"
	"github.com/deatil/go-cryptobin/cipher/saferplus"
	"github.com/emmansun/certinfo"
	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm3"
	"github.com/emmansun/gmsm/sm4"
	"github.com/emmansun/gmsm/sm9"
	"github.com/emmansun/gmsm/smx509"
	"github.com/emmansun/gmsm/zuc"
	"github.com/emmansun/go-pkcs12"
	"github.com/kasperdi/SPHINCSPLUS-golang/parameters"
	"github.com/kasperdi/SPHINCSPLUS-golang/sphincs"
	"github.com/pedroalbanese/IGE-go/ige"
	"github.com/pedroalbanese/anubis"
	"github.com/pedroalbanese/bash"
	"github.com/pedroalbanese/belt"
	belthash "github.com/pedroalbanese/belt/hash/belt"
	"github.com/pedroalbanese/bign"
	bigncurves "github.com/pedroalbanese/bign/curves"
	"github.com/pedroalbanese/bip0340"
	"github.com/pedroalbanese/bls12381"
	"github.com/pedroalbanese/bls12381/ff"
	"github.com/pedroalbanese/bls12381/sign/bls"
	"github.com/pedroalbanese/bmw"
	"github.com/pedroalbanese/bn256"
	"github.com/pedroalbanese/brainpool"
	"github.com/pedroalbanese/camellia"
	"github.com/pedroalbanese/cast256"
	"github.com/pedroalbanese/cast5"
	"github.com/pedroalbanese/ccm"
	"github.com/pedroalbanese/cfb1"
	"github.com/pedroalbanese/cfb8"
	"github.com/pedroalbanese/cmac"
	"github.com/pedroalbanese/crypto/hc128"
	"github.com/pedroalbanese/crypto/hc256"
	"github.com/pedroalbanese/crypto/serpent"
	"github.com/pedroalbanese/crypton"
	"github.com/pedroalbanese/crystals-go/crystals-dilithium"
	"github.com/pedroalbanese/crystals-go/crystals-kyber"
	"github.com/pedroalbanese/cubehash"
	"github.com/pedroalbanese/cubehash256"
	"github.com/pedroalbanese/curupira1"
	"github.com/pedroalbanese/curve448/ed448"
	"github.com/pedroalbanese/curve448/x448"
	"github.com/pedroalbanese/e2"
	"github.com/pedroalbanese/eac"
	elgamalphp "github.com/pedroalbanese/eac/elgamal"
	"github.com/pedroalbanese/eax"
	"github.com/pedroalbanese/ecb"
	"github.com/pedroalbanese/ecgdsa"
	"github.com/pedroalbanese/echo"
	"github.com/pedroalbanese/ecsdsa"
	"github.com/pedroalbanese/esch"
	"github.com/pedroalbanese/frp256v1"
	"github.com/pedroalbanese/fugue"
	"github.com/pedroalbanese/gmac"
	"github.com/pedroalbanese/go-ascon"
	"github.com/pedroalbanese/go-chaskey"
	"github.com/pedroalbanese/go-external-ip"
	"github.com/pedroalbanese/go-grain"
	"github.com/pedroalbanese/go-idea"
	"github.com/pedroalbanese/go-kcipher2"
	"github.com/pedroalbanese/go-krcrypt"
	"github.com/pedroalbanese/go-misty1"
	"github.com/pedroalbanese/go-nums"
	"github.com/pedroalbanese/go-rc5"
	"github.com/pedroalbanese/go-ripemd"
	"github.com/pedroalbanese/gogost/gost28147"
	"github.com/pedroalbanese/gogost/gost34112012256"
	"github.com/pedroalbanese/gogost/gost34112012512"
	"github.com/pedroalbanese/gogost/gost341194"
	"github.com/pedroalbanese/gogost/gost341264"
	"github.com/pedroalbanese/gogost/mgm"
	"github.com/pedroalbanese/golang-rc6"
	"github.com/pedroalbanese/gopass"
	"github.com/pedroalbanese/groestl"
	"github.com/pedroalbanese/hamsi"
	"github.com/pedroalbanese/haraka"
	"github.com/pedroalbanese/jh"
	"github.com/pedroalbanese/kalyna"
	"github.com/pedroalbanese/khazad"
	"github.com/pedroalbanese/kupyna"
	"github.com/pedroalbanese/kuznechik"
	"github.com/pedroalbanese/loki97"
	"github.com/pedroalbanese/luffa"
	"github.com/pedroalbanese/lyra2re"
	"github.com/pedroalbanese/lyra2rev2"
	"github.com/pedroalbanese/magenta"
	"github.com/pedroalbanese/makwa-go"
	"github.com/pedroalbanese/mars"
	"github.com/pedroalbanese/md6"
	"github.com/pedroalbanese/noekeon"
	"github.com/pedroalbanese/ocb"
	"github.com/pedroalbanese/ocb3"
	"github.com/pedroalbanese/panama"
	"github.com/pedroalbanese/pmac"
	"github.com/pedroalbanese/present"
	"github.com/pedroalbanese/rabbitio"
	"github.com/pedroalbanese/radio_gatun"
	"github.com/pedroalbanese/randomart"
	"github.com/pedroalbanese/rc2"
	"github.com/pedroalbanese/secp256k1"
	"github.com/pedroalbanese/shacal2"
	"github.com/pedroalbanese/shavite"
	"github.com/pedroalbanese/simd"
	"github.com/pedroalbanese/simpleini"
	"github.com/pedroalbanese/siphash"
	"github.com/pedroalbanese/siv"
	"github.com/pedroalbanese/skein"
	skeincipher "github.com/pedroalbanese/skein-1"
	"github.com/pedroalbanese/spritz"
	"github.com/pedroalbanese/threefish"
	"github.com/pedroalbanese/tiger"
	"github.com/pedroalbanese/tom"
	"github.com/pedroalbanese/trivium"
	"github.com/pedroalbanese/twine"
	"github.com/pedroalbanese/uuencode"
	"github.com/pedroalbanese/vmac"
	"github.com/pedroalbanese/whirlpool"
	"github.com/pedroalbanese/xoodoo/xoodyak"
	"github.com/pedroalbanese/xxencode"
	"github.com/zeebo/blake3"
)

var (
	alg            = flag.String("algorithm", "RSA", "Public key algorithm: EC, Ed25519, GOST2012, SM2.")
	cacert         = flag.String("cacert", "", "CA Certificate path. (for TLCP Protocol)")
	cakey          = flag.String("cakey", "", "CA Private key. (for TLCP Protocol)")
	change         = flag.Bool("change", false, "Change Passphrase of a Private Key.")
	cert           = flag.String("cert", "", "Certificate path.")
	check          = flag.Bool("check", false, "Check hashsum file. ('-' for STDIN)")
	cph            = flag.String("cipher", "aes", "Symmetric algorithm: aes, blowfish, magma or sm4.")
	crl            = flag.String("crl", "", "Certificate Revocation List path.")
	crypt          = flag.String("crypt", "", "Bulk Encryption with Stream and Block ciphers. [enc|dec|help]")
	curveFlag      = flag.String("curve", "", "Subjacent curve. (secp256r1, secp256k1, numsp256t1)")
	digest         = flag.Bool("digest", false, "Target file/wildcard to generate hashsum list. ('-' for STDIN)")
	encode         = flag.String("hex", "", "Encode binary string to hex format and vice-versa. [enc|dump|dec]")
	b85            = flag.String("base85", "", "Encode binary string to Base85 format and vice-versa. [enc|dec]")
	b64            = flag.String("base64", "", "Encode binary string to Base64 format and vice-versa. [enc|dec]")
	b32            = flag.String("base32", "", "Encode binary string to Base32 format and vice-versa. [enc|dec]")
	zz             = flag.String("zlib", "", "Compress string with zlib algorithm and vice-versa. [enc|dec]")
	days           = flag.Int("days", 0, "Defines the validity of the certificate from the date of creation.")
	factorPStr     = flag.String("factorp", "", "Makwa private Factor P. (for Makwa Password-hashing Scheme)")
	factorQStr     = flag.String("factorq", "", "Makwa private Factor Q. (for Makwa Password-hashing Scheme)")
	hierarchy      = flag.Uint("hid", 0x01, "Hierarchy Identifier. (for IBE/IBS User Private Key)")
	id             = flag.String("id", "", "User Identifier. (for IBE/IBS User Private Key operations)")
	id2            = flag.String("peerid", "", "Remote's side User Identifier. (for SM9 Key Exchange)")
	info           = flag.String("info", "", "Additional info. (for HKDF command and AEAD bulk encryption)")
	iport          = flag.String("ipport", "", "Local Port/remote's side Public IP:Port.")
	isca           = flag.Bool("isca", false, "The requested CSR is for a Certificate Authority (CA).")
	iter           = flag.Int("iter", 1, "Iter. (for Password-based key derivation function)")
	kdf            = flag.String("kdf", "", "Key derivation function. [pbkdf2|hkdf|scrypt|argon2|lyra2re2]")
	key            = flag.String("key", "", "Asymmetric key, symmetric key or HMAC key, depending on operation.")
	length         = flag.Int("bits", 0, "Key length. (for keypair generation and symmetric encryption)")
	mac            = flag.String("mac", "", "Compute Hash/Cipher-based message authentication code.")
	master         = flag.String("master", "Master.pem", "Master key path. (for sm9 setup)")
	md             = flag.String("md", "sha256", "Hash algorithm: sha256, sha3-256 or whirlpool.")
	mode           = flag.String("mode", "CTR", "Mode of operation: GCM, MGM, CBC, CFB8, OCB, OFB.")
	modulusStr     = flag.String("modulus", "", "Makwa modulus. (Makwa hash Public Parameter)")
	paramset       = flag.String("paramset", "A", "Elliptic curve ParamSet: A, B, C, D. (for GOST2012)")
	params         = flag.String("params", "", "ElGamal Public Parameters path.")
	pkey           = flag.String("pkey", "", "Subcommands: keygen|certgen, sign|verify|derive, text|modulus.")
	priv           = flag.String("prv", "Private.pem", "Private key path. (for keypair generation)")
	pub            = flag.String("pub", "Public.pem", "Public key path. (for keypair generation)")
	pub2           = flag.String("pub2", "", "Public key 2 path. (for keypair generation)")
	pwd            = flag.String("pass", "", "Password/Passphrase. (for Private key PEM encryption)")
	pwd2           = flag.String("passout", "", "User Password. (for SM9 User Private Key PEM encryption)")
	random         = flag.Int("rand", 0, "Generate random cryptographic key with given bit length.")
	recover        = flag.Bool("recover", false, "Recover Passphrase from Makwa hash with Private Parameters.")
	recursive      = flag.Bool("recursive", false, "Process directories recursively. (for DIGEST command only)")
	root           = flag.String("root", "", "Root CA Certificate path.")
	salt           = flag.String("salt", "", "Salt. (for HKDF and PBKDF2 commands)")
	seedStr        = flag.String("seed", "", "Seed. (for ML-KEM and ML-DSA key generation)")
	sig            = flag.String("signature", "", "Input signature. (for VERIFY command and MAC verification)")
	subj           = flag.String("subj", "", "Subject: Identity. (Example: \"/CN=/OU=/O=/ST=/L=/C=/emailAddress=\")")
	tcpip          = flag.String("tcp", "", "Encrypted TCP/IP Transfer Protocol. [server|ip|client]")
	tweakStr       = flag.String("tweak", "", "Additional 128-bit parameter input. (for THREEFISH encryption)")
	vector         = flag.String("iv", "", "Initialization Vector. (for symmetric encryption)")
	col            = flag.Int("wrap", 64, "Wrap lines after N columns. (for Base64/32 encoding)")
	pad            = flag.Bool("nopad", false, "No padding. (for Base64 and Base32 encoding)")
	version        = flag.Bool("version", false, "Print version info.")
	commitmentFlag = flag.String("commitment", "", "Commitment for the proof. (for Zero-Knowledge Proof ZKP)")
	challengeFlag  = flag.String("challenge", "", "Challenge for the proof. (for Zero-Knowledge Proof ZKP)")
	responseFlag   = flag.String("response", "", "Response for the proof. (for Zero-Knowledge Proof ZKP)")
	scheme         = flag.String("scheme", "", "Subjacent Scheme. (for Identity-Based Cryptography IBE/IBS)")
	token          = flag.String("token", "", "Token containing an encrypted symmetric key.")
	xx             = flag.String("xx", "", "Encode binary files with xxencoding and vice-versa. [enc|dec]")
	uu             = flag.String("uu", "", "Encode binary files with uuencoding and vice-versa. [enc|dec]")
)

func loadDefaultsFromINI(path string) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()

	ini, err := simpleini.Parse(file)
	if err != nil {
		log.Fatalf("Failed to parse INI file: %v", err)
	}

	section := "Defaults"

	setStringFlag := func(flagVar *string, key string) {
		val, err := ini.GetString(section, key)
		if err == nil && val != "" {
			*flagVar = val
		}
	}

	setIntFlag := func(flagVar *int, key string) {
		val, err := ini.GetString(section, key)
		if err == nil && val != "" {
			if n, err := strconv.Atoi(val); err == nil {
				*flagVar = n
			}
		}
	}

	setStringFlag(alg, "algorithm")
	setStringFlag(cph, "cipher")
	setStringFlag(mode, "mode")
	setStringFlag(md, "md")
	setIntFlag(days, "days")
}

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
	oidPublicKeyElGamal             = asn1.ObjectIdentifier{1, 3, 14, 7, 2, 1, 1}
)

func handleConnectionTLS(c net.Conn) {
	log.Printf("Client(TLS) %v connected via secure channel.", c.RemoteAddr())
}

func handleConnectionTLCP(c net.Conn) {
	log.Printf("Client(TLCP) %v connected via secure channel.", c.RemoteAddr())
}

func main() {
	var pubs PubPaths
	var msgs MsgsPaths
	var keys KeysPaths
	flag.Var(&pubs, "pubs", "Paths to the public keys. (can be passed multiple times)")
	flag.Var(&msgs, "msgs", "Messages to be verified. (can be passed multiple times)")
	flag.Var(&keys, "keys", "Key to be combined. (can be passed multiple times)")

	const iniFile = "edgetk.ini"
	loadDefaultsFromINI(iniFile)

	flag.Parse()

	if *version {
		fmt.Println("EDGE Toolkit v1.5.12  18 Sep 2025")
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
  bign/dbign        eckcdsa           gost2012          sm2[ph]
  bip0340           ecsdsa            koblitz           sm9sign
  bls12381[i]       ed25519[ph]       ml-dsa            sm9encrypt
  bn256[i]          ed448[ph]         ml-kem            slh-dsa
  ecdsa             elgamal           rsa (default)     x25519
  ecgdsa            ec-elgamal        schnorr           x448

Subjacent Elliptic Curves:
  secp224r1         brainpoolp256r1   numsp384t1        GOST256 Paramset A
  secp256r1         brainpoolp384r1   numsp512t1        GOST256 Paramset B
  secp384r1         brainpoolp512r1   tom256            GOST256 Paramset C
  secp521r1         brainpoolp256t1   tom384            GOST256 Paramset D
  sect283r1         brainpoolp384t1   bls12381          GOST512 Paramset A
  sect409r1         brainpoolp512t1   ed25519           GOST512 Paramset B
  sect571r1         numsp256d1        pallas            GOST512 Paramset C
  sect283k1         numsp384d1        frp256v1          bign256v1
  sect409k1         numsp512d1        secp256k1         bign384v1
  sect571k1         numsp256t1        sm2p256v1         bign512v1

Stream Ciphers:
  ascon (aead)      grain128a         rabbit            spritz
  chacha20          hc128             rc4 [obsolete]    trivium
  chacha20poly1305  hc256             salsa20           zuc128/eea128
  grain (aead)      kcipher2          skein             zuc256/eea256

Modes of Operation:
  eax (aead)        siv (aead)        cbc               ecb
  gcm (aead)        mgm (aead)        cfb/cfb1/cfb8     ige
  ocb1/3 (aead)     ccm (aead)        ctr (default)     ofb

Block Ciphers:
  3des              curupira          kuznechik         rc6
  aes (default)     e2                lea               safer+
  anubis            gost89            loki97            seed
  aria              hight             magenta           serpent
  belt              idea [obsolete]   magma             shacal2
  blowfish          kalyna128_128     mars              sm4
  camellia          kalyna128_256     misty1            threefish256
  cast5             kalyna256_256     noekeon           threefish512
  cast256           kalyna256_512     present           threefish1024
  clefia            kalyna512_512     rc2 [obsolete]    twine
  crypton           khazad            rc5               twofish

Key Derivation Functions:
  hkdf              pbkdf2            scrypt            gost
  argon2            blake3            lyra2re/2         help

Password Hash Functions:
  argon2            bcrypt            lyra2re/2         makwa

Message Athentication Code:
  blake3            gost [legacy]     pmac              vmac
  chaskey           hmac              poly1305          xoodyak
  cmac              kmac              siphash           zuc128/eia128
  gmac              mgmac             skein             zuc256/eia256

Message Digests:
  bash224           fugue512          lsh512            sha3-224
  bash256           gost94            lsh512-224        sha3-256
  bash384           groestl224        lsh512-256        sha3-384
  bash512           groestl256        luffa224          sha3-512
  belt              groestl384        luffa256          shake128
  blake2b256        groestl512        luffa384          shake256
  blake2b512        hamsi224          luffa512          shavite224
  blake2s128 (MAC)  hamsi256          md4 [obsolete]    shavite256
  blake2s256        hamsi384          md5 [obsolete]    shavite384
  blake3            hamsi512          md6-224           shavite512
  bmw224            haraka256         md6-256           simd224
  bmw256            haraka512         md6-384           simd256
  bmw384            has160 [obsolete] md6-512           simd384
  bmw512            jh224             radiogatun32      simd512
  cubehash256       jh256             radiogatun64      siphash64
  cubehash512       jh384             ripemd128         siphash
  echo224           jh512             ripemd160         skein256
  echo256           keccak256         ripemd256         skein512
  echo384           keccak512         ripemd320         sm3
  echo512           kupyna256         sha1 [obsolete]   streebog256
  esch256           kupyna384         sha224            streebog512
  esch384           kupyna512         sha256 (default)  tiger
  fugue224          lsh224            sha384            tiger2
  fugue256          lsh256            sha512            whirlpool
  fugue384          lsh384            sha512-256        xoodyak`)
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
  hkdf, pbkdf2, scrypt, argon2, lyra2re, lyra2re2, gost (streebog)

 HKDF:
  edgetk -kdf hkdf [-bits N] [-salt "SALT"] [-info "AAD"] [-key "IKM"]

 Argon2:
  edgetk -kdf argon2 [-bits N] [-salt "SALT"] [-iter N] [-key "PASSPHRASE"]

 GOST:
  edgetk -kdf streebog [-bits N] [-salt "SALT"] [-info "AAD"] [-key "IKM"]

 Lyra2:
  edgetk -kdf lyra2re [-bits N] [-salt "SALT"] [-iter N] [-key "PASSPHRASE"]

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
  edgetk -pkey keygen [-algorithm <alg>] [-prv <private>] [-pub <public>]

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
  edgetk -pkey <text|modulus|randomart|fingerprint> [-key <public.pem>]

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

 For non-interactive scripts, you must use the flags -pass, -days and -subj:
  -pass "passphrase"
  -days 365
  -subj "/CN=Test/OU=/O=/ST=/L=/C=/emailAddress=test@test.com"

 Derive Shared Secret:
  edgetk -pkey <derive|vko|x25519> [-key <privatekey>] [-pub <peerkey>]

 Digital Signature:
  edgetk -pkey <sign|verify> [-algorithm <alg>] [-key <private|public>]
  [-md sha256] [-signature <signature>] FILE.ext

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
  
  IPv4:
  edgetk -tcp server -cert cert.pem -key priv.pem [-ipport "8081"]
  edgetk -tcp client -cert cert.pem -key priv.pem [-ipport "127.0.0.1:8081"]
  
  IPv6:
  edgetk -tcp server -cert cert.pem -key priv.pem [-ipport "8081"]
  edgetk -tcp client -cert cert.pem -key priv.pem [-ipport "[2001::1]:8081"]`)
		os.Exit(3)
	}

	if (*pkey == "keygen") && (*alg != "sm9encrypt" && *alg != "sm9sign" && *alg != "bn256" && *alg != "bn256sign" && *alg != "bn256encrypt" && *alg != "bls12381" && *alg != "bls12381sign" && *alg != "bls12381encrypt" && *alg != "egphp" && *alg != "elgamalphp") && *pwd == "" {
		print("Passphrase: ")
		pass, _ := gopass.GetPasswdMasked()
		*pwd = string(pass)
	} else if (*pkey == "keygen") && (*alg != "sm9encrypt" && *alg != "sm9sign") && *pwd == "nil" {
		*pwd = ""
	}

	if (*pkey == "setup" || *pkey == "setup-threshold") && *key != "" && (strings.ToUpper(*alg) != "ELGAMAL" && strings.ToUpper(*alg) != "SCHNORR") {
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

	if (*pkey == "setup") && *key != "" && (strings.ToUpper(*alg) != "ELGAMAL" && strings.ToUpper(*alg) != "SCHNORR") {
		print("New MasterKey Passphrase: ")
		pass, _ := gopass.GetPasswdMasked()
		*pwd2 = string(pass)
	}

	if (*pkey == "setup") && *pwd == "" && (strings.ToUpper(*alg) != "ELGAMAL" && strings.ToUpper(*alg) != "SCHNORR") {
		print("Passphrase: ")
		pass, _ := gopass.GetPasswdMasked()
		*pwd = string(pass)
	} else if (*pkey == "setup") && *pwd == "nil" && (strings.ToUpper(*alg) != "ELGAMAL" && strings.ToUpper(*alg) != "SCHNORR") {
		*pwd = ""
	}

	if *token != "" {
		if info, err := os.Stat(*token); err != nil || info.Size() == 0 {
			print("Enter a new PIN: ")
			pin, _ := gopass.GetPasswdMasked()

			encryptedKey, err := encryptKey([]byte(*key), string(pin))
			if err != nil {
				log.Fatal("Error encrypting key:", err)
			}

			err = os.WriteFile(*token, []byte(encryptedKey), 0600)
			if err != nil {
				log.Fatal("Error writing to token file:", err)
			}

			fmt.Println("Encrypted key saved successfully.")
		} else {
			print("Enter PIN: ")
			pin, err := term.ReadPassword(int(os.Stdin.Fd()))
			if err != nil {
				log.Fatal("Error reading PIN:", err)
			}
			println()

			encryptedKeyBytes, err := os.ReadFile(*token)
			if err != nil {
				log.Fatal("Error reading token file:", err)
			}

			encryptedKey := string(encryptedKeyBytes)

			decryptedKey, err := decryptKey(encryptedKey, string(pin))
			if err != nil {
				log.Fatal("Error decrypting key:", err)
			}

			*key = string(decryptedKey)
		}
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

	if (*pkey == "keygen-threshold") && *pwd == "" {
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
			print("ShareKey Passphrase: ")
			pass, _ := gopass.GetPasswd()
			*pwd = string(pass)
		}
	}

	if (*pkey == "keygen") && (*alg == "bn256" || *alg == "bn256encrypt" || *alg == "bn256sign" || *alg == "bls12381" || *alg == "bls12381sign" || *alg == "bls12381encrypt") && *pwd == "" {
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
	} else if (*pkey == "keygen") && (*alg == "sm9encrypt" || *alg == "sm9sign") && *pwd2 == "nil" {
		*pwd2 = ""
	}

	if (*pkey == "keygen") && (*alg == "bn256" || *alg == "bn256encrypt" || *alg == "bn256sign" || *alg == "bls12381" || *alg == "bls12381sign" || *alg == "bls12381encrypt") && *pwd2 == "" {
		print("UserKey Passphrase: ")
		pass, _ := gopass.GetPasswdMasked()
		*pwd2 = string(pass)
	} else if (*pkey == "keygen") && (*alg == "bn256" || *alg == "bls12381") && *pwd2 == "nil" {
		*pwd2 = ""
	}

	if (*pkey == "combine-threshold") && *pwd == "" {
		print("Passphrase: ")
		pass, _ := gopass.GetPasswdMasked()
		*pwd = string(pass)
	}

	if *pkey == "keygen" {
		if data, err := ioutil.ReadFile(*params); err == nil {
			if block, _ := pem.Decode(data); block != nil {
				if strings.Contains(block.Type, "SCHNORR") {
					*alg = "SCHNORR"
				} else if strings.Contains(block.Type, "ELGAMAL") {
					*alg = "ELGAMAL"
				}
			}
		}
	}

	if (*pkey == "sign" || *pkey == "decrypt" || *pkey == "derive" || *pkey == "derive-scalar" || *pkey == "aggregate" || *pkey == "proof" || *pkey == "derivea" || *pkey == "unwrapkey" || *pkey == "deriveb" || *pkey == "certgen" || *pkey == "text" || *pkey == "modulus" || *tcpip == "server" || *tcpip == "client" || *pkey == "pkcs12" || *pkey == "req" || *pkey == "x509" || *pkey == "x25519" || *pkey == "x448" || *pkey == "vko" || *pkey == "crl") && (*key != "" && strings.ToUpper(*alg) != "EGPHP" && strings.ToUpper(*alg) != "ELGAMALPHP") && *pwd == "" {
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
			pass, err := term.ReadPassword(int(os.Stdin.Fd()))
			if err != nil {
				log.Fatal("Error reading PIN:", err)
			}
			println()
			*pwd = string(pass)
		}
	}

	if (*tcpip == "server" || *tcpip == "client") && (*alg == "sm2") && (*key != "") && *pwd2 == "" {
		file, err := os.Open(*cakey)
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
			print("EncKey Passphrase: ")
			pass, _ := gopass.GetPasswd()
			*pwd2 = string(pass)
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
	switch *md {
	case "sha224":
		myHash = sha256.New224
	case "sha256":
		myHash = sha256.New
	case "sha384":
		myHash = sha512.New384
	case "sha512":
		myHash = sha512.New
	case "sha512-256":
		myHash = sha512.New512_256
	case "sha1":
		myHash = sha1.New
	case "rmd160", "ripemd160":
		myHash = ripemd160.New
	case "rmd128", "ripemd128":
		myHash = ripemd.New128
	case "rmd256", "ripemd256":
		myHash = ripemd.New256
	case "rmd320", "ripemd320":
		myHash = ripemd.New320
	case "sha3-224":
		myHash = sha3.New224
	case "sha3-256":
		myHash = sha3.New256
	case "sha3-384":
		myHash = sha3.New384
	case "sha3-512":
		myHash = sha3.New512
	case "keccak", "keccak256":
		myHash = sha3.NewLegacyKeccak256
	case "keccak512":
		myHash = sha3.NewLegacyKeccak512
	case "shake128":
		myHash = func() hash.Hash {
			return sha3.NewShake128()
		}
	case "shake256":
		myHash = func() hash.Hash {
			return sha3.NewShake256()
		}
	case "lsh224", "lsh256-224":
		myHash = lsh256.New224
	case "lsh", "lsh256", "lsh256-256":
		myHash = lsh256.New
	case "lsh512-256":
		myHash = lsh512.New256
	case "lsh512-224":
		myHash = lsh512.New224
	case "lsh384", "lsh512-384":
		myHash = lsh512.New384
	case "lsh512":
		myHash = lsh512.New
	case "has160":
		myHash = has160.New
	case "whirlpool":
		myHash = whirlpool.New
	case "blake2b256":
		myHash = crypto.BLAKE2b_256.New
	case "blake2b512":
		myHash = crypto.BLAKE2b_512.New
	case "blake2s256":
		myHash = crypto.BLAKE2s_256.New
	case "blake3":
		myHash = func() hash.Hash {
			return blake3.New()
		}
	case "md5":
		myHash = md5.New
	case "gost94":
		myHash = func() hash.Hash {
			return gost341194.New(&gost28147.SboxIdGostR341194CryptoProParamSet)
		}
	case "streebog", "streebog256":
		myHash = gost34112012256.New
	case "streebog512":
		myHash = gost34112012512.New
	case "sm3":
		myHash = sm3.New
	case "md4":
		myHash = md4.New
	case "cubehash", "cubehash512":
		myHash = cubehash.New
	case "cubehash256":
		myHash = cubehash256.New
	case "xoodyak", "xhash":
		myHash = xoodyak.NewXoodyakHash
	case "skein", "skein256":
		myHash = func() hash.Hash {
			return skein.New256(nil)
		}
	case "skein512":
		myHash = func() hash.Hash {
			return skein.New512(nil)
		}
	case "jh224":
		myHash = jh.New224
	case "jh", "jh256":
		myHash = jh.New256
	case "jh384":
		myHash = jh.New384
	case "jh512":
		myHash = jh.New512
	case "groestl224":
		myHash = groestl.New224
	case "groestl", "groestl256":
		myHash = groestl.New256
	case "groestl384":
		myHash = groestl.New384
	case "groestl512":
		myHash = groestl.New512
	case "tiger":
		myHash = tiger.New
	case "tiger2":
		myHash = tiger.New2
	case "kupyna256", "kupyna":
		myHash = kupyna.New256
	case "kupyna384":
		myHash = kupyna.New384
	case "kupyna512":
		myHash = kupyna.New512
	case "echo224":
		myHash = echo.New224
	case "echo", "echo256":
		myHash = echo.New256
	case "echo384":
		myHash = echo.New384
	case "echo512":
		myHash = echo.New512
	case "esch", "esch256":
		myHash = esch.New256
	case "esch384":
		myHash = esch.New384
	case "bmw224":
		myHash = bmw.New224
	case "bmw", "bmw256":
		myHash = bmw.New256
	case "bmw384":
		myHash = bmw.New384
	case "bmw512":
		myHash = bmw.New512
	case "hamsi224":
		myHash = hamsi.New224
	case "hamsi", "hamsi256":
		myHash = hamsi.New256
	case "hamsi384":
		myHash = hamsi.New384
	case "hamsi512":
		myHash = hamsi.New512
	case "fugue224":
		myHash = fugue.New224
	case "fugue", "fugue256":
		myHash = fugue.New256
	case "fugue384":
		myHash = fugue.New384
	case "fugue512":
		myHash = fugue.New512
	case "luffa224":
		myHash = luffa.New224
	case "luffa", "luffa256":
		myHash = luffa.New256
	case "luffa384":
		myHash = luffa.New384
	case "luffa512":
		myHash = luffa.New512
	case "shavite224":
		myHash = shavite.New224
	case "shavite", "shavite256":
		myHash = shavite.New256
	case "shavite384":
		myHash = shavite.New384
	case "shavite512":
		myHash = shavite.New512
	case "simd224":
		myHash = simd.New224
	case "simd", "simd256":
		myHash = simd.New256
	case "simd384":
		myHash = simd.New384
	case "simd512":
		myHash = simd.New512
	case "radiogatun", "radiogatun32":
		myHash = radio_gatun.New32
	case "radiogatun64":
		myHash = radio_gatun.New64
	case "md6-224":
		myHash = md6.New224
	case "md6", "md6-256":
		myHash = md6.New256
	case "md6-384":
		myHash = md6.New384
	case "md6-512":
		myHash = md6.New512
	case "belt":
		myHash = belthash.New
	case "bash224":
		myHash = bash.New224
	case "bash", "bash256":
		myHash = bash.New256
	case "bash384":
		myHash = bash.New384
	case "bash512":
		myHash = bash.New512
	case "haraka", "haraka256", "haraka512":
	case "bcrypt", "lyra2re", "lyra2re2", "argon2":
	case "blake2s128":
	case "siphash", "siphash64", "siphash128":
	default:
		log.Fatalf("Message digest type %s not recognized", *md)
	}

	var h hash.Hash
	switch *md {
	case "sha224":
		h = sha256.New224()
	case "sha256":
		h = sha256.New()
	case "sha384":
		h = sha512.New384()
	case "sha512-256":
		h = sha512.New512_256()
	case "sha512":
		h = sha512.New()
	case "sha1":
		h = sha1.New()
	case "rmd160", "ripemd160":
		h = ripemd160.New()
	case "rmd128", "ripemd128":
		h = ripemd.New128()
	case "rmd256", "ripemd256":
		h = ripemd.New256()
	case "rmd320", "ripemd320":
		h = ripemd.New320()
	case "sha3-224":
		h = sha3.New224()
	case "sha3-256":
		h = sha3.New256()
	case "sha3-384":
		h = sha3.New384()
	case "sha3-512":
		h = sha3.New512()
	case "shake128":
		h = sha3.NewShake128()
	case "shake256":
		h = sha3.NewShake256()
	case "lsh224", "lsh256-224":
		h = lsh256.New224()
	case "lsh", "lsh256", "lsh256-256":
		h = lsh256.New()
	case "lsh512-224":
		h = lsh512.New224()
	case "lsh512-256":
		h = lsh512.New256()
	case "lsh384", "lsh512-384":
		h = lsh512.New384()
	case "lsh512":
		h = lsh512.New()
	case "has160":
		h = has160.New()
	case "keccak", "keccak256":
		h = sha3.NewLegacyKeccak256()
	case "keccak512":
		h = sha3.NewLegacyKeccak512()
	case "whirlpool":
		h = whirlpool.New()
	case "blake2b256":
		h, _ = blake2b.New256([]byte(*key))
	case "blake2b512":
		h, _ = blake2b.New512([]byte(*key))
	case "blake2s128":
		h, _ = blake2s.New128([]byte(*key))
	case "blake2s256":
		h, _ = blake2s.New256([]byte(*key))
	case "blake3":
		h = blake3.New()
	case "md5":
		h = md5.New()
	case "gost94":
		h = gost341194.New(&gost28147.SboxIdGostR341194CryptoProParamSet)
	case "streebog", "streebog256":
		h = gost34112012256.New()
	case "streebog512":
		h = gost34112012512.New()
	case "sm3":
		h = sm3.New()
	case "md4":
		h = md4.New()
	case "siphash", "siphash128":
		var xkey [16]byte
		copy(xkey[:], []byte(*key))
		h, _ = siphash.New128(xkey[:])
	case "siphash64":
		var xkey [16]byte
		copy(xkey[:], []byte(*key))
		h, _ = siphash.New64(xkey[:])
	case "cubehash", "cubehash512":
		h = cubehash.New()
	case "xoodyak", "xhash":
		h = xoodyak.NewXoodyakHash()
	case "skein", "skein256":
		h = skein.New256([]byte(*key))
	case "skein512":
		h = skein.New512([]byte(*key))
	case "jh224":
		h = jh.New224()
	case "jh", "jh256":
		h = jh.New256()
	case "jh384":
		h = jh.New384()
	case "jh512":
		h = jh.New512()
	case "groestl224":
		h = groestl.New224()
	case "groestl", "groestl256":
		h = groestl.New256()
	case "groestl384":
		h = groestl.New384()
	case "groestl512":
		h = groestl.New512()
	case "tiger":
		h = tiger.New()
	case "tiger2":
		h = tiger.New2()
	case "kupyna256", "kupyna":
		h = kupyna.New256()
	case "kupyna384":
		h = kupyna.New384()
	case "kupyna512":
		h = kupyna.New512()
	case "echo224":
		h = echo.New224()
	case "echo", "echo256":
		h = echo.New256()
	case "echo384":
		h = echo.New384()
	case "echo512":
		h = echo.New512()
	case "esch", "esch256":
		h = esch.New256()
	case "esch384":
		h = esch.New384()
	case "bmw224":
		h = bmw.New224()
	case "bmw", "bmw256":
		h = bmw.New256()
	case "bmw384":
		h = bmw.New384()
	case "bmw512":
		h = bmw.New512()
	case "cubehash256":
		h = cubehash256.New()
	case "hamsi224":
		h = hamsi.New224()
	case "hamsi", "hamsi256":
		h = hamsi.New256()
	case "hamsi384":
		h = hamsi.New384()
	case "hamsi512":
		h = hamsi.New512()
	case "fugue224":
		h = fugue.New224()
	case "fugue", "fugue256":
		h = fugue.New256()
	case "fugue384":
		h = fugue.New384()
	case "fugue512":
		h = fugue.New512()
	case "luffa224":
		h = luffa.New224()
	case "luffa", "luffa256":
		h = luffa.New256()
	case "luffa384":
		h = luffa.New384()
	case "luffa512":
		h = luffa.New512()
	case "shavite224":
		h = shavite.New224()
	case "shavite", "shavite256":
		h = shavite.New256()
	case "shavite384":
		h = shavite.New384()
	case "shavite512":
		h = shavite.New512()
	case "simd224":
		h = simd.New224()
	case "simd", "simd256":
		h = simd.New256()
	case "simd384":
		h = simd.New384()
	case "simd512":
		h = simd.New512()
	case "radiogatun", "radiogatun32":
		h = radio_gatun.New32()
	case "radiogatun64":
		h = radio_gatun.New64()
	case "md6-224":
		h = md6.New224()
	case "md6", "md6-256":
		h = md6.New256()
	case "md6-384":
		h = md6.New384()
	case "md6-512":
		h = md6.New512()
	case "belt":
		h = belthash.New()
	case "bash224":
		h = bash.New224()
	case "bash", "bash256":
		h = bash.New256()
	case "bash384":
		h = bash.New384()
	case "bash512":
		h = bash.New512()
	case "haraka", "haraka256", "haraka512":
	case "bcrypt", "lyra2re", "lyra2re2", "argon2":
	default:
		log.Fatalf("Message digest type %s not recognized", *md)
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

	if (strings.ToUpper(*alg) == "ELGAMALPHP" || strings.ToUpper(*alg) == "EGPHP") && flag.Arg(0) != "" {
		inputfile, err = os.Open(flag.Arg(0))
		if err != nil {
			log.Fatalf("failed opening file: %s", err)
		}
	} else if (strings.ToUpper(*alg) == "ELGAMALPHP" || strings.ToUpper(*alg) == "EGPHP") && flag.Arg(0) == "" {
		inputfile = os.Stdin
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
		o = append(o, '\n')
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

	if *zz == "enc" || *zz == "dec" {
		var inputData []byte

		data, err := ioutil.ReadAll(inputfile)
		if err != nil {
			fmt.Println("Error reading the file:", err)
			os.Exit(1)
		}
		inputData = data

		if *zz == "enc" {
			compressed, err := compressZlib(inputData)
			if err != nil {
				fmt.Println("Compression error:", err)
				os.Exit(1)
			}
			os.Stdout.Write(compressed)
		} else {
			decompressed, err := decompressZlib(inputData)
			if err != nil {
				fmt.Println("Decompression error:", err)
				os.Exit(1)
			}
			os.Stdout.Write(decompressed)
		}
	}

	if *xx == "enc" {
		mw := xxencode.NewMultiWriter(os.Stdout)
		defer mw.Close()

		for _, inputdesc := range flag.Args() {
			infile, err := os.Open(inputdesc)
			if err != nil {
				log.Fatal(err)
			}

			info, err := infile.Stat()
			if err != nil {
				infile.Close()
				log.Fatal(err)
			}

			if err := mw.WriteFile(inputdesc, info.Mode(), infile); err != nil {
				infile.Close()
				log.Fatal(err)
			}
			infile.Close()
		}
	} else if *xx == "dec" {
		if len(flag.Args()) == 0 {
			log.Fatal("No input file specified for decoding")
		}

		for _, inputdesc := range flag.Args() {
			infile, err := os.Open(inputdesc)
			if err != nil {
				log.Fatal(err)
			}
			defer infile.Close()

			mr := xxencode.NewMultiReader(infile)

			for {
				fileInfo, reader, err := mr.Next()
				if err == io.EOF {
					break
				}
				if err != nil {
					log.Fatal(err)
				}

				outfile, err := os.Create(fileInfo.Name)
				if err != nil {
					log.Fatal(err)
				}

				if _, err := io.Copy(outfile, reader); err != nil {
					outfile.Close()
					log.Fatal(err)
				}

				if err := outfile.Chmod(fileInfo.Mode); err != nil {
					log.Println("Warning: could not set file mode:", err)
				}
				outfile.Close()

				fmt.Fprintf(os.Stderr, "file: %s, mode: %03o\n", fileInfo.Name, fileInfo.Mode)
			}
		}
	}

	if *uu == "enc" {
		mw := uuencode.NewMultiWriter(os.Stdout)
		defer mw.Close()

		for _, inputdesc := range flag.Args() {
			infile, err := os.Open(inputdesc)
			if err != nil {
				log.Fatal(err)
			}

			info, err := infile.Stat()
			if err != nil {
				infile.Close()
				log.Fatal(err)
			}

			if err := mw.WriteFile(inputdesc, info.Mode(), infile); err != nil {
				infile.Close()
				log.Fatal(err)
			}
			infile.Close()
		}
	} else if *uu == "dec" {
		if len(flag.Args()) == 0 {
			log.Fatal("No input file specified for decoding")
		}

		for _, inputdesc := range flag.Args() {
			infile, err := os.Open(inputdesc)
			if err != nil {
				log.Fatal(err)
			}
			defer infile.Close()

			mr := uuencode.NewMultiReader(infile)

			for {
				fileInfo, reader, err := mr.Next()
				if err == io.EOF {
					break
				}
				if err != nil {
					log.Fatal(err)
				}

				outfile, err := os.Create(fileInfo.Name)
				if err != nil {
					log.Fatal(err)
				}

				if _, err := io.Copy(outfile, reader); err != nil {
					outfile.Close()
					log.Fatal(err)
				}

				if err := outfile.Chmod(fileInfo.Mode); err != nil {
					log.Println("Warning: could not set file mode:", err)
				}
				outfile.Close()

				fmt.Fprintf(os.Stderr, "file: %s, mode: %03o\n", fileInfo.Name, fileInfo.Mode)
			}
		}
	}

	if (*cph == "aes" || *cph == "aria" || *cph == "mars" || *cph == "cast256" || *cph == "cast6" || *cph == "clefia" || *cph == "kalyna128_256" || *cph == "kalyna256_256" || *cph == "crypton" || *cph == "e2" || *cph == "loki97" || *cph == "grasshopper" || *cph == "kuznechik" || *cph == "magma" || *cph == "gost89" || *cph == "camellia" || *cph == "chacha20poly1305" || *cph == "chacha20" || *cph == "salsa20" || *cph == "twofish" || *cph == "lea" || *cph == "hc256" || *cph == "eea256" || *cph == "zuc256" || *cph == "skein" || *cph == "serpent" || *cph == "rc6" || *cph == "magenta" || *cph == "belt") && *pkey != "keygen" && (*length != 256 && *length != 192 && *length != 128) && *crypt != "" {
		*length = 256
	}

	if (*cph == "shacal2") && *pkey != "keygen" && (*length != 128 && *length != 192 && *length != 256 && *length != 320 && *length != 448 && *length != 512) && *crypt != "" {
		*length = 256
	}

	if *mac == "skein" && *length == 0 {
		*length = 256
	}

	if *cph == "3des" && *pkey != "keygen" && *length != 192 && *crypt != "" {
		*length = 192
	}

	if (*cph == "blowfish" || *cph == "cast5" || *cph == "idea" || *cph == "rc2" || *cph == "rc5" || *cph == "rc4" || *cph == "sm4" || *cph == "seed" || *cph == "hight" || *cph == "misty1" || *cph == "khazad" || *cph == "noekeon" || *cph == "xoodyak" || *cph == "hc128" || *cph == "eea128" || *cph == "zuc128" || *cph == "ascon" || *cph == "grain128a" || *cph == "grain128aead" || *cph == "kcipher2" || *cph == "rabbit" || *cph == "kalyna128_128") && *pkey != "keygen" && (*length != 128) && *crypt != "" {
		*length = 128
	}

	if (*cph == "saferplus" || *cph == "safer+") && *pkey != "keygen" && (*length != 64 && *length != 128) && *crypt != "" {
		*length = 128
	}

	if (*cph == "present" || *cph == "twine") && *pkey != "keygen" && (*length != 80 && *length != 128) && *crypt != "" {
		*length = 128
	}

	if (*cph == "curupira") && *pkey != "keygen" && (*length != 96 && *length != 144 && *length != 192) && *crypt != "" {
		*length = 96
	}

	if (*cph == "anubis") && *pkey != "keygen" && (*length < 128 || *length > 320) && *crypt != "" {
		*length = 128
	}

	if (*cph == "threefish" || *cph == "threefish256") && *pkey != "keygen" && (*length != 256) && *crypt != "" {
		*length = 256
	}

	if (*cph == "threefish512" || *cph == "kalyna256_512" || *cph == "kalyna512_512") && *pkey != "keygen" && (*length != 512) && *crypt != "" {
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

	if (strings.ToUpper(*alg) == "NUMS" || strings.ToUpper(*alg) == "NUMS-TE") && *pkey == "keygen" && *length == 0 {
		*length = 256
	}

	if *pkey == "wrapkey" && *cph == "aes" {
		*cph = ""
	}

	if strings.ToUpper(*alg) == "ML-KEM" && *pkey == "keygen" && *length == 0 {
		*length = 768
	}

	if strings.ToUpper(*alg) == "ML-DSA" && *pkey == "keygen" && *length == 0 {
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

	if (strings.ToUpper(*alg) == "SCHNORR" && *pkey != "wrapkey" && *pkey != "unwrapkey") && *length == 0 {
		*length = 3072
	}

	if *digest && *md == "spritz" && *length == 0 {
		*length = 256
	}

	if (*pkey == "wrapkey" || *pkey == "unwrapkey") && *length == 0 {
		*length = 256
	}

	if (*pkey == "derivea" || *pkey == "deriveb") && *length == 0 {
		*length = 128
	}

	if *kdf == "scrypt" && *iter == 1 {
		*iter = 4096
	}

	if (strings.ToUpper(*md) == "ARGON2" || strings.ToUpper(*kdf) == "ARGON2" || strings.ToUpper(*kdf) == "SCRYPT" || strings.ToUpper(*kdf) == "PBKDF2" || strings.ToUpper(*kdf) == "HKDF" || strings.ToUpper(*kdf) == "BLAKE3" || strings.ToUpper(*kdf) == "LYRA2RE" || strings.ToUpper(*kdf) == "LYRA2RE2" || strings.ToUpper(*kdf) == "STREEBOG256" || strings.ToUpper(*kdf) == "STREEBOG" || strings.ToUpper(*kdf) == "GOST") && *length == 0 {
		*length = 256
	}

	if (strings.ToUpper(*alg) == "GOST2012" || strings.ToUpper(*alg) == "EC" || strings.ToUpper(*alg) == "ECDSA" || strings.ToUpper(*alg) == "ECGDSA" || strings.ToUpper(*alg) == "ECSDSA" || strings.ToUpper(*alg) == "BIP0340" || strings.ToUpper(*alg) == "ECKCDSA" || strings.ToUpper(*alg) == "BIGN" || strings.ToUpper(*alg) == "TOM") && *pkey == "keygen" && *length == 0 && *curveFlag == "" {
		*length = 256
	}

	if strings.ToUpper(*mac) == "VMAC" && *length == 0 {
		*length = 64
	}

	if strings.ToUpper(*mode) == "SIV" {
		*length = *length * 2
	}

	if *kdf == "pbkdf2" {
		keyRaw := pbkdf2.Key([]byte(*key), []byte(*salt), *iter, *length/8, myHash)
		*key = hex.EncodeToString(keyRaw)
		if *crypt == "" {
			fmt.Println(*key)
			os.Exit(0)
		}
	}

	if *kdf == "scrypt" {
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

	if *kdf == "lyra2re" {
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

	if *kdf == "lyra2re2" {
		data := []byte(*key + *salt)
		for i := 0; i < *iter; i++ {
			hash, _ := lyra2re2.Sum(data)
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

	if *kdf == "streebog256" || *kdf == "streebog" || *kdf == "gost" {
		kdf := gost34112012256.NewKDF([]byte(*key))

		derivedKey := kdf.Derive(nil, []byte(*salt), []byte(*info))

		*key = hex.EncodeToString(derivedKey[:*length/8])

		if *crypt == "" {
			fmt.Println(*key)
			os.Exit(0)
		}
	}

	if *kdf == "blake3" {
		out := make([]byte, *length/8)
		blake3.DeriveKey(*info, []byte(*key), out)
		*key = hex.EncodeToString(out)

		if *crypt == "" {
			fmt.Println(*key)
			os.Exit(0)
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
			if *vector != "" {
				iv, _ = hex.DecodeString(*vector)
				copy(nonce[:], iv)
			} else {
				fmt.Fprintf(os.Stderr, "IV= %x\n", nonce)
			}
			ciph = hc256.NewCipher(&nonce, &key)
			if len(key) != 32 {
				log.Fatal("Invalid key size.")
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
				log.Fatal("Invalid key size.")
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
			macBytes := h.Sum(nil)

			sigBytes, err := hex.DecodeString(*sig)
			if err != nil {
				log.Fatal(err)
			}

			if len(macBytes) != len(sigBytes) {
				verify = false
			} else {
				verify = subtle.ConstantTimeCompare(macBytes, sigBytes) == 1
			}

			fmt.Printf("Verified: %t\n", verify)
			if verify {
				os.Exit(0)
			} else {
				os.Exit(1)
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
			macBytes := h.Sum(nil)

			sigBytes, err := hex.DecodeString(*sig)
			if err != nil {
				log.Fatal(err)
			}

			if len(macBytes) != len(sigBytes) {
				verify = false
			} else {
				verify = subtle.ConstantTimeCompare(macBytes, sigBytes) == 1
			}

			fmt.Printf("Verified: %t\n", verify)
			if verify {
				os.Exit(0)
			} else {
				os.Exit(1)
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
			sigBytes, err := hex.DecodeString(*sig)
			if err != nil {
				log.Fatal(err)
			}

			if len(h.MAC(line, t[:])) != len(sigBytes) {
				verify = false
			} else {
				verify = subtle.ConstantTimeCompare(h.MAC(line, t[:]), sigBytes) == 1
			}

			fmt.Printf("Verified: %t\n", verify)
			if verify {
				os.Exit(0)
			} else {
				os.Exit(1)
			}
		}
		fmt.Printf("MAC-CHASKEY("+inputdesc+")= %s\n", hex.EncodeToString(h.MAC(line, t[:])))
		os.Exit(0)
	}

	if *crypt != "" && (*cph == "blowfish" || *cph == "idea" || *cph == "cast5" || *cph == "rc2" || *cph == "rc5" || *cph == "des" || *cph == "3des" || *cph == "hight" || *cph == "misty1" || *cph == "khazad" || *cph == "present" || *cph == "twine") && (strings.ToUpper(*mode) == "EAX") {
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
			if len(key) != 64 && len(key) != 56 && len(key) != 40 && len(key) != 32 && len(key) != 24 && len(key) != 20 && len(key) != 16 && len(key) != 10 && len(key) != 8 {
				log.Fatal("Invalid key size.")
			}
		}
		var ciph cipher.Block
		switch *cph {
		case "blowfish":
			ciph, err = blowfish.NewCipher(key)
		case "idea":
			ciph, err = idea.NewCipher(key)
		case "cast5":
			ciph, err = cast5.NewCipher(key)
		case "rc5":
			ciph, err = rc5.New(key)
		case "hight":
			ciph, err = krcrypt.NewHIGHT(key)
		case "rc2":
			ciph, err = rc2.NewCipher(key)
		case "des":
			ciph, err = des.NewCipher(key)
		case "3des":
			ciph, err = des.NewTripleDESCipher(key)
		case "misty1":
			ciph, err = misty1.New(key)
		case "khazad":
			ciph, err = khazad.NewCipher(key)
		case "present":
			ciph, err = present.NewCipher(key)
		case "twine":
			ciph, err = twine.NewCipher(key)
		default:
			log.Fatalf("Cipher type %s not recognized", *cph)
		}
		if err != nil {
			log.Fatal(err)
		}

		var aead cipher.AEAD
		aead, err = eax.NewEAXWithNonceAndTagSize(ciph, 12, 8)

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

	if *crypt != "" && (*cph == "curupira" && strings.ToUpper(*mode) == "LETTERSOUP") {
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
			if len(key) != 12 && len(key) != 18 && len(key) != 24 {
				log.Fatal("Invalid key size. Key must be either 96, 144, or 192 bits for Curupira.")
			}
		}

		buf := bytes.NewBuffer(nil)
		var data io.Reader
		data = inputfile
		io.Copy(buf, data)
		msg := buf.Bytes()

		aad := []byte(*info)

		cipher, err := curupira1.NewCipher(key)
		if err != nil {
			log.Fatal("Error creating Curupira cipher instance:", err)
		}

		aead := curupira1.NewLetterSoup(cipher)

		if *crypt == "enc" {
			nonce := make([]byte, 12)
			if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
				log.Fatal(err)
			}
			aead.SetIV(nonce)

			ciphertext := make([]byte, len(msg))
			aead.Encrypt(ciphertext, msg)
			aead.Update(aad)
			tag := aead.GetTag(nil, 96)

			output := append(nonce, tag...)
			output = append(output, ciphertext...)
			os.Stdout.Write(output)

			os.Exit(0)
		}

		if *crypt == "dec" {
			nonce, tag, msg := msg[:12], msg[12:24], msg[24:]

			aead.SetIV(nonce)

			decrypted := make([]byte, len(msg))
			aead.Decrypt(decrypted, msg)

			ciphertext := make([]byte, len(decrypted))
			aead.Encrypt(ciphertext, decrypted)
			aead.Update(aad)
			tagEnc := aead.GetTag(nil, 96)

			if len(tag) == len(tagEnc) && subtle.ConstantTimeCompare(tag, tagEnc) == 1 {
				os.Stdout.Write(decrypted)
				os.Exit(0)
			} else {
				log.Fatal("Error: authentication verification failed!")
			}
		}
	}

	if *crypt != "" && (*cph == "curupira") && (strings.ToUpper(*mode) == "EAX") {
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
			if len(key) != 24 && len(key) != 18 && len(key) != 12 {
				log.Fatal("Invalid key size.")
			}
		}
		ciph, err := curupira1.NewCipher(key)

		if err != nil {
			log.Fatal(err)
		}

		var aead cipher.AEAD
		aead, err = eax.NewEAXWithNonceAndTagSize(ciph, 12, 12)

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

	if *crypt != "" && (*cph == "anubis") && (strings.ToUpper(*mode) == "EAC") {
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
			if len(key) < 16 || len(key) > 40 {
				log.Fatal("Invalid key size.")
			}
		}
		aead, err := eac.NewEAC(key)

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

	if *crypt != "" && (*cph == "kalyna256_256" || *cph == "kalyna256_512" || *cph == "kalyna512_512" || *cph == "threefish" || *cph == "threefish256" || *cph == "threefish512" || *cph == "threefish1024" || *cph == "shacal2") && (strings.ToUpper(*mode) == "EAX") {
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
			if len(key) != 128 && len(key) != 64 && len(key) != 32 {
				log.Fatal("Invalid key size.")
			}
		}
		var ciph cipher.Block
		var tweak []byte
		tweak = make([]byte, 16)
		var n int

		switch *cph {
		case "threefish", "threefish256":
			if *tweakStr != "" {
				tweak = []byte(*tweakStr)
			}
			ciph, err = threefish.New256(key, tweak)
			n = 32
		case "threefish512":
			if *tweakStr != "" {
				tweak = []byte(*tweakStr)
			}
			ciph, err = threefish.New512(key, tweak)
			n = 64
		case "threefish1024":
			if *tweakStr != "" {
				tweak = []byte(*tweakStr)
			}
			ciph, err = threefish.New1024(key, tweak)
			n = 128
		case "kalyna256_256":
			ciph, err = kalyna.NewCipher256_256(key)
			n = 32
		case "kalyna256_512":
			ciph, err = kalyna.NewCipher256_512(key)
			n = 32
		case "kalyna512_512":
			ciph, err = kalyna.NewCipher512_512(key)
			n = 64
		case "shacal2":
			ciph, err = shacal2.NewCipher(key)
			n = 32
		default:
			log.Fatalf("Cipher type %s not recognized", *cph)
		}

		if err != nil {
			log.Fatal(err)
		}

		var aead cipher.AEAD
		aead, err = eax.NewEAXWithNonceAndTagSize(ciph, 12, n)

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

	if *crypt != "" && (*cph == "aes" || *cph == "anubis" || *cph == "aria" || *cph == "lea" || *cph == "seed" || *cph == "lea" || *cph == "sm4" || *cph == "camellia" || *cph == "grasshopper" || *cph == "kuznechik" || *cph == "magma" || *cph == "gost89" || *cph == "twofish" || *cph == "serpent" || *cph == "rc6" || *cph == "magenta" || *cph == "mars" || *cph == "noekeon" || *cph == "loki97" || *cph == "cast256" || *cph == "cast6" || *cph == "clefia" || *cph == "kalyna128_128" || *cph == "kalyna128_256" || *cph == "kalyna256_256" || *cph == "kalyna256_512" || *cph == "kalyna512_512" || *cph == "crypton" || *cph == "e2" || *cph == "blowfish" || *cph == "idea" || *cph == "cast5" || *cph == "rc2" || *cph == "rc5" || *cph == "des" || *cph == "3des" || *cph == "hight" || *cph == "misty1" || *cph == "khazad" || *cph == "present" || *cph == "twine" || *cph == "threefish" || *cph == "threefish256" || *cph == "threefish512" || *cph == "threefish1024" || *cph == "shacal2" || *cph == "belt" || *cph == "safer+" || *cph == "saferplus") && (strings.ToUpper(*mode) == "SIV") {
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
			if len(key) != 128*2 && len(key) != 64*2 && len(key) != 80*2 && len(key) != 56*2 && len(key) != 48*2 && len(key) != 40*2 && len(key) != 32*2 && len(key) != 24*2 && len(key) != 16*2 && len(key) != 10*2 && len(key) != 8*2 {
				log.Fatal("Invalid key size.")
			}
		}
		var ciph cipher.Block
		var macBlock cipher.Block

		macKey := key[:len(key)/2]
		blockKey := key[len(key)/2:]

		var tweak []byte
		tweak = make([]byte, 16)

		switch *cph {
		case "aes":
			ciph, err = aes.NewCipher(blockKey)
			if err != nil {
				log.Fatal(err)
			}
			macBlock, err = aes.NewCipher(macKey)
			if err != nil {
				log.Fatal(err)
			}
		case "twofish":
			ciph, err = twofish.NewCipher(blockKey)
			if err != nil {
				log.Fatal(err)
			}
			macBlock, err = twofish.NewCipher(macKey)
			if err != nil {
				log.Fatal(err)
			}
		case "aria":
			ciph, err = aria.NewCipher(blockKey)
			if err != nil {
				log.Fatal(err)
			}
			macBlock, err = aria.NewCipher(macKey)
			if err != nil {
				log.Fatal(err)
			}
		case "lea":
			ciph, err = lea.NewCipher(blockKey)
			if err != nil {
				log.Fatal(err)
			}
			macBlock, err = lea.NewCipher(macKey)
			if err != nil {
				log.Fatal(err)
			}
		case "camellia":
			ciph, err = camellia.NewCipher(blockKey)
			if err != nil {
				log.Fatal(err)
			}
			macBlock, err = camellia.NewCipher(macKey)
			if err != nil {
				log.Fatal(err)
			}
		case "serpent":
			ciph, err = serpent.NewCipher(blockKey)
			if err != nil {
				log.Fatal(err)
			}
			macBlock, err = serpent.NewCipher(macKey)
			if err != nil {
				log.Fatal(err)
			}
		case "grasshopper", "kuznechik":
			ciph, err = kuznechik.NewCipher(blockKey)
			if err != nil {
				log.Fatal(err)
			}
			macBlock, err = kuznechik.NewCipher(macKey)
			if err != nil {
				log.Fatal(err)
			}
		case "sm4":
			ciph, err = sm4.NewCipher(blockKey)
			if err != nil {
				log.Fatal(err)
			}
			macBlock, err = sm4.NewCipher(macKey)
			if err != nil {
				log.Fatal(err)
			}
		case "seed":
			ciph, err = krcrypt.NewSEED(blockKey)
			if err != nil {
				log.Fatal(err)
			}
			macBlock, err = krcrypt.NewSEED(macKey)
			if err != nil {
				log.Fatal(err)
			}
		case "anubis":
			ciph, err = anubis.NewWithKeySize(key, len(blockKey))
			if err != nil {
				log.Fatal(err)
			}
			macBlock, err = anubis.NewWithKeySize(key, len(macKey))
			if err != nil {
				log.Fatal(err)
			}
		case "rc6":
			ciph, err = rc6.NewCipher(blockKey)
			if err != nil {
				log.Fatal(err)
			}
			macBlock, err = rc6.NewCipher(macKey)
			if err != nil {
				log.Fatal(err)
			}
		case "magenta":
			ciph, err = magenta.NewCipher(blockKey)
			if err != nil {
				log.Fatal(err)
			}
			macBlock, err = magenta.NewCipher(macKey)
			if err != nil {
				log.Fatal(err)
			}
		case "mars":
			ciph, err = mars.NewCipher(blockKey)
			if err != nil {
				log.Fatal(err)
			}
			macBlock, err = mars.NewCipher(macKey)
			if err != nil {
				log.Fatal(err)
			}
		case "noekeon":
			ciph, err = noekeon.NewCipher(blockKey)
			if err != nil {
				log.Fatal(err)
			}
			macBlock, err = noekeon.NewCipher(macKey)
			if err != nil {
				log.Fatal(err)
			}
		case "loki97":
			ciph, err = loki97.NewCipher(blockKey)
			if err != nil {
				log.Fatal(err)
			}
			macBlock, err = loki97.NewCipher(macKey)
			if err != nil {
				log.Fatal(err)
			}
		case "clefia":
			ciph, err = clefia.NewCipher(blockKey)
			if err != nil {
				log.Fatal(err)
			}
			macBlock, err = clefia.NewCipher(macKey)
			if err != nil {
				log.Fatal(err)
			}
		case "kalyna128_128":
			ciph, err = kalyna.NewCipher128_128(blockKey)
			if err != nil {
				log.Fatal(err)
			}
			macBlock, err = kalyna.NewCipher128_128(macKey)
			if err != nil {
				log.Fatal(err)
			}
		case "kalyna128_256":
			ciph, err = kalyna.NewCipher128_256(blockKey)
			if err != nil {
				log.Fatal(err)
			}
			macBlock, err = kalyna.NewCipher128_256(macKey)
			if err != nil {
				log.Fatal(err)
			}
		case "kalyna256_256":
			ciph, err = kalyna.NewCipher256_256(blockKey)
			if err != nil {
				log.Fatal(err)
			}
			macBlock, err = kalyna.NewCipher256_256(macKey)
			if err != nil {
				log.Fatal(err)
			}
		case "kalyna256_512":
			ciph, err = kalyna.NewCipher256_512(blockKey)
			if err != nil {
				log.Fatal(err)
			}
			macBlock, err = kalyna.NewCipher256_512(macKey)
			if err != nil {
				log.Fatal(err)
			}
		case "kalyna512_512":
			ciph, err = kalyna.NewCipher512_512(blockKey)
			if err != nil {
				log.Fatal(err)
			}
			macBlock, err = kalyna.NewCipher512_512(macKey)
			if err != nil {
				log.Fatal(err)
			}
		case "khazad":
			ciph, err = khazad.NewCipher(blockKey)
			if err != nil {
				log.Fatal(err)
			}
			macBlock, err = khazad.NewCipher(macKey)
			if err != nil {
				log.Fatal(err)
			}
		case "cast256", "cast6":
			ciph, err = cast256.NewCipher(blockKey)
			if err != nil {
				log.Fatal(err)
			}
			macBlock, err = cast256.NewCipher(macKey)
			if err != nil {
				log.Fatal(err)
			}
		case "crypton":
			ciph, err = crypton1.NewCipher(blockKey)
			if err != nil {
				log.Fatal(err)
			}
			macBlock, err = crypton1.NewCipher(macKey)
			if err != nil {
				log.Fatal(err)
			}
		case "e2":
			ciph, err = e2.NewCipher(blockKey)
			if err != nil {
				log.Fatal(err)
			}
			macBlock, err = e2.NewCipher(macKey)
			if err != nil {
				log.Fatal(err)
			}
		case "blowfish":
			ciph, err = blowfish.NewCipher(blockKey)
			if err != nil {
				log.Fatal(err)
			}
			macBlock, err = blowfish.NewCipher(macKey)
			if err != nil {
				log.Fatal(err)
			}
		case "idea":
			ciph, err = idea.NewCipher(blockKey)
			if err != nil {
				log.Fatal(err)
			}
			macBlock, err = idea.NewCipher(macKey)
			if err != nil {
				log.Fatal(err)
			}
		case "cast5":
			ciph, err = cast5.NewCipher(blockKey)
			if err != nil {
				log.Fatal(err)
			}
			macBlock, err = cast5.NewCipher(macKey)
			if err != nil {
				log.Fatal(err)
			}
		case "rc5":
			ciph, err = rc5.New(blockKey)
			if err != nil {
				log.Fatal(err)
			}
			macBlock, err = rc5.New(macKey)
			if err != nil {
				log.Fatal(err)
			}
		case "hight":
			ciph, err = krcrypt.NewHIGHT(blockKey)
			if err != nil {
				log.Fatal(err)
			}
			macBlock, err = krcrypt.NewHIGHT(macKey)
			if err != nil {
				log.Fatal(err)
			}
		case "rc2":
			ciph, err = rc2.NewCipher(blockKey)
			if err != nil {
				log.Fatal(err)
			}
			macBlock, err = rc2.NewCipher(macKey)
			if err != nil {
				log.Fatal(err)
			}
		case "des":
			ciph, err = des.NewCipher(blockKey)
			if err != nil {
				log.Fatal(err)
			}
			macBlock, err = des.NewCipher(macKey)
			if err != nil {
				log.Fatal(err)
			}
		case "3des":
			ciph, err = des.NewTripleDESCipher(blockKey)
			if err != nil {
				log.Fatal(err)
			}
			macBlock, err = des.NewTripleDESCipher(macKey)
			if err != nil {
				log.Fatal(err)
			}
		case "misty1":
			ciph, err = misty1.New(blockKey)
			if err != nil {
				log.Fatal(err)
			}
			macBlock, err = misty1.New(macKey)
			if err != nil {
				log.Fatal(err)
			}
		case "present":
			ciph, err = present.NewCipher(blockKey)
			if err != nil {
				log.Fatal(err)
			}
			macBlock, err = present.NewCipher(macKey)
			if err != nil {
				log.Fatal(err)
			}
		case "twine":
			ciph, err = twine.NewCipher(blockKey)
			if err != nil {
				log.Fatal(err)
			}
			macBlock, err = twine.NewCipher(macKey)
			if err != nil {
				log.Fatal(err)
			}
		case "threefish", "threefish256":
			if *tweakStr != "" {
				tweak = []byte(*tweakStr)
			}
			ciph, err = threefish.New256(blockKey, tweak)
			if err != nil {
				log.Fatal(err)
			}
			macBlock, err = threefish.New256(macKey, tweak)
			if err != nil {
				log.Fatal(err)
			}
		case "threefish512":
			if *tweakStr != "" {
				tweak = []byte(*tweakStr)
			}
			ciph, err = threefish.New512(blockKey, tweak)
			if err != nil {
				log.Fatal(err)
			}
			macBlock, err = threefish.New512(macKey, tweak)
			if err != nil {
				log.Fatal(err)
			}
		case "threefish1024":
			if *tweakStr != "" {
				tweak = []byte(*tweakStr)
			}
			ciph, err = threefish.New1024(blockKey, tweak)
			if err != nil {
				log.Fatal(err)
			}
			macBlock, err = threefish.New1024(macKey, tweak)
			if err != nil {
				log.Fatal(err)
			}
		case "shacal2":
			ciph, err = shacal2.NewCipher(blockKey)
			if err != nil {
				log.Fatal(err)
			}
			macBlock, err = shacal2.NewCipher(macKey)
			if err != nil {
				log.Fatal(err)
			}
		case "saferplus", "safer+":
			ciph, err = saferplus.NewCipher(blockKey)
			if err != nil {
				log.Fatal(err)
			}
			macBlock, err = saferplus.NewCipher(macKey)
			if err != nil {
				log.Fatal(err)
			}
		case "belt":
			ciph, err = belt.NewCipher(blockKey)
			if err != nil {
				log.Fatal(err)
			}
			macBlock, err = belt.NewCipher(macKey)
			if err != nil {
				log.Fatal(err)
			}
		default:
			log.Fatalf("Cipher type %s not recognized", *cph)
		}

		aead, err := siv.NewSiv(macBlock, ciph, 12)
		if err != nil {
			log.Fatalf("Error creating PMAC cipher: %s", err)
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

	if *crypt != "" && (*cph == "aes" || *cph == "anubis" || *cph == "aria" || *cph == "lea" || *cph == "seed" || *cph == "lea" || *cph == "sm4" || *cph == "camellia" || *cph == "grasshopper" || *cph == "kuznechik" || *cph == "magma" || *cph == "gost89" || *cph == "twofish" || *cph == "serpent" || *cph == "rc6" || *cph == "magenta" || *cph == "khazad" || *cph == "present" || *cph == "twine" || *cph == "mars" || *cph == "noekeon" || *cph == "loki97" || *cph == "cast256" || *cph == "cast6" || *cph == "clefia" || *cph == "kalyna128_128" || *cph == "kalyna128_256" || *cph == "crypton" || *cph == "e2" || *cph == "saferplus" || *cph == "safer+" || *cph == "belt") && (strings.ToUpper(*mode) == "GCM" || strings.ToUpper(*mode) == "MGM" || strings.ToUpper(*mode) == "OCB" || strings.ToUpper(*mode) == "OCB1" || strings.ToUpper(*mode) == "OCB3" || strings.ToUpper(*mode) == "EAX" || strings.ToUpper(*mode) == "CCM") {
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
			if len(key) != 64 && len(key) != 56 && len(key) != 40 && len(key) != 32 && len(key) != 24 && len(key) != 16 && len(key) != 10 {
				log.Fatal("Invalid key size.")
			}
		}
		var ciph cipher.Block
		var n int

		switch *cph {
		case "aes":
			ciph, err = aes.NewCipher(key)
			n = 16
		case "twofish":
			ciph, err = twofish.NewCipher(key)
			n = 16
		case "aria":
			ciph, err = aria.NewCipher(key)
			n = 16
		case "lea":
			ciph, err = lea.NewCipher(key)
			n = 16
		case "camellia":
			ciph, err = camellia.NewCipher(key)
			n = 16
		case "serpent":
			ciph, err = serpent.NewCipher(key)
			n = 16
		case "grasshopper", "kuznechik":
			ciph, err = kuznechik.NewCipher(key)
			n = 16
		case "sm4":
			ciph, err = sm4.NewCipher(key)
			n = 16
		case "seed":
			ciph, err = krcrypt.NewSEED(key)
			n = 16
		case "anubis":
			ciph, err = anubis.NewWithKeySize(key, len(key))
			n = 16
		case "magma":
			ciph = gost341264.NewCipher(key)
			n = 8
		case "gost89":
			ciph = gost28147.NewCipher(key, &gost28147.SboxIdtc26gost28147paramZ)
			n = 8
		case "rc6":
			ciph, err = rc6.NewCipher(key)
			n = 16
		case "magenta":
			ciph, err = magenta.NewCipher(key)
			n = 16
		case "khazad":
			ciph, err = khazad.NewCipher(key)
			n = 8
		case "present":
			ciph, err = present.NewCipher(key)
			n = 8
		case "twine":
			ciph, err = twine.NewCipher(key)
			n = 8
		case "mars":
			ciph, err = mars.NewCipher(key)
			n = 16
		case "noekeon":
			ciph, err = noekeon.NewCipher(key)
			n = 16
		case "loki97":
			ciph, err = loki97.NewCipher(key)
			n = 16
		case "clefia":
			ciph, err = clefia.NewCipher(key)
			n = 16
		case "kalyna128_128":
			ciph, err = kalyna.NewCipher128_128(key)
			n = 16
		case "kalyna128_256":
			ciph, err = kalyna.NewCipher128_256(key)
			n = 16
		case "cast256", "cast6":
			ciph, err = cast256.NewCipher(key)
			n = 16
		case "crypton":
			ciph, err = crypton1.NewCipher(key)
			n = 16
		case "e2":
			ciph, err = e2.NewCipher(key)
			n = 16
		case "saferplus", "safer+":
			ciph, err = saferplus.NewCipher(key)
			n = 8
		case "belt":
			ciph, err = belt.NewCipher(key)
			n = 16
		default:
			log.Fatalf("Cipher type %s not recognized", *cph)
		}
		if err != nil {
			log.Fatal(err)
		}

		var aead cipher.AEAD
		modeUpper := strings.ToUpper(*mode)

		switch modeUpper {
		case "GCM":
			aead, err = cipher.NewGCMWithTagSize(ciph, 16)
		case "MGM":
			aead, err = mgm.NewMGM(ciph, n)
		case "OCB", "OCB1":
			aead, err = ocb.NewOCB(ciph)
		case "OCB3":
			aead, err = ocb3.New(ciph)
		case "EAX":
			aead, err = eax.NewEAXWithNonceAndTagSize(ciph, 12, n)
		case "CCM":
			aead, err = ccm.NewCCM(ciph, 16, 12)
		default:
			log.Fatalf("AEAD mode %s not recognized", modeUpper)
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
			if len(key) != 128 && len(key) != 64 && len(key) != 56 && len(key) != 40 && len(key) != 32 && len(key) != 24 && len(key) != 18 && len(key) != 16 && len(key) != 12 && len(key) != 10 && len(key) != 8 {
				log.Fatal("Invalid key size.")
			}
		}

		var ciph cipher.Block
		var n int
		var tweak []byte
		tweak = make([]byte, 16)

		switch *cph {
		case "aes":
			ciph, err = aes.NewCipher(key)
			n = 16
		case "twofish":
			ciph, err = twofish.NewCipher(key)
			n = 16
		case "aria":
			ciph, err = aria.NewCipher(key)
			n = 16
		case "lea":
			ciph, err = lea.NewCipher(key)
			n = 16
		case "camellia":
			ciph, err = camellia.NewCipher(key)
			n = 16
		case "serpent":
			ciph, err = serpent.NewCipher(key)
			n = 16
		case "grasshopper", "kuznechik":
			ciph, err = kuznechik.NewCipher(key)
			n = 16
		case "sm4":
			ciph, err = sm4.NewCipher(key)
			n = 16
		case "seed":
			ciph, err = krcrypt.NewSEED(key)
			n = 16
		case "hight":
			ciph, err = krcrypt.NewHIGHT(key)
			n = 8
		case "anubis":
			ciph, err = anubis.NewWithKeySize(key, len(key))
			n = 16
		case "magma":
			ciph = gost341264.NewCipher(key)
			n = 8
		case "gost89":
			ciph = gost28147.NewCipher(key, &gost28147.SboxIdtc26gost28147paramZ)
			n = 8
		case "3des":
			ciph, err = des.NewTripleDESCipher(key)
			n = 8
		case "des":
			ciph, err = des.NewCipher(key)
			n = 8
		case "rc2":
			ciph, err = rc2.NewCipher(key)
			n = 8
		case "rc5":
			ciph, err = rc5.New(key)
			n = 8
		case "rc6":
			ciph, err = rc6.NewCipher(key)
			n = 16
		case "magenta":
			ciph, err = magenta.NewCipher(key)
			n = 16
		case "idea":
			ciph, _ = idea.NewCipher(key)
			n = 8
		case "blowfish":
			ciph, err = blowfish.NewCipher(key)
			n = 8
		case "cast5":
			ciph, err = cast5.NewCipher(key)
			n = 8
		case "misty1":
			ciph, err = misty1.New(key)
			n = 8
		case "threefish256", "threefish":
			if *tweakStr != "" {
				tweak = []byte(*tweakStr)
			}
			ciph, err = threefish.New256(key, tweak)
			n = 32
		case "threefish512":
			if *tweakStr != "" {
				tweak = []byte(*tweakStr)
			}
			ciph, err = threefish.New512(key, tweak)
			n = 64
		case "threefish1024":
			if *tweakStr != "" {
				tweak = []byte(*tweakStr)
			}
			ciph, err = threefish.New1024(key, tweak)
			n = 128
		case "khazad":
			ciph, err = khazad.NewCipher(key)
			n = 8
		case "present":
			ciph, err = present.NewCipher(key)
			n = 8
		case "twine":
			ciph, err = twine.NewCipher(key)
			n = 8
		case "mars":
			ciph, err = mars.NewCipher(key)
			n = 16
		case "noekeon":
			ciph, err = noekeon.NewCipher(key)
			n = 16
		case "loki97":
			ciph, err = loki97.NewCipher(key)
			n = 16
		case "clefia":
			ciph, err = clefia.NewCipher(key)
			n = 16
		case "kalyna128_128":
			ciph, err = kalyna.NewCipher128_128(key)
			n = 16
		case "kalyna128_256":
			ciph, err = kalyna.NewCipher128_256(key)
			n = 16
		case "kalyna256_256":
			ciph, err = kalyna.NewCipher256_256(key)
			n = 32
		case "kalyna256_512":
			ciph, err = kalyna.NewCipher256_512(key)
			n = 32
		case "kalyna512_512":
			ciph, err = kalyna.NewCipher512_512(key)
			n = 64
		case "cast256", "cast6":
			ciph, err = cast256.NewCipher(key)
			n = 16
		case "crypton":
			ciph, err = crypton1.NewCipher(key)
			n = 16
		case "e2":
			ciph, err = e2.NewCipher(key)
			n = 16
		case "curupira":
			ciph, err = curupira1.NewCipher(key)
			n = 12
		case "shacal2":
			ciph, err = shacal2.NewCipher(key)
			n = 32
		case "saferplus", "safer+":
			ciph, err = saferplus.NewCipher(key)
			n = 8
		case "belt":
			ciph, err = belt.NewCipher(key)
			n = 16
		default:
			log.Fatalf("Cipher type %s not recognized", *cph)
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
			switch strings.ToUpper(*mode) {
			case "ECB":
				blockmode = ecb.NewECBEncrypter(ciph)
			case "CBC":
				blockmode = cipher.NewCBCEncrypter(ciph, iv)
			case "IGE":
				blockmode = ige.NewIGEEncrypter(ciph, iv)
			default:
				log.Fatalf("Mode %s not recognized", *mode)
			}
			blockmode.CryptBlocks(ciphertext, plaintext)
			fmt.Printf("%s", ciphertext)
		} else if *crypt == "dec" {
			buf := bytes.NewBuffer(nil)
			io.Copy(buf, inputfile)
			ciphertext := buf.Bytes()
			plaintext := make([]byte, len(ciphertext))
			var blockmode cipher.BlockMode
			switch strings.ToUpper(*mode) {
			case "ECB":
				blockmode = ecb.NewECBDecrypter(ciph)
			case "CBC":
				blockmode = cipher.NewCBCDecrypter(ciph, iv)
			case "IGE":
				blockmode = ige.NewIGEDecrypter(ciph, iv)
			default:
				log.Fatalf("Mode %s not recognized", *mode)
			}
			blockmode.CryptBlocks(plaintext, ciphertext)
			plaintext = PKCS7UnPadding(plaintext)
			fmt.Printf("%s", plaintext)
		}
		os.Exit(0)
	}

	if *crypt != "" && (*cph == "aes" || *cph == "aria" || *cph == "lea" || *cph == "camellia" || *cph == "magma" || *cph == "grasshopper" || *cph == "kuznechik" || *cph == "gost89" || *cph == "twofish" || *cph == "serpent" || *cph == "rc6" || *cph == "magenta" || *cph == "threefish" || *cph == "threefish256" || *cph == "threefish512" || *cph == "threefish1024" || *cph == "mars" || *cph == "noekeon" || *cph == "loki97" || *cph == "cast256" || *cph == "cast6" || *cph == "clefia" || *cph == "kalyna128_128" || *cph == "kalyna128_256" || *cph == "kalyna256_256" || *cph == "kalyna256_512" || *cph == "kalyna512_512" || *cph == "crypton" || *cph == "e2" || *cph == "shacal2" || *cph == "saferplus" || *cph == "safer+" || *cph == "belt") {
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
			if len(key) != 128 && len(key) != 64 && len(key) != 56 && len(key) != 40 && len(key) != 32 && len(key) != 24 && len(key) != 16 {
				log.Fatal("Invalid key size.")
			}
		}
		var ciph cipher.Block
		var iv []byte
		var tweak []byte
		tweak = make([]byte, 16)

		switch *cph {
		case "aes":
			ciph, err = aes.NewCipher(key)
			iv = make([]byte, 16)
		case "twofish":
			ciph, err = twofish.NewCipher(key)
			iv = make([]byte, 16)
		case "aria":
			ciph, err = aria.NewCipher(key)
			iv = make([]byte, 16)
		case "lea":
			ciph, err = lea.NewCipher(key)
			iv = make([]byte, 16)
		case "camellia":
			ciph, err = camellia.NewCipher(key)
			iv = make([]byte, 16)
		case "serpent":
			ciph, err = serpent.NewCipher(key)
			iv = make([]byte, 16)
		case "rc6":
			ciph, err = rc6.NewCipher(key)
			iv = make([]byte, 16)
		case "magenta":
			ciph, err = magenta.NewCipher(key)
			iv = make([]byte, 16)
		case "magma":
			ciph = gost341264.NewCipher(key)
			iv = make([]byte, 8)
		case "gost89":
			ciph = gost28147.NewCipher(key, &gost28147.SboxIdtc26gost28147paramZ)
			iv = make([]byte, 8)
		case "grasshopper", "kuznechik":
			ciph, err = kuznechik.NewCipher(key)
			iv = make([]byte, 16)
		case "threefish256", "threefish":
			if *tweakStr != "" {
				tweak = []byte(*tweakStr)
			}
			ciph, err = threefish.New256(key, tweak)
			iv = make([]byte, 32)
		case "threefish512":
			if *tweakStr != "" {
				tweak = []byte(*tweakStr)
			}
			ciph, err = threefish.New512(key, tweak)
			iv = make([]byte, 64)
		case "threefish1024":
			if *tweakStr != "" {
				tweak = []byte(*tweakStr)
			}
			ciph, err = threefish.New1024(key, tweak)
			iv = make([]byte, 128)
		case "mars":
			ciph, err = mars.NewCipher(key)
			iv = make([]byte, 16)
		case "noekeon":
			ciph, err = noekeon.NewCipher(key)
			iv = make([]byte, 16)
		case "loki97":
			ciph, err = loki97.NewCipher(key)
			iv = make([]byte, 16)
		case "clefia":
			ciph, err = clefia.NewCipher(key)
			iv = make([]byte, 16)
		case "kalyna128_128":
			ciph, err = kalyna.NewCipher128_128(key)
			iv = make([]byte, 16)
		case "kalyna128_256":
			ciph, err = kalyna.NewCipher128_256(key)
			iv = make([]byte, 16)
		case "kalyna256_256":
			ciph, err = kalyna.NewCipher256_256(key)
			iv = make([]byte, 32)
		case "kalyna256_512":
			ciph, err = kalyna.NewCipher256_512(key)
			iv = make([]byte, 32)
		case "kalyna512_512":
			ciph, err = kalyna.NewCipher512_512(key)
			iv = make([]byte, 64)
		case "cast256", "cast6":
			ciph, err = cast256.NewCipher(key)
			iv = make([]byte, 16)
		case "crypton":
			ciph, err = crypton1.NewCipher(key)
			iv = make([]byte, 16)
		case "e2":
			ciph, err = e2.NewCipher(key)
			iv = make([]byte, 16)
		case "shacal2":
			ciph, err = shacal2.NewCipher(key)
			iv = make([]byte, 32)
		case "saferplus", "safer+":
			ciph, err = saferplus.NewCipher(key)
			iv = make([]byte, 8)
		case "belt":
			ciph, err = belt.NewCipher(key)
			iv = make([]byte, 16)
		default:
			log.Fatalf("Cipher type %s not recognized", *cph)
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
		modeUpper := strings.ToUpper(*mode)

		switch {
		case modeUpper == "CTR":
			stream = cipher.NewCTR(ciph, iv)
		case modeUpper == "OFB":
			stream = cipher.NewOFB(ciph, iv)
		case *crypt == "enc" && modeUpper == "CFB1":
			stream = CFB1.NewCFB1Encrypt(ciph, iv)
		case *crypt == "dec" && modeUpper == "CFB1":
			stream = CFB1.NewCFB1Decrypt(ciph, iv)
		case *crypt == "enc" && modeUpper == "CFB8":
			stream = CFB8.NewCFB8Encrypt(ciph, iv)
		case *crypt == "dec" && modeUpper == "CFB8":
			stream = CFB8.NewCFB8Decrypt(ciph, iv)
		case *crypt == "enc" && modeUpper == "CFB":
			stream = cipher.NewCFBEncrypter(ciph, iv)
		case *crypt == "dec" && modeUpper == "CFB":
			stream = cipher.NewCFBDecrypter(ciph, iv)
		default:
			log.Fatalf("Mode %s not recognized", *mode)
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

	if *crypt != "" && (*cph == "blowfish" || *cph == "idea" || *cph == "cast5" || *cph == "rc2" || *cph == "rc5" || *cph == "sm4" || *cph == "des" || *cph == "3des" || *cph == "seed" || *cph == "hight" || *cph == "misty1" || *cph == "anubis" || *cph == "khazad" || *cph == "present" || *cph == "twine" || *cph == "curupira") {
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
			if len(key) != 32 && len(key) != 40 && len(key) != 16 && len(key) != 10 && len(key) != 24 && len(key) != 18 && len(key) != 12 && len(key) != 10 && len(key) != 8 {
				log.Fatal("Invalid key size.")
			}
		}
		var ciph cipher.Block
		var iv []byte

		switch *cph {
		case "blowfish":
			ciph, err = blowfish.NewCipher(key)
			iv = make([]byte, 8)
		case "idea":
			ciph, err = idea.NewCipher(key)
			iv = make([]byte, 8)
		case "cast5":
			ciph, err = cast5.NewCipher(key)
			iv = make([]byte, 8)
		case "rc5":
			ciph, err = rc5.New(key)
			iv = make([]byte, 8)
		case "sm4":
			ciph, err = sm4.NewCipher(key)
			iv = make([]byte, 16)
		case "seed":
			ciph, err = krcrypt.NewSEED(key)
			iv = make([]byte, 16)
		case "hight":
			ciph, err = krcrypt.NewHIGHT(key)
			iv = make([]byte, 8)
		case "anubis":
			ciph, err = anubis.NewWithKeySize(key, len(key))
			iv = make([]byte, 16)
		case "rc2":
			ciph, err = rc2.NewCipher(key)
			iv = make([]byte, 8)
		case "des":
			ciph, err = des.NewCipher(key)
			iv = make([]byte, 8)
		case "3des":
			ciph, err = des.NewTripleDESCipher(key)
			iv = make([]byte, 8)
		case "misty1":
			ciph, err = misty1.New(key)
			iv = make([]byte, 8)
		case "khazad":
			ciph, err = khazad.NewCipher(key)
			iv = make([]byte, 8)
		case "present":
			ciph, err = present.NewCipher(key)
			iv = make([]byte, 8)
		case "twine":
			ciph, err = twine.NewCipher(key)
			iv = make([]byte, 8)
		case "curupira":
			ciph, err = curupira1.NewCipher(key)
			iv = make([]byte, 12)
		default:
			log.Fatalf("Cipher type %s not recognized", *cph)
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
		modeUpper := strings.ToUpper(*mode)

		switch {
		case modeUpper == "CTR":
			stream = cipher.NewCTR(ciph, iv)
		case modeUpper == "OFB":
			stream = cipher.NewOFB(ciph, iv)
		case *crypt == "enc" && modeUpper == "CFB1":
			stream = CFB1.NewCFB1Encrypt(ciph, iv)
		case *crypt == "dec" && modeUpper == "CFB1":
			stream = CFB1.NewCFB1Decrypt(ciph, iv)
		case *crypt == "enc" && modeUpper == "CFB8":
			stream = CFB8.NewCFB8Encrypt(ciph, iv)
		case *crypt == "dec" && modeUpper == "CFB8":
			stream = CFB8.NewCFB8Decrypt(ciph, iv)
		case *crypt == "enc" && modeUpper == "CFB":
			stream = cipher.NewCFBEncrypter(ciph, iv)
		case *crypt == "dec" && modeUpper == "CFB":
			stream = cipher.NewCFBDecrypter(ciph, iv)
		default:
			log.Fatalf("Mode %s not recognized", *mode)
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
		expectedHash, err := hex.DecodeString(hashedPasswordString)
		if err != nil {
			log.Fatalf("Erro ao decodificar hash hexadecimal: %v", err)
		}
		computedHash := argon2.IDKey([]byte(*key), []byte(*salt), uint32(*iter), 64*1024, 4, uint32(*length/8))
		if subtle.ConstantTimeCompare(expectedHash, computedHash) == 1 {
			fmt.Println("Verify: true")
		} else {
			fmt.Println("Verify: false")
			os.Exit(1)
		}
		os.Exit(0)
	}

	if *digest && *md == "lyra2re" && !*check {
		passwordBytes := []byte(*key + *salt)
		hash, err := lyra2re.Sum(passwordBytes)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(hex.EncodeToString(hash))
		os.Exit(0)
	}

	if *md == "lyra2re" && *check {
		passwordBytes := []byte(*key + *salt)
		hash, err := lyra2re.Sum(passwordBytes)
		if err != nil {
			log.Fatal(err)
		}

		hashedPassword, err := ioutil.ReadAll(inputfile)
		if err != nil {
			log.Fatal(err)
		}
		hashedPasswordString := strings.TrimSpace(string(hashedPassword))

		expectedHash, err := hex.DecodeString(hashedPasswordString)
		if err != nil {
			log.Fatalf("Erro ao decodificar hash hexadecimal: %v", err)
		}

		if subtle.ConstantTimeCompare(expectedHash, hash) == 1 {
			fmt.Println("Verify: true")
		} else {
			fmt.Println("Verify: false")
			os.Exit(1)
		}
		os.Exit(0)
	}

	if *digest && *md == "lyra2re2" && !*check {
		passwordBytes := []byte(*key + *salt)
		hash, err := lyra2re2.Sum(passwordBytes)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(hex.EncodeToString(hash))
		os.Exit(0)
	}

	if *md == "lyra2re2" && *check {
		passwordBytes := []byte(*key + *salt)
		hash, err := lyra2re2.Sum(passwordBytes)
		if err != nil {
			log.Fatal(err)
		}

		hashedPassword, err := ioutil.ReadAll(inputfile)
		if err != nil {
			log.Fatal(err)
		}
		hashedPasswordString := strings.TrimSpace(string(hashedPassword))

		expectedHash, err := hex.DecodeString(hashedPasswordString)
		if err != nil {
			log.Fatalf("Erro ao decodificar hash hexadecimal: %v", err)
		}

		if subtle.ConstantTimeCompare(expectedHash, hash) == 1 {
			fmt.Println("Verify: true")
		} else {
			fmt.Println("Verify: false")
			os.Exit(1)
		}
		os.Exit(0)
	}

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
		h.Reset()
		io.Copy(h, os.Stdin)
		fmt.Println(hex.EncodeToString(h.Sum(nil)), "(stdin)")
		os.Exit(0)
	}

	if *digest && !*recursive {
		for _, wildcard := range flag.Args() {
			files, err := filepath.Glob(wildcard)
			if err != nil {
				log.Fatal(err)
			}
			for _, match := range files {
				h.Reset()
				f, err := os.Open(match)
				if err != nil {
					log.Fatal(err)
				}
				file, err := os.Stat(match)
				if err != nil {
					log.Fatal(err)
				}
				if !file.IsDir() {
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

	if *digest && *recursive {
		err := filepath.Walk(filepath.Dir(Files),
			func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				file, err := os.Stat(path)
				if err != nil {
					log.Fatal(err)
				}
				if !file.IsDir() {
					for _, match := range flag.Args() {
						filename := filepath.Base(path)
						pattern := filepath.Base(match)
						matched, err := filepath.Match(pattern, filename)
						if err != nil {
							log.Fatal(err)
						}
						if matched {
							h.Reset()
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
				h.Reset()
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
			macBytes := h.Sum(nil)

			sigBytes, err := hex.DecodeString(*sig)
			if err != nil {
				log.Fatal(err)
			}

			if len(macBytes) != len(sigBytes) {
				verify = false
			} else {
				verify = subtle.ConstantTimeCompare(macBytes, sigBytes) == 1
			}

			fmt.Printf("Verified: %t\n", verify)
			if verify {
				os.Exit(0)
			} else {
				os.Exit(1)
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
			macBytes := h.Sum(nil)

			sigBytes, err := hex.DecodeString(*sig)
			if err != nil {
				log.Fatal(err)
			}

			if len(macBytes) != len(sigBytes) {
				verify = false
			} else {
				verify = subtle.ConstantTimeCompare(macBytes, sigBytes) == 1
			}

			fmt.Printf("Verified: %t\n", verify)
			if verify {
				os.Exit(0)
			} else {
				os.Exit(1)
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
			macBytes := h.Sum(nil)

			sigBytes, err := hex.DecodeString(*sig)
			if err != nil {
				log.Fatal(err)
			}

			if len(macBytes) != len(sigBytes) {
				verify = false
			} else {
				verify = subtle.ConstantTimeCompare(macBytes, sigBytes) == 1
			}

			fmt.Printf("Verified: %t\n", verify)
			if verify {
				os.Exit(0)
			} else {
				os.Exit(1)
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
			macBytes := h.Sum(nil)

			sigBytes, err := hex.DecodeString(*sig)
			if err != nil {
				log.Fatal(err)
			}

			if len(macBytes) != len(sigBytes) {
				verify = false
			} else {
				verify = subtle.ConstantTimeCompare(macBytes, sigBytes) == 1
			}

			fmt.Printf("Verified: %t\n", verify)
			if verify {
				os.Exit(0)
			} else {
				os.Exit(1)
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
			macBytes := h.Sum(nil)

			sigBytes, err := hex.DecodeString(*sig)
			if err != nil {
				log.Fatal(err)
			}

			if len(macBytes) != len(sigBytes) {
				verify = false
			} else {
				verify = subtle.ConstantTimeCompare(macBytes, sigBytes) == 1
			}

			fmt.Printf("Verified: %t\n", verify)
			if verify {
				os.Exit(0)
			} else {
				os.Exit(1)
			}
		}
		fmt.Println("MAC-SKEIN("+inputdesc+")=", hex.EncodeToString(h.Sum(nil)))
		os.Exit(0)
	}

	if *mac == "blake3" {
		h, err = blake3.NewKeyed([]byte(*key))
		if err != nil {
			log.Fatal(err)
		}
		if _, err = io.Copy(h, inputfile); err != nil {
			log.Fatal(err)
		}
		var verify bool
		if *sig != "" {
			macBytes := h.Sum(nil)

			sigBytes, err := hex.DecodeString(*sig)
			if err != nil {
				log.Fatal(err)
			}

			if len(macBytes) != len(sigBytes) {
				verify = false
			} else {
				verify = subtle.ConstantTimeCompare(macBytes, sigBytes) == 1
			}

			fmt.Printf("Verified: %t\n", verify)
			if verify {
				os.Exit(0)
			} else {
				os.Exit(1)
			}
		}
		fmt.Println("MAC-BLAKE3("+inputdesc+")=", hex.EncodeToString(h.Sum(nil)))
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

		var verify bool
		if *sig != "" {
			macBytes := outerHash[:]

			sigBytes, err := hex.DecodeString(*sig)
			if err != nil {
				log.Fatal(err)
			}

			if len(macBytes) != len(sigBytes) {
				verify = false
			} else {
				verify = subtle.ConstantTimeCompare(macBytes, sigBytes) == 1
			}

			fmt.Printf("Verified: %t\n", verify)
			if verify {
				os.Exit(0)
			} else {
				os.Exit(1)
			}
		}

		fmt.Println("HMAC-HARAKA("+inputdesc+")=", hex.EncodeToString(outerHash[:]))
		os.Exit(0)
	}

	if *mac == "hmac" {
		var err error
		h := hmac.New(myHash, []byte(*key))
		if _, err = io.Copy(h, inputfile); err != nil {
			log.Fatal(err)
		}
		if *sig != "" {
			macBytes := h.Sum(nil)
			sigBytes, err := hex.DecodeString(*sig)
			if err != nil {
				log.Fatal(err)
			}
			verify := hmac.Equal(macBytes, sigBytes)
			fmt.Printf("Verified: %t\n", verify)
			if verify {
				os.Exit(0)
			} else {
				os.Exit(1)
			}
		}
		fmt.Println("HMAC-"+strings.ToUpper(*md)+"("+inputdesc+")=", hex.EncodeToString(h.Sum(nil)))
		os.Exit(0)
	}

	if *md == "sha256" && *mac == "kmac" {
		*md = "kupyna256"
	}

	if *mac == "kmac" {
		var err error
		var h hash.Hash
		if *md == "kupyna256" || *md == "kupyna" {
			h, err = kupyna.NewKmac256([]byte(*key))
		} else if *md == "kupyna384" {
			h, err = kupyna.NewKmac384([]byte(*key))
		} else if *md == "kupyna512" {
			h, err = kupyna.NewKmac512([]byte(*key))
		}
		if err != nil {
			log.Fatal(err)
		}
		if _, err = io.Copy(h, inputfile); err != nil {
			log.Fatal(err)
		}
		var verify bool
		if *sig != "" {
			macBytes := h.Sum(nil)

			sigBytes, err := hex.DecodeString(*sig)
			if err != nil {
				log.Fatal(err)
			}

			if len(macBytes) != len(sigBytes) {
				verify = false
			} else {
				verify = subtle.ConstantTimeCompare(macBytes, sigBytes) == 1
			}

			fmt.Printf("Verified: %t\n", verify)
			if verify {
				os.Exit(0)
			} else {
				os.Exit(1)
			}
		}
		fmt.Println("KMAC-"+strings.ToUpper(*md)+"("+inputdesc+")=", hex.EncodeToString(h.Sum(nil)))
		os.Exit(0)
	}

	if *mac == "cmac" {
		var c cipher.Block
		var err error
		switch *cph {
		case "blowfish":
			c, err = blowfish.NewCipher([]byte(*key))
		case "idea":
			c, err = idea.NewCipher([]byte(*key))
		case "cast5":
			c, err = cast5.NewCipher([]byte(*key))
		case "rc5":
			c, err = rc5.New([]byte(*key))
		case "sm4":
			c, err = sm4.NewCipher([]byte(*key))
		case "seed":
			c, err = krcrypt.NewSEED([]byte(*key))
		case "hight":
			c, err = krcrypt.NewHIGHT([]byte(*key))
		case "rc2":
			c, err = rc2.NewCipher([]byte(*key))
		case "des":
			c, err = des.NewCipher([]byte(*key))
		case "3des":
			c, err = des.NewTripleDESCipher([]byte(*key))
		case "aes":
			c, err = aes.NewCipher([]byte(*key))
		case "twofish":
			c, err = twofish.NewCipher([]byte(*key))
		case "aria":
			c, err = aria.NewCipher([]byte(*key))
		case "lea":
			c, err = lea.NewCipher([]byte(*key))
		case "camellia":
			c, err = camellia.NewCipher([]byte(*key))
		case "serpent":
			c, err = serpent.NewCipher([]byte(*key))
		case "rc6":
			c, err = rc6.NewCipher([]byte(*key))
		case "magenta":
			c, err = magenta.NewCipher([]byte(*key))
		case "misty1":
			c, err = misty1.New([]byte(*key))
		case "magma":
			if len(*key) != 32 {
				log.Fatal("MAGMA invalid key size ", len(*key))
			}
			c = gost341264.NewCipher([]byte(*key))
		case "grasshopper", "kuznechik":
			if len(*key) != 32 {
				log.Fatal("KUZNECHIK: invalid key size ", len(*key))
			}
			c, err = kuznechik.NewCipher([]byte(*key))
		case "gost89":
			if len(*key) != 32 {
				log.Fatal("GOST89: invalid key size ", len(*key))
			}
			c = gost28147.NewCipher([]byte(*key), &gost28147.SboxIdtc26gost28147paramZ)
		case "anubis":
			if len(*key) != 16 && len(*key) != 24 && len(*key) != 32 && len(*key) != 40 {
				log.Fatal("ANUBIS: invalid key size ", len(*key))
			}
			c, err = anubis.NewWithKeySize([]byte(*key), len(*key))
		case "khazad":
			c, err = khazad.NewCipher([]byte(*key))
		case "mars":
			c, err = mars.NewCipher([]byte(*key))
		case "noekeon":
			c, err = noekeon.NewCipher([]byte(*key))
		case "loki97":
			c, err = loki97.NewCipher([]byte(*key))
		case "clefia":
			c, err = clefia.NewCipher([]byte(*key))
		case "kalyna128_128":
			c, err = kalyna.NewCipher128_128([]byte(*key))
		case "kalyna128_256":
			c, err = kalyna.NewCipher128_256([]byte(*key))
		case "cast256", "cast6":
			c, err = cast256.NewCipher([]byte(*key))
		case "e2":
			c, err = e2.NewCipher([]byte(*key))
		case "crypton":
			c, err = crypton1.NewCipher([]byte(*key))
		case "present":
			c, err = present.NewCipher([]byte(*key))
		case "twine":
			c, err = twine.NewCipher([]byte(*key))
		case "saferplus", "safer+":
			c, err = saferplus.NewCipher([]byte(*key))
		case "belt":
			c, err = belt.NewCipher([]byte(*key))
		default:
			log.Fatalf("Unsupported cipher type: %s", *cph)
		}
		if err != nil {
			log.Fatal(err)
		}

		h, _ := cmac.New(c)
		io.Copy(h, inputfile)
		var verify bool
		if *sig != "" {
			macBytes := h.Sum(nil)

			sigBytes, err := hex.DecodeString(*sig)
			if err != nil {
				log.Fatal(err)
			}

			if len(macBytes) != len(sigBytes) {
				verify = false
			} else {
				verify = subtle.ConstantTimeCompare(macBytes, sigBytes) == 1
			}

			fmt.Printf("Verified: %t\n", verify)
			if verify {
				os.Exit(0)
			} else {
				os.Exit(1)
			}
		}
		fmt.Println("CMAC-"+strings.ToUpper(*cph)+"("+inputdesc+")=", hex.EncodeToString(h.Sum(nil)))
		os.Exit(0)
	}

	if *mac == "pmac" {
		var c cipher.Block
		var err error
		switch *cph {
		case "blowfish":
			c, err = blowfish.NewCipher([]byte(*key))
		case "idea":
			c, err = idea.NewCipher([]byte(*key))
		case "cast5":
			c, err = cast5.NewCipher([]byte(*key))
		case "rc5":
			c, err = rc5.New([]byte(*key))
		case "sm4":
			c, err = sm4.NewCipher([]byte(*key))
		case "seed":
			c, err = krcrypt.NewSEED([]byte(*key))
		case "hight":
			c, err = krcrypt.NewHIGHT([]byte(*key))
		case "rc2":
			c, err = rc2.NewCipher([]byte(*key))
		case "des":
			c, err = des.NewCipher([]byte(*key))
		case "3des":
			c, err = des.NewTripleDESCipher([]byte(*key))
		case "aes":
			c, err = aes.NewCipher([]byte(*key))
		case "twofish":
			c, err = twofish.NewCipher([]byte(*key))
		case "aria":
			c, err = aria.NewCipher([]byte(*key))
		case "lea":
			c, err = lea.NewCipher([]byte(*key))
		case "camellia":
			c, err = camellia.NewCipher([]byte(*key))
		case "serpent":
			c, err = serpent.NewCipher([]byte(*key))
		case "rc6":
			c, err = rc6.NewCipher([]byte(*key))
		case "magenta":
			c, err = magenta.NewCipher([]byte(*key))
		case "misty1":
			c, err = misty1.New([]byte(*key))
		case "magma":
			if len(*key) != 32 {
				log.Fatal("MAGMA invalid key size ", len(*key))
			}
			c = gost341264.NewCipher([]byte(*key))
		case "grasshopper", "kuznechik":
			if len(*key) != 32 {
				log.Fatal("KUZNECHIK: invalid key size ", len(*key))
			}
			c, err = kuznechik.NewCipher([]byte(*key))
		case "gost89":
			if len(*key) != 32 {
				log.Fatal("GOST89: invalid key size ", len(*key))
			}
			c = gost28147.NewCipher([]byte(*key), &gost28147.SboxIdtc26gost28147paramZ)
		case "anubis":
			if len(*key) != 16 && len(*key) != 24 && len(*key) != 32 && len(*key) != 40 {
				log.Fatal("ANUBIS: invalid key size ", len(*key))
			}
			c, err = anubis.NewWithKeySize([]byte(*key), len(*key))
		case "threefish256", "threefish":
			var tweak []byte
			tweak = make([]byte, 16)
			if *tweakStr != "" {
				tweak = []byte(*tweakStr)
			}
			c, err = threefish.New256([]byte(*key), tweak)
		case "threefish512":
			var tweak []byte
			tweak = make([]byte, 16)
			if *tweakStr != "" {
				tweak = []byte(*tweakStr)
			}
			c, err = threefish.New512([]byte(*key), tweak)
		case "threefish1024":
			var tweak []byte
			tweak = make([]byte, 16)
			if *tweakStr != "" {
				tweak = []byte(*tweakStr)
			}
			c, err = threefish.New1024([]byte(*key), tweak)
		case "khazad":
			c, err = khazad.NewCipher([]byte(*key))
		case "mars":
			c, err = mars.NewCipher([]byte(*key))
		case "noekeon":
			c, err = noekeon.NewCipher([]byte(*key))
		case "loki97":
			c, err = loki97.NewCipher([]byte(*key))
		case "clefia":
			c, err = clefia.NewCipher([]byte(*key))
		case "kalyna128_128":
			c, err = kalyna.NewCipher128_128([]byte(*key))
		case "kalyna128_256":
			c, err = kalyna.NewCipher128_256([]byte(*key))
		case "kalyna256_256":
			c, err = kalyna.NewCipher256_256([]byte(*key))
		case "kalyna256_512":
			c, err = kalyna.NewCipher256_512([]byte(*key))
		case "kalyna512_512":
			c, err = kalyna.NewCipher512_512([]byte(*key))
		case "cast256", "cast6":
			c, err = cast256.NewCipher([]byte(*key))
		case "e2":
			c, err = e2.NewCipher([]byte(*key))
		case "crypton":
			c, err = crypton1.NewCipher([]byte(*key))
		case "present":
			c, err = present.NewCipher([]byte(*key))
		case "twine":
			c, err = twine.NewCipher([]byte(*key))
		case "shacal2":
			c, err = shacal2.NewCipher([]byte(*key))
		case "saferplus", "safer+":
			c, err = saferplus.NewCipher([]byte(*key))
		case "belt":
			c, err = belt.NewCipher([]byte(*key))
		default:
			log.Fatalf("Unsupported cipher type: %s", *cph)
		}
		if err != nil {
			log.Fatal(err)
		}

		h, err := pmac.New(c)
		if err != nil {
			log.Fatal(err)
		}
		io.Copy(h, inputfile)
		var verify bool
		if *sig != "" {
			macBytes := h.Sum(nil)

			sigBytes, err := hex.DecodeString(*sig)
			if err != nil {
				log.Fatal(err)
			}

			if len(macBytes) != len(sigBytes) {
				verify = false
			} else {
				verify = subtle.ConstantTimeCompare(macBytes, sigBytes) == 1
			}

			fmt.Printf("Verified: %t\n", verify)
			if verify {
				os.Exit(0)
			} else {
				os.Exit(1)
			}
		}
		fmt.Println("PMAC-"+strings.ToUpper(*cph)+"("+inputdesc+")=", hex.EncodeToString(h.Sum(nil)))
		os.Exit(0)
	}

	if *mac == "gmac" {
		var c cipher.Block
		var err error

		key := []byte(*key)

		switch *cph {
		case "sm4":
			c, err = sm4.NewCipher(key)
		case "seed":
			c, err = krcrypt.NewSEED(key)
		case "aes":
			c, err = aes.NewCipher(key)
		case "twofish":
			c, err = twofish.NewCipher(key)
		case "aria":
			c, err = aria.NewCipher(key)
		case "lea":
			c, err = lea.NewCipher(key)
		case "camellia":
			c, err = camellia.NewCipher(key)
		case "serpent":
			c, err = serpent.NewCipher(key)
		case "rc6":
			c, err = rc6.NewCipher(key)
		case "magenta":
			c, err = magenta.NewCipher(key)
		case "grasshopper", "kuznechik":
			c, err = kuznechik.NewCipher(key)
		case "anubis":
			c, err = anubis.NewWithKeySize(key, len(key))
		case "mars":
			c, err = mars.NewCipher(key)
		case "noekeon":
			c, err = noekeon.NewCipher(key)
		case "loki97":
			c, err = loki97.NewCipher(key)
		case "clefia":
			c, err = clefia.NewCipher(key)
		case "kalyna128_128":
			c, err = kalyna.NewCipher128_128(key)
		case "kalyna128_256":
			c, err = kalyna.NewCipher128_256(key)
		case "cast256", "cast6":
			c, err = cast256.NewCipher(key)
		case "e2":
			c, err = e2.NewCipher(key)
		case "crypton":
			c, err = crypton1.NewCipher(key)
		case "saferplus", "safer+":
			c, err = saferplus.NewCipher(key)
		case "belt":
			c, err = belt.NewCipher(key)
		default:
			log.Fatalf("Unsupported cipher type: %s", *cph)
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
			macBytes := h

			sigBytes, err := hex.DecodeString(*sig)
			if err != nil {
				log.Fatal(err)
			}

			if len(macBytes) != len(sigBytes) {
				verify = false
			} else {
				verify = subtle.ConstantTimeCompare(macBytes, sigBytes) == 1
			}

			fmt.Printf("Verified: %t\n", verify)
			if verify {
				os.Exit(0)
			} else {
				os.Exit(1)
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

		switch *cph {
		case "sm4":
			c, err = sm4.NewCipher(key)
			n = 16
		case "seed":
			c, err = krcrypt.NewSEED(key)
			n = 16
		case "aes":
			c, err = aes.NewCipher(key)
			n = 16
		case "twofish":
			c, err = twofish.NewCipher(key)
			n = 16
		case "aria":
			c, err = aria.NewCipher(key)
			n = 16
		case "lea":
			c, err = lea.NewCipher(key)
			n = 16
		case "camellia":
			c, err = camellia.NewCipher(key)
			n = 16
		case "serpent":
			c, err = serpent.NewCipher(key)
			n = 16
		case "rc6":
			c, err = rc6.NewCipher(key)
			n = 16
		case "magenta":
			c, err = magenta.NewCipher(key)
			n = 16
		case "magma":
			c = gost341264.NewCipher(key)
			n = 8
		case "gost89":
			c = gost28147.NewCipher(key, &gost28147.SboxIdtc26gost28147paramZ)
			n = 8
		case "grasshopper", "kuznechik":
			c, err = kuznechik.NewCipher(key)
			n = 16
		case "anubis":
			c, err = anubis.NewWithKeySize(key, len(key))
			n = 16
		case "blowfish":
			c, err = blowfish.NewCipher(key)
			n = 8
		case "idea":
			c, err = idea.NewCipher(key)
			n = 8
		case "cast5":
			c, err = cast5.NewCipher(key)
			n = 8
		case "rc5":
			c, err = rc5.New(key)
			n = 8
		case "hight":
			c, err = krcrypt.NewHIGHT(key)
			n = 8
		case "rc2":
			c, err = rc2.NewCipher(key)
			n = 8
		case "des":
			c, err = des.NewCipher(key)
			n = 8
		case "3des":
			c, err = des.NewTripleDESCipher(key)
			n = 8
		case "khazad":
			c, err = khazad.NewCipher(key)
			n = 8
		case "present":
			c, err = present.NewCipher(key)
			n = 8
		case "twine":
			c, err = twine.NewCipher(key)
			n = 8
		case "kalyna128_128":
			c, err = kalyna.NewCipher128_128(key)
			n = 16
		case "kalyna128_256":
			c, err = kalyna.NewCipher128_256(key)
			n = 16
		case "cast256", "cast6":
			c, err = cast256.NewCipher(key)
			n = 16
		case "e2":
			c, err = e2.NewCipher(key)
			n = 16
		case "crypton":
			c, err = crypton1.NewCipher(key)
			n = 16
		case "saferplus", "safer+":
			c, err = saferplus.NewCipher(key)
			n = 8
		case "belt":
			c, err = belt.NewCipher(key)
			n = 16
		default:
			log.Fatalf("Unsupported cipher type: %s", *cph)
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
		nonce[0] &= 0x7F
		h, err := NewMGMAC(c, n, nonce, message)
		if err != nil {
			log.Fatal(err)
		}
		var verify bool
		if *sig != "" {
			macBytes := h

			sigBytes, err := hex.DecodeString(*sig)
			if err != nil {
				log.Fatal(err)
			}

			if len(macBytes) != len(sigBytes) {
				verify = false
			} else {
				verify = subtle.ConstantTimeCompare(macBytes, sigBytes) == 1
			}

			fmt.Printf("Verified: %t\n", verify)
			if verify {
				os.Exit(0)
			} else {
				os.Exit(1)
			}
		}
		fmt.Println("MGMAC-"+strings.ToUpper(*cph)+"("+inputdesc+")=", hex.EncodeToString(h))
		os.Exit(0)
	}

	if *mac == "vmac" {
		var c cipher.Block
		var err error
		switch *cph {
		case "blowfish":
			c, err = blowfish.NewCipher([]byte(*key))
		case "idea":
			c, err = idea.NewCipher([]byte(*key))
		case "cast5":
			c, err = cast5.NewCipher([]byte(*key))
		case "rc5":
			c, err = rc5.New([]byte(*key))
		case "sm4":
			c, err = sm4.NewCipher([]byte(*key))
		case "seed":
			c, err = krcrypt.NewSEED([]byte(*key))
		case "hight":
			c, err = krcrypt.NewHIGHT([]byte(*key))
		case "rc2":
			c, err = rc2.NewCipher([]byte(*key))
		case "des":
			c, err = des.NewCipher([]byte(*key))
		case "3des":
			c, err = des.NewTripleDESCipher([]byte(*key))
		case "aes":
			c, err = aes.NewCipher([]byte(*key))
		case "twofish":
			c, err = twofish.NewCipher([]byte(*key))
		case "aria":
			c, err = aria.NewCipher([]byte(*key))
		case "lea":
			c, err = lea.NewCipher([]byte(*key))
		case "camellia":
			c, err = camellia.NewCipher([]byte(*key))
		case "serpent":
			c, err = serpent.NewCipher([]byte(*key))
		case "rc6":
			c, err = rc6.NewCipher([]byte(*key))
		case "magenta":
			c, err = magenta.NewCipher([]byte(*key))
		case "misty1":
			c, err = misty1.New([]byte(*key))
		case "magma":
			if len(*key) != 32 {
				log.Fatal("MAGMA invalid key size ", len(*key))
			}
			c = gost341264.NewCipher([]byte(*key))
		case "grasshopper", "kuznechik":
			if len(*key) != 32 {
				log.Fatal("KUZNECHIK: invalid key size ", len(*key))
			}
			c, err = kuznechik.NewCipher([]byte(*key))
		case "gost89":
			if len(*key) != 32 {
				log.Fatal("GOST89: invalid key size ", len(*key))
			}
			c = gost28147.NewCipher([]byte(*key), &gost28147.SboxIdtc26gost28147paramZ)
		case "anubis":
			if len(*key) != 16 && len(*key) != 24 && len(*key) != 32 && len(*key) != 40 {
				log.Fatal("ANUBIS: invalid key size ", len(*key))
			}
			c, err = anubis.NewWithKeySize([]byte(*key), len(*key))
		case "threefish256", "threefish":
			var tweak []byte
			tweak = make([]byte, 16)
			if *tweakStr != "" {
				tweak = []byte(*tweakStr)
			}
			c, err = threefish.New256([]byte(*key), tweak)
		case "threefish512":
			var tweak []byte
			tweak = make([]byte, 16)
			if *tweakStr != "" {
				tweak = []byte(*tweakStr)
			}
			c, err = threefish.New512([]byte(*key), tweak)
		case "threefish1024":
			var tweak []byte
			tweak = make([]byte, 16)
			if *tweakStr != "" {
				tweak = []byte(*tweakStr)
			}
			c, err = threefish.New1024([]byte(*key), tweak)
		case "khazad":
			c, err = khazad.NewCipher([]byte(*key))
		case "mars":
			c, err = mars.NewCipher([]byte(*key))
		case "noekeon":
			c, err = noekeon.NewCipher([]byte(*key))
		case "loki97":
			c, err = loki97.NewCipher([]byte(*key))
		case "clefia":
			c, err = clefia.NewCipher([]byte(*key))
		case "kalyna128_128":
			c, err = kalyna.NewCipher128_128([]byte(*key))
		case "kalyna128_256":
			c, err = kalyna.NewCipher128_256([]byte(*key))
		case "kalyna256_256":
			c, err = kalyna.NewCipher256_256([]byte(*key))
		case "kalyna256_512":
			c, err = kalyna.NewCipher256_512([]byte(*key))
		case "kalyna512_512":
			c, err = kalyna.NewCipher512_512([]byte(*key))
		case "cast256", "cast6":
			c, err = cast256.NewCipher([]byte(*key))
		case "e2":
			c, err = e2.NewCipher([]byte(*key))
		case "crypton":
			c, err = crypton1.NewCipher([]byte(*key))
		case "present":
			c, err = present.NewCipher([]byte(*key))
		case "twine":
			c, err = twine.NewCipher([]byte(*key))
		case "curupira":
			c, err = curupira1.NewCipher([]byte(*key))
		case "shacal2":
			c, err = shacal2.NewCipher([]byte(*key))
		case "saferplus", "safer+":
			c, err = saferplus.NewCipher([]byte(*key))
		case "belt":
			c, err = belt.NewCipher([]byte(*key))
		default:
			log.Fatalf("Unsupported cipher type: %s", *cph)
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
			macBytes := h.Sum()

			sigBytes, err := hex.DecodeString(*sig)
			if err != nil {
				log.Fatal(err)
			}

			if len(macBytes) != len(sigBytes) {
				verify = false
			} else {
				verify = subtle.ConstantTimeCompare(macBytes, sigBytes) == 1
			}

			fmt.Printf("Verified: %t\n", verify)
			if verify {
				os.Exit(0)
			} else {
				os.Exit(1)
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
		hash, err := Hkdf([]byte(*key), []byte(*salt), []byte(*info))
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%x\n", hash[:*length/8])
	}

	if strings.ToUpper(*alg) == "EC" || strings.ToUpper(*alg) == "ECDSA" && (*pkey == "sign" || *pkey == "verify" || *pkey == "derive" || *pkey == "encrypt" || *pkey == "decrypt") {
		if data, err := ioutil.ReadFile(*key); err == nil {
			if block, _ := pem.Decode(data); block != nil {
				if strings.Contains(block.Type, "NUMS") {
					*alg = "NUMS"
				} else if strings.Contains(block.Type, "KOBLITZ") {
					*alg = "KOBLITZ"
				} else if strings.Contains(block.Type, "ANSSI") {
					*alg = "ANSSI"
				} else if strings.Contains(block.Type, "TOM") {
					*alg = "TOM"
				}
			}
		}
	}

	var pubkey ecdsa.PublicKey
	var public *ecdsa.PublicKey
	var pubkeyCurve elliptic.Curve

	if *pkey == "keygen" && *curveFlag == "sect283k1" {
		pubkeyCurve = nist.K283()
	} else if *pkey == "keygen" && *length == 283 || *curveFlag == "sect283r1" {
		pubkeyCurve = nist.B283()
	} else if *pkey == "keygen" && *curveFlag == "sect409k1" {
		pubkeyCurve = nist.K409()
	} else if *pkey == "keygen" && *length == 409 || *curveFlag == "sect409r1" {
		pubkeyCurve = nist.B409()
	} else if *pkey == "keygen" && *curveFlag == "sect571k1" {
		pubkeyCurve = nist.K571()
	} else if *pkey == "keygen" && *length == 571 || *curveFlag == "sect571r1" {
		pubkeyCurve = nist.B571()
	} else if *pkey == "keygen" && *curveFlag == "brainpoolp256r1" {
		pubkeyCurve = brainpool.P256r1()
	} else if *pkey == "keygen" && *curveFlag == "brainpoolp256t1" {
		pubkeyCurve = brainpool.P256t1()
	} else if *pkey == "keygen" && *curveFlag == "brainpoolp384r1" {
		pubkeyCurve = brainpool.P384r1()
	} else if *pkey == "keygen" && *curveFlag == "brainpoolp384t1" {
		pubkeyCurve = brainpool.P384t1()
	} else if *pkey == "keygen" && *curveFlag == "brainpoolp512r1" {
		pubkeyCurve = brainpool.P512r1()
	} else if *pkey == "keygen" && *curveFlag == "brainpoolp512t1" {
		pubkeyCurve = brainpool.P512t1()
	} else if *pkey == "keygen" && *curveFlag == "secp256k1" {
		pubkeyCurve = secp256k1.S256()
	} else if *pkey == "keygen" && *curveFlag == "frp256v1" {
		pubkeyCurve = frp256v1.P256()
	} else if *pkey == "keygen" && *length == 224 || *curveFlag == "secp224r1" {
		pubkeyCurve = elliptic.P224()
	} else if *pkey == "keygen" && *length == 384 || *curveFlag == "secp384r1" {
		pubkeyCurve = elliptic.P384()
	} else if *pkey == "keygen" && *length == 521 || *curveFlag == "secp521r1" {
		pubkeyCurve = elliptic.P521()
	} else if *pkey == "keygen" && *length == 256 || *curveFlag == "secp256r1" {
		pubkeyCurve = elliptic.P256()
	} else if *pkey == "keygen" && *curveFlag == "numsp256d1" {
		pubkeyCurve = nums.P256d1()
	} else if *pkey == "keygen" && *curveFlag == "numsp256t1" {
		pubkeyCurve = nums.P256t1()
	} else if *pkey == "keygen" && *curveFlag == "numsp384d1" {
		pubkeyCurve = nums.P384d1()
	} else if *pkey == "keygen" && *curveFlag == "numsp384t1" {
		pubkeyCurve = nums.P384t1()
	} else if *pkey == "keygen" && *curveFlag == "numsp512d1" {
		pubkeyCurve = nums.P512d1()
	} else if *pkey == "keygen" && *curveFlag == "numsp512t1" {
		pubkeyCurve = nums.P512t1()
	} else if *pkey == "keygen" && *curveFlag == "tom256" {
		pubkeyCurve = tom.P256()
	} else if *pkey == "keygen" && *curveFlag == "tom384" {
		pubkeyCurve = tom.P384()
	}

	if *pkey == "keygen" && (strings.ToUpper(*alg) == "EC" || strings.ToUpper(*alg) == "ECDSA") && (*length == 224 || *length == 256 || *length == 384 || *length == 521 || *curveFlag == "secp224r1" || *curveFlag == "secp384r1" || *curveFlag == "secp521r1" || *curveFlag == "secp256r1") && *curveFlag != "frp256v1" && *curveFlag != "secp256k1" && *curveFlag != "numsp256t1" && *curveFlag != "numsp384t1" && *curveFlag != "numsp512t1" && *curveFlag != "numsp256d1" && *curveFlag != "numsp384d1" && *curveFlag != "numsp512d1" && *curveFlag != "tom256" && *curveFlag != "tom384" {
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

	if *pkey == "keygen" && (strings.ToUpper(*alg) == "ECKCDSA") && ((*length == 224 || *length == 256 || *length == 384 || *length == 521 || *length == 283 || *length == 409 || *length == 571) || (*curveFlag == "secp224r1" || *curveFlag == "secp384r1" || *curveFlag == "secp521r1" || *curveFlag == "secp256r1" || *curveFlag == "sect283r1" || *curveFlag == "sect409r1" || *curveFlag == "sect571r1" || *curveFlag == "sect283k1" || *curveFlag == "sect409k1" || *curveFlag == "sect571k1")) {
		privateKey, err := eckcdsa.GenerateKey(pubkeyCurve, rand.Reader)
		if err != nil {
			log.Fatal("Error generating private key:", err)
		}

		pubkey := privateKey.PublicKey
		pripem, _ := EncodeECKCDSAPrivateKey(privateKey)
		ioutil.WriteFile(*priv, pripem, 0644)

		pubpem, _ := EncodeECKCDSAPublicKey(&pubkey)
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

	if *pkey == "keygen" && (strings.ToUpper(*alg) == "ECGDSA") && ((*length == 224 || *length == 256 || *length == 384 || *length == 512 || *length == 521) || (*curveFlag == "secp224r1" || *curveFlag == "secp384r1" || *curveFlag == "secp521r1" || *curveFlag == "secp256r1" || *curveFlag != "frp256v1" || *curveFlag != "secp256k1" || *curveFlag == "brainpoolp256r1" || *curveFlag == "brainpoolp384r1" || *curveFlag == "brainpoolp512r1" || *curveFlag == "brainpoolp256t1" || *curveFlag == "brainpoolp384t1" || *curveFlag == "brainpoolp512t1" || *curveFlag == "numsp256t1" || *curveFlag == "numsp384t1" || *curveFlag == "numsp512t1" || *curveFlag == "numsp256d1" || *curveFlag == "numsp384d1" || *curveFlag == "numsp512d1" || *curveFlag == "tom256" || *curveFlag == "tom384" || *curveFlag == "sect283r1" || *curveFlag == "sect409r1" || *curveFlag == "sect571r1" || *curveFlag == "sect283k1" || *curveFlag == "sect409k1" || *curveFlag == "sect571k1")) {
		privateKey, err := ecgdsa.GenerateKey(rand.Reader, pubkeyCurve)
		if err != nil {
			log.Fatal("Error generating private key:", err)
		}

		pubkey := privateKey.PublicKey
		pripem, _ := EncodeECGDSAPrivateKey(privateKey)
		ioutil.WriteFile(*priv, pripem, 0644)

		pubpem, _ := EncodeECGDSAPublicKey(&pubkey)
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

	if *pkey == "keygen" && (strings.ToUpper(*alg) == "ECSDSA") && ((*length == 224 || *length == 256 || *length == 384 || *length == 512 || *length == 521) || (*curveFlag == "secp224r1" || *curveFlag == "secp384r1" || *curveFlag == "secp521r1" || *curveFlag == "secp256r1" || *curveFlag != "frp256v1" || *curveFlag != "secp256k1" || *curveFlag == "brainpoolp256r1" || *curveFlag == "brainpoolp384r1" || *curveFlag == "brainpoolp512r1" || *curveFlag == "brainpoolp256t1" || *curveFlag == "brainpoolp384t1" || *curveFlag == "brainpoolp512t1" || *curveFlag == "numsp256t1" || *curveFlag == "numsp384t1" || *curveFlag == "numsp512t1" || *curveFlag == "numsp256d1" || *curveFlag == "numsp384d1" || *curveFlag == "numsp512d1" || *curveFlag == "tom256" || *curveFlag == "tom384" || *curveFlag == "sect283r1" || *curveFlag == "sect409r1" || *curveFlag == "sect571r1" || *curveFlag == "sect283k1" || *curveFlag == "sect409k1" || *curveFlag == "sect571k1")) {
		privateKey, err := ecsdsa.GenerateKey(rand.Reader, pubkeyCurve)
		if err != nil {
			log.Fatal("Error generating private key:", err)
		}

		pubkey := privateKey.PublicKey
		pripem, _ := EncodeECSDSAPrivateKey(privateKey)
		ioutil.WriteFile(*priv, pripem, 0644)

		pubpem, _ := EncodeECSDSAPublicKey(&pubkey)
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

	if *pkey == "keygen" && (strings.ToUpper(*alg) == "BIP0340") && ((*length == 224 || *length == 256 || *length == 384 || *length == 512 || *length == 521) || (*curveFlag == "secp224r1" || *curveFlag == "secp384r1" || *curveFlag == "secp521r1" || *curveFlag == "secp256r1" || *curveFlag != "frp256v1" || *curveFlag != "secp256k1" || *curveFlag == "brainpoolp256r1" || *curveFlag == "brainpoolp384r1" || *curveFlag == "brainpoolp512r1" || *curveFlag == "brainpoolp256t1" || *curveFlag == "brainpoolp384t1" || *curveFlag == "brainpoolp512t1" || *curveFlag == "numsp256t1" || *curveFlag == "numsp384t1" || *curveFlag == "numsp512t1" || *curveFlag == "numsp256d1" || *curveFlag == "numsp384d1" || *curveFlag == "numsp512d1" || *curveFlag == "tom256" || *curveFlag == "tom384" || *curveFlag == "sect283r1" || *curveFlag == "sect409r1" || *curveFlag == "sect571r1" || *curveFlag == "sect283k1" || *curveFlag == "sect409k1" || *curveFlag == "sect571k1")) {
		privateKey, err := bip0340.GenerateKey(rand.Reader, pubkeyCurve)
		if err != nil {
			log.Fatal("Error generating private key:", err)
		}

		pubkey := privateKey.PublicKey
		pripem, _ := EncodeBIP0340PrivateKey(privateKey)
		ioutil.WriteFile(*priv, pripem, 0644)

		pubpem, _ := EncodeBIP0340PublicKey(&pubkey)
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

	if *pkey == "keygen" && strings.ToUpper(*alg) == "ANSSI" || (strings.ToUpper(*alg) == "EC" || strings.ToUpper(*alg) == "ECDSA") && *curveFlag == "frp256v1" {
		privateKey, err := ecdsa.GenerateKey(frp256v1.P256(), rand.Reader)
		if err != nil {
			log.Fatal("Error generating private key:", err)
		}

		pk := frp256v1.NewPrivateKey(privateKey)

		pubkey := pk.PublicKey
		pripem, _ := EncodeANSSIPrivateKey(pk)
		ioutil.WriteFile(*priv, pripem, 0644)

		pubpem, _ := EncodeANSSIPublicKey(&pubkey)
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

	if *pkey == "encrypt" && (strings.ToUpper(*alg) == "ANSSI") {
		file, err := ioutil.ReadFile(*key)
		if err != nil {
			log.Fatal(err)
		}
		public, err := DecodeANSSIPublicKey(file)
		if err != nil {
			log.Fatal(err)
		}
		buf := bytes.NewBuffer(nil)
		data := inputfile
		io.Copy(buf, data)
		scanner := string(buf.Bytes())
		ciphertxt, err := public.ToECDSA().EncryptAsn1([]byte(scanner), rand.Reader)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s", ciphertxt)
		os.Exit(0)
	}

	if *pkey == "decrypt" && (strings.ToUpper(*alg) == "ANSSI") {
		var privatekey *frp256v1.PrivateKey
		file, err := ioutil.ReadFile(*key)
		if err != nil {
			log.Fatal(err)
		}
		privatekey, err = DecodeANSSIPrivateKey(file)
		if err != nil {
			log.Fatal(err)
		}
		buf := bytes.NewBuffer(nil)
		data := inputfile
		io.Copy(buf, data)
		scanner := string(buf.Bytes())
		str := string(scanner)
		plaintxt, err := privatekey.ToECDSAPrivateKey().DecryptAsn1([]byte(str))
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s", plaintxt)
		os.Exit(0)
	}

	if *pkey == "sign" && (strings.ToUpper(*alg) == "ANSSI") {
		var privatekey *frp256v1.PrivateKey
		var h hash.Hash
		h = myHash()
		if _, err := io.Copy(h, inputfile); err != nil {
			log.Fatal(err)
		}
		file, err := ioutil.ReadFile(*key)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		privatekey, err = DecodeANSSIPrivateKey(file)
		if err != nil {
			log.Fatal(err)
		}
		signature, err := ecdsa.SignASN1(rand.Reader, privatekey.ToECDSAPrivateKey(), h.Sum(nil))
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(strings.ToUpper(*alg)+"-"+strings.ToUpper(*md)+"("+inputdesc+")=", hex.EncodeToString(signature))
		os.Exit(0)
	}

	if *pkey == "verify" && (strings.ToUpper(*alg) == "ANSSI") {
		var h hash.Hash
		h = myHash()
		if _, err := io.Copy(h, inputfile); err != nil {
			log.Fatal(err)
		}
		file, err := ioutil.ReadFile(*key)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		public, err := DecodeANSSIPublicKey(file)
		if err != nil {
			log.Fatal(err)
		}
		sig, _ := hex.DecodeString(*sig)
		verifystatus := ecdsa.VerifyASN1(public.ToECDSA(), h.Sum(nil), sig)
		if verifystatus == true {
			fmt.Printf("Verified: %v\n", verifystatus)
			os.Exit(0)
		} else {
			fmt.Printf("Verified: %v\n", verifystatus)
			os.Exit(1)
		}
		os.Exit(0)
	}

	if *pkey == "derive" && strings.ToUpper(*alg) == "ANSSI" {
		var privatekey *frp256v1.PrivateKey
		file, err := ioutil.ReadFile(*pub)
		if err != nil {
			log.Fatal(err)
		}
		public, err := DecodeANSSIPublicKey(file)
		if err != nil {
			log.Fatal(err)
		}
		file2, err := ioutil.ReadFile(*key)
		if err != nil {
			log.Fatal(err)
			os.Exit(1)
		}
		privatekey, err = DecodeANSSIPrivateKey(file2)
		if err != nil {
			log.Fatal(err)
		}
		sharedKey, err := frp256v1.ECDH(privatekey.ToECDSAPrivateKey(), public.ToECDSA())
		if err != nil {
			log.Fatal("Error computing shared key:", err)
		}
		fmt.Printf("%x\n", sharedKey)
		os.Exit(0)
	}

	if *pkey == "derive" && strings.ToUpper(*alg) == "BIP0340" {
		var privatekey *bip0340.PrivateKey

		file, err := ioutil.ReadFile(*pub)
		if err != nil {
			log.Fatal(err)
		}
		public, err := DecodeBIP0340PublicKey(file)
		if err != nil {
			log.Fatal(err)
		}

		if public.X == nil || public.Y == nil {
			log.Fatal("invalid public key: coordinates are nil")
		}
		if public.X.Sign() == 0 && public.Y.Sign() == 0 {
			log.Fatal("invalid public key: point at infinity")
		}
		if !public.Curve.IsOnCurve(public.X, public.Y) {
			log.Fatal("invalid public key: point not on curve")
		}

		file2, err := ioutil.ReadFile(*key)
		if err != nil {
			log.Fatal(err)
		}
		privatekey, err = DecodeBIP0340PrivateKey(file2)
		if err != nil {
			log.Fatal(err)
		}

		if privatekey.D.Cmp(public.Curve.Params().N) >= 0 || privatekey.D.Sign() <= 0 {
			log.Fatal("invalid private key: scalar out of range")
		}

		bX, bY := public.Curve.ScalarMult(public.X, public.Y, privatekey.D.Bytes())

		if bX == nil || bY == nil {
			log.Fatal("invalid shared secret: null point")
		}
		if bX.Sign() == 0 && bY.Sign() == 0 {
			log.Fatal("invalid shared secret: point at infinity")
		}
		if !public.Curve.IsOnCurve(bX, bY) {
			log.Fatal("invalid shared secret: point not on curve")
		}

		fmt.Printf("%x\n", bX.Bytes())
		os.Exit(0)
	}

	if *pkey == "derive" && strings.ToUpper(*alg) == "ECSDSA" {
		var privatekey *ecsdsa.PrivateKey

		file, err := ioutil.ReadFile(*pub)
		if err != nil {
			log.Fatal(err)
		}
		public, err := DecodeECSDSAPublicKey(file)
		if err != nil {
			log.Fatal(err)
		}

		if public.X == nil || public.Y == nil {
			log.Fatal("invalid public key: coordinates are nil")
		}
		if public.X.Sign() == 0 && public.Y.Sign() == 0 {
			log.Fatal("invalid public key: point at infinity")
		}
		if !public.Curve.IsOnCurve(public.X, public.Y) {
			log.Fatal("invalid public key: point not on curve")
		}

		file2, err := ioutil.ReadFile(*key)
		if err != nil {
			log.Fatal(err)
		}
		privatekey, err = DecodeECSDSAPrivateKey(file2)
		if err != nil {
			log.Fatal(err)
		}

		if privatekey.D.Cmp(public.Curve.Params().N) >= 0 || privatekey.D.Sign() <= 0 {
			log.Fatal("invalid private key: scalar out of range")
		}

		bX, bY := public.Curve.ScalarMult(public.X, public.Y, privatekey.D.Bytes())

		if bX == nil || bY == nil {
			log.Fatal("invalid shared secret: null point")
		}
		if bX.Sign() == 0 && bY.Sign() == 0 {
			log.Fatal("invalid shared secret: point at infinity")
		}
		if !public.Curve.IsOnCurve(bX, bY) {
			log.Fatal("invalid shared secret: point not on curve")
		}

		fmt.Printf("%x\n", bX.Bytes())
		os.Exit(0)
	}

	if *pkey == "keygen" && strings.ToUpper(*alg) == "KOBLITZ" || (strings.ToUpper(*alg) == "EC" || strings.ToUpper(*alg) == "ECDSA") && *curveFlag == "secp256k1" {
		privateKey, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
		if err != nil {
			log.Fatal("Error generating private key:", err)
		}

		pk := secp256k1.NewPrivateKey(privateKey)

		pubkey := pk.PublicKey
		pripem, _ := EncodeKOBLITZPrivateKey(pk)
		ioutil.WriteFile(*priv, pripem, 0644)

		pubpem, _ := EncodeKOBLITZPublicKey(&pubkey)
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

	if *pkey == "encrypt" && (strings.ToUpper(*alg) == "KOBLITZ") {
		file, err := ioutil.ReadFile(*key)
		if err != nil {
			log.Fatal(err)
		}
		public, err := DecodeKOBLITZPublicKey(file)
		if err != nil {
			log.Fatal(err)
		}
		buf := bytes.NewBuffer(nil)
		data := inputfile
		io.Copy(buf, data)
		scanner := string(buf.Bytes())
		ciphertxt, err := public.ToECDSA().EncryptAsn1([]byte(scanner), rand.Reader)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s", ciphertxt)
		os.Exit(0)
	}

	if *pkey == "decrypt" && (strings.ToUpper(*alg) == "KOBLITZ") {
		var privatekey *secp256k1.PrivateKey
		file, err := ioutil.ReadFile(*key)
		if err != nil {
			log.Fatal(err)
		}
		privatekey, err = DecodeKOBLITZPrivateKey(file)
		if err != nil {
			log.Fatal(err)
		}
		buf := bytes.NewBuffer(nil)
		data := inputfile
		io.Copy(buf, data)
		scanner := string(buf.Bytes())
		str := string(scanner)
		plaintxt, err := privatekey.ToECDSAPrivateKey().DecryptAsn1([]byte(str))
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s", plaintxt)
		os.Exit(0)
	}

	if *pkey == "sign" && (strings.ToUpper(*alg) == "KOBLITZ") {
		var privatekey *secp256k1.PrivateKey
		var h hash.Hash
		h = myHash()
		if _, err := io.Copy(h, inputfile); err != nil {
			log.Fatal(err)
		}
		file, err := ioutil.ReadFile(*key)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		privatekey, err = DecodeKOBLITZPrivateKey(file)
		if err != nil {
			log.Fatal(err)
		}
		signature, err := ecdsa.SignASN1(rand.Reader, privatekey.ToECDSAPrivateKey(), h.Sum(nil))
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(strings.ToUpper(*alg)+"-"+strings.ToUpper(*md)+"("+inputdesc+")=", hex.EncodeToString(signature))
		os.Exit(0)
	}

	if *pkey == "verify" && (strings.ToUpper(*alg) == "KOBLITZ") {
		var h hash.Hash
		h = myHash()
		if _, err := io.Copy(h, inputfile); err != nil {
			log.Fatal(err)
		}
		file, err := ioutil.ReadFile(*key)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		public, err := DecodeKOBLITZPublicKey(file)
		if err != nil {
			log.Fatal(err)
		}
		sig, _ := hex.DecodeString(*sig)
		verifystatus := ecdsa.VerifyASN1(public.ToECDSA(), h.Sum(nil), sig)
		if verifystatus == true {
			fmt.Printf("Verified: %v\n", verifystatus)
			os.Exit(0)
		} else {
			fmt.Printf("Verified: %v\n", verifystatus)
			os.Exit(1)
		}
		os.Exit(0)
	}

	if *pkey == "derive" && strings.ToUpper(*alg) == "KOBLITZ" {
		var privatekey *secp256k1.PrivateKey
		file, err := ioutil.ReadFile(*pub)
		if err != nil {
			log.Fatal(err)
		}
		public, err := DecodeKOBLITZPublicKey(file)
		if err != nil {
			log.Fatal(err)
		}
		file2, err := ioutil.ReadFile(*key)
		if err != nil {
			log.Fatal(err)
			os.Exit(1)
		}
		privatekey, err = DecodeKOBLITZPrivateKey(file2)
		if err != nil {
			log.Fatal(err)
		}
		sharedKey, err := secp256k1.ECDH(privatekey.ToECDSAPrivateKey(), public.ToECDSA())
		if err != nil {
			log.Fatal("Error computing shared key:", err)
		}
		fmt.Printf("%x\n", sharedKey)
		os.Exit(0)
	}

	if *pkey == "keygen" && strings.ToUpper(*alg) == "TOM" || ((strings.ToUpper(*alg) == "EC" || strings.ToUpper(*alg) == "ECDSA") && *curveFlag == "tom256" || *curveFlag == "tom384") {
		var curve elliptic.Curve

		if *length == 256 || *curveFlag == "tom256" {
			curve = tom.P256()
		} else if *length == 384 || *curveFlag == "tom384" {
			curve = tom.P384()
		}

		privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			log.Fatal("Error generating private key:", err)
		}

		pk := tom.NewPrivateKey(privateKey)

		pubkey := pk.PublicKey
		pripem, _ := EncodeTomPrivateKey(pk)
		ioutil.WriteFile(*priv, pripem, 0644)

		pubpem, _ := EncodeTomPublicKey(&pubkey)
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

	if *pkey == "encrypt" && (strings.ToUpper(*alg) == "TOM") {
		file, err := ioutil.ReadFile(*key)
		if err != nil {
			log.Fatal(err)
		}
		public, err := DecodeTomPublicKey(file)
		if err != nil {
			log.Fatal(err)
		}
		buf := bytes.NewBuffer(nil)
		data := inputfile
		io.Copy(buf, data)
		scanner := string(buf.Bytes())
		ciphertxt, err := public.ToECDSA().EncryptAsn1([]byte(scanner), rand.Reader)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s", ciphertxt)
		os.Exit(0)
	}

	if *pkey == "decrypt" && (strings.ToUpper(*alg) == "TOM") {
		var privatekey *tom.PrivateKey
		file, err := ioutil.ReadFile(*key)
		if err != nil {
			log.Fatal(err)
		}
		privatekey, err = DecodeTomPrivateKey(file)
		if err != nil {
			log.Fatal(err)
		}
		buf := bytes.NewBuffer(nil)
		data := inputfile
		io.Copy(buf, data)
		scanner := string(buf.Bytes())
		str := string(scanner)
		plaintxt, err := privatekey.ToECDSAPrivateKey().DecryptAsn1([]byte(str))
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s", plaintxt)
		os.Exit(0)
	}

	if *pkey == "sign" && (strings.ToUpper(*alg) == "TOM") {
		var privatekey *tom.PrivateKey
		var h hash.Hash
		h = myHash()
		if _, err := io.Copy(h, inputfile); err != nil {
			log.Fatal(err)
		}
		file, err := ioutil.ReadFile(*key)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		privatekey, err = DecodeTomPrivateKey(file)
		if err != nil {
			log.Fatal(err)
		}
		signature, err := ecdsa.SignASN1(rand.Reader, privatekey.ToECDSAPrivateKey(), h.Sum(nil))
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(strings.ToUpper(*alg)+"-"+strings.ToUpper(*md)+"("+inputdesc+")=", hex.EncodeToString(signature))
		os.Exit(0)
	}

	if *pkey == "verify" && (strings.ToUpper(*alg) == "TOM") {
		var h hash.Hash
		h = myHash()
		if _, err := io.Copy(h, inputfile); err != nil {
			log.Fatal(err)
		}
		file, err := ioutil.ReadFile(*key)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		public, err := DecodeTomPublicKey(file)
		if err != nil {
			log.Fatal(err)
		}
		sig, _ := hex.DecodeString(*sig)
		verifystatus := ecdsa.VerifyASN1(public.ToECDSA(), h.Sum(nil), sig)
		if verifystatus == true {
			fmt.Printf("Verified: %v\n", verifystatus)
			os.Exit(0)
		} else {
			fmt.Printf("Verified: %v\n", verifystatus)
			os.Exit(1)
		}
		os.Exit(0)
	}

	if *pkey == "derive" && strings.ToUpper(*alg) == "TOM" {
		var privatekey *tom.PrivateKey
		file, err := ioutil.ReadFile(*pub)
		if err != nil {
			log.Fatal(err)
		}
		public, err := DecodeTomPublicKey(file)
		if err != nil {
			log.Fatal(err)
		}
		file2, err := ioutil.ReadFile(*key)
		if err != nil {
			log.Fatal(err)
			os.Exit(1)
		}
		privatekey, err = DecodeTomPrivateKey(file2)
		if err != nil {
			log.Fatal(err)
		}
		sharedKey, err := tom.ECDH(privatekey.ToECDSAPrivateKey(), public.ToECDSA())
		if err != nil {
			log.Fatal("Error computing shared key:", err)
		}
		fmt.Printf("%x\n", sharedKey)
		os.Exit(0)
	}

	if *pkey == "keygen" && (strings.ToUpper(*alg) == "BIGN") && (*length == 256 || *length == 384 || *length == 512) {
		var BignCurve elliptic.Curve
		if *length == 256 {
			BignCurve = bigncurves.P256v1()
		} else if *length == 384 {
			BignCurve = bigncurves.P384v1()
		} else if *length == 512 {
			BignCurve = bigncurves.P512v1()
		}

		privateKey, err := bign.GenerateKey(rand.Reader, BignCurve)
		if err != nil {
			log.Fatal("Error generating private key:", err)
		}

		pubkey := privateKey.PublicKey
		pripem, _ := EncodeBIGNPrivateKey(privateKey)
		ioutil.WriteFile(*priv, pripem, 0644)

		pubpem, _ := EncodeBIGNPublicKey(&pubkey)
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

	if *pkey == "keygen" && ((strings.ToUpper(*alg) == "NUMS" || strings.ToUpper(*alg) == "NUMS-TE") && (*length == 256 || *length == 384 || *length == 512)) || ((strings.ToUpper(*alg) == "EC" || strings.ToUpper(*alg) == "ECDSA") && (*curveFlag == "numsp256d1" || *curveFlag == "numsp384d1" || *curveFlag == "numsp512d1" || *curveFlag == "numsp256t1" || *curveFlag == "numsp384t1" || *curveFlag == "numsp512t1")) {
		var curve elliptic.Curve

		switch {
		case strings.EqualFold(*curveFlag, "numsp256d1") || (*length == 256 && strings.EqualFold(*alg, "NUMS")):
			curve = nums.P256d1()
		case strings.EqualFold(*curveFlag, "numsp384d1") || (*length == 384 && strings.EqualFold(*alg, "NUMS")):
			curve = nums.P384d1()
		case strings.EqualFold(*curveFlag, "numsp512d1") || (*length == 512 && strings.EqualFold(*alg, "NUMS")):
			curve = nums.P512d1()
		case strings.EqualFold(*curveFlag, "numsp256t1") || (*length == 256 && strings.EqualFold(*alg, "NUMS-TE")):
			curve = nums.P256t1()
		case strings.EqualFold(*curveFlag, "numsp384t1") || (*length == 384 && strings.EqualFold(*alg, "NUMS-TE")):
			curve = nums.P384t1()
		case strings.EqualFold(*curveFlag, "numsp512t1") || (*length == 512 && strings.EqualFold(*alg, "NUMS-TE")):
			curve = nums.P512t1()
		default:
			log.Fatal("Unsupported curve or bit length. Use -curve or -bits with a valid value.")
		}

		privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			log.Fatal("Error generating private key:", err)
		}

		pk := nums.NewPrivateKey(privateKey)

		pubkey := pk.PublicKey
		pripem, _ := EncodeNUMSPrivateKey(pk)
		ioutil.WriteFile(*priv, pripem, 0644)

		pubpem, _ := EncodeNUMSPublicKey(&pubkey)
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
		keySize := pk.PublicKey.Curve.Params().BitSize
		switch keySize {
		case 256:
			fmt.Println("NUMS (256-bit)")
		case 384:
			fmt.Println("NUMS (384-bit)")
		case 512:
			fmt.Println("NUMS (512-bit)")
		default:
			fmt.Printf("Unknown key size: %d bits\n", keySize)
		}
		randomArt := randomart.FromString(string(buf))
		println(randomArt)

		os.Exit(0)
	}

	if *pkey == "encrypt" && (strings.ToUpper(*alg) == "NUMS") {
		file, err := ioutil.ReadFile(*key)
		if err != nil {
			log.Fatal(err)
		}
		public, err := DecodeNUMSPublicKey(file)
		if err != nil {
			log.Fatal(err)
		}
		buf := bytes.NewBuffer(nil)
		data := inputfile
		io.Copy(buf, data)
		scanner := string(buf.Bytes())
		ciphertxt, err := public.ToECDSA().EncryptAsn1([]byte(scanner), rand.Reader)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s", ciphertxt)
		os.Exit(0)
	}

	if *pkey == "decrypt" && (strings.ToUpper(*alg) == "NUMS") {
		var privatekey *nums.PrivateKey
		file, err := ioutil.ReadFile(*key)
		if err != nil {
			log.Fatal(err)
		}
		privatekey, err = DecodeNUMSPrivateKey(file)
		if err != nil {
			log.Fatal(err)
		}
		buf := bytes.NewBuffer(nil)
		data := inputfile
		io.Copy(buf, data)
		scanner := string(buf.Bytes())
		str := string(scanner)
		plaintxt, err := privatekey.ToECDSAPrivateKey().DecryptAsn1([]byte(str))
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s", plaintxt)
		os.Exit(0)
	}

	if *pkey == "sign" && (strings.ToUpper(*alg) == "NUMS") {
		var privatekey *nums.PrivateKey
		var h hash.Hash
		h = myHash()
		if _, err := io.Copy(h, inputfile); err != nil {
			log.Fatal(err)
		}
		file, err := ioutil.ReadFile(*key)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		privatekey, err = DecodeNUMSPrivateKey(file)
		if err != nil {
			log.Fatal(err)
		}
		signature, err := ecdsa.SignASN1(rand.Reader, privatekey.ToECDSAPrivateKey(), h.Sum(nil))
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(strings.ToUpper(*alg)+"-"+strings.ToUpper(*md)+"("+inputdesc+")=", hex.EncodeToString(signature))
		os.Exit(0)
	}

	if *pkey == "verify" && (strings.ToUpper(*alg) == "NUMS") {
		var h hash.Hash
		h = myHash()
		if _, err := io.Copy(h, inputfile); err != nil {
			log.Fatal(err)
		}
		file, err := ioutil.ReadFile(*key)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		public, err := DecodeNUMSPublicKey(file)
		if err != nil {
			log.Fatal(err)
		}
		sig, _ := hex.DecodeString(*sig)
		verifystatus := ecdsa.VerifyASN1(public.ToECDSA(), h.Sum(nil), sig)
		if verifystatus == true {
			fmt.Printf("Verified: %v\n", verifystatus)
			os.Exit(0)
		} else {
			fmt.Printf("Verified: %v\n", verifystatus)
			os.Exit(1)
		}
		os.Exit(0)
	}

	if *pkey == "derive" && strings.ToUpper(*alg) == "NUMS" {
		var privatekey *nums.PrivateKey
		file, err := ioutil.ReadFile(*pub)
		if err != nil {
			log.Fatal(err)
		}
		public, err := DecodeNUMSPublicKey(file)
		if err != nil {
			log.Fatal(err)
		}
		file2, err := ioutil.ReadFile(*key)
		if err != nil {
			log.Fatal(err)
			os.Exit(1)
		}
		privatekey, err = DecodeNUMSPrivateKey(file2)
		if err != nil {
			log.Fatal(err)
		}
		sharedKey, err := nums.ECDH(privatekey.ToECDSAPrivateKey(), public.ToECDSA())
		if err != nil {
			log.Fatal("Error computing shared key:", err)
		}
		fmt.Printf("%x\n", sharedKey)
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
			err = EncryptAndWriteBlock(*cph, block, []byte(*pwd), file)
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

	if *pkey == "keygen" && (strings.ToUpper(*alg) == "ED448") {
		var privatekey ed448.PrivateKey
		var public ed448.PublicKey
		public, privatekey, err = ed448.GenerateKey(rand.Reader)

		if err != nil {
			log.Fatal(err)
		}

		privateStream, err := ed448.MarshalPrivateKey(privatekey)
		if err != nil {
			log.Fatal(err)
		}
		block := &pem.Block{
			Type:  "ED448 PRIVATE KEY",
			Bytes: privateStream,
		}
		file, err := os.Create(*priv)
		if err != nil {
			log.Fatal(err)
		}
		if *pwd != "" {
			err = EncryptAndWriteBlock(*cph, block, []byte(*pwd), file)
			if err != nil {
				log.Fatal(err)
			}
		} else {
			err = pem.Encode(file, block)
			if err != nil {
				log.Fatal(err)
			}
		}
		publicStream, err := ed448.MarshalPublicKey(public)
		if err != nil {
			log.Fatal(err)
		}
		pubblock := &pem.Block{
			Type:  "ED448 PUBLIC KEY",
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

	if *pkey == "sign" && (strings.ToUpper(*alg) == "ED448PH") {
		var h hash.Hash
		h = myHash()
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
			privPEM = pem.EncodeToMemory(&pem.Block{Type: "ED448 PRIVATE KEY", Bytes: privKeyBytes})
		} else {
			privPEM = buf
		}

		var privateKeyPemBlock, _ = pem.Decode([]byte(privPEM))

		var privKey, _ = ed448.ParsePrivateKey(privateKeyPemBlock.Bytes)
		if err != nil {
			log.Fatal(err)
		}
		edKey := privKey

		signature := ed448.Sign(edKey, h.Sum(nil))

		fmt.Println("ED448PH-"+strings.ToUpper(*md)+"("+inputdesc+")=", hex.EncodeToString(signature))
		os.Exit(0)
	}

	if *pkey == "verify" && (strings.ToUpper(*alg) == "ED448PH") {
		var h hash.Hash
		h = myHash()
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
		publicInterface, err := ed448.ParsePublicKey(block.Bytes)
		if err != nil {
			log.Fatal(err)
		}
		publicKey := publicInterface
		sig, _ := hex.DecodeString(*sig)
		verifystatus := ed448.Verify(publicKey, h.Sum(nil), sig)
		if verifystatus == true {
			fmt.Printf("Verified: %v\n", verifystatus)
			os.Exit(0)
		} else {
			fmt.Printf("Verified: %v\n", verifystatus)
			os.Exit(1)
		}
		os.Exit(0)
	}

	if *pkey == "sign" && (strings.ToUpper(*alg) == "ED448") {
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
			privPEM = pem.EncodeToMemory(&pem.Block{Type: "ED448 PRIVATE KEY", Bytes: privKeyBytes})
		} else {
			privPEM = buf
		}

		var privateKeyPemBlock, _ = pem.Decode([]byte(privPEM))

		var privKey, _ = ed448.ParsePrivateKey(privateKeyPemBlock.Bytes)
		if err != nil {
			log.Fatal(err)
		}
		edKey := privKey

		signature := ed448.Sign(edKey, data.Bytes())

		fmt.Println("PureED448("+inputdesc+")=", hex.EncodeToString(signature))
		os.Exit(0)
	}

	if *pkey == "verify" && (strings.ToUpper(*alg) == "ED448") {
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
		publicInterface, err := ed448.ParsePublicKey(block.Bytes)
		if err != nil {
			log.Fatal(err)
		}
		publicKey := publicInterface
		sig, _ := hex.DecodeString(*sig)
		verifystatus := ed448.Verify(publicKey, data.Bytes(), sig)
		if verifystatus == true {
			fmt.Printf("Verified: %v\n", verifystatus)
			os.Exit(0)
		} else {
			fmt.Printf("Verified: %v\n", verifystatus)
			os.Exit(1)
		}
		os.Exit(0)
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
			err = EncryptAndWriteBlock(*cph, block, []byte(*pwd), file)
			if err != nil {
				log.Fatal(err)
			}
		} else {
			err = pem.Encode(file, block)
			if err != nil {
				log.Fatal(err)
			}
		}
		pubKey, err := masterKey.Public().(*sm9.SignMasterPublicKey).MarshalASN1()
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

		absPrivPath, err := filepath.Abs(*master)
		if err != nil {
			log.Fatal("Failed to get absolute path for master key:", err)
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
			err = EncryptAndWriteBlock(*cph, block, []byte(*pwd), file)
			if err != nil {
				log.Fatal(err)
			}
		} else {
			err = pem.Encode(file, block)
			if err != nil {
				log.Fatal(err)
			}
		}
		pubKey, err := masterKey.Public().(*sm9.EncryptMasterPublicKey).MarshalASN1()
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

		absPrivPath, err := filepath.Abs(*master)
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
		if err != nil {
			log.Fatal(err)
		}

		block = &pem.Block{
			Type:  "SM9 ENC PRIVATE KEY",
			Bytes: privKeyBytes,
		}
		file, err = os.Create(*priv)
		if err != nil {
			log.Fatal(err)
		}
		if *pwd2 != "" {
			err = EncryptAndWriteBlock(*cph, block, []byte(*pwd2), file)
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
			fmt.Println("Error reading the file:", err)
			return
		}

		block, _ := pem.Decode(fileContent)
		if block == nil {
			fmt.Println("Failed to decode PEM block containing the public key.")
			return
		}

		pubKey, err := sm9.UnmarshalEncryptMasterPublicKeyASN1(block.Bytes)
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
			fmt.Println("Error reading the file:", err)
			return
		}

		block, _ := pem.Decode(fileContent)
		if block == nil {
			fmt.Println("Failed to decode PEM block containing the public key.")
			return
		}

		pubKey, err := sm9.UnmarshalEncryptMasterPublicKeyASN1(block.Bytes)
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

		fmt.Printf("Cipher= %x\n", cipher)
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

		cipher, err := hex.DecodeString(cipherHexString)
		if err != nil {
			log.Fatal(err)
		}

		key, err := sm9.UnwrapKey(encryptPrivateKey, []byte(*id), cipher, *length/8)
		if err != nil {
			os.Exit(1)
		}
		fmt.Printf("Shared= %x\n", key)
	}

	if *pkey == "derivea" || *pkey == "deriveb" {
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
			aExchange := encryptPrivateKey.NewKeyExchange([]byte(*id), []byte(*id2), *length/8, true)
			defer aExchange.Destroy()

			rA, err := aExchange.InitKeyExchange(rand.Reader, byte(*hierarchy))
			if err != nil {
				log.Fatal("Error during key exchange A: ", err)
			}

			fmt.Println("rA=", hex.EncodeToString(rA))

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

			sharedKey, _, err := aExchange.ConfirmResponder(rBBytes, signBBytes)
			if err != nil {
				log.Fatal("Error during confirmation A: ", err)
			}

			fmt.Println("Shared=", hex.EncodeToString(sharedKey))

		} else if *pkey == "deriveb" {
			var rA string
			fmt.Print("Enter rA: ")
			fmt.Scanln(&rA)

			rABytes, err := hex.DecodeString(rA)
			if err != nil {
				log.Fatal("Error decoding rA:", err)
			}

			bExchange := encryptPrivateKey.NewKeyExchange([]byte(*id), []byte(*id2), *length/8, true)
			defer bExchange.Destroy()

			rB, sigB, err := bExchange.RespondKeyExchange(rand.Reader, byte(*hierarchy), rABytes)
			if err != nil {
				log.Fatal("Error during key exchange B: ", err)
			}

			sharedKey, err := bExchange.ConfirmInitiator(nil)
			if err != nil {
				log.Fatal("Error during confirmation B: ", err)
			}

			fmt.Println("rB=", hex.EncodeToString(rB))
			fmt.Println("signB=", hex.EncodeToString(sigB))
			fmt.Println("Shared=", hex.EncodeToString(sharedKey))
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
		if err != nil {
			log.Fatal(err)
		}

		block = &pem.Block{
			Type:  "SM9 SIGN PRIVATE KEY",
			Bytes: privKeyBytes,
		}
		file, err = os.Create(*priv)
		if err != nil {
			log.Fatal(err)
		}
		if *pwd2 != "" {
			err = EncryptAndWriteBlock(*cph, block, []byte(*pwd2), file)
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

	if *pkey == "sign" && strings.ToUpper(*alg) == "SM9SIGN" {
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
		block, _ := pem.Decode(buf)
		if block == nil {
			log.Fatal("no valid private key found")
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

		privateKeyPemBlock, _ := pem.Decode([]byte(privPEM))
		privKey, err := smx509.ParsePKCS8PrivateKey(privateKeyPemBlock.Bytes)
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

		fmt.Printf("SM9(%s)= %x\n", inputdesc, signature)
	}

	if *pkey == "verify" && strings.ToUpper(*alg) == "SM9SIGN" {
		fileContent, err := ioutil.ReadFile(*key)
		if err != nil {
			fmt.Println("Error reading the file:", err)
			return
		}

		block, _ := pem.Decode(fileContent)
		if block == nil {
			fmt.Println("Failed to decode PEM block containing the public key.")
			return
		}

		pubKey, err := sm9.UnmarshalSignMasterPublicKeyASN1(block.Bytes)
		if err != nil {
			fmt.Println("Error parsing public key:", err)
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
		h = myHash()
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
		h = myHash()
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
		sig, err := hex.DecodeString(*sig)
		if err != nil {
			log.Fatal(err)
		}
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

	if *pkey == "sign" && (strings.ToUpper(*alg) == "ECKCDSA") {
		var privatekey *eckcdsa.PrivateKey

		input, err := ioutil.ReadAll(inputfile)
		file, err := ioutil.ReadFile(*key)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		privatekey, err = DecodeECKCDSAPrivateKey(file)
		if err != nil {
			log.Fatal(err)
		}
		signature, err := eckcdsa.SignASN1(rand.Reader, privatekey, myHash(), input)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(strings.ToUpper(*alg)+"-"+strings.ToUpper(*md)+"("+inputdesc+")=", hex.EncodeToString(signature))
		os.Exit(0)
	}

	if *pkey == "verify" && (strings.ToUpper(*alg) == "ECKCDSA") {

		input, err := ioutil.ReadAll(inputfile)
		file, err := ioutil.ReadFile(*key)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		publica, err := DecodeECKCDSAPublicKey(file)
		if err != nil {
			log.Fatal(err)
		}
		sig, err := hex.DecodeString(*sig)
		if err != nil {
			log.Fatal(err)
		}
		verifystatus := eckcdsa.VerifyASN1(publica, myHash(), input, sig)

		fmt.Printf("Verified: %v\n", verifystatus)
		os.Exit(0)
	}

	if *pkey == "sign" && (strings.ToUpper(*alg) == "ECGDSA") {
		var privatekey *ecgdsa.PrivateKey

		input, err := ioutil.ReadAll(inputfile)
		file, err := ioutil.ReadFile(*key)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		privatekey, err = DecodeECGDSAPrivateKey(file)
		if err != nil {
			log.Fatal(err)
		}
		opts := &ecgdsa.SignerOpts{
			Hash: myHash,
		}
		signature, err := privatekey.Sign(rand.Reader, input, opts)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(strings.ToUpper(*alg)+"-"+strings.ToUpper(*md)+"("+inputdesc+")=", hex.EncodeToString(signature))
		os.Exit(0)
	}

	if *pkey == "verify" && (strings.ToUpper(*alg) == "ECGDSA") {

		input, err := ioutil.ReadAll(inputfile)
		file, err := ioutil.ReadFile(*key)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		opts := &ecgdsa.SignerOpts{
			Hash: myHash,
		}
		publica, err := DecodeECGDSAPublicKey(file)
		if err != nil {
			log.Fatal(err)
		}
		sig, err := hex.DecodeString(*sig)
		if err != nil {
			log.Fatal(err)
		}
		verifystatus, err := publica.Verify(input, sig, opts)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		fmt.Printf("Verified: %v\n", verifystatus)
		os.Exit(0)
	}

	if *pkey == "sign" && (strings.ToUpper(*alg) == "ECSDSA") {
		var privatekey *ecsdsa.PrivateKey

		input, err := ioutil.ReadAll(inputfile)
		file, err := ioutil.ReadFile(*key)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		privatekey, err = DecodeECSDSAPrivateKey(file)
		if err != nil {
			log.Fatal(err)
		}
		opts := &ecsdsa.SignerOpts{
			Hash: myHash,
		}
		signature, err := privatekey.Sign(rand.Reader, input, opts)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(strings.ToUpper(*alg)+"-"+strings.ToUpper(*md)+"("+inputdesc+")=", hex.EncodeToString(signature))
		os.Exit(0)
	}

	if *pkey == "verify" && (strings.ToUpper(*alg) == "ECSDSA") {

		input, err := ioutil.ReadAll(inputfile)
		file, err := ioutil.ReadFile(*key)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		opts := &ecsdsa.SignerOpts{
			Hash: myHash,
		}
		publica, err := DecodeECSDSAPublicKey(file)
		if err != nil {
			log.Fatal(err)
		}
		sig, err := hex.DecodeString(*sig)
		if err != nil {
			log.Fatal(err)
		}
		verifystatus, err := publica.Verify(input, sig, opts)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		fmt.Printf("Verified: %v\n", verifystatus)
		os.Exit(0)
	}

	if *pkey == "sign" && (strings.ToUpper(*alg) == "BIP0340") {
		var privatekey *bip0340.PrivateKey

		input, err := ioutil.ReadAll(inputfile)
		file, err := ioutil.ReadFile(*key)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		privatekey, err = DecodeBIP0340PrivateKey(file)
		if err != nil {
			log.Fatal(err)
		}
		opts := &bip0340.SignerOpts{
			Hash: myHash,
		}
		signature, err := privatekey.Sign(rand.Reader, input, opts)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(strings.ToUpper(*alg)+"-"+strings.ToUpper(*md)+"("+inputdesc+")=", hex.EncodeToString(signature))
		os.Exit(0)
	}

	if *pkey == "verify" && (strings.ToUpper(*alg) == "BIP0340") {

		input, err := ioutil.ReadAll(inputfile)
		file, err := ioutil.ReadFile(*key)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		opts := &bip0340.SignerOpts{
			Hash: myHash,
		}
		publica, err := DecodeBIP0340PublicKey(file)
		if err != nil {
			log.Fatal(err)
		}
		sig, err := hex.DecodeString(*sig)
		if err != nil {
			log.Fatal(err)
		}
		verifystatus, err := publica.Verify(input, sig, opts)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		fmt.Printf("Verified: %v\n", verifystatus)
		os.Exit(0)
	}

	if *pkey == "sign" && (strings.ToUpper(*alg) == "BIGN") {
		var privatekey *bign.PrivateKey

		input, err := ioutil.ReadAll(inputfile)
		file, err := ioutil.ReadFile(*key)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		privatekey, err = DecodeBIGNPrivateKey(file)
		if err != nil {
			log.Fatal(err)
		}
		adata := bign.MakeAdata([]byte(*id), []byte(*info))
		signature, err := bign.Sign(rand.Reader, privatekey, myHash, input, adata)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(strings.ToUpper(*alg)+"-"+strings.ToUpper(*md)+"("+inputdesc+")=", hex.EncodeToString(signature))
		os.Exit(0)
	}

	if *pkey == "sign" && (strings.ToUpper(*alg) == "DBIGN") {
		var privatekey *bign.PrivateKey

		input, err := ioutil.ReadAll(inputfile)
		file, err := ioutil.ReadFile(*key)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		privatekey, err = DecodeBIGNPrivateKey(file)
		if err != nil {
			log.Fatal(err)
		}
		adata := bign.MakeAdata([]byte(*id), []byte(*info))
		signature, err := bign.Sign(nil, privatekey, myHash, input, adata)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(strings.ToUpper(*alg)+"-"+strings.ToUpper(*md)+"("+inputdesc+")=", hex.EncodeToString(signature))
		os.Exit(0)
	}

	if *pkey == "verify" && (strings.ToUpper(*alg) == "BIGN") {

		input, err := ioutil.ReadAll(inputfile)
		file, err := ioutil.ReadFile(*key)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		publica, err := DecodeBIGNPublicKey(file)
		if err != nil {
			log.Fatal(err)
		}
		adata := bign.MakeAdata([]byte(*id), []byte(*info))
		sig, err := hex.DecodeString(*sig)
		if err != nil {
			log.Fatal(err)
		}
		verifystatus := bign.Verify(publica, myHash, input, adata, sig)

		fmt.Printf("Verified: %v\n", verifystatus)
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

	if *pkey == "sign" && (strings.ToUpper(*alg) == "SM2PH") {
		var privatekey *sm2.PrivateKey
		var h hash.Hash
		h = myHash()
		if _, err := io.Copy(h, inputfile); err != nil {
			log.Fatal(err)
		}
		file, err := ioutil.ReadFile(*key)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		privatekey, err = DecodeSM2PrivateKey(file)
		if err != nil {
			log.Fatal(err)
		}
		signature, err := privatekey.Sign(rand.Reader, h.Sum(nil), sm2.DefaultSM2SignerOpts)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("SM2"+"-"+strings.ToUpper(*md)+"("+inputdesc+")=", hex.EncodeToString(signature))
		os.Exit(0)
	}

	if *pkey == "verify" && (strings.ToUpper(*alg) == "SM2PH") {
		var h hash.Hash
		h = myHash()
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
		sigBytes, err := hex.DecodeString(*sig)
		if err != nil {
			log.Fatal(err)
		}
		verifystatus := sm2.VerifyASN1WithSM2(public, nil, h.Sum(nil), sigBytes)
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
		h = myHash()
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
		h = myHash()
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
			err = EncryptAndWriteBlock(*cph, block, []byte(*pwd), file)
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

	if *pkey == "keygen" && (strings.ToUpper(*alg) == "X448") {
		var privateKey x448.PrivateKey

		publicKey, privateKey, err := x448.GenerateKey(nil)
		if err != nil {
			log.Fatal(err)
		}

		privateStream, err := x448.MarshalPrivateKey(privateKey)
		if err != nil {
			log.Fatal(err)
		}

		block := &pem.Block{
			Type:  "X448 PRIVATE KEY",
			Bytes: privateStream,
		}
		file, err := os.Create(*priv)
		if err != nil {
			log.Fatal(err)
		}
		if *pwd != "" {
			err = EncryptAndWriteBlock(*cph, block, []byte(*pwd), file)
			if err != nil {
				log.Fatal(err)
			}
		} else {
			err = pem.Encode(file, block)
			if err != nil {
				log.Fatal(err)
			}
		}

		publicStream, err := x448.MarshalPublicKey(publicKey)
		if err != nil {
			log.Fatal(err)
		}
		pubblock := &pem.Block{
			Type:  "X448 PUBLIC KEY",
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

	if *pkey == "derive" && strings.ToUpper(*alg) == "X448" || strings.ToUpper(*pkey) == "X448" {
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
			privPEM = pem.EncodeToMemory(&pem.Block{Type: "X448 PRIVATE KEY", Bytes: privKeyBytes})
		} else {
			privPEM = buf
		}

		var privateKeyPemBlock, _ = pem.Decode([]byte(privPEM))

		var privKey, _ = x448.ParsePrivateKey(privateKeyPemBlock.Bytes)
		if err != nil {
			log.Fatal(err)
		}
		XKey := privKey

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
		publicInterface, err := x448.ParsePublicKey(block.Bytes)
		if err != nil {
			log.Fatal(err)
		}
		publicKey := publicInterface

		var secret []byte
		secret, err = x448.X448(XKey[:56], publicKey)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%x\n", secret[:])
		os.Exit(0)
	}

	if *pkey == "derive" && strings.ToUpper(*alg) == "BIGN" {
		var privatekey *bign.PrivateKey

		file, err := ioutil.ReadFile(*pub)
		if err != nil {
			log.Fatal(err)
		}
		publica, err := DecodeBIGNPublicKey(file)
		if err != nil {
			log.Fatal(err)
		}

		if publica.X == nil || publica.Y == nil {
			log.Fatal("invalid public key: coordinates are nil")
		}
		if publica.X.Sign() == 0 && publica.Y.Sign() == 0 {
			log.Fatal("invalid public key: point at infinity")
		}
		if !publica.Curve.IsOnCurve(publica.X, publica.Y) {
			log.Fatal("invalid public key: point not on curve")
		}

		file2, err := ioutil.ReadFile(*key)
		if err != nil {
			log.Fatal(err)
		}
		privatekey, err = DecodeBIGNPrivateKey(file2)
		if err != nil {
			log.Fatal(err)
		}

		if privatekey.D.Cmp(publica.Curve.Params().N) >= 0 || privatekey.D.Sign() <= 0 {
			log.Fatal("invalid private key: scalar out of range")
		}

		bX, bY := publica.Curve.ScalarMult(publica.X, publica.Y, privatekey.D.Bytes())

		if bX == nil || bY == nil {
			log.Fatal("invalid shared secret: null point")
		}
		if bX.Sign() == 0 && bY.Sign() == 0 {
			log.Fatal("invalid shared secret: point at infinity")
		}
		if !publica.Curve.IsOnCurve(bX, bY) {
			log.Fatal("invalid shared secret: point not on curve")
		}

		fmt.Printf("%x\n", bX.Bytes())
		os.Exit(0)
	}

	if *pkey == "randomart" || *pkey == "text" || *pkey == "fingerprint" || *pkey == "certgen" || *pkey == "req" || *pkey == "x509" || *pkey == "crl" || *pkey == "sign" || *pkey == "aggregate" || *pkey == "verify-aggregate" || *pkey == "proof" || *pkey == "verify-proof" || *pkey == "derive" || *pkey == "encrypt" || *pkey == "decrypt" || *pkey == "verify" || *pkey == "check" || *pkey == "validate" || *pkey == "wrapkey" || *pkey == "unwrapkey" || *tcpip == "server" || *tcpip == "client" || *pkey == "combine-threshold" || *pkey == "keygen-threshold" || *pkey == "setup-threshold" {

		if *pkey == "combine-threshold" || *pkey == "keygen-threshold" || *pkey == "setup-threshold" {
			*alg = "BLS12381"
		}

		if data, err := ioutil.ReadFile(*key); err == nil {
			if block, _ := pem.Decode(data); block != nil {
				if strings.Contains(block.Type, "SLH-DSA") {
					*alg = "SLH-DSA"
				} else if strings.Contains(block.Type, "ML-KEM") {
					*alg = "ML-KEM"
				} else if strings.Contains(block.Type, "ML-DSA") {
					*alg = "ML-DSA"
				} else if strings.Contains(block.Type, "BN256I") {
					*alg = "BN256I"
				} else if strings.Contains(block.Type, "BN256") {
					*alg = "BN256"
				} else if strings.Contains(block.Type, "BN256SIGN") {
					*alg = "BN256SIGN"
				} else if strings.Contains(block.Type, "BN256ENCRYPT") {
					*alg = "BN256ENCRYPT"
				} else if strings.Contains(block.Type, "BLS12381I") {
					*alg = "BLS12381I"
				} else if strings.Contains(block.Type, "BLS12381SIGN") {
					*alg = "BLS12381SIGN"
				} else if strings.Contains(block.Type, "BLS12381ENCRYPT") {
					*alg = "BLS12381ENCRYPT"
				} else if strings.Contains(block.Type, "BLS12381") {
					*alg = "BLS12381"
				} else if strings.Contains(block.Type, "SCHNORR") {
					*alg = "SCHNORR"
				} else if strings.Contains(block.Type, "ELGAMAL") {
					*alg = "ELGAMAL"
				}
			}
		}

		if data, err := ioutil.ReadFile(*crl); err == nil {
			if block, _ := pem.Decode(data); block != nil {
				if strings.Contains(block.Type, "SLH-DSA") {
					*alg = "SLH-DSA"
				} else if strings.Contains(block.Type, "ML-DSA") {
					*alg = "ML-DSA"
				} else if strings.Contains(block.Type, "BN256I") {
					*alg = "BN256I"
				} else if strings.Contains(block.Type, "BN256") {
					*alg = "BN256"
				} else if strings.Contains(block.Type, "BN256SIGN") {
					*alg = "BN256SIGN"
				} else if strings.Contains(block.Type, "BN256ENCRYPT") {
					*alg = "BN256ENCRYPT"
				} else if strings.Contains(block.Type, "BLS12381I") {
					*alg = "BLS12381I"
				} else if strings.Contains(block.Type, "BLS12381SIGN") {
					*alg = "BLS12381SIGN"
				} else if strings.Contains(block.Type, "BLS12381ENCRYPT") {
					*alg = "BLS12381ENCRYPT"
				} else if strings.Contains(block.Type, "BLS12381") {
					*alg = "BLS12381"
				}
			}
		}

		if *pkey != "certgen" && *pkey != "req" {
			if data, err := ioutil.ReadFile(*cert); err == nil {
				if block, _ := pem.Decode(data); block != nil {
					if strings.Contains(block.Type, "SLH-DSA") {
						*alg = "SLH-DSA"
					} else if strings.Contains(block.Type, "ML-DSA") {
						*alg = "ML-DSA"
					} else if strings.Contains(block.Type, "BN256I") {
						*alg = "BN256I"
					} else if strings.Contains(block.Type, "BN256") {
						*alg = "BN256"
					} else if strings.Contains(block.Type, "BN256SIGN") {
						*alg = "BN256SIGN"
					} else if strings.Contains(block.Type, "BN256ENCRYPT") {
						*alg = "BN256ENCRYPT"
					} else if strings.Contains(block.Type, "BLS12381I") {
						*alg = "BLS12381I"
					} else if strings.Contains(block.Type, "BLS12381SIGN") {
						*alg = "BLS12381SIGN"
					} else if strings.Contains(block.Type, "BLS12381ENCRYPT") {
						*alg = "BLS12381ENCRYPT"
					} else if strings.Contains(block.Type, "BLS12381") {
						*alg = "BLS12381"
					}
				}
			}
		}
	}

	if *pkey == "derive" && strings.ToUpper(*alg) != "GOST2012" && strings.ToUpper(*alg) != "BN256" && strings.ToUpper(*alg) != "BN256I" && strings.ToUpper(*alg) != "BLS12381" && strings.ToUpper(*alg) != "BLS12381I" {

		var privateKey *ecdh.PrivateKey
		var publicKey *ecdh.PublicKey

		pubBytes, err := ioutil.ReadFile(*pub)
		if err != nil {
			log.Fatalf("failed to read public key file: %v", err)
		}
		public, err = DecodePublicKey(pubBytes)
		if err != nil {
			log.Fatalf("failed to decode public key: %v", err)
		}

		var curve ecdh.Curve
		switch public.Curve.Params().Name {
		case "P-256":
			curve = ecdh.P256()
		case "P-384":
			curve = ecdh.P384()
		case "P-521":
			curve = ecdh.P521()
		default:
			log.Fatal("unsupported curve for crypto/ecdh")
		}

		pubKeyBytes := elliptic.Marshal(public.Curve, public.X, public.Y)
		publicKey, err = curve.NewPublicKey(pubKeyBytes)
		if err != nil {
			log.Fatalf("failed to create ecdh public key: %v", err)
		}

		privBytes, err := ioutil.ReadFile(*key)
		if err != nil {
			log.Fatalf("failed to read private key file: %v", err)
		}
		privatekey, err := DecodePrivateKey(privBytes)
		if err != nil {
			log.Fatalf("failed to decode private key: %v", err)
		}

		privateKey, err = curve.NewPrivateKey(privatekey.D.Bytes())
		if err != nil {
			log.Fatalf("failed to create ecdh private key: %v", err)
		}

		sharedSecret, err := privateKey.ECDH(publicKey)
		if err != nil {
			log.Fatalf("failed to derive shared secret: %v", err)
		}

		fmt.Printf("%x\n", sharedSecret)
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
			err = EncryptAndWriteBlock(*cph, block, []byte(*pwd), file)
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
		h = myHash()
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
		fmt.Println("GOST2012-"+strings.ToUpper(*md)+"("+inputdesc+")=", hex.EncodeToString(signature))
		os.Exit(0)
	}

	if *pkey == "verify" && strings.ToUpper(*alg) == "GOST2012" {
		var h hash.Hash
		h = myHash()
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
	if (*pkey == "text") && *crl == "" && *params != "" {
		if *params != "" {
			b, err = ioutil.ReadFile(*params)
			if err != nil {
				log.Fatal(err)
			}
		}
		s := string(b)
		if strings.Contains(s, "ELGAMAL") {
			*alg = "ELGAMAL"
		} else if strings.Contains(s, "SCHNORR") {
			*alg = "SCHNORR"
		}
	}

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
		} else if strings.Contains(s, "SLH-DSA") {
			*alg = "SLH-DSA"
		} else if strings.Contains(s, "BN256I") {
			*alg = "BN256I"
		} else if strings.Contains(s, "BN256") {
			*alg = "BN256"
		} else if strings.Contains(s, "BN256SIGN") {
			*alg = "BN256SIGN"
		} else if strings.Contains(s, "BN256ENCRYPT") {
			*alg = "BN256ENCRYPT"
		} else if strings.Contains(s, "BLS12381I") {
			*alg = "BLS12381I"
		} else if strings.Contains(s, "BLS12381SIGN") {
			*alg = "BLS12381SIGN"
		} else if strings.Contains(s, "BLS12381ENCRYPT") {
			*alg = "BLS12381ENCRYPT"
		} else if strings.Contains(s, "THRESHOLD IBE SHARE") {
			*alg = "BLS12381"
		} else if strings.Contains(s, "BLS12381") {
			*alg = "BLS12381"
		} else if strings.Contains(s, "EC-ELGAMAL") {
			*alg = "EC-ELGAMAL"
		} else if strings.Contains(s, "ELGAMAL") {
			*alg = "ELGAMAL"
		} else if strings.Contains(s, "SCHNORR") {
			*alg = "SCHNORR"
		} else if strings.Contains(s, "ML-KEM") {
			*alg = "ML-KEM"
		} else if strings.Contains(s, "ML-DSA") {
			*alg = "ML-DSA"
		} else if strings.Contains(s, "NUMS") {
			*alg = "NUMS"
		} else if strings.Contains(s, "ANSSI") {
			*alg = "ANSSI"
		} else if strings.Contains(s, "KOBLITZ") {
			*alg = "KOBLITZ"
		} else if strings.Contains(s, "TOM") {
			*alg = "TOM"
		} else if strings.Contains(s, "BIGN") {
			*alg = "BIGN"
		} else if strings.Contains(s, "ECKCDSA PRIVATE") {
			*alg = "ECKCDSA"
		} else if strings.Contains(s, "ECGDSA PRIVATE") {
			*alg = "ECGDSA"
		} else if strings.Contains(s, "ECSDSA PRIVATE") {
			*alg = "ECSDSA"
		} else if strings.Contains(s, "BIP0340 PRIVATE") {
			*alg = "BIP0340"
		} else if strings.Contains(s, "ED448 PRIVATE") {
			*alg = "ED448"
		} else if strings.Contains(s, "X448 PRIVATE") {
			*alg = "X448"
		} else if strings.Contains(s, "PRIVATE") {
			*alg = "ED25519"
		}
	}

	if strings.ToUpper(*alg) == "SLH-DSA" && *pkey == "keygen" {
		generateKeyPair(*priv, *pub)
	}

	if strings.ToUpper(*alg) == "SLH-DSA" && *pkey == "sign" {
		signMessage(inputfile, *key)
	}

	if strings.ToUpper(*alg) == "SLH-DSA" && *pkey == "verify" {
		verifySignature(inputfile, *key, *sig)
	}

	if *pkey == "modulus" && strings.ToUpper(*alg) == "SLH-DSA" {
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

		isPrivateKey := block.Type == "SLH-DSA SECRET KEY"

		loadedKeyBytes, err := readKeyFromPEM(*key, isPrivateKey)
		if err != nil {
			log.Fatal(err)
		}
		if err := printKeyParams(loadedKeyBytes, isPrivateKey); err != nil {
			log.Fatal(err)
		}
	}

	if *pkey == "text" && strings.ToUpper(*alg) == "SLH-DSA" && *key != "" {
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

		isPrivateKey := block.Type == "SLH-DSA SECRET KEY"

		loadedKeyBytes, err := readKeyFromPEM(*key, isPrivateKey)
		if err != nil {
			log.Fatal(err)
		}
		if err := printKeyParamsFull(loadedKeyBytes, isPrivateKey); err != nil {
			log.Fatal(err)
		}
	}

	if *pkey == "randomart" && strings.ToUpper(*alg) == "SLH-DSA" {
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
		println("SLH-DSA (256-bit)")
		randomArt := randomart.FromString(string(buf))
		println(randomArt)
		os.Exit(0)
	}

	if *pkey == "fingerprint" && strings.ToUpper(*alg) == "SLH-DSA" {
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

	var validity string

	if (strings.ToUpper(*alg) == "ML-DSA" || strings.ToUpper(*alg) == "SLH-DSA" || strings.ToUpper(*alg) == "BN256I" || strings.ToUpper(*alg) == "BLS12381I") && (*pkey == "certgen" || *pkey == "req" || *pkey == "x509" || *pkey == "crl") {
		if *pkey == "certgen" || *pkey == "req" {
			if *subj == "" {
				println("You are about to be asked to enter information \nthat will be incorporated into your certificate.")

				scanner := bufio.NewScanner(os.Stdin)

				print("Common Name: ")
				scanner.Scan()
				name = scanner.Text()

				print("Country Name (2 letter code) [AU]: ")
				scanner.Scan()
				country = scanner.Text()

				print("State or Province Name (full name) [Some-State]: ")
				scanner.Scan()
				province = scanner.Text()

				print("Locality Name (eg, city): ")
				scanner.Scan()
				locality = scanner.Text()

				print("Organization Name (eg, company) [Internet Widgits Pty Ltd]: ")
				scanner.Scan()
				organization = scanner.Text()

				print("Organizational Unit Name (eg, section): ")
				scanner.Scan()
				organizationunit = scanner.Text()

				print("Email Address []: ")
				scanner.Scan()
				email = scanner.Text()

				print("StreetAddress: ")
				scanner.Scan()
				street = scanner.Text()

				print("PostalCode: ")
				scanner.Scan()
				postalcode = scanner.Text()

				print("SerialNumber: ")
				scanner.Scan()
				number = scanner.Text()
			} else {
				name, number, country, province, locality, organization, organizationunit, street, email, postalcode, err = parseSubjectString(*subj)
				if err != nil {
					log.Fatal(err)
				}
			}
		}

		if *pkey == "certgen" || *pkey == "x509" || *pkey == "crl" {
			if *days > 0 {
				validity = fmt.Sprintf("%d", *days)
			} else {
				fmt.Print("Validity (in Days): ")
				fmt.Scanln(&validity)
			}
		}
	}

	if (*pkey == "certgen" || *pkey == "x509" || *pkey == "req" || *pkey == "check" || *pkey == "text" || *pkey == "crl" || *pkey == "validate") && strings.ToUpper(*alg) == "SLH-DSA" {
		if *pkey == "certgen" {
			pk, err := readKeyFromPEM(*pub, false)
			if err != nil {
				fmt.Println("Error loading key:", err)
				return
			}

			sk, err := readKeyFromPEM(*key, true)
			if err != nil {
				fmt.Println("Error loading key:", err)
				return
			}

			ca := NewCA(sk, pk, validity)

			subject := pkix.Name{
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

			certificate, err := ca.IssueCertificate(subject, email, pk, sk, true, validity)
			if err != nil {
				fmt.Println("Error issuing certificate:", err)
				return
			}

			err = SaveCertificateToPEM(certificate, *cert)
			if err != nil {
				fmt.Println("Error saving certificate:", err)
				return
			}

			fmt.Println("Certificate issued and saved successfully.")
			os.Exit(0)
		} else if *pkey == "text" && *key == "" && *crl != "" {
			crl, err := ReadCRLFromPEM(*crl)
			if err != nil {
				log.Fatalf("Error reading the CRL: %v", err)
			}

			PrintCRLInfo(crl)
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
			pubFile, err := os.Open(*key)
			if err != nil {
				fmt.Println("Error opening public key file:", err)
				os.Exit(1)
			}
			defer pubFile.Close()

			fmt.Printf("SLH-DSA 256-bit\n")

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
		} else if *pkey == "check" && *crl == "" {
			pk, err := readKeyFromPEM(*key, false)
			if err != nil {
				fmt.Println("Error loading key:", err)
				return
			}
			certificate, err := ReadCertificateFromPEM(*cert)
			if err != nil {
				fmt.Println("Error reading the certificate:", err)
				return
			}

			err = VerifyCertificate(certificate, pk)
			if err != nil {
				fmt.Println("Verified: false", err)
				os.Exit(1)
			} else {
				fmt.Println("Verified: true")
				os.Exit(0)
			}
		} else if *pkey == "text" && *cert != "" {
			certificate, err := ReadCertificateFromPEM(*cert)
			if err != nil {
				csr, err := ReadCSRFromPEM(*cert)
				if err != nil {
					fmt.Println("Error loading certificate or CSR:", err)
					return
				}
				PrintInfo(csr)
			} else {
				PrintInfo(certificate)
			}
			os.Exit(0)
		} else if *pkey == "req" {
			caPrivateKey, err := readKeyFromPEM(*key, true)
			if err != nil {
				fmt.Println("Error loading key:", err)
				return
			}

			subject := pkix.Name{
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

			publicKey, err := readKeyFromPEM(*pub, false)
			if err != nil {
				fmt.Println("Error loading key:", err)
				return
			}

			csr, err := CreateCSR(subject, email, publicKey, caPrivateKey)
			if err != nil {
				log.Fatalf("Failed to create CSR: %v", err)
			}

			err = SaveCSRToPEM(csr, *cert)
			if err != nil {
				log.Fatalf("Failed to save CSR: %v", err)
			}

			fmt.Println("CSR created and saved to", *cert)
			os.Exit(0)
		} else if *pkey == "x509" {
			caPrivateKey, err := readKeyFromPEM(*key, true)
			if err != nil {
				fmt.Println("Error loading key:", err)
				return
			}

			caCert, err := ReadCertificateFromPEM(*root)
			if err != nil {
				log.Fatalf("Failed to read CA certificate: %v", err)
			}

			csr, err := ReadCSRFromPEM(*cert)
			if err != nil {
				log.Fatalf("Failed to read CSR: %v", err)
			}

			ca := &CA{
				PrivateKey:  caPrivateKey,
				Certificate: *caCert,
			}

			signedCert, err := SignCSR(csr, ca, caPrivateKey, validity)
			if err != nil {
				log.Fatalf("Failed to sign CSR: %v", err)
			}

			var outputFilename string
			if flag.Arg(0) == "" {
				outputFilename = "stdout"
			} else {
				outputFilename = flag.Arg(0)
			}

			err = SaveCertificateToPEM(signedCert, outputFilename)
			if err != nil {
				log.Fatalf("Failed to save certificate: %v", err)
			}

			fmt.Fprintf(os.Stderr, "Certificate signed and saved to %s\n", outputFilename)
			os.Exit(0)
		} else if *pkey == "crl" {
			pk, err := readKeyFromPEM(*pub, false)
			if err != nil {
				fmt.Println("Error loading public key:", err)
				return
			}

			sk, err := readKeyFromPEM(*key, true)
			if err != nil {
				fmt.Println("Error loading private key:", err)
				return
			}

			cert, err := ReadCertificateFromPEM(*cert)
			if err != nil {
				log.Fatalf("Failed to read CA certificate: %v", err)
			}

			ca := NewCA(sk, pk, validity)

			crl, err := NewCRL(ca, *crl, validity)
			if err != nil {
				fmt.Println("Error generating CRL:", err)
				return
			}

			revokedSerials, err := readRevokedSerials(flag.Arg(0))
			if err != nil {
				fmt.Printf("Error reading revoked serial numbers: %v\n", err)
				return
			}

			for _, serial := range revokedSerials {
				crl.RevokeCertificate(serial)
			}

			if err := crl.Sign(ca, cert); err != nil {
				fmt.Printf("Error signing CRL: %v\n", err)
				return
			}

			var outputFile string
			if len(flag.Args()) > 0 {
				outputFile = flag.Arg(1)
			}

			if err := SaveCRLToPEM(crl, outputFile); err != nil {
				fmt.Printf("Error saving CRL: %v\n", err)
				return
			}

			fmt.Println("CRL generated and saved successfully.")
			os.Exit(0)
		} else if *pkey == "validate" {
			certToValidate, err := ReadCertificateFromPEM(*cert)
			if err != nil {
				fmt.Printf("Error reading certificate: %v\n", err)
				return
			}

			readCRL, err := ReadCRLFromPEM(*crl)
			if err != nil {
				fmt.Printf("Error reading CRL: %v\n", err)
				return
			}

			if readCRL.IsRevoked(certToValidate.SerialNumber) {
				fmt.Println("The certificate has been revoked")
				os.Exit(1)
			} else {
				fmt.Println("The certificate is not revoked")
				os.Exit(0)
			}
		} else if *pkey == "check" && *crl != "" {
			certificate, err := ReadCertificateFromPEM(*cert)
			if err != nil {
				fmt.Println("Error reading certificate:", err)
				return
			}

			crl, err := ReadCRLFromPEM(*crl)
			if err != nil {
				fmt.Printf("Error reading CRL: %v\n", err)
				os.Exit(1)
			}

			if err := CheckCRL(crl, certificate.PublicKey); err != nil {
				fmt.Println("Verified: false", err)
				os.Exit(3)
			}

			fmt.Println("Verified: true")
			os.Exit(0)
		}
	}

	if (strings.ToUpper(*alg) == "ELGAMALPHP" || strings.ToUpper(*alg) == "EGPHP") && (*pkey == "keygen" || *pkey == "setup" || *pkey == "wrapkey" || *pkey == "unwrapkey" || *pkey == "sign" || *pkey == "verify") {
		if *pkey == "keygen" {
			if *priv == "" || *pub == "" {
				log.Fatal("You must specify -prv and -pub to save the keys")
			}

			prv, pubkey, err := elgamalphp.GenerateKeys()
			if err != nil {
				log.Fatalf("Error generating keys: %v", err)
			}

			privASN1 := PrivateKeyASN1{P: prv.P, G: prv.G, X: prv.X}
			privDER, err := asn1.Marshal(privASN1)
			if err != nil {
				log.Fatalf("Error encoding private key: %v", err)
			}
			err = savePEM(*priv, "ELGAMAL PRIVATE KEY", privDER)
			if err != nil {
				log.Fatalf("Error saving private key: %v", err)
			}

			pubASN1 := PublicKeyASN1{P: pubkey.P, G: pubkey.G, Y: pubkey.Y}
			pubDER, err := asn1.Marshal(pubASN1)
			if err != nil {
				log.Fatalf("Error encoding public key: %v", err)
			}
			err = savePEM(*pub, "ELGAMAL PUBLIC KEY", pubDER)
			if err != nil {
				log.Fatalf("Error saving public key: %v", err)
			}

			privPath, err := filepath.Abs(*priv)
			if err != nil {
				fmt.Println("Error getting absolute path for private key:", err)
				os.Exit(1)
			}
			fmt.Printf("Private Key saved to: %s\n", privPath)

			pubPath, err := filepath.Abs(*pub)
			if err != nil {
				fmt.Println("Error getting absolute path for public key:", err)
				os.Exit(1)
			}
			fmt.Printf("Public Key saved to: %s\n", pubPath)

			fingerprint := calculateFingerprint(pubkey.Y.Bytes())
			fmt.Println("Fingerprint=", fingerprint)

			primeBitLength := pubkey.P.BitLen()
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
			fmt.Println(randomArt)
			return
		}

		if *key == "" {
			log.Fatal("You must specify a key file with -key")
		}

		stdinBytes, err := io.ReadAll(inputfile)
		if err != nil {
			log.Fatalf("Error reading stdin: %v", err)
		}

		switch {
		case *pkey == "unwrapkey":
			privDER, err := readPEM(*key)
			if err != nil {
				log.Fatalf("Error reading private key: %v", err)
			}
			var privASN1 PrivateKeyASN1
			_, err = asn1.Unmarshal(privDER, &privASN1)
			if err != nil {
				log.Fatalf("Error decoding private key: %v", err)
			}
			priv := &elgamalphp.PrivateKey{P: privASN1.P, G: privASN1.G, X: privASN1.X}

			hexStr := strings.ReplaceAll(strings.TrimSpace(string(stdinBytes)), "\n", "")
			encData, err := hex.DecodeString(hexStr)
			if err != nil {
				log.Fatalf("Error decoding signature: %v", err)
			}

			var cipher CiphertextPHP
			_, err = asn1.Unmarshal(encData, &cipher)
			if err != nil {
				log.Fatalf("Error decoding ciphertext: %v", err)
			}

			msg, err := elgamalphp.Decrypt(priv, cipher.C1, cipher.C2)
			if err != nil {
				log.Fatalf("Error decrypting: %v", err)
			}
			os.Stdout.Write(msg)

		case *pkey == "sign":
			privDER, err := readPEM(*key)
			if err != nil {
				log.Fatalf("Error reading private key: %v", err)
			}
			var privASN1 PrivateKeyASN1
			_, err = asn1.Unmarshal(privDER, &privASN1)
			if err != nil {
				log.Fatalf("Error decoding private key: %v", err)
			}
			priv := &elgamalphp.PrivateKey{P: privASN1.P, G: privASN1.G, X: privASN1.X}

			hash := hashMessage(stdinBytes)
			r, s, err := elgamalphp.Sign(priv, hash)
			if err != nil {
				log.Fatalf("Error signing: %v", err)
			}

			signature := Signature{R: r, S: s}
			sigDER, err := asn1.Marshal(signature)
			if err != nil {
				log.Fatalf("Error encoding signature: %v", err)
			}
			fmt.Println(hex.EncodeToString(sigDER))

		case *pkey == "verify":
			pubDER, err := readPEM(*key)
			if err != nil {
				log.Fatalf("Error reading public key: %v", err)
			}
			var pubASN1 PublicKeyASN1
			_, err = asn1.Unmarshal(pubDER, &pubASN1)
			if err != nil {
				log.Fatalf("Error decoding public key: %v", err)
			}
			pub := &elgamalphp.PublicKey{P: pubASN1.P, G: pubASN1.G, Y: pubASN1.Y}

			signData, err := hex.DecodeString(*sig)
			if err != nil {
				log.Fatalf("Error decoding signature: %v", err)
			}

			var signature Signature
			_, err = asn1.Unmarshal(signData, &signature)
			if err != nil {
				log.Fatalf("Error decoding signature: %v", err)
			}

			hash := hashMessage(stdinBytes)
			valid, err := elgamalphp.Verify(pub, hash, signature.R, signature.S)
			if err != nil {
				log.Fatalf("Verification error: %v", err)
			}

			if valid {
				fmt.Println("Verified: true")
			} else {
				fmt.Println("Verified: false")
				os.Exit(1)
			}

		default:
			pubDER, err := readPEM(*key)
			if err != nil {
				log.Fatalf("Error reading public key: %v", err)
			}
			var pubASN1 PublicKeyASN1
			_, err = asn1.Unmarshal(pubDER, &pubASN1)
			if err != nil {
				log.Fatalf("Error decoding public key: %v", err)
			}
			pub := &elgamalphp.PublicKey{P: pubASN1.P, G: pubASN1.G, Y: pubASN1.Y}

			c1, c2, err := elgamalphp.Encrypt(pub, stdinBytes)
			if err != nil {
				log.Fatalf("Error encrypting: %v", err)
			}

			cipher := CiphertextPHP{C1: c1, C2: c2}
			cipherDER, err := asn1.Marshal(cipher)
			if err != nil {
				log.Fatalf("Error encoding ciphertext: %v", err)
			}
			fmt.Println(hex.EncodeToString(cipherDER))
		}
	}

	if (strings.ToUpper(*alg) == "SCHNORR") && (*pkey == "keygen" || *pkey == "setup" || *pkey == "text" || *pkey == "modulus" || *pkey == "sign" || *pkey == "verify" || *pkey == "proof" || *pkey == "verify-proof") {
		if *pkey == "setup" {
			setParams, err := generateSchnorrParams(*length)
			if err != nil {
				log.Fatal(err)
			}
			err = saveSchnorrParamsToPEM(*params, setParams)
			if err != nil {
				log.Fatal("Error saving Schnorr parameters to PEM file:", err)
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

		if *pkey == "text" && *key != "" && blockType == "SCHNORR PRIVATE KEY" {
			priv, err := readSchnorrPrivateKeyFromPEM(*key)
			if err != nil {
				fmt.Println("Error reading private key:", err)
				return
			}

			privBytes, err := encodeSchnorrPrivateKeyPEM(priv)
			if err != nil {
				log.Fatal(err)
			}
			pemBlock := &pem.Block{
				Type:  "SCHNORR PRIVATE KEY",
				Bytes: privBytes,
			}
			pemData := pem.EncodeToMemory(pemBlock)
			fmt.Print(string(pemData))

			fmt.Println("Private Key (x):")
			x := fmt.Sprintf("%x", priv.X)
			splitz := SplitSubN(x, 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}

			fmt.Println("Prime Modulus (p):")
			p := fmt.Sprintf("%x", priv.P)
			splitz = SplitSubN(p, 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}

			fmt.Println("Subgroup Order (q):")
			q := fmt.Sprintf("%x", priv.Q)
			splitz = SplitSubN(q, 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}

			fmt.Println("Generator (g):")
			g := fmt.Sprintf("%x", priv.G)
			splitz = SplitSubN(g, 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}

			fmt.Println("Public Key (Y = g^x mod p):")
			y := fmt.Sprintf("%x", priv.Y)
			splitz = SplitSubN(y, 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}

			os.Exit(0)
		}

		if *pkey == "text" && *key != "" && blockType == "SCHNORR PUBLIC KEY" {
			pub, err := readSchnorrPublicKeyFromPEM(*key)
			if err != nil {
				fmt.Println("Error reading public key:", err)
				os.Exit(1)
			}

			pemData, _ := ioutil.ReadFile(*key)
			fmt.Print(string(pemData))

			fmt.Println("Public Key Parameters:")
			fmt.Println("Prime Modulus (p):")
			p := fmt.Sprintf("%x", pub.P)
			splitz := SplitSubN(p, 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}

			fmt.Println("Subgroup Order (q):")
			q := fmt.Sprintf("%x", pub.Q)
			splitz = SplitSubN(q, 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}

			fmt.Println("Generator (g):")
			g := fmt.Sprintf("%x", pub.G)
			splitz = SplitSubN(g, 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}

			fmt.Println("Public Key (Y):")
			y := fmt.Sprintf("%x", pub.Y)
			splitz = SplitSubN(y, 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}

			return
		}

		if *pkey == "modulus" && blockType == "SCHNORR PRIVATE KEY" {
			priv, err := readSchnorrPrivateKeyFromPEM(*key)
			if err != nil {
				fmt.Println("Error reading private key:", err)
				os.Exit(1)
			}
			fmt.Printf("Y=%X\n", priv.Y)
			return
		}

		if *pkey == "modulus" && blockType == "SCHNORR PUBLIC KEY" {
			pub, err := readSchnorrPublicKeyFromPEM(*key)
			if err != nil {
				fmt.Println("Error reading public key:", err)
				os.Exit(1)
			}
			fmt.Printf("Y=%X\n", pub.Y)
			return
		}

		if *pkey == "text" && *params != "" {
			readParams, err := readSchnorrParamsFromPEM(*params)
			if err != nil {
				fmt.Println("Error reading Schnorr parameters from PEM file:", err)
				os.Exit(1)
			}

			pemData, err := ioutil.ReadFile(*params)
			if err != nil {
				fmt.Println("Error reading PEM file:", err)
				os.Exit(1)
			}
			fmt.Print(string(pemData))

			fmt.Println("Schnorr Parameters:")
			fmt.Println("Prime Modulus (p):")
			p := fmt.Sprintf("%x", readParams.P)
			splitz := SplitSubN(p, 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}

			fmt.Println("Subgroup Order (q):")
			q := fmt.Sprintf("%x", readParams.Q)
			splitz = SplitSubN(q, 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}

			fmt.Println("Generator (g):")
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

			readParams, err := readSchnorrParamsFromPEM(*params)
			if err != nil {
				log.Fatal("Error reading Schnorr parameters from PEM file:", err)
				os.Exit(1)
			}

			if *key == "" {
				xval, err = generatePrivateKey(readParams.Q)
				if err != nil {
					log.Fatal("Error generating private key:", err)
					os.Exit(1)
				}
				path, err = filepath.Abs(*priv)
				if err != nil {
					log.Fatal(err)
				}

				y := generatePublicKey(xval, readParams.G, readParams.P)
				privateKey := &SchnorrPrivateKey{
					SchnorrPublicKey: SchnorrPublicKey{
						P: readParams.P,
						Q: readParams.Q,
						G: readParams.G,
						Y: y,
					},
					X: xval,
				}

				if err := saveSchnorrPrivateKeyToPEM(*priv, privateKey); err != nil {
					log.Fatal("Error saving private key:", err)
					os.Exit(1)
				}
				fmt.Fprintf(os.Stderr, "Private Key saved to: %s\n", path)
			} else {
				priva, err := readSchnorrPrivateKeyFromPEM(*key)
				if err != nil {
					log.Fatal("Error reading private key:", err)
					os.Exit(1)
				}
				xval = new(big.Int).Set(priva.X)
				path, err = filepath.Abs(*priv)
				if err != nil {
					log.Fatal(err)
				}

				y := generatePublicKey(xval, readParams.G, readParams.P)
				privateKey := &SchnorrPrivateKey{
					SchnorrPublicKey: SchnorrPublicKey{
						P: readParams.P,
						Q: readParams.Q,
						G: readParams.G,
						Y: y,
					},
					X: xval,
				}

				if err := saveSchnorrPrivateKeyToPEM(*priv, privateKey); err != nil {
					log.Fatal("Error saving private key:", err)
					os.Exit(1)
				}
				fmt.Fprintf(os.Stderr, "Private Key saved to: %s\n", path)
			}

			publicKey := generatePublicKey(xval, readParams.G, readParams.P)

			path, err = filepath.Abs(*pub)
			if err != nil {
				log.Fatal(err)
			}

			publicKeyStruct := &SchnorrPublicKey{
				P: readParams.P,
				Q: readParams.Q,
				G: readParams.G,
				Y: publicKey,
			}

			if err := saveSchnorrPublicKeyToPEM(*pub, publicKeyStruct); err != nil {
				log.Fatal("Error saving public key:", err)
				os.Exit(1)
			}
			fmt.Fprintf(os.Stderr, "Public Key saved to: %s\n", path)

			fingerprint := calculateFingerprint(publicKey.Bytes())
			fmt.Fprintf(os.Stderr, "Fingerprint: %s\n", fingerprint)

			primeBitLength := readParams.P.BitLen()
			fmt.Fprintf(os.Stderr, "Schnorr (%d-bits)\n", primeBitLength)

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
			priv, err := readSchnorrPrivateKeyFromPEM(*key)
			if err != nil {
				fmt.Println("Error reading private key:", err)
				os.Exit(1)
			}

			message, err := ioutil.ReadAll(inputfile)
			if err != nil {
				log.Fatal("Error reading message:", err)
			}

			signature, err := SchnorrSignASN1(rand.Reader, priv, message, myHash())
			if err != nil {
				log.Fatal("Error signing message:", err)
				os.Exit(1)
			}

			fmt.Printf("SCHNORR-%s(%s)= %x\n", strings.ToUpper(*md), inputdesc, signature)
		}

		if *pkey == "verify" {
			if *key == "" {
				fmt.Println("Error: Public key file not provided for verification.")
				os.Exit(3)
			}

			pub, err := readSchnorrPublicKeyFromPEM(*key)
			if err != nil {
				fmt.Println("Error: Invalid public key value")
				os.Exit(1)
			}

			message, err := ioutil.ReadAll(inputfile)
			if err != nil {
				log.Fatal("Error reading message:", err)
			}

			signatureBytes, err := hex.DecodeString(*sig)
			if err != nil {
				fmt.Println("Error decoding hexadecimal signature:", err)
				return
			}

			isValid, err := SchnorrVerifyASN1(pub, message, signatureBytes, myHash())
			if err != nil {
				fmt.Println("Error verifying signature:", err)
				os.Exit(1)
			}

			fmt.Println("Verified:", isValid)
			if isValid {
				os.Exit(0)
			} else {
				os.Exit(1)
			}
		}

		if *pkey == "proof" {
			priv, err := readSchnorrPrivateKeyFromPEM(*key)
			if err != nil {
				fmt.Println("Error reading private key:", err)
				os.Exit(1)
			}

			message, err := ioutil.ReadAll(inputfile)
			if err != nil {
				log.Fatal("Error reading message:", err)
			}

			t, e, s, err := ProveKnowledge(priv, message, myHash())
			if err != nil {
				fmt.Println("Error generating ZKP:", err)
				return
			}

			fmt.Printf("Commitment= %x\n", t)
			fmt.Printf("Challenge= %x\n", e)
			fmt.Printf("Response= %x\n", s)
		}

		if *pkey == "verify-proof" {
			if *key == "" {
				fmt.Println("Error: Public key file not provided for verification.")
				os.Exit(3)
			}

			pub, err := readSchnorrPublicKeyFromPEM(*key)
			if err != nil {
				fmt.Println("Error: Invalid public key value")
				os.Exit(1)
			}

			message, err := ioutil.ReadAll(inputfile)
			if err != nil {
				log.Fatal("Error reading message:", err)
			}

			if *commitmentFlag == "" || *challengeFlag == "" || *responseFlag == "" {
				log.Fatal("All of --commitment, --challenge, and --response must be provided")
			}

			t := new(big.Int)
			e := new(big.Int)
			s := new(big.Int)

			_, ok := t.SetString(*commitmentFlag, 16)
			if !ok {
				log.Fatalf("Invalid commitment: %s", *commitmentFlag)
			}

			_, ok = e.SetString(*challengeFlag, 16)
			if !ok {
				log.Fatalf("Invalid challenge: %s", *challengeFlag)
			}

			_, ok = s.SetString(*responseFlag, 16)
			if !ok {
				log.Fatalf("Invalid response: %s", *responseFlag)
			}

			if VerifyKnowledge(pub, t, e, s, message, myHash()) {
				fmt.Println("Verified: true")
			} else {
				fmt.Println("Verified: false")
				os.Exit(1)
			}
		}
	}

	if (strings.ToUpper(*alg) == "ELGAMAL" || strings.ToUpper(*alg) == "EG") && (*pkey == "keygen" || *pkey == "setup" || *pkey == "wrapkey" || *pkey == "unwrapkey" || *pkey == "text" || *pkey == "modulus" || *pkey == "sign" || *pkey == "verify" || *pkey == "proof" || *pkey == "verify-proof") {
		if *pkey == "setup" {
			setParams, err := generateElGamalParams(*length)
			if err != nil {
				log.Fatal(err)
			}
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
			data, err := os.ReadFile(*key)
			if err != nil {
				fmt.Println("Error reading private key file:", err)
				return
			}

			block, _ := pem.Decode(data)
			if block == nil {
				fmt.Println("Failed to decode PEM block")
				return
			}

			var rawComponents []asn1.RawValue
			if _, err := asn1.Unmarshal(block.Bytes, &rawComponents); err == nil {
				if len(rawComponents) == 3 {
					var privASN1 PrivateKeyASN1
					if _, err := asn1.Unmarshal(block.Bytes, &privASN1); err == nil {
						priv := &PrivateKey{
							PublicKey: PublicKey{
								P: privASN1.P,
								G: privASN1.G,
								Y: new(big.Int).Exp(privASN1.G, privASN1.X, privASN1.P),
							},
							X: privASN1.X,
						}

						publicKey := priv.PublicKey.Y

						fmt.Print(string(data))

						xval := new(big.Int).Set(priv.X)
						fmt.Println("Private Key (x):")
						x := fmt.Sprintf("%x", xval)
						splitz := SplitSubN(x, 2)
						for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
							fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
						}
						fmt.Println("Prime (p):")
						p := fmt.Sprintf("%x", priv.P)
						splitz = SplitSubN(p, 2)
						for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
							fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
						}
						fmt.Println("Generator (g in the range [2, p-2]):")
						g := fmt.Sprintf("%x", priv.G)
						splitz = SplitSubN(g, 2)
						for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
							fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
						}
						fmt.Println("Public Key (Y = g^x mod p):")
						pub := fmt.Sprintf("%x", publicKey)
						splitz = SplitSubN(pub, 2)
						for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
							fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
						}
						os.Exit(0)
					}
				}
			}

			priv, err := readPrivateKeyFromPEM(*key)
			if err != nil {
				fmt.Println("Error reading private key:", err)
				return
			}

			privPEM := &PrivateKey{
				PublicKey: PublicKey{
					G: priv.G,
					Q: priv.Q,
					P: priv.P,
					Y: priv.Y,
				},
				X: priv.X,
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
			fmt.Println("Private Key (x):")
			x := fmt.Sprintf("%x", xval)
			splitz := SplitSubN(x, 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}
			fmt.Println("Prime Modulus (p):")
			p := fmt.Sprintf("%x", priv.P)
			splitz = SplitSubN(p, 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}
			fmt.Println("Subgroup Order (q):")
			q := fmt.Sprintf("%x", priv.Q)
			splitz = SplitSubN(q, 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}
			fmt.Println("Generator (g in the range [2, p-2]):")
			g := fmt.Sprintf("%x", priv.G)
			splitz = SplitSubN(g, 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}
			fmt.Println("Public Key (Y = g^x mod p):")
			pub := fmt.Sprintf("%x", publicKey)
			splitz = SplitSubN(pub, 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}
			os.Exit(0)
		}

		if *pkey == "text" && *key != "" && blockType == "ELGAMAL PUBLIC KEY" {
			pemData, err := os.ReadFile(*key)
			if err != nil {
				fmt.Println("Error reading public key file:", err)
				os.Exit(1)
			}

			block, _ := pem.Decode(pemData)
			if block == nil {
				fmt.Println("Failed to decode PEM block")
				os.Exit(1)
			}

			var rawComponents []asn1.RawValue
			if _, err := asn1.Unmarshal(block.Bytes, &rawComponents); err == nil {
				if len(rawComponents) == 3 {
					var pubASN1 PublicKeyASN1
					if _, err := asn1.Unmarshal(block.Bytes, &pubASN1); err == nil {
						publicKeyVal := &PublicKey{
							P: pubASN1.P,
							G: pubASN1.G,
							Y: pubASN1.Y,
						}

						fmt.Print(string(pemData))

						fmt.Println("Public Key Parameters:")
						fmt.Println("Prime (p):")
						p := fmt.Sprintf("%x", publicKeyVal.P)
						splitz := SplitSubN(p, 2)
						for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
							fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
						}
						fmt.Println("Generator (g):")
						g := fmt.Sprintf("%x", publicKeyVal.G)
						splitz = SplitSubN(g, 2)
						for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
							fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
						}
						fmt.Println("Public Key (Y):")
						y := fmt.Sprintf("%x", publicKeyVal.Y)
						splitz = SplitSubN(y, 2)
						for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
							fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
						}
						return
					}
				}
			}

			publicKeyVal, err := readPublicKeyFromPEM(*key)
			if err != nil {
				fmt.Println("Error: Invalid public key value")
				os.Exit(1)
			}

			fmt.Print(string(pemData))
			fmt.Println("Public Key Parameters:")
			fmt.Println("Prime Modulus (p):")
			p := fmt.Sprintf("%x", publicKeyVal.P)
			splitz := SplitSubN(p, 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}
			fmt.Println("Subgroup Order (q):")
			q := fmt.Sprintf("%x", publicKeyVal.Q)
			splitz = SplitSubN(q, 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}
			fmt.Println("Generator (g):")
			g := fmt.Sprintf("%x", publicKeyVal.G)
			splitz = SplitSubN(g, 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}
			fmt.Println("Public Key (Y):")
			y := fmt.Sprintf("%x", publicKeyVal.Y)
			splitz = SplitSubN(y, 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}
			return
		}
		if *pkey == "modulus" && blockType == "ELGAMAL PRIVATE KEY" {
			data, err := os.ReadFile(*key)
			if err != nil {
				fmt.Println("Error reading private key file:", err)
				os.Exit(1)
			}

			block, _ := pem.Decode(data)
			if block == nil {
				fmt.Println("Failed to decode PEM block")
				os.Exit(1)
			}

			var privASN1 PrivateKeyASN1
			if _, err := asn1.Unmarshal(block.Bytes, &privASN1); err == nil {
				y := new(big.Int).Exp(privASN1.G, privASN1.X, privASN1.P)
				fmt.Printf("Y=%X\n", y)
				return
			}

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
			data, err := os.ReadFile(*key)
			if err != nil {
				fmt.Println("Error reading public key file:", err)
				os.Exit(1)
			}

			block, _ := pem.Decode(data)
			if block == nil {
				fmt.Println("Failed to decode PEM block")
				os.Exit(1)
			}

			var pubASN1 PublicKeyASN1
			if _, err := asn1.Unmarshal(block.Bytes, &pubASN1); err == nil {
				fmt.Printf("Y=%X\n", pubASN1.Y)
				return
			}

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
				Q: publicKeyVal.Q,
				P: publicKeyVal.P,
				Y: publicKeyVal.Y,
			}

			messageBytes := make([]byte, *length/8)
			_, err = rand.Read(messageBytes)
			if err != nil {
				fmt.Println("Error generating random key:", err)
				os.Exit(1)
			}
			c, err := EncryptASN1(rand.Reader, pub, messageBytes)
			if err != nil {
				fmt.Println("Error encrypting message:", err)
				os.Exit(1)
			}

			fmt.Printf("Cipher= %x\n", c)
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

			ciphertext, err := hex.DecodeString(*cph)
			if err != nil {
				fmt.Println("Error decoding the hexadecimal cipher:", err)
				return
			}
			message, err := DecryptASN1(priv, ciphertext)
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
			fmt.Println("Prime Modulus (p):")
			p := fmt.Sprintf("%x", readParams.P)
			splitz := SplitSubN(p, 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}
			fmt.Println("Subgroup Order (q):")
			q := fmt.Sprintf("%x", readParams.Q)
			splitz = SplitSubN(q, 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}
			fmt.Println("Generator (g):")
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
				xval, err = generateRandomX(readParams.Q)
				if err != nil {
					log.Fatal("Error generating x:", err)
					os.Exit(1)
				}
				path, err = filepath.Abs(*priv)
				if err != nil {
					log.Fatal(err)
				}
				y := setup(xval, readParams.G, readParams.P)
				privateKey := &PrivateKey{
					PublicKey: PublicKey{
						G: readParams.G,
						Q: readParams.Q,
						P: readParams.P,
						Y: y,
					},
					X: xval,
				}
				if err := savePrivateKeyToPEM(*priv, privateKey); err != nil {
					log.Fatal("Error saving private key:", err)
					os.Exit(1)
				}
				fmt.Fprintf(os.Stderr, "Private Key saved to: %s\n", path)
			} else {
				priva, err := readPrivateKeyFromPEM(*key)
				if err != nil {
					log.Fatal("Error reading private key:", err)
					os.Exit(1)
				}
				xval = new(big.Int).Set(priva.X)
				path, err = filepath.Abs(*priv)
				if err != nil {
					log.Fatal(err)
				}
				y := setup(xval, readParams.G, readParams.P)
				privateKey := &PrivateKey{
					PublicKey: PublicKey{
						G: readParams.G,
						Q: readParams.Q,
						P: readParams.P,
						Y: y,
					},
					X: xval,
				}
				if err := savePrivateKeyToPEM(*priv, privateKey); err != nil {
					log.Fatal("Error saving private key:", err)
					os.Exit(1)
				}
				fmt.Fprintf(os.Stderr, "Private Key saved to: %s\n", path)
			}

			publicKey := setup(xval, readParams.G, readParams.P)

			path, err = filepath.Abs(*pub)
			if err != nil {
				log.Fatal(err)
			}

			fmt.Fprintf(os.Stderr, "Public Key saved to: %s\n", path)
			if err := savePublicKeyToPEM(*pub, &PublicKey{Y: publicKey, G: readParams.G, Q: readParams.Q, P: readParams.P}); err != nil {
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

		if *pkey == "sign" && strings.ToUpper(*scheme) == "DSA" {
			priv, err := readPrivateKeyFromPEM(*key)
			if err != nil {
				fmt.Println("Error reading private key:", err)
				os.Exit(1)
			}

			hash := myHash()
			if _, err := io.Copy(hash, inputfile); err != nil {
				log.Fatal(err)
			}
			if err != nil {
				fmt.Println("Error hashing message:", err)
				os.Exit(1)
			}
			hashBytes := hash.Sum(nil)

			sign, err := SignASN1DSA(rand.Reader, priv, hashBytes)
			if err != nil {
				log.Fatal("Error signing message:", err)
				os.Exit(1)
			}

			fmt.Printf("EG-DSA-%s(%s)= %x\n", strings.ToUpper(*md), inputdesc, sign)
			os.Exit(0)
		}
		if *pkey == "verify" && strings.ToUpper(*scheme) == "DSA" {
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
				Q: publicKeyVal.Q,
				P: publicKeyVal.P,
				Y: publicKeyVal.Y,
			}

			signatureBytes, err := hex.DecodeString(*sig)
			if err != nil {
				fmt.Println("Error decoding hexadecimal signature:", err)
				return
			}

			hash := myHash()
			if _, err := io.Copy(hash, inputfile); err != nil {
				log.Fatal(err)
			}
			if err != nil {
				fmt.Println("Error hashing message:", err)
				os.Exit(1)
			}
			hashBytes := hash.Sum(nil)

			isValid, _ := VerifyASN1DSA(pub, hashBytes, signatureBytes)
			fmt.Println("Verified:", isValid)
			if isValid {
				os.Exit(0)
			} else {
				os.Exit(1)
			}
		}

		if *pkey == "sign" {
			priv, err := readPrivateKeyFromPEM(*key)
			if err != nil {
				fmt.Println("Error reading private key:", err)
				os.Exit(1)
			}

			data, err := io.ReadAll(inputfile)
			if err != nil {
				log.Fatal(err)
			}

			sign, err := SignASN1(rand.Reader, priv, data, myHash())
			if err != nil {
				log.Fatal("Error signing message:", err)
				os.Exit(1)
			}

			fmt.Printf("EG-%s(%s)= %x\n", strings.ToUpper(*md), inputdesc, sign)
			os.Exit(0)
		}
		if *pkey == "verify" {
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
				Q: publicKeyVal.Q,
				P: publicKeyVal.P,
				Y: publicKeyVal.Y,
			}

			signatureBytes, err := hex.DecodeString(*sig)
			if err != nil {
				fmt.Println("Error decoding hexadecimal signature:", err)
				return
			}

			data, err := io.ReadAll(inputfile)
			if err != nil {
				log.Fatal(err)
			}

			isValid, _ := VerifyASN1(pub, data, signatureBytes, myHash())
			fmt.Println("Verified:", isValid)
			if isValid {
				os.Exit(0)
			} else {
				os.Exit(1)
			}
		}

		if *pkey == "proof" {
			priv, err := readPrivateKeyFromPEM(*key)
			if err != nil {
				fmt.Println("Error reading private key:", err)
				os.Exit(1)
			}

			message, err := ioutil.ReadAll(inputfile)
			if err != nil {
				log.Fatal("Error reading message:", err)
			}

			t, c, s, err := ProveKnowledgeElGamal(priv, message, myHash())
			if err != nil {
				fmt.Println("Error generating ZKP:", err)
				return
			}

			fmt.Printf("Commitment= %x\n", t)
			fmt.Printf("Challenge= %x\n", c)
			fmt.Printf("Response= %x\n", s)
		}

		if *pkey == "verify-proof" {
			if *key == "" {
				fmt.Println("Error: Public key file not provided for verification.")
				os.Exit(3)
			}

			pub, err := readPublicKeyFromPEM(*key)
			if err != nil {
				fmt.Println("Error: Invalid public key value")
				os.Exit(1)
			}

			message, err := ioutil.ReadAll(inputfile)
			if err != nil {
				log.Fatal("Error reading message:", err)
			}

			if *commitmentFlag == "" || *challengeFlag == "" || *responseFlag == "" {
				log.Fatal("All of --commitment, --challenge, and --response must be provided")
			}

			t := new(big.Int)
			c := new(big.Int)
			s := new(big.Int)

			if _, ok := t.SetString(*commitmentFlag, 16); !ok {
				log.Fatalf("Invalid commitment: %s", *commitmentFlag)
			}
			if _, ok := c.SetString(*challengeFlag, 16); !ok {
				log.Fatalf("Invalid challenge: %s", *challengeFlag)
			}
			if _, ok := s.SetString(*responseFlag, 16); !ok {
				log.Fatalf("Invalid response: %s", *responseFlag)
			}

			if VerifyKnowledgeElGamal(pub, t, c, s, message, myHash()) {
				fmt.Println("Verified: true")
			} else {
				fmt.Println("Verified: false")
				os.Exit(1)
			}
		}
	}

	if (strings.ToUpper(*alg) == "EC" || strings.ToUpper(*alg) == "EC-ELGAMAL" || strings.ToUpper(*alg) == "ECKA-EG" || strings.ToUpper(*alg) == "FRP256V1" || strings.ToUpper(*alg) == "NUMS" || strings.ToUpper(*alg) == "KOBLITZ" || strings.ToUpper(*alg) == "FRP256V1" || strings.ToUpper(*alg) == "ANSSI" || strings.ToUpper(*alg) == "TOM" || strings.ToUpper(*alg) == "BIGN" || strings.ToUpper(*alg) == "SM2" || strings.ToUpper(*alg) == "BIP0340" || strings.ToUpper(*alg) == "ECSDSA") && (*pkey == "wrapkey" || *pkey == "unwrapkey") {
		if *pkey == "unwrapkey" {
			keyBytes, err := readKeyFromPEM(*key, true)
			if err != nil {
				fmt.Println("Error reading key from PEM:", err)
				return
			}

			parsers := []func([]byte) (interface{}, error){
				func(b []byte) (interface{}, error) { return smx509.ParsePKCS8PrivateKey(b) },
				func(b []byte) (interface{}, error) { return smx509.ParseECPrivateKey(b) },
				func(b []byte) (interface{}, error) { return x509.ParseECPrivateKey(b) },
				func(b []byte) (interface{}, error) { return nums.ParsePrivateKey(b) },
				func(b []byte) (interface{}, error) { return bign.ParsePrivateKey(b) },
				func(b []byte) (interface{}, error) { return frp256v1.ParsePrivateKey(b) },
				func(b []byte) (interface{}, error) { return secp256k1.ParsePrivateKey(b) },
				func(b []byte) (interface{}, error) { return tom.ParsePrivateKey(b) },
				func(b []byte) (interface{}, error) { return ecsdsa.ParsePrivateKey(b) },
				func(b []byte) (interface{}, error) { return bip0340.ParsePrivateKey(b) },
			}

			var privateKey interface{}
			for _, parser := range parsers {
				privateKey, err = parser(keyBytes)
				if err == nil {
					break
				}
			}
			if err != nil {
				log.Fatal("Failed to parse private key:", err)
			}

			var curve elliptic.Curve
			var d *big.Int

			switch k := privateKey.(type) {
			case *ecdsa.PrivateKey:
				curve = k.Curve
				d = k.D
			case *nums.PrivateKey:
				curve = k.PublicKey.Curve
				d = k.D
			case *frp256v1.PrivateKey:
				curve = frp256v1.P256()
				d = k.D
			case *secp256k1.PrivateKey:
				curve = secp256k1.S256()
				d = k.D
			case *bign.PrivateKey:
				curve = k.Curve
				d = k.D
			case *tom.PrivateKey:
				curve = k.PublicKey.Curve
				d = k.D
			case *sm2.PrivateKey:
				curve = k.Curve
				d = k.D
			case *ecsdsa.PrivateKey:
				curve = k.Curve
				d = k.D
			case *bip0340.PrivateKey:
				curve = k.Curve
				d = k.D
			default:
				log.Fatal("Unsupported private key type")
			}

			ctASN1, err := hex.DecodeString(*cph)
			if err != nil {
				log.Fatalf("Error decoding hex: %v", err)
			}

			var ct2 CiphertextEC
			if _, err := asn1.Unmarshal(ctASN1, &ct2); err != nil {
				log.Fatal(err)
			}

			dMx, dMy, err := decryptECElGamal(curve, d, &ct2)
			if err != nil {
				fmt.Println("Error decrypting:", err)
				return
			}
			buf := append(dMx.Bytes(), dMy.Bytes()...)
			hasher := myHash()
			hasher.Write(buf)
			result := hasher.Sum(nil)[:*length/8]

			fmt.Printf("Shared= %x\n", result)
		} else {
			keyBytes, err := readKeyFromPEM(*key, false)
			if err != nil {
				fmt.Println("Error reading key from PEM:", err)
				return
			}

			parsers := []func([]byte) (interface{}, error){
				func(b []byte) (interface{}, error) { return smx509.ParsePKIXPublicKey(b) },
				func(b []byte) (interface{}, error) { return x509.ParsePKIXPublicKey(b) },
				func(b []byte) (interface{}, error) { return nums.ParsePublicKey(b) },
				func(b []byte) (interface{}, error) { return bign.ParsePublicKey(b) },
				func(b []byte) (interface{}, error) { return frp256v1.ParsePublicKey(b) },
				func(b []byte) (interface{}, error) { return secp256k1.ParsePublicKey(b) },
				func(b []byte) (interface{}, error) { return tom.ParsePublicKey(b) },
				func(b []byte) (interface{}, error) { return ecsdsa.ParsePublicKey(b) },
				func(b []byte) (interface{}, error) { return bip0340.ParsePublicKey(b) },
			}

			var publicKey interface{}
			for _, parser := range parsers {
				publicKey, err = parser(keyBytes)
				if err == nil {
					break
				}
			}
			if err != nil {
				log.Fatal("Failed to parse public key:", err)
			}

			var curve elliptic.Curve
			var x, y *big.Int

			switch k := publicKey.(type) {
			case *ecdsa.PublicKey:
				curve = k.Curve
				x, y = k.X, k.Y
			case *nums.PublicKey:
				curve = k.Curve
				x, y = k.X, k.Y
			case *frp256v1.PublicKey:
				curve = frp256v1.P256()
				x, y = k.X, k.Y
			case *secp256k1.PublicKey:
				curve = secp256k1.S256()
				x, y = k.X, k.Y
			case *bign.PublicKey:
				curve = k.Curve
				x, y = k.X, k.Y
			case *tom.PublicKey:
				curve = k.Curve
				x, y = k.X, k.Y
			case *ecsdsa.PublicKey:
				curve = k.Curve
				x, y = k.X, k.Y
			case *bip0340.PublicKey:
				curve = k.Curve
				x, y = k.X, k.Y
			default:
				log.Fatal("Unsupported public key type")
			}

			s, _ := rand.Int(rand.Reader, curve.Params().N)
			Mx, My := curve.ScalarBaseMult(s.Bytes())

			ct, err := encryptECElGamal(curve, x, y, Mx, My)
			if err != nil {
				log.Fatal(err)
			}

			ctASN1, err := asn1.Marshal(*ct)
			if err != nil {
				log.Fatal(err)
			}

			fmt.Printf("Cipher= %x\n", ctASN1)
			buf := append(Mx.Bytes(), My.Bytes()...)
			hasher := myHash()
			hasher.Write(buf)
			result := hasher.Sum(nil)[:*length/8]

			fmt.Printf("Shared= %x\n", result)
		}
	}

	if (strings.ToUpper(*alg) == "ML-KEM") && (*pkey == "keygen" || *pkey == "wrapkey" || *pkey == "unwrapkey" || *pkey == "text" || *pkey == "fingerprint" || *pkey == "randomart") {
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
		if *pkey == "text" && *key != "" && blockType == "ML-KEM SECRET KEY" {
			keyBytes, err := readKeyFromPEM(*key, true)
			if err != nil {
				fmt.Println("Error reading key from PEM:", err)
				os.Exit(1)
			}
			pubKeyPEM := pem.Block{Type: "ML-KEM SECRET KEY", Bytes: keyBytes}
			keyPEMText := string(pem.EncodeToMemory(&pubKeyPEM))
			fmt.Print(keyPEMText)
			fmt.Println("SecretKey:")
			p := fmt.Sprintf("%x", keyBytes)
			splitz := SplitSubN(p, 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}

			var oid string
			switch len(keyBytes) {
			case 1632:
				oid = "ML-KEM-512"
			case 2400:
				oid = "ML-KEM-768"
			case 3168:
				oid = "ML-KEM-1024"
			default:
				fmt.Errorf("invalid public key size: %d", len(keyBytes))
			}

			fmt.Printf("ASN.1 OID: %s\n", oid)

			os.Exit(0)
		} else if *pkey == "text" && *key != "" && blockType == "ML-KEM PUBLIC KEY" {
			keyBytes, err := readKeyFromPEM(*key, false)
			if err != nil {
				fmt.Println("Error reading key from PEM:", err)
				os.Exit(1)
			}
			pubKeyPEM := pem.Block{Type: "ML-KEM PUBLIC KEY", Bytes: keyBytes}
			keyPEMText := string(pem.EncodeToMemory(&pubKeyPEM))
			fmt.Print(keyPEMText)
			fmt.Println("PublicKey:")
			p := fmt.Sprintf("%x", keyBytes)
			splitz := SplitSubN(p, 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}

			var oid string
			switch len(keyBytes) {
			case 800:
				oid = "ML-KEM-512"
			case 1184:
				oid = "ML-KEM-768"
			case 1568:
				oid = "ML-KEM-1024"
			default:
				fmt.Errorf("invalid public key size: %d", len(keyBytes))
			}
			fmt.Printf("ASN.1 OID: %s\n", oid)

			skid := sha3.Sum256(keyBytes)
			fmt.Printf("\nKeyID: %x \n", skid[:20])
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
			pubFile, err := os.Open(*key)
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

			pk, err := readKeyFromPEM(*key, false)
			if err != nil {
				fmt.Println("Error loading key:", err)
				return
			}

			var keySize string
			switch len(pk) {
			case 800:
				keySize = "512-bit"
			case 1184:
				keySize = "768-bit"
			case 1568:
				keySize = "1024-bit"
			default:
				keySize = "unknown size"
			}

			fmt.Printf("ML-KEM (%s)\n", keySize)
			pubFile.Read(pubBuf)
			randomArt := randomart.FromString(string(pubBuf))
			fmt.Println(randomArt)
			os.Exit(0)
		}
		if *pkey == "keygen" {
			pk, sk, err := GenerateKyber(*length)
			if err != nil {
				fmt.Println("Error:", err)
				return
			}

			block := &pem.Block{
				Type:  "ML-KEM SECRET KEY",
				Bytes: sk,
			}
			if err := savePEMToFile(*priv, block, true); err != nil {
				fmt.Println("Error saving keys:", err)
				return
			}

			block = &pem.Block{
				Type:  "ML-KEM PUBLIC KEY",
				Bytes: pk,
			}

			if err := savePEMToFile(*pub, block, false); err != nil {
				fmt.Println("Error saving keys:", err)
				return
			}

			privPath, err := filepath.Abs(*priv)
			if err != nil {
				fmt.Println("Error getting absolute path for private key:", err)
				os.Exit(1)
			}
			fmt.Printf("Private Key saved to: %s\n", privPath)

			pubPath, err := filepath.Abs(*pub)
			if err != nil {
				fmt.Println("Error getting absolute path for public key:", err)
				os.Exit(1)
			}
			fmt.Printf("Public Key saved to: %s\n", pubPath)

			fingerprint := calculateFingerprint(pk)
			fmt.Printf("Fingerprint: %s\n", fingerprint)

			fmt.Printf("ML-KEM (%d-bit)\n", *length)

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
		} else if *pkey == "wrapkey" {
			pk, err := readKeyFromPEM(*key, false)
			if err != nil {
				fmt.Println("Error loading key:", err)
				return
			}

			err = WrapKey(pk)
			if err != nil {
				fmt.Println(err)
				return
			}
		} else if *pkey == "unwrapkey" {
			sk, err := readKeyFromPEM(*key, true)
			if err != nil {
				fmt.Println("Error loading key:", err)
				return
			}

			unwrappedKey, err := UnwrapKey(sk, *cph)
			if err != nil {
				fmt.Println("Error unwrapping key:", err)
				return
			}

			fmt.Println("Shared=", hex.EncodeToString(unwrappedKey))
		}
	}

	if (strings.ToUpper(*alg) == "ML-DSA") && (*pkey == "keygen" || *pkey == "certgen" || *pkey == "req" || *pkey == "x509" || *pkey == "check" || *pkey == "crl" || *pkey == "validate" || *pkey == "sign" || *pkey == "verify" || *pkey == "text" || *pkey == "fingerprint" || *pkey == "randomart") {
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
		if *pkey == "text" && *key != "" && blockType == "ML-DSA SECRET KEY" {
			keyBytes, err := readKeyFromPEM(*key, true)
			if err != nil {
				fmt.Println("Error reading key from PEM:", err)
				os.Exit(1)
			}
			pubKeyPEM := pem.Block{Type: "ML-DSA SECRET KEY", Bytes: keyBytes}
			keyPEMText := string(pem.EncodeToMemory(&pubKeyPEM))
			fmt.Print(keyPEMText)
			fmt.Println("SecretKey:")
			p := fmt.Sprintf("%x", keyBytes)
			splitz := SplitSubN(p, 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}

			var oid string
			switch len(keyBytes) {
			case 2528:
				oid = "ML-DSA-44"
			case 4000:
				oid = "ML-DSA-65"
			case 4864:
				oid = "ML-DSA-87"
			default:
				fmt.Errorf("invalid public key size: %d", len(keyBytes))
			}
			fmt.Printf("ASN.1 OID: %s\n", oid)

			os.Exit(0)
		} else if *pkey == "text" && *key != "" && blockType == "ML-DSA PUBLIC KEY" {
			keyBytes, err := readKeyFromPEM(*key, false)
			if err != nil {
				fmt.Println("Error reading key from PEM:", err)
				os.Exit(1)
			}
			pubKeyPEM := pem.Block{Type: "ML-DSA PUBLIC KEY", Bytes: keyBytes}
			keyPEMText := string(pem.EncodeToMemory(&pubKeyPEM))
			fmt.Print(keyPEMText)
			fmt.Println("PublicKey:")
			p := fmt.Sprintf("%x", keyBytes)
			splitz := SplitSubN(p, 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}

			var oid string
			switch len(keyBytes) {
			case 1312:
				oid = "ML-DSA-44"
			case 1952:
				oid = "ML-DSA-65"
			case 2592:
				oid = "ML-DSA-87"
			default:
				fmt.Errorf("invalid public key size: %d", len(keyBytes))
			}
			fmt.Printf("ASN.1 OID: %s\n", oid)

			skid := sha3.Sum256(keyBytes)
			fmt.Printf("\nKeyID: %x \n", skid[:20])
			os.Exit(0)
		} else if *pkey == "text" && *key == "" && *crl != "" {
			crl, err := ReadCRLFromPEM(*crl)
			if err != nil {
				log.Fatalf("Error reading the CRL: %v", err)
			}

			PrintCRLInfo(crl)
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
			pubFile, err := os.Open(*key)
			if err != nil {
				fmt.Println("Error opening public key file:", err)
				os.Exit(1)
			}
			defer pubFile.Close()

			pk, err := readKeyFromPEM(*key, false)
			if err != nil {
				fmt.Println("Error loading key:", err)
				return
			}

			var keySize string
			switch len(pk) {
			case 1312:
				keySize = "2048-bit"
			case 1952:
				keySize = "3072-bit"
			case 2592:
				keySize = "4096-bit"
			default:
				keySize = "unknown size"
			}

			fmt.Printf("ML-DSA (%s)\n", keySize)

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
			pk, sk, err := GenerateDilithium(*length)
			if err != nil {
				fmt.Println("Error:", err)
				return
			}

			block := &pem.Block{
				Type:  "ML-DSA SECRET KEY",
				Bytes: sk,
			}
			if err := savePEMToFile(*priv, block, true); err != nil {
				fmt.Println("Error saving keys:", err)
				return
			}

			block = &pem.Block{
				Type:  "ML-DSA PUBLIC KEY",
				Bytes: pk,
			}

			if err := savePEMToFile(*pub, block, false); err != nil {
				fmt.Println("Error saving keys:", err)
				return
			}

			privPath, err := filepath.Abs(*priv)
			if err != nil {
				fmt.Println("Error getting absolute path for private key:", err)
				os.Exit(1)
			}
			fmt.Printf("Private Key saved to: %s\n", privPath)

			pubPath, err := filepath.Abs(*pub)
			if err != nil {
				fmt.Println("Error getting absolute path for public key:", err)
				os.Exit(1)
			}
			fmt.Printf("Public Key saved to: %s\n", pubPath)

			fingerprint := calculateFingerprint(pk)
			fmt.Printf("Fingerprint: %s\n", fingerprint)

			var keySize string
			switch len(pk) {
			case 1312:
				keySize = "2048-bit"
			case 1952:
				keySize = "3072-bit"
			case 2592:
				keySize = "4096-bit"
			default:
				keySize = "unknown size"
			}

			fmt.Printf("ML-DSA (%s)\n", keySize)

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
		} else if *pkey == "sign" {
			sk, err := readKeyFromPEM(*key, true)
			if err != nil {
				fmt.Println("Error loading key:", err)
				os.Exit(1)
			}

			signature, err := Sign(sk, inputfile)
			if err != nil {
				fmt.Println("Error signing message:", err)
				os.Exit(1)
			}

			if err := SaveSignatureToPEM(signature, *sig); err != nil {
				fmt.Println("Error saving signature:", err)
				os.Exit(1)
			}
		} else if *pkey == "verify" {
			pk, err := readKeyFromPEM(*key, false)
			if err != nil {
				fmt.Println("Error loading key:", err)
				os.Exit(1)
			}

			msg, err := ioutil.ReadAll(inputfile)
			if err != nil {
				fmt.Println("Error reading message:", err)
				os.Exit(1)
			}

			err = Verify(pk, *sig, msg)
			if err != nil {
				fmt.Println("Error verifying signature:", err)
				os.Exit(1)
			}
			fmt.Println("Verified: true")
		} else if *pkey == "certgen" {
			pk, err := readKeyFromPEM(*pub, false)
			if err != nil {
				fmt.Println("Error loading key:", err)
				return
			}

			sk, err := readKeyFromPEM(*key, true)
			if err != nil {
				fmt.Println("Error loading key:", err)
				return
			}

			ca := NewCA(sk, pk, validity)

			subject := pkix.Name{
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

			certificate, err := ca.IssueCertificate(subject, email, pk, sk, true, validity)
			if err != nil {
				fmt.Println("Error issuing certificate:", err)
				return
			}

			err = SaveCertificateToPEM(certificate, *cert)
			if err != nil {
				fmt.Println("Error saving certificate:", err)
				return
			}

			fmt.Println("Certificate issued and saved successfully.")
			os.Exit(0)
		} else if *pkey == "check" && *crl == "" {
			pk, err := readKeyFromPEM(*key, false)
			if err != nil {
				fmt.Println("Error loading key:", err)
				return
			}
			certificate, err := ReadCertificateFromPEM(*cert)
			if err != nil {
				fmt.Println("Error reading the certificate:", err)
				return
			}

			err = VerifyCertificate(certificate, pk)
			if err != nil {
				fmt.Println("Verified: false", err)
				os.Exit(1)
			} else {
				fmt.Println("Verified: true")
				os.Exit(0)
			}
		} else if *pkey == "text" && *cert != "" {
			certificate, err := ReadCertificateFromPEM(*cert)
			if err != nil {
				csr, err := ReadCSRFromPEM(*cert)
				if err != nil {
					fmt.Println("Error loading certificate or CSR:", err)
					return
				}
				PrintInfo(csr)
			} else {
				PrintInfo(certificate)
			}
			os.Exit(0)
		} else if *pkey == "req" {
			caPrivateKey, err := readKeyFromPEM(*key, true)
			if err != nil {
				fmt.Println("Error loading key:", err)
				return
			}

			subject := pkix.Name{
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

			publicKey, err := readKeyFromPEM(*pub, false)
			if err != nil {
				fmt.Println("Error loading key:", err)
				return
			}

			csr, err := CreateCSR(subject, email, publicKey, caPrivateKey)
			if err != nil {
				log.Fatalf("Failed to create CSR: %v", err)
			}

			err = SaveCSRToPEM(csr, *cert)
			if err != nil {
				log.Fatalf("Failed to save CSR: %v", err)
			}

			fmt.Println("CSR created and saved to", *cert)
			os.Exit(0)
		} else if *pkey == "x509" {
			caPrivateKey, err := readKeyFromPEM(*key, true)
			if err != nil {
				fmt.Println("Error loading key:", err)
				return
			}

			caCert, err := ReadCertificateFromPEM(*root)
			if err != nil {
				log.Fatalf("Failed to read CA certificate: %v", err)
			}

			csr, err := ReadCSRFromPEM(*cert)
			if err != nil {
				log.Fatalf("Failed to read CSR: %v", err)
			}

			ca := &CA{
				PrivateKey:  caPrivateKey,
				Certificate: *caCert,
			}

			signedCert, err := SignCSR(csr, ca, caPrivateKey, validity)
			if err != nil {
				log.Fatalf("Failed to sign CSR: %v", err)
			}

			var outputFilename string
			if flag.Arg(0) == "" {
				outputFilename = "stdout"
			} else {
				outputFilename = flag.Arg(0)
			}

			err = SaveCertificateToPEM(signedCert, flag.Arg(0))
			if err != nil {
				log.Fatalf("Failed to save certificate: %v", err)
			}

			fmt.Fprintf(os.Stderr, "Certificate signed and saved to %s\n", outputFilename)
			os.Exit(0)
		} else if *pkey == "crl" {
			pk, err := readKeyFromPEM(*pub, false)
			if err != nil {
				fmt.Println("Error loading public key:", err)
				return
			}

			sk, err := readKeyFromPEM(*key, true)
			if err != nil {
				fmt.Println("Error loading private key:", err)
				return
			}

			cert, err := ReadCertificateFromPEM(*cert)
			if err != nil {
				log.Fatalf("Failed to read CA certificate: %v", err)
			}

			ca := NewCA(sk, pk, validity)

			crl, err := NewCRL(ca, *crl, validity)
			if err != nil {
				fmt.Println("Error generating CRL:", err)
				return
			}

			revokedSerials, err := readRevokedSerials(flag.Arg(0))
			if err != nil {
				fmt.Printf("Error reading revoked serial numbers: %v\n", err)
				return
			}

			for _, serial := range revokedSerials {
				crl.RevokeCertificate(serial)
			}

			if err := crl.Sign(ca, cert); err != nil {
				fmt.Printf("Error signing CRL: %v\n", err)
				return
			}

			var outputFile string
			if len(flag.Args()) > 0 {
				outputFile = flag.Arg(1)
			}

			if err := SaveCRLToPEM(crl, outputFile); err != nil {
				fmt.Printf("Error saving CRL: %v\n", err)
				return
			}

			fmt.Println("CRL generated and saved successfully.")
			os.Exit(0)
		} else if *pkey == "validate" {
			certToValidate, err := ReadCertificateFromPEM(*cert)
			if err != nil {
				fmt.Printf("Error reading certificate: %v\n", err)
				return
			}

			readCRL, err := ReadCRLFromPEM(*crl)
			if err != nil {
				fmt.Printf("Error reading CRL: %v\n", err)
				return
			}

			if readCRL.IsRevoked(certToValidate.SerialNumber) {
				fmt.Println("The certificate has been revoked")
				os.Exit(1)
			} else {
				fmt.Println("The certificate is not revoked")
				os.Exit(0)
			}
		} else if *pkey == "check" && *crl != "" {
			certificate, err := ReadCertificateFromPEM(*cert)
			if err != nil {
				fmt.Println("Error reading certificate:", err)
				return
			}

			crl, err := ReadCRLFromPEM(*crl)
			if err != nil {
				fmt.Printf("Error reading CRL: %v\n", err)
				os.Exit(1)
			}

			if err := CheckCRL(crl, certificate.PublicKey); err != nil {
				fmt.Println("Verified: false", err)
				os.Exit(3)
			}

			fmt.Println("Verified: true")
			os.Exit(0)
		}
	}

	if (strings.ToUpper(*alg) == "BLS12381" || strings.ToUpper(*alg) == "BLS12381SIGN" || strings.ToUpper(*alg) == "BLS12381ENCRYPT") && (*pkey == "setup" || *pkey == "setup-threshold" || *pkey == "keygen-threshold" || *pkey == "combine-threshold" || *pkey == "keygen" || *pkey == "sign" || *pkey == "verify" || *pkey == "proof" || *pkey == "verify-proof" || *pkey == "derive" || *pkey == "encrypt" || *pkey == "decrypt" || *pkey == "text" || *pkey == "fingerprint" || *pkey == "randomart") {
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

		if *pkey == "text" && *key != "" && (blockType == "BLS12381 PARTIAL SECRET KEY" || blockType == "THRESHOLD IBE SHARE") {
			keyBytes, err := readKeyFromPEM(*key, true)
			if err != nil {
				fmt.Println("Error loading key:", err)
				os.Exit(1)
			}

			keyPEM := pem.Block{Type: blockType, Bytes: keyBytes}
			fmt.Print(string(pem.EncodeToMemory(&keyPEM)))

			index := int(keyBytes[0])
			valueBytes := keyBytes[1:]

			fmt.Printf("Index: %d\n", index)

			switch blockType {
			case "THRESHOLD IBE SHARE":
				fmt.Println("ShareKey:")
			case "BLS12381 PARTIAL SECRET KEY":
				fmt.Println("Partial SecretKey:")
			}

			hexValue := fmt.Sprintf("%x", valueBytes)
			splitz := SplitSubN(hexValue, 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}

			fmt.Printf("Curve: %s\n", "BLS12381")
			os.Exit(0)
		}

		if *pkey == "text" && *key != "" && (blockType == "BLS12381 SECRET KEY" || blockType == "BLS12381SIGN SECRET KEY" || blockType == "BLS12381ENCRYPT SECRET KEY" || blockType == "BLS12381 MASTER KEY") {
			keyBytes, err := readKeyFromPEM(*key, true)
			if err != nil {
				fmt.Println("Error loading key:", err)
				os.Exit(1)
			}

			skScalar := new(ff.Scalar)
			skScalar.SetBytes(keyBytes)

			pubKey1 := new(bls12381.G1)
			pubKey1.ScalarMult(skScalar, bls12381.G1Generator())

			pubKey2 := new(bls12381.G2)
			pubKey2.ScalarMult(skScalar, bls12381.G2Generator())

			if blockType == "BLS12381 MASTER KEY" && len(keyBytes) >= 40 {
				keyPEM := pem.Block{Type: "BLS12381 MASTER KEY", Bytes: keyBytes}
				keyPEMText := string(pem.EncodeToMemory(&keyPEM))
				fmt.Print(keyPEMText)
				fmt.Println("MasterKey:")

				var masterASN MasterPrivateKeyASN
				if _, err := asn1.Unmarshal(keyBytes, &masterASN); err != nil {
					fmt.Println("Error decoding master key:", err)
					os.Exit(1)
				}

				s := new(ff.Scalar)
				if err := s.UnmarshalBinary(masterASN.S); err != nil {
					fmt.Println("Error decoding s:", err)
					os.Exit(1)
				}
				sBytes, err := s.MarshalBinary()
				if err != nil {
					fmt.Println("Error encoding s:", err)
					os.Exit(1)
				}

				x := new(ff.Scalar)
				if err := x.UnmarshalBinary(masterASN.X); err != nil {
					fmt.Println("Error decoding x:", err)
					os.Exit(1)
				}
				xBytes, err := x.MarshalBinary()
				if err != nil {
					fmt.Println("Error encoding x:", err)
					os.Exit(1)
				}

				Ppubs := new(bls12381.G2)
				if err := Ppubs.SetBytes(masterASN.Ppubs); err != nil {
					fmt.Println("Error decoding Ppubs:", err)
					os.Exit(1)
				}
				PpubsBytes := Ppubs.Bytes()

				v := new(bls12381.Gt)
				if err := v.UnmarshalBinary(masterASN.V); err != nil {
					fmt.Println("Error decoding v:", err)
					os.Exit(1)
				}
				vBytes, err := v.MarshalBinary()
				if err != nil {
					fmt.Println("Error encoding v:", err)
					os.Exit(1)
				}

				fmt.Println("Component s:")
				sHex := fmt.Sprintf("%x", sBytes)
				sSplit := SplitSubN(sHex, 2)
				for _, chunk := range split(strings.Trim(fmt.Sprint(sSplit), "[]"), 45) {
					fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
				}

				fmt.Println("Component x:")
				xHex := fmt.Sprintf("%x", xBytes)
				xSplit := SplitSubN(xHex, 2)
				for _, chunk := range split(strings.Trim(fmt.Sprint(xSplit), "[]"), 45) {
					fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
				}

				fmt.Println("Component Ppubs:")
				ppubsHex := fmt.Sprintf("%x", PpubsBytes)
				ppubsSplit := SplitSubN(ppubsHex, 2)
				for _, chunk := range split(strings.Trim(fmt.Sprint(ppubsSplit), "[]"), 45) {
					fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
				}

				fmt.Println("Component v:")
				vHex := fmt.Sprintf("%x", vBytes)
				vSplit := SplitSubN(vHex, 2)
				for _, chunk := range split(strings.Trim(fmt.Sprint(vSplit), "[]"), 45) {
					fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
				}

				fmt.Printf("Curve: %s\n", "BLS12381")
				os.Exit(0)
			}

			if blockType == "BLS12381 MASTER KEY" {
				keyPEM := pem.Block{Type: "BLS12381 MASTER KEY", Bytes: keyBytes}
				keyPEMText := string(pem.EncodeToMemory(&keyPEM))
				fmt.Print(keyPEMText)
				fmt.Println("MasterKey:")
				p := fmt.Sprintf("%x", keyBytes)
				splitz := SplitSubN(p, 2)
				for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
					fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
				}
				fmt.Println("PublicKeyG1:")
				p = fmt.Sprintf("%x", pubKey1.BytesCompressed())
				splitz = SplitSubN(p, 2)
				for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
					fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
				}
				fmt.Println("PublicKeyG2:")
				p = fmt.Sprintf("%x", pubKey2.BytesCompressed())
				splitz = SplitSubN(p, 2)
				for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
					fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
				}
			} else if blockType == "BLS12381 SECRET KEY" {
				var privASN UserPrivateKeyASN
				var privGG PrivateKeyGG
				if _, err := asn1.Unmarshal(keyBytes, &privASN); err == nil {
					keyPEM := pem.Block{Type: "BLS12381 SECRET KEY", Bytes: keyBytes}
					keyPEMText := string(pem.EncodeToMemory(&keyPEM))
					fmt.Print(keyPEMText)
					fmt.Println("SecretKey:")

					r := new(ff.Scalar)
					if err := r.UnmarshalBinary(privASN.R); err != nil {
						fmt.Println("Error decoding r:", err)
						os.Exit(1)
					}

					Did := new(bls12381.G2)
					if err := Did.SetBytes(privASN.Did); err != nil {
						fmt.Println("Error decoding Did:", err)
						os.Exit(1)
					}

					rBytes, err := r.MarshalBinary()
					if err != nil {
						fmt.Println("Error encoding r:", err)
						os.Exit(1)
					}

					didBytes := Did.BytesCompressed()

					fmt.Println("Component r:")
					rHex := fmt.Sprintf("%x", rBytes)
					rSplit := SplitSubN(rHex, 2)
					for _, chunk := range split(strings.Trim(fmt.Sprint(rSplit), "[]"), 45) {
						fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
					}

					fmt.Println("Component Did:")
					didHex := fmt.Sprintf("%x", didBytes)
					didSplit := SplitSubN(didHex, 2)
					for _, chunk := range split(strings.Trim(fmt.Sprint(didSplit), "[]"), 45) {
						fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
					}

					fmt.Println("Component v:")
					vHex := fmt.Sprintf("%x", privASN.V)
					vSplit := SplitSubN(vHex, 2)
					for _, chunk := range split(strings.Trim(fmt.Sprint(vSplit), "[]"), 45) {
						fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
					}
				} else if _, err := asn1.Unmarshal(keyBytes, &privGG); err == nil {
					keyPEM := pem.Block{Type: "BLS12381 SECRET KEY", Bytes: keyBytes}
					keyPEMText := string(pem.EncodeToMemory(&keyPEM))
					fmt.Print(keyPEMText)
					fmt.Println("SecretKey:")

					y := new(ff.Scalar)
					if err := y.UnmarshalBinary(privGG.Y); err != nil {
						fmt.Println("Error decoding y:", err)
						os.Exit(1)
					}

					gr := new(bls12381.G1)
					if err := gr.SetBytes(privGG.Gr); err != nil {
						fmt.Println("Error decoding gr:", err)
						os.Exit(1)
					}

					fmt.Println("Component y:")
					yHex := fmt.Sprintf("%x", privGG.Y)
					ySplit := SplitSubN(yHex, 2)
					for _, chunk := range split(strings.Trim(fmt.Sprint(ySplit), "[]"), 45) {
						fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
					}

					fmt.Println("Component gr:")
					grHex := fmt.Sprintf("%x", privGG.Gr)
					grSplit := SplitSubN(grHex, 2)
					for _, chunk := range split(strings.Trim(fmt.Sprint(grSplit), "[]"), 45) {
						fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
					}
				} else {
					keyPEM := pem.Block{Type: "BLS12381 SECRET KEY", Bytes: keyBytes}
					keyPEMText := string(pem.EncodeToMemory(&keyPEM))
					fmt.Print(keyPEMText)
					fmt.Println("SecretKey:")
					p := fmt.Sprintf("%x", keyBytes)
					splitz := SplitSubN(p, 2)
					for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
						fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
					}
				}
			} else if blockType == "BLS12381SIGN SECRET KEY" {
				var privGG PrivateKeyGG
				if _, err := asn1.Unmarshal(keyBytes, &privGG); err == nil {
					keyPEM := pem.Block{Type: "BLS12381SIGN SECRET KEY", Bytes: keyBytes}
					keyPEMText := string(pem.EncodeToMemory(&keyPEM))
					fmt.Print(keyPEMText)
					fmt.Println("SecretKey:")

					y := new(ff.Scalar)
					if err := y.UnmarshalBinary(privGG.Y); err != nil {
						fmt.Println("Error decoding y:", err)
						os.Exit(1)
					}

					gr := new(bls12381.G1)
					if err := gr.SetBytes(privGG.Gr); err != nil {
						fmt.Println("Error decoding gr:", err)
						os.Exit(1)
					}

					fmt.Println("Component y:")
					yHex := fmt.Sprintf("%x", privGG.Y)
					ySplit := SplitSubN(yHex, 2)
					for _, chunk := range split(strings.Trim(fmt.Sprint(ySplit), "[]"), 45) {
						fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
					}

					fmt.Println("Component gr:")
					grHex := fmt.Sprintf("%x", privGG.Gr)
					grSplit := SplitSubN(grHex, 2)
					for _, chunk := range split(strings.Trim(fmt.Sprint(grSplit), "[]"), 45) {
						fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
					}
				} else {
					keyPEM := pem.Block{Type: "BLS12381SIGN SECRET KEY", Bytes: keyBytes}
					keyPEMText := string(pem.EncodeToMemory(&keyPEM))
					fmt.Print(keyPEMText)
					fmt.Println("SecretKey:")
					p := fmt.Sprintf("%x", keyBytes)
					splitz := SplitSubN(p, 2)
					for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
						fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
					}
				}
			} else if blockType == "BLS12381ENCRYPT SECRET KEY" {
				keyPEM := pem.Block{Type: "BLS12381ENCRYPT SECRET KEY", Bytes: keyBytes}
				keyPEMText := string(pem.EncodeToMemory(&keyPEM))
				fmt.Print(keyPEMText)
				fmt.Println("SecretKey:")
				p := fmt.Sprintf("%x", keyBytes)
				splitz := SplitSubN(p, 2)
				for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
					fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
				}
			}

			fmt.Printf("Curve: %s\n", "BLS12381")

			os.Exit(0)
		} else if *pkey == "text" && *key != "" && (blockType == "BLS12381 PUBLIC KEY") {
			keyBytes, err := readKeyFromPEM(*key, false)
			if err != nil {
				fmt.Println("Error reading key from PEM:", err)
				os.Exit(1)
			}
			keyPEM := pem.Block{Type: "BLS12381 PUBLIC KEY", Bytes: keyBytes}
			keyPEMText := string(pem.EncodeToMemory(&keyPEM))
			fmt.Print(keyPEMText)

			if len(keyBytes) > 96 {
				fmt.Println("PublicKey:")

				var pubASN MasterPublicKeyASN
				if _, err := asn1.Unmarshal(keyBytes, &pubASN); err != nil {
					fmt.Println("Error decoding public key:", err)
					os.Exit(1)
				}

				fmt.Println("Component Ppub:")
				ppubHex := fmt.Sprintf("%x", pubASN.Ppub)
				ppubSplit := SplitSubN(ppubHex, 2)
				for _, chunk := range split(strings.Trim(fmt.Sprint(ppubSplit), "[]"), 45) {
					fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
				}

				fmt.Println("Component Q:")
				qHex := fmt.Sprintf("%x", pubASN.Q)
				qSplit := SplitSubN(qHex, 2)
				for _, chunk := range split(strings.Trim(fmt.Sprint(qSplit), "[]"), 45) {
					fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
				}

				fmt.Println("Component v:")
				vHex := fmt.Sprintf("%x", pubASN.V)
				vSplit := SplitSubN(vHex, 2)
				for _, chunk := range split(strings.Trim(fmt.Sprint(vSplit), "[]"), 45) {
					fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
				}

				fmt.Printf("Curve: %s\n", "BLS12381")
				skid := sha3.Sum256(keyBytes)
				fmt.Printf("\nKeyID: %x \n", skid[:20])
				os.Exit(0)

			} else {
				fmt.Println("PublicKey:")
				p := fmt.Sprintf("%x", keyBytes)
				splitz := SplitSubN(p, 2)
				for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
					fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
				}

				fmt.Printf("Curve: %s\n", "BLS12381")
				skid := sha3.Sum256(keyBytes)
				fmt.Printf("\nKeyID: %x \n", skid[:20])
				os.Exit(0)
			}
		} else if *pkey == "fingerprint" && *key != "" {
			keyBytes, err := readKeyFromPEM(*key, true)
			if err != nil {
				fmt.Println("Error reading key from PEM:", err)
				os.Exit(1)
			}
			fingerprint := calculateFingerprint(keyBytes)
			fmt.Printf("Fingerprint: %s\n", fingerprint)
			os.Exit(0)
		}

		if *pkey == "randomart" && *key != "" {
			pubFile, err := os.Open(*key)
			if err != nil {
				fmt.Println("Error opening public key file:", err)
				os.Exit(1)
			}
			defer pubFile.Close()

			fmt.Println("BLS12 381-bit")

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
		if *pkey == "setup" && (strings.ToUpper(*scheme) == "BB" || strings.ToUpper(*scheme) == "BONEH-BOYEN") {
			var s, x *ff.Scalar
			var Ppubs *bls12381.G2
			var v *bls12381.Gt

			if *key != "" {
				data, err := os.ReadFile(*key)
				if err != nil {
					fmt.Println("Error reading master key file:", err)
					return
				}

				s, x, Ppubs, v, err = DeserializeMasterPrivateKey(data)
				if err != nil {
					fmt.Println("Error decoding master key:", err)
					return
				}
				fmt.Println("Using provided master key.")
			} else {
				s = new(ff.Scalar)
				s.Random(rand.Reader)

				x = new(ff.Scalar)
				x.Random(rand.Reader)

				Ppubs = new(bls12381.G2)
				Ppubs.ScalarMult(x, bls12381.G2Generator())

				v = bls12381.Pair(bls12381.G1Generator(), Ppubs)

				masterPrivData, err := SerializeMasterPrivateKey(s, x, Ppubs, v)
				if err != nil {
					fmt.Println("Error serializing master key:", err)
					return
				}

				privBlock := &pem.Block{
					Type:  "BLS12381 MASTER KEY",
					Bytes: masterPrivData,
				}

				if err := savePEMToFile(*master, privBlock, true); err != nil {
					fmt.Println("Error saving master private key PEM:", err)
					return
				}

				privPath, err := filepath.Abs(*master)
				if err != nil {
					fmt.Println("Error getting absolute path:", err)
					return
				}
				fmt.Printf("Master Key saved to: %s\n", privPath)
			}

			Ppub := new(bls12381.G1)
			Ppub.ScalarMult(s, bls12381.G1Generator())

			Q := new(bls12381.G1)
			Q.ScalarMult(x, bls12381.G1Generator())

			masterPubData, err := SerializeMasterPublicKey(Ppub, Q, v)
			if err != nil {
				fmt.Println("Error serializing master public key:", err)
				return
			}

			pubBlock := &pem.Block{
				Type:  "BLS12381 PUBLIC KEY",
				Bytes: masterPubData,
			}

			if err := savePEMToFile(*pub, pubBlock, false); err != nil {
				fmt.Println("Error saving master public key PEM:", err)
				return
			}

			pubPath, err := filepath.Abs(*pub)
			if err != nil {
				fmt.Println("Error getting absolute path:", err)
				return
			}
			fmt.Printf("Public Key saved to: %s\n", pubPath)

			keyBytes, err := readKeyFromPEM(*pub, false)
			if err != nil {
				fmt.Println("Error reading key from PEM:", err)
				os.Exit(1)
			}
			fingerprint := calculateFingerprint(keyBytes)
			fmt.Printf("Fingerprint: %s\n", fingerprint)

			fmt.Println("BLS12-381")
			pubFile, err := os.Open(*pub)
			if err != nil {
				fmt.Println("Error opening public key PEM file:", err)
				os.Exit(1)
			}
			defer pubFile.Close()

			pubInfo, err := pubFile.Stat()
			if err != nil {
				fmt.Println("Error getting public key file info:", err)
				os.Exit(1)
			}

			pubBuf := make([]byte, pubInfo.Size())
			if _, err := pubFile.Read(pubBuf); err != nil {
				fmt.Println("Error reading public key PEM file:", err)
				os.Exit(1)
			}

			randomArt := randomart.FromString(string(pubBuf))
			fmt.Println(randomArt)

			os.Exit(0)
		}

		if *pkey == "setup" && (strings.ToUpper(*scheme) == "SK" || strings.ToUpper(*scheme) == "SAKAI-KASAHARA") {
			var s *ff.Scalar
			var Ppub *bls12381.G1

			if *key != "" {
				data, err := readKeyFromPEM(*key, true)
				if err != nil {
					fmt.Println("Error reading master key file:", err)
					return
				}

				if len(data) < 32 {
					fmt.Println("Invalid master key length")
					return
				}

				s = new(ff.Scalar)
				s.SetBytes(data[:32])

				fmt.Println("Using provided SK master key.")

				Ppub = new(bls12381.G1)
				Ppub.ScalarMult(s, bls12381.G1Generator())

				privBlock := &pem.Block{
					Type:  "BLS12381 MASTER KEY",
					Bytes: data,
				}

				if err := savePEMToFile2(*master, privBlock, true); err != nil {
					fmt.Println("Error saving SK private key PEM:", err)
					return
				}

				pubBlock := &pem.Block{
					Type:  "BLS12381 PUBLIC KEY",
					Bytes: Ppub.BytesCompressed(),
				}

				if err := savePEMToFile(*pub, pubBlock, false); err != nil {
					fmt.Println("Error saving SK public key PEM:", err)
					return
				}

				privPath, _ := filepath.Abs(*master)
				pubPath, _ := filepath.Abs(*pub)
				fmt.Printf("Master Key saved to: %s\n", privPath)
				fmt.Printf("Public Key saved to: %s\n", pubPath)
			} else {
				s = new(ff.Scalar)
				s.Random(rand.Reader)

				Ppub = new(bls12381.G1)
				Ppub.ScalarMult(s, bls12381.G1Generator())

				sBytes, _ := s.MarshalBinary()

				privBlock := &pem.Block{
					Type:  "BLS12381 MASTER KEY",
					Bytes: sBytes,
				}

				if err := savePEMToFile(*master, privBlock, true); err != nil {
					fmt.Println("Error saving SK private key PEM:", err)
					return
				}

				pubBlock := &pem.Block{
					Type:  "BLS12381 PUBLIC KEY",
					Bytes: Ppub.BytesCompressed(),
				}

				if err := savePEMToFile(*pub, pubBlock, false); err != nil {
					fmt.Println("Error saving SK public key PEM:", err)
					return
				}

				privPath, _ := filepath.Abs(*master)
				pubPath, _ := filepath.Abs(*pub)
				fmt.Printf("Master Key saved to: %s\n", privPath)
				fmt.Printf("Public Key saved to: %s\n", pubPath)
			}

			keyBytes, err := readKeyFromPEM(*pub, false)
			if err != nil {
				fmt.Println("Error reading SK public key from PEM:", err)
				os.Exit(1)
			}
			fingerprint := calculateFingerprint(keyBytes)
			fmt.Printf("SK fingerprint: %s\n", fingerprint)

			fmt.Println("BLS12-381 SK")
			pubFile, err := os.Open(*pub)
			if err != nil {
				fmt.Println("Error opening SK public key PEM file:", err)
				os.Exit(1)
			}
			defer pubFile.Close()

			pubInfo, err := pubFile.Stat()
			if err != nil {
				fmt.Println("Error getting SK public key file info:", err)
				os.Exit(1)
			}

			pubBuf := make([]byte, pubInfo.Size())
			if _, err := pubFile.Read(pubBuf); err != nil {
				fmt.Println("Error reading SK public key PEM file:", err)
				os.Exit(1)
			}

			randomArt := randomart.FromString(string(pubBuf))
			fmt.Println(randomArt)

			os.Exit(0)
		}

		if *pkey == "setup" && (strings.ToUpper(*scheme) == "GG" || strings.ToUpper(*scheme) == "GALINDO-GARCIA") {
			var z *ff.Scalar
			var mpk *bls12381.G1

			if *key != "" {
				data, err := readKeyFromPEM(*key, true)
				if err != nil {
					fmt.Println("Error reading GG master key file:", err)
					return
				}

				if len(data) < 32 {
					fmt.Println("Invalid GG master key length")
					return
				}

				z = new(ff.Scalar)
				z.SetBytes(data[:32])

				mpk = new(bls12381.G1)
				if err := mpk.SetBytes(data[32:]); err != nil {
					fmt.Println("Error decoding GG public key:", err)
					return
				}

				fmt.Println("Using provided GG master key.")
			} else {
				z = new(ff.Scalar)
				z.Random(rand.Reader)

				mpk = new(bls12381.G1)
				mpk.ScalarMult(z, bls12381.G1Generator())
			}

			zBytes, _ := z.MarshalBinary()

			privBlock := &pem.Block{
				Type:  "BLS12381 MASTER KEY",
				Bytes: zBytes,
			}

			if err := savePEMToFile(*master, privBlock, true); err != nil {
				fmt.Println("Error saving GG private key PEM:", err)
				return
			}

			pubBlock := &pem.Block{
				Type:  "BLS12381 PUBLIC KEY",
				Bytes: mpk.BytesCompressed(),
			}

			if err := savePEMToFile(*pub, pubBlock, false); err != nil {
				fmt.Println("Error saving GG public key PEM:", err)
				return
			}

			privPath, _ := filepath.Abs(*master)
			pubPath, _ := filepath.Abs(*pub)
			fmt.Printf("Master Key saved to: %s\n", privPath)
			fmt.Printf("Public Key saved to: %s\n", pubPath)

			keyBytes, err := readKeyFromPEM(*pub, false)
			if err != nil {
				fmt.Println("Error reading GG public key from PEM:", err)
				os.Exit(1)
			}
			fingerprint := calculateFingerprint(keyBytes)
			fmt.Printf("Fingerprint: %s\n", fingerprint)

			fmt.Println("BLS12-381 GG")
			pubFile, err := os.Open(*pub)
			if err != nil {
				fmt.Println("Error opening GG public key PEM file:", err)
				os.Exit(1)
			}
			defer pubFile.Close()

			pubInfo, err := pubFile.Stat()
			if err != nil {
				fmt.Println("Error getting GG public key file info:", err)
				os.Exit(1)
			}

			pubBuf := make([]byte, pubInfo.Size())
			if _, err := pubFile.Read(pubBuf); err != nil {
				fmt.Println("Error reading GG public key PEM file:", err)
				os.Exit(1)
			}

			randomArt := randomart.FromString(string(pubBuf))
			fmt.Println(randomArt)

			os.Exit(0)
		}

		if *pkey == "setup" {
			var ikm []byte
			var err error

			if *key != "" {
				ikm, err = readKeyFromPEM(*key, true)
				if err != nil {
					fmt.Println("Error reading the master key:", err)
					return
				}
				fmt.Println("Using provided master key.")

				block := &pem.Block{
					Type:  "BLS12381 MASTER KEY",
					Bytes: ikm,
				}
				if err := savePEMToFile2(*master, block, true); err != nil {
					fmt.Println("Error saving master key:", err)
					return
				}

				privPath, _ := filepath.Abs(*master)
				fmt.Printf("Master Key saved to: %s\n", privPath)
			} else {
				ikm = make([]byte, 32)
				_, err = rand.Read(ikm)
				if err != nil {
					log.Fatal("Error generating master key:", err)
				}

				block := &pem.Block{
					Type:  "BLS12381 MASTER KEY",
					Bytes: ikm,
				}
				if err := savePEMToFile(*master, block, true); err != nil {
					fmt.Println("Error saving master key:", err)
					return
				}

				privPath, _ := filepath.Abs(*master)
				fmt.Printf("Master Key saved to: %s\n", privPath)
			}

			skScalar := new(ff.Scalar)
			skScalar.SetBytes(ikm)

			if *pub2 != "" {
				pkG1 := new(bls12381.G1)
				pkG1.ScalarMult(skScalar, bls12381.G1Generator())

				pkG2 := new(bls12381.G2)
				pkG2.ScalarMult(skScalar, bls12381.G2Generator())

				blockG1 := &pem.Block{
					Type:  "BLS12381 PUBLIC KEY",
					Bytes: pkG1.BytesCompressed(),
				}
				if err := savePEMToFile(*pub, blockG1, false); err != nil {
					fmt.Println("Error saving G1 public key:", err)
					return
				}

				pub1Path, _ := filepath.Abs(*pub)
				pub2Path, _ := filepath.Abs(*pub2)
				fmt.Printf("Public Key saved to: %s\n", pub1Path)
				fmt.Printf("Public Key saved to: %s\n", pub2Path)
				fmt.Printf("Fingerprint (G1): %s\n", calculateFingerprint(pkG1.BytesCompressed()))
				fmt.Printf("Fingerprint (G2): %s\n", calculateFingerprint(pkG2.BytesCompressed()))

				fmt.Println("BLS12-381 G1")
				pubFile, err := os.Open(*pub)
				if err != nil {
					fmt.Println("Error opening G1 public key file:", err)
					os.Exit(1)
				}
				defer pubFile.Close()

				pubInfo, _ := pubFile.Stat()
				pubBuf := make([]byte, pubInfo.Size())
				pubFile.Read(pubBuf)
				randomArt := randomart.FromString(string(pubBuf))
				fmt.Println(randomArt)

				blockG2 := &pem.Block{
					Type:  "BLS12381 PUBLIC KEY",
					Bytes: pkG2.BytesCompressed(),
				}
				if err := savePEMToFile(*pub2, blockG2, false); err != nil {
					fmt.Println("Error saving G2 public key:", err)
					return
				}

				fmt.Println("BLS12-381 G2")
				pubFile2, err := os.Open(*pub2)
				if err != nil {
					fmt.Println("Error opening G2 public key file:", err)
					os.Exit(1)
				}
				defer pubFile2.Close()

				pubInfo2, _ := pubFile2.Stat()
				pubBuf2 := make([]byte, pubInfo2.Size())
				pubFile2.Read(pubBuf2)
				randomArt2 := randomart.FromString(string(pubBuf2))
				fmt.Println(randomArt2)

			} else {
				pk := new(bls12381.G2)
				pk.ScalarMult(skScalar, bls12381.G2Generator())

				block := &pem.Block{
					Type:  "BLS12381 PUBLIC KEY",
					Bytes: pk.BytesCompressed(),
				}
				if err := savePEMToFile(*pub, block, false); err != nil {
					fmt.Println("Error saving public key:", err)
					return
				}

				pubPath, _ := filepath.Abs(*pub)
				fmt.Printf("Public Key saved to: %s\n", pubPath)
				fmt.Printf("Fingerprint: %s\n", calculateFingerprint(pk.BytesCompressed()))

				fmt.Println("BLS12-381 G2")
				pubFile, err := os.Open(*pub)
				if err != nil {
					fmt.Println("Error opening public key file:", err)
					os.Exit(1)
				}
				defer pubFile.Close()

				pubInfo, _ := pubFile.Stat()
				pubBuf := make([]byte, pubInfo.Size())
				pubFile.Read(pubBuf)
				randomArt := randomart.FromString(string(pubBuf))
				fmt.Println(randomArt)
			}
		}

		if *pkey == "setup-threshold" {
			var ikm []byte
			var err error

			if *key != "" {
				ikm, err = readKeyFromPEM(*key, true)
				if err != nil {
					fmt.Println("Error reading the master key:", err)
					return
				}
				fmt.Println("Using provided master key.")
			} else {
				ikm = make([]byte, 32)
				_, err = rand.Read(ikm)
				if err != nil {
					log.Fatal("Error generating master key:", err)
				}
			}

			msk := new(ff.Scalar)
			msk.SetBytes(ikm)

			t, n := 2, 5
			shares, err := GenerateShares(msk, t, n)
			if err != nil {
				fmt.Println("Error generating shares:", err)
				return
			}

			basePath := strings.TrimSuffix(*master, filepath.Ext(*master))
			for i, share := range shares {
				filename := fmt.Sprintf("%s_%02d.pem", basePath, i+1)

				absPath, err := filepath.Abs(filename)
				if err != nil {
					fmt.Printf("Error getting the absolute path of %s: %v\n", filename, err)
				}

				err = SaveShareToPEM(filename, share)
				if err != nil {
					fmt.Printf("Error saving share %d: %v\n", i+1, err)
					continue
				}

				fmt.Printf("Share %d saved to: %s\n", i+1, absPath)
			}

			P_pub := new(bls12381.G2)
			P_pub.ScalarMult(msk, bls12381.G2Generator())

			block := &pem.Block{
				Type:  "BLS12381 PUBLIC KEY",
				Bytes: P_pub.BytesCompressed(),
			}

			if err := savePEMToFile(*pub, block, false); err != nil {
				fmt.Println("Error saving public key:", err)
				return
			}

			pubPath, _ := filepath.Abs(*pub)
			fmt.Printf("Public Key saved to: %s\n", pubPath)
			fmt.Printf("Fingerprint: %s\n", calculateFingerprint(P_pub.BytesCompressed()))

			fmt.Println("BLS12-381 G2")
			pubFile, err := os.Open(*pub)
			if err != nil {
				fmt.Println("Error opening public key file:", err)
				os.Exit(1)
			}
			defer pubFile.Close()

			pubInfo, _ := pubFile.Stat()
			pubBuf := make([]byte, pubInfo.Size())
			pubFile.Read(pubBuf)
			randomArt := randomart.FromString(string(pubBuf))
			fmt.Println(randomArt)
		}

		if *pkey == "keygen-threshold" {
			fmt.Printf("Extracting partial key for identity: %s\n", *id)
			fmt.Printf("Using share: %s\n", *key)

			partialKey, err := partialExtractFromShare(*key, append([]byte(*id), byte(*hierarchy)))
			if err != nil {
				fmt.Printf("Error extracting partial key: %v\n", err)
				os.Exit(1)
			}

			share, err := LoadShareFromPEM(*key)
			if err != nil {
				fmt.Printf("Error getting share index: %v\n", err)
				os.Exit(1)
			}

			baseName := strings.TrimSuffix(filepath.Base(*priv), ".pem")
			partialKeyFile := fmt.Sprintf("partial_key_%s_%02d.pem", baseName, share.Index)

			keyData := append([]byte{byte(share.Index)}, partialKey.BytesCompressed()...)

			block := &pem.Block{
				Type:  "BLS12381 PARTIAL SECRET KEY",
				Bytes: keyData,
			}

			if err := savePEMToFile(partialKeyFile, block, false); err != nil {
				fmt.Printf("Error saving partial key: %v\n", err)
				os.Exit(1)
			}

			fmt.Printf("Partial key successfully extracted and saved to: %s\n", partialKeyFile)
			fmt.Printf("Share index: %d\n", share.Index)
			os.Exit(0)
		}

		if *pkey == "combine-threshold" {
			partialKeys := make([]PartialKey, len(keys))
			for i, filename := range keys {
				partialKey, index, err := loadPartialKeyFromPEM(filename)
				if err != nil {
					fmt.Printf("Error loading partial key %s: %v\n", filename, err)
					os.Exit(1)
				}
				partialKeys[i] = PartialKey{Index: index, Key: partialKey}
				fmt.Printf("Loaded partial key from %s (index: %d)\n", filename, index)
			}

			if len(partialKeys) < 2 {
				fmt.Printf("Error: Need at least 2 partial keys, got %d\n", len(partialKeys))
				os.Exit(1)
			}

			fmt.Printf("Combining %d partial keys...\n", len(partialKeys))

			fullKey, err := combinePartialKeys(partialKeys)
			if err != nil {
				fmt.Printf("Error combining keys: %v\n", err)
				os.Exit(1)
			}

			block := &pem.Block{
				Type:  "BLS12381 SECRET KEY",
				Bytes: fullKey.BytesCompressed(),
			}

			if err := savePEMToFile(*priv, block, true); err != nil {
				fmt.Printf("Error saving private key: %v\n", err)
				os.Exit(1)
			}

			fmt.Printf("Full private key successfully combined and saved to: %s\n", *priv)
			fmt.Printf("Key fingerprint: %s\n", calculateFingerprint(fullKey.BytesCompressed()))
			os.Exit(0)
		}

		if *pkey == "keygen" && strings.ToUpper(*alg) == "BLS12381" && (strings.ToUpper(*scheme) == "BB" || strings.ToUpper(*scheme) == "BONEH-BOYEN") {
			masterPrivData, err := readKeyFromPEM(*master, true)
			if err != nil {
				fmt.Println("Error loading key:", err)
				os.Exit(1)
			}

			s, x, Ppubs, v, err := DeserializeMasterPrivateKey(masterPrivData)
			if err != nil {
				fmt.Println("Error decoding master key:", err)
				os.Exit(1)
			}

			if *id == "" {
				fmt.Println("Error: user ID is required (use -id flag)")
				os.Exit(1)
			}

			r, Did := Extract(string(append([]byte(*id), byte(*hierarchy))), s, x, Ppubs)

			userPrivData, err := SerializeUserPrivateKey(r, Did, v)
			if err != nil {
				fmt.Println("Error serializing user private key:", err)
				os.Exit(1)
			}

			block := &pem.Block{
				Type:  "BLS12381 SECRET KEY",
				Bytes: userPrivData,
			}

			if err := savePEMToFile2(*priv, block, true); err != nil {
				fmt.Println("Error saving private key:", err)
				return
			}

			privPath, err := filepath.Abs(*priv)
			if err != nil {
				fmt.Println("Error getting absolute path for private key:", err)
				return
			}
			fmt.Printf("Private Key saved to: %s\n", privPath)
			os.Exit(0)
		}

		if *pkey == "keygen" && strings.ToUpper(*alg) == "BLS12381" && (strings.ToUpper(*scheme) == "SK" || strings.ToUpper(*scheme) == "SAKAI-KASAHARA") {
			sk, err := readKeyFromPEM(*master, true)
			if err != nil {
				fmt.Println("Error loading key:", err)
				os.Exit(1)
			}

			skScalar := new(ff.Scalar)
			skScalar.SetBytes(sk)

			privateKey := extractSK(skScalar, append([]byte(*id), byte(*hierarchy)))
			privateKeyBytes := privateKey.BytesCompressed()

			block := &pem.Block{
				Type:  "BLS12381 SECRET KEY",
				Bytes: privateKeyBytes,
			}

			if err := savePEMToFile2(*priv, block, true); err != nil {
				fmt.Println("Error saving private key:", err)
				return
			}

			privPath, err := filepath.Abs(*priv)
			if err != nil {
				fmt.Println("Error getting absolute path for private key:", err)
				return
			}
			fmt.Printf("Private Key saved to: %s\n", privPath)
			os.Exit(0)
		}

		if *pkey == "keygen" && strings.ToUpper(*alg) == "BLS12381" && (strings.ToUpper(*scheme) == "GG" || strings.ToUpper(*scheme) == "GALINDO-GARCIA") {
			sk, err := readKeyFromPEM(*master, true)
			if err != nil {
				fmt.Println("Error loading GG master key:", err)
				os.Exit(1)
			}

			skScalar := new(ff.Scalar)
			skScalar.SetBytes(sk)

			y, gr := extractGG(skScalar, append([]byte(*id), byte(*hierarchy)))

			privBytes, err := encodePrivateKeyGG(y, gr)
			if err != nil {
				fmt.Println("Error encoding GG private key:", err)
				os.Exit(1)
			}

			block := &pem.Block{
				Type:  "BLS12381 SECRET KEY",
				Bytes: privBytes,
			}

			if err := savePEMToFile2(*priv, block, true); err != nil {
				fmt.Println("Error saving GG user secret key:", err)
				return
			}

			privPath, err := filepath.Abs(*priv)
			if err != nil {
				fmt.Println("Error getting path for GG private key:", err)
				return
			}
			fmt.Printf("Private Key saved to: %s\n", privPath)
			os.Exit(0)
		}

		if *pkey == "keygen" && strings.ToUpper(*alg) == "BLS12381" {
			sk, err := readKeyFromPEM(*master, true)
			if err != nil {
				fmt.Println("Error loading key:", err)
				os.Exit(1)
			}

			skScalar := new(ff.Scalar)
			skScalar.SetBytes(sk)

			var privateKeyBytes []byte
			if strings.ToUpper(*scheme) == "BF" || strings.ToUpper(*scheme) == "BONEH-FRANKLIN" || strings.ToUpper(*scheme) == "CC" || strings.ToUpper(*scheme) == "CHA-CHEON" || strings.ToUpper(*scheme) == "HESS" {
				privateKey := extract(skScalar, append([]byte(*id), byte(*hierarchy)))
				privateKeyBytes = privateKey.BytesCompressed()
			} else if strings.ToUpper(*scheme) == "SK" || strings.ToUpper(*scheme) == "SAKAI-KASAHARA" {
				privateKey := extractSK(skScalar, append([]byte(*id), byte(*hierarchy)))
				privateKeyBytes = privateKey.BytesCompressed()
			} else if strings.ToUpper(*scheme) == "BR" || strings.ToUpper(*scheme) == "BARRETO" {
				privateKey := extractBARRETO(skScalar, append([]byte(*id), byte(*hierarchy)))
				privateKeyBytes = privateKey.BytesCompressed()
			} else if strings.ToUpper(*scheme) == "SM" || strings.ToUpper(*scheme) == "SHANGMI" {
				privateKey := extractSM(skScalar, append([]byte(*id), byte(*hierarchy)))
				privateKeyBytes = privateKey.BytesCompressed()
			} else {
				privateKey := extract(skScalar, append([]byte(*id), byte(*hierarchy)))
				privateKeyBytes = privateKey.BytesCompressed()
			}

			block := &pem.Block{
				Type:  "BLS12381 SECRET KEY",
				Bytes: privateKeyBytes,
			}

			if err := savePEMToFile2(*priv, block, true); err != nil {
				fmt.Println("Error saving private key:", err)
				return
			}

			privPath, err := filepath.Abs(*priv)
			if err != nil {
				fmt.Println("Error getting absolute path for private key:", err)
				return
			}
			fmt.Printf("Private Key saved to: %s\n", privPath)
		} else if *pkey == "keygen" && strings.ToUpper(*alg) == "BLS12381ENCRYPT" {
			sk, err := readKeyFromPEM(*master, true)
			if err != nil {
				fmt.Println("Error loading key:", err)
				os.Exit(1)
			}

			skScalar := new(ff.Scalar)
			skScalar.SetBytes(sk)

			var privateKeyBytes []byte
			if strings.ToUpper(*scheme) == "BF" || strings.ToUpper(*scheme) == "BONEH-FRANKLIN" {
				privateKey := extract(skScalar, append([]byte(*id), byte(*hierarchy)))
				privateKeyBytes = privateKey.BytesCompressed()
			} else if strings.ToUpper(*scheme) == "SK" || strings.ToUpper(*scheme) == "SAKAI-KASAHARA" {
				privateKey := extractSK(skScalar, append([]byte(*id), byte(*hierarchy)))
				privateKeyBytes = privateKey.BytesCompressed()
			} else {
				privateKey := extract(skScalar, append([]byte(*id), byte(*hierarchy)))
				privateKeyBytes = privateKey.BytesCompressed()
			}

			block := &pem.Block{
				Type:  "BLS12381ENCRYPT SECRET KEY",
				Bytes: privateKeyBytes,
			}

			if err := savePEMToFile2(*priv, block, true); err != nil {
				fmt.Println("Error saving private key:", err)
				return
			}

			privPath, err := filepath.Abs(*priv)
			if err != nil {
				fmt.Println("Error getting absolute path for private key:", err)
				return
			}
			fmt.Printf("Private Key saved to: %s\n", privPath)
		} else if *pkey == "keygen" && strings.ToUpper(*alg) == "BLS12381SIGN" {
			sk, err := readKeyFromPEM(*master, true)
			if err != nil {
				fmt.Println("Error loading key:", err)
				os.Exit(1)
			}

			skScalar := new(ff.Scalar)
			skScalar.SetBytes(sk)

			var privateKeyBytes []byte
			if strings.ToUpper(*scheme) == "CC" || strings.ToUpper(*scheme) == "CHA-CHEON" || strings.ToUpper(*scheme) == "HESS" {
				privateKey := extract(skScalar, append([]byte(*id), byte(*hierarchy)))
				privateKeyBytes = privateKey.BytesCompressed()
			} else if strings.ToUpper(*scheme) == "SM" || strings.ToUpper(*scheme) == "SHANGMI" {
				privateKey := extractSM(skScalar, append([]byte(*id), byte(*hierarchy)))
				privateKeyBytes = privateKey.BytesCompressed()
			} else if strings.ToUpper(*scheme) == "BR" || strings.ToUpper(*scheme) == "BARRETO" {
				privateKey := extractBARRETO(skScalar, append([]byte(*id), byte(*hierarchy)))
				privateKeyBytes = privateKey.BytesCompressed()
			} else if strings.ToUpper(*scheme) == "GG" || strings.ToUpper(*scheme) == "GALINDO-GARCIA" {
				y, gr := extractGG(skScalar, append([]byte(*id), byte(*hierarchy)))
				privateKeyBytes, err = encodePrivateKeyGG(y, gr)
				if err != nil {
					fmt.Println("Error generating key:", err)
					os.Exit(1)
				}
			} else {
				privateKey := extract(skScalar, append([]byte(*id), byte(*hierarchy)))
				privateKeyBytes = privateKey.BytesCompressed()
			}

			block := &pem.Block{
				Type:  "BLS12381SIGN SECRET KEY",
				Bytes: privateKeyBytes,
			}

			if err := savePEMToFile2(*priv, block, true); err != nil {
				fmt.Println("Error saving private key:", err)
				return
			}

			privPath, err := filepath.Abs(*priv)
			if err != nil {
				fmt.Println("Error getting absolute path for private key:", err)
				return
			}
			fmt.Printf("Private Key saved to: %s\n", privPath)
		} else if *pkey == "sign" && (strings.ToUpper(*scheme) == "SM" || strings.ToUpper(*scheme) == "SHANGMI") {
			sk, err := readKeyFromPEM(*key, true)
			if err != nil {
				fmt.Println("Error loading key:", err)
				os.Exit(1)
			}
			skG1 := new(bls12381.G1)
			if err := skG1.SetBytes(sk); err != nil {
				fmt.Println("Error setting G1 bytes:", err)
				os.Exit(1)
			}

			msg, err := ioutil.ReadAll(inputfile)
			if err != nil {
				fmt.Println("Error getting input file:", err)
				os.Exit(1)
			}

			h, signature := signSM(skG1, msg)

			asn1Data, err := encodeSignature(h, signature)
			if err != nil {
				fmt.Println("Error serializing signature:", err)
				return
			}

			fmt.Println("BLS12381("+inputdesc+")=", hex.EncodeToString(asn1Data))
		} else if *pkey == "verify" && (strings.ToUpper(*scheme) == "SM" || strings.ToUpper(*scheme) == "SHANGMI") {
			pk, err := readKeyFromPEM(*key, false)
			if err != nil {
				fmt.Println("Error loading key:", err)
				os.Exit(1)
			}

			msg, err := ioutil.ReadAll(inputfile)
			if err != nil {
				fmt.Println("Error reading message:", err)
				os.Exit(1)
			}

			var pubKey bls12381.G2
			pubKey.SetBytes(pk)

			sigBytes, err := hex.DecodeString(*sig)
			if err != nil {
				fmt.Println("Error decoding signature:", err)
				os.Exit(1)
			}

			decodedH, decodedSig, err := decodeSignature(sigBytes)
			if err != nil {
				fmt.Println("Error deserializing signature:", err)
				return
			}

			if verifySM(&pubKey, append([]byte(*id), byte(*hierarchy)), msg, decodedH, decodedSig) {
				fmt.Println("Verified: true")
			} else {
				fmt.Println("Verified: false")
				os.Exit(1)
			}
			os.Exit(0)
		} else if *pkey == "sign" && (strings.ToUpper(*scheme) == "BR" || strings.ToUpper(*scheme) == "BARRETO") {
			sk, err := readKeyFromPEM(*key, true)
			if err != nil {
				fmt.Println("Error loading key:", err)
				os.Exit(1)
			}
			skG1 := new(bls12381.G1)
			if err := skG1.SetBytes(sk); err != nil {
				fmt.Println("Error setting G1 bytes:", err)
				os.Exit(1)
			}

			msg, err := ioutil.ReadAll(inputfile)
			if err != nil {
				fmt.Println("Error getting input file:", err)
				os.Exit(1)
			}

			h, signature := signBARRETO(skG1, msg)

			asn1Data, err := encodeSignatureBARRETO(h, signature)
			if err != nil {
				fmt.Println("Error serializing signature:", err)
				return
			}

			fmt.Println("BLS12381("+inputdesc+")=", hex.EncodeToString(asn1Data))
		} else if *pkey == "verify" && (strings.ToUpper(*scheme) == "BR" || strings.ToUpper(*scheme) == "BARRETO") {
			pk, err := readKeyFromPEM(*key, false)
			if err != nil {
				fmt.Println("Error loading key:", err)
				os.Exit(1)
			}

			msg, err := ioutil.ReadAll(inputfile)
			if err != nil {
				fmt.Println("Error reading message:", err)
				os.Exit(1)
			}

			var pubKey bls12381.G2
			pubKey.SetBytes(pk)

			sigBytes, err := hex.DecodeString(*sig)
			if err != nil {
				fmt.Println("Error decoding signature:", err)
				os.Exit(1)
			}

			decodedH, decodedSig, err := decodeSignatureBARRETO(sigBytes)
			if err != nil {
				fmt.Println("Error deserializing signature:", err)
				return
			}

			if verifyBARRETO(decodedH, decodedSig, append([]byte(*id), byte(*hierarchy)), msg, &pubKey) {
				fmt.Println("Verified: true")
			} else {
				fmt.Println("Verified: false")
				os.Exit(1)
			}
			os.Exit(0)
		} else if *pkey == "sign" && (strings.ToUpper(*scheme) == "GG" || strings.ToUpper(*scheme) == "GALINDO-GARCIA") {
			skData, err := readKeyFromPEM(*key, true)
			if err != nil {
				fmt.Println("Error loading GG private key:", err)
				os.Exit(1)
			}

			y, gr, err := decodePrivateKeyGG(skData)
			if err != nil {
				fmt.Println("Error decoding GG private key:", err)
				os.Exit(1)
			}

			msg, err := ioutil.ReadAll(inputfile)
			if err != nil {
				fmt.Println("Error reading message:", err)
				os.Exit(1)
			}

			ga, b, grOut := signGG(y, gr, append([]byte(*id), byte(*hierarchy)), msg)

			asn1Data, err := encodeSignatureGG(ga, b, grOut)
			if err != nil {
				fmt.Println("Error serializing GG signature:", err)
				return
			}

			fmt.Println("BLS12381("+inputdesc+")=", hex.EncodeToString(asn1Data))
		} else if *pkey == "verify" && (strings.ToUpper(*scheme) == "GG" || strings.ToUpper(*scheme) == "GALINDO-GARCIA") {
			pk, err := readKeyFromPEM(*key, false)
			if err != nil {
				fmt.Println("Error loading GG public key:", err)
				os.Exit(1)
			}

			mpk := new(bls12381.G1)
			if err := mpk.SetBytes(pk); err != nil {
				fmt.Println("Error decoding GG public key:", err)
				os.Exit(1)
			}

			msg, err := ioutil.ReadAll(inputfile)
			if err != nil {
				fmt.Println("Error reading message:", err)
				os.Exit(1)
			}

			sigBytes, err := hex.DecodeString(*sig)
			if err != nil {
				fmt.Println("Error decoding signature:", err)
				os.Exit(1)
			}

			ga, b, grOut, err := decodeSignatureGG(sigBytes)
			if err != nil {
				fmt.Println("Error deserializing GG signature:", err)
				os.Exit(1)
			}

			if verifyGG(ga, b, grOut, mpk, append([]byte(*id), byte(*hierarchy)), msg) {
				fmt.Println("Verified: true")
			} else {
				fmt.Println("Verified: false")
				os.Exit(1)
			}
			os.Exit(0)
		} else if *pkey == "sign" && (strings.ToUpper(*scheme) == "CC" || strings.ToUpper(*scheme) == "CHA-CHEON") {
			sk, err := readKeyFromPEM(*key, true)
			if err != nil {
				fmt.Println("Error loading key:", err)
				os.Exit(1)
			}
			skG1 := new(bls12381.G1)
			if err := skG1.SetBytes(sk); err != nil {
				fmt.Println("Error setting G1 bytes:", err)
				os.Exit(1)
			}

			msg, err := ioutil.ReadAll(inputfile)
			if err != nil {
				fmt.Println("Error getting input file:", err)
				os.Exit(1)
			}

			U, V := signCC(skG1, append([]byte(*id), byte(*hierarchy)), msg)

			asn1Data, err := encodeSignatureCC(U, V)
			if err != nil {
				fmt.Println("Error serializing signature:", err)
				return
			}

			fmt.Println("BLS12381("+inputdesc+")=", hex.EncodeToString(asn1Data))
		} else if *pkey == "verify" && (strings.ToUpper(*scheme) == "CC" || strings.ToUpper(*scheme) == "CHA-CHEON") {
			pk, err := readKeyFromPEM(*key, false)
			if err != nil {
				fmt.Println("Error loading key:", err)
				os.Exit(1)
			}

			msg, err := ioutil.ReadAll(inputfile)
			if err != nil {
				fmt.Println("Error reading message:", err)
				os.Exit(1)
			}

			var pubKey bls12381.G2
			pubKey.SetBytes(pk)

			sigBytes, err := hex.DecodeString(*sig)
			if err != nil {
				fmt.Println("Error decoding signature:", err)
				os.Exit(1)
			}

			decodedU, decodedV, err := decodeSignatureCC(sigBytes)
			if err != nil {
				fmt.Println("Error deserializing signature:", err)
				return
			}

			if verifyCC(&pubKey, append([]byte(*id), byte(*hierarchy)), msg, decodedU, decodedV) {
				fmt.Println("Verified: true")
			} else {
				fmt.Println("Verified: false")
				os.Exit(1)
			}
			os.Exit(0)
		} else if *pkey == "sign" {
			sk, err := readKeyFromPEM(*key, true)
			if err != nil {
				fmt.Println("Error loading key:", err)
				os.Exit(1)
			}
			skG1 := new(bls12381.G1)
			if err := skG1.SetBytes(sk); err != nil {
				fmt.Println("Error setting G1 bytes:", err)
				os.Exit(1)
			}

			msg, err := ioutil.ReadAll(inputfile)
			if err != nil {
				fmt.Println("Error getting input file:", err)
				os.Exit(1)
			}

			r := new(ff.Scalar)
			r.Random(rand.Reader)
			P1 := new(bls12381.G1)
			P1.ScalarMult(r, bls12381.G1Generator())

			U, V := signHESS(skG1, P1, msg)

			asn1Data, err := encodeSignatureHESS(U, V)
			if err != nil {
				fmt.Println("Error serializing signature:", err)
				return
			}

			fmt.Println("BLS12381("+inputdesc+")=", hex.EncodeToString(asn1Data))
		} else if *pkey == "verify" {
			pk, err := readKeyFromPEM(*key, false)
			if err != nil {
				fmt.Println("Error loading key:", err)
				os.Exit(1)
			}

			msg, err := ioutil.ReadAll(inputfile)
			if err != nil {
				fmt.Println("Error reading message:", err)
				os.Exit(1)
			}

			var pubKey bls12381.G2
			pubKey.SetBytes(pk)

			sigBytes, err := hex.DecodeString(*sig)
			if err != nil {
				fmt.Println("Error decoding signature:", err)
				os.Exit(1)
			}

			decodedU, decodedV, err := decodeSignatureHESS(sigBytes)
			if err != nil {
				fmt.Println("Error deserializing signature:", err)
				return
			}

			if verifyHESS(decodedU, decodedV, &pubKey, append([]byte(*id), byte(*hierarchy)), msg) {
				fmt.Println("Verified: true")
			} else {
				fmt.Println("Verified: false")
				os.Exit(1)
			}
			os.Exit(0)
		} else if *pkey == "encrypt" && (strings.ToUpper(*scheme) == "BB" || strings.ToUpper(*scheme) == "BONEH-BOYEN") {
			pemData, err := os.ReadFile(*key)
			if err != nil {
				fmt.Println("Error loading public key file:", err)
				os.Exit(1)
			}

			block, _ := pem.Decode(pemData)
			if block == nil || block.Type != "BLS12381 PUBLIC KEY" {
				fmt.Println("Error: invalid PEM format or wrong key type")
				os.Exit(1)
			}

			Ppub, Q, v, err := DeserializeMasterPublicKey(block.Bytes)
			if err != nil {
				fmt.Println("Error decoding public key:", err)
				os.Exit(1)
			}

			msg, err := ioutil.ReadAll(inputfile)
			if err != nil {
				fmt.Println("Error reading input message:", err)
				os.Exit(1)
			}

			if *id == "" {
				fmt.Println("Error: ID is required for BB encryption")
				os.Exit(1)
			}

			ciphertext, err := EncryptBB(string(append([]byte(*id), byte(*hierarchy))), msg, Ppub, Q, v)
			if err != nil {
				fmt.Println("Encryption failed:", err)
				os.Exit(1)
			}

			fmt.Printf("%s", ciphertext)
		} else if *pkey == "decrypt" && (strings.ToUpper(*scheme) == "BB" || strings.ToUpper(*scheme) == "BONEH-BOYEN") {
			sk, err := readKeyFromPEM(*key, true)
			if err != nil {
				fmt.Println("Error loading key:", err)
				os.Exit(1)
			}

			var privASN UserPrivateKeyASN
			if _, err := asn1.Unmarshal(sk, &privASN); err != nil {
				fmt.Println("Error decoding private key:", err)
				os.Exit(1)
			}

			r := new(ff.Scalar)
			if err := r.UnmarshalBinary(privASN.R); err != nil {
				fmt.Println("Error decoding r:", err)
				os.Exit(1)
			}

			Did := new(bls12381.G2)
			if err := Did.SetBytes(privASN.Did); err != nil {
				fmt.Println("Error decoding Did:", err)
				os.Exit(1)
			}

			v := new(bls12381.Gt)
			if err := v.UnmarshalBinary(privASN.V); err != nil {
				fmt.Println("Error decoding v:", err)
				os.Exit(1)
			}

			ct, err := ioutil.ReadAll(inputfile)
			if err != nil {
				fmt.Println("Error reading ciphertext:", err)
				os.Exit(1)
			}

			plaintext, err := DecryptBB(ct, r, Did, v)
			if err != nil {
				fmt.Println("Decryption failed:", err)
				os.Exit(1)
			}

			fmt.Printf("%s", plaintext)
		} else if *pkey == "encrypt" && (strings.ToUpper(*scheme) == "FO" || strings.ToUpper(*scheme) == "FUJISAKI-OKAMOTO") {
			pk, err := readKeyFromPEM(*key, false)
			if err != nil {
				fmt.Println("Error loading public key:", err)
				os.Exit(1)
			}

			var pubKey bls12381.G2
			err = pubKey.SetBytes(pk)
			if err != nil {
				log.Fatalf("Error deserializing public key: %v", err)
			}

			msg, err := ioutil.ReadAll(inputfile)
			if err != nil {
				fmt.Println("Error getting input file:", err)
				os.Exit(1)
			}

			U, V, W := encryptFO(&pubKey, append([]byte(*id), byte(*hierarchy)), []byte(msg), myHash)
			serialized, err := serializeToASN1BF_FO(U, V, W)
			if err != nil {
				log.Fatal("Failed to serialize ciphertext: " + err.Error())
			}

			fmt.Printf("%s", serialized)
		} else if *pkey == "decrypt" && (strings.ToUpper(*scheme) == "FO" || strings.ToUpper(*scheme) == "FUJISAKI-OKAMOTO") {
			sk, err := readKeyFromPEM(*key, true)
			if err != nil {
				fmt.Println("Error loading key:", err)
				os.Exit(1)
			}
			skG1 := new(bls12381.G1)
			if err := skG1.SetBytes(sk); err != nil {
				fmt.Println("Error setting G1 bytes:", err)
				os.Exit(1)
			}

			serialized, err := ioutil.ReadAll(inputfile)
			if err != nil {
				fmt.Println("Error getting input file:", err)
				os.Exit(1)
			}

			deserializedU, deserializedV, deserializedW, err := deserializeFromASN1BF_FO(serialized)
			if err != nil {
				log.Fatal("Failed to deserialize ciphertext: " + err.Error())
			}

			decryptedMessage, valid := decryptFO(deserializedU, skG1, deserializedV, deserializedW, myHash)
			if !valid {
				log.Fatal("Authentication failed! Message integrity compromised.")
			}
			fmt.Printf("%s", decryptedMessage)
		} else if *pkey == "encrypt" && (strings.ToUpper(*scheme) == "SK" || strings.ToUpper(*scheme) == "SAKAI-KASAHARA") {
			pk, err := readKeyFromPEM(*key, false)
			if err != nil {
				fmt.Println("Error loading public key:", err)
				os.Exit(1)
			}

			var pubKey bls12381.G1
			err = pubKey.SetBytes(pk)
			if err != nil {
				log.Fatalf("Error deserializing public key: %v", err)
			}

			msg, err := ioutil.ReadAll(inputfile)
			if err != nil {
				fmt.Println("Error getting input file:", err)
				os.Exit(1)
			}

			U, V, W := encryptSK(append([]byte(*id), byte(*hierarchy)), []byte(msg), &pubKey, myHash)
			serialized, err := serializeToASN1SK_FO(U, V, W)
			if err != nil {
				log.Fatal("Failed to serialize ciphertext: " + err.Error())
			}

			fmt.Printf("%s", serialized)
		} else if *pkey == "decrypt" && (strings.ToUpper(*scheme) == "SK" || strings.ToUpper(*scheme) == "SAKAI-KASAHARA") {
			sk, err := readKeyFromPEM(*key, true)
			if err != nil {
				fmt.Println("Error loading key:", err)
				os.Exit(1)
			}
			skG2 := new(bls12381.G2)
			if err := skG2.SetBytes(sk); err != nil {
				fmt.Println("Error setting G1 bytes:", err)
				os.Exit(1)
			}

			pk, err := readKeyFromPEM(*pub, false)
			if err != nil {
				fmt.Println("Error loading public key:", err)
				os.Exit(1)
			}

			var pubKey bls12381.G1
			err = pubKey.SetBytes(pk)
			if err != nil {
				log.Fatalf("Error deserializing public key: %v", err)
			}

			serialized, err := ioutil.ReadAll(inputfile)
			if err != nil {
				fmt.Println("Error getting input file:", err)
				os.Exit(1)
			}

			deserializedU, deserializedV, deserializedW, err := deserializeFromASN1SK_FO(serialized)
			if err != nil {
				log.Fatal("Failed to deserialize ciphertext: " + err.Error())
			}

			decryptedMessage, valid := decryptSK(append([]byte(*id), byte(*hierarchy)), deserializedU, deserializedV, deserializedW, skG2, &pubKey, myHash)
			if !valid {
				log.Fatal("Authentication failed! Message integrity compromised.")
			}
			fmt.Printf("%s", decryptedMessage)
		} else if *pkey == "encrypt" {
			pk, err := readKeyFromPEM(*key, false)
			if err != nil {
				fmt.Println("Error loading public key:", err)
				os.Exit(1)
			}

			var pubKey bls12381.G2
			err = pubKey.SetBytes(pk)
			if err != nil {
				log.Fatalf("Error deserializing public key: %v", err)
			}

			msg, err := ioutil.ReadAll(inputfile)
			if err != nil {
				fmt.Println("Error getting input file:", err)
				os.Exit(1)
			}

			U, V, T := encryptBF(&pubKey, append([]byte(*id), byte(*hierarchy)), []byte(msg), myHash)
			serialized, err := serializeToASN1BF(U, V, T)
			if err != nil {
				log.Fatal("Failed to serialize ciphertext: " + err.Error())
			}

			fmt.Printf("%s", serialized)
		} else if *pkey == "decrypt" {
			sk, err := readKeyFromPEM(*key, true)
			if err != nil {
				fmt.Println("Error loading key:", err)
				os.Exit(1)
			}
			skG1 := new(bls12381.G1)
			if err := skG1.SetBytes(sk); err != nil {
				fmt.Println("Error setting G1 bytes:", err)
				os.Exit(1)
			}

			serialized, err := ioutil.ReadAll(inputfile)
			if err != nil {
				fmt.Println("Error getting input file:", err)
				os.Exit(1)
			}

			deserializedU, deserializedV, Hash, err := deserializeFromASN1BF(serialized)
			if err != nil {
				log.Fatal("Failed to deserialize ciphertext: " + err.Error())
			}

			decryptedMessage, valid := decryptBF(deserializedU, skG1, deserializedV, Hash, myHash)
			if !valid {
				log.Fatal("Authentication failed! Message integrity compromised.")
			}
			fmt.Printf("%s", decryptedMessage)
		} else if *pkey == "proof" && (strings.ToUpper(*scheme) == "SM" || strings.ToUpper(*scheme) == "SHANGMI" || strings.ToUpper(*scheme) == "BR" || strings.ToUpper(*scheme) == "BARRETO") {
			skb, err := readKeyFromPEM(*key, true)
			if err != nil {
				fmt.Println("Error loading secret key:", err)
				os.Exit(1)
			}
			skid := new(bls12381.G1)
			if err := skid.SetBytes(skb); err != nil {
				fmt.Println("Error setting secret key:", err)
				os.Exit(1)
			}

			msg, err := ioutil.ReadAll(inputfile)
			if err != nil {
				fmt.Println("Error reading message:", err)
				os.Exit(1)
			}

			chi, S := createProofShangMi(skid, msg)

			chiB, _ := chi.MarshalBinary()
			SB := S.BytesCompressed()

			fmt.Printf("Challenge= %x\n", chiB)
			fmt.Printf("Response= %x\n", SB)

		} else if *pkey == "verify-proof" && (strings.ToUpper(*scheme) == "SM" || strings.ToUpper(*scheme) == "SHANGMI" || strings.ToUpper(*scheme) == "BR" || strings.ToUpper(*scheme) == "BARRETO") {
			pkb, err := readKeyFromPEM(*key, false)
			if err != nil {
				fmt.Println("Error loading public key:", err)
				os.Exit(1)
			}
			mpk := new(bls12381.G2)
			if err := mpk.SetBytes(pkb); err != nil {
				fmt.Println("Error setting public key:", err)
				os.Exit(1)
			}

			msg, err := ioutil.ReadAll(inputfile)
			if err != nil {
				fmt.Println("Error reading message:", err)
				os.Exit(1)
			}

			chb, err := hex.DecodeString(*challengeFlag)
			if err != nil {
				fmt.Println("Invalid challenge hex:", err)
				os.Exit(1)
			}
			chi := new(ff.Scalar)
			chi.SetBytes(chb)

			rb, err := hex.DecodeString(*responseFlag)
			if err != nil {
				fmt.Println("Invalid response hex:", err)
				os.Exit(1)
			}
			S := new(bls12381.G1)
			if err := S.SetBytes(rb); err != nil {
				fmt.Println("Invalid response bytes:", err)
				os.Exit(1)
			}

			if verifyProofShangMi(mpk, append([]byte(*id), byte(*hierarchy)), msg, chi, S) {
				fmt.Println("Verified: true")
			} else {
				fmt.Println("Verified: false")
				os.Exit(1)
			}
		} else if *pkey == "proof" {
			skBytes, err := readKeyFromPEM(*key, true)
			if err != nil {
				fmt.Println("Error loading secret key:", err)
				os.Exit(1)
			}

			skG1 := new(bls12381.G1)
			if err := skG1.SetBytes(skBytes); err != nil {
				fmt.Println("Error setting G1 secret key bytes:", err)
				os.Exit(1)
			}

			msg, err := ioutil.ReadAll(inputfile)
			if err != nil {
				fmt.Println("Error loading input file:", err)
				os.Exit(1)
			}

			QID := hashToG1(append([]byte(*id), byte(*hierarchy)))

			C, s := createProofIBE(skG1, QID, msg)

			Cbytes, err := C.MarshalBinary()
			if err != nil {
				fmt.Println("Error serializing commitment:", err)
				os.Exit(1)
			}

			sBytes := s.BytesCompressed()
			if err != nil {
				fmt.Println("Error serializing response:", err)
				os.Exit(1)
			}

			fmt.Printf("Commitment= %x\n", Cbytes)
			fmt.Printf("Response= %x\n", sBytes)
		} else if *pkey == "verify-proof" {
			pkBytes, err := readKeyFromPEM(*key, false)
			if err != nil {
				fmt.Println("Error loading public key:", err)
				os.Exit(1)
			}

			pubKey := new(bls12381.G2)
			if err := pubKey.SetBytes(pkBytes); err != nil {
				fmt.Println("Error setting public key bytes:", err)
				os.Exit(1)
			}

			msg, err := ioutil.ReadAll(inputfile)
			if err != nil {
				fmt.Println("Error loading input file:", err)
				os.Exit(1)
			}

			commitmentBytes, err := hex.DecodeString(*commitmentFlag)
			if err != nil {
				fmt.Println("Error decoding commitment hex:", err)
				os.Exit(1)
			}
			C := new(bls12381.Gt)
			if err := C.UnmarshalBinary(commitmentBytes); err != nil {
				fmt.Println("Error setting commitment bytes:", err)
				os.Exit(1)
			}

			responseBytes, err := hex.DecodeString(*responseFlag)
			if err != nil {
				fmt.Println("Error decoding response hex:", err)
				os.Exit(1)
			}
			response := new(bls12381.G1)
			if err := response.SetBytes(responseBytes); err != nil {
				fmt.Println("Error deserializing G1 response:", err)
				os.Exit(1)
			}

			QID := hashToG1(append([]byte(*id), byte(*hierarchy)))

			if verifyProofIBE(C, response, QID, pubKey, msg) {
				fmt.Println("Verified: true")
			} else {
				fmt.Println("Verified: false")
				os.Exit(1)
			}
		}
	}

	if (strings.ToUpper(*alg) == "BLS12381I") && (*pkey == "keygen" || *pkey == "sign" || *pkey == "aggregate" || *pkey == "verify-aggregate" || *pkey == "verify" || *pkey == "derive" || *pkey == "encrypt" || *pkey == "decrypt" || *pkey == "text" || *pkey == "fingerprint" || *pkey == "randomart" || *pkey == "certgen" || *pkey == "x509" || *pkey == "req" || *pkey == "check" || *pkey == "text" || *pkey == "crl" || *pkey == "validate" || *pkey == "proof" || *pkey == "verify-proof") {
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
		if *pkey == "text" && *key != "" && blockType == "BLS12381I SECRET KEY" {
			keyBytes, err := readKeyFromPEM(*key, true)
			if err != nil {
				fmt.Println("Error reading key from PEM:", err)
				os.Exit(1)
			}

			var privKey bls.PrivateKey[bls.G2]
			privKey.UnmarshalBinary(keyBytes)

			pubKey := privKey.PublicKey()

			keyPEM := pem.Block{Type: "BLS12381I SECRET KEY", Bytes: keyBytes}
			keyPEMText := string(pem.EncodeToMemory(&keyPEM))
			fmt.Print(keyPEMText)
			fmt.Println("SecretKey:")
			p := fmt.Sprintf("%x", keyBytes)
			splitz := SplitSubN(p, 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}
			pubBytes, err := pubKey.MarshalBinary()
			if err != nil {
				log.Fatalf("Error serializing public key: %v", err)
			}
			fmt.Println("PublicKey:")
			p = fmt.Sprintf("%x", pubBytes)
			splitz = SplitSubN(p, 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}

			fmt.Printf("Curve: %s\n", "BLS12381")

			os.Exit(0)
		} else if *pkey == "text" && *key != "" && (blockType == "BLS12381I PUBLIC KEY") {
			keyBytes, err := readKeyFromPEM(*key, false)
			if err != nil {
				fmt.Println("Error reading key from PEM:", err)
				os.Exit(1)
			}
			pubKeyPEM := pem.Block{Type: "BLS12381I PUBLIC KEY", Bytes: keyBytes}
			keyPEMText := string(pem.EncodeToMemory(&pubKeyPEM))
			fmt.Print(keyPEMText)
			fmt.Println("PublicKey:")
			p := fmt.Sprintf("%x", keyBytes)
			splitz := SplitSubN(p, 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}

			fmt.Printf("Curve: %s\n", "BLS12381")

			skid := sha3.Sum256(keyBytes)
			fmt.Printf("\nKeyID: %x \n", skid[:20])
			os.Exit(0)
		} else if *pkey == "fingerprint" && *key != "" {
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
			pubFile, err := os.Open(*key)
			if err != nil {
				fmt.Println("Error opening public key file:", err)
				os.Exit(1)
			}
			defer pubFile.Close()

			fmt.Println("BLS12 381-bit")

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
		} else if *pkey == "text" && *key == "" && *crl != "" {
			crl, err := ReadCRLFromPEM(*crl)
			if err != nil {
				log.Fatalf("Error reading the CRL: %v", err)
			}

			PrintCRLInfo(crl)
			os.Exit(0)
		}
		if *pkey == "keygen" && *pub2 == "" {
			ikm := make([]byte, 32)
			_, err := rand.Read(ikm)
			if err != nil {
				log.Fatal("Error:", err)
			}

			privKey, err := bls.KeyGen[bls.G2](ikm, []byte(*salt), []byte(*info))
			if err != nil {
				log.Fatal("Error generating private key: ", err)
			}

			pubKey := privKey.PublicKey()

			privBytes, err := privKey.MarshalBinary()
			if err != nil {
				log.Fatal("Error serializing private key: ", err)
			}
			pubBytes, err := pubKey.MarshalBinary()
			if err != nil {
				log.Fatal("Error serializing public key: ", err)
			}

			privPEM := pem.Block{Type: "BLS12381I SECRET KEY", Bytes: privBytes}
			pubPEM := pem.Block{Type: "BLS12381I PUBLIC KEY", Bytes: pubBytes}

			if err := savePEMToFile(*priv, &privPEM, true); err != nil {
				fmt.Println("Error saving private key:", err)
				return
			}
			if err := savePEMToFile(*pub, &pubPEM, false); err != nil {
				fmt.Println("Error saving public key:", err)
				return
			}

			privPath, err := filepath.Abs(*priv)
			if err != nil {
				fmt.Println("Error getting absolute path for private key:", err)
				os.Exit(1)
			}
			fmt.Printf("Private Key saved to: %s\n", privPath)

			pubPath, err := filepath.Abs(*pub)
			if err != nil {
				fmt.Println("Error getting absolute path for public key:", err)
				os.Exit(1)
			}
			fmt.Printf("Public Key saved to: %s\n", pubPath)

			fingerprint := calculateFingerprint(pubBytes)
			fmt.Printf("Fingerprint: %s\n", fingerprint)

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

			fmt.Println("BLS12 381-bit")
			pubBuf := make([]byte, pubInfo.Size())
			pubFile.Read(pubBuf)
			randomArt := randomart.FromString(string(pubBuf))
			fmt.Println(randomArt)
		} else if *pkey == "keygen" && *pub2 != "" {
			ikm := make([]byte, 32)
			_, err := rand.Read(ikm)
			if err != nil {
				log.Fatal("Error generating randomness:", err)
			}

			skScalar := new(ff.Scalar)
			skScalar.SetBytes(ikm)

			pkG1 := new(bls12381.G1)
			pkG1.ScalarMult(skScalar, bls12381.G1Generator())
			pkG1Bytes := pkG1.Bytes()

			pkG2 := new(bls12381.G2)
			pkG2.ScalarMult(skScalar, bls12381.G2Generator())
			pkG2Bytes := pkG2.Bytes()

			skBytes, err := skScalar.MarshalBinary()
			if err != nil {
				log.Fatal("Error serializing private key: ", err)
			}

			privPEM := &pem.Block{Type: "BLS12381I SECRET KEY", Bytes: skBytes}
			if err := savePEMToFile(*priv, privPEM, true); err != nil {
				fmt.Println("Error saving private key:", err)
				return
			}

			pubPEM := &pem.Block{Type: "BLS12381I PUBLIC KEY G1", Bytes: pkG1Bytes}
			if err := savePEMToFile(*pub, pubPEM, false); err != nil {
				fmt.Println("Error saving G1 public key:", err)
				return
			}

			if *pub2 != "" {
				pubPEM2 := &pem.Block{Type: "BLS12381I PUBLIC KEY G2", Bytes: pkG2Bytes}
				if err := savePEMToFile(*pub2, pubPEM2, false); err != nil {
					fmt.Println("Error saving G2 public key:", err)
					return
				}
			}

			privPath, _ := filepath.Abs(*priv)
			pubPath, _ := filepath.Abs(*pub)
			fmt.Printf("Private Key saved to: %s\n", privPath)
			fmt.Printf("Public Key G1 saved to: %s\n", pubPath)
			if *pub2 != "" {
				pub2Path, _ := filepath.Abs(*pub2)
				fmt.Printf("Public Key G2 saved to: %s\n", pub2Path)
			}

			fingerprint := calculateFingerprint(pkG1Bytes)
			fmt.Printf("Fingerprint G1: %s\n", fingerprint)
			fingerprint = calculateFingerprint(pkG2Bytes)
			fmt.Printf("Fingerprint G2: %s\n", fingerprint)

			fmt.Println("BLS12-381 G2")

			pubFile, err := os.Open(*pub2)
			if err != nil {
				fmt.Println("Error opening public key file:", err)
				os.Exit(1)
			}
			defer pubFile.Close()

			pubInfo, _ := pubFile.Stat()
			pubBuf := make([]byte, pubInfo.Size())
			pubFile.Read(pubBuf)
			randomArt := randomart.FromString(string(pubBuf))
			fmt.Println(randomArt)
		} else if *pkey == "sign" {
			privKeyBytes, err := readKeyFromPEM(*key, true)
			if err != nil {
				fmt.Println("Error loading key:", err)
				os.Exit(1)
			}

			var privKey bls.PrivateKey[bls.G2]
			err = privKey.UnmarshalBinary(privKeyBytes)
			if err != nil {
				fmt.Println("Error unmarshaling private key:", err)
				os.Exit(1)
			}

			msg, err := ioutil.ReadAll(inputfile)
			if err != nil {
				fmt.Println("Error getting input file:", err)
				os.Exit(1)
			}

			signature := bls.Sign(&privKey, msg)

			fmt.Println("PureBLS12381("+inputdesc+")=", hex.EncodeToString(signature))
			os.Exit(0)
		} else if *pkey == "verify" {
			pubKeyBytes, err := readKeyFromPEM(*key, false)
			if err != nil {
				fmt.Println("Error loading public key:", err)
				os.Exit(1)
			}

			var pubKey bls.PublicKey[bls.G2]
			err = pubKey.UnmarshalBinary(pubKeyBytes)
			if err != nil {
				fmt.Println("Error unmarshaling public key:", err)
				os.Exit(1)
			}

			msg, err := ioutil.ReadAll(inputfile)
			if err != nil {
				fmt.Println("Error reading message:", err)
				os.Exit(1)
			}

			sigBytes, err := hex.DecodeString(*sig)
			if err != nil {
				fmt.Println("Error decoding signature:", err)
				os.Exit(1)
			}

			valid := bls.Verify(&pubKey, msg, sigBytes)
			if valid {
				fmt.Println("Verified: true")
			} else {
				fmt.Println("Verified: false")
				os.Exit(1)
			}
			os.Exit(0)
		} else if *pkey == "aggregate" {
			privKeyBytes, err := readKeyFromPEM(*key, true)
			if err != nil {
				fmt.Println("Error loading key:", err)
				os.Exit(1)
			}

			var privKey bls.PrivateKey[bls.G2]
			err = privKey.UnmarshalBinary(privKeyBytes)
			if err != nil {
				fmt.Println("Error deserializing private key:", err)
				os.Exit(1)
			}

			msg, err := ioutil.ReadAll(inputfile)
			if err != nil {
				fmt.Println("Error loading input file:", err)
				os.Exit(1)
			}

			signature := bls.Sign(&privKey, msg)
			fmt.Println("Individual_BLS12381("+inputdesc+")=", hex.EncodeToString(signature))

			aggregatedSignature := signature
			if *sig != "" {
				aggregatedSigData, err := hex.DecodeString(*sig)
				if err != nil {
					log.Fatalf("Error decoding aggregated signature: %v", err)
				}

				existingAggregatedSig := aggregatedSigData

				aggregatedSignature, err = bls.Aggregate(bls.G2{}, []bls.Signature{existingAggregatedSig, signature})
				if err != nil {
					log.Fatalf("Error aggregating signatures: %v", err)
				}
			}

			fmt.Println("Aggregated_BLS12381=", hex.EncodeToString(aggregatedSignature[:]))
		} else if *pkey == "verify-aggregate" {
			if len(pubs) != len(msgs) {
				log.Fatal("The number of public keys and messages must be the same.")
			}

			var pubKeys []*bls.PublicKey[bls.G2]
			for _, pubPath := range pubs {
				pubKeyBytes, err := readKeyFromPEM(pubPath, false)
				if err != nil {
					fmt.Println("Error loading public key from", pubPath, ":", err)
					os.Exit(1)
				}

				var pubKey bls.PublicKey[bls.G2]
				err = pubKey.UnmarshalBinary(pubKeyBytes)
				if err != nil {
					fmt.Println("Error deserializing public key from", pubPath, ":", err)
					os.Exit(1)
				}

				pubKeys = append(pubKeys, &pubKey)
			}

			var msgsData [][]byte
			for _, msgPath := range msgs {
				msg, err := ioutil.ReadFile(msgPath)
				if err != nil {
					log.Fatalf("Error loading message %s: %v", msgPath, err)
				}
				msgsData = append(msgsData, msg)
			}

			sigBytes, err := hex.DecodeString(*sig)
			if err != nil {
				fmt.Println("Error decoding signature:", err)
				os.Exit(1)
			}

			valid := bls.VerifyAggregate(pubKeys, msgsData, sigBytes)
			if valid {
				fmt.Println("Verified: true")
			} else {
				fmt.Println("Verified: false")
				os.Exit(1)
			}
			os.Exit(0)
		} else if *pkey == "derive" && *pub2 == "" {
			sk, err := readKeyFromPEM(*key, true)
			if err != nil {
				fmt.Println("Error loading secret key:", err)
				os.Exit(1)
			}
			skBigInt := new(big.Int).SetBytes(sk)

			skScalar := new(ff.Scalar)
			skScalar.SetBytes(skBigInt.Bytes())

			pk, err := readKeyFromPEM(*pub, false)
			if err != nil {
				fmt.Println("Error loading public key:", err)
				os.Exit(1)
			}

			var pubKey bls12381.G2
			err = pubKey.SetBytes(pk)
			if err != nil {
				log.Fatalf("Error deserializing public key: %v", err)
			}

			baseG1 := bls12381.G1Generator()

			pairing := bls12381.Pair(baseG1, &pubKey)

			sharedKey := new(bls12381.Gt)
			sharedKey.Exp(pairing, skScalar)

			sharedBytes, err := sharedKey.MarshalBinary()
			if err != nil {
				log.Fatalf("Error marshaling shared key: %v", err)
			}
			fmt.Printf("Shared= %x\n", bmw.Sum256(sharedBytes))
		} else if *pkey == "derive" && *pub2 != "" {
			skBytes, err := readKeyFromPEM(*key, true)
			if err != nil {
				fmt.Println("Error loading secret key:", err)
				os.Exit(1)
			}

			skScalar := new(ff.Scalar)
			if err := skScalar.UnmarshalBinary(skBytes); err != nil {
				log.Fatalf("Error parsing scalar from secret key: %v", err)
			}

			pubG1Bytes, err := readKeyFromPEM(*pub, false)
			if err != nil {
				fmt.Println("Error loading public key (G1):", err)
				os.Exit(1)
			}
			var pkG1 bls12381.G1
			if err := pkG1.SetBytes(pubG1Bytes); err != nil {
				log.Fatalf("Error deserializing public key G1: %v", err)
			}

			pubG2Bytes, err := readKeyFromPEM(*pub2, false)
			if err != nil {
				fmt.Println("Error loading public key (G2):", err)
				os.Exit(1)
			}
			var pkG2 bls12381.G2
			if err := pkG2.SetBytes(pubG2Bytes); err != nil {
				log.Fatalf("Error deserializing public key G2: %v", err)
			}

			shared := bls12381.Pair(&pkG1, &pkG2)

			shared.Exp(shared, skScalar)

			sharedBytes, err := shared.MarshalBinary()
			if err != nil {
				log.Fatalf("Error marshaling shared key: %v", err)
			}

			fmt.Printf("Shared= %x\n", bmw.Sum256(sharedBytes))
		} else if *pkey == "encrypt" {
			pk, err := readKeyFromPEM(*key, false)
			if err != nil {
				fmt.Println("Error loading public key:", err)
				os.Exit(1)
			}

			var pubKey bls12381.G2
			err = pubKey.SetBytes(pk)
			if err != nil {
				log.Fatalf("Error deserializing public key: %v", err)
			}

			msg, err := ioutil.ReadAll(inputfile)
			if err != nil {
				fmt.Println("Error getting input file:", err)
				os.Exit(1)
			}

			C1, C2, encryptedMessage := encryptBLS(string(msg), &pubKey, myHash)

			serialized, err := serializeToASN1BLS(C1, C2, encryptedMessage)
			if err != nil {
				log.Fatal("Failed to serialize ciphertext: " + err.Error())
			}

			fmt.Printf("%s", serialized)
		} else if *pkey == "decrypt" {
			sk, err := readKeyFromPEM(*key, true)
			if err != nil {
				fmt.Println("Error loading key:", err)
				os.Exit(1)
			}
			skBigInt := new(big.Int).SetBytes(sk)

			serialized, err := ioutil.ReadAll(inputfile)
			if err != nil {
				fmt.Println("Error getting input file:", err)
				os.Exit(1)
			}

			deserializedC1, deserializedC2, deserializedMessage, err := deserializeFromASN1BLS(serialized)
			if err != nil {
				log.Fatal("Failed to deserialize ciphertext: " + err.Error())
			}

			decryptedMessage := decryptBLS(deserializedC1, deserializedC2, deserializedMessage, skBigInt, myHash)

			fmt.Printf("%s", decryptedMessage)
		} else if *pkey == "certgen" {
			keyBytes, err := readKeyFromPEM(*key, true)
			if err != nil {
				fmt.Println("Error reading key from PEM:", err)
				os.Exit(1)
			}

			var privKey bls.PrivateKey[bls.G2]
			privKey.UnmarshalBinary(keyBytes)

			pubKey := privKey.PublicKey()
			pubKeyBytes, err := pubKey.MarshalBinary()
			if err != nil {
				fmt.Println("Error marshaling public key from PEM:", err)
				os.Exit(1)
			}
			ca := NewCA(keyBytes, pubKeyBytes, validity)

			subject := pkix.Name{
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

			certificate, err := ca.IssueCertificate(subject, email, pubKeyBytes, keyBytes, true, validity)
			if err != nil {
				fmt.Println("Error issuing certificate:", err)
				return
			}

			err = SaveCertificateToPEM(certificate, *cert)
			if err != nil {
				fmt.Println("Error saving certificate:", err)
				return
			}

			fmt.Println("Certificate issued and saved successfully.")
			os.Exit(0)
		} else if *pkey == "check" && *crl == "" {
			pk, err := readKeyFromPEM(*key, false)
			if err != nil {
				fmt.Println("Error loading key:", err)
				return
			}
			certificate, err := ReadCertificateFromPEM(*cert)
			if err != nil {
				fmt.Println("Error reading the certificate:", err)
				return
			}

			err = VerifyCertificate(certificate, pk)
			if err != nil {
				fmt.Println("Verified: false", err)
				os.Exit(1)
			} else {
				fmt.Println("Verified: true")
				os.Exit(0)
			}
		} else if *pkey == "text" && *cert != "" {
			certificate, err := ReadCertificateFromPEM(*cert)
			if err != nil {
				csr, err := ReadCSRFromPEM(*cert)
				if err != nil {
					fmt.Println("Error loading certificate or CSR:", err)
					return
				}
				PrintInfo(csr)
			} else {
				PrintInfo(certificate)
			}
			os.Exit(0)
		} else if *pkey == "req" {
			keyBytes, err := readKeyFromPEM(*key, true)
			if err != nil {
				fmt.Println("Error reading key from PEM:", err)
				os.Exit(1)
			}

			var caPrivateKey bls.PrivateKey[bls.G2]
			caPrivateKey.UnmarshalBinary(keyBytes)

			pubKey := caPrivateKey.PublicKey()
			pubKeyBytes, err := pubKey.MarshalBinary()

			subject := pkix.Name{
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

			csr, err := CreateCSR(subject, email, pubKeyBytes, keyBytes)
			if err != nil {
				log.Fatalf("Failed to create CSR: %v", err)
			}

			err = SaveCSRToPEM(csr, *cert)
			if err != nil {
				log.Fatalf("Failed to save CSR: %v", err)
			}

			fmt.Println("CSR created and saved to", *cert)
			os.Exit(0)
		} else if *pkey == "x509" {
			keyBytes, err := readKeyFromPEM(*key, true)
			if err != nil {
				fmt.Println("Error reading key from PEM:", err)
				os.Exit(1)
			}

			var privKey bls.PrivateKey[bls.G2]
			privKey.UnmarshalBinary(keyBytes)

			caCert, err := ReadCertificateFromPEM(*root)
			if err != nil {
				log.Fatalf("Failed to read CA certificate: %v", err)
			}

			csr, err := ReadCSRFromPEM(*cert)
			if err != nil {
				log.Fatalf("Failed to read CSR: %v", err)
			}

			ca := &CA{
				PrivateKey:  keyBytes,
				Certificate: *caCert,
			}

			signedCert, err := SignCSR(csr, ca, keyBytes, validity)
			if err != nil {
				log.Fatalf("Failed to sign CSR: %v", err)
			}

			var outputFilename string
			if flag.Arg(0) == "" {
				outputFilename = "stdout"
			} else {
				outputFilename = flag.Arg(0)
			}

			err = SaveCertificateToPEM(signedCert, flag.Arg(0))
			if err != nil {
				log.Fatalf("Failed to save certificate: %v", err)
			}

			fmt.Fprintf(os.Stderr, "Certificate signed and saved to %s\n", outputFilename)
			os.Exit(0)
		} else if *pkey == "crl" {
			keyBytes, err := readKeyFromPEM(*key, true)
			if err != nil {
				fmt.Println("Error reading key from PEM:", err)
				os.Exit(1)
			}

			var caPrivateKey bls.PrivateKey[bls.G2]
			caPrivateKey.UnmarshalBinary(keyBytes)

			pubKey := caPrivateKey.PublicKey()
			pubKeyBytes, err := pubKey.MarshalBinary()

			cert, err := ReadCertificateFromPEM(*cert)
			if err != nil {
				log.Fatalf("Failed to read CA certificate: %v", err)
			}

			ca := NewCA(keyBytes, pubKeyBytes, validity)

			crl, err := NewCRL(ca, *crl, validity)
			if err != nil {
				fmt.Println("Error generating CRL:", err)
				return
			}

			revokedSerials, err := readRevokedSerials(flag.Arg(0))
			if err != nil {
				fmt.Printf("Error reading revoked serial numbers: %v\n", err)
				return
			}

			for _, serial := range revokedSerials {
				crl.RevokeCertificate(serial)
			}

			if err := crl.Sign(ca, cert); err != nil {
				fmt.Printf("Error signing CRL: %v\n", err)
				return
			}

			var outputFile string
			if len(flag.Args()) > 0 {
				outputFile = flag.Arg(1)
			}

			if err := SaveCRLToPEM(crl, outputFile); err != nil {
				fmt.Printf("Error saving CRL: %v\n", err)
				return
			}

			fmt.Println("CRL generated and saved successfully.")
			os.Exit(0)
		} else if *pkey == "validate" {
			certToValidate, err := ReadCertificateFromPEM(*cert)
			if err != nil {
				fmt.Printf("Error reading certificate: %v\n", err)
				return
			}

			readCRL, err := ReadCRLFromPEM(*crl)
			if err != nil {
				fmt.Printf("Error reading CRL: %v\n", err)
				return
			}

			if readCRL.IsRevoked(certToValidate.SerialNumber) {
				fmt.Println("The certificate has been revoked")
				os.Exit(1)
			} else {
				fmt.Println("The certificate is not revoked")
				os.Exit(0)
			}
		} else if *pkey == "check" && *crl != "" {
			certificate, err := ReadCertificateFromPEM(*cert)
			if err != nil {
				fmt.Println("Error reading certificate:", err)
				return
			}

			crl, err := ReadCRLFromPEM(*crl)
			if err != nil {
				fmt.Printf("Error reading CRL: %v\n", err)
				os.Exit(1)
			}

			if err := CheckCRL(crl, certificate.PublicKey); err != nil {
				fmt.Println("Verified: false", err)
				os.Exit(3)
			}

			fmt.Println("Verified: true")
			os.Exit(0)
		} else if *pkey == "proof" {
			sk, err := readKeyFromPEM(*key, true)
			if err != nil {
				fmt.Println("Error loading key:", err)
				os.Exit(1)
			}
			skScalar := new(ff.Scalar)
			skScalar.SetBytes(sk)

			msg, err := ioutil.ReadAll(inputfile)
			if err != nil {
				fmt.Println("Error loading input file:", err)
				os.Exit(1)
			}

			random := randomScalar()

			commitment := generateCommitment(random, bls12381.G2Generator())
			challenge := generateChallenge(commitment, msg)
			response := generateResponse(random, skScalar, challenge)

			responseBytes, err := response.MarshalBinary()
			if err != nil {
				fmt.Println("Error serializing response:", err)
				os.Exit(1)
			}

			challengeBytes, err := challenge.MarshalBinary()
			if err != nil {
				fmt.Println("Error serializing challenge:", err)
				os.Exit(1)
			}

			fmt.Printf("Commitment= %x\n", commitment.BytesCompressed())
			fmt.Printf("Challenge= %x\n", challengeBytes)
			fmt.Printf("Response= %x\n", responseBytes)
		} else if *pkey == "verify-proof" {
			pk, err := readKeyFromPEM(*key, false)
			if err != nil {
				fmt.Println("Error loading key:", err)
				os.Exit(1)
			}

			var pubKey bls12381.G2
			pubKey.SetBytes(pk)

			commitment := new(bls12381.G2)
			challenge := new(ff.Scalar)
			response := new(ff.Scalar)

			commitmentBytes, err := hex.DecodeString(*commitmentFlag)
			if err != nil {
				log.Fatalf("Error decoding commitment: %v", err)
			}
			err = commitment.SetBytes(commitmentBytes)
			if err != nil {
				log.Fatalf("Error deserializing commitment: %v", err)
			}

			msg, err := ioutil.ReadAll(inputfile)
			if err != nil {
				fmt.Println("Error loading input file:", err)
				os.Exit(1)
			}

			challenge = generateChallenge(commitment, msg)

			responseBytes, err := hex.DecodeString(*responseFlag)
			if err != nil {
				log.Fatalf("Error decoding response: %v", err)
			}
			response.SetBytes(responseBytes)

			isValid := verifyProof(commitment, challenge, response, &pubKey)
			if isValid {
				fmt.Println("Verified: true")
			} else {
				fmt.Println("Verified: false")
				os.Exit(1)
			}
		}
	}

	if (strings.ToUpper(*alg) == "BLS12381I") && (*tcpip == "client" || *tcpip == "server") {
		if *tcpip == "server" {
			keyBytes, err := readKeyFromPEM(*key, true)
			if err != nil {
				log.Fatal(err)
			}

			port := "8081"
			if *iport != "" {
				port = *iport
			}

			ln, err := net.Listen("tcp", ":"+port)
			if err != nil {
				log.Fatal(err)
			}
			defer ln.Close()

			fmt.Printf("Server(TUPI) up and listening on port %s\n", port)

			for {
				var serverPrivKey bls.PrivateKey[bls.G2]
				serverPrivKey.UnmarshalBinary(keyBytes)

				serverPubKey := serverPrivKey.PublicKey()
				serverPubKeyBytes, err := serverPubKey.MarshalBinary()
				if err != nil {
					log.Println("Error serializing server's public key:", err)
					return
				}

				certificate, err := ReadCertificateFromPEM(*cert)
				if err != nil {
					fmt.Println("Error reading the certificate:", err)
					return
				}
				if len(certificate.PublicKey) != len(serverPubKeyBytes) || subtle.ConstantTimeCompare(certificate.PublicKey, serverPubKeyBytes) != 1 {
					log.Fatal("The certificate does not match the private key.")
				}

				conn, err := ln.Accept()
				if err != nil {
					log.Fatal(err)
				}
				defer conn.Close()

				certData, err := os.ReadFile(*cert)
				if err != nil {
					log.Fatalf("Error reading the certificate: %v", err)
				}

				_, err = conn.Write(certData)
				if err != nil {
					log.Printf("Error sending the certificate to the client: %v", err)
					return
				}

				clientPublicKeyBytes := make([]byte, 96)
				_, err = conn.Read(clientPublicKeyBytes)
				if err != nil {
					if err == io.EOF {
						fmt.Println("Client disconnected.")
					} else {
						log.Println("Error reading client's public key:", err)
					}
					return
				}

				var clientPubKey bls12381.G2
				err = clientPubKey.SetBytes(clientPublicKeyBytes)
				if err != nil {
					log.Println("Error processing client's public key:", err)
					return
				}

				conn.Write(certificate.PublicKey)

				baseG1 := bls12381.G1Generator()
				pairingResult := bls12381.Pair(baseG1, &clientPubKey)

				serverPrivKeyBytes, err := serverPrivKey.MarshalBinary()
				if err != nil {
					log.Fatal(err)
				}

				serverPrivScalar := new(ff.Scalar)
				serverPrivScalar.SetBytes(serverPrivKeyBytes)

				sharedKey := new(bls12381.Gt)
				sharedKey.Exp(pairingResult, serverPrivScalar)

				sharedBytes, err := sharedKey.MarshalBinary()
				if err != nil {
					log.Fatalf("Error serializing shared key: %v", err)
				}

				handshake := append(clientPublicKeyBytes, serverPubKeyBytes...)
				handshake = append(handshake, sharedBytes...)

				signature := bls.Sign(&serverPrivKey, handshake)
				conn.Write(signature)

				var pubKey bls.PublicKey[bls.G2]
				err = pubKey.UnmarshalBinary(clientPublicKeyBytes)
				if err != nil {
					fmt.Println("Error unmarshaling public key:", err)
					os.Exit(1)
				}

				signatureBytes := make([]byte, 96)
				_, err = conn.Read(signatureBytes)
				if err != nil {
					log.Fatal("Error reading server's signature:", err)
				}

				validClientSignature := bls.Verify(&pubKey, handshake, signatureBytes)
				if !validClientSignature {
					log.Fatal("Client's signature verification failed")
				} else {
					fmt.Println("Handshake completed")
				}

				clientPubKeyPEM := pem.EncodeToMemory(&pem.Block{
					Type:  "BLS12381I PUBLIC KEY",
					Bytes: clientPublicKeyBytes,
				})

				fmt.Printf("%s\n", clientPubKeyPEM)

				clientAddr := conn.RemoteAddr()
				currentTime := time.Now().Format("2006/01/02 15:04:05")
				fmt.Printf("%s Client(TUPI) %s connected via secure channel.\n", currentTime, clientAddr)

				whirlpoolHash := whirlpool.New()
				whirlpoolHash.Write(sharedBytes)
				whirlpoolHashSum := whirlpoolHash.Sum(nil)
				/*
					var block cipher.Block
					var size int
					if strings.ToUpper(*paramset) == "A" {
						block, err = anubis.NewWithKeySize(whirlpoolHashSum[:], 40)
						size = 16
					} else if strings.ToUpper(*paramset) == "B" {
						block, err = curupira1.NewCipher(whirlpoolHashSum[:24])
						size = 12
					}
					if err != nil {
						log.Fatal("Error creating Anubis cipher:", err)
					}

					aead, err := eax.NewEAX(block, size)
					if err != nil {
						log.Fatal("Error creating AEAD:", err)
					}
				*/

				cipher, err := curupira1.NewCipher(whirlpoolHashSum[:24])
				if err != nil {
					log.Fatal("Error creating Curupira cipher instance:", err)
				}

				aead := curupira1.NewLetterSoup(cipher)

				for {
					buf := make([]byte, 1024)
					n, err := conn.Read(buf)
					if err != nil {
						if err == io.EOF {
							log.Fatal("Client disconnected.")
						}
						log.Println("Error reading data from client:", err)
						return
					}
					/*
						nonce, ciphertext := buf[:aead.NonceSize()], buf[aead.NonceSize():n]

						plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
						if err != nil {
							log.Println("Error decrypting data:", err)
							return
						}
					*/

					nonce, tag, msg := buf[:12], buf[12:24], buf[24:n]

					aead.SetIV(nonce)

					plaintext := make([]byte, len(msg))
					aead.Decrypt(plaintext, msg)

					ciphertext := make([]byte, len(plaintext))
					aead.Encrypt(ciphertext, plaintext)
					aead.Update(nil)
					tagEnc := aead.GetTag(nil, 96)

					if subtle.ConstantTimeCompare(tag, tagEnc) != 1 {
						log.Fatal("Error: authentication verification failed!")
					}

					fmt.Printf("Client response: %s\n", string(plaintext))

					reader := bufio.NewReader(os.Stdin)
					fmt.Print("Text to be sent: ")
					response, err := reader.ReadString('\n')
					if err != nil {
						log.Fatal("Error reading input:", err)
					}
					response = response[:len(response)-1]
					/*
						ciphertextResponse := aead.Seal(nonce, nonce, []byte(response), nil)
					*/

					nonce = make([]byte, 12)
					if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
						log.Fatal(err)
					}
					aead.SetIV(nonce)

					ciphertext = make([]byte, len([]byte(response)))
					aead.Encrypt(ciphertext, []byte(response))
					aead.Update(nil)
					tag = aead.GetTag(nil, 96)

					ciphertextResponse := append(nonce, tag...)
					ciphertextResponse = append(ciphertextResponse, ciphertext...)

					_, err = conn.Write(ciphertextResponse)
					if err != nil {
						log.Fatal("Error sending encrypted data:", err)
					}
				}
			}
		} else {
			ipport := "127.0.0.1:8081"
			if *iport != "" {
				ipport = *iport
			}
			conn, err := net.Dial("tcp", ipport)
			if err != nil {
				log.Fatal(err)
			}
			defer conn.Close()

			keyBytes, err := readKeyFromPEM(*key, true)
			if err != nil {
				log.Fatal(err)
			}

			var clientPrivKey bls.PrivateKey[bls.G2]
			clientPrivKey.UnmarshalBinary(keyBytes)

			clientPubKey := clientPrivKey.PublicKey()

			clientPubKeyBytes, err := clientPubKey.MarshalBinary()
			if err != nil {
				log.Fatal("Error serializing client's public key:", err)
			}

			certificate, err := ReadCertificateFromPEM(*cert)
			if err != nil {
				fmt.Println("Error reading the certificate:", err)
				return
			}
			if len(certificate.PublicKey) != len(clientPubKeyBytes) || subtle.ConstantTimeCompare(certificate.PublicKey, clientPubKeyBytes) != 1 {
				log.Fatal("The certificate does not match the private key.")
			}

			conn.Write(certificate.PublicKey)

			certData := make([]byte, 2048)
			n, err := conn.Read(certData)
			if err != nil && err != io.EOF {
				log.Fatalf("Error reading the server certificate: %v", err)
			}

			certBlock, _ := pem.Decode(certData)
			if certBlock == nil {
				return
			}

			if certBlock.Type != strings.ToUpper(*alg)+" CERTIFICATE" {
				return
			}

			var cert Certificate
			_, err = asn1.Unmarshal(certBlock.Bytes, &cert)
			if err != nil {
				log.Fatal(err)
			}

			fmt.Println("Issuer:")
			fmt.Println("       ", cert.Issuer)
			fmt.Println("Subject:")
			fmt.Println("       ", cert.Subject)
			fmt.Printf("Expiry: %s \n", cert.NotAfter.Format("Monday, 02-Jan-06 15:04:05 MST"))

			fmt.Println(string(certData[:n]))

			serverPubKeyBytes := make([]byte, 96)
			_, err = conn.Read(serverPubKeyBytes)
			if err != nil {
				log.Fatal("Error reading server's public key:", err)
			}

			var serverPubKey bls12381.G2
			err = serverPubKey.SetBytes(serverPubKeyBytes)
			if err != nil {
				log.Fatal("Error processing server's public key:", err)
			}

			baseG1 := bls12381.G1Generator()

			pairing := bls12381.Pair(baseG1, &serverPubKey)

			clientKeyBytes, err := clientPrivKey.MarshalBinary()
			if err != nil {
				log.Fatal(err)
			}

			clientPrivKeyBigInt := new(big.Int).SetBytes(clientKeyBytes)
			clientPrivScalar := new(ff.Scalar)
			clientPrivScalar.SetBytes(clientPrivKeyBigInt.Bytes())

			sharedKey := new(bls12381.Gt)
			sharedKey.Exp(pairing, clientPrivScalar)

			sharedBytes, err := sharedKey.MarshalBinary()
			if err != nil {
				log.Fatalf("Error serializing shared key: %v", err)
			}

			var pubKey bls.PublicKey[bls.G2]
			err = pubKey.UnmarshalBinary(serverPubKeyBytes)
			if err != nil {
				fmt.Println("Error unmarshaling public key:", err)
				os.Exit(1)
			}

			signatureBytes := make([]byte, 96)
			_, err = conn.Read(signatureBytes)
			if err != nil {
				log.Fatal("Error reading server's signature:", err)
			}

			handshake := append(clientPubKeyBytes, serverPubKeyBytes...)
			handshake = append(handshake, sharedBytes...)

			valid := bls.Verify(&pubKey, handshake, signatureBytes)
			if !valid {
				log.Fatal("Failed to verify the shared key's signature")
			}

			sessionKeySignature := bls.Sign(&clientPrivKey, handshake)

			_, err = conn.Write(sessionKeySignature)
			if err != nil {
				log.Fatal("Error sending session key signature:", err)
			}

			whirlpoolHash := whirlpool.New()
			whirlpoolHash.Write(sharedBytes)
			whirlpoolHashSum := whirlpoolHash.Sum(nil)
			/*
				var block cipher.Block
				var size int
				if strings.ToUpper(*paramset) == "A" {
					block, err = anubis.NewWithKeySize(whirlpoolHashSum[:], 40)
					size = 16
				} else if strings.ToUpper(*paramset) == "B" {
					block, err = curupira1.NewCipher(whirlpoolHashSum[:24])
					size = 12
				}
				if err != nil {
					log.Fatal("Error creating Anubis cipher:", err)
				}

				aead, err := eax.NewEAX(block, size)
				if err != nil {
					log.Fatal("Error creating AEAD:", err)
				}
			*/

			cipher, err := curupira1.NewCipher(whirlpoolHashSum[:24])
			if err != nil {
				log.Fatal("Error creating Curupira cipher instance:", err)
			}

			aead := curupira1.NewLetterSoup(cipher)

			for {
				reader := bufio.NewReader(os.Stdin)
				fmt.Print("Text to be sent: ")
				message, err := reader.ReadString('\n')
				if err != nil {
					log.Fatal("Error reading input:", err)
				}
				message = message[:len(message)-1]
				/*
					nonce := make([]byte, aead.NonceSize())
					if _, err := rand.Read(nonce); err != nil {
						log.Fatal("Error generating nonce:", err)
					}

					ciphertext := aead.Seal(nonce, nonce, []byte(message), nil)
				*/

				nonce := make([]byte, 12)
				if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
					log.Fatal(err)
				}
				aead.SetIV(nonce)

				ciphertext := make([]byte, len([]byte(message)))
				aead.Encrypt(ciphertext, []byte(message))
				aead.Update(nil)
				tag := aead.GetTag(nil, 96)

				output := append(nonce, tag...)
				output = append(output, ciphertext...)

				_, err = conn.Write(output)
				if err != nil {
					log.Fatal("Error sending encrypted data:", err)
				}

				buf := make([]byte, 1024)
				n, err := conn.Read(buf)
				if err != nil {
					if err == io.EOF {
						fmt.Println("Server closed the connection. Exiting...")
						break
					} else {
						log.Fatal("Error reading data from the server:", err)
					}
				}
				/*
					nonce, ciphertext = buf[:aead.NonceSize()], buf[aead.NonceSize():n]

					plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
					if err != nil {
						log.Fatal("Error decrypting data:", err)
					}
				*/

				nonce, tag, msg := buf[:12], buf[12:24], buf[24:n]

				aead.SetIV(nonce)

				plaintext := make([]byte, len(msg))
				aead.Decrypt(plaintext, msg)

				ciphertext = make([]byte, len(plaintext))
				aead.Encrypt(ciphertext, plaintext)
				aead.Update(nil)
				tagEnc := aead.GetTag(nil, 96)

				if len(tag) != len(tagEnc) || subtle.ConstantTimeCompare(tag, tagEnc) != 1 {
					log.Fatal("Error: authentication verification failed!")
				}

				fmt.Printf("Server response: %s\n", string(plaintext))
			}
			os.Exit(0)
		}
	}

	if (strings.ToUpper(*alg) == "BN256I") && (*pkey == "keygen" || *pkey == "sign" || *pkey == "aggregate" || *pkey == "verify" || *pkey == "derive" || *pkey == "derive-scalar" || *pkey == "encrypt" || *pkey == "decrypt" || *pkey == "text" || *pkey == "fingerprint" || *pkey == "randomart" || *pkey == "certgen" || *pkey == "x509" || *pkey == "req" || *pkey == "check" || *pkey == "text" || *pkey == "crl" || *pkey == "validate") {
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
		if *pkey == "text" && *key != "" && blockType == "BN256I SECRET KEY" {
			keyBytes, err := readKeyFromPEM(*key, true)
			if err != nil {
				fmt.Println("Error reading key from PEM:", err)
				os.Exit(1)
			}

			var privKey big.Int
			privKey.SetBytes(keyBytes)

			pubKey := new(bn256.G2).ScalarBaseMult(&privKey)

			keyPEM := pem.Block{Type: "BN256I SECRET KEY", Bytes: keyBytes}
			keyPEMText := string(pem.EncodeToMemory(&keyPEM))
			fmt.Print(keyPEMText)
			fmt.Println("SecretKey:")
			p := fmt.Sprintf("%x", keyBytes)
			splitz := SplitSubN(p, 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}
			fmt.Println("PublicKey:")
			p = fmt.Sprintf("%x", pubKey.Marshal())
			splitz = SplitSubN(p, 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}

			fmt.Printf("Curve: %s\n", "BN256")

			os.Exit(0)
		} else if *pkey == "text" && *key != "" && (blockType == "BN256I PUBLIC KEY" || blockType == "BN256I AGGREGATED PUBLIC KEY") {
			keyBytes, err := readKeyFromPEM(*key, false)
			if err != nil {
				fmt.Println("Error reading key from PEM:", err)
				os.Exit(1)
			}
			pubKeyPEM := pem.Block{Type: "BN256I PUBLIC KEY", Bytes: keyBytes}
			keyPEMText := string(pem.EncodeToMemory(&pubKeyPEM))
			fmt.Print(keyPEMText)
			fmt.Println("PublicKey:")
			p := fmt.Sprintf("%x", keyBytes)
			splitz := SplitSubN(p, 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}

			fmt.Printf("Curve: %s\n", "BN256")

			skid := sha3.Sum256(keyBytes)
			fmt.Printf("\nKeyID: %x \n", skid[:20])
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
			pubFile, err := os.Open(*key)
			if err != nil {
				fmt.Println("Error opening public key file:", err)
				os.Exit(1)
			}
			defer pubFile.Close()

			fmt.Println("Barreto-Naehrig 256")

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
		} else if *pkey == "text" && *key == "" && *crl != "" {
			crl, err := ReadCRLFromPEM(*crl)
			if err != nil {
				log.Fatalf("Error reading the CRL: %v", err)
			}

			PrintCRLInfo(crl)
			os.Exit(0)
		}
		if *pkey == "keygen" {
			sk, _, err := bn256.RandomG2(rand.Reader)
			if err != nil {
				fmt.Println("Error generating secret key:", err)
				return
			}

			pkG2 := new(bn256.G2).ScalarBaseMult(sk)

			if *pub2 != "" {
				pkG1 := new(bn256.G1).ScalarBaseMult(sk)

				block := &pem.Block{
					Type:  "BN256I SECRET KEY",
					Bytes: sk.Bytes(),
				}
				if err := savePEMToFile(*priv, block, true); err != nil {
					fmt.Println("Error saving private key:", err)
					return
				}

				blockG1 := &pem.Block{
					Type:  "BN256I PUBLIC KEY G1",
					Bytes: pkG1.Marshal(),
				}
				if err := savePEMToFile(*pub, blockG1, false); err != nil {
					fmt.Println("Error saving G1 public key:", err)
					return
				}

				blockG2 := &pem.Block{
					Type:  "BN256I PUBLIC KEY G2",
					Bytes: pkG2.Marshal(),
				}
				if err := savePEMToFile(*pub2, blockG2, false); err != nil {
					fmt.Println("Error saving G2 public key:", err)
					return
				}

				privPath, err := filepath.Abs(*priv)
				if err != nil {
					fmt.Println("Error getting absolute path for private key:", err)
					os.Exit(1)
				}
				fmt.Printf("Private Key saved to: %s\n", privPath)

				pubPath, err := filepath.Abs(*pub)
				if err != nil {
					fmt.Println("Error getting absolute path for G1 public key:", err)
					os.Exit(1)
				}
				fmt.Printf("G1 Public Key saved to: %s\n", pubPath)

				pub2Path, err := filepath.Abs(*pub2)
				if err != nil {
					fmt.Println("Error getting absolute path for G2 public key:", err)
					os.Exit(1)
				}
				fmt.Printf("G2 Public Key saved to: %s\n", pub2Path)

				fingerprintG1 := calculateFingerprint(pkG1.Marshal())
				fmt.Printf("Fingerprint G1: %s\n", fingerprintG1)
				fingerprintG2 := calculateFingerprint(pkG2.Marshal())
				fmt.Printf("Fingerprint G2: %s\n", fingerprintG2)

				pubFileG1, err := os.Open(*pub)
				if err != nil {
					fmt.Println("Error opening G1 public key file:", err)
					os.Exit(1)
				}
				defer pubFileG1.Close()

				pubInfoG1, err := pubFileG1.Stat()
				if err != nil {
					fmt.Println("Error getting G1 public key file info:", err)
					os.Exit(1)
				}

				pubBufG1 := make([]byte, pubInfoG1.Size())
				_, err = pubFileG1.Read(pubBufG1)
				if err != nil {
					fmt.Println("Error reading G1 public key file:", err)
					os.Exit(1)
				}
				randomArtG1 := randomart.FromString(string(pubBufG1))
				fmt.Println("RandomArt G1:")
				fmt.Println(randomArtG1)

				pubFileG2, err := os.Open(*pub2)
				if err != nil {
					fmt.Println("Error opening G2 public key file:", err)
					os.Exit(1)
				}
				defer pubFileG2.Close()

				pubInfoG2, err := pubFileG2.Stat()
				if err != nil {
					fmt.Println("Error getting G2 public key file info:", err)
					os.Exit(1)
				}

				pubBufG2 := make([]byte, pubInfoG2.Size())
				_, err = pubFileG2.Read(pubBufG2)
				if err != nil {
					fmt.Println("Error reading G2 public key file:", err)
					os.Exit(1)
				}
				randomArtG2 := randomart.FromString(string(pubBufG2))
				fmt.Println("RandomArt G2:")
				fmt.Println(randomArtG2)

			} else {
				block := &pem.Block{
					Type:  "BN256I SECRET KEY",
					Bytes: sk.Bytes(),
				}
				if err := savePEMToFile(*priv, block, true); err != nil {
					fmt.Println("Error saving keys:", err)
					return
				}

				block = &pem.Block{
					Type:  "BN256I PUBLIC KEY",
					Bytes: pkG2.Marshal(),
				}
				if err := savePEMToFile(*pub, block, false); err != nil {
					fmt.Println("Error saving keys:", err)
					return
				}

				privPath, err := filepath.Abs(*priv)
				if err != nil {
					fmt.Println("Error getting absolute path for private key:", err)
					os.Exit(1)
				}
				fmt.Printf("Private Key saved to: %s\n", privPath)

				pubPath, err := filepath.Abs(*pub)
				if err != nil {
					fmt.Println("Error getting absolute path for public key:", err)
					os.Exit(1)
				}
				fmt.Printf("Public Key saved to: %s\n", pubPath)

				fingerprint := calculateFingerprint(pkG2.Marshal())
				fmt.Printf("Fingerprint: %s\n", fingerprint)

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
				_, err = pubFile.Read(pubBuf)
				if err != nil {
					fmt.Println("Error reading public key file:", err)
					os.Exit(1)
				}
				randomArt := randomart.FromString(string(pubBuf))
				fmt.Println(randomArt)
			}
		} else if *pkey == "aggregate" {
			sk, err := readKeyFromPEM(*key, true)
			if err != nil {
				fmt.Println("Error loading key:", err)
				os.Exit(1)
			}
			skBigInt := new(big.Int).SetBytes(sk)

			msg, err := ioutil.ReadAll(inputfile)
			if err != nil {
				fmt.Println("Error getting input file:", err)
				os.Exit(1)
			}

			hash := bn256.HashG1(msg, []byte(*salt))
			signature := hash.ScalarMult(hash, skBigInt)
			if err != nil {
				fmt.Println("Error signing message:", err)
				os.Exit(1)
			}

			fmt.Println("Individual_BN256("+inputdesc+")=", hex.EncodeToString(signature.Marshal()))

			aggregatedSignature := signature

			if *sig != "" {
				aggregatedSigData, err := hex.DecodeString(*sig)
				if err != nil {
					log.Fatalf("Error decoding aggregated signature from hex: %v", err)
				}
				existingAggregatedSig := new(bn256.G1)
				_, err = existingAggregatedSig.Unmarshal(aggregatedSigData)
				if err != nil {
					log.Fatalf("Error unmarshalling aggregated signature: %v", err)
				}
				aggregatedSignature.Add(aggregatedSignature, existingAggregatedSig)
			}

			pubKey := new(bn256.G2).ScalarBaseMult(skBigInt)

			aggregatedPubKey := pubKey
			if *pub != "" {
				aggregatedPubKeyData, err := readKeyFromPEM(*root, false)
				if err != nil {
					log.Fatalf("Error loading aggregated public key: %v", err)
				}
				existingAggregatedPubKey := new(bn256.G2)
				_, err = existingAggregatedPubKey.Unmarshal(aggregatedPubKeyData)
				if err != nil {
					log.Fatalf("Error unmarshalling aggregated public key: %v", err)
				}
				aggregatedPubKey.Add(aggregatedPubKey, existingAggregatedPubKey)
			}

			block := &pem.Block{
				Type:  "BN256I AGGREGATED PUBLIC KEY",
				Bytes: aggregatedPubKey.Marshal(),
			}

			if err := savePEMToFile(*pub, block, false); err != nil {
				fmt.Println("Error saving aggregated public key:", err)
				return
			}

			fmt.Println("Aggregated_BN256("+inputdesc+")=", hex.EncodeToString(signature.Marshal()))
		} else if *pkey == "sign" {
			sk, err := readKeyFromPEM(*key, true)
			if err != nil {
				fmt.Println("Error loading key:", err)
				os.Exit(1)
			}
			skBigInt := new(big.Int).SetBytes(sk)

			msg, err := ioutil.ReadAll(inputfile)
			if err != nil {
				fmt.Println("Error getting input file:", err)
				os.Exit(1)
			}

			hash := bn256.HashG1(msg, []byte(*salt))
			signature := hash.ScalarMult(hash, skBigInt)
			if err != nil {
				fmt.Println("Error signing message:", err)
				os.Exit(1)
			}

			fmt.Println("PureBN256("+inputdesc+")=", hex.EncodeToString(signature.Marshal()))
		} else if *pkey == "verify" {
			pk, err := readKeyFromPEM(*key, false)
			if err != nil {
				fmt.Println("Error loading key:", err)
				os.Exit(1)
			}

			msg, err := ioutil.ReadAll(inputfile)
			if err != nil {
				fmt.Println("Error reading message:", err)
				os.Exit(1)
			}

			var pubKey bn256.G2
			_, err = pubKey.Unmarshal(pk)
			if err != nil {
				log.Fatalf("Error deserializing public key: %v", err)
			}

			sigBytes, err := hex.DecodeString(*sig)
			if err != nil {
				fmt.Println("Error decoding signature:", err)
				os.Exit(1)
			}

			var signature bn256.G1
			signature.Unmarshal(sigBytes)

			h := bn256.HashG1(msg, []byte(*salt))
			rhs := bn256.Pair(h, &pubKey)
			lhs := bn256.Pair(&signature, new(bn256.G2).ScalarBaseMult(big.NewInt(1)))

			rhsBytes := rhs.Marshal()
			lhsBytes := lhs.Marshal()

			if len(rhsBytes) == len(lhsBytes) && subtle.ConstantTimeCompare(rhsBytes, lhsBytes) == 1 {
				fmt.Println("Verified: true")
			} else {
				fmt.Println("Verified: false")
			}
		} else if *pkey == "derive-scalar" {
			sk, err := readKeyFromPEM(*key, true)
			if err != nil {
				fmt.Println("Error loading key:", err)
				os.Exit(1)
			}
			skBigInt := new(big.Int).SetBytes(sk)

			pk, err := readKeyFromPEM(*pub, false)
			if err != nil {
				fmt.Println("Error loading key:", err)
				os.Exit(1)
			}

			var pubKey bn256.G2
			_, err = pubKey.Unmarshal(pk)
			if err != nil {
				log.Fatalf("Error deserializing public key: %v", err)
			}

			sharedKey := new(bn256.G2).ScalarMult(&pubKey, skBigInt)
			fmt.Printf("Shared= %x\n", bmw.Sum256(sharedKey.Marshal()))
		} else if *pkey == "derive" && *pub2 == "" {
			sk, err := readKeyFromPEM(*key, true)
			if err != nil {
				fmt.Println("Error loading key:", err)
				os.Exit(1)
			}
			skBigInt := new(big.Int).SetBytes(sk)

			pk, err := readKeyFromPEM(*pub, false)
			if err != nil {
				fmt.Println("Error loading public key:", err)
				os.Exit(1)
			}

			var pubKey bn256.G2
			_, err = pubKey.Unmarshal(pk)
			if err != nil {
				log.Fatalf("Error deserializing public key: %v", err)
			}

			baseG1 := new(bn256.G1).ScalarBaseMult(big.NewInt(1048576))

			pairing := bn256.Pair(baseG1, &pubKey)

			sharedKey := new(bn256.GT)
			sharedKey.ScalarMult(pairing, skBigInt)

			fmt.Printf("Shared= %x\n", bmw.Sum256(sharedKey.Marshal()))
		} else if *pkey == "derive" && *pub2 != "" {
			sk, err := readKeyFromPEM(*key, true)
			if err != nil {
				fmt.Println("Error loading secret key:", err)
				os.Exit(1)
			}
			skBigInt := new(big.Int).SetBytes(sk)

			pkG1Bytes, err := readKeyFromPEM(*pub, false)
			if err != nil {
				fmt.Println("Error loading public G1 key:", err)
				os.Exit(1)
			}
			var pubG1 bn256.G1
			_, err = pubG1.Unmarshal(pkG1Bytes)
			if err != nil {
				log.Fatalf("Error deserializing G1 public key: %v", err)
			}

			pkG2Bytes, err := readKeyFromPEM(*pub2, false)
			if err != nil {
				fmt.Println("Error loading public G2 key:", err)
				os.Exit(1)
			}
			var pubG2 bn256.G2
			_, err = pubG2.Unmarshal(pkG2Bytes)
			if err != nil {
				log.Fatalf("Error deserializing G2 public key: %v", err)
			}

			shared := bn256.Pair(&pubG1, &pubG2)

			sharedKey := new(bn256.GT).ScalarMult(shared, skBigInt)

			fmt.Printf("Shared= %x\n", bmw.Sum256(sharedKey.Marshal()))
		} else if *pkey == "encrypt" {
			pk, err := readKeyFromPEM(*key, false)
			if err != nil {
				fmt.Println("Error loading public key:", err)
				os.Exit(1)
			}

			var pubKey bn256.G2
			_, err = pubKey.Unmarshal(pk)
			if err != nil {
				log.Fatalf("Error deserializing public key: %v", err)
			}

			msg, err := ioutil.ReadAll(inputfile)
			if err != nil {
				fmt.Println("Error getting input file:", err)
				os.Exit(1)
			}

			C1, C2, encryptedMessage := encryptBN(string(msg), &pubKey, myHash)
			serialized, err := serializeToASN1(C1, C2, encryptedMessage)
			if err != nil {
				log.Fatal("Failed to serialize ciphertext: " + err.Error())
			}

			fmt.Printf("%s", serialized)
		} else if *pkey == "decrypt" {
			sk, err := readKeyFromPEM(*key, true)
			if err != nil {
				fmt.Println("Error loading key:", err)
				os.Exit(1)
			}
			skBigInt := new(big.Int).SetBytes(sk)

			serialized, err := ioutil.ReadAll(inputfile)
			if err != nil {
				fmt.Println("Error getting input file:", err)
				os.Exit(1)
			}

			deserializedC1, deserializedC2, deserializedMessage, err := deserializeFromASN1(serialized)
			if err != nil {
				log.Fatal("Failed to deserialize ciphertext: " + err.Error())
			}

			decryptedMessage := decryptBN(deserializedC1, deserializedC2, deserializedMessage, skBigInt, myHash)
			fmt.Printf("%s", decryptedMessage)
		} else if *pkey == "certgen" {
			sk, err := readKeyFromPEM(*key, true)
			if err != nil {
				fmt.Println("Error loading key:", err)
				os.Exit(1)
			}

			var privKey big.Int
			privKey.SetBytes(sk)
			pk := new(bn256.G2).ScalarBaseMult(&privKey)

			ca := NewCA(sk, pk.Marshal(), validity)

			subject := pkix.Name{
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

			certificate, err := ca.IssueCertificate(subject, email, pk.Marshal(), sk, true, validity)
			if err != nil {
				fmt.Println("Error issuing certificate:", err)
				return
			}

			err = SaveCertificateToPEM(certificate, *cert)
			if err != nil {
				fmt.Println("Error saving certificate:", err)
				return
			}

			fmt.Println("Certificate issued and saved successfully.")
			os.Exit(0)
		} else if *pkey == "check" && *crl == "" {
			pk, err := readKeyFromPEM(*key, false)
			if err != nil {
				fmt.Println("Error loading key:", err)
				return
			}
			certificate, err := ReadCertificateFromPEM(*cert)
			if err != nil {
				fmt.Println("Error reading the certificate:", err)
				return
			}

			err = VerifyCertificate(certificate, pk)
			if err != nil {
				fmt.Println("Verified: false", err)
				os.Exit(1)
			} else {
				fmt.Println("Verified: true")
				os.Exit(0)
			}
		} else if *pkey == "text" && *cert != "" {
			certificate, err := ReadCertificateFromPEM(*cert)
			if err != nil {
				csr, err := ReadCSRFromPEM(*cert)
				if err != nil {
					fmt.Println("Error loading certificate or CSR:", err)
					return
				}
				PrintInfo(csr)
			} else {
				PrintInfo(certificate)
			}
			os.Exit(0)
		} else if *pkey == "req" {
			sk, err := readKeyFromPEM(*key, true)
			if err != nil {
				fmt.Println("Error loading key:", err)
				os.Exit(1)
			}

			subject := pkix.Name{
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

			var privKey big.Int
			privKey.SetBytes(sk)
			pk := new(bn256.G2).ScalarBaseMult(&privKey)

			csr, err := CreateCSR(subject, email, pk.Marshal(), sk)
			if err != nil {
				log.Fatalf("Failed to create CSR: %v", err)
			}

			err = SaveCSRToPEM(csr, *cert)
			if err != nil {
				log.Fatalf("Failed to save CSR: %v", err)
			}

			fmt.Println("CSR created and saved to", *cert)
			os.Exit(0)
		} else if *pkey == "x509" {
			sk, err := readKeyFromPEM(*key, true)
			if err != nil {
				fmt.Println("Error loading key:", err)
				os.Exit(1)
			}

			caCert, err := ReadCertificateFromPEM(*root)
			if err != nil {
				log.Fatalf("Failed to read CA certificate: %v", err)
			}

			csr, err := ReadCSRFromPEM(*cert)
			if err != nil {
				log.Fatalf("Failed to read CSR: %v", err)
			}

			ca := &CA{
				PrivateKey:  sk,
				Certificate: *caCert,
			}

			signedCert, err := SignCSR(csr, ca, sk, validity)
			if err != nil {
				log.Fatalf("Failed to sign CSR: %v", err)
			}

			var outputFilename string
			if flag.Arg(0) == "" {
				outputFilename = "stdout"
			} else {
				outputFilename = flag.Arg(0)
			}

			err = SaveCertificateToPEM(signedCert, flag.Arg(0))
			if err != nil {
				log.Fatalf("Failed to save certificate: %v", err)
			}

			fmt.Fprintf(os.Stderr, "Certificate signed and saved to %s\n", outputFilename)
			os.Exit(0)
		} else if *pkey == "crl" {
			sk, err := readKeyFromPEM(*key, true)
			if err != nil {
				fmt.Println("Error loading key:", err)
				os.Exit(1)
			}

			var privKey big.Int
			privKey.SetBytes(sk)
			pk := new(bn256.G2).ScalarBaseMult(&privKey)

			cert, err := ReadCertificateFromPEM(*cert)
			if err != nil {
				log.Fatalf("Failed to read CA certificate: %v", err)
			}

			ca := NewCA(sk, pk.Marshal(), validity)

			crl, err := NewCRL(ca, *crl, validity)
			if err != nil {
				fmt.Println("Error generating CRL:", err)
				return
			}

			revokedSerials, err := readRevokedSerials(flag.Arg(0))
			if err != nil {
				fmt.Printf("Error reading revoked serial numbers: %v\n", err)
				return
			}

			for _, serial := range revokedSerials {
				crl.RevokeCertificate(serial)
			}

			if err := crl.Sign(ca, cert); err != nil {
				fmt.Printf("Error signing CRL: %v\n", err)
				return
			}

			var outputFile string
			if len(flag.Args()) > 0 {
				outputFile = flag.Arg(1)
			}

			if err := SaveCRLToPEM(crl, outputFile); err != nil {
				fmt.Printf("Error saving CRL: %v\n", err)
				return
			}

			fmt.Println("CRL generated and saved successfully.")
			os.Exit(0)
		} else if *pkey == "validate" {
			certToValidate, err := ReadCertificateFromPEM(*cert)
			if err != nil {
				fmt.Printf("Error reading certificate: %v\n", err)
				return
			}

			readCRL, err := ReadCRLFromPEM(*crl)
			if err != nil {
				fmt.Printf("Error reading CRL: %v\n", err)
				return
			}

			if readCRL.IsRevoked(certToValidate.SerialNumber) {
				fmt.Println("The certificate has been revoked")
				os.Exit(1)
			} else {
				fmt.Println("The certificate is not revoked")
				os.Exit(0)
			}
		} else if *pkey == "check" && *crl != "" {
			certificate, err := ReadCertificateFromPEM(*cert)
			if err != nil {
				fmt.Println("Error reading certificate:", err)
				return
			}

			crl, err := ReadCRLFromPEM(*crl)
			if err != nil {
				fmt.Printf("Error reading CRL: %v\n", err)
				os.Exit(1)
			}

			if err := CheckCRL(crl, certificate.PublicKey); err != nil {
				fmt.Println("Verified: false", err)
				os.Exit(3)
			}

			fmt.Println("Verified: true")
			os.Exit(0)
		}
	}

	if (strings.ToUpper(*alg) == "BN256" || strings.ToUpper(*alg) == "BN256SIGN" || strings.ToUpper(*alg) == "BN256ENCRYPT") && (*pkey == "keygen" || *pkey == "setup" || *pkey == "sign" || *pkey == "verify" || *pkey == "encrypt" || *pkey == "decrypt" || *pkey == "text" || *pkey == "fingerprint" || *pkey == "randomart") {
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
		if *pkey == "text" && *key != "" && (blockType == "BN256 SECRET KEY" || blockType == "BN256SIGN SECRET KEY" || blockType == "BN256ENCRYPT SECRET KEY" || blockType == "BN256 MASTER KEY") {
			keyBytes, err := readKeyFromPEM(*key, true)
			if err != nil {
				fmt.Println("Error reading key from PEM:", err)
				os.Exit(1)
			}

			var privKey big.Int
			privKey.SetBytes(keyBytes)

			pubKey := new(bn256.G2).ScalarBaseMult(&privKey)

			if blockType == "BN256 MASTER KEY" {
				keyPEM := pem.Block{Type: "BN256 MASTER KEY", Bytes: keyBytes}
				keyPEMText := string(pem.EncodeToMemory(&keyPEM))
				fmt.Print(keyPEMText)
				fmt.Println("MasterKey:")
				p := fmt.Sprintf("%x", keyBytes)
				splitz := SplitSubN(p, 2)
				for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
					fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
				}
				fmt.Println("PublicKey:")
				p = fmt.Sprintf("%x", pubKey.Marshal())
				splitz = SplitSubN(p, 2)
				for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
					fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
				}
			} else if blockType == "BN256 SECRET KEY" {
				keyPEM := pem.Block{Type: "BN256 SECRET KEY", Bytes: keyBytes}
				keyPEMText := string(pem.EncodeToMemory(&keyPEM))
				fmt.Print(keyPEMText)
				fmt.Println("SecretKey:")
				p := fmt.Sprintf("%x", keyBytes)
				splitz := SplitSubN(p, 2)
				for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
					fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
				}
			} else if blockType == "BN256SIGN SECRET KEY" {
				keyPEM := pem.Block{Type: "BN256SIGN SECRET KEY", Bytes: keyBytes}
				keyPEMText := string(pem.EncodeToMemory(&keyPEM))
				fmt.Print(keyPEMText)
				fmt.Println("SecretKey:")
				p := fmt.Sprintf("%x", keyBytes)
				splitz := SplitSubN(p, 2)
				for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
					fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
				}
			} else if blockType == "BN256ENCRYPT SECRET KEY" {
				keyPEM := pem.Block{Type: "BN256ENCRYPT SECRET KEY", Bytes: keyBytes}
				keyPEMText := string(pem.EncodeToMemory(&keyPEM))
				fmt.Print(keyPEMText)
				fmt.Println("SecretKey:")
				p := fmt.Sprintf("%x", keyBytes)
				splitz := SplitSubN(p, 2)
				for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
					fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
				}
			}

			fmt.Printf("Curve: %s\n", "BN256")

			os.Exit(0)
		} else if *pkey == "text" && *key != "" && (blockType == "BN256 PUBLIC KEY" || blockType == "BN256 PUBLIC KEY") {
			keyBytes, err := readKeyFromPEM(*key, false)
			if err != nil {
				fmt.Println("Error reading key from PEM:", err)
				os.Exit(1)
			}
			pubKeyPEM := pem.Block{Type: "BN256I PUBLIC KEY", Bytes: keyBytes}
			keyPEMText := string(pem.EncodeToMemory(&pubKeyPEM))
			fmt.Print(keyPEMText)
			fmt.Println("PublicKey:")
			p := fmt.Sprintf("%x", keyBytes)
			splitz := SplitSubN(p, 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}

			fmt.Printf("Curve: %s\n", "BN256")

			skid := sha3.Sum256(keyBytes)
			fmt.Printf("\nKeyID: %x \n", skid[:20])
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
			pubFile, err := os.Open(*key)
			if err != nil {
				fmt.Println("Error opening public key file:", err)
				os.Exit(1)
			}
			defer pubFile.Close()

			fmt.Println("Barreto-Naehrig 256")

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
		} else if *pkey == "text" && *key == "" && *crl != "" {
			crl, err := ReadCRLFromPEM(*crl)
			if err != nil {
				log.Fatalf("Error reading the CRL: %v", err)
			}

			PrintCRLInfo(crl)
			os.Exit(0)
		}
		if *pkey == "setup" {
			sk, _, _ := bn256.RandomG2(rand.Reader)
			pk := generateMasterPublicKey(sk)
			if err != nil {
				fmt.Println("Error:", err)
				return
			}

			block := &pem.Block{
				Type:  "BN256 MASTER KEY",
				Bytes: sk.Bytes(),
			}
			if err := savePEMToFile(*master, block, true); err != nil {
				fmt.Println("Error saving keys:", err)
				return
			}

			block = &pem.Block{
				Type:  "BN256 PUBLIC KEY",
				Bytes: pk.Marshal(),
			}

			if err := savePEMToFile(*pub, block, false); err != nil {
				fmt.Println("Error saving keys:", err)
				return
			}

			privPath, err := filepath.Abs(*master)
			if err != nil {
				fmt.Println("Error getting absolute path for private key:", err)
				os.Exit(1)
			}
			fmt.Printf("Master Key saved to: %s\n", privPath)

			pubPath, err := filepath.Abs(*pub)
			if err != nil {
				fmt.Println("Error getting absolute path for public key:", err)
				os.Exit(1)
			}
			fmt.Printf("Public Key saved to: %s\n", pubPath)

			fingerprint := calculateFingerprint(pk.Marshal())
			fmt.Printf("Fingerprint: %s\n", fingerprint)

			fmt.Printf("Barreto-Naehrig %d\n", 256)

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
		} else if *pkey == "keygen" && strings.ToUpper(*alg) == "BN256" {
			sk, err := readKeyFromPEM(*master, true)
			if err != nil {
				fmt.Println("Error loading key:", err)
				os.Exit(1)
			}
			skBigInt := new(big.Int).SetBytes(sk)

			var privateKey *bn256.G1
			if strings.ToUpper(*scheme) == "BF" || strings.ToUpper(*scheme) == "BONEH-FRANKLIN" || strings.ToUpper(*scheme) == "CC" || strings.ToUpper(*scheme) == "CHA-CHEON" || strings.ToUpper(*scheme) == "HESS" {
				privateKey = extractBN(skBigInt, append([]byte(*id), byte(*hierarchy)))
			} else if strings.ToUpper(*scheme) == "SM" || strings.ToUpper(*scheme) == "SHANGMI" {
				privateKey = extractSM_BN(skBigInt, append([]byte(*id), byte(*hierarchy)))
			} else if strings.ToUpper(*scheme) == "BR" || strings.ToUpper(*scheme) == "BARRETO" {
				privateKey = extractBARRETO_BN(skBigInt, append([]byte(*id), byte(*hierarchy)))
			} else {
				privateKey = extractBN(skBigInt, append([]byte(*id), byte(*hierarchy)))
			}

			block := &pem.Block{
				Type:  "BN256 SECRET KEY",
				Bytes: privateKey.Marshal(),
			}

			if err := savePEMToFile2(*priv, block, true); err != nil {
				fmt.Println("Error saving private key:", err)
				return
			}

			privPath, err := filepath.Abs(*priv)
			if err != nil {
				fmt.Println("Error getting absolute path for private key:", err)
				return
			}
			fmt.Printf("Private Key saved to: %s\n", privPath)
		} else if *pkey == "keygen" && strings.ToUpper(*alg) == "BN256SIGN" {
			sk, err := readKeyFromPEM(*master, true)
			if err != nil {
				fmt.Println("Error loading key:", err)
				os.Exit(1)
			}
			skBigInt := new(big.Int).SetBytes(sk)

			var privateKey *bn256.G1
			if strings.ToUpper(*scheme) == "CC" || strings.ToUpper(*scheme) == "CHA-CHEON" || strings.ToUpper(*scheme) == "HESS" {
				privateKey = extractBN(skBigInt, append([]byte(*id), byte(*hierarchy)))
			} else if strings.ToUpper(*scheme) == "SM" || strings.ToUpper(*scheme) == "SHANGMI" {
				privateKey = extractSM_BN(skBigInt, append([]byte(*id), byte(*hierarchy)))
			} else if strings.ToUpper(*scheme) == "BR" || strings.ToUpper(*scheme) == "BARRETO" {
				privateKey = extractBARRETO_BN(skBigInt, append([]byte(*id), byte(*hierarchy)))
			} else {
				privateKey = extractBN(skBigInt, append([]byte(*id), byte(*hierarchy)))
			}

			block := &pem.Block{
				Type:  "BN256SIGN SECRET KEY",
				Bytes: privateKey.Marshal(),
			}

			if err := savePEMToFile2(*priv, block, true); err != nil {
				fmt.Println("Error saving private key:", err)
				return
			}

			privPath, err := filepath.Abs(*priv)
			if err != nil {
				fmt.Println("Error getting absolute path for private key:", err)
				return
			}
			fmt.Printf("Private Key saved to: %s\n", privPath)
		} else if *pkey == "keygen" && strings.ToUpper(*alg) == "BN256ENCRYPT" {
			sk, err := readKeyFromPEM(*master, true)
			if err != nil {
				fmt.Println("Error loading key:", err)
				os.Exit(1)
			}
			skBigInt := new(big.Int).SetBytes(sk)

			privateKey := extractBN(skBigInt, append([]byte(*id), byte(*hierarchy)))

			block := &pem.Block{
				Type:  "BN256ENCRYPT SECRET KEY",
				Bytes: privateKey.Marshal(),
			}

			if err := savePEMToFile2(*priv, block, true); err != nil {
				fmt.Println("Error saving private key:", err)
				return
			}

			privPath, err := filepath.Abs(*priv)
			if err != nil {
				fmt.Println("Error getting absolute path for private key:", err)
				return
			}
			fmt.Printf("Private Key saved to: %s\n", privPath)
		} else if *pkey == "sign" && (strings.ToUpper(*scheme) == "SM" || strings.ToUpper(*scheme) == "SHANGMI") {
			sk, err := readKeyFromPEM(*key, true)
			if err != nil {
				fmt.Println("Error loading key:", err)
				os.Exit(1)
			}
			skG1 := new(bn256.G1)
			_, err = skG1.Unmarshal(sk)
			if err != nil {
				fmt.Println("Error unmarshaling G1 key:", err)
				os.Exit(1)
			}

			msg, err := ioutil.ReadAll(inputfile)
			if err != nil {
				fmt.Println("Error getting input file:", err)
				os.Exit(1)
			}

			h, signature := signSM_BN(skG1, msg)

			signatureBytes, err := encodeSignatureSM_BN(h, signature)
			if err != nil {
				fmt.Println("Error encoding signature:", err)
				os.Exit(1)
			}

			fmt.Println("BN256("+inputdesc+")=", hex.EncodeToString(signatureBytes))
		} else if *pkey == "verify" && (strings.ToUpper(*scheme) == "SM" || strings.ToUpper(*scheme) == "SHANGMI") {
			pk, err := readKeyFromPEM(*key, false)
			if err != nil {
				fmt.Println("Error loading key:", err)
				os.Exit(1)
			}

			msg, err := ioutil.ReadAll(inputfile)
			if err != nil {
				fmt.Println("Error reading message:", err)
				os.Exit(1)
			}

			var pubKey bn256.G2
			_, err = pubKey.Unmarshal(pk)
			if err != nil {
				log.Fatalf("Error deserializing public key: %v", err)
			}

			sigBytes, err := hex.DecodeString(*sig)
			if err != nil {
				fmt.Println("Error decoding signature:", err)
				os.Exit(1)
			}

			h, signature, err := decodeSignatureSM_BN(sigBytes)
			if err != nil {
				fmt.Println("Error decoding signature:", err)
				os.Exit(1)
			}

			if verifySM_BN(&pubKey, append([]byte(*id), byte(*hierarchy)), msg, h, signature) {
				fmt.Println("Verified: true")
			} else {
				fmt.Println("Verified: false")
				os.Exit(1)
			}
			os.Exit(0)
		} else if *pkey == "sign" && (strings.ToUpper(*scheme) == "BR" || strings.ToUpper(*scheme) == "BARRETO") {
			sk, err := readKeyFromPEM(*key, true)
			if err != nil {
				fmt.Println("Error loading key:", err)
				os.Exit(1)
			}
			skG1 := new(bn256.G1)
			_, err = skG1.Unmarshal(sk)
			if err != nil {
				fmt.Println("Error unmarshaling G1 key:", err)
				os.Exit(1)
			}

			msg, err := ioutil.ReadAll(inputfile)
			if err != nil {
				fmt.Println("Error getting input file:", err)
				os.Exit(1)
			}

			h, signature := signBARRETO_BN(skG1, msg)

			signatureBytes, err := encodeSignatureBARRETO_BN(h, signature)
			if err != nil {
				fmt.Println("Error encoding signature:", err)
				os.Exit(1)
			}

			fmt.Println("BN256("+inputdesc+")=", hex.EncodeToString(signatureBytes))
		} else if *pkey == "verify" && (strings.ToUpper(*scheme) == "BR" || strings.ToUpper(*scheme) == "BARRETO") {
			pk, err := readKeyFromPEM(*key, false)
			if err != nil {
				fmt.Println("Error loading key:", err)
				os.Exit(1)
			}

			msg, err := ioutil.ReadAll(inputfile)
			if err != nil {
				fmt.Println("Error reading message:", err)
				os.Exit(1)
			}

			var pubKey bn256.G2
			_, err = pubKey.Unmarshal(pk)
			if err != nil {
				log.Fatalf("Error deserializing public key: %v", err)
			}

			sigBytes, err := hex.DecodeString(*sig)
			if err != nil {
				fmt.Println("Error decoding signature:", err)
				os.Exit(1)
			}

			h, signature, err := decodeSignatureBARRETO_BN(sigBytes)
			if err != nil {
				fmt.Println("Error decoding signature:", err)
				os.Exit(1)
			}

			if verifyBARRETO_BN(h, signature, append([]byte(*id), byte(*hierarchy)), msg, &pubKey) {
				fmt.Println("Verified: true")
			} else {
				fmt.Println("Verified: false")
				os.Exit(1)
			}
			os.Exit(0)
		} else if *pkey == "sign" && (strings.ToUpper(*scheme) == "CC" || strings.ToUpper(*scheme) == "CHA-CHEON") {
			sk, err := readKeyFromPEM(*key, true)
			if err != nil {
				fmt.Println("Error loading key:", err)
				os.Exit(1)
			}
			skG1 := new(bn256.G1)
			_, err = skG1.Unmarshal(sk)
			if err != nil {
				fmt.Println("Error unmarshaling G1 key:", err)
				os.Exit(1)
			}

			msg, err := ioutil.ReadAll(inputfile)
			if err != nil {
				fmt.Println("Error getting input file:", err)
				os.Exit(1)
			}

			h, signature := signCC_BN(skG1, append([]byte(*id), byte(*hierarchy)), msg)

			signatureBytes, err := encodeSignatureCC_BN(h, signature)
			if err != nil {
				fmt.Println("Error encoding signature:", err)
				os.Exit(1)
			}

			fmt.Println("BN256("+inputdesc+")=", hex.EncodeToString(signatureBytes))
		} else if *pkey == "verify" && (strings.ToUpper(*scheme) == "CC" || strings.ToUpper(*scheme) == "CHA-CHEON") {
			pk, err := readKeyFromPEM(*key, false)
			if err != nil {
				fmt.Println("Error loading key:", err)
				os.Exit(1)
			}

			msg, err := ioutil.ReadAll(inputfile)
			if err != nil {
				fmt.Println("Error reading message:", err)
				os.Exit(1)
			}

			var pubKey bn256.G2
			_, err = pubKey.Unmarshal(pk)
			if err != nil {
				log.Fatalf("Error deserializing public key: %v", err)
			}

			sigBytes, err := hex.DecodeString(*sig)
			if err != nil {
				fmt.Println("Error decoding signature:", err)
				os.Exit(1)
			}

			h, signature, err := decodeSignatureCC_BN(sigBytes)
			if err != nil {
				fmt.Println("Error decoding signature:", err)
				os.Exit(1)
			}

			if verifyCC_BN(&pubKey, append([]byte(*id), byte(*hierarchy)), msg, h, signature) {
				fmt.Println("Verified: true")
			} else {
				fmt.Println("Verified: false")
				os.Exit(1)
			}
			os.Exit(0)
		} else if *pkey == "sign" {
			sk, err := readKeyFromPEM(*key, true)
			if err != nil {
				fmt.Println("Error loading key:", err)
				os.Exit(1)
			}
			skG1 := new(bn256.G1)
			_, err = skG1.Unmarshal(sk)
			if err != nil {
				fmt.Println("Error unmarshaling G1 key:", err)
				os.Exit(1)
			}

			msg, err := ioutil.ReadAll(inputfile)
			if err != nil {
				fmt.Println("Error getting input file:", err)
				os.Exit(1)
			}

			r, _ := rand.Int(rand.Reader, bn256.Order)
			P1 := new(bn256.G1).ScalarBaseMult(r)

			u, v := signHESS_BN(skG1, P1, msg)

			signatureBytes, err := encodeSignatureHESS_BN(u, v)
			if err != nil {
				fmt.Println("Error encoding signature:", err)
				os.Exit(1)
			}

			fmt.Println("BN256("+inputdesc+")=", hex.EncodeToString(signatureBytes))
		} else if *pkey == "verify" {
			pk, err := readKeyFromPEM(*key, false)
			if err != nil {
				fmt.Println("Error loading key:", err)
				os.Exit(1)
			}

			msg, err := ioutil.ReadAll(inputfile)
			if err != nil {
				fmt.Println("Error reading message:", err)
				os.Exit(1)
			}

			var pubKey bn256.G2
			_, err = pubKey.Unmarshal(pk)
			if err != nil {
				log.Fatalf("Error deserializing public key: %v", err)
			}

			sigBytes, err := hex.DecodeString(*sig)
			if err != nil {
				fmt.Println("Error decoding signature:", err)
				os.Exit(1)
			}

			decodedU, decodedV, err := decodeSignatureHESS_BN(sigBytes)
			if err != nil {
				fmt.Println("Error decoding signature:", err)
				os.Exit(1)
			}

			if verifyHESS_BN(decodedU, decodedV, &pubKey, append([]byte(*id), byte(*hierarchy)), msg) {
				fmt.Println("Verified: true")
			} else {
				fmt.Println("Verified: false")
				os.Exit(1)
			}
			os.Exit(0)
		} else if *pkey == "encrypt" && (strings.ToUpper(*scheme) == "FO" || strings.ToUpper(*scheme) == "FUJISAKI-OKAMOTO") {
			pk, err := readKeyFromPEM(*key, false)
			if err != nil {
				fmt.Println("Error loading public key:", err)
				os.Exit(1)
			}

			var pubKey bn256.G2
			_, err = pubKey.Unmarshal(pk)
			if err != nil {
				log.Fatalf("Error deserializing public key: %v", err)
			}

			msg, err := ioutil.ReadAll(inputfile)
			if err != nil {
				fmt.Println("Error getting input file:", err)
				os.Exit(1)
			}

			U, V, W := encryptFO_BN(&pubKey, append([]byte(*id), byte(*hierarchy)), msg, myHash)
			serialized, err := serializeToASN1BF_FO_BN(U, V, W)
			if err != nil {
				log.Fatal("Failed to serialize ciphertext: " + err.Error())
			}

			fmt.Printf("%s", serialized)
		} else if *pkey == "decrypt" && (strings.ToUpper(*scheme) == "FO" || strings.ToUpper(*scheme) == "FUJISAKI-OKAMOTO") {
			sk, err := readKeyFromPEM(*key, true)
			if err != nil {
				fmt.Println("Error loading key:", err)
				os.Exit(1)
			}
			skG1 := new(bn256.G1)
			_, err = skG1.Unmarshal(sk)
			if err != nil {
				fmt.Println("Error unmarshaling G1 key:", err)
				os.Exit(1)
			}

			serialized, err := ioutil.ReadAll(inputfile)
			if err != nil {
				fmt.Println("Error getting input file:", err)
				os.Exit(1)
			}

			deserializedU, deserializedV, deserializedW, err := deserializeFromASN1BF_FO_BN(serialized)
			if err != nil {
				log.Fatal("Failed to deserialize ciphertext: " + err.Error())
			}

			decryptedMessage, valid := decryptFO_BN(deserializedU, skG1, deserializedV, deserializedW, myHash)
			if !valid {
				log.Fatal("Authentication failed! Message integrity compromised.")
			}
			fmt.Printf("%s", decryptedMessage)
		} else if *pkey == "encrypt" {
			pk, err := readKeyFromPEM(*key, false)
			if err != nil {
				fmt.Println("Error loading public key:", err)
				os.Exit(1)
			}

			var pubKey bn256.G2
			_, err = pubKey.Unmarshal(pk)
			if err != nil {
				log.Fatalf("Error deserializing public key: %v", err)
			}

			msg, err := ioutil.ReadAll(inputfile)
			if err != nil {
				fmt.Println("Error getting input file:", err)
				os.Exit(1)
			}

			U, V, T := encryptBF_BN(&pubKey, append([]byte(*id), byte(*hierarchy)), msg, myHash)
			serialized, err := serializeToASN1BF_BN(U, V, T)
			if err != nil {
				log.Fatal("Failed to serialize ciphertext: " + err.Error())
			}

			fmt.Printf("%s", serialized)
		} else if *pkey == "decrypt" {
			sk, err := readKeyFromPEM(*key, true)
			if err != nil {
				fmt.Println("Error loading key:", err)
				os.Exit(1)
			}
			skG1 := new(bn256.G1)
			_, err = skG1.Unmarshal(sk)
			if err != nil {
				fmt.Println("Error unmarshaling G1 key:", err)
				os.Exit(1)
			}

			serialized, err := ioutil.ReadAll(inputfile)
			if err != nil {
				fmt.Println("Error getting input file:", err)
				os.Exit(1)
			}

			deserializedU, deserializedV, Hash, err := deserializeFromASN1BF_BN(serialized)
			if err != nil {
				log.Fatal("Failed to deserialize ciphertext: " + err.Error())
			}

			decryptedMessage, valid := decryptBF_BN(deserializedU, skG1, deserializedV, Hash, myHash)
			if !valid {
				log.Fatal("Authentication failed! Message integrity compromised.")
			}
			fmt.Printf("%s", decryptedMessage)
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
			publicBytes, err := keyType.MasterPublic().MarshalASN1()
			if err != nil {
				log.Fatal("Error marshaling public key:", err)
			}
			fmt.Printf("Public=%X\n", publicBytes)

		case *sm9.SignPrivateKey:
			publicBytes, err := keyType.MasterPublic().MarshalASN1()
			if err != nil {
				log.Fatal("Error marshaling public key:", err)
			}
			fmt.Printf("Public=%X\n", publicBytes)

		case *sm9.EncryptMasterPrivateKey:
			publicBytes, err := keyType.PublicKey().MarshalASN1()
			if err != nil {
				log.Fatal("Error marshaling public key:", err)
			}
			fmt.Printf("Public=%X\n", publicBytes)

		case *sm9.SignMasterPrivateKey:
			publicBytes, err := keyType.PublicKey().MarshalASN1()
			if err != nil {
				log.Fatal("Error marshaling public key:", err)
			}
			fmt.Printf("Public=%X\n", publicBytes)

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

		pubKey, err := sm9.UnmarshalSignMasterPublicKeyASN1(keyBlock.Bytes)
		if err != nil {
			fmt.Println("Error parsing public key:", err)
			return
		}

		fmt.Printf("Public=%X\n", pubKey.Bytes())
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

		pubKey, err := sm9.UnmarshalEncryptMasterPublicKeyASN1(keyBlock.Bytes)
		if err != nil {
			fmt.Println("Error parsing public key:", err)
			return
		}

		fmt.Printf("Public=%X\n", pubKey.Bytes())
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
			fmt.Println("priv:")
			privKeyBytes, err := keyType.MarshalASN1()
			if err != nil {
				log.Fatal(err)
			}
			privKeyHex := hex.EncodeToString(privKeyBytes)
			splitz := SplitSubN(privKeyHex, 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}
			fmt.Println("pub:")
			pubKeyHex := hex.EncodeToString(keyType.MasterPublic().Bytes())
			splitz = SplitSubN(pubKeyHex, 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}
			fmt.Println("Curve: sm9p256v1")

		case *sm9.SignPrivateKey:
			fmt.Println("Sign Private-Key: (256-bit)")
			fmt.Println("priv:")
			privKeyBytes, err := keyType.MarshalASN1()
			if err != nil {
				log.Fatal(err)
			}
			privKeyHex := hex.EncodeToString(privKeyBytes)
			splitz := SplitSubN(privKeyHex, 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}
			fmt.Println("pub:")
			pubKeyHex := hex.EncodeToString(keyType.MasterPublic().Bytes())
			splitz = SplitSubN(pubKeyHex, 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}
			fmt.Println("Curve: sm9p256v1")

		case *sm9.EncryptMasterPrivateKey:
			fmt.Println("Encrypt Master-Key: (256-bit)")
			fmt.Println("master:")
			privKeyBytes, err := keyType.MarshalASN1()
			if err != nil {
				log.Fatal(err)
			}
			privKeyHex := hex.EncodeToString(privKeyBytes)
			splitz := SplitSubN(privKeyHex, 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}
			fmt.Println("pub:")
			pubKeyHex := hex.EncodeToString(keyType.PublicKey().Bytes())
			splitz = SplitSubN(pubKeyHex, 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}
			fmt.Println("Curve: sm9p256v1")

		case *sm9.SignMasterPrivateKey:
			fmt.Println("Sign Master-Key: (256-bit)")
			fmt.Println("master:")
			privKeyBytes, err := keyType.MarshalASN1()
			if err != nil {
				log.Fatal(err)
			}
			privKeyHex := hex.EncodeToString(privKeyBytes)
			splitz := SplitSubN(privKeyHex, 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}
			fmt.Println("pub:")
			pubKeyHex := hex.EncodeToString(keyType.PublicKey().Bytes())
			splitz = SplitSubN(pubKeyHex, 2)
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

		pubKey, err := sm9.UnmarshalSignMasterPublicKeyASN1(keyBlock.Bytes)
		if err != nil {
			fmt.Println("Error parsing public key with UnmarshalASN1:", err)
			return
		}

		fmt.Print(string(keyFileContent))
		fmt.Println("Sign Public-Key: (256-bit)")
		fmt.Println("pub:")
		pubKeyHex := fmt.Sprintf("%x", pubKey.Bytes())
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

		pubKey, err := sm9.UnmarshalEncryptMasterPublicKeyASN1(keyBlock.Bytes)
		if err != nil {
			fmt.Println("Error parsing public key with UnmarshalASN1:", err)
			return
		}

		fmt.Print(string(keyFileContent))
		fmt.Println("Encrypt Public-Key: (256-bit)")
		fmt.Println("pub:")
		pubKeyHex := fmt.Sprintf("%x", pubKey.Bytes())
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

		if *subj == "" {
			println("You are about to be asked to enter information \nthat will be incorporated into your certificate.")

			scanner := bufio.NewScanner(os.Stdin)

			print("Common Name: ")
			scanner.Scan()
			name = scanner.Text()

			print("Country Name (2 letter code) [AU]: ")
			scanner.Scan()
			country = scanner.Text()

			print("State or Province Name (full name) [Some-State]: ")
			scanner.Scan()
			province = scanner.Text()

			print("Locality Name (eg, city): ")
			scanner.Scan()
			locality = scanner.Text()

			print("Organization Name (eg, company) [Internet Widgits Pty Ltd]: ")
			scanner.Scan()
			organization = scanner.Text()

			print("Organizational Unit Name (eg, section): ")
			scanner.Scan()
			organizationunit = scanner.Text()

			print("Email Address []: ")
			scanner.Scan()
			email = scanner.Text()

			print("StreetAddress: ")
			scanner.Scan()
			street = scanner.Text()

			print("PostalCode: ")
			scanner.Scan()
			postalcode = scanner.Text()

			print("SerialNumber: ")
			scanner.Scan()
			number = scanner.Text()
		} else {
			name, number, country, province, locality, organization, organizationunit, street, email, postalcode, err = parseSubjectString(*subj)
			if err != nil {
				log.Fatal(err)
			}
		}

		var validity string

		if *days > 0 {
			validity = fmt.Sprintf("%d", *days)
		} else {
			fmt.Print("Validity (in Days): ")
			fmt.Scanln(&validity)
		}

		intVar, err := strconv.Atoi(validity)
		if err != nil {
			log.Fatal(err)
		}
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

		if *subj == "" {
			println("You are about to be asked to enter information \nthat will be incorporated into your certificate.")

			scanner := bufio.NewScanner(os.Stdin)

			print("Common Name: ")
			scanner.Scan()
			name = scanner.Text()

			print("Country Name (2 letter code) [AU]: ")
			scanner.Scan()
			country = scanner.Text()

			print("State or Province Name (full name) [Some-State]: ")
			scanner.Scan()
			province = scanner.Text()

			print("Locality Name (eg, city): ")
			scanner.Scan()
			locality = scanner.Text()

			print("Organization Name (eg, company) [Internet Widgits Pty Ltd]: ")
			scanner.Scan()
			organization = scanner.Text()

			print("Organizational Unit Name (eg, section): ")
			scanner.Scan()
			organizationunit = scanner.Text()

			print("Email Address []: ")
			scanner.Scan()
			email = scanner.Text()

			print("StreetAddress: ")
			scanner.Scan()
			street = scanner.Text()

			print("PostalCode: ")
			scanner.Scan()
			postalcode = scanner.Text()

			print("SerialNumber: ")
			scanner.Scan()
			number = scanner.Text()
		} else {
			name, number, country, province, locality, organization, organizationunit, street, email, postalcode, err = parseSubjectString(*subj)
			if err != nil {
				log.Fatal(err)
			}
		}

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
			if err != nil {
				log.Fatal(err)
			}
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
			if err != nil {
				log.Fatal(err)
			}
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
		if err != nil {
			log.Fatal(err)
		}
		err = VerifyRSA([]byte(Data), Signature)
		if err != nil {
			fmt.Println("Checksum error:", err)
			os.Exit(1)
		}
		fmt.Println("Verified: true")
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
		data, err := os.ReadFile(*key)
		if err != nil {
			fmt.Println("Error reading public key file:", err)
			os.Exit(1)
		}

		block, _ := pem.Decode(data)
		if block == nil {
			fmt.Println("Failed to decode PEM block")
			os.Exit(1)
		}

		var pubASN1 PublicKeyASN1
		if _, err := asn1.Unmarshal(block.Bytes, &pubASN1); err == nil {
			fingerprint := calculateFingerprintFromASN1(pubASN1.Y.Bytes())
			fmt.Println("Fingerprint=", fingerprint)
			os.Exit(0)
		}

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

	if *pkey == "fingerprint" && (strings.ToUpper(*alg) == "SCHNORR") && (PEM == "Public") {
		data, err := os.ReadFile(*key)
		if err != nil {
			fmt.Println("Error reading public key file:", err)
			os.Exit(1)
		}

		block, _ := pem.Decode(data)
		if block == nil {
			fmt.Println("Failed to decode PEM block")
			os.Exit(1)
		}

		publicKeyVal, err := readSchnorrPublicKeyFromPEM(*key)
		if err != nil {
			fmt.Println("Error reading PEM file:", err)
			return
		}

		fingerprint := calculateFingerprint(publicKeyVal.Y.Bytes())
		fmt.Println("Fingerprint=", fingerprint)
		os.Exit(0)
	}
	if *pkey == "randomart" && (strings.ToUpper(*alg) == "SCHNORR") && (PEM == "Public") {
		publicKeyVal, err := readPublicKeyFromPEM(*key)
		if err != nil {
			fmt.Println("Error reading PEM file:", err)
			return
		}

		primeBitLength := publicKeyVal.P.BitLen()
		fmt.Fprintf(os.Stderr, "Schnorr (%d-bits)\n", primeBitLength)

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

		parsers := []func([]byte) (interface{}, error){
			func(b []byte) (interface{}, error) {
				return smx509.ParsePKIXPublicKey(b)
			},
			func(b []byte) (interface{}, error) {
				return x509.ParsePKIXPublicKey(b)
			},
			func(b []byte) (interface{}, error) {
				return nums.ParsePublicKey(b)
			},
			func(b []byte) (interface{}, error) {
				pub, err := ed448.ParsePublicKey(b)
				return pub, err
			},
			func(b []byte) (interface{}, error) {
				pub, err := x448.ParsePublicKey(b)
				return pub, err
			},
			func(b []byte) (interface{}, error) {
				return kx509.ParsePKIXPublicKey(b)
			},
			func(b []byte) (interface{}, error) {
				pub, err := ecgdsa.ParsePublicKey(b)
				return pub, err
			},
			func(b []byte) (interface{}, error) {
				pub, err := ecsdsa.ParsePublicKey(b)
				return pub, err
			},
			func(b []byte) (interface{}, error) {
				pub, err := bip0340.ParsePublicKey(b)
				return pub, err
			},
			func(b []byte) (interface{}, error) {
				pub, err := bign.ParsePublicKey(b)
				return pub, err
			},
			func(b []byte) (interface{}, error) {
				pub, err := frp256v1.ParsePublicKey(b)
				return pub, err
			},
			func(b []byte) (interface{}, error) {
				pub, err := secp256k1.ParsePublicKey(b)
				return pub, err
			},
			func(b []byte) (interface{}, error) {
				pub, err := tom.ParsePublicKey(b)
				return pub, err
			},
		}
		var publicInterface interface{}
		for _, parser := range parsers {
			publicInterface, err = parser(block.Bytes)
			if err == nil {
				break
			}
		}
		if err != nil {
			log.Fatal("Failed to parse public key:", err)
		}

		switch publicInterface.(type) {
		case *rsa.PublicKey:
			publicKey := publicInterface.(*rsa.PublicKey)
			fmt.Printf("RSA (%v-bit)\n", publicKey.N.BitLen())
		case *ecdsa.PublicKey:
			publicKey := publicInterface.(*ecdsa.PublicKey)
			fmt.Printf("ECDSA (%v-bit)\n", publicKey.Curve.Params().BitSize)
		case *nums.PublicKey:
			publicKey := publicInterface.(*nums.PublicKey)
			curve := publicKey.Curve
			fmt.Printf("NUMS (%v-bit)\n", curve.Params().BitSize)
		case *frp256v1.PublicKey:
			publicKey := publicInterface.(*frp256v1.PublicKey)
			curve := publicKey.Curve
			fmt.Printf("ANSSI (%v-bit)\n", curve.Params().BitSize)
		case *secp256k1.PublicKey:
			publicKey := publicInterface.(*secp256k1.PublicKey)
			curve := publicKey.Curve
			fmt.Printf("KOBLITZ (%v-bit)\n", curve.Params().BitSize)
		case *eckcdsa.PublicKey:
			publicKey := publicInterface.(*eckcdsa.PublicKey)
			curve := publicKey.Curve
			fmt.Printf("ECKCDSA (%v-bit)\n", curve.Params().BitSize)
		case *tom.PublicKey:
			publicKey := publicInterface.(*tom.PublicKey)
			curve := publicKey.Curve
			fmt.Printf("Tom (%v-bit)\n", curve.Params().BitSize)
		case *ecgdsa.PublicKey:
			publicKey := publicInterface.(*ecgdsa.PublicKey)
			curve := publicKey.Curve
			fmt.Printf("ECGDSA (%v-bit)\n", curve.Params().BitSize)
		case *ecsdsa.PublicKey:
			publicKey := publicInterface.(*ecsdsa.PublicKey)
			curve := publicKey.Curve
			fmt.Printf("ECSDSA (%v-bit)\n", curve.Params().BitSize)
		case *bip0340.PublicKey:
			publicKey := publicInterface.(*bip0340.PublicKey)
			curve := publicKey.Curve
			fmt.Printf("BIP0340 (%v-bit)\n", curve.Params().BitSize)
		case *bign.PublicKey:
			publicKey := publicInterface.(*bign.PublicKey)
			curve := publicKey.Curve
			fmt.Printf("BIGN (%v-bit)\n", curve.Params().BitSize)
		case *ecdh.PublicKey:
			fmt.Println("X25519 (256-bit)")
		case ed25519.PublicKey:
			fmt.Println("Ed25519 (256-bit)")
		case ed448.PublicKey:
			fmt.Println("Ed448 (448-bit)")
		case x448.PublicKey:
			fmt.Println("X448 (448-bit)")
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

		parsers := []func([]byte) (interface{}, error){
			func(b []byte) (interface{}, error) {
				return smx509.ParsePKIXPublicKey(b)
			},
			func(b []byte) (interface{}, error) {
				return x509.ParsePKIXPublicKey(b)
			},
			func(b []byte) (interface{}, error) {
				return nums.ParsePublicKey(b)
			},
			func(b []byte) (interface{}, error) {
				pub, err := ed448.ParsePublicKey(b)
				return pub, err
			},
			func(b []byte) (interface{}, error) {
				pub, err := x448.ParsePublicKey(b)
				return pub, err
			},
			func(b []byte) (interface{}, error) {
				return kx509.ParsePKIXPublicKey(b)
			},
			func(b []byte) (interface{}, error) {
				pub, err := ecgdsa.ParsePublicKey(b)
				return pub, err
			},
			func(b []byte) (interface{}, error) {
				pub, err := ecsdsa.ParsePublicKey(b)
				return pub, err
			},
			func(b []byte) (interface{}, error) {
				pub, err := bip0340.ParsePublicKey(b)
				return pub, err
			},
			func(b []byte) (interface{}, error) {
				pub, err := bign.ParsePublicKey(b)
				return pub, err
			},
			func(b []byte) (interface{}, error) {
				pub, err := frp256v1.ParsePublicKey(b)
				return pub, err
			},
			func(b []byte) (interface{}, error) {
				pub, err := secp256k1.ParsePublicKey(b)
				return pub, err
			},
			func(b []byte) (interface{}, error) {
				pub, err := tom.ParsePublicKey(b)
				return pub, err
			},
		}
		var publicInterface interface{}
		for _, parser := range parsers {
			publicInterface, err = parser(block.Bytes)
			if err == nil {
				break
			}
		}
		if err != nil {
			log.Fatal("Failed to parse public key:", err)
		}

		var fingerprint string
		switch publicInterface.(type) {
		case *rsa.PublicKey, *ecdsa.PublicKey, *ecdh.PublicKey, ed25519.PublicKey:
			fingerprint = calculateFingerprint(buf)
		case *gost3410.PublicKey:
			fingerprint = calculateFingerprintGOST(buf)
		case *nums.PublicKey:
			fingerprint = calculateFingerprint(buf)
		case *frp256v1.PublicKey:
			fingerprint = calculateFingerprint(buf)
		case *secp256k1.PublicKey:
			fingerprint = calculateFingerprint(buf)
		case *eckcdsa.PublicKey:
			fingerprint = calculateFingerprint(buf)
		case *ecgdsa.PublicKey:
			fingerprint = calculateFingerprint(buf)
		case *ecsdsa.PublicKey:
			fingerprint = calculateFingerprint(buf)
		case *bip0340.PublicKey:
			fingerprint = calculateFingerprint(buf)
		case ed448.PublicKey:
			fingerprint = calculateFingerprint(buf)
		case x448.PublicKey:
			fingerprint = calculateFingerprint(buf)
		case *bign.PublicKey:
			fingerprint = calculateFingerprint(buf)
		case *tom.PublicKey:
			fingerprint = calculateFingerprint(buf)
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

		parsers := []func([]byte) (interface{}, error){
			func(b []byte) (interface{}, error) {
				return smx509.ParsePKIXPublicKey(b)
			},
			func(b []byte) (interface{}, error) {
				return x509.ParsePKIXPublicKey(b)
			},
			func(b []byte) (interface{}, error) {
				return nums.ParsePublicKey(b)
			},
			func(b []byte) (interface{}, error) {
				pub, err := ed448.ParsePublicKey(b)
				return pub, err
			},
			func(b []byte) (interface{}, error) {
				pub, err := x448.ParsePublicKey(b)
				return pub, err
			},
			func(b []byte) (interface{}, error) {
				return kx509.ParsePKIXPublicKey(b)
			},
			func(b []byte) (interface{}, error) {
				pub, err := ecgdsa.ParsePublicKey(b)
				return pub, err
			},
			func(b []byte) (interface{}, error) {
				pub, err := ecsdsa.ParsePublicKey(b)
				return pub, err
			},
			func(b []byte) (interface{}, error) {
				pub, err := bip0340.ParsePublicKey(b)
				return pub, err
			},
			func(b []byte) (interface{}, error) {
				pub, err := bign.ParsePublicKey(b)
				return pub, err
			},
			func(b []byte) (interface{}, error) {
				pub, err := frp256v1.ParsePublicKey(b)
				return pub, err
			},
			func(b []byte) (interface{}, error) {
				pub, err := secp256k1.ParsePublicKey(b)
				return pub, err
			},
			func(b []byte) (interface{}, error) {
				pub, err := tom.ParsePublicKey(b)
				return pub, err
			},
		}
		var publicInterface interface{}
		for _, parser := range parsers {
			publicInterface, err = parser(block.Bytes)
			if err == nil {
				break
			}
		}
		if err != nil {
			log.Fatal("Failed to parse public key:", err)
		}

		switch publicInterface.(type) {
		case *ecdh.PublicKey:
			*alg = "X25519"
		case ed25519.PublicKey:
			*alg = "ED25519"
		case ed448.PublicKey:
			*alg = "ED448"
		case x448.PublicKey:
			*alg = "X448"
		case *rsa.PublicKey:
			*alg = "RSA"
		case *ecdsa.PublicKey:
			*alg = "EC"
		case *eckcdsa.PublicKey:
			*alg = "ECKCDSA"
		case *ecgdsa.PublicKey:
			*alg = "ECGDSA"
		case *ecsdsa.PublicKey:
			*alg = "ECSDSA"
		case *bip0340.PublicKey:
			*alg = "BIP0340"
		case *nums.PublicKey:
			*alg = "NUMS"
		case *frp256v1.PublicKey:
			*alg = "ANSSI"
		case *secp256k1.PublicKey:
			*alg = "KOBLITZ"
		case *tom.PublicKey:
			*alg = "TOM"
		case *bign.PublicKey:
			*alg = "BIGN"
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
		} else if *pkey == "modulus" && (strings.ToUpper(*alg) == "NUMS") {
			var publicKey = publicInterface.(*nums.PublicKey)
			fmt.Printf("Public.X=%X\n", publicKey.X)
			fmt.Printf("Public.Y=%X\n", publicKey.Y)
			os.Exit(0)
		} else if *pkey == "modulus" && (strings.ToUpper(*alg) == "ANSSI") {
			var publicKey = publicInterface.(*frp256v1.PublicKey)
			fmt.Printf("Public.X=%X\n", publicKey.X)
			fmt.Printf("Public.Y=%X\n", publicKey.Y)
			os.Exit(0)
		} else if *pkey == "modulus" && (strings.ToUpper(*alg) == "KOBLITZ") {
			var publicKey = publicInterface.(*secp256k1.PublicKey)
			fmt.Printf("Public.X=%X\n", publicKey.X)
			fmt.Printf("Public.Y=%X\n", publicKey.Y)
			os.Exit(0)
		} else if *pkey == "modulus" && (strings.ToUpper(*alg) == "TOM") {
			var publicKey = publicInterface.(*tom.PublicKey)
			fmt.Printf("Public.X=%X\n", publicKey.X)
			fmt.Printf("Public.Y=%X\n", publicKey.Y)
			os.Exit(0)
		} else if *pkey == "modulus" && (strings.ToUpper(*alg) == "BIGN") {
			var publicKey = publicInterface.(*bign.PublicKey)
			fmt.Printf("Public.X=%X\n", publicKey.X)
			fmt.Printf("Public.Y=%X\n", publicKey.Y)
			os.Exit(0)
		} else if *pkey == "modulus" && (strings.ToUpper(*alg) == "ECKCDSA") {
			var publicKey = publicInterface.(*eckcdsa.PublicKey)
			fmt.Printf("Public.X=%X\n", publicKey.X)
			fmt.Printf("Public.Y=%X\n", publicKey.Y)
			os.Exit(0)
		} else if *pkey == "modulus" && (strings.ToUpper(*alg) == "ECGDSA") {
			var publicKey = publicInterface.(*ecgdsa.PublicKey)
			fmt.Printf("Public.X=%X\n", publicKey.X)
			fmt.Printf("Public.Y=%X\n", publicKey.Y)
			os.Exit(0)
		} else if *pkey == "modulus" && (strings.ToUpper(*alg) == "ECSDSA") {
			var publicKey = publicInterface.(*ecsdsa.PublicKey)
			fmt.Printf("Public.X=%X\n", publicKey.X)
			fmt.Printf("Public.Y=%X\n", publicKey.Y)
			os.Exit(0)
		} else if *pkey == "modulus" && (strings.ToUpper(*alg) == "BIP0340") {
			var publicKey = publicInterface.(*bip0340.PublicKey)
			fmt.Printf("Public.X=%X\n", publicKey.X)
			fmt.Printf("Public.Y=%X\n", publicKey.Y)
			os.Exit(0)
		} else if *pkey == "modulus" && (strings.ToUpper(*alg) == "ED25519") {
			var publicKey = publicInterface.(ed25519.PublicKey)
			fmt.Printf("Public=%X\n", publicKey)
			os.Exit(0)
		} else if *pkey == "modulus" && (strings.ToUpper(*alg) == "ED448") {
			var publicKey = publicInterface.(ed448.PublicKey)
			fmt.Printf("Public=%X\n", publicKey)
			os.Exit(0)
		} else if *pkey == "modulus" && (strings.ToUpper(*alg) == "X448") {
			var publicKey = publicInterface.(x448.PublicKey)
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

			fmt.Printf("Public-Key:\n")
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
			fmt.Println("Curve: ed25519")
			skid := sha1.Sum(spki.SubjectPublicKey.Bytes)
			fmt.Printf("\nKeyID: %x \n", skid)
		} else if strings.ToUpper(*alg) == "ED448" {
			publicKey := publicInterface.(ed448.PublicKey)
			derBytes, err := ed448.MarshalPublicKey(publicKey)
			if err != nil {
				log.Fatal(err)
			}
			block := &pem.Block{
				Type:  "ED448 PUBLIC KEY",
				Bytes: derBytes,
			}
			public := pem.EncodeToMemory(block)
			fmt.Printf(string(public))

			fmt.Printf("Public-Key:\n")
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
			fmt.Println("Curve: ed448")
			skid := sha1.Sum(spki.SubjectPublicKey.Bytes)
			fmt.Printf("\nKeyID: %x \n", skid)
		} else if strings.ToUpper(*alg) == "X448" {
			publicKey := publicInterface.(x448.PublicKey)
			derBytes, err := x448.MarshalPublicKey(publicKey)
			if err != nil {
				log.Fatal(err)
			}
			block := &pem.Block{
				Type:  "X448 PUBLIC KEY",
				Bytes: derBytes,
			}
			public := pem.EncodeToMemory(block)
			fmt.Printf(string(public))

			fmt.Printf("Public-Key:\n")
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
			fmt.Println("Curve: x448")
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

			fmt.Printf("Public-Key:\n")
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
			fmt.Println("Curve: x25519")
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
		} else if strings.ToUpper(*alg) == "ECKCDSA" {
			publicKey := publicInterface.(*eckcdsa.PublicKey)
			derBytes, err := kx509.MarshalPKIXPublicKey(publicKey)
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
		} else if strings.ToUpper(*alg) == "ECGDSA" {
			publicKey := publicInterface.(*ecgdsa.PublicKey)
			derBytes, err := ecgdsa.MarshalPublicKey(publicKey)
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
		} else if strings.ToUpper(*alg) == "ECSDSA" {
			publicKey := publicInterface.(*ecsdsa.PublicKey)
			derBytes, err := ecsdsa.MarshalPublicKey(publicKey)
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
		} else if strings.ToUpper(*alg) == "BIP0340" {
			publicKey := publicInterface.(*bip0340.PublicKey)
			derBytes, err := bip0340.MarshalPublicKey(publicKey)
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
		} else if strings.ToUpper(*alg) == "ANSSI" {
			publicKey := publicInterface.(*frp256v1.PublicKey)
			curve := publicKey.Curve
			derBytes, err := publicKey.MarshalPKCS8PublicKey(curve)
			if err != nil {
				log.Fatal(err)
			}
			block := &pem.Block{
				Type:  "PUBLIC KEY",
				Bytes: derBytes,
			}
			public := pem.EncodeToMemory(block)
			fmt.Printf(string(public))

			fmt.Printf("Public-Key: (%v-bit)\n", curve.Params().BitSize)
			x := publicKey.X.Bytes()
			if n := len(x); n < 24 && n < 32 && n < 48 && n < 64 {
				x = append(zeroByteSlice()[:(curve.Params().BitSize/8)-n], x...)
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
				y = append(zeroByteSlice()[:(curve.Params().BitSize/8)-n], y...)
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
				x = append(zeroByteSlice()[:(curve.Params().BitSize/8)-n], x...)
			}
			if n := len(y); n < 24 && n < 32 && n < 48 && n < 64 {
				y = append(zeroByteSlice()[:(curve.Params().BitSize/8)-n], y...)
			}
			c = []byte{}
			c = append(c, x...)
			c = append(c, y...)
			c = append([]byte{0x04}, c...)
			splitz = SplitSubN(hex.EncodeToString(c), 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}
			fmt.Printf("Curve: %s\n", publicKey.Curve.Params().Name)
		} else if strings.ToUpper(*alg) == "KOBLITZ" {
			publicKey := publicInterface.(*secp256k1.PublicKey)
			curve := publicKey.Curve
			derBytes, err := publicKey.MarshalPKCS8PublicKey(curve)
			if err != nil {
				log.Fatal(err)
			}
			block := &pem.Block{
				Type:  "PUBLIC KEY",
				Bytes: derBytes,
			}
			public := pem.EncodeToMemory(block)
			fmt.Printf(string(public))

			fmt.Printf("Public-Key: (%v-bit)\n", curve.Params().BitSize)
			x := publicKey.X.Bytes()
			if n := len(x); n < 24 && n < 32 && n < 48 && n < 64 {
				x = append(zeroByteSlice()[:(curve.Params().BitSize/8)-n], x...)
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
				y = append(zeroByteSlice()[:(curve.Params().BitSize/8)-n], y...)
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
				x = append(zeroByteSlice()[:(curve.Params().BitSize/8)-n], x...)
			}
			if n := len(y); n < 24 && n < 32 && n < 48 && n < 64 {
				y = append(zeroByteSlice()[:(curve.Params().BitSize/8)-n], y...)
			}
			c = []byte{}
			c = append(c, x...)
			c = append(c, y...)
			c = append([]byte{0x04}, c...)
			splitz = SplitSubN(hex.EncodeToString(c), 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}
			fmt.Printf("Curve: %s\n", publicKey.Curve.Params().Name)
		} else if strings.ToUpper(*alg) == "TOM" {
			publicKey := publicInterface.(*tom.PublicKey)
			curve := publicKey.Curve
			derBytes, err := publicKey.MarshalPKCS8PublicKey(curve)
			if err != nil {
				log.Fatal(err)
			}
			block := &pem.Block{
				Type:  "PUBLIC KEY",
				Bytes: derBytes,
			}
			public := pem.EncodeToMemory(block)
			fmt.Printf(string(public))

			fmt.Printf("Public-Key: (%v-bit)\n", curve.Params().BitSize)
			x := publicKey.X.Bytes()
			if n := len(x); n < 24 && n < 32 && n < 48 && n < 64 {
				x = append(zeroByteSlice()[:(curve.Params().BitSize/8)-n], x...)
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
				y = append(zeroByteSlice()[:(curve.Params().BitSize/8)-n], y...)
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
				x = append(zeroByteSlice()[:(curve.Params().BitSize/8)-n], x...)
			}
			if n := len(y); n < 24 && n < 32 && n < 48 && n < 64 {
				y = append(zeroByteSlice()[:(curve.Params().BitSize/8)-n], y...)
			}
			c = []byte{}
			c = append(c, x...)
			c = append(c, y...)
			c = append([]byte{0x04}, c...)
			splitz = SplitSubN(hex.EncodeToString(c), 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}
			fmt.Printf("Curve: %s\n", publicKey.Curve.Params().Name)
		} else if strings.ToUpper(*alg) == "BIGN" {
			publicKey := publicInterface.(*bign.PublicKey)
			derBytes, err := bign.MarshalPublicKey(publicKey)
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
		} else if strings.ToUpper(*alg) == "NUMS" {
			publicKey := publicInterface.(*nums.PublicKey)
			curve := publicKey.Curve
			derBytes, err := publicKey.MarshalPKCS8PublicKey(curve)
			if err != nil {
				log.Fatal(err)
			}
			block := &pem.Block{
				Type:  "PUBLIC KEY",
				Bytes: derBytes,
			}
			public := pem.EncodeToMemory(block)
			fmt.Printf(string(public))

			fmt.Printf("Public-Key: (%v-bit)\n", curve.Params().BitSize)
			x := publicKey.X.Bytes()
			if n := len(x); n < 24 && n < 32 && n < 48 && n < 64 {
				x = append(zeroByteSlice()[:(curve.Params().BitSize/8)-n], x...)
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
				y = append(zeroByteSlice()[:(curve.Params().BitSize/8)-n], y...)
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
				x = append(zeroByteSlice()[:(curve.Params().BitSize/8)-n], x...)
			}
			if n := len(y); n < 24 && n < 32 && n < 48 && n < 64 {
				y = append(zeroByteSlice()[:(curve.Params().BitSize/8)-n], y...)
			}
			c = []byte{}
			c = append(c, x...)
			c = append(c, y...)
			c = append([]byte{0x04}, c...)
			splitz = SplitSubN(hex.EncodeToString(c), 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}
			fmt.Printf("Curve: %s\n", publicKey.Curve.Params().Name)
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
		} else if strings.ToUpper(*alg) == "ECKCDSA" {
			var privKey, err = kx509.ParsePKCS8PrivateKey(privateKeyPemBlock.Bytes)
			if err != nil {
				log.Fatal(err)
			}
			eckcdsaPrivKey, ok := privKey.(*eckcdsa.PrivateKey)
			if !ok {
				log.Fatalf("expected an ECKCDSA key but received another type")
			}
			derBytes, err := kx509.MarshalPKIXPublicKey(&eckcdsaPrivKey.PublicKey)
			if err != nil {
				log.Fatal(err)
			}
			if *pkey == "modulus" {
				fmt.Printf("Public.X=%X\n", eckcdsaPrivKey.PublicKey.X)
				fmt.Printf("Public.Y=%X\n", eckcdsaPrivKey.PublicKey.Y)
				os.Exit(0)
			}
			fmt.Printf(string(privPEM))
			d := eckcdsaPrivKey.D.Bytes()
			if n := len(d); n < 24 && n < 32 && n < 48 && n < 64 {
				d = append(zeroByteSlice()[:(eckcdsaPrivKey.Curve.Params().BitSize/8)-n], d...)
			}
			c := []byte{}
			c = append(c, d...)
			fmt.Printf("Private-Key: (%v-bit)\n", eckcdsaPrivKey.Curve.Params().BitSize)
			fmt.Printf("priv: \n")
			splitz := SplitSubN(hex.EncodeToString(c), 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}

			publicKey := eckcdsaPrivKey.PublicKey
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
		} else if strings.ToUpper(*alg) == "ECGDSA" {
			var privKey, err = ecgdsa.ParsePrivateKey(privateKeyPemBlock.Bytes)
			if err != nil {
				log.Fatal(err)
			}
			derBytes, err := ecgdsa.MarshalPublicKey(&privKey.PublicKey)
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
		} else if strings.ToUpper(*alg) == "ECSDSA" {
			var privKey, err = ecsdsa.ParsePrivateKey(privateKeyPemBlock.Bytes)
			if err != nil {
				log.Fatal(err)
			}
			derBytes, err := ecsdsa.MarshalPublicKey(&privKey.PublicKey)
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
		} else if strings.ToUpper(*alg) == "BIP0340" {
			var privKey, err = bip0340.ParsePrivateKey(privateKeyPemBlock.Bytes)
			if err != nil {
				log.Fatal(err)
			}
			derBytes, err := bip0340.MarshalPublicKey(&privKey.PublicKey)
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
		} else if strings.ToUpper(*alg) == "ANSSI" {
			var privKey, err = frp256v1.ParsePrivateKey(privateKeyPemBlock.Bytes)
			if err != nil {
				log.Fatal(err)
			}
			curve := privKey.PublicKey.Curve

			pub := &privKey.PublicKey
			derBytes, err := pub.MarshalPKCS8PublicKey(curve)
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
				d = append(zeroByteSlice()[:(curve.Params().BitSize/8)-n], d...)
			}
			c := []byte{}
			c = append(c, d...)
			fmt.Printf("Private-Key: (%v-bit)\n", curve.Params().BitSize)
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
				x = append(zeroByteSlice()[:(curve.Params().BitSize/8)-n], x...)
			}
			if n := len(y); n < 24 && n < 32 && n < 48 && n < 64 {
				y = append(zeroByteSlice()[:(curve.Params().BitSize/8)-n], y...)
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
			fmt.Printf("Curve: %s\n", publicKey.Curve.Params().Name)
			skid := sha1.Sum(spki.SubjectPublicKey.Bytes)
			fmt.Printf("\nKeyID: %x \n", skid)
		} else if strings.ToUpper(*alg) == "KOBLITZ" {
			var privKey, err = secp256k1.ParsePrivateKey(privateKeyPemBlock.Bytes)
			if err != nil {
				log.Fatal(err)
			}
			curve := privKey.PublicKey.Curve

			pub := &privKey.PublicKey
			derBytes, err := pub.MarshalPKCS8PublicKey(curve)
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
				d = append(zeroByteSlice()[:(curve.Params().BitSize/8)-n], d...)
			}
			c := []byte{}
			c = append(c, d...)
			fmt.Printf("Private-Key: (%v-bit)\n", curve.Params().BitSize)
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
				x = append(zeroByteSlice()[:(curve.Params().BitSize/8)-n], x...)
			}
			if n := len(y); n < 24 && n < 32 && n < 48 && n < 64 {
				y = append(zeroByteSlice()[:(curve.Params().BitSize/8)-n], y...)
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
			fmt.Printf("Curve: %s\n", publicKey.Curve.Params().Name)
			skid := sha1.Sum(spki.SubjectPublicKey.Bytes)
			fmt.Printf("\nKeyID: %x \n", skid)
		} else if strings.ToUpper(*alg) == "TOM" {
			var privKey, err = tom.ParsePrivateKey(privateKeyPemBlock.Bytes)
			if err != nil {
				log.Fatal(err)
			}
			curve := privKey.PublicKey.Curve

			pub := &privKey.PublicKey
			derBytes, err := pub.MarshalPKCS8PublicKey(curve)
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
				d = append(zeroByteSlice()[:(curve.Params().BitSize/8)-n], d...)
			}
			c := []byte{}
			c = append(c, d...)
			fmt.Printf("Private-Key: (%v-bit)\n", curve.Params().BitSize)
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
				x = append(zeroByteSlice()[:(curve.Params().BitSize/8)-n], x...)
			}
			if n := len(y); n < 24 && n < 32 && n < 48 && n < 64 {
				y = append(zeroByteSlice()[:(curve.Params().BitSize/8)-n], y...)
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
			fmt.Printf("Curve: %s\n", publicKey.Curve.Params().Name)
			skid := sha1.Sum(spki.SubjectPublicKey.Bytes)
			fmt.Printf("\nKeyID: %x \n", skid)
		} else if strings.ToUpper(*alg) == "BIGN" {
			var privKey, err = bign.ParsePrivateKey(privateKeyPemBlock.Bytes)
			if err != nil {
				log.Fatal(err)
			}
			derBytes, err := bign.MarshalPublicKey(&privKey.PublicKey)
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
		} else if strings.ToUpper(*alg) == "NUMS" {
			var privKey, err = nums.ParsePrivateKey(privateKeyPemBlock.Bytes)
			if err != nil {
				log.Fatal(err)
			}
			curve := privKey.PublicKey.Curve
			pub := &privKey.PublicKey
			derBytes, err := pub.MarshalPKCS8PublicKey(curve)
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
				d = append(zeroByteSlice()[:(curve.Params().BitSize/8)-n], d...)
			}
			c := []byte{}
			c = append(c, d...)
			fmt.Printf("Private-Key: (%v-bit)\n", curve.Params().BitSize)
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
				x = append(zeroByteSlice()[:(curve.Params().BitSize/8)-n], x...)
			}
			if n := len(y); n < 24 && n < 32 && n < 48 && n < 64 {
				y = append(zeroByteSlice()[:(curve.Params().BitSize/8)-n], y...)
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
			fmt.Printf("Curve: %s\n", publicKey.Curve.Params().Name)
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
			fmt.Printf("Private-Key:\n")
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
			fmt.Println("Curve: ed25519")
			skid := sha1.Sum(spki.SubjectPublicKey.Bytes)
			fmt.Printf("\nKeyID: %x \n", skid)
		} else if strings.ToUpper(*alg) == "ED448" {
			var privKey, _ = ed448.ParsePrivateKey(privateKeyPemBlock.Bytes)
			if err != nil {
				log.Fatal(err)
			}
			edKey := privKey

			if *pkey == "modulus" {
				fmt.Printf("Public=%X\n", edKey.Public())
				os.Exit(0)
			}

			fmt.Printf(string(privPEM))
			derBytes, err := ed448.MarshalPublicKey(edKey.Public().(ed448.PublicKey))
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("Private-Key:\n")
			p := fmt.Sprintf("%x", privKey)
			fmt.Printf("priv: \n")
			splitz := SplitSubN(p[:114], 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}
			fmt.Printf("pub: \n")
			splitz = SplitSubN(p[114:], 2)
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
			fmt.Println("Curve: ed448")
			skid := sha1.Sum(spki.SubjectPublicKey.Bytes)
			fmt.Printf("\nKeyID: %x \n", skid)
		} else if strings.ToUpper(*alg) == "X448" {
			var privKey, _ = x448.ParsePrivateKey(privateKeyPemBlock.Bytes)
			if err != nil {
				log.Fatal(err)
			}
			edKey := privKey

			if *pkey == "modulus" {
				fmt.Printf("Public=%X\n", edKey.Public())
				os.Exit(0)
			}

			fmt.Printf(string(privPEM))
			derBytes, err := x448.MarshalPublicKey(edKey.Public().(x448.PublicKey))
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("Private-Key:\n")
			p := fmt.Sprintf("%x", privKey)
			fmt.Printf("priv: \n")
			splitz := SplitSubN(p[:112], 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
				fmt.Printf("    %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
			}
			fmt.Printf("pub: \n")
			splitz = SplitSubN(p[112:], 2)
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
			fmt.Println("Curve: x448")
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
			fmt.Printf("Private-Key:\n")
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
			fmt.Println("Curve: x25519")
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

		if *subj == "" {
			println("You are about to be asked to enter information \nthat will be incorporated into your certificate.")

			scanner := bufio.NewScanner(os.Stdin)

			print("Common Name: ")
			scanner.Scan()
			name = scanner.Text()

			print("Country Name (2 letter code) [AU]: ")
			scanner.Scan()
			country = scanner.Text()

			print("State or Province Name (full name) [Some-State]: ")
			scanner.Scan()
			province = scanner.Text()

			print("Locality Name (eg, city): ")
			scanner.Scan()
			locality = scanner.Text()

			print("Organization Name (eg, company) [Internet Widgits Pty Ltd]: ")
			scanner.Scan()
			organization = scanner.Text()

			print("Organizational Unit Name (eg, section): ")
			scanner.Scan()
			organizationunit = scanner.Text()

			print("Email Address []: ")
			scanner.Scan()
			email = scanner.Text()

			print("StreetAddress: ")
			scanner.Scan()
			street = scanner.Text()

			print("PostalCode: ")
			scanner.Scan()
			postalcode = scanner.Text()

			print("SerialNumber: ")
			scanner.Scan()
			number = scanner.Text()
		} else {
			name, number, country, province, locality, organization, organizationunit, street, email, postalcode, err = parseSubjectString(*subj)
			if err != nil {
				log.Fatal(err)
			}
		}

		var validity string

		if *days > 0 {
			validity = fmt.Sprintf("%d", *days)
		} else {
			fmt.Print("Validity (in Days): ")
			fmt.Scanln(&validity)
		}

		intVar, err := strconv.Atoi(validity)
		if err != nil {
			log.Fatal(err)
		}
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

		if *subj == "" {
			println("You are about to be asked to enter information \nthat will be incorporated into your certificate.")

			scanner := bufio.NewScanner(os.Stdin)

			print("Common Name: ")
			scanner.Scan()
			name = scanner.Text()

			print("Country Name (2 letter code) [AU]: ")
			scanner.Scan()
			country = scanner.Text()

			print("State or Province Name (full name) [Some-State]: ")
			scanner.Scan()
			province = scanner.Text()

			print("Locality Name (eg, city): ")
			scanner.Scan()
			locality = scanner.Text()

			print("Organization Name (eg, company) [Internet Widgits Pty Ltd]: ")
			scanner.Scan()
			organization = scanner.Text()

			print("Organizational Unit Name (eg, section): ")
			scanner.Scan()
			organizationunit = scanner.Text()

			print("Email Address []: ")
			scanner.Scan()
			email = scanner.Text()

			print("StreetAddress: ")
			scanner.Scan()
			street = scanner.Text()

			print("PostalCode: ")
			scanner.Scan()
			postalcode = scanner.Text()

			print("SerialNumber: ")
			scanner.Scan()
			number = scanner.Text()
		} else {
			name, number, country, province, locality, organization, organizationunit, street, email, postalcode, err = parseSubjectString(*subj)
			if err != nil {
				log.Fatal(err)
			}
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
		fmt.Println("    Data:")
		fmt.Printf("        Number             : %d (%X)\n", revocationList.Number, revocationList.Number)
		fmt.Println("        Last Update        :", crl.TBSCertList.ThisUpdate)
		fmt.Println("        Next Update        :", crl.TBSCertList.NextUpdate)

		fmt.Println("        Issuer")
		fmt.Println("            ", crl.TBSCertList.Issuer)

		fmt.Printf("        Authority Key ID   : %x\n", akid)

		algoName := getAlgorithmName(crl.SignatureAlgorithm.Algorithm.String())
		fmt.Println("    Signature Algorithm:", algoName)

		splitz := SplitSubN(hex.EncodeToString(crl.SignatureValue.Bytes), 2)
		for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
			fmt.Printf("        %-10s            \n", strings.ReplaceAll(chunk, " ", ":"))
		}

		fmt.Println("    Revoked Certificates:")
		for _, revokedCert := range revocationList.RevokedCertificates {
			fmt.Printf("    - Serial Number: %X\n", revokedCert.SerialNumber)
			fmt.Println("      Revocation Time:", revokedCert.RevocationTime)
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
				EmailAddresses: []string{email},

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
			if err != nil {
				log.Fatal(err)
			}
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
			if err != nil {
				log.Fatal(err)
			}
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
				privKeyBytes2, err = DecryptPEMBlock(block, []byte(*pwd2))
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
			if err != nil {
				log.Fatal(err)
			}
			enccert, err = tlcp.X509KeyPair(enccertPEM, encprivPEM)
			if err != nil {
				log.Fatal(err)
			}

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
			if err != nil {
				log.Fatal(err)
			}

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
		var sigcertPEM []byte
		var sigprivPEM []byte
		var enccertPEM []byte
		var encprivPEM []byte

		if *tcpip == "server" {
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
				privKeyBytes2, err = DecryptPEMBlock(block, []byte(*pwd2))
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

		if *tcpip == "server" {
			var sigcert tlcp.Certificate
			var enccert tlcp.Certificate
			sigcert, err = tlcp.X509KeyPair(sigcertPEM, sigprivPEM)
			if err != nil {
				log.Fatal(err)
			}
			enccert, err = tlcp.X509KeyPair(enccertPEM, encprivPEM)
			if err != nil {
				log.Fatal(err)
			}

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

	if *change {
		err := ChangePrivateKeyPassword(*key, *pwd, *pwd2)
		if err != nil {
			fmt.Println("Error changing the password:", err)
		} else {
			fmt.Println("Password changed successfully.")
		}
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
	switch *md {
	case "md5":
		myHash = md5.New()
	case "sha224":
		myHash = sha256.New224()
	case "sha256":
		myHash = sha256.New()
	case "sha384":
		myHash = sha512.New384()
	case "sha512":
		myHash = sha512.New()
	case "sha1":
		myHash = sha1.New()
	case "rmd160", "ripemd160":
		myHash = ripemd160.New()
	default:
		return nil, fmt.Errorf("unsupported hash algorithm: '%s'. Supported algorithms are: md5, sha1, sha224, sha256, sha384, sha512, ripemd160", *md)
	}

	myHash.Write(sourceData)
	hashRes := myHash.Sum(nil)
	var res []byte
	if *md == "md5" {
		res, err = rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.MD5, hashRes)
		if err != nil {
			return msg, err
		}
	} else if *md == "rmd160" || *md == "ripemd160" {
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
	switch *md {
	case "md5":
		mySha = md5.New()
	case "sha224":
		mySha = sha256.New224()
	case "sha256":
		mySha = sha256.New()
	case "sha384":
		mySha = sha512.New384()
	case "sha512":
		mySha = sha512.New()
	case "sha1":
		mySha = sha1.New()
	case "rmd160", "ripemd160":
		mySha = ripemd160.New()
	default:
		return fmt.Errorf("unsupported hash algorithm: '%s'. Supported algorithms are: md5, sha1, sha224, sha256, sha384, sha512, ripemd160", *md)
	}
	mySha.Write(sourceData)
	res := mySha.Sum(nil)
	if *md == "md5" {
		err = rsa.VerifyPKCS1v15(publicKey, crypto.MD5, res, signedData)
		if err != nil {
			return err
		}
	} else if *md == "rmd160" || *md == "ripemd160" {
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
		err = EncryptAndWriteBlock(*cph, block, []byte(*pwd), file)
		if err != nil {
			log.Fatal(err)
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
		encryptedBlock, err := EncryptBlockWithCipher(rand.Reader, keyBlock.Type, keyBlock.Bytes, []byte(*pwd), *cph)
		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(encryptedBlock), nil
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
		encryptedBlock, err := EncryptBlockWithCipher(rand.Reader, keyBlock.Type, keyBlock.Bytes, []byte(*pwd), *cph)
		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(encryptedBlock), nil
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

func EncodeECKCDSAPrivateKey(key *eckcdsa.PrivateKey) ([]byte, error) {
	derKey, err := kx509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	keyBlock := &pem.Block{
		Type:  "ECKCDSA PRIVATE KEY",
		Bytes: derKey,
	}
	if *pwd != "" {
		encryptedBlock, err := EncryptBlockWithCipher(rand.Reader, keyBlock.Type, keyBlock.Bytes, []byte(*pwd), *cph)
		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(encryptedBlock), nil
	} else {
		return pem.EncodeToMemory(keyBlock), nil
	}
}

func DecodeECKCDSAPrivateKey(encodedKey []byte) (*eckcdsa.PrivateKey, error) {
	var skippedTypes []string
	var block *pem.Block
	for {
		block, encodedKey = pem.Decode(encodedKey)
		if block == nil {
			return nil, fmt.Errorf("failed to find EC PRIVATE KEY in PEM data after skipping types %v", skippedTypes)
		}

		if block.Type == "ECKCDSA PRIVATE KEY" {
			break
		} else {
			skippedTypes = append(skippedTypes, block.Type)
			continue
		}
	}

	var privKey *eckcdsa.PrivateKey
	var privKeyBytes []byte
	var err error
	if IsEncryptedPEMBlock(block) {
		privKeyBytes, err = DecryptPEMBlock(block, []byte(*pwd))
		if err != nil {
			return nil, errors.New("could not decrypt private key")
		}
	} else {
		privKeyBytes = block.Bytes
	}

	parsedKey, err := kx509.ParsePKCS8PrivateKey(privKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#8 private key: %v", err)
	}

	privKey, ok := parsedKey.(*eckcdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("parsed key is not of type *eckcdsa.PrivateKey")
	}

	return privKey, nil
}

func EncodeECKCDSAPublicKey(key *eckcdsa.PublicKey) ([]byte, error) {
	derBytes, err := kx509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, err
	}
	block := &pem.Block{
		Type:  "ECKCDSA PUBLIC KEY",
		Bytes: derBytes,
	}
	return pem.EncodeToMemory(block), nil
}

func DecodeECKCDSAPublicKey(encodedKey []byte) (*eckcdsa.PublicKey, error) {
	block, _ := pem.Decode(encodedKey)
	if block == nil || block.Type != "ECKCDSA PUBLIC KEY" {
		return nil, fmt.Errorf("marshal: could not decode PEM block type %s", block.Type)
	}

	publicKey, err := kx509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	eckcdsaPublicKey, ok := publicKey.(*eckcdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("parsed key is not of type *eckcdsa.PublicKey")
	}

	return eckcdsaPublicKey, nil
}

func EncodeECGDSAPrivateKey(key *ecgdsa.PrivateKey) ([]byte, error) {
	derKey, err := ecgdsa.MarshalPrivateKey(key)
	if err != nil {
		return nil, err
	}
	keyBlock := &pem.Block{
		Type:  "ECGDSA PRIVATE KEY",
		Bytes: derKey,
	}
	if *pwd != "" {
		encryptedBlock, err := EncryptBlockWithCipher(rand.Reader, keyBlock.Type, keyBlock.Bytes, []byte(*pwd), *cph)
		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(encryptedBlock), nil
	} else {
		return pem.EncodeToMemory(keyBlock), nil
	}
}

func DecodeECGDSAPrivateKey(encodedKey []byte) (*ecgdsa.PrivateKey, error) {
	var skippedTypes []string
	var block *pem.Block
	for {
		block, encodedKey = pem.Decode(encodedKey)
		if block == nil {
			return nil, fmt.Errorf("failed to find EC PRIVATE KEY in PEM data after skipping types %v", skippedTypes)
		}

		if block.Type == "ECGDSA PRIVATE KEY" {
			break
		} else {
			skippedTypes = append(skippedTypes, block.Type)
			continue
		}
	}
	var privKey *ecgdsa.PrivateKey
	var privKeyBytes []byte
	var err error
	if IsEncryptedPEMBlock(block) {
		privKeyBytes, err = DecryptPEMBlock(block, []byte(*pwd))
		if err != nil {
			return nil, errors.New("could not decrypt private key")
		}
		privKey, _ = ecgdsa.ParsePrivateKey(privKeyBytes)
	} else {
		privKey, _ = ecgdsa.ParsePrivateKey(block.Bytes)
	}
	return privKey, nil
}

func EncodeECGDSAPublicKey(key *ecgdsa.PublicKey) ([]byte, error) {
	derBytes, err := ecgdsa.MarshalPublicKey(key)
	if err != nil {
		return nil, err
	}
	block := &pem.Block{
		Type:  "ECGDSA PUBLIC KEY",
		Bytes: derBytes,
	}
	return pem.EncodeToMemory(block), nil
}

func DecodeECGDSAPublicKey(encodedKey []byte) (*ecgdsa.PublicKey, error) {
	block, _ := pem.Decode(encodedKey)
	if block == nil || block.Type != "ECGDSA PUBLIC KEY" {
		return nil, fmt.Errorf("marshal: could not decode PEM block type %s", block.Type)

	}
	public, err := ecgdsa.ParsePublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return public, nil
}

func EncodeECSDSAPrivateKey(key *ecsdsa.PrivateKey) ([]byte, error) {
	derKey, err := ecsdsa.MarshalPrivateKey(key)
	if err != nil {
		return nil, err
	}
	keyBlock := &pem.Block{
		Type:  "ECSDSA PRIVATE KEY",
		Bytes: derKey,
	}
	if *pwd != "" {
		encryptedBlock, err := EncryptBlockWithCipher(rand.Reader, keyBlock.Type, keyBlock.Bytes, []byte(*pwd), *cph)
		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(encryptedBlock), nil
	} else {
		return pem.EncodeToMemory(keyBlock), nil
	}
}

func DecodeECSDSAPrivateKey(encodedKey []byte) (*ecsdsa.PrivateKey, error) {
	var skippedTypes []string
	var block *pem.Block
	for {
		block, encodedKey = pem.Decode(encodedKey)
		if block == nil {
			return nil, fmt.Errorf("failed to find EC PRIVATE KEY in PEM data after skipping types %v", skippedTypes)
		}

		if block.Type == "ECSDSA PRIVATE KEY" {
			break
		} else {
			skippedTypes = append(skippedTypes, block.Type)
			continue
		}
	}
	var privKey *ecsdsa.PrivateKey
	var privKeyBytes []byte
	var err error
	if IsEncryptedPEMBlock(block) {
		privKeyBytes, err = DecryptPEMBlock(block, []byte(*pwd))
		if err != nil {
			return nil, errors.New("could not decrypt private key")
		}
		privKey, _ = ecsdsa.ParsePrivateKey(privKeyBytes)
	} else {
		privKey, _ = ecsdsa.ParsePrivateKey(block.Bytes)
	}
	return privKey, nil
}

func EncodeECSDSAPublicKey(key *ecsdsa.PublicKey) ([]byte, error) {
	derBytes, err := ecsdsa.MarshalPublicKey(key)
	if err != nil {
		return nil, err
	}
	block := &pem.Block{
		Type:  "ECSDSA PUBLIC KEY",
		Bytes: derBytes,
	}
	return pem.EncodeToMemory(block), nil
}

func DecodeECSDSAPublicKey(encodedKey []byte) (*ecsdsa.PublicKey, error) {
	block, _ := pem.Decode(encodedKey)
	if block == nil || block.Type != "ECSDSA PUBLIC KEY" {
		return nil, fmt.Errorf("marshal: could not decode PEM block type %s", block.Type)

	}
	public, err := ecsdsa.ParsePublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return public, nil
}

func EncodeBIP0340PrivateKey(key *bip0340.PrivateKey) ([]byte, error) {
	derKey, err := bip0340.MarshalPrivateKey(key)
	if err != nil {
		return nil, err
	}
	keyBlock := &pem.Block{
		Type:  "BIP0340 PRIVATE KEY",
		Bytes: derKey,
	}
	if *pwd != "" {
		encryptedBlock, err := EncryptBlockWithCipher(rand.Reader, keyBlock.Type, keyBlock.Bytes, []byte(*pwd), *cph)
		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(encryptedBlock), nil
	} else {
		return pem.EncodeToMemory(keyBlock), nil
	}
}

func DecodeBIP0340PrivateKey(encodedKey []byte) (*bip0340.PrivateKey, error) {
	var skippedTypes []string
	var block *pem.Block
	for {
		block, encodedKey = pem.Decode(encodedKey)
		if block == nil {
			return nil, fmt.Errorf("failed to find EC PRIVATE KEY in PEM data after skipping types %v", skippedTypes)
		}

		if block.Type == "BIP0340 PRIVATE KEY" {
			break
		} else {
			skippedTypes = append(skippedTypes, block.Type)
			continue
		}
	}
	var privKey *bip0340.PrivateKey
	var privKeyBytes []byte
	var err error
	if IsEncryptedPEMBlock(block) {
		privKeyBytes, err = DecryptPEMBlock(block, []byte(*pwd))
		if err != nil {
			return nil, errors.New("could not decrypt private key")
		}
		privKey, _ = bip0340.ParsePrivateKey(privKeyBytes)
	} else {
		privKey, _ = bip0340.ParsePrivateKey(block.Bytes)
	}
	return privKey, nil
}

func EncodeBIP0340PublicKey(key *bip0340.PublicKey) ([]byte, error) {
	derBytes, err := bip0340.MarshalPublicKey(key)
	if err != nil {
		return nil, err
	}
	block := &pem.Block{
		Type:  "BIP0340 PUBLIC KEY",
		Bytes: derBytes,
	}
	return pem.EncodeToMemory(block), nil
}

func DecodeBIP0340PublicKey(encodedKey []byte) (*bip0340.PublicKey, error) {
	block, _ := pem.Decode(encodedKey)
	if block == nil || block.Type != "BIP0340 PUBLIC KEY" {
		return nil, fmt.Errorf("marshal: could not decode PEM block type %s", block.Type)

	}
	public, err := bip0340.ParsePublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return public, nil
}

func EncodeBIGNPrivateKey(key *bign.PrivateKey) ([]byte, error) {
	derKey, err := bign.MarshalPrivateKey(key)
	if err != nil {
		return nil, err
	}
	keyBlock := &pem.Block{
		Type:  "BIGN PRIVATE KEY",
		Bytes: derKey,
	}
	if *pwd != "" {
		encryptedBlock, err := EncryptBlockWithCipher(rand.Reader, keyBlock.Type, keyBlock.Bytes, []byte(*pwd), *cph)
		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(encryptedBlock), nil
	} else {
		return pem.EncodeToMemory(keyBlock), nil
	}
}

func DecodeBIGNPrivateKey(encodedKey []byte) (*bign.PrivateKey, error) {
	var skippedTypes []string
	var block *pem.Block
	for {
		block, encodedKey = pem.Decode(encodedKey)
		if block == nil {
			return nil, fmt.Errorf("failed to find EC PRIVATE KEY in PEM data after skipping types %v", skippedTypes)
		}

		if block.Type == "BIGN PRIVATE KEY" {
			break
		} else {
			skippedTypes = append(skippedTypes, block.Type)
			continue
		}
	}
	var privKey *bign.PrivateKey
	var privKeyBytes []byte
	var err error
	if IsEncryptedPEMBlock(block) {
		privKeyBytes, err = DecryptPEMBlock(block, []byte(*pwd))
		if err != nil {
			return nil, errors.New("could not decrypt private key")
		}
		privKey, _ = bign.ParsePrivateKey(privKeyBytes)
	} else {
		privKey, _ = bign.ParsePrivateKey(block.Bytes)
	}
	return privKey, nil
}

func EncodeBIGNPublicKey(key *bign.PublicKey) ([]byte, error) {
	derBytes, err := bign.MarshalPublicKey(key)
	if err != nil {
		return nil, err
	}
	block := &pem.Block{
		Type:  "BIGN PUBLIC KEY",
		Bytes: derBytes,
	}
	return pem.EncodeToMemory(block), nil
}

func DecodeBIGNPublicKey(encodedKey []byte) (*bign.PublicKey, error) {
	block, _ := pem.Decode(encodedKey)
	if block == nil || block.Type != "BIGN PUBLIC KEY" {
		return nil, fmt.Errorf("marshal: could not decode PEM block type %s", block.Type)

	}
	public, err := bign.ParsePublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return public, nil
}

func EncodeNUMSPrivateKey(key *nums.PrivateKey) ([]byte, error) {
	derKey, err := key.MarshalPKCS8PrivateKey(key.PublicKey.Curve)
	if err != nil {
		return nil, err
	}
	keyBlock := &pem.Block{
		Type:  "NUMS PRIVATE KEY",
		Bytes: derKey,
	}
	if *pwd != "" {
		encryptedBlock, err := EncryptBlockWithCipher(rand.Reader, keyBlock.Type, keyBlock.Bytes, []byte(*pwd), *cph)
		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(encryptedBlock), nil
	} else {
		return pem.EncodeToMemory(keyBlock), nil
	}
}

func DecodeNUMSPrivateKey(encodedKey []byte) (*nums.PrivateKey, error) {
	var skippedTypes []string
	var block *pem.Block
	for {
		block, encodedKey = pem.Decode(encodedKey)
		if block == nil {
			return nil, fmt.Errorf("failed to find EC PRIVATE KEY in PEM data after skipping types %v", skippedTypes)
		}

		if block.Type == "NUMS PRIVATE KEY" {
			break
		} else {
			skippedTypes = append(skippedTypes, block.Type)
			continue
		}
	}
	var privKey *nums.PrivateKey
	var privKeyBytes []byte
	var err error
	if IsEncryptedPEMBlock(block) {
		privKeyBytes, err = DecryptPEMBlock(block, []byte(*pwd))
		if err != nil {
			return nil, errors.New("could not decrypt private key")
		}
		privKey, _ = nums.ParsePrivateKey(privKeyBytes)
	} else {
		privKey, _ = nums.ParsePrivateKey(block.Bytes)
	}
	return privKey, nil
}

func EncodeNUMSPublicKey(key *nums.PublicKey) ([]byte, error) {
	curve := key.Curve
	if curve == nil {
		return nil, errors.New("unsupported key length")
	}

	derBytes, err := key.MarshalPKCS8PublicKey(curve)
	if err != nil {
		return nil, err
	}

	block := &pem.Block{
		Type:  "NUMS PUBLIC KEY",
		Bytes: derBytes,
	}
	return pem.EncodeToMemory(block), nil
}

func DecodeNUMSPublicKey(encodedKey []byte) (*nums.PublicKey, error) {
	block, _ := pem.Decode(encodedKey)
	if block == nil || block.Type != "NUMS PUBLIC KEY" {
		return nil, fmt.Errorf("marshal: could not decode PEM block type %s", block.Type)

	}
	public, err := nums.ParsePublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return public, nil
}

func EncodeANSSIPrivateKey(key *frp256v1.PrivateKey) ([]byte, error) {
	derKey, err := key.MarshalPKCS8PrivateKey(key.PublicKey.Curve)
	if err != nil {
		return nil, err
	}
	keyBlock := &pem.Block{
		Type:  "ANSSI PRIVATE KEY",
		Bytes: derKey,
	}
	if *pwd != "" {
		encryptedBlock, err := EncryptBlockWithCipher(rand.Reader, keyBlock.Type, keyBlock.Bytes, []byte(*pwd), *cph)
		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(encryptedBlock), nil
	} else {
		return pem.EncodeToMemory(keyBlock), nil
	}
}

func DecodeANSSIPrivateKey(encodedKey []byte) (*frp256v1.PrivateKey, error) {
	var skippedTypes []string
	var block *pem.Block
	for {
		block, encodedKey = pem.Decode(encodedKey)
		if block == nil {
			return nil, fmt.Errorf("failed to find EC PRIVATE KEY in PEM data after skipping types %v", skippedTypes)
		}

		if block.Type == "ANSSI PRIVATE KEY" {
			break
		} else {
			skippedTypes = append(skippedTypes, block.Type)
			continue
		}
	}
	var privKey *frp256v1.PrivateKey
	var privKeyBytes []byte
	var err error
	if IsEncryptedPEMBlock(block) {
		privKeyBytes, err = DecryptPEMBlock(block, []byte(*pwd))
		if err != nil {
			return nil, errors.New("could not decrypt private key")
		}
		privKey, _ = frp256v1.ParsePrivateKey(privKeyBytes)
	} else {
		privKey, _ = frp256v1.ParsePrivateKey(block.Bytes)
	}
	return privKey, nil
}

func EncodeANSSIPublicKey(key *frp256v1.PublicKey) ([]byte, error) {
	curve := key.Curve
	if curve == nil {
		return nil, errors.New("unsupported key length")
	}

	derBytes, err := key.MarshalPKCS8PublicKey(curve)
	if err != nil {
		return nil, err
	}

	block := &pem.Block{
		Type:  "ANSSI PUBLIC KEY",
		Bytes: derBytes,
	}
	return pem.EncodeToMemory(block), nil
}

func DecodeANSSIPublicKey(encodedKey []byte) (*frp256v1.PublicKey, error) {
	block, _ := pem.Decode(encodedKey)
	if block == nil || block.Type != "ANSSI PUBLIC KEY" {
		return nil, fmt.Errorf("marshal: could not decode PEM block type %s", block.Type)

	}
	public, err := frp256v1.ParsePublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return public, nil
}

func EncodeKOBLITZPrivateKey(key *secp256k1.PrivateKey) ([]byte, error) {
	derKey, err := key.MarshalPKCS8PrivateKey(key.PublicKey.Curve)
	if err != nil {
		return nil, err
	}
	keyBlock := &pem.Block{
		Type:  "KOBLITZ PRIVATE KEY",
		Bytes: derKey,
	}
	if *pwd != "" {
		encryptedBlock, err := EncryptBlockWithCipher(rand.Reader, keyBlock.Type, keyBlock.Bytes, []byte(*pwd), *cph)
		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(encryptedBlock), nil
	} else {
		return pem.EncodeToMemory(keyBlock), nil
	}
}

func DecodeKOBLITZPrivateKey(encodedKey []byte) (*secp256k1.PrivateKey, error) {
	var skippedTypes []string
	var block *pem.Block
	for {
		block, encodedKey = pem.Decode(encodedKey)
		if block == nil {
			return nil, fmt.Errorf("failed to find EC PRIVATE KEY in PEM data after skipping types %v", skippedTypes)
		}

		if block.Type == "KOBLITZ PRIVATE KEY" {
			break
		} else {
			skippedTypes = append(skippedTypes, block.Type)
			continue
		}
	}
	var privKey *secp256k1.PrivateKey
	var privKeyBytes []byte
	var err error
	if IsEncryptedPEMBlock(block) {
		privKeyBytes, err = DecryptPEMBlock(block, []byte(*pwd))
		if err != nil {
			return nil, errors.New("could not decrypt private key")
		}
		privKey, _ = secp256k1.ParsePrivateKey(privKeyBytes)
	} else {
		privKey, _ = secp256k1.ParsePrivateKey(block.Bytes)
	}
	return privKey, nil
}

func EncodeKOBLITZPublicKey(key *secp256k1.PublicKey) ([]byte, error) {
	curve := key.Curve
	if curve == nil {
		return nil, errors.New("unsupported key length")
	}

	derBytes, err := key.MarshalPKCS8PublicKey(curve)
	if err != nil {
		return nil, err
	}

	block := &pem.Block{
		Type:  "KOBLITZ PUBLIC KEY",
		Bytes: derBytes,
	}
	return pem.EncodeToMemory(block), nil
}

func DecodeKOBLITZPublicKey(encodedKey []byte) (*secp256k1.PublicKey, error) {
	block, _ := pem.Decode(encodedKey)
	if block == nil || block.Type != "KOBLITZ PUBLIC KEY" {
		return nil, fmt.Errorf("marshal: could not decode PEM block type %s", block.Type)

	}
	public, err := secp256k1.ParsePublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return public, nil
}

func EncodeTomPrivateKey(key *tom.PrivateKey) ([]byte, error) {
	derKey, err := key.MarshalPKCS8PrivateKey(key.PublicKey.Curve)
	if err != nil {
		return nil, err
	}
	keyBlock := &pem.Block{
		Type:  "TOM PRIVATE KEY",
		Bytes: derKey,
	}
	if *pwd != "" {
		encryptedBlock, err := EncryptBlockWithCipher(rand.Reader, keyBlock.Type, keyBlock.Bytes, []byte(*pwd), *cph)
		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(encryptedBlock), nil
	} else {
		return pem.EncodeToMemory(keyBlock), nil
	}
}

func DecodeTomPrivateKey(encodedKey []byte) (*tom.PrivateKey, error) {
	var skippedTypes []string
	var block *pem.Block
	for {
		block, encodedKey = pem.Decode(encodedKey)
		if block == nil {
			return nil, fmt.Errorf("failed to find EC PRIVATE KEY in PEM data after skipping types %v", skippedTypes)
		}

		if block.Type == "TOM PRIVATE KEY" {
			break
		} else {
			skippedTypes = append(skippedTypes, block.Type)
			continue
		}
	}
	var privKey *tom.PrivateKey
	var privKeyBytes []byte
	var err error
	if IsEncryptedPEMBlock(block) {
		privKeyBytes, err = DecryptPEMBlock(block, []byte(*pwd))
		if err != nil {
			return nil, errors.New("could not decrypt private key")
		}
		privKey, _ = tom.ParsePrivateKey(privKeyBytes)
	} else {
		privKey, _ = tom.ParsePrivateKey(block.Bytes)
	}
	return privKey, nil
}

func EncodeTomPublicKey(key *tom.PublicKey) ([]byte, error) {
	curve := key.Curve
	if curve == nil {
		return nil, errors.New("unsupported key length")
	}

	derBytes, err := key.MarshalPKCS8PublicKey(curve)
	if err != nil {
		return nil, err
	}

	block := &pem.Block{
		Type:  "TOM PUBLIC KEY",
		Bytes: derBytes,
	}
	return pem.EncodeToMemory(block), nil
}

func DecodeTomPublicKey(encodedKey []byte) (*tom.PublicKey, error) {
	block, _ := pem.Decode(encodedKey)
	if block == nil || block.Type != "TOM PUBLIC KEY" {
		return nil, fmt.Errorf("marshal: could not decode PEM block type %s", block.Type)

	}
	public, err := tom.ParsePublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return public, nil
}

func Hkdf(master, salt, info []byte) ([128]byte, error) {
	var myHash func() hash.Hash
	switch *md {
	case "sha224":
		myHash = sha256.New224
	case "sha256":
		myHash = sha256.New
	case "sha384":
		myHash = sha512.New384
	case "sha512":
		myHash = sha512.New
	case "sha512-256":
		myHash = sha512.New512_256
	case "sha1":
		myHash = sha1.New
	case "rmd160", "ripemd160":
		myHash = ripemd160.New
	case "rmd128", "ripemd128":
		myHash = ripemd.New128
	case "rmd256", "ripemd256":
		myHash = ripemd.New256
	case "rmd320", "ripemd320":
		myHash = ripemd.New320
	case "sha3-224":
		myHash = sha3.New224
	case "sha3-256":
		myHash = sha3.New256
	case "sha3-384":
		myHash = sha3.New384
	case "sha3-512":
		myHash = sha3.New512
	case "keccak", "keccak256":
		myHash = sha3.NewLegacyKeccak256
	case "keccak512":
		myHash = sha3.NewLegacyKeccak512
	case "shake128":
		myHash = func() hash.Hash {
			return sha3.NewShake128()
		}
	case "shake256":
		myHash = func() hash.Hash {
			return sha3.NewShake256()
		}
	case "lsh224", "lsh256-224":
		myHash = lsh256.New224
	case "lsh", "lsh256", "lsh256-256":
		myHash = lsh256.New
	case "lsh512-256":
		myHash = lsh512.New256
	case "lsh512-224":
		myHash = lsh512.New224
	case "lsh384", "lsh512-384":
		myHash = lsh512.New384
	case "lsh512":
		myHash = lsh512.New
	case "has160":
		myHash = has160.New
	case "whirlpool":
		myHash = whirlpool.New
	case "blake2b256":
		myHash = crypto.BLAKE2b_256.New
	case "blake2b512":
		myHash = crypto.BLAKE2b_512.New
	case "blake2s256":
		myHash = crypto.BLAKE2s_256.New
	case "blake3":
		myHash = func() hash.Hash {
			return blake3.New()
		}
	case "md5":
		myHash = md5.New
	case "gost94":
		myHash = func() hash.Hash {
			return gost341194.New(&gost28147.SboxIdGostR341194CryptoProParamSet)
		}
	case "streebog", "streebog256":
		myHash = gost34112012256.New
	case "streebog512":
		myHash = gost34112012512.New
	case "sm3":
		myHash = sm3.New
	case "md4":
		myHash = md4.New
	case "cubehash", "cubehash512":
		myHash = cubehash.New
	case "cubehash256":
		myHash = cubehash256.New
	case "xoodyak", "xhash":
		myHash = xoodyak.NewXoodyakHash
	case "skein", "skein256":
		myHash = func() hash.Hash {
			return skein.New256(nil)
		}
	case "skein512":
		myHash = func() hash.Hash {
			return skein.New512(nil)
		}
	case "jh224":
		myHash = jh.New224
	case "jh", "jh256":
		myHash = jh.New256
	case "jh384":
		myHash = jh.New384
	case "jh512":
		myHash = jh.New512
	case "groestl224":
		myHash = groestl.New224
	case "groestl", "groestl256":
		myHash = groestl.New256
	case "groestl384":
		myHash = groestl.New384
	case "groestl512":
		myHash = groestl.New512
	case "tiger":
		myHash = tiger.New
	case "tiger2":
		myHash = tiger.New2
	case "kupyna256", "kupyna":
		myHash = kupyna.New256
	case "kupyna384":
		myHash = kupyna.New384
	case "kupyna512":
		myHash = kupyna.New512
	case "echo224":
		myHash = echo.New224
	case "echo", "echo256":
		myHash = echo.New256
	case "echo384":
		myHash = echo.New384
	case "echo512":
		myHash = echo.New512
	case "esch", "esch256":
		myHash = esch.New256
	case "esch384":
		myHash = esch.New384
	case "bmw224":
		myHash = bmw.New224
	case "bmw", "bmw256":
		myHash = bmw.New256
	case "bmw384":
		myHash = bmw.New384
	case "bmw512":
		myHash = bmw.New512
	case "hamsi224":
		myHash = hamsi.New224
	case "hamsi", "hamsi256":
		myHash = hamsi.New256
	case "hamsi384":
		myHash = hamsi.New384
	case "hamsi512":
		myHash = hamsi.New512
	case "fugue224":
		myHash = fugue.New224
	case "fugue", "fugue256":
		myHash = fugue.New256
	case "fugue384":
		myHash = fugue.New384
	case "fugue512":
		myHash = fugue.New512
	case "luffa224":
		myHash = luffa.New224
	case "luffa", "luffa256":
		myHash = luffa.New256
	case "luffa384":
		myHash = luffa.New384
	case "luffa512":
		myHash = luffa.New512
	case "shavite224":
		myHash = shavite.New224
	case "shavite", "shavite256":
		myHash = shavite.New256
	case "shavite384":
		myHash = shavite.New384
	case "shavite512":
		myHash = shavite.New512
	case "simd224":
		myHash = simd.New224
	case "simd", "simd256":
		myHash = simd.New256
	case "simd384":
		myHash = simd.New384
	case "simd512":
		myHash = simd.New512
	case "radiogatun", "radiogatun32":
		myHash = radio_gatun.New32
	case "radiogatun64":
		myHash = radio_gatun.New64
	case "md6-224":
		myHash = md6.New224
	case "md6", "md6-256":
		myHash = md6.New256
	case "md6-384":
		myHash = md6.New384
	case "md6-512":
		myHash = md6.New512
	case "belt":
		myHash = belthash.New
	case "bash224":
		myHash = bash.New224
	case "bash", "bash256":
		myHash = bash.New256
	case "bash384":
		myHash = bash.New384
	case "bash512":
		myHash = bash.New512
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
	switch *md {
	case "sha224":
		myHash = sha256.New224
	case "sha256":
		myHash = sha256.New
	case "sha384":
		myHash = sha512.New384
	case "sha512":
		myHash = sha512.New
	case "sha512-256":
		myHash = sha512.New512_256
	case "sha1":
		myHash = sha1.New
	case "rmd160", "ripemd160":
		myHash = ripemd160.New
	case "rmd128", "ripemd128":
		myHash = ripemd.New128
	case "rmd256", "ripemd256":
		myHash = ripemd.New256
	case "rmd320", "ripemd320":
		myHash = ripemd.New320
	case "sha3-224":
		myHash = sha3.New224
	case "sha3-256":
		myHash = sha3.New256
	case "sha3-384":
		myHash = sha3.New384
	case "sha3-512":
		myHash = sha3.New512
	case "keccak", "keccak256":
		myHash = sha3.NewLegacyKeccak256
	case "keccak512":
		myHash = sha3.NewLegacyKeccak512
	case "shake128":
		myHash = func() hash.Hash {
			return sha3.NewShake128()
		}
	case "shake256":
		myHash = func() hash.Hash {
			return sha3.NewShake256()
		}
	case "lsh224", "lsh256-224":
		myHash = lsh256.New224
	case "lsh", "lsh256", "lsh256-256":
		myHash = lsh256.New
	case "lsh512-256":
		myHash = lsh512.New256
	case "lsh512-224":
		myHash = lsh512.New224
	case "lsh384", "lsh512-384":
		myHash = lsh512.New384
	case "lsh512":
		myHash = lsh512.New
	case "has160":
		myHash = has160.New
	case "whirlpool":
		myHash = whirlpool.New
	case "blake2b256":
		myHash = crypto.BLAKE2b_256.New
	case "blake2b512":
		myHash = crypto.BLAKE2b_512.New
	case "blake2s256":
		myHash = crypto.BLAKE2s_256.New
	case "blake3":
		myHash = func() hash.Hash {
			return blake3.New()
		}
	case "md5":
		myHash = md5.New
	case "gost94":
		myHash = func() hash.Hash {
			return gost341194.New(&gost28147.SboxIdGostR341194CryptoProParamSet)
		}
	case "streebog", "streebog256":
		myHash = gost34112012256.New
	case "streebog512":
		myHash = gost34112012512.New
	case "sm3":
		myHash = sm3.New
	case "md4":
		myHash = md4.New
	case "cubehash", "cubehash512":
		myHash = cubehash.New
	case "cubehash256":
		myHash = cubehash256.New
	case "xoodyak", "xhash":
		myHash = xoodyak.NewXoodyakHash
	case "skein", "skein256":
		myHash = func() hash.Hash {
			return skein.New256(nil)
		}
	case "skein512":
		myHash = func() hash.Hash {
			return skein.New512(nil)
		}
	case "jh224":
		myHash = jh.New224
	case "jh", "jh256":
		myHash = jh.New256
	case "jh384":
		myHash = jh.New384
	case "jh512":
		myHash = jh.New512
	case "groestl224":
		myHash = groestl.New224
	case "groestl", "groestl256":
		myHash = groestl.New256
	case "groestl384":
		myHash = groestl.New384
	case "groestl512":
		myHash = groestl.New512
	case "tiger":
		myHash = tiger.New
	case "tiger2":
		myHash = tiger.New2
	case "kupyna256", "kupyna":
		myHash = kupyna.New256
	case "kupyna384":
		myHash = kupyna.New384
	case "kupyna512":
		myHash = kupyna.New512
	case "echo224":
		myHash = echo.New224
	case "echo", "echo256":
		myHash = echo.New256
	case "echo384":
		myHash = echo.New384
	case "echo512":
		myHash = echo.New512
	case "esch", "esch256":
		myHash = esch.New256
	case "esch384":
		myHash = esch.New384
	case "bmw224":
		myHash = bmw.New224
	case "bmw", "bmw256":
		myHash = bmw.New256
	case "bmw384":
		myHash = bmw.New384
	case "bmw512":
		myHash = bmw.New512
	case "hamsi224":
		myHash = hamsi.New224
	case "hamsi", "hamsi256":
		myHash = hamsi.New256
	case "hamsi384":
		myHash = hamsi.New384
	case "hamsi512":
		myHash = hamsi.New512
	case "fugue224":
		myHash = fugue.New224
	case "fugue", "fugue256":
		myHash = fugue.New256
	case "fugue384":
		myHash = fugue.New384
	case "fugue512":
		myHash = fugue.New512
	case "luffa224":
		myHash = luffa.New224
	case "luffa", "luffa256":
		myHash = luffa.New256
	case "luffa384":
		myHash = luffa.New384
	case "luffa512":
		myHash = luffa.New512
	case "shavite224":
		myHash = shavite.New224
	case "shavite", "shavite256":
		myHash = shavite.New256
	case "shavite384":
		myHash = shavite.New384
	case "shavite512":
		myHash = shavite.New512
	case "simd224":
		myHash = simd.New224
	case "simd", "simd256":
		myHash = simd.New256
	case "simd384":
		myHash = simd.New384
	case "simd512":
		myHash = simd.New512
	case "radiogatun", "radiogatun32":
		myHash = radio_gatun.New32
	case "radiogatun64":
		myHash = radio_gatun.New64
	case "md6-224":
		myHash = md6.New224
	case "md6", "md6-256":
		myHash = md6.New256
	case "md6-384":
		myHash = md6.New384
	case "md6-512":
		myHash = md6.New512
	case "belt":
		myHash = belthash.New
	case "bash224":
		myHash = bash.New224
	case "bash", "bash256":
		myHash = bash.New256
	case "bash384":
		myHash = bash.New384
	case "bash512":
		myHash = bash.New512
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
			keyBlock, err = EncryptBlockWithCipher(rand.Reader, keyBlock.Type, PEM[1].Bytes, []byte(psd), *cph)
			if err != nil {
				return err
			}
		}
		fmt.Printf("%s", pem.EncodeToMemory(keyBlock))
	} else {
		keyBlock := &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: PEM[1].Bytes,
		}
		if psd != "" {
			keyBlock, err = EncryptBlockWithCipher(rand.Reader, keyBlock.Type, PEM[1].Bytes, []byte(psd), *cph)
			if err != nil {
				return err
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

	if !caCRT.BasicConstraintsValid || !caCRT.IsCA {
		return fmt.Errorf("root certificate is not a valid CA")
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

	var validity string

	if *days > 0 {
		validity = fmt.Sprintf("%d", *days)
	} else {
		println("Digital certificates are valid for up to three years:")
		fmt.Print("Validity (in Days): ")
		fmt.Scanln(&validity)
	}

	intVar, err := strconv.Atoi(validity)
	if err != nil {
		log.Fatal(err)
	}
	NotAfter := time.Now().AddDate(0, 0, intVar)

	var spki struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}

	var apki struct {
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

	derBytes, err = smx509.MarshalPKIXPublicKey(caCRT.PublicKey)
	if err != nil {
		log.Fatal(err)
	}
	_, err = asn1.Unmarshal(derBytes, &apki)
	if err != nil {
		return err
	}
	akid := sha1.Sum(apki.SubjectPublicKey.Bytes)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 160)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("Failed to generate serial number: %v", err)
	}

	clientCRTTemplate := x509.Certificate{
		Signature:          clientCSR.Signature,
		SignatureAlgorithm: clientCSR.SignatureAlgorithm,

		PublicKeyAlgorithm: clientCSR.PublicKeyAlgorithm,
		PublicKey:          clientCSR.PublicKey,

		SerialNumber:          serialNumber,
		Issuer:                caCRT.Subject,
		Subject:               clientCSR.Subject,
		SubjectKeyId:          skid[:],
		EmailAddresses:        clientCSR.EmailAddresses,
		NotBefore:             time.Now(),
		NotAfter:              NotAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		AuthorityKeyId:        akid[:],
		BasicConstraintsValid: *isca,
		IsCA:                  *isca,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
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
		if err != nil {
			log.Fatal(err)
		}
	} else if strings.ToUpper(*alg) == "ED25519" {
		caPrivateKey, err := x509.ParsePKCS8PrivateKey(der)
		if err != nil {
			return err
		}
		clientCRTRaw, err = x509.CreateCertificate(rand.Reader, &clientCRTTemplate, caCRT.ToX509(), clientCSR.PublicKey, caPrivateKey)
		if err != nil {
			log.Fatal(err)
		}
	} else if strings.ToUpper(*alg) == "ECDSA" || strings.ToUpper(*alg) == "EC" {
		caPrivateKey, err := x509.ParseECPrivateKey(der)
		if err != nil {
			return err
		}
		clientCRTRaw, err = x509.CreateCertificate(rand.Reader, &clientCRTTemplate, caCRT.ToX509(), clientCSR.PublicKey, caPrivateKey)
		if err != nil {
			log.Fatal(err)
		}
	} else if strings.ToUpper(*alg) == "SM2" {
		caPrivateKey, err := smx509.ParseSM2PrivateKey(der)
		if err != nil {
			return err
		}
		clientCRTRaw, err = smx509.CreateCertificate(rand.Reader, &clientCRTTemplate, caCRT.ToX509(), clientCSR.PublicKey, caPrivateKey)
		if err != nil {
			log.Fatal(err)
		}
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

	if !caCRT.BasicConstraintsValid || !caCRT.IsCA {
		return fmt.Errorf("root certificate is not a valid CA")
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

	var validity string

	if *days > 0 {
		validity = fmt.Sprintf("%d", *days)
	} else {
		println("Digital certificates are valid for up to three years:")
		fmt.Print("Validity (in Days): ")
		fmt.Scanln(&validity)
	}

	intVar, err := strconv.Atoi(validity)
	if err != nil {
		log.Fatal(err)
	}
	NotAfter := time.Now().AddDate(0, 0, intVar)

	hasher := gost34112012256.New()
	if _, err = hasher.Write(clientCSR.PublicKey.(*gost3410.PublicKey).Raw()); err != nil {
		log.Fatalln(err)
	}
	spki := hasher.Sum(nil)
	spki = spki[:20]

	hasher = gost34112012256.New()
	if _, err = hasher.Write(caCRT.PublicKey.(*gost3410.PublicKey).Raw()); err != nil {
		log.Fatalln(err)
	}
	akid := hasher.Sum(nil)
	akid = akid[:20]

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 160)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("Failed to generate serial number: %v", err)
	}

	clientCRTTemplate := x509.Certificate{
		Signature:          clientCSR.Signature,
		SignatureAlgorithm: clientCSR.SignatureAlgorithm,

		PublicKeyAlgorithm: clientCSR.PublicKeyAlgorithm,
		PublicKey:          clientCSR.PublicKey,

		SerialNumber:          serialNumber,
		Issuer:                caCRT.Subject,
		Subject:               clientCSR.Subject,
		SubjectKeyId:          spki,
		EmailAddresses:        clientCSR.EmailAddresses,
		NotBefore:             time.Now(),
		NotAfter:              NotAfter,
		AuthorityKeyId:        akid[:],
		BasicConstraintsValid: *isca,
		IsCA:                  *isca,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment | x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment | x509.KeyUsageKeyAgreement | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
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

var (
	name, number, country, province, locality, organization, organizationunit, street, email, postalcode string
)

func parseSubjectString(subject string) (name, number, country, province, locality, organization, organizationunit, street, email, postalcode string, err error) {
	parts := strings.Split(subject, "/")

	if len(parts) < 6 || len(parts) > 10 {
		return "", "", "", "", "", "", "", "", "", "", errors.New("invalid subject string format")
	}

	for _, part := range parts {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}

		key := kv[0]
		value := kv[1]

		switch key {
		case "C":
			country = value
		case "ST":
			province = value
		case "L":
			locality = value
		case "O":
			organization = value
		case "OU":
			organizationunit = value
		case "CN":
			name = value
		case "emailAddress":
			email = value
		case "postalCode":
			postalcode = value
		case "STREET":
			street = value
		}
	}

	return name, number, country, province, locality, organization, organizationunit, street, email, postalcode, nil
}

func PKCS7Padding(ciphertext []byte) []byte {
	var padding int
	if *cph == "aes" || *cph == "aria" || *cph == "grasshopper" || *cph == "kuznechik" || *cph == "camellia" || *cph == "twofish" || *cph == "lea" || *cph == "seed" || *cph == "sm4" || *cph == "anubis" || *cph == "serpent" || *cph == "rc6" || *cph == "magenta" || *cph == "crypton" || *cph == "noekeon" || *cph == "loki97" || *cph == "mars" || *cph == "e2" || *cph == "clefia" || *cph == "kalyna128_128" || *cph == "kalyna128_256" || *cph == "cast256" || *cph == "cast6" || *cph == "belt" {
		padding = 16 - len(ciphertext)%16
	} else if *cph == "blowfish" || *cph == "cast5" || *cph == "des" || *cph == "3des" || *cph == "magma" || *cph == "gost89" || *cph == "idea" || *cph == "rc2" || *cph == "rc5" || *cph == "hight" || *cph == "misty1" || *cph == "khazad" || *cph == "present" || *cph == "twine" || *cph == "saferplus" || *cph == "safer+" {
		padding = 8 - len(ciphertext)%8
	} else if *cph == "threefish" || *cph == "threefish256" || *cph == "kalyna256_256" || *cph == "kalyna256_512" || *cph == "shacal2" {
		padding = 32 - len(ciphertext)%32
	} else if *cph == "threefish512" || *cph == "kalyna512_512" {
		padding = 64 - len(ciphertext)%64
	} else if *cph == "threefish1024" {
		padding = 128 - len(ciphertext)%128
	} else if *cph == "curupira" {
		padding = 12 - len(ciphertext)%12
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

func calculateFingerprintFromASN1(key []byte) string {
	hash := sha256.Sum256(key)
	fingerprint := base64.StdEncoding.EncodeToString(hash[:])
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
	var err error
	parsers := []func([]byte) (interface{}, error){
		func(b []byte) (interface{}, error) {
			return smx509.ParsePKIXPublicKey(b)
		},
		func(b []byte) (interface{}, error) {
			return x509.ParsePKIXPublicKey(b)
		},
		func(b []byte) (interface{}, error) {
			return nums.ParsePublicKey(b)
		},
		func(b []byte) (interface{}, error) {
			pub, err := ed448.ParsePublicKey(b)
			return pub, err
		},
		func(b []byte) (interface{}, error) {
			pub, err := x448.ParsePublicKey(b)
			return pub, err
		},
		func(b []byte) (interface{}, error) {
			return kx509.ParsePKIXPublicKey(b)
		},
		func(b []byte) (interface{}, error) {
			pub, err := ecgdsa.ParsePublicKey(b)
			return pub, err
		},
		func(b []byte) (interface{}, error) {
			pub, err := ecsdsa.ParsePublicKey(b)
			return pub, err
		},
		func(b []byte) (interface{}, error) {
			pub, err := bip0340.ParsePublicKey(b)
			return pub, err
		},
		func(b []byte) (interface{}, error) {
			pub, err := bign.ParsePublicKey(b)
			return pub, err
		},
		func(b []byte) (interface{}, error) {
			pub, err := frp256v1.ParsePublicKey(b)
			return pub, err
		},
		func(b []byte) (interface{}, error) {
			pub, err := secp256k1.ParsePublicKey(b)
			return pub, err
		},
		func(b []byte) (interface{}, error) {
			pub, err := tom.ParsePublicKey(b)
			return pub, err
		},
	}
	var publicInterface interface{}
	for _, parser := range parsers {
		publicInterface, err = parser(block.Bytes)
		if err == nil {
			break
		}
	}
	if err != nil {
		log.Fatal("Failed to parse public key:", err)
	}
	switch publicInterface.(type) {
	case *rsa.PublicKey:
		publicKey := publicInterface.(*rsa.PublicKey)
		fmt.Fprintf(os.Stderr, "RSA (%v-bit)\n", publicKey.N.BitLen())
	case *ecdsa.PublicKey:
		publicKey := publicInterface.(*ecdsa.PublicKey)
		fmt.Fprintf(os.Stderr, "ECDSA (%v-bit)\n", publicKey.Curve.Params().BitSize)
	case *eckcdsa.PublicKey:
		publicKey := publicInterface.(*eckcdsa.PublicKey)
		fmt.Fprintf(os.Stderr, "ECKCDSA (%v-bit)\n", publicKey.Curve.Params().BitSize)
	case *ecgdsa.PublicKey:
		publicKey := publicInterface.(*ecgdsa.PublicKey)
		fmt.Fprintf(os.Stderr, "ECGDSA (%v-bit)\n", publicKey.Curve.Params().BitSize)
	case *ecsdsa.PublicKey:
		publicKey := publicInterface.(*ecsdsa.PublicKey)
		fmt.Fprintf(os.Stderr, "ECSDSA (%v-bit)\n", publicKey.Curve.Params().BitSize)
	case *bip0340.PublicKey:
		publicKey := publicInterface.(*bip0340.PublicKey)
		fmt.Fprintf(os.Stderr, "BIP0340 (%v-bit)\n", publicKey.Curve.Params().BitSize)
	case *ecdh.PublicKey:
		fmt.Fprintln(os.Stderr, "X25519 (256-bit)")
	case ed25519.PublicKey:
		fmt.Fprintln(os.Stderr, "Ed25519 (256-bit)")
	case ed448.PublicKey:
		fmt.Fprintln(os.Stderr, "Ed448 (448-bit)")
	case x448.PublicKey:
		fmt.Fprintln(os.Stderr, "X448 (448-bit)")
	case *gost3410.PublicKey:
		publicKey := publicInterface.(*gost3410.PublicKey)
		fmt.Fprintf(os.Stderr, "GOST2012 (%v-bit)\n", len(publicKey.Raw())*4)
	case *bign.PublicKey:
		publicKey := publicInterface.(*bign.PublicKey)
		fmt.Fprintf(os.Stderr, "BIGN (%v-bit)\n", publicKey.Curve.Params().BitSize)
	case *frp256v1.PublicKey:
		publicKey := publicInterface.(*frp256v1.PublicKey)
		fmt.Fprintf(os.Stderr, "ANSSI (%v-bit)\n", publicKey.Curve.Params().BitSize)
	case *secp256k1.PublicKey:
		publicKey := publicInterface.(*secp256k1.PublicKey)
		fmt.Fprintf(os.Stderr, "KOBLITZ (%v-bit)\n", publicKey.Curve.Params().BitSize)
	case *tom.PublicKey:
		publicKey := publicInterface.(*tom.PublicKey)
		fmt.Fprintf(os.Stderr, "Tom (%v-bit)\n", publicKey.Curve.Params().BitSize)
	default:
		log.Fatal("unknown type of public key")
	}
}

func savePEMKey(filename string, keyBytes []byte, blockType string) error {
	block := &pem.Block{
		Type:  blockType,
		Bytes: keyBytes,
	}

	return savePEMToFile(filename, block, true)
}

func savePEMPublicKey(filename string, keyBytes []byte) error {
	block := &pem.Block{
		Type:  "SLH-DSA PUBLIC KEY",
		Bytes: keyBytes,
	}

	return savePEMToFile(filename, block, false)
}

func generateKeyPair(privPath, pubPath string) {
	params := parameters.MakeSphincsPlusSHAKE256256fRobust(true)
	fmt.Printf("SLH-DSA Parameters\nN=%d, W=%d, Hprime=%d, H=%d, D=%d, K=%d, T=%d, LogT=%d, A=%d\n", params.N, params.W, params.Hprime,
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

	err = savePEMKey(privPath, serializedSK, "SLH-DSA SECRET KEY")
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
	println("SLH-DSA (256-bit)")
	randomArt := randomart.FromString(string(buf))
	println(randomArt)
}

func signMessage(input io.Reader, keyPath string) {
	messageBytes, err := ioutil.ReadAll(input)
	if err != nil {
		log.Fatal(err)
	}
	params := parameters.MakeSphincsPlusSHAKE256256fRobust(true)

	privateKeyBytes, err := readKeyFromPEM(keyPath, true)
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
		Type:  "SLH-DSA SIGNATURE",
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

	publicKeyBytes, err := readKeyFromPEM(keyPath, false)
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

func SignSLH(sk []byte, msgInput io.Reader) ([]byte, error) {
	msg, err := ioutil.ReadAll(msgInput)
	if err != nil {
		return nil, err
	}

	params := parameters.MakeSphincsPlusSHAKE256256fRobust(true)

	deserializedSK, err := sphincs.DeserializeSK(params, sk)
	if err != nil {
		return nil, fmt.Errorf("error deserializing secret key: %v", err)
	}

	signature := sphincs.Spx_sign(params, msg, deserializedSK)

	serializedSignature, err := signature.SerializeSignature()
	if err != nil {
		return nil, fmt.Errorf("error serializing signature: %v", err)
	}

	return serializedSignature, nil
}

func VerifySLH(pk []byte, signature []byte, msg []byte) error {
	params := parameters.MakeSphincsPlusSHAKE256256fRobust(true)

	deserializedPK, err := sphincs.DeserializePK(params, pk)
	if err != nil {
		return fmt.Errorf("error deserializing public key: %v", err)
	}

	deserializedSignature, err := sphincs.DeserializeSignature(params, signature)
	if err != nil {
		return fmt.Errorf("error deserializing signature: %v", err)
	}

	verified := sphincs.Spx_verify(params, msg, deserializedSignature, deserializedPK)
	if !verified {
		return fmt.Errorf("signature verification failed")
	}

	return nil
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
		Type:  "SLH-DSA PUBLIC KEY",
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
	fmt.Println("ASN.1 OID: SLH-DSA")

	skid := sha3.Sum256(serializedPK)
	fmt.Printf("\nKeyID: %x \n", skid[:20])
}

func printPrivateKeyParamsFull(sk *sphincs.SPHINCS_SK) {
	serializedSK, err := sk.SerializeSK()
	if err != nil {
		log.Fatal(err)
	}

	block := &pem.Block{
		Type:  "SLH-DSA SECRET KEY",
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
	fmt.Println("ASN.1 OID: SLH-DSA")

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
	PEMCipherBETL128
	PEMCipherBETL192
	PEMCipherBETL256
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
	PEMCipherMAGENTA128
	PEMCipherMAGENTA192
	PEMCipherMAGENTA256
	PEMCipherCRYPTON128
	PEMCipherCRYPTON192
	PEMCipherCRYPTON256
	PEMCipherE2128
	PEMCipherE2192
	PEMCipherE2256
	PEMCipherLOKI97128
	PEMCipherLOKI97192
	PEMCipherLOKI97256
	PEMCipherMARS128
	PEMCipherMARS192
	PEMCipherMARS256
	PEMCipherNOEKEON
	PEMCipherCAST256_128
	PEMCipherCAST256_192
	PEMCipherCAST256_256
	PEMCipherTWOFISH128
	PEMCipherTWOFISH192
	PEMCipherTWOFISH256
	PEMCipherKALYNA128_128
	PEMCipherKALYNA128_256
	PEMCipherCURUPIRA96
	PEMCipherCURUPIRA144
	PEMCipherCURUPIRA192
	PEMCipherBELT128
	PEMCipherBELT192
	PEMCipherBELT256
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
}, {
	cipher:     PEMCipherMAGENTA128,
	name:       "MAGENTA-128-CBC",
	cipherFunc: magenta.NewCipher,
	keySize:    16,
	blockSize:  16,
}, {
	cipher:     PEMCipherMAGENTA192,
	name:       "MAGENTA-192-CBC",
	cipherFunc: magenta.NewCipher,
	keySize:    24,
	blockSize:  16,
}, {
	cipher:     PEMCipherMAGENTA256,
	name:       "MAGENTA-256-CBC",
	cipherFunc: magenta.NewCipher,
	keySize:    32,
	blockSize:  16,
}, {
	cipher:     PEMCipherCRYPTON128,
	name:       "CRYPTON-128-CBC",
	cipherFunc: crypton1.NewCipher,
	keySize:    16,
	blockSize:  16,
}, {
	cipher:     PEMCipherCRYPTON192,
	name:       "CRYPTON-192-CBC",
	cipherFunc: crypton1.NewCipher,
	keySize:    24,
	blockSize:  16,
}, {
	cipher:     PEMCipherCRYPTON256,
	name:       "CRYPTON-256-CBC",
	cipherFunc: crypton1.NewCipher,
	keySize:    32,
	blockSize:  16,
}, {
	cipher:     PEMCipherE2128,
	name:       "E2-128-CBC",
	cipherFunc: e2.NewCipher,
	keySize:    16,
	blockSize:  16,
}, {
	cipher:     PEMCipherE2192,
	name:       "E2-192-CBC",
	cipherFunc: e2.NewCipher,
	keySize:    24,
	blockSize:  16,
}, {
	cipher:     PEMCipherE2256,
	name:       "E2-256-CBC",
	cipherFunc: e2.NewCipher,
	keySize:    32,
	blockSize:  16,
}, {
	cipher:     PEMCipherLOKI97128,
	name:       "LOKI97-128-CBC",
	cipherFunc: loki97.NewCipher,
	keySize:    16,
	blockSize:  16,
}, {
	cipher:     PEMCipherLOKI97192,
	name:       "LOKI97-192-CBC",
	cipherFunc: loki97.NewCipher,
	keySize:    24,
	blockSize:  16,
}, {
	cipher:     PEMCipherLOKI97256,
	name:       "LOKI97-256-CBC",
	cipherFunc: loki97.NewCipher,
	keySize:    32,
	blockSize:  16,
}, {
	cipher:     PEMCipherMARS128,
	name:       "MARS-128-CBC",
	cipherFunc: mars.NewCipher,
	keySize:    16,
	blockSize:  16,
}, {
	cipher:     PEMCipherMARS192,
	name:       "MARS-192-CBC",
	cipherFunc: mars.NewCipher,
	keySize:    24,
	blockSize:  16,
}, {
	cipher:     PEMCipherMARS256,
	name:       "MARS-256-CBC",
	cipherFunc: mars.NewCipher,
	keySize:    32,
	blockSize:  16,
}, {
	cipher:     PEMCipherNOEKEON,
	name:       "NOEKEON-CBC",
	cipherFunc: noekeon.NewCipher,
	keySize:    16,
	blockSize:  16,
}, {
	cipher:     PEMCipherCAST256_128,
	name:       "CAST256-128-CBC",
	cipherFunc: cast256.NewCipher,
	keySize:    16,
	blockSize:  16,
}, {
	cipher:     PEMCipherCAST256_192,
	name:       "CAST256-192-CBC",
	cipherFunc: cast256.NewCipher,
	keySize:    24,
	blockSize:  16,
}, {
	cipher:     PEMCipherCAST256_256,
	name:       "CAST256-256-CBC",
	cipherFunc: cast256.NewCipher,
	keySize:    32,
	blockSize:  16,
}, {
	cipher:     PEMCipherTWOFISH128,
	name:       "TWOFISH-128-CBC",
	cipherFunc: twofishCipherFunc,
	keySize:    16,
	blockSize:  16,
}, {
	cipher:     PEMCipherTWOFISH192,
	name:       "TWOFISH-192-CBC",
	cipherFunc: twofishCipherFunc,
	keySize:    24,
	blockSize:  16,
}, {
	cipher:     PEMCipherTWOFISH256,
	name:       "TWOFISH-256-CBC",
	cipherFunc: twofishCipherFunc,
	keySize:    32,
	blockSize:  16,
}, {
	cipher:     PEMCipherKALYNA128_128,
	name:       "KALYNA128_128-CBC",
	cipherFunc: kalyna.NewCipher128_128,
	keySize:    16,
	blockSize:  16,
}, {
	cipher:     PEMCipherKALYNA128_256,
	name:       "KALYNA128_256-CBC",
	cipherFunc: kalyna.NewCipher128_256,
	keySize:    32,
	blockSize:  16,
}, {
	cipher:     PEMCipherCURUPIRA96,
	name:       "CURUPIRA-96-CBC",
	cipherFunc: curupiraCipherFunc,
	keySize:    12,
	blockSize:  12,
}, {
	cipher:     PEMCipherCURUPIRA144,
	name:       "CURUPIRA-144-CBC",
	cipherFunc: curupiraCipherFunc,
	keySize:    18,
	blockSize:  12,
}, {
	cipher:     PEMCipherCURUPIRA192,
	name:       "CURUPIRA-192-CBC",
	cipherFunc: curupiraCipherFunc,
	keySize:    24,
	blockSize:  12,
}, {
	cipher:     PEMCipherBELT128,
	name:       "BELT-128-CBC",
	cipherFunc: belt.NewCipher,
	keySize:    16,
	blockSize:  16,
}, {
	cipher:     PEMCipherBELT192,
	name:       "BELT-192-CBC",
	cipherFunc: belt.NewCipher,
	keySize:    24,
	blockSize:  16,
}, {
	cipher:     PEMCipherBELT256,
	name:       "BELT-256-CBC",
	cipherFunc: belt.NewCipher,
	keySize:    32,
	blockSize:  16,
},
}

func twofishCipherFunc(key []byte) (cipher.Block, error) {
	ciph, err := twofish.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return ciph, nil
}

func curupiraCipherFunc(key []byte) (cipher.Block, error) {
	ciph, err := curupira1.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return ciph, nil
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

func EncryptPEMBlock(rand io.Reader, blockType string, data, password []byte, algo PEMCipher) (*pem.Block, error) {
	ciph := cipherByKey(algo)
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

func EncryptAndWriteBlock(cph string, block *pem.Block, pwd []byte, file *os.File) error {
	var cipher PEMCipher
	var err error

	cipherMap := map[string]PEMCipher{
		"aes128":        PEMCipherAES128,
		"aes192":        PEMCipherAES192,
		"aes256":        PEMCipherAES256,
		"aes":           PEMCipherAES256,
		"3des":          PEMCipher3DES,
		"des":           PEMCipherDES,
		"sm4":           PEMCipherSM4,
		"gost":          PEMCipherGOST,
		"idea":          PEMCipherIDEA,
		"camellia128":   PEMCipherCAMELLIA128,
		"camellia192":   PEMCipherCAMELLIA192,
		"camellia256":   PEMCipherCAMELLIA256,
		"camellia":      PEMCipherCAMELLIA256,
		"aria128":       PEMCipherARIA128,
		"aria192":       PEMCipherARIA192,
		"aria256":       PEMCipherARIA256,
		"aria":          PEMCipherARIA256,
		"lea128":        PEMCipherLEA128,
		"lea192":        PEMCipherLEA192,
		"lea256":        PEMCipherLEA256,
		"lea":           PEMCipherLEA256,
		"seed":          PEMCipherSEED,
		"cast5":         PEMCipherCAST,
		"anubis":        PEMCipherANUBIS,
		"serpent128":    PEMCipherSERPENT128,
		"serpent192":    PEMCipherSERPENT192,
		"serpent256":    PEMCipherSERPENT256,
		"serpent":       PEMCipherSERPENT256,
		"rc6-128":       PEMCipherRC6128,
		"rc6-192":       PEMCipherRC6192,
		"rc6-256":       PEMCipherRC6256,
		"rc6":           PEMCipherRC6256,
		"magenta-128":   PEMCipherMAGENTA128,
		"magenta-192":   PEMCipherMAGENTA192,
		"magenta-256":   PEMCipherMAGENTA256,
		"magenta":       PEMCipherMAGENTA256,
		"crypton128":    PEMCipherCRYPTON128,
		"crypton192":    PEMCipherCRYPTON192,
		"crypton256":    PEMCipherCRYPTON256,
		"crypton":       PEMCipherCRYPTON256,
		"cast256-128":   PEMCipherCAST256_128,
		"cast256-192":   PEMCipherCAST256_192,
		"cast256-256":   PEMCipherCAST256_256,
		"cast256":       PEMCipherCAST256_256,
		"e2-128":        PEMCipherE2128,
		"e2-192":        PEMCipherE2192,
		"e2-256":        PEMCipherE2256,
		"e2":            PEMCipherE2256,
		"loki97-128":    PEMCipherLOKI97128,
		"loki97-192":    PEMCipherLOKI97192,
		"loki97-256":    PEMCipherLOKI97256,
		"loki97":        PEMCipherLOKI97256,
		"mars128":       PEMCipherMARS128,
		"mars192":       PEMCipherMARS192,
		"mars256":       PEMCipherMARS256,
		"mars":          PEMCipherMARS256,
		"noekeon":       PEMCipherNOEKEON,
		"twofish128":    PEMCipherTWOFISH128,
		"twofish192":    PEMCipherTWOFISH192,
		"twofish256":    PEMCipherTWOFISH256,
		"twofish":       PEMCipherTWOFISH256,
		"kalyna128_128": PEMCipherKALYNA128_128,
		"kalyna128_256": PEMCipherKALYNA128_256,
		"kalyna128":     PEMCipherKALYNA128_256,
		"kalyna":        PEMCipherKALYNA128_256,
		"kuznechik":     PEMCipherGOST,
		"grasshopper":   PEMCipherGOST,
		"curupira96":    PEMCipherCURUPIRA96,
		"curupira144":   PEMCipherCURUPIRA144,
		"curupira192":   PEMCipherCURUPIRA192,
		"curupira":      PEMCipherCURUPIRA192,
		"belt128":       PEMCipherBELT128,
		"belt192":       PEMCipherBELT192,
		"belt256":       PEMCipherBELT256,
		"belt":          PEMCipherBELT256,
	}

	if val, ok := cipherMap[cph]; ok {
		cipher = val
	} else {
		return errors.New("unsupported cipher algorithm")
	}

	block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, pwd, cipher)
	if err != nil {
		return err
	}

	if err := pem.Encode(file, block); err != nil {
		return err
	}

	return nil
}

func EncryptBlockWithCipher(rand io.Reader, blockType string, blockBytes, password []byte, cipherName string) (*pem.Block, error) {
	var cipher PEMCipher
	switch cipherName {
	case "aes128":
		cipher = PEMCipherAES128
	case "aes192":
		cipher = PEMCipherAES192
	case "aes", "aes256":
		cipher = PEMCipherAES256
	case "3des":
		cipher = PEMCipher3DES
	case "des":
		cipher = PEMCipherDES
	case "sm4":
		cipher = PEMCipherSM4
	case "seed":
		cipher = PEMCipherSEED
	case "gost":
		cipher = PEMCipherGOST
	case "idea":
		cipher = PEMCipherIDEA
	case "camellia128":
		cipher = PEMCipherCAMELLIA128
	case "camellia192":
		cipher = PEMCipherCAMELLIA192
	case "camellia", "camellia256":
		cipher = PEMCipherCAMELLIA256
	case "aria128":
		cipher = PEMCipherARIA128
	case "aria192":
		cipher = PEMCipherARIA192
	case "aria", "aria256":
		cipher = PEMCipherARIA256
	case "lea128":
		cipher = PEMCipherLEA128
	case "lea192":
		cipher = PEMCipherLEA192
	case "lea", "lea256":
		cipher = PEMCipherLEA256
	case "cast5":
		cipher = PEMCipherCAST
	case "anubis":
		cipher = PEMCipherANUBIS
	case "serpent128":
		cipher = PEMCipherSERPENT128
	case "serpent192":
		cipher = PEMCipherSERPENT192
	case "serpent", "serpent256":
		cipher = PEMCipherSERPENT256
	case "rc6128":
		cipher = PEMCipherRC6128
	case "rc6192":
		cipher = PEMCipherRC6192
	case "rc6", "rc6256":
		cipher = PEMCipherMAGENTA256
	case "magenta128":
		cipher = PEMCipherMAGENTA128
	case "magenta192":
		cipher = PEMCipherMAGENTA192
	case "magenta", "magenta256":
		cipher = PEMCipherMAGENTA256
	case "crypton128":
		cipher = PEMCipherCRYPTON128
	case "crypton192":
		cipher = PEMCipherCRYPTON192
	case "crypton256", "crypton":
		cipher = PEMCipherCRYPTON256
	case "cast256-128":
		cipher = PEMCipherCAST256_128
	case "cast256-192":
		cipher = PEMCipherCAST256_192
	case "cast256-256", "cast256":
		cipher = PEMCipherCAST256_256
	case "e2-128":
		cipher = PEMCipherE2128
	case "e2-192":
		cipher = PEMCipherE2192
	case "e2-256", "e2":
		cipher = PEMCipherE2256
	case "loki97-128":
		cipher = PEMCipherLOKI97128
	case "loki97-192":
		cipher = PEMCipherLOKI97192
	case "loki97-256", "loki97":
		cipher = PEMCipherLOKI97256
	case "mars128":
		cipher = PEMCipherMARS128
	case "mars192":
		cipher = PEMCipherMARS192
	case "mars256", "mars":
		cipher = PEMCipherMARS256
	case "noekeon":
		cipher = PEMCipherNOEKEON
	case "twofish128":
		cipher = PEMCipherTWOFISH128
	case "twofish192":
		cipher = PEMCipherTWOFISH192
	case "twofish", "twofish256":
		cipher = PEMCipherTWOFISH256
	case "kalyna128_128":
		cipher = PEMCipherKALYNA128_128
	case "kalyna128", "kalyna128_256":
		cipher = PEMCipherKALYNA128_256
	case "kuznechik", "grasshopper":
		cipher = PEMCipherGOST
	case "curupira96":
		cipher = PEMCipherCURUPIRA96
	case "curupira144":
		cipher = PEMCipherCURUPIRA144
	case "curupira192", "curupira":
		cipher = PEMCipherCURUPIRA192
	case "belt128":
		cipher = PEMCipherBELT128
	case "belt192":
		cipher = PEMCipherBELT192
	case "belt", "belt256":
		cipher = PEMCipherBELT256
	default:
		return nil, errors.New("unsupported cipher algorithm")
	}

	encryptedBlock, err := EncryptPEMBlock(rand, blockType, blockBytes, password, cipher)
	if err != nil {
		return nil, err
	}

	return encryptedBlock, nil
}

func setup(privateKey *big.Int, g, p *big.Int) *big.Int {
	publicKey := new(big.Int).Exp(g, privateKey, p)
	return publicKey
}

type PublicKey struct {
	P, Q, G, Y *big.Int
}

type PrivateKey struct {
	PublicKey
	X *big.Int
}

type elgamalEncrypt struct {
	C1, C2 *big.Int
}

func EncryptASN1(random io.Reader, pub *PublicKey, message []byte) ([]byte, error) {
	c1, c2, err := EncryptLegacy(random, pub, message)
	if err != nil {
		return nil, err
	}

	return asn1.Marshal(elgamalEncrypt{
		C1: c1,
		C2: c2,
	})
}

func DecryptASN1(priv *PrivateKey, cipherData []byte) ([]byte, error) {
	var enc elgamalEncrypt
	_, err := asn1.Unmarshal(cipherData, &enc)
	if err != nil {
		return nil, err
	}

	return DecryptLegacy(priv, enc.C1, enc.C2)
}

func EncryptLegacy(random io.Reader, pub *PublicKey, msg []byte) (c1, c2 *big.Int, err error) {
	m := new(big.Int).SetBytes(msg)
	if m.Cmp(pub.P) >= 0 {
		return nil, nil, errors.New("plaintext too large for modulus")
	}

	k, err := rand.Int(random, new(big.Int).Sub(pub.Q, big.NewInt(1)))
	if err != nil {
		return nil, nil, err
	}
	k.Add(k, big.NewInt(1))

	c1 = new(big.Int).Exp(pub.G, k, pub.P)

	s := new(big.Int).Exp(pub.Y, k, pub.P)

	c2 = new(big.Int).Mul(m, s)
	c2.Mod(c2, pub.P)

	return
}

func DecryptLegacy(priv *PrivateKey, c1, c2 *big.Int) (msg []byte, err error) {
	s := new(big.Int).Exp(c1, priv.X, priv.P)

	if s.ModInverse(s, priv.P) == nil {
		return nil, errors.New("elgamal: invalid private key")
	}

	m := new(big.Int).Mul(c2, s)
	m.Mod(m, priv.P)

	return m.Bytes(), nil
}

var (
	zero = big.NewInt(0)
	one  = big.NewInt(1)
	two  = big.NewInt(2)
)

func sign(random io.Reader, priv *PrivateKey, message []byte, h hash.Hash) (*big.Int, *big.Int, error) {
	k := new(big.Int)
	var err error

	for {
		k, err = rand.Int(random, priv.Q)
		if err != nil {
			return nil, nil, err
		}
		if k.Sign() == 0 {
			k = new(big.Int).Set(one)
		}
		if new(big.Int).GCD(nil, nil, k, priv.Q).Cmp(one) == 0 {
			break
		}
	}

	r := new(big.Int).Exp(priv.G, k, priv.P)

	h.Reset()
	h.Write(r.Bytes())
	h.Write(message)
	hashBytes := h.Sum(nil)
	χ := new(big.Int).SetBytes(hashBytes)
	χ.Mod(χ, priv.Q)

	xr := new(big.Int).Mul(priv.X, r)
	xr.Mod(xr, priv.Q)

	χMinusXr := new(big.Int).Sub(χ, xr)
	χMinusXr.Mod(χMinusXr, priv.Q)

	kInv := k.ModInverse(k, priv.Q)
	s := new(big.Int).Mul(χMinusXr, kInv)
	s.Mod(s, priv.Q)

	return r, s, nil
}

func verify(pub *PublicKey, message []byte, r, s *big.Int, h hash.Hash) (bool, error) {
	if r.Cmp(zero) <= 0 || r.Cmp(pub.P) >= 0 {
		return false, errors.New("r out of bounds")
	}
	if s.Cmp(zero) <= 0 || s.Cmp(pub.Q) >= 0 {
		return false, errors.New("s out of bounds")
	}

	h.Reset()
	h.Write(r.Bytes())
	h.Write(message)
	hashBytes := h.Sum(nil)
	χ := new(big.Int).SetBytes(hashBytes)
	χ.Mod(χ, pub.Q)

	gχ := new(big.Int).Exp(pub.G, χ, pub.P)

	yr := new(big.Int).Exp(pub.Y, r, pub.P)
	rs := new(big.Int).Exp(r, s, pub.P)
	yrRs := new(big.Int).Mul(yr, rs)
	yrRs.Mod(yrRs, pub.P)

	gχBytes := bigIntToFixedBytes(gχ, pub.P.BitLen())
	yrRsBytes := bigIntToFixedBytes(yrRs, pub.P.BitLen())

	return subtle.ConstantTimeCompare(gχBytes, yrRsBytes) == 1, nil
}

func signDSA(random io.Reader, priv *PrivateKey, hash []byte) (*big.Int, *big.Int, error) {
	k := new(big.Int)
	var err error

	k, err = rand.Int(random, priv.Q)
	if err != nil {
		return nil, nil, err
	}
	if k.Sign() == 0 {
		k = new(big.Int).Set(one)
	}

	m := new(big.Int).SetBytes(hash)
	m.Mod(m, priv.Q)

	rTemp := new(big.Int).Exp(priv.G, k, priv.P)
	r := new(big.Int).Mod(rTemp, priv.Q)
	if r.Sign() == 0 {
		return signDSA(random, priv, hash)
	}

	xr := new(big.Int).Mul(priv.X, r)
	xr.Mod(xr, priv.Q)

	mPlusXr := new(big.Int).Add(m, xr)
	mPlusXr.Mod(mPlusXr, priv.Q)

	kInv := new(big.Int).ModInverse(k, priv.Q)
	s := new(big.Int).Mul(mPlusXr, kInv)
	s.Mod(s, priv.Q)

	return r, s, nil
}

func verifyDSA(pub *PublicKey, hash []byte, r, s *big.Int) (bool, error) {
	if r.Cmp(one) < 0 || r.Cmp(pub.Q) >= 0 {
		return false, errors.New("elgamal: r out of bounds")
	}
	if s.Cmp(one) < 0 || s.Cmp(pub.Q) >= 0 {
		return false, errors.New("elgamal: s out of bounds")
	}

	m := new(big.Int).SetBytes(hash)
	m.Mod(m, pub.Q)

	w := new(big.Int).ModInverse(s, pub.Q)
	if w == nil {
		return false, errors.New("elgamal: invalid s")
	}

	u1 := new(big.Int).Mul(m, w)
	u1.Mod(u1, pub.Q)

	u2 := new(big.Int).Mul(r, w)
	u2.Mod(u2, pub.Q)

	gu1 := new(big.Int).Exp(pub.G, u1, pub.P)
	yu2 := new(big.Int).Exp(pub.Y, u2, pub.P)
	v := new(big.Int).Mul(gu1, yu2)
	v.Mod(v, pub.P)
	v.Mod(v, pub.Q)

	vBytes := bigIntToFixedBytes(v, pub.Q.BitLen())
	rBytes := bigIntToFixedBytes(r, pub.Q.BitLen())

	if subtle.ConstantTimeCompare(vBytes, rBytes) == 1 {
		return true, nil
	}
	return false, errors.New("elgamal: signature verification failed")
}

type elgamalSignature struct {
	R, S *big.Int
}

func SignASN1(random io.Reader, priv *PrivateKey, message []byte, h hash.Hash) ([]byte, error) {
	r, s, err := sign(random, priv, message, h)
	if err != nil {
		return nil, err
	}

	return asn1.Marshal(elgamalSignature{
		R: r,
		S: s,
	})
}

func VerifyASN1(pub *PublicKey, message, sig []byte, h hash.Hash) (bool, error) {
	var sign elgamalSignature
	_, err := asn1.Unmarshal(sig, &sign)
	if err != nil {
		return false, err
	}

	return verify(pub, message, sign.R, sign.S, h)
}

func SignASN1DSA(rand io.Reader, priv *PrivateKey, hash []byte) ([]byte, error) {
	r, s, err := signDSA(rand, priv, hash)
	if err != nil {
		return nil, err
	}

	return asn1.Marshal(elgamalSignature{
		R: r,
		S: s,
	})
}

func VerifyASN1DSA(pub *PublicKey, hash, sig []byte) (bool, error) {
	var sign elgamalSignature
	_, err := asn1.Unmarshal(sig, &sign)
	if err != nil {
		return false, err
	}

	return verifyDSA(pub, hash, sign.R, sign.S)
}

func ProveKnowledgeElGamal(priv *PrivateKey, message []byte, h hash.Hash) (t, c, s *big.Int, err error) {
	if priv == nil || priv.P == nil || priv.G == nil || priv.X == nil || priv.Q == nil {
		return nil, nil, nil, fmt.Errorf("elgamal: incomplete private key")
	}

	r, err := rand.Int(rand.Reader, priv.Q)
	if err != nil {
		return nil, nil, nil, err
	}
	if r.Sign() == 0 {
		r = new(big.Int).Set(one)
	}

	Y := new(big.Int).Exp(priv.G, priv.X, priv.P)

	t = new(big.Int).Exp(priv.G, r, priv.P)

	h.Reset()
	h.Write(priv.G.Bytes())
	h.Write(Y.Bytes())
	h.Write(priv.Q.Bytes())
	h.Write(t.Bytes())
	h.Write(message)
	challenge := h.Sum(nil)

	c = new(big.Int).SetBytes(challenge)
	c.Mod(c, priv.Q)

	cx := new(big.Int).Mul(c, priv.X)
	s = new(big.Int).Add(r, cx)
	s.Mod(s, priv.Q)

	return t, c, s, nil
}

func VerifyKnowledgeElGamal(pub *PublicKey, t, c, s *big.Int, message []byte, h hash.Hash) bool {
	if pub == nil || pub.G == nil || pub.P == nil || pub.Y == nil || pub.Q == nil {
		return false
	}

	if c.Cmp(zero) < 0 || c.Cmp(pub.Q) >= 0 {
		return false
	}
	if s.Cmp(zero) < 0 || s.Cmp(pub.Q) >= 0 {
		return false
	}

	h.Reset()
	h.Write(pub.G.Bytes())
	h.Write(pub.Y.Bytes())
	h.Write(pub.Q.Bytes())
	h.Write(t.Bytes())
	h.Write(message)
	expectedHash := h.Sum(nil)

	expectedC := new(big.Int).SetBytes(expectedHash)
	expectedC.Mod(expectedC, pub.Q)

	if expectedC.Cmp(c) != 0 {
		return false
	}

	gs := new(big.Int).Exp(pub.G, s, pub.P)
	yc := new(big.Int).Exp(pub.Y, c, pub.P)
	right := new(big.Int).Mul(t, yc)
	right.Mod(right, pub.P)

	return gs.Cmp(right) == 0
}

type Share struct {
	Index int
	Value *ff.Scalar
}

type PartialKey struct {
	Index int
	Key   *bls12381.G1
}

func evaluatePolynomial(coeffs []*ff.Scalar, x *ff.Scalar) *ff.Scalar {
	result := new(ff.Scalar)
	result.Set(coeffs[0])

	power := new(ff.Scalar)
	power.Set(x)

	for i := 1; i < len(coeffs); i++ {
		tmp := new(ff.Scalar)
		tmp.Mul(coeffs[i], power)
		result.Add(result, tmp)
		power.Mul(power, x)
	}
	return result
}

func GenerateShares(secret *ff.Scalar, t, n int) ([]Share, error) {
	if t >= n {
		return nil, fmt.Errorf("threshold t deve ser menor que n")
	}
	coeffs := make([]*ff.Scalar, t+1)
	coeffs[0] = new(ff.Scalar)
	coeffs[0].Set(secret)
	for i := 1; i <= t; i++ {
		coeff := new(ff.Scalar)
		coeff.Random(rand.Reader)
		coeffs[i] = coeff
	}
	shares := make([]Share, n)
	for i := 1; i <= n; i++ {
		xScalar := new(ff.Scalar)
		xScalar.SetUint64(uint64(i))
		y := evaluatePolynomial(coeffs, xScalar)
		shares[i-1] = Share{Index: i, Value: y}
	}
	return shares, nil
}

func lagrangeCoefficient(shares []Share, i int) *ff.Scalar {
	numerator := new(ff.Scalar)
	numerator.SetUint64(1)
	denominator := new(ff.Scalar)
	denominator.SetUint64(1)

	xi := new(ff.Scalar)
	xi.SetUint64(uint64(shares[i].Index))

	for j := range shares {
		if i == j {
			continue
		}

		xj := new(ff.Scalar)
		xj.SetUint64(uint64(shares[j].Index))

		numerator.Mul(numerator, xj)

		diff := new(ff.Scalar)
		diff.Sub(xi, xj)
		denominator.Mul(denominator, diff)
	}

	denInv := new(ff.Scalar)
	denInv.Inv(denominator)

	result := new(ff.Scalar)
	result.Mul(numerator, denInv)

	return result
}

func lagrangeCoefficientForIndices(indices []int, i int) *ff.Scalar {
	numerator := new(ff.Scalar)
	numerator.SetUint64(1)
	denominator := new(ff.Scalar)
	denominator.SetUint64(1)

	xi := new(ff.Scalar)
	xi.SetUint64(uint64(indices[i]))

	for j := range indices {
		if i == j {
			continue
		}

		xj := new(ff.Scalar)
		xj.SetUint64(uint64(indices[j]))

		negXj := new(ff.Scalar)
		numerator.Mul(numerator, negXj)

		diff := new(ff.Scalar)
		diff.Sub(xi, xj)
		denominator.Mul(denominator, diff)
	}

	denInv := new(ff.Scalar)
	denInv.Inv(denominator)

	result := new(ff.Scalar)
	result.Mul(numerator, denInv)

	return result
}

func SaveShareToPEM(filename string, share Share) error {
	valueBytes, err := share.Value.MarshalBinary()
	if err != nil {
		return err
	}

	data := append([]byte{byte(share.Index)}, valueBytes...)

	block := &pem.Block{
		Type:  "THRESHOLD IBE SHARE",
		Bytes: data,
	}

	return savePEMToFile(filename, block, true)
}

func LoadShareFromPEM(filename string) (Share, error) {
	fileData, err := os.ReadFile(filename)
	if err != nil {
		return Share{}, err
	}

	block, _ := pem.Decode(fileData)
	if block == nil {
		return Share{}, fmt.Errorf("failed to decode PEM block")
	}

	var shareBytes []byte
	if x509.IsEncryptedPEMBlock(block) {
		if pwd == nil || *pwd == "" {
			return Share{}, fmt.Errorf("PEM file is encrypted, but no password was provided")
		}
		shareBytes, err = DecryptPEMBlock(block, []byte(*pwd))
		if err != nil {
			return Share{}, fmt.Errorf("error decrypting PEM block: %v", err)
		}
	} else {
		shareBytes = block.Bytes
	}

	if len(shareBytes) < 1 {
		return Share{}, fmt.Errorf("invalid share data")
	}

	index := int(shareBytes[0])
	valueBytes := shareBytes[1:]

	value := new(ff.Scalar)
	if err := value.UnmarshalBinary(valueBytes); err != nil {
		return Share{}, fmt.Errorf("failed to unmarshal share value: %v", err)
	}

	return Share{Index: index, Value: value}, nil
}

func encodePrivateKeyPEM(privPEM *PrivateKey) ([]byte, error) {
	privBytes, err := MarshalPKCS8PrivateKey(privPEM)
	if err != nil {
		return nil, err
	}

	return privBytes, nil
}

func savePrivateKeyToPEM(fileName string, privKey *PrivateKey) error {
	privBytes, err := MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return err
	}
	privPEM := &pem.Block{
		Type:  "ELGAMAL PRIVATE KEY",
		Bytes: privBytes,
	}
	return savePEMToFile(fileName, privPEM, *pwd != "")
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

		decryptedBlock, err := DecryptPEMBlock(block, []byte(*pwd))
		if err != nil {
			return nil, err
		}

		block.Bytes = decryptedBlock
	}

	privKey, err := ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privKey, nil
}

func savePublicKeyToPEM(fileName string, pubKey *PublicKey) error {
	pubBytes, err := MarshalPKCS8PublicKey(pubKey)
	if err != nil {
		return err
	}

	pubPEM := &pem.Block{
		Type:  "ELGAMAL PUBLIC KEY",
		Bytes: pubBytes,
	}

	return savePEMToFile(fileName, pubPEM, false)
}

func readPublicKeyFromPEM(fileName string) (*PublicKey, error) {
	pemData, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	pubKey, err := ParsePKCS8PublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return pubKey, nil
}

func generateRandomX(q *big.Int) (*big.Int, error) {
	max := new(big.Int).Sub(q, big.NewInt(1))
	x, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, err
	}
	return x.Add(x, big.NewInt(1)), nil
}

type ElGamalParams struct {
	P *big.Int
	Q *big.Int
	G *big.Int
}

func generateElGamalParams(pBits int) (*ElGamalParams, error) {
	if pBits < 1024 {
		return nil, errors.New("P must be at least 1024 bits for security")
	}

	var qBits int
	switch {
	case pBits >= 15360:
		qBits = 512
	case pBits >= 7680:
		qBits = 384
	case pBits >= 4096:
		qBits = 320
	case pBits >= 3072:
		qBits = 256
	case pBits >= 2048:
		qBits = 224
	default:
		qBits = 160
	}

	fmt.Fprintf(os.Stderr, "Generating ElGamal params (P: %d bits, Q: %d bits)...", pBits, qBits)

	q, err := rand.Prime(rand.Reader, qBits)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Q: %v", err)
	}
	fmt.Fprint(os.Stderr, " Q found!")

	for attempt := 0; attempt < 20000; attempt++ {
		rBits := pBits - qBits
		r, err := rand.Int(rand.Reader, new(big.Int).Lsh(one, uint(rBits)))
		if err != nil {
			return nil, err
		}

		p := new(big.Int).Mul(r, q)
		p.Add(p, one)

		if p.BitLen() < pBits {
			p.SetBit(p, pBits-1, 1)
		}

		if p.ProbablyPrime(5) {
			fmt.Fprint(os.Stderr, " P found!")

			g, err := findGenerator(p, q)
			if err != nil {
			}
			fmt.Fprint(os.Stderr, " G found!")

			return &ElGamalParams{
				P: p,
				Q: q,
				G: g,
			}, nil
		}

		if attempt%100 == 0 {
			print(".")
		}
	}

	return nil, fmt.Errorf("failed to generate safe prime P after 20000 attempts")
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

type SchnorrPrivateKey struct {
	SchnorrPublicKey
	X *big.Int
}

type SchnorrPublicKey struct {
	P, Q, G, Y *big.Int
}

type SchnorrParams struct {
	P *big.Int
	Q *big.Int
	G *big.Int
}

func generateSchnorrParams(pBits int) (*SchnorrParams, error) {
	if pBits < 1024 {
		return nil, errors.New("P must be at least 1024 bits for security")
	}

	var inferBits int
	switch {
	case pBits >= 15360:
		inferBits = 512
	case pBits >= 7680:
		inferBits = 384
	case pBits >= 4096:
		inferBits = 320
	case pBits >= 3072:
		inferBits = 256
	case pBits >= 2048:
		inferBits = 224
	default:
		inferBits = 160
	}

	fmt.Fprintf(os.Stderr, "Generating Schnorr params (P: %d bits, Q: %d bits)...", pBits, inferBits)

	q, err := rand.Prime(rand.Reader, inferBits)
	if err != nil {
		return nil, err
	}
	fmt.Fprint(os.Stderr, " Q found!")

	for attempt := 0; attempt < 20000; attempt++ {
		rBits := pBits - inferBits
		r, err := rand.Int(rand.Reader, new(big.Int).Lsh(one, uint(rBits)))
		if err != nil {
			return nil, err
		}

		p := new(big.Int).Mul(r, q)
		p.Add(p, one)

		if p.BitLen() < pBits {
			p.SetBit(p, pBits-1, 1)
		}

		if p.ProbablyPrime(5) {
			fmt.Fprint(os.Stderr, " P found!")

			g, err := findGenerator(p, q)
			if err != nil {
			}
			fmt.Fprint(os.Stderr, " G found!")

			return &SchnorrParams{
				P: p,
				Q: q,
				G: g,
			}, nil
		}

		if attempt%100 == 0 {
			print(".")
		}
	}

	return nil, fmt.Errorf("failed to find suitable P after 20000 attempts")
}

func findGenerator(p, q *big.Int) (*big.Int, error) {
	exp := new(big.Int).Sub(p, one)
	exp.Div(exp, q)

	smallPrimes := []int64{
		2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
		31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
		73, 79, 83, 89, 97, 101, 103, 107, 109, 113,
	}

	for _, prime := range smallPrimes {
		h := big.NewInt(prime)
		g := new(big.Int).Exp(h, exp, p)

		if g.Cmp(one) != 0 {
			if new(big.Int).Exp(g, q, p).Cmp(one) == 0 {
				return g, nil
			}
		}
	}

	return nil, errors.New("generator not found in small primes")
}

type schnorrSignature struct {
	E, S *big.Int
}

func signSchnorr(random io.Reader, priv *SchnorrPrivateKey, message []byte, h hash.Hash) (*big.Int, *big.Int, error) {
	k, err := rand.Int(random, new(big.Int).Sub(priv.Q, one))
	if err != nil {
		return nil, nil, err
	}

	r := new(big.Int).Exp(priv.G, k, priv.P)

	e := schnorrHash(&priv.SchnorrPublicKey, r, message, priv.Q, h)

	xE := new(big.Int).Mul(priv.X, e)
	s := new(big.Int).Sub(k, xE)
	s.Mod(s, priv.Q)

	return e, s, nil
}

func verifySchnorr(pub *SchnorrPublicKey, message []byte, e, s *big.Int, h hash.Hash) (bool, error) {
	if e.Cmp(zero) < 0 || e.Cmp(pub.Q) >= 0 {
		return false, errors.New("schnorr: e is out of range")
	}
	if s.Cmp(zero) < 0 || s.Cmp(pub.Q) >= 0 {
		return false, errors.New("schnorr: s is out of range")
	}

	gS := new(big.Int).Exp(pub.G, s, pub.P)
	yE := new(big.Int).Exp(pub.Y, e, pub.P)
	rPrime := new(big.Int).Mul(gS, yE)
	rPrime.Mod(rPrime, pub.P)

	ePrime := schnorrHash(pub, rPrime, message, pub.Q, h)

	ePrimeBytes := bigIntToFixedBytes(ePrime, pub.Q.BitLen())
	eBytes := bigIntToFixedBytes(e, pub.Q.BitLen())

	eq := subtle.ConstantTimeCompare(ePrimeBytes, eBytes) == 1

	return eq, nil
}

func bigIntToFixedBytes(x *big.Int, bitLen int) []byte {
	byteLen := (bitLen + 7) / 8
	b := x.Bytes()
	if len(b) > byteLen {
		b = b[len(b)-byteLen:]
	} else if len(b) < byteLen {
		padded := make([]byte, byteLen)
		copy(padded[byteLen-len(b):], b)
		b = padded
	}
	return b
}

func schnorrHash(pub *SchnorrPublicKey, r *big.Int, message []byte, q *big.Int, h hash.Hash) *big.Int {
	h.Reset()

	h.Write(r.Bytes())
	h.Write(pub.Y.Bytes())
	h.Write(message)

	hash := h.Sum(nil)

	e := new(big.Int).SetBytes(hash)
	return e.Mod(e, q)
}

func SchnorrSignASN1(rand io.Reader, priv *SchnorrPrivateKey, message []byte, h hash.Hash) ([]byte, error) {
	e, s, err := signSchnorr(rand, priv, message, h)
	if err != nil {
		return nil, err
	}

	return asn1.Marshal(schnorrSignature{
		E: e,
		S: s,
	})
}

func SchnorrVerifyASN1(pub *SchnorrPublicKey, message, sig []byte, h hash.Hash) (bool, error) {
	var sign schnorrSignature
	_, err := asn1.Unmarshal(sig, &sign)
	if err != nil {
		return false, err
	}

	return verifySchnorr(pub, message, sign.E, sign.S, h)
}

func ProveKnowledge(priv *SchnorrPrivateKey, message []byte, h hash.Hash) (*big.Int, *big.Int, *big.Int, error) {
	r, err := rand.Int(rand.Reader, new(big.Int).Sub(priv.Q, one))
	if err != nil {
		return nil, nil, nil, err
	}
	r.Add(r, one)

	t := new(big.Int).Exp(priv.G, r, priv.P)

	h.Reset()
	h.Write(t.Bytes())
	h.Write(message)
	digest := h.Sum(nil)

	e := new(big.Int).SetBytes(digest)
	e.Mod(e, priv.Q)

	xE := new(big.Int).Mul(priv.X, e)
	s := new(big.Int).Add(r, xE)
	s.Mod(s, priv.Q)

	return t, e, s, nil
}

func VerifyKnowledge(pub *SchnorrPublicKey, t, e, s *big.Int, message []byte, h hash.Hash) bool {
	gS := new(big.Int).Exp(pub.G, s, pub.P)

	yE := new(big.Int).Exp(pub.Y, e, pub.P)
	yEInv := new(big.Int).ModInverse(yE, pub.P)

	tPrime := new(big.Int).Mul(gS, yEInv)
	tPrime.Mod(tPrime, pub.P)

	h.Reset()
	h.Write(tPrime.Bytes())
	h.Write(message)
	digest := h.Sum(nil)

	ePrime := new(big.Int).SetBytes(digest)
	ePrime.Mod(ePrime, pub.Q)

	return e.Cmp(ePrime) == 0
}

func generatePrivateKey(q *big.Int) (*big.Int, error) {
	x, err := rand.Int(rand.Reader, new(big.Int).Sub(q, one))
	if err != nil {
		return nil, err
	}
	return x.Add(x, one), nil
}

func generatePublicKey(x, g, p *big.Int) *big.Int {
	return new(big.Int).Exp(g, x, p)
}

func encodeSchnorrPrivateKeyPEM(privPEM *SchnorrPrivateKey) ([]byte, error) {
	privBytes, err := MarshalPKCS8SchnorrPrivateKey(privPEM)
	if err != nil {
		return nil, err
	}

	return privBytes, nil
}

func saveSchnorrPrivateKeyToPEM(fileName string, privKey *SchnorrPrivateKey) error {
	privBytes, err := MarshalPKCS8SchnorrPrivateKey(privKey)
	if err != nil {
		return err
	}
	privPEM := &pem.Block{
		Type:  "SCHNORR PRIVATE KEY",
		Bytes: privBytes,
	}
	return savePEMToFile(fileName, privPEM, *pwd != "")
}

func readSchnorrPrivateKeyFromPEM(fileName string) (*SchnorrPrivateKey, error) {
	pemData, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	if block.Type != "SCHNORR PRIVATE KEY" {
		return nil, errors.New("unexpected PEM block type")
	}

	if block.Headers["Proc-Type"] == "4,ENCRYPTED" {
		if *pwd == "" {
			return nil, fmt.Errorf("private key is encrypted, but no decryption key provided")
		}

		decryptedBlock, err := DecryptPEMBlock(block, []byte(*pwd))
		if err != nil {
			return nil, err
		}

		block.Bytes = decryptedBlock
	}

	privKey, err := ParsePKCS8SchnorrPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privKey, nil
}

func saveSchnorrPublicKeyToPEM(fileName string, pubKey *SchnorrPublicKey) error {
	pubBytes, err := MarshalPKCS8SchnorrPublicKey(pubKey)
	if err != nil {
		return err
	}

	pubPEM := &pem.Block{
		Type:  "SCHNORR PUBLIC KEY",
		Bytes: pubBytes,
	}

	return savePEMToFile(fileName, pubPEM, false)
}

func readSchnorrPublicKeyFromPEM(fileName string) (*SchnorrPublicKey, error) {
	pemData, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	if block.Type != "SCHNORR PUBLIC KEY" {
		return nil, errors.New("unexpected PEM block type")
	}

	pubKey, err := ParsePKCS8SchnorrPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return pubKey, nil
}

func MarshalPKCS8SchnorrPrivateKey(priv *SchnorrPrivateKey) ([]byte, error) {
	privASN1 := struct {
		Version int
		P       *big.Int
		Q       *big.Int
		G       *big.Int
		Y       *big.Int
		X       *big.Int
	}{
		Version: 0,
		P:       priv.P,
		Q:       priv.Q,
		G:       priv.G,
		Y:       priv.Y,
		X:       priv.X,
	}
	return asn1.Marshal(privASN1)
}

func ParsePKCS8SchnorrPrivateKey(der []byte) (*SchnorrPrivateKey, error) {
	var privASN1 struct {
		Version int
		P       *big.Int
		Q       *big.Int
		G       *big.Int
		Y       *big.Int
		X       *big.Int
	}

	_, err := asn1.Unmarshal(der, &privASN1)
	if err != nil {
		return nil, err
	}

	return &SchnorrPrivateKey{
		SchnorrPublicKey: SchnorrPublicKey{
			P: privASN1.P,
			Q: privASN1.Q,
			G: privASN1.G,
			Y: privASN1.Y,
		},
		X: privASN1.X,
	}, nil
}

func MarshalPKCS8SchnorrPublicKey(pub *SchnorrPublicKey) ([]byte, error) {
	pubASN1 := struct {
		P *big.Int
		Q *big.Int
		G *big.Int
		Y *big.Int
	}{
		P: pub.P,
		Q: pub.Q,
		G: pub.G,
		Y: pub.Y,
	}
	return asn1.Marshal(pubASN1)
}

func ParsePKCS8SchnorrPublicKey(der []byte) (*SchnorrPublicKey, error) {
	var pubASN1 struct {
		P *big.Int
		Q *big.Int
		G *big.Int
		Y *big.Int
	}

	_, err := asn1.Unmarshal(der, &pubASN1)
	if err != nil {
		return nil, err
	}

	return &SchnorrPublicKey{
		P: pubASN1.P,
		Q: pubASN1.Q,
		G: pubASN1.G,
		Y: pubASN1.Y,
	}, nil
}

func init() {
	gob.Register(&SchnorrParams{})
}

func schnorrParamsToBytes(params *SchnorrParams) ([]byte, error) {
	if params == nil {
		return nil, errors.New("cannot encode nil SchnorrParams pointer")
	}

	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(params)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func bytesToSchnorrParams(data []byte) (*SchnorrParams, error) {
	var params SchnorrParams
	dec := gob.NewDecoder(bytes.NewReader(data))

	err := dec.Decode(&params)
	if err != nil {
		return nil, err
	}

	return &params, nil
}

func saveSchnorrParamsToPEM(fileName string, params *SchnorrParams) error {
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

	paramsBytes, err := schnorrParamsToBytes(params)
	if err != nil {
		return err
	}

	err = pem.Encode(file, &pem.Block{
		Type:  "SCHNORR PARAMETERS",
		Bytes: paramsBytes,
	})
	if err != nil {
		return err
	}

	return nil
}

func readSchnorrParamsFromPEM(fileName string) (*SchnorrParams, error) {
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

	if block.Type != "SCHNORR PARAMETERS" {
		return nil, errors.New("unexpected PEM block type, expected SCHNORR PARAMETERS")
	}

	return bytesToSchnorrParams(block.Bytes)
}

func savePEMToFile(fileName string, block *pem.Block, isPrivateKey bool) error {
	file, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer file.Close()

	if isPrivateKey && *pwd != "" {
		err = EncryptAndWriteBlock(*cph, block, []byte(*pwd), file)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		err = pem.Encode(file, block)
		if err != nil {
			return err
		}
	}

	return nil
}

func savePEMToFile2(fileName string, block *pem.Block, isPrivateKey bool) error {
	file, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer file.Close()

	if isPrivateKey && *pwd2 != "" {
		err = EncryptAndWriteBlock(*cph, block, []byte(*pwd2), file)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		err = pem.Encode(file, block)
		if err != nil {
			return err
		}
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
		decryptedBlock, err := DecryptPEMBlock(block, []byte(*pwd))
		if err != nil {
			return nil, fmt.Errorf("error decrypting PEM block: %v", err)
		}
		return decryptedBlock, nil
	}

	return block.Bytes, nil
}

func GenerateKyber(size int) ([]byte, []byte, error) {
	var seed []byte

	if *seedStr != "" {
		var err error
		seed, err = hex.DecodeString(*seedStr)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid seed format (expected hex): %v", err)
		}
		if len(seed) != 64 {
			return nil, nil, fmt.Errorf("seed must be exactly 64 bytes (128 hex characters)")
		}
	} else {
		seed = make([]byte, 64)
		if _, err := rand.Read(seed); err != nil {
			return nil, nil, err
		}
	}

	var d *kyber.Kyber
	switch size {
	case 512:
		d = kyber.NewKyber512()
	case 768:
		d = kyber.NewKyber768()
	case 1024:
		d = kyber.NewKyber1024()
	default:
		return nil, nil, fmt.Errorf("invalid key size: %d. Valid sizes are: 512, 768 or 1024-bit.", size)
	}

	pk, sk := d.KeyGen(seed)
	return pk, sk, nil
}

func WrapKey(pk []byte) error {
	var k *kyber.Kyber

	switch len(pk) {
	case 800:
		k = kyber.NewKyber512()
	case 1184:
		k = kyber.NewKyber768()
	case 1568:
		k = kyber.NewKyber1024()
	default:
		return fmt.Errorf("invalid public key size: %d", len(pk))
	}

	seed := make([]byte, 32)
	rand.Read(seed)

	ciphertext, ss := k.Encaps(pk, seed)

	ciphertextBlock := &pem.Block{
		Type:  "ML-KEM ENCAPSULATED KEY",
		Bytes: ciphertext,
	}

	var writer io.Writer
	if *cph == "" {
		writer = os.Stdout
	} else {
		file, err := os.Create(*cph)
		if err != nil {
			return fmt.Errorf("error opening file %s: %v", *cph, err)
		}
		defer file.Close()
		writer = file
	}

	err := pem.Encode(writer, ciphertextBlock)
	if err != nil {
		return fmt.Errorf("error encoding ciphertext to PEM: %v", err)
	}

	fmt.Println("Shared=", hex.EncodeToString(ss))
	return nil
}

func UnwrapKey(sk []byte, cipherFile string) ([]byte, error) {
	ciphertext, err := ioutil.ReadFile(cipherFile)
	if err != nil {
		return nil, fmt.Errorf("error reading wrapped key file: %v", err)
	}

	block, _ := pem.Decode(ciphertext)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	var k *kyber.Kyber

	switch len(sk) {
	case 1632:
		k = kyber.NewKyber512()
	case 2400:
		k = kyber.NewKyber768()
	case 3168:
		k = kyber.NewKyber1024()
	default:
		return nil, fmt.Errorf("invalid public key size: %d", len(sk))
	}

	unwrappedSecret := k.Decaps(sk, block.Bytes)

	return unwrappedSecret, nil
}

const (
	Dilithium2Size = 2048
	Dilithium3Size = 3072
	Dilithium5Size = 4096
)

func GetDilithium(size int) *dilithium.Dilithium {
	switch size {
	case Dilithium2Size:
		return dilithium.NewDilithium2()
	case Dilithium3Size:
		return dilithium.NewDilithium3()
	case Dilithium5Size:
		return dilithium.NewDilithium5()
	default:
		return nil
	}
}

func GenerateDilithium(length int) ([]byte, []byte, error) {
	var seed []byte

	if *seedStr != "" {
		var err error
		seed, err = hex.DecodeString(*seedStr)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid seed format (expected hex): %v", err)
		}
		if len(seed) != 32 {
			return nil, nil, fmt.Errorf("seed must be exactly 32 bytes (64 hex characters)")
		}
	} else {
		seed = make([]byte, 32)
		if _, err := rand.Read(seed); err != nil {
			return nil, nil, err
		}
	}

	d := GetDilithium(length)
	if d == nil {
		return nil, nil, fmt.Errorf("invalid key size: %d. Valid sizes are: 2048, 3072 or 4096-bit.", length)
	}
	pk, sk := d.KeyGen(seed)

	return pk, sk, nil
}

func Sign(sk []byte, msgInput io.Reader) ([]byte, error) {
	msg, err := ioutil.ReadAll(msgInput)
	if err != nil {
		return nil, err
	}

	var d *dilithium.Dilithium
	switch len(sk) {
	case 2528:
		d = dilithium.NewDilithium2()
	case 4000:
		d = dilithium.NewDilithium3()
	case 4864:
		d = dilithium.NewDilithium5()
	default:
		return nil, fmt.Errorf("invalid secret key size: %d", len(sk))
	}

	signature := d.Sign(sk, msg)

	return signature, nil
}

func Verify(pk []byte, signatureFile string, msg []byte) error {
	signatureBytes, err := ioutil.ReadFile(signatureFile)
	if err != nil {
		return err
	}

	block, _ := pem.Decode(signatureBytes)
	if block == nil {
		return fmt.Errorf("failed to decode PEM block")
	}

	if block.Type != "ML-DSA SIGNATURE" {
		return fmt.Errorf("unexpected PEM block type: %s", block.Type)
	}

	signature := block.Bytes

	var d *dilithium.Dilithium
	switch len(pk) {
	case 1312:
		d = dilithium.NewDilithium2()
	case 1952:
		d = dilithium.NewDilithium3()
	case 2592:
		d = dilithium.NewDilithium5()
	default:
		return fmt.Errorf("invalid public key size: %d", len(pk))
	}

	verified := d.Verify(pk, msg, signature)
	if !verified {
		return fmt.Errorf("verification failed")
	}

	return nil
}

func VerifyBytes(pk []byte, signature []byte, msg []byte) error {
	var d *dilithium.Dilithium
	switch len(pk) {
	case 1312:
		d = dilithium.NewDilithium2()
	case 1952:
		d = dilithium.NewDilithium3()
	case 2592:
		d = dilithium.NewDilithium5()
	default:
		return fmt.Errorf("invalid public key size: %d", len(pk))
	}

	verified := d.Verify(pk, msg, signature)
	if !verified {
		return fmt.Errorf("verification failed")
	}

	return nil
}

func SaveSignatureToPEM(signature []byte, filename string) error {
	signatureBlock := &pem.Block{
		Type:  "ML-DSA SIGNATURE",
		Bytes: signature,
	}

	if filename == "" {
		err := pem.Encode(os.Stdout, signatureBlock)
		if err != nil {
			return fmt.Errorf("error encoding signature to PEM: %v", err)
		}
		return nil
	}

	return savePEMToFile(filename, signatureBlock, false)
}

type PKCS8Key struct{}

func NewPKCS8Key() PKCS8Key {
	return PKCS8Key{}
}

func (this PKCS8Key) MarshalPublicKey(key *PublicKey) ([]byte, error) {
	pubASN1 := struct {
		P *big.Int
		Q *big.Int
		G *big.Int
		Y *big.Int
	}{
		P: key.P,
		Q: key.Q,
		G: key.G,
		Y: key.Y,
	}
	return asn1.Marshal(pubASN1)
}

func MarshalPKCS8PublicKey(pub *PublicKey) ([]byte, error) {
	return NewPKCS8Key().MarshalPublicKey(pub)
}

func (this PKCS8Key) ParsePublicKey(der []byte) (*PublicKey, error) {
	var pubASN1 struct {
		P *big.Int
		Q *big.Int
		G *big.Int
		Y *big.Int
	}

	_, err := asn1.Unmarshal(der, &pubASN1)
	if err != nil {
		return nil, err
	}

	return &PublicKey{
		P: pubASN1.P,
		Q: pubASN1.Q,
		G: pubASN1.G,
		Y: pubASN1.Y,
	}, nil
}

func ParsePKCS8PublicKey(derBytes []byte) (*PublicKey, error) {
	return NewPKCS8Key().ParsePublicKey(derBytes)
}

func (this PKCS8Key) MarshalPrivateKey(key *PrivateKey) ([]byte, error) {
	privASN1 := struct {
		Version int
		P       *big.Int
		Q       *big.Int
		G       *big.Int
		Y       *big.Int
		X       *big.Int
	}{
		Version: 0,
		P:       key.P,
		Q:       key.Q,
		G:       key.G,
		Y:       key.Y,
		X:       key.X,
	}
	return asn1.Marshal(privASN1)
}

func MarshalPKCS8PrivateKey(key *PrivateKey) ([]byte, error) {
	return NewPKCS8Key().MarshalPrivateKey(key)
}

func (this PKCS8Key) ParsePrivateKey(der []byte) (key *PrivateKey, err error) {
	var privASN1 struct {
		Version int
		P       *big.Int
		Q       *big.Int
		G       *big.Int
		Y       *big.Int
		X       *big.Int
	}

	_, err = asn1.Unmarshal(der, &privASN1)
	if err != nil {
		return nil, err
	}

	return &PrivateKey{
		PublicKey: PublicKey{
			P: privASN1.P,
			Q: privASN1.Q,
			G: privASN1.G,
			Y: privASN1.Y,
		},
		X: privASN1.X,
	}, nil
}

func ParsePKCS8PrivateKey(derBytes []byte) (key *PrivateKey, err error) {
	return NewPKCS8Key().ParsePrivateKey(derBytes)
}

func encryptBN(message string, publicKey *bn256.G2, hashFunc func() hash.Hash) (*bn256.G1, []byte, []byte) {
	messageBytes := []byte(message)

	k, err := rand.Int(rand.Reader, bn256.Order)
	if err != nil {
		log.Fatal(err)
	}

	C1 := new(bn256.G1).ScalarBaseMult(k)

	pairingResult := bn256.Pair(C1, publicKey)
	pairingBytes := pairingResult.Marshal()

	S1, S2 := deriveKeys(pairingBytes, hashFunc)

	mask := expandKey(S1, len(messageBytes), hashFunc)
	encrypted := make([]byte, len(messageBytes))
	for i := range messageBytes {
		encrypted[i] = messageBytes[i] ^ mask[i]
	}

	mac := hmac.New(hashFunc, S2)
	mac.Write(S1)
	mac.Write(messageBytes)
	mac.Write(C1.Marshal())
	authTag := mac.Sum(nil)

	return C1, authTag, encrypted
}

func decryptBN(C1 *bn256.G1, authTag, encrypted []byte, privateKey *big.Int, hashFunc func() hash.Hash) string {
	C1MulPrivate := new(bn256.G1).ScalarMult(C1, privateKey)

	pairingResult := bn256.Pair(C1MulPrivate, new(bn256.G2).ScalarBaseMult(big.NewInt(1)))
	pairingBytes := pairingResult.Marshal()

	S1, S2 := deriveKeys(pairingBytes, hashFunc)

	mask := expandKey(S1, len(encrypted), hashFunc)
	message := make([]byte, len(encrypted))
	for i := range encrypted {
		message[i] = encrypted[i] ^ mask[i]
	}

	mac := hmac.New(hashFunc, S2)
	mac.Write(S1)
	mac.Write(message)
	mac.Write(C1.Marshal())
	expectedAuthTag := mac.Sum(nil)

	if !hmac.Equal(expectedAuthTag, authTag) {
		log.Fatal("Authentication failed! Message integrity compromised.")
	}

	return string(message)
}

type CiphertextBN struct {
	C1 []byte
	C2 []byte
	C3 []byte
}

func serializeToASN1(C1 *bn256.G1, C2 []byte, encryptedMessage []byte) ([]byte, error) {
	C1Bytes := C1.Marshal()

	cipher := CiphertextBN{
		C1: C1Bytes,
		C2: C2,
		C3: encryptedMessage,
	}

	return asn1.Marshal(cipher)
}

func deserializeFromASN1(serialized []byte) (*bn256.G1, []byte, []byte, error) {
	var cipher CiphertextBN

	_, err := asn1.Unmarshal(serialized, &cipher)
	if err != nil {
		return nil, nil, nil, err
	}

	C1 := new(bn256.G1)
	_, err = C1.Unmarshal(cipher.C1)
	if err != nil {
		return nil, nil, nil, err
	}

	return C1, cipher.C2, cipher.C3, nil
}

func encryptBLS(message string, publicKey *bls12381.G2, hashFunc func() hash.Hash) (*bls12381.G1, []byte, []byte) {
	messageBytes := []byte(message)
	order := new(big.Int).SetBytes(bls12381.Order())

	k, err := rand.Int(rand.Reader, order)
	if err != nil {
		log.Fatal(err)
	}

	kScalar := new(ff.Scalar)
	kScalar.SetBytes(k.Bytes())

	baseG1 := bls12381.G1Generator()
	C1 := new(bls12381.G1)
	C1.ScalarMult(kScalar, baseG1)

	pairingResult := bls12381.Pair(C1, publicKey)
	pairingBytes, err := pairingResult.MarshalBinary()
	if err != nil {
		log.Fatal(err)
	}

	S1, S2 := deriveKeys(pairingBytes, hashFunc)

	mask := expandKey(S1, len(messageBytes), hashFunc)
	encrypted := make([]byte, len(messageBytes))
	for i := range messageBytes {
		encrypted[i] = messageBytes[i] ^ mask[i]
	}

	mac := hmac.New(hashFunc, S2)
	mac.Write(S1)
	mac.Write(encrypted)
	mac.Write(C1.BytesCompressed())
	authTag := mac.Sum(nil)

	return C1, authTag, encrypted
}

func decryptBLS(C1 *bls12381.G1, authTag []byte, encrypted []byte, privateKey *big.Int, hashFunc func() hash.Hash) string {
	skScalar := new(bls12381.Scalar)
	skScalar.SetBytes(privateKey.Bytes())

	C1MulPrivate := new(bls12381.G1)
	C1MulPrivate.ScalarMult(skScalar, C1)

	pairingResult := bls12381.Pair(C1MulPrivate, bls12381.G2Generator())
	pairingBytes, err := pairingResult.MarshalBinary()
	if err != nil {
		log.Fatal(err)
	}

	S1, S2 := deriveKeys(pairingBytes, hashFunc)

	mask := expandKey(S1, len(encrypted), hashFunc)
	message := make([]byte, len(encrypted))
	for i := range encrypted {
		message[i] = encrypted[i] ^ mask[i]
	}

	mac := hmac.New(hashFunc, S2)
	mac.Write(S1)
	mac.Write(encrypted)
	mac.Write(C1.BytesCompressed())
	expectedAuthTag := mac.Sum(nil)

	if !hmac.Equal(expectedAuthTag, authTag) {
		log.Fatal("Authentication failed! Message integrity compromised.")
	}

	return string(message)
}

type CiphertextBLS struct {
	C1 []byte
	C2 []byte
	C3 []byte
}

func serializeToASN1BLS(C1 *bls12381.G1, C2 []byte, encryptedMessage []byte) ([]byte, error) {
	C1Bytes := C1.Bytes()

	cipher := CiphertextBLS{
		C1: C1Bytes,
		C2: C2,
		C3: encryptedMessage,
	}

	serialized, err := asn1.Marshal(cipher)
	if err != nil {
		return nil, err
	}

	return serialized, nil
}

func deserializeFromASN1BLS(serialized []byte) (*bls12381.G1, []byte, []byte, error) {
	var cipher CiphertextBLS

	_, err := asn1.Unmarshal(serialized, &cipher)
	if err != nil {
		return nil, nil, nil, err
	}

	C1 := new(bls12381.G1)
	err = C1.SetBytes(cipher.C1)
	if err != nil {
		return nil, nil, nil, err
	}

	return C1, cipher.C2, cipher.C3, nil
}

type CiphertextBF struct {
	U []byte
	V []byte
	H []byte
}

func serializeToASN1BF_BN(U *bn256.G2, V, H []byte) ([]byte, error) {
	cipher := CiphertextBF{
		U: U.Marshal(),
		V: V,
		H: H,
	}

	serialized, err := asn1.Marshal(cipher)
	if err != nil {
		return nil, err
	}

	return serialized, nil
}

func deserializeFromASN1BF_BN(serialized []byte) (*bn256.G2, []byte, []byte, error) {
	var cipher CiphertextBF

	_, err := asn1.Unmarshal(serialized, &cipher)
	if err != nil {
		return nil, nil, nil, err
	}

	U := new(bn256.G2)
	_, err = U.Unmarshal(cipher.U)
	if err != nil {
		return nil, nil, nil, err
	}

	return U, cipher.V, cipher.H, nil
}

func serializeToASN1BF(U *bls12381.G2, V, H []byte) ([]byte, error) {
	cipher := CiphertextBF{
		U: U.BytesCompressed(),
		V: V,
		H: H,
	}

	serialized, err := asn1.Marshal(cipher)
	if err != nil {
		return nil, err
	}

	return serialized, nil
}

func deserializeFromASN1BF(serialized []byte) (*bls12381.G2, []byte, []byte, error) {
	var cipher CiphertextBF

	_, err := asn1.Unmarshal(serialized, &cipher)
	if err != nil {
		return nil, nil, nil, err
	}

	U := new(bls12381.G2)
	_ = U.SetBytes(cipher.U)
	if err != nil {
		return nil, nil, nil, err
	}

	return U, cipher.V, cipher.H, nil
}

type CiphertextFO struct {
	U []byte
	V []byte
	W []byte
}

func serializeToASN1BF_FO(U *bls12381.G2, V, W []byte) ([]byte, error) {
	cipher := CiphertextFO{
		U: U.BytesCompressed(),
		V: V,
		W: W,
	}

	serialized, err := asn1.Marshal(cipher)
	if err != nil {
		return nil, err
	}

	return serialized, nil
}

func deserializeFromASN1BF_FO(serialized []byte) (*bls12381.G2, []byte, []byte, error) {
	var cipher CiphertextFO

	_, err := asn1.Unmarshal(serialized, &cipher)
	if err != nil {
		return nil, nil, nil, err
	}

	U := new(bls12381.G2)
	_ = U.SetBytes(cipher.U)
	if err != nil {
		return nil, nil, nil, err
	}

	return U, cipher.V, cipher.W, nil
}

func serializeToASN1BF_FO_BN(U *bn256.G2, V, W []byte) ([]byte, error) {
	cipher := CiphertextFO{
		U: U.Marshal(),
		V: V,
		W: W,
	}

	serialized, err := asn1.Marshal(cipher)
	if err != nil {
		return nil, err
	}

	return serialized, nil
}

func deserializeFromASN1BF_FO_BN(serialized []byte) (*bn256.G2, []byte, []byte, error) {
	var cipher CiphertextFO

	_, err := asn1.Unmarshal(serialized, &cipher)
	if err != nil {
		return nil, nil, nil, err
	}

	U := new(bn256.G2)
	_, err = U.Unmarshal(cipher.U)
	if err != nil {
		return nil, nil, nil, err
	}

	return U, cipher.V, cipher.W, nil
}

type CiphertextSK struct {
	U []byte
	V []byte
	W []byte
}

func serializeToASN1SK_FO(U *bls12381.G1, V, W []byte) ([]byte, error) {
	cipher := CiphertextSK{
		U: U.BytesCompressed(),
		V: V,
		W: W,
	}

	serialized, err := asn1.Marshal(cipher)
	if err != nil {
		return nil, err
	}

	return serialized, nil
}

func deserializeFromASN1SK_FO(serialized []byte) (*bls12381.G1, []byte, []byte, error) {
	var cipher CiphertextSK

	_, err := asn1.Unmarshal(serialized, &cipher)
	if err != nil {
		return nil, nil, nil, err
	}

	U := new(bls12381.G1)
	_ = U.SetBytes(cipher.U)
	if err != nil {
		return nil, nil, nil, err
	}

	return U, cipher.V, cipher.W, nil
}

type Certificate struct {
	SerialNumber   *big.Int  `asn1:"explicit,tag:0"`
	Subject        pkix.Name `asn1:"explicit,tag:1"`
	Issuer         pkix.Name `asn1:"explicit,tag:2"`
	NotBefore      time.Time `asn1:"explicit,tag:3"`
	NotAfter       time.Time `asn1:"explicit,tag:4"`
	PublicKey      []byte    `asn1:"explicit,tag:5"`
	SubjectKeyID   []byte    `asn1:"explicit,tag:6"`
	AuthorityKeyID []byte    `asn1:"explicit,tag:7"`
	SubjectEmail   string    `asn1:"explicit,tag:8"`
	IsCA           bool      `asn1:"explicit,tag:9"`
	Signature      []byte    `asn1:"explicit,tag:10"`
}

type CA struct {
	PrivateKey  []byte
	Certificate Certificate
}

func (ca *CA) IssueCertificate(subject pkix.Name, email string, publicKey, privateKey []byte, isCA bool, validityDays string) (*Certificate, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 160)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("Failed to generate serial number: %v", err)
	}

	hash := sha3.Sum256(publicKey)
	subjectKeyID := hash[:20]

	caHash := sha3.Sum256(ca.Certificate.PublicKey)
	authorityKeyID := caHash[:20]

	validity, err := strconv.Atoi(validityDays)
	if err != nil {
		log.Fatalf("Invalid validity: %v", err)
	}
	notAfter := time.Now().Add(time.Duration(validity) * 24 * time.Hour)

	cert := &Certificate{
		SerialNumber:   serialNumber,
		Subject:        subject,
		SubjectEmail:   email,
		Issuer:         subject,
		NotBefore:      time.Now(),
		NotAfter:       notAfter,
		PublicKey:      publicKey,
		SubjectKeyID:   subjectKeyID,
		AuthorityKeyID: authorityKeyID,
		IsCA:           isCA,
	}

	if !isCA {
		cert.Issuer = ca.Certificate.Subject
	}

	if *isca {
		cert.IsCA = true
	}

	TBS := struct {
		SerialNumber   *big.Int  `asn1:"explicit,tag:0"`
		Subject        pkix.Name `asn1:"explicit,tag:1"`
		Issuer         pkix.Name `asn1:"explicit,tag:2"`
		NotBefore      time.Time `asn1:"explicit,tag:3"`
		NotAfter       time.Time `asn1:"explicit,tag:4"`
		PublicKey      []byte    `asn1:"explicit,tag:5"`
		SubjectKeyID   []byte    `asn1:"explicit,tag:6"`
		AuthorityKeyID []byte    `asn1:"explicit,tag:7"`
		SubjectEmail   string    `asn1:"explicit,tag:8"`
		IsCA           bool      `asn1:"explicit,tag:9"`
	}{
		SerialNumber:   cert.SerialNumber,
		Subject:        cert.Subject,
		Issuer:         cert.Issuer,
		NotBefore:      cert.NotBefore,
		NotAfter:       cert.NotAfter,
		PublicKey:      publicKey,
		SubjectKeyID:   subjectKeyID,
		AuthorityKeyID: authorityKeyID,
		SubjectEmail:   email,
		IsCA:           cert.IsCA,
	}

	certData, err := asn1.Marshal(TBS)
	if err != nil {
		return nil, fmt.Errorf("error serializing the data for signing: %v", err)
	}

	var signature []byte

	switch strings.ToUpper(*alg) {
	case "ML-DSA":
		signature, err = Sign(privateKey, bytes.NewReader(certData))
		if err != nil {
			return nil, fmt.Errorf("failed to sign with ML-DSA: %v", err)
		}
	case "SLH-DSA":
		signature, err = SignSLH(privateKey, bytes.NewReader(certData))
		if err != nil {
			return nil, fmt.Errorf("failed to sign with SLH-DSA: %v", err)
		}
	case "BN256I":
		skBigInt := new(big.Int).SetBytes(privateKey)
		hash := bn256.HashG1(certData, []byte(*salt))
		signatureBN := hash.ScalarMult(hash, skBigInt)
		if err != nil {
			return nil, fmt.Errorf("failed to sign with BN256: %v", err)
		}
		signature = signatureBN.Marshal()
	case "BLS12381I":
		var privKey bls.PrivateKey[bls.G2]
		privKey.UnmarshalBinary(privateKey)
		signature = bls.Sign(&privKey, certData)
		if err != nil {
			return nil, fmt.Errorf("failed to sign with BLS12381: %v", err)
		}
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", *alg)
	}

	cert.Signature = signature

	return cert, nil
}

func SaveCertificateToPEM(cert *Certificate, filename string) error {
	certData, err := asn1.Marshal(*cert)
	if err != nil {
		return fmt.Errorf("error serializing the certificate: %v", err)
	}

	certBlock := &pem.Block{
		Type:  strings.ToUpper(*alg) + " CERTIFICATE",
		Bytes: certData,
	}

	if filename == "stdout" {
		err := pem.Encode(os.Stdout, certBlock)
		if err != nil {
			return fmt.Errorf("error printing the certificate to stdout: %v", err)
		}
	} else {
		file, err := os.Create(filename)
		if err != nil {
			return fmt.Errorf("error creating the file: %v", err)
		}
		defer file.Close()

		err = pem.Encode(file, certBlock)
		if err != nil {
			return fmt.Errorf("error writing the certificate to the file: %v", err)
		}
	}

	return nil
}

func NewCA(privateKey, publicKey []byte, validityDays string) *CA {
	validity, err := strconv.Atoi(validityDays)
	if err != nil {
		log.Fatalf("Invalid validity: %v", err)
	}
	notAfter := time.Now().Add(time.Duration(validity) * 24 * time.Hour)
	return &CA{
		PrivateKey: privateKey,
		Certificate: Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{},
			Issuer:       pkix.Name{},
			NotBefore:    time.Now(),
			NotAfter:     notAfter,
			PublicKey:    publicKey,
		},
	}
}

func VerifyCertificate(cert *Certificate, publicKey []byte) error {
	TBS := struct {
		SerialNumber   *big.Int  `asn1:"explicit,tag:0"`
		Subject        pkix.Name `asn1:"explicit,tag:1"`
		Issuer         pkix.Name `asn1:"explicit,tag:2"`
		NotBefore      time.Time `asn1:"explicit,tag:3"`
		NotAfter       time.Time `asn1:"explicit,tag:4"`
		PublicKey      []byte    `asn1:"explicit,tag:5"`
		SubjectKeyID   []byte    `asn1:"explicit,tag:6"`
		AuthorityKeyID []byte    `asn1:"explicit,tag:7"`
		SubjectEmail   string    `asn1:"explicit,tag:8"`
		IsCA           bool      `asn1:"explicit,tag:9"`
	}{
		SerialNumber:   cert.SerialNumber,
		Subject:        cert.Subject,
		Issuer:         cert.Issuer,
		NotBefore:      cert.NotBefore,
		NotAfter:       cert.NotAfter,
		PublicKey:      cert.PublicKey,
		SubjectKeyID:   cert.SubjectKeyID,
		AuthorityKeyID: cert.AuthorityKeyID,
		SubjectEmail:   cert.SubjectEmail,
		IsCA:           cert.IsCA,
	}

	certData, err := asn1.Marshal(TBS)
	if err != nil {
		return fmt.Errorf("error serializing the certificate data: %v", err)
	}

	signature := cert.Signature

	switch strings.ToUpper(*alg) {
	case "ML-DSA":
		return VerifyBytes(publicKey, signature, certData)
	case "SLH-DSA":
		return VerifySLH(publicKey, signature, certData)
	case "BN256I":
		return VerifyBN(publicKey, signature, certData, []byte(*salt))
	case "BLS12381I":
		return VerifyBLS(publicKey, signature, certData)
	default:
		return fmt.Errorf("unsupported algorithm: %s", *alg)
	}
}

func ReadCertificateFromPEM(filename string) (*Certificate, error) {
	certBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(certBytes)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	if block.Type != strings.ToUpper(*alg)+" CERTIFICATE" {
		return nil, errors.New("unexpected PEM block type")
	}

	var cert Certificate
	_, err = asn1.Unmarshal(block.Bytes, &cert)
	if err != nil {
		return nil, fmt.Errorf("error deserializing the certificate (ASN.1): %v", err)
	}

	return &cert, nil
}

func (cert *Certificate) IsValid() bool {
	now := time.Now()
	return now.After(cert.NotBefore) && now.Before(cert.NotAfter)
}

func PrintInfo(certOrCsr interface{}) {
	switch v := certOrCsr.(type) {
	case *Certificate:
		PrintCertificateInfo(v)
	case *CSR:
		PrintCSRInfo(v)
	default:
		fmt.Println("Unknown type!")
	}
}

func PrintCertificateInfo(cert *Certificate) {
	fmt.Printf("Certificate:\n")
	fmt.Printf("    Data:\n")
	fmt.Printf("        Serial Number: %s (0x%x)\n", cert.SerialNumber.String(), cert.SerialNumber)
	fmt.Printf("        Issuer: %s\n", cert.Issuer)
	fmt.Printf("        Authority Key ID: %x\n", cert.AuthorityKeyID)
	fmt.Printf("        Validity\n")
	fmt.Printf("            Not Before: %s\n", cert.NotBefore.Format(time.RFC3339))
	fmt.Printf("            Not After : %s\n", cert.NotAfter.Format(time.RFC3339))
	fmt.Printf("        Subject: %s\n", cert.Subject)
	fmt.Printf("        Subject Key ID:   %x\n", cert.SubjectKeyID)
	fmt.Printf("        Subject Email:    %s\n", cert.SubjectEmail)
	if cert.IsCA == true {
		fmt.Printf("        IsCA:             %v\n", cert.IsCA)
	}
	fmt.Printf("    Signature Algorithm: %s\n", strings.ToUpper(*alg))
	fmt.Printf("    Public Key:\n")
	if strings.ToUpper(*alg) == "SLH-DSA" || strings.ToUpper(*alg) == "ML-DSA" {
		splitz := SplitSubN(hex.EncodeToString(cert.PublicKey[:64]), 2)
		for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
			fmt.Printf("        %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
		}
	} else {
		splitz := SplitSubN(hex.EncodeToString(cert.PublicKey), 2)
		for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
			fmt.Printf("        %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
		}
	}
	if strings.ToUpper(*alg) == "ML-DSA" {
		fmt.Println("        [...]")
	}
	fmt.Printf("    Signature:\n")
	if strings.ToUpper(*alg) == "BLS12381I" {
		splitz := SplitSubN(hex.EncodeToString(cert.Signature), 2)
		for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
			fmt.Printf("        %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
		}
	} else {
		splitz := SplitSubN(hex.EncodeToString(cert.Signature[:64]), 2)
		for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
			fmt.Printf("        %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
		}
	}
	if strings.ToUpper(*alg) == "ML-DSA" || strings.ToUpper(*alg) == "SLH-DSA" {
		fmt.Println("        [...]")
	}

	fmt.Printf("IsValid: %t\n", cert.IsValid())
}

func PrintCSRInfo(csr *CSR) {
	fmt.Printf("CSR:\n")
	fmt.Printf("    Data:\n")
	fmt.Printf("        Subject: %s\n", csr.Subject)
	fmt.Printf("        Email:   %s\n", csr.Email)
	fmt.Printf("    Algorithm: %s\n", strings.ToUpper(*alg))
	fmt.Printf("    Public Key:\n")
	if strings.ToUpper(*alg) == "SLH-DSA" || strings.ToUpper(*alg) == "ML-DSA" {
		splitz := SplitSubN(hex.EncodeToString(csr.PublicKey[:64]), 2)
		for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
			fmt.Printf("        %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
		}
	} else {
		splitz := SplitSubN(hex.EncodeToString(csr.PublicKey), 2)
		for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
			fmt.Printf("        %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
		}
	}
	if strings.ToUpper(*alg) == "ML-DSA" {
		fmt.Println("        [...]")
	}
	fmt.Printf("    Signature:\n")
	if strings.ToUpper(*alg) == "BLS12381I" {
		splitz := SplitSubN(hex.EncodeToString(csr.Signature), 2)
		for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
			fmt.Printf("        %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
		}
	} else {
		splitz := SplitSubN(hex.EncodeToString(csr.Signature[:64]), 2)
		for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
			fmt.Printf("        %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
		}
	}
	if strings.ToUpper(*alg) == "ML-DSA" || strings.ToUpper(*alg) == "SLH-DSA" {
		fmt.Println("        [...]")
	}
}

type CSR struct {
	Subject   pkix.Name `asn1:"explicit,tag:0"`
	PublicKey []byte    `asn1:"explicit,tag:1"`
	Email     string    `asn1:"explicit,tag:2"`
	Signature []byte    `asn1:"explicit,tag:3"`
}

func CreateCSR(subject pkix.Name, email string, publicKey, privateKey []byte) (*CSR, error) {
	csr := &CSR{
		Subject:   subject,
		PublicKey: publicKey,
		Email:     email,
	}

	TBS := struct {
		Subject   pkix.Name `asn1:"explicit,tag:0"`
		PublicKey []byte    `asn1:"explicit,tag:1"`
		Email     string    `asn1:"explicit,tag:2"`
	}{
		Subject:   csr.Subject,
		PublicKey: csr.PublicKey,
		Email:     csr.Email,
	}

	certData, err := asn1.Marshal(TBS)
	if err != nil {
		return nil, fmt.Errorf("error serializing CSR data: %v", err)
	}

	var signature []byte

	switch strings.ToUpper(*alg) {
	case "ML-DSA":
		signature, err = Sign(privateKey, bytes.NewReader(certData))
		if err != nil {
			return nil, fmt.Errorf("failed to sign with ML-DSA: %v", err)
		}
	case "SLH-DSA":
		signature, err = SignSLH(privateKey, bytes.NewReader(certData))
		if err != nil {
			return nil, fmt.Errorf("failed to sign with SLH-DSA: %v", err)
		}
	case "BN256I":
		skBigInt := new(big.Int).SetBytes(privateKey)
		hash := bn256.HashG1(certData, []byte(*salt))
		signatureBN := hash.ScalarMult(hash, skBigInt)
		if err != nil {
			return nil, fmt.Errorf("failed to sign with BN256: %v", err)
		}
		signature = signatureBN.Marshal()
	case "BLS12381I":
		var privKey bls.PrivateKey[bls.G2]
		privKey.UnmarshalBinary(privateKey)
		signature = bls.Sign(&privKey, certData)
		if err != nil {
			return nil, fmt.Errorf("failed to sign with BLS12381: %v", err)
		}
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", *alg)
	}

	csr.Signature = signature

	return csr, nil
}

func SignCSR(csr *CSR, ca *CA, privateKey []byte, validityDays string) (*Certificate, error) {
	if !ca.Certificate.IsCA {
		return nil, fmt.Errorf("the CA certificate is not a valid CA, cannot sign CSR")
	}
	err := VerifyCSR(csr)
	if err != nil {
		return nil, fmt.Errorf("CSR verification failed: %v", err)
	}
	signedCert, err := ca.IssueCertificate(csr.Subject, csr.Email, csr.PublicKey, privateKey, false, validityDays)
	if err != nil {
		return nil, fmt.Errorf("failed to issue certificate: %v", err)
	}

	return signedCert, nil
}

func VerifyCSR(csr *CSR) error {
	TBS := struct {
		Subject   pkix.Name `asn1:"explicit,tag:0"`
		PublicKey []byte    `asn1:"explicit,tag:1"`
		Email     string    `asn1:"explicit,tag:2"`
	}{
		Subject:   csr.Subject,
		PublicKey: csr.PublicKey,
		Email:     csr.Email,
	}

	certData, err := asn1.Marshal(TBS)
	if err != nil {
		return fmt.Errorf("error serializing the certificate data (ASN.1): %v", err)
	}

	switch strings.ToUpper(*alg) {
	case "ML-DSA":
		return VerifyBytes(csr.PublicKey, csr.Signature, certData)
	case "SLH-DSA":
		return VerifySLH(csr.PublicKey, csr.Signature, certData)
	case "BN256I":
		return VerifyBN(csr.PublicKey, csr.Signature, certData, []byte(*salt))
	case "BLS12381I":
		return VerifyBLS(csr.PublicKey, csr.Signature, certData)
	default:
		return fmt.Errorf("unsupported algorithm: %s", *alg)
	}
}

func VerifyBN(publicKey []byte, signature []byte, certData []byte, salt []byte) error {
	var pubKey bn256.G2
	_, err := pubKey.Unmarshal(publicKey)
	if err != nil {
		return fmt.Errorf("error deserializing public key: %v", err)
	}

	var sig bn256.G1
	sig.Unmarshal(signature)

	h := bn256.HashG1(certData, salt)
	rhs := bn256.Pair(h, &pubKey)
	lhs := bn256.Pair(&sig, new(bn256.G2).ScalarBaseMult(big.NewInt(1)))

	rhsBytes := rhs.Marshal()
	lhsBytes := lhs.Marshal()

	if len(rhsBytes) != len(lhsBytes) {
		return fmt.Errorf("signature verification failed")
	}

	if subtle.ConstantTimeCompare(rhsBytes, lhsBytes) == 1 {
		return nil
	} else {
		return fmt.Errorf("signature verification failed")
	}
}

func VerifyBLS(publicKey []byte, signature []byte, certData []byte) error {
	var pubKey bls.PublicKey[bls.G2]
	err := pubKey.UnmarshalBinary(publicKey)
	if err != nil {
		return fmt.Errorf("error unmarshaling public key: %v", err)
	}

	valid := bls.Verify(&pubKey, certData, signature)
	if valid {
		return nil
	} else {
		return fmt.Errorf("signature verification failed")
	}
}

func SaveCSRToPEM(csr *CSR, filename string) error {
	csrData, err := asn1.Marshal(*csr)
	if err != nil {
		return fmt.Errorf("error serializing CSR to DER (ASN.1): %v", err)
	}

	csrBlock := &pem.Block{
		Type:  strings.ToUpper(*alg) + "CERTIFICATE REQUEST",
		Bytes: csrData,
	}

	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	return pem.Encode(file, csrBlock)
}

func ReadCSRFromPEM(filename string) (*CSR, error) {
	csrBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(csrBytes)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	if block.Type != strings.ToUpper(*alg)+"CERTIFICATE REQUEST" {
		return nil, errors.New("unexpected PEM block type")
	}

	var csr CSR
	_, err = asn1.Unmarshal(block.Bytes, &csr)
	if err != nil {
		return nil, fmt.Errorf("error deserializing CSR from ASN.1: %v", err)
	}

	return &csr, nil
}

type CRL struct {
	Issuer              pkix.Name            `asn1:"explicit,tag:0"`
	NotBefore           time.Time            `asn1:"explicit,tag:1"`
	NotAfter            time.Time            `asn1:"explicit,tag:2"`
	RawData             []byte               `asn1:"explicit,tag:3"`
	SerialNumber        *big.Int             `asn1:"explicit,tag:4"`
	AuthorityKeyID      []byte               `asn1:"explicit,tag:5"`
	RevokedCertificates []RevokedCertificate `asn1:"explicit,tag:6"`
	Signature           []byte               `asn1:"explicit,tag:7"`
}

type RevokedCertificate struct {
	SerialNumber   *big.Int  `asn1:"explicit,tag:0"`
	RevocationTime time.Time `asn1:"explicit,tag:1"`
}

func NewCRL(ca *CA, oldCRLFile string, validityDays string) (*CRL, error) {
	var revokedCertificates []RevokedCertificate

	validity, err := strconv.Atoi(validityDays)
	if err != nil {
		log.Fatalf("Invalid validity: %v", err)
	}
	notAfter := time.Now().Add(time.Duration(validity) * 24 * time.Hour)

	if oldCRLFile != "" {
		oldCRL, err := ReadCRLFromPEM(oldCRLFile)
		if err != nil {
			return nil, fmt.Errorf("error reading the old CRL: %v", err)
		}
		revokedCertificates = oldCRL.RevokedCertificates
	}

	newCRL := &CRL{
		RevokedCertificates: revokedCertificates,
		Issuer:              ca.Certificate.Subject,
		NotBefore:           time.Now(),
		NotAfter:            notAfter,
		SerialNumber:        big.NewInt(1),
		AuthorityKeyID:      ca.Certificate.AuthorityKeyID,
	}

	return newCRL, nil
}

func (crl *CRL) RevokeCertificate(serialNumber *big.Int) {
	crl.RevokedCertificates = append(crl.RevokedCertificates, RevokedCertificate{
		SerialNumber:   serialNumber,
		RevocationTime: time.Now(),
	})
}

func (crl *CRL) Sign(ca *CA, cert *Certificate) error {
	crl.AuthorityKeyID = cert.AuthorityKeyID

	crl.Issuer = cert.Issuer

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 80)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return fmt.Errorf("error generating the serial number for the CRL: %v", err)
	}
	crl.SerialNumber = serialNumber

	TBS := struct {
		Issuer              pkix.Name            `asn1:"explicit,tag:0"`
		NotBefore           time.Time            `asn1:"explicit,tag:1"`
		NotAfter            time.Time            `asn1:"explicit,tag:2"`
		SerialNumber        *big.Int             `asn1:"explicit,tag:3"`
		AuthorityKeyID      []byte               `asn1:"explicit,tag:4"`
		RevokedCertificates []RevokedCertificate `asn1:"explicit,tag:5"`
	}{
		Issuer:              crl.Issuer,
		NotBefore:           crl.NotBefore,
		NotAfter:            crl.NotAfter,
		SerialNumber:        crl.SerialNumber,
		AuthorityKeyID:      crl.AuthorityKeyID,
		RevokedCertificates: crl.RevokedCertificates,
	}

	crlData, err := asn1.Marshal(TBS)
	if err != nil {
		return fmt.Errorf("error serializing CRL data: %v", err)
	}

	var signature []byte
	switch strings.ToUpper(*alg) {
	case "ML-DSA":
		signature, err = Sign(ca.PrivateKey, bytes.NewReader(crlData))
		if err != nil {
			return fmt.Errorf("failed to sign with ML-DSA: %v", err)
		}
	case "SLH-DSA":
		signature, err = SignSLH(ca.PrivateKey, bytes.NewReader(crlData))
		if err != nil {
			return fmt.Errorf("failed to sign with SLH-DSA: %v", err)
		}
	case "BN256I":
		skBigInt := new(big.Int).SetBytes(ca.PrivateKey)
		hash := bn256.HashG1(crlData, []byte(*salt))
		signatureBN := hash.ScalarMult(hash, skBigInt)
		if err != nil {
			return fmt.Errorf("failed to sign with BN256: %v", err)
		}
		signature = signatureBN.Marshal()
	case "BLS12381I":
		var privKey bls.PrivateKey[bls.G2]
		privKey.UnmarshalBinary(ca.PrivateKey)
		signature = bls.Sign(&privKey, crlData)
		if err != nil {
			return fmt.Errorf("failed to sign with BLS12381: %v", err)
		}
	default:
		return fmt.Errorf("unsupported algorithm: %s", *alg)
	}

	crl.Signature = signature
	crl.RawData = crlData

	return nil
}

func SaveCRLToPEM(crl *CRL, filename string) error {
	crlData, err := asn1.Marshal(*crl)
	if err != nil {
		return fmt.Errorf("error serializing CRL: %v", err)
	}

	crlBlock := &pem.Block{
		Type:  strings.ToUpper(*alg) + " CRL",
		Bytes: crlData,
	}

	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	return pem.Encode(file, crlBlock)
}

func ReadCRLFromPEM(filename string) (*CRL, error) {
	crlBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(crlBytes)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	if block.Type != strings.ToUpper(*alg)+" CRL" {
		return nil, errors.New("unexpected PEM block type")
	}

	var crl CRL
	_, err = asn1.Unmarshal(block.Bytes, &crl)
	if err != nil {
		return nil, fmt.Errorf("error deserializing CRL: %v", err)
	}

	return &crl, nil
}

func (crl *CRL) IsRevoked(serialNumber *big.Int) bool {
	for _, revoked := range crl.RevokedCertificates {
		if revoked.SerialNumber.Cmp(serialNumber) == 0 {
			return true
		}
	}
	return false
}

func readRevokedSerials(filename string) ([]*big.Int, error) {
	var serials []*big.Int

	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if line != "" {
			serial, ok := new(big.Int).SetString(line, 10)
			if ok {
				serials = append(serials, serial)
			} else {
				fmt.Printf("Invalid serial number format: %s\n", line)
			}
		}
	}

	return serials, nil
}

func CheckCRL(crl *CRL, publicKey []byte) error {
	switch strings.ToUpper(*alg) {
	case "ML-DSA":
		if err := VerifyBytes(publicKey, crl.Signature, crl.RawData); err != nil {
			return fmt.Errorf("CRL signature verification failed using ML-DSA: %v", err)
		}
	case "SLH-DSA":
		if err := VerifySLH(publicKey, crl.Signature, crl.RawData); err != nil {
			return fmt.Errorf("CRL signature verification failed using SLH-DSA: %v", err)
		}
	case "BN256I":
		if err := VerifyBN(publicKey, crl.Signature, crl.RawData, []byte(*salt)); err != nil {
			return fmt.Errorf("CRL signature verification failed using BN256: %v", err)
		}
	case "BLS12381I":
		if err := VerifyBLS(publicKey, crl.Signature, crl.RawData); err != nil {
			return fmt.Errorf("CRL signature verification failed using BLS12381: %v", err)
		}
	default:
		return fmt.Errorf("unsupported algorithm: %s", *alg)
	}
	return nil
}

func PrintCRLInfo(crl *CRL) {
	fmt.Printf("CRL:\n")
	fmt.Printf("    Data:\n")
	fmt.Printf("        Number             : %s (%X)\n", crl.SerialNumber.String(), crl.SerialNumber)
	fmt.Printf("        Last Update        : %s\n", crl.NotBefore.Format(time.RFC3339))
	fmt.Printf("        Next Update        : %s\n", crl.NotAfter.Format(time.RFC3339))
	fmt.Printf("        Issuer\n")
	fmt.Printf("            %s\n", crl.Issuer)
	fmt.Printf("        Authority Key ID   : %x\n", crl.AuthorityKeyID)
	fmt.Printf("    Signature Algorithm: %s\n", strings.ToUpper(*alg))
	fmt.Printf("    Signature:\n")
	if strings.ToUpper(*alg) == "BLS12381I" {
		splitz := SplitSubN(hex.EncodeToString(crl.Signature), 2)
		for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
			fmt.Printf("        %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
		}
	} else {
		splitz := SplitSubN(hex.EncodeToString(crl.Signature[:64]), 2)
		for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
			fmt.Printf("        %-10s\n", strings.ReplaceAll(chunk, " ", ":"))
		}
	}
	if strings.ToUpper(*alg) == "ML-DSA" || strings.ToUpper(*alg) == "SLH-DSA" {
		fmt.Println("        [...]")
	}

	fmt.Printf("    Revoked Certificates:\n")
	for _, revoked := range crl.RevokedCertificates {
		fmt.Printf("    - Serial Number: %s\n", revoked.SerialNumber.String())
		fmt.Printf("      Revocation Time: %s\n", revoked.RevocationTime.Format(time.RFC3339))
	}
}

func ChangePrivateKeyPassword(keyFile, oldPassword, newPassword string) error {
	fileContent, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return fmt.Errorf("error reading private key file: %w", err)
	}

	block, _ := pem.Decode(fileContent)
	if block == nil {
		return fmt.Errorf("failed to decode PEM block")
	}

	var privKeyBytes []byte
	if IsEncryptedPEMBlock(block) {
		privKeyBytes, err = DecryptPEMBlock(block, []byte(oldPassword))
		if err != nil {
			return fmt.Errorf("error decrypting private key: %w", err)
		}
	} else {
		privKeyBytes = block.Bytes
	}

	newBlock := &pem.Block{
		Type:  block.Type,
		Bytes: privKeyBytes,
	}

	file, err := os.Create(keyFile)
	if err != nil {
		return fmt.Errorf("error creating private key file: %w", err)
	}
	defer file.Close()

	if newPassword != "" {
		err = EncryptAndWriteBlock(*cph, newBlock, []byte(newPassword), file)
		if err != nil {
			return fmt.Errorf("error saving private key with new password: %w", err)
		}
	} else {
		if err := pem.Encode(file, newBlock); err != nil {
			return fmt.Errorf("error encoding PEM block: %w", err)
		}
	}

	return nil
}

func hashToPoint(data []byte) *big.Int {
	hash, err := lyra2re2.Sum(append([]byte("CRYPTOGRAPHIC DOMAIN|"), data...))
	if err != nil {
		log.Fatal(err)
	}
	hashInt := new(big.Int).SetBytes(hash[:])

	return hashInt
}

func generateMasterPublicKey(masterKey *big.Int) *bn256.G2 {
	publicKey := new(bn256.G2)
	publicKey.ScalarBaseMult(masterKey)

	return publicKey
}

func hashToScalar(data []byte) *ff.Scalar {
	hash, err := lyra2re2.Sum(append([]byte("CRYPTOGRAPHIC DOMAIN|"), data...))
	if err != nil {
		log.Fatal(err)
	}
	hashInt := new(big.Int).SetBytes(hash[:])

	scalar := new(ff.Scalar)
	scalar.SetBytes(hashInt.Bytes())

	return scalar
}

func randomScalar() *ff.Scalar {
	scalar := new(ff.Scalar)
	buf := make([]byte, 32)
	_, err := rand.Read(buf)
	if err != nil {
		log.Fatal("Error generating random number.")
	}
	scalar.SetBytes(buf)
	return scalar
}

func hashToG1(message []byte) *bls12381.G1 {
	hashMessage := new(bls12381.G1)
	hashMessage.Hash(message, nil)
	return hashMessage
}

func extract(msk *ff.Scalar, id []byte) *bls12381.G1 {
	Q := hashToG1(id)
	d := new(bls12381.G1)
	d.ScalarMult(msk, Q)
	return d
}

func extractBN(msk *big.Int, id []byte) *bn256.G1 {
	Qid := bn256.HashG1(id, nil)
	return new(bn256.G1).ScalarMult(Qid, msk)
}

func deriveKeys(pairRaw []byte, hFunc func() hash.Hash) ([]byte, []byte) {
	hkdfEnc := hkdf.New(hFunc, pairRaw, nil, []byte("IBE:Session-Key/Encryption@v1"))
	S1 := make([]byte, 32)
	io.ReadFull(hkdfEnc, S1)

	hkdfMac := hkdf.New(hFunc, pairRaw, nil, []byte("IBE:Session-Key/Authentication@v1"))
	S2 := make([]byte, 32)
	io.ReadFull(hkdfMac, S2)

	return S1, S2
}

func expandKey(S1 []byte, length int, hFunc func() hash.Hash) []byte {
	hkdfStream := hkdf.New(hFunc, S1, nil, []byte("IBE:Stream-XOR-Mask"))
	mask := make([]byte, length)
	io.ReadFull(hkdfStream, mask)
	return mask
}

func combinePartialKeys(partialKeys []PartialKey) (*bls12381.G1, error) {
	if len(partialKeys) < 3 {
		return nil, fmt.Errorf("at least 3 partial keys required for combination")
	}

	indices := make([]int, len(partialKeys))
	for i, pk := range partialKeys {
		indices[i] = pk.Index
	}

	result := new(bls12381.G1)
	result.SetIdentity()

	for i := range partialKeys {
		lambda := lagrangeCoefficientForIndices(indices, i)

		tmp := new(bls12381.G1)
		tmp.ScalarMult(lambda, partialKeys[i].Key)

		result.Add(result, tmp)
	}
	return result, nil
}

func loadPartialKeyFromPEM(filename string) (*bls12381.G1, int, error) {
	file, err := os.ReadFile(filename)
	if err != nil {
		return nil, 0, err
	}

	block, _ := pem.Decode(file)
	if block == nil {
		return nil, 0, fmt.Errorf("failed to parse PEM block")
	}

	if block.Type != "BLS12381 PARTIAL SECRET KEY" {
		return nil, 0, fmt.Errorf("invalid PEM block type: %s", block.Type)
	}

	if len(block.Bytes) < 1 {
		return nil, 0, fmt.Errorf("invalid partial key data")
	}

	index := int(block.Bytes[0])
	keyData := block.Bytes[1:]

	partialKey := new(bls12381.G1)
	if err := partialKey.SetBytes(keyData); err != nil {
		return nil, 0, fmt.Errorf("invalid partial key data: %v", err)
	}

	return partialKey, index, nil
}

func partialExtractFromShare(shareFile string, id []byte) (*bls12381.G1, error) {
	share, err := LoadShareFromPEM(shareFile)
	if err != nil {
		return nil, fmt.Errorf("error loading share %s: %v", shareFile, err)
	}

	partialKey := partialExtract(share, id)
	return partialKey, nil
}

func partialExtract(share Share, id []byte) *bls12381.G1 {
	Q := hashToG1(id)
	d := new(bls12381.G1)
	d.ScalarMult(share.Value, Q)
	return d
}

func encryptBF(P_pub *bls12381.G2, id []byte, M []byte, hFunc func() hash.Hash) (*bls12381.G2, []byte, []byte) {
	r := new(ff.Scalar)
	r.Random(rand.Reader)

	U := new(bls12381.G2)
	U.ScalarMult(r, bls12381.G2Generator())

	Q_ID := hashToG1(id)

	pair := bls12381.Pair(Q_ID, P_pub)
	pair.Exp(pair, r)

	k, _ := pair.MarshalBinary()

	S1, S2 := deriveKeys(k, hFunc)

	mask := expandKey(S1, len(M), hFunc)
	V := make([]byte, len(M))
	for i := range M {
		V[i] = M[i] ^ mask[i]
	}

	mac := hmac.New(hFunc, S2)
	mac.Write(V)
	mac.Write(U.BytesCompressed())
	T := mac.Sum(nil)

	return U, V, T
}

func decryptBF(U *bls12381.G2, d_ID *bls12381.G1, V, T []byte, hFunc func() hash.Hash) ([]byte, bool) {
	pair := bls12381.Pair(d_ID, U)
	k, _ := pair.MarshalBinary()

	S1, S2 := deriveKeys(k, hFunc)

	mask := expandKey(S1, len(V), hFunc)
	M := make([]byte, len(V))
	for i := range V {
		M[i] = V[i] ^ mask[i]
	}

	mac := hmac.New(hFunc, S2)
	mac.Write(V)
	mac.Write(U.BytesCompressed())
	Tcheck := mac.Sum(nil)

	return M, hmac.Equal(T, Tcheck)
}

func encryptBF_BN(Ppub *bn256.G2, id []byte, msg []byte, hFunc func() hash.Hash) (*bn256.G2, []byte, []byte) {
	r, _ := rand.Int(rand.Reader, bn256.Order)
	U := new(bn256.G2).ScalarBaseMult(r)

	Qid := bn256.HashG1(id, nil)
	pair := bn256.Pair(Qid, Ppub)
	pair.ScalarMult(pair, r)

	k := pair.Marshal()
	S1, S2 := deriveKeys(k, hFunc)

	mask := expandKey(S1, len(msg), hFunc)

	V := make([]byte, len(msg))
	for i := range msg {
		V[i] = msg[i] ^ mask[i]
	}

	mac := hmac.New(hFunc, S2)
	mac.Write(V)
	mac.Write(U.Marshal())
	T := mac.Sum(nil)

	return U, V, T
}

func decryptBF_BN(U *bn256.G2, sk *bn256.G1, V, T []byte, hFunc func() hash.Hash) ([]byte, bool) {
	pair := bn256.Pair(sk, U)
	k := pair.Marshal()
	S1, S2 := deriveKeys(k, hFunc)

	mask := expandKey(S1, len(V), hFunc)

	M := make([]byte, len(V))
	for i := range V {
		M[i] = V[i] ^ mask[i]
	}

	mac := hmac.New(hFunc, S2)
	mac.Write(V)
	mac.Write(U.Marshal())
	Tcheck := mac.Sum(nil)

	return M, hmac.Equal(T, Tcheck)
}

func H2(g *bls12381.Gt, hashFunc func() hash.Hash) []byte {
	h := hashFunc()
	h.Write([]byte("H2|"))
	data, err := g.MarshalBinary()
	if err != nil {
		log.Fatal(err)
	}
	h.Write(data)
	return h.Sum(nil)
}

func H3(sigma, M []byte, hashFunc func() hash.Hash) *ff.Scalar {
	h := hashFunc()
	h.Write([]byte("H3|"))
	h.Write(sigma)
	h.Write(M)
	rBytes := h.Sum(nil)

	r := new(ff.Scalar)
	r.SetBytes(rBytes)
	return r
}

func H4(sigma []byte, hashFunc func() hash.Hash, msgLen int) []byte {
	var result []byte
	counter := 0
	for len(result) < msgLen {
		h := hashFunc()
		h.Write([]byte("H4|"))
		h.Write(sigma)

		counterBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(counterBytes, uint32(counter))
		h.Write(counterBytes)

		result = append(result, h.Sum(nil)...)
		counter++
	}
	return result[:msgLen]
}

func encryptFO(Ppub *bls12381.G2, id, M []byte, hashFunc func() hash.Hash) (*bls12381.G2, []byte, []byte) {
	n := 32

	sigma := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, sigma); err != nil {
		log.Fatal(err)
	}

	r := H3(sigma, M, hashFunc)

	U := new(bls12381.G2)
	U.ScalarMult(r, bls12381.G2Generator())

	Q := hashToG1(id)
	g := bls12381.Pair(Q, Ppub)
	g.Exp(g, r)

	h2g := H2(g, hashFunc)
	V := make([]byte, n)
	for i := 0; i < n; i++ {
		V[i] = sigma[i] ^ h2g[i%len(h2g)]
	}

	h4sigma := H4(sigma, hashFunc, len(M))
	W := make([]byte, len(M))
	for i := 0; i < len(M); i++ {
		W[i] = M[i] ^ h4sigma[i]
	}

	return U, V, W
}

func decryptFO(U *bls12381.G2, dID *bls12381.G1, V, W []byte, hashFunc func() hash.Hash) ([]byte, bool) {
	n := len(V)

	g := bls12381.Pair(dID, U)

	h2g := H2(g, hashFunc)
	sigma := make([]byte, n)
	for i := 0; i < n; i++ {
		sigma[i] = V[i] ^ h2g[i%len(h2g)]
	}

	h4sigma := H4(sigma, hashFunc, len(W))
	M := make([]byte, len(W))
	for i := 0; i < len(W); i++ {
		M[i] = W[i] ^ h4sigma[i]
	}

	rPrime := H3(sigma, M, hashFunc)
	UPrime := new(bls12381.G2)
	UPrime.ScalarMult(rPrime, bls12381.G2Generator())

	if !U.IsEqual(UPrime) {
		return nil, false
	}

	return M, true
}

func hashH2(gt *bls12381.Gt, length int, hashFunc func() hash.Hash) []byte {
	raw, err := gt.MarshalBinary()
	if err != nil {
		log.Fatal(err)
	}

	var result []byte
	counter := 0
	for len(result) < length {
		h := hashFunc()
		h.Write(raw)

		counterBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(counterBytes, uint32(counter))
		h.Write(counterBytes)

		result = append(result, h.Sum(nil)...)
		counter++
	}
	return result[:length]
}

func hashH3(sigma, m []byte, hashFunc func() hash.Hash) *ff.Scalar {
	h := hashFunc()
	h.Write(sigma)
	h.Write(m)
	digest := h.Sum(nil)

	s := new(ff.Scalar)
	s.SetBytes(digest)
	return s
}

func hashH4(sigma []byte, length int, hashFunc func() hash.Hash) []byte {
	var result []byte
	counter := 0
	for len(result) < length {
		h := hashFunc()
		h.Write(sigma)

		counterBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(counterBytes, uint32(counter))
		h.Write(counterBytes)

		result = append(result, h.Sum(nil)...)
		counter++
	}
	return result[:length]
}

func setupSK() (*ff.Scalar, *bls12381.G1) {
	s := new(ff.Scalar)
	s.Random(rand.Reader)

	Ppub := new(bls12381.G1)

	return s, Ppub
}

func extractSK(s *ff.Scalar, id []byte) *bls12381.G2 {
	idScalar := hashToScalar(id)
	den := new(ff.Scalar)
	den.Add(s, idScalar)
	if den.IsZero() == 1 {
		log.Fatal("Erro: s + H1(ID) == 0")
	}
	den.Inv(den)

	dA := new(bls12381.G2)
	dA.ScalarMult(den, bls12381.G2Generator())

	return dA
}

func encryptSK(id, m []byte, Ppub *bls12381.G1, hashFunc func() hash.Hash) (*bls12381.G1, []byte, []byte) {
	n := len(m)
	sigma := make([]byte, n)
	_, err := rand.Read(sigma)
	if err != nil {
		log.Fatal(err)
	}

	r := hashH3(sigma, m, hashFunc)
	idScalar := hashToScalar(id)

	QA := new(bls12381.G1)
	QA.ScalarMult(idScalar, bls12381.G1Generator())
	QA.Add(QA, Ppub)

	U := new(bls12381.G1)
	U.ScalarMult(r, QA)

	g := bls12381.Pair(bls12381.G1Generator(), bls12381.G2Generator())
	g.Exp(g, r)

	h2 := hashH2(g, n, hashFunc)
	V := make([]byte, n)
	for i := 0; i < n; i++ {
		V[i] = sigma[i] ^ h2[i]
	}

	h4 := hashH4(sigma, n, hashFunc)
	W := make([]byte, n)
	for i := 0; i < n; i++ {
		W[i] = m[i] ^ h4[i]
	}

	return U, V, W
}

func decryptSK(id []byte, U *bls12381.G1, V, W []byte, dA *bls12381.G2, Ppub *bls12381.G1, hashFunc func() hash.Hash) ([]byte, bool) {
	n := len(V)

	g := bls12381.Pair(U, dA)

	h2 := hashH2(g, n, hashFunc)

	sigma := make([]byte, n)
	for i := 0; i < n; i++ {
		sigma[i] = V[i] ^ h2[i]
	}

	h4 := hashH4(sigma, n, hashFunc)
	m := make([]byte, n)
	for i := 0; i < n; i++ {
		m[i] = W[i] ^ h4[i]
	}

	rPrime := hashH3(sigma, m, hashFunc)

	idScalar := hashToScalar(id)
	QA := new(bls12381.G1)
	QA.ScalarMult(idScalar, bls12381.G1Generator())
	QA.Add(QA, Ppub)

	Ucheck := new(bls12381.G1)
	Ucheck.ScalarMult(rPrime, QA)

	if !Ucheck.IsEqual(U) {
		return nil, false
	}

	return m, true
}

func H2_BN(gt *bn256.GT, hashFunc func() hash.Hash) []byte {
	data := gt.Marshal()
	h := hashFunc()
	h.Write([]byte("H2|"))
	h.Write(data)
	return h.Sum(nil)
}

func H3_BN(sigma, M []byte, hashFunc func() hash.Hash) *big.Int {
	h := hashFunc()
	h.Write([]byte("H3|"))
	h.Write(sigma)
	h.Write(M)
	digest := h.Sum(nil)

	r := new(big.Int).SetBytes(digest)
	return r.Mod(r, bn256.Order)
}

func H4_BN(sigma []byte, hashFunc func() hash.Hash, msgLen int) []byte {
	var result []byte
	counter := 0
	for len(result) < msgLen {
		h := hashFunc()
		h.Write([]byte("H4|"))
		h.Write(sigma)

		counterBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(counterBytes, uint32(counter))
		h.Write(counterBytes)

		result = append(result, h.Sum(nil)...)
		counter++
	}
	return result[:msgLen]
}

func encryptFO_BN(Ppub *bn256.G2, id, M []byte, hashFunc func() hash.Hash) (*bn256.G2, []byte, []byte) {
	n := 32

	sigma := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, sigma); err != nil {
		log.Fatal(err)
	}

	r := H3_BN(sigma, M, hashFunc)

	U := new(bn256.G2).ScalarBaseMult(r)

	Q := bn256.HashG1(id, nil)
	g := bn256.Pair(Q, Ppub)
	g.ScalarMult(g, r)

	h2g := H2_BN(g, hashFunc)
	V := make([]byte, n)
	for i := 0; i < n; i++ {
		V[i] = sigma[i] ^ h2g[i%len(h2g)]
	}

	h4sigma := H4_BN(sigma, hashFunc, len(M))
	W := make([]byte, len(M))
	for i := 0; i < len(M); i++ {
		W[i] = M[i] ^ h4sigma[i]
	}

	return U, V, W
}

func decryptFO_BN(U *bn256.G2, dID *bn256.G1, V, W []byte, hashFunc func() hash.Hash) ([]byte, bool) {
	n := len(V)

	g := bn256.Pair(dID, U)

	h2g := H2_BN(g, hashFunc)
	sigma := make([]byte, n)
	for i := 0; i < n; i++ {
		sigma[i] = V[i] ^ h2g[i%len(h2g)]
	}

	h4sigma := H4_BN(sigma, hashFunc, len(W))
	M := make([]byte, len(W))
	for i := 0; i < len(W); i++ {
		M[i] = W[i] ^ h4sigma[i]
	}

	rPrime := H3_BN(sigma, M, hashFunc)
	UPrime := new(bn256.G2).ScalarBaseMult(rPrime)

	if subtle.ConstantTimeCompare([]byte(U.String()), []byte(UPrime.String())) != 1 {
		return nil, false
	}

	return M, true
}

type SignatureSM struct {
	H []byte `asn1:"tag:0"`
	S []byte `asn1:"tag:1"`
}

func extractSM(msk *ff.Scalar, id []byte) *bls12381.G1 {
	h := hashToScalar(id)
	h.Add(h, msk)

	inv := new(ff.Scalar)
	inv.Inv(h)

	skid := new(bls12381.G1)
	skid.ScalarMult(inv, bls12381.G1Generator())

	return skid
}

func signSM(skid *bls12381.G1, msg []byte) (*ff.Scalar, *bls12381.G1) {
	r := new(ff.Scalar)
	r.Random(rand.Reader)

	g := bls12381.Pair(bls12381.G1Generator(), bls12381.G2Generator())

	w := new(bls12381.Gt)
	w.Exp(g, r)

	wBytes, _ := w.MarshalBinary()
	h := hashToScalar(append(msg, wBytes...))

	r.Sub(r, h)
	S := new(bls12381.G1)
	S.ScalarMult(r, skid)

	return h, S
}

func verifySM(mpk *bls12381.G2, id []byte, msg []byte, h *ff.Scalar, S *bls12381.G1) bool {
	Qid := hashToScalar(id)

	g := bls12381.Pair(bls12381.G1Generator(), bls12381.G2Generator())

	QidP2 := new(bls12381.G2)
	QidP2.ScalarMult(Qid, bls12381.G2Generator())

	temp := new(bls12381.G2)
	temp.Add(mpk, QidP2)

	left := bls12381.Pair(S, temp)

	right := new(bls12381.Gt)
	right.Exp(g, h)

	wPrime := new(bls12381.Gt)
	wPrime.Mul(left, right)

	wPrimeBytes, _ := wPrime.MarshalBinary()
	hPrime := hashToScalar(append(msg, wPrimeBytes...))

	return scalarEqual(h, hPrime)
}

func encodeSignature(h *ff.Scalar, S *bls12381.G1) ([]byte, error) {
	hBytes, _ := h.MarshalBinary()
	SBytes := S.BytesCompressed()

	sig := SignatureSM{
		H: hBytes,
		S: SBytes,
	}

	return asn1.Marshal(sig)
}

func decodeSignature(data []byte) (*ff.Scalar, *bls12381.G1, error) {
	var sig SignatureSM
	_, err := asn1.Unmarshal(data, &sig)
	if err != nil {
		return nil, nil, err
	}

	h := new(ff.Scalar)
	if err := h.UnmarshalBinary(sig.H); err != nil {
		return nil, nil, err
	}

	S := new(bls12381.G1)
	if err := S.SetBytes(sig.S); err != nil {
		return nil, nil, fmt.Errorf("invalid G1 point in signature: %v", err)
	}

	return h, S, nil
}

func extractSM_BN(msk *big.Int, id []byte) *bn256.G1 {
	h := hashToPoint(id)
	sum := new(big.Int).Add(msk, h)
	sum.Mod(sum, bn256.Order)

	inv := new(big.Int).ModInverse(sum, bn256.Order)
	return new(bn256.G1).ScalarBaseMult(inv)
}

func signSM_BN(skid *bn256.G1, msg []byte) (*big.Int, *bn256.G1) {
	r, err := rand.Int(rand.Reader, bn256.Order)
	if err != nil {
		panic(err)
	}

	g := bn256.Pair(new(bn256.G1).ScalarBaseMult(big.NewInt(1)),
		new(bn256.G2).ScalarBaseMult(big.NewInt(1)))

	w := new(bn256.GT).ScalarMult(g, r)

	wBytes := w.Marshal()
	h := hashToPoint(append(msg, wBytes...))

	rh := new(big.Int).Sub(r, h)
	rh.Mod(rh, bn256.Order)
	S := new(bn256.G1).ScalarMult(skid, rh)
	return h, S
}

func verifySM_BN(mpk *bn256.G2, id, msg []byte, h *big.Int, S *bn256.G1) bool {
	Qid := hashToPoint(id)
	QidP2 := new(bn256.G2).ScalarBaseMult(Qid)

	tmp := new(bn256.G2).Add(mpk, QidP2)
	left := bn256.Pair(S, tmp)

	g := bn256.Pair(new(bn256.G1).ScalarBaseMult(big.NewInt(1)),
		new(bn256.G2).ScalarBaseMult(big.NewInt(1)))
	right := new(bn256.GT).ScalarMult(g, h)

	wPrime := new(bn256.GT).Add(left, right)

	hPrime := hashToPoint(append(msg, wPrime.Marshal()...))

	hPrimeBytes := hPrime.Bytes()
	hBytes := h.Bytes()

	if len(hPrimeBytes) != len(hBytes) {
		return false
	}

	return subtle.ConstantTimeCompare(hPrimeBytes, hBytes) == 1
}

func encodeSignatureSM_BN(h *big.Int, S *bn256.G1) ([]byte, error) {
	hBytes := h.Bytes()
	SBytes := S.Marshal()

	sig := SignatureSM{
		H: hBytes,
		S: SBytes,
	}

	return asn1.Marshal(sig)
}

func decodeSignatureSM_BN(data []byte) (*big.Int, *bn256.G1, error) {
	var sig SignatureSM
	_, err := asn1.Unmarshal(data, &sig)
	if err != nil {
		return nil, nil, err
	}

	h := new(big.Int).SetBytes(sig.H)

	S := new(bn256.G1)
	if _, err := S.Unmarshal(sig.S); err != nil {
		return nil, nil, fmt.Errorf("invalid G1 point in signature: %v", err)
	}

	return h, S, nil
}

func extractBARRETO(s *ff.Scalar, id []byte) *bls12381.G1 {
	h1 := hashToScalar(id)

	sum := new(ff.Scalar)
	sum.Add(h1, s)

	inv := new(ff.Scalar)
	inv.Inv(sum)

	SID := new(bls12381.G1)
	SID.ScalarMult(inv, bls12381.G1Generator())

	return SID
}

type SignatureBARRETO struct {
	H []byte `asn1:"tag:0"`
	S []byte `asn1:"tag:1"`
}

func signBARRETO(SID *bls12381.G1, msg []byte) (*ff.Scalar, *bls12381.G1) {
	x := new(ff.Scalar)
	x.Random(rand.Reader)

	g := bls12381.Pair(bls12381.G1Generator(), bls12381.G2Generator())

	r := new(bls12381.Gt)
	r.Exp(g, x)

	h := h(msg, r)

	sum := new(ff.Scalar)
	sum.Add(x, h)

	S := new(bls12381.G1)
	S.ScalarMult(sum, SID)

	return h, S
}

func verifyBARRETO(H *ff.Scalar, S *bls12381.G1, id, msg []byte, Qpub *bls12381.G2) bool {
	h1 := hashToScalar(id)

	h1Q := new(bls12381.G2)
	h1Q.ScalarMult(h1, bls12381.G2Generator())

	sum := new(bls12381.G2)
	sum.Add(h1Q, Qpub)

	pair := bls12381.Pair(S, sum)

	g := bls12381.Pair(bls12381.G1Generator(), bls12381.G2Generator())

	hNeg := new(ff.Scalar)
	hNeg.Set(H)
	hNeg.Neg()

	gInv := new(bls12381.Gt)
	gInv.Exp(g, hNeg)

	rPrime := new(bls12381.Gt)
	rPrime.Mul(pair, gInv)

	hPrime := h(msg, rPrime)

	return hPrime.IsEqual(H) == 1
}

func encodeSignatureBARRETO(h *ff.Scalar, S *bls12381.G1) ([]byte, error) {
	hBytes, _ := h.MarshalBinary()
	SBytes := S.BytesCompressed()

	sig := SignatureBARRETO{
		H: hBytes,
		S: SBytes,
	}

	return asn1.Marshal(sig)
}

func decodeSignatureBARRETO(data []byte) (*ff.Scalar, *bls12381.G1, error) {
	var sig SignatureBARRETO
	_, err := asn1.Unmarshal(data, &sig)
	if err != nil {
		return nil, nil, err
	}

	h := new(ff.Scalar)
	if err := h.UnmarshalBinary(sig.H); err != nil {
		return nil, nil, err
	}

	S := new(bls12381.G1)
	if err := S.SetBytes(sig.S); err != nil {
		return nil, nil, fmt.Errorf("invalid G1 point in signature: %v", err)
	}

	return h, S, nil
}

func extractBARRETO_BN(s *big.Int, id []byte) *bn256.G1 {
	h1 := hashToPoint(id)

	sum := new(big.Int).Add(h1, s)
	sum.Mod(sum, bn256.Order)

	inv := new(big.Int).ModInverse(sum, bn256.Order)
	SID := new(bn256.G1).ScalarBaseMult(inv)
	return SID
}

func signBARRETO_BN(SID *bn256.G1, msg []byte) (*big.Int, *bn256.G1) {
	x, _ := rand.Int(rand.Reader, bn256.Order)

	g := bn256.Pair(new(bn256.G1).ScalarBaseMult(big.NewInt(1)),
		new(bn256.G2).ScalarBaseMult(big.NewInt(1)))

	r := new(bn256.GT).ScalarMult(g, x)
	h := h_BN(msg, r)

	sum := new(big.Int).Add(x, h)
	sum.Mod(sum, bn256.Order)

	S := new(bn256.G1).ScalarMult(SID, sum)
	return h, S
}

func verifyBARRETO_BN(h *big.Int, S *bn256.G1, id, msg []byte, Qpub *bn256.G2) bool {
	h1 := hashToPoint(id)

	h1Q := new(bn256.G2).ScalarBaseMult(h1)

	sum := new(bn256.G2).Add(h1Q, Qpub)

	pair := bn256.Pair(S, sum)

	g := bn256.Pair(new(bn256.G1).ScalarBaseMult(big.NewInt(1)),
		new(bn256.G2).ScalarBaseMult(big.NewInt(1)))

	hNeg := new(big.Int).Neg(h)
	hNeg.Mod(hNeg, bn256.Order)
	gInv := new(bn256.GT).ScalarMult(g, hNeg)

	rPrime := new(bn256.GT).Add(pair, gInv)

	hPrime := h_BN(msg, rPrime)

	return h.Cmp(hPrime) == 0
}

func encodeSignatureBARRETO_BN(h *big.Int, S *bn256.G1) ([]byte, error) {
	hBytes := h.Bytes()
	SBytes := S.Marshal()

	sig := SignatureBARRETO{
		H: hBytes,
		S: SBytes,
	}

	return asn1.Marshal(sig)
}

func decodeSignatureBARRETO_BN(data []byte) (*big.Int, *bn256.G1, error) {
	var sig SignatureBARRETO
	_, err := asn1.Unmarshal(data, &sig)
	if err != nil {
		return nil, nil, fmt.Errorf("ASN.1 unmarshal failed: %v", err)
	}

	h := new(big.Int).SetBytes(sig.H)

	S := new(bn256.G1)
	_, err = S.Unmarshal(sig.S)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal G1 point: %v", err)
	}

	return h, S, nil
}

func GHash(id, gaBytes, msg []byte) *ff.Scalar {
	h := bmw.New256()
	h.Write(id)
	h.Write(gaBytes)
	h.Write(msg)
	sum := h.Sum(nil)

	d := new(ff.Scalar)
	d.SetBytes(sum)
	return d
}

func HHash(grBytes []byte, id []byte) *ff.Scalar {
	h := bmw.New256()
	h.Write(grBytes)
	h.Write(id)
	sum := h.Sum(nil)

	c := new(ff.Scalar)
	c.SetBytes(sum)
	return c
}

type SignatureGG struct {
	Ga []byte `asn1:"tag:0"`
	B  []byte `asn1:"tag:1"`
	Gr []byte `asn1:"tag:2"`
}

type PrivateKeyGG struct {
	Y  []byte `asn1:"tag:0"`
	Gr []byte `asn1:"tag:1"`
}

func extractGG(z *ff.Scalar, id []byte) (*ff.Scalar, *bls12381.G1) {
	r := new(ff.Scalar)
	r.Random(rand.Reader)

	gr := new(bls12381.G1)
	gr.ScalarMult(r, bls12381.G1Generator())

	grBytes := gr.BytesCompressed()
	c := HHash(grBytes, id)

	zc := new(ff.Scalar)
	zc.Mul(z, c)

	y := new(ff.Scalar)
	y.Add(r, zc)

	return y, gr
}

func signGG(y *ff.Scalar, gr *bls12381.G1, id, msg []byte) (*bls12381.G1, *ff.Scalar, *bls12381.G1) {
	a := new(ff.Scalar)
	a.Random(rand.Reader)

	ga := new(bls12381.G1)
	ga.ScalarMult(a, bls12381.G1Generator())

	gaBytes := ga.BytesCompressed()
	d := GHash(id, gaBytes, msg)

	yd := new(ff.Scalar)
	yd.Mul(y, d)

	b := new(ff.Scalar)
	b.Add(a, yd)

	return ga, b, gr
}

func verifyGG(ga *bls12381.G1, b *ff.Scalar, gr *bls12381.G1, mpk *bls12381.G1, id, msg []byte) bool {
	grBytes := gr.BytesCompressed()
	c := HHash(grBytes, id)

	gzc := new(bls12381.G1)
	gzc.ScalarMult(c, mpk)

	grp := new(bls12381.G1)
	grp.Add(gr, gzc)

	gaBytes := ga.BytesCompressed()
	d := GHash(id, gaBytes, msg)

	grpToD := new(bls12381.G1)
	grpToD.ScalarMult(d, grp)

	right := new(bls12381.G1)
	right.Add(ga, grpToD)

	gb := new(bls12381.G1)
	gb.ScalarMult(b, bls12381.G1Generator())

	return gb.IsEqual(right)
}

func encodeSignatureGG(ga *bls12381.G1, b *ff.Scalar, gr *bls12381.G1) ([]byte, error) {
	bBytes, err := b.MarshalBinary()
	if err != nil {
		return nil, err
	}
	sig := SignatureGG{
		Ga: ga.BytesCompressed(),
		B:  bBytes,
		Gr: gr.BytesCompressed(),
	}
	return asn1.Marshal(sig)
}

func decodeSignatureGG(data []byte) (*bls12381.G1, *ff.Scalar, *bls12381.G1, error) {
	var sig SignatureGG
	_, err := asn1.Unmarshal(data, &sig)
	if err != nil {
		return nil, nil, nil, err
	}

	ga := new(bls12381.G1)
	if err := ga.SetBytes(sig.Ga); err != nil {
		return nil, nil, nil, fmt.Errorf("invalid ga point: %w", err)
	}

	b := new(ff.Scalar)
	if err := b.UnmarshalBinary(sig.B); err != nil {
		return nil, nil, nil, fmt.Errorf("invalid scalar b: %w", err)
	}

	gr := new(bls12381.G1)
	if err := gr.SetBytes(sig.Gr); err != nil {
		return nil, nil, nil, fmt.Errorf("invalid gr point: %w", err)
	}

	return ga, b, gr, nil
}

func encodePrivateKeyGG(y *ff.Scalar, gr *bls12381.G1) ([]byte, error) {
	yBytes, err := y.MarshalBinary()
	if err != nil {
		return nil, err
	}

	sk := PrivateKeyGG{
		Y:  yBytes,
		Gr: gr.BytesCompressed(),
	}

	return asn1.Marshal(sk)
}

func decodePrivateKeyGG(data []byte) (*ff.Scalar, *bls12381.G1, error) {
	var sk PrivateKeyGG
	_, err := asn1.Unmarshal(data, &sk)
	if err != nil {
		return nil, nil, err
	}

	y := new(ff.Scalar)
	if err := y.UnmarshalBinary(sk.Y); err != nil {
		return nil, nil, fmt.Errorf("falha ao desserializar y: %w", err)
	}

	gr := new(bls12381.G1)
	if err := gr.SetBytes(sk.Gr); err != nil {
		return nil, nil, fmt.Errorf("falha ao desserializar gr: %w", err)
	}

	return y, gr, nil
}

type SignatureCC struct {
	U []byte `asn1:"tag:0"`
	V []byte `asn1:"tag:1"`
}

func signCC(dID *bls12381.G1, id []byte, msg []byte) (*bls12381.G1, *bls12381.G1) {
	Qid := hashToG1(id)

	r := new(ff.Scalar)
	r.Random(rand.Reader)

	U := new(bls12381.G1)
	U.ScalarMult(r, Qid)

	uBytes := U.BytesCompressed()

	data := append(msg, uBytes...)

	h := hashToScalar(data)

	r_plus_h := new(ff.Scalar)
	r_plus_h.Add(r, h)

	V := new(bls12381.G1)
	V.ScalarMult(r_plus_h, dID)

	return U, V
}

func verifyCC(Ppub *bls12381.G2, id, msg []byte, U, V *bls12381.G1) bool {
	Qid := hashToG1(id)

	uBytes := U.BytesCompressed()

	data := append(msg, uBytes...)

	h := hashToScalar(data)

	hQid := new(bls12381.G1)
	hQid.ScalarMult(h, Qid)

	UhQid := new(bls12381.G1)
	UhQid.Add(U, hQid)

	left := bls12381.Pair(V, bls12381.G2Generator())
	right := bls12381.Pair(UhQid, Ppub)

	return left.IsEqual(right)
}

func encodeSignatureCC(U *bls12381.G1, V *bls12381.G1) ([]byte, error) {
	sig := SignatureCC{
		U: U.BytesCompressed(),
		V: V.BytesCompressed(),
	}

	return asn1.Marshal(sig)
}

func decodeSignatureCC(data []byte) (*bls12381.G1, *bls12381.G1, error) {
	var sig SignatureCC
	_, err := asn1.Unmarshal(data, &sig)
	if err != nil {
		return nil, nil, err
	}

	U := new(bls12381.G1)
	if err := U.SetBytes(sig.U); err != nil {
		return nil, nil, fmt.Errorf("invalid G1 point in signature: %v", err)
	}

	V := new(bls12381.G1)
	if err := V.SetBytes(sig.V); err != nil {
		return nil, nil, fmt.Errorf("invalid G1 point in signature: %v", err)
	}

	return U, V, nil
}

func signCC_BN(skID *bn256.G1, id, msg []byte) (*bn256.G1, *bn256.G1) {
	Qid := bn256.HashG1(id, nil)

	r, _ := rand.Int(rand.Reader, bn256.Order)
	U := new(bn256.G1).ScalarMult(Qid, r)

	h := hashToPoint(append(msg, U.Marshal()...))
	rPlusH := new(big.Int).Add(r, h)

	V := new(bn256.G1).ScalarMult(skID, rPlusH)

	return U, V
}

func verifyCC_BN(mpk *bn256.G2, id, msg []byte, U, V *bn256.G1) bool {
	Qid := bn256.HashG1(id, nil)
	h := hashToPoint(append(msg, U.Marshal()...))

	hQid := new(bn256.G1).ScalarMult(Qid, h)
	UhQid := new(bn256.G1).Add(U, hQid)

	left := bn256.Pair(V, new(bn256.G2).ScalarBaseMult(big.NewInt(1)))
	right := bn256.Pair(UhQid, mpk)

	leftBytes := left.Marshal()
	rightBytes := right.Marshal()

	if len(leftBytes) != len(rightBytes) {
		return false
	}
	return subtle.ConstantTimeCompare(leftBytes, rightBytes) == 1
}

func encodeSignatureCC_BN(U *bn256.G1, V *bn256.G1) ([]byte, error) {
	sig := SignatureCC{
		U: U.Marshal(),
		V: V.Marshal(),
	}
	return asn1.Marshal(sig)
}

func decodeSignatureCC_BN(data []byte) (*bn256.G1, *bn256.G1, error) {
	var sig SignatureCC
	_, err := asn1.Unmarshal(data, &sig)
	if err != nil {
		return nil, nil, err
	}

	U := new(bn256.G1)
	if _, err := U.Unmarshal(sig.U); err != nil {
		return nil, nil, fmt.Errorf("invalid G1 point in U: %v", err)
	}

	V := new(bn256.G1)
	if _, err := V.Unmarshal(sig.V); err != nil {
		return nil, nil, fmt.Errorf("invalid G1 point in V: %v", err)
	}

	return U, V, nil
}

func h(m []byte, r *bls12381.Gt) *ff.Scalar {
	hasher := bmw.New256()
	hasher.Write(m)
	rBytes, _ := r.MarshalBinary()
	hasher.Write(rBytes)
	digest := hasher.Sum(nil)

	scalar := new(ff.Scalar)
	scalar.SetBytes(digest)
	return scalar
}

type SignatureHess struct {
	U []byte `asn1:"tag:0"`
	V []byte `asn1:"tag:1"`
}

func signHESS(SID *bls12381.G1, P1 *bls12381.G1, msg []byte) (*bls12381.G1, *ff.Scalar) {
	k := new(ff.Scalar)
	k.Random(rand.Reader)

	e := bls12381.Pair(P1, bls12381.G2Generator())
	r := new(bls12381.Gt)
	r.Exp(e, k)

	v := h(msg, r)

	vSID := new(bls12381.G1)
	vSID.ScalarMult(v, SID)

	kP1 := new(bls12381.G1)
	kP1.ScalarMult(k, P1)

	u := new(bls12381.G1)
	u.Add(vSID, kP1)

	return u, v
}

func verifyHESS(u *bls12381.G1, v *ff.Scalar, QTA *bls12381.G2, id, msg []byte) bool {
	Qid := hashToG1(id)

	e1 := bls12381.Pair(u, bls12381.G2Generator())

	negQTA := new(bls12381.G2)
	*negQTA = *QTA
	negQTA.Neg()

	e2 := bls12381.Pair(Qid, negQTA)

	e2v := new(bls12381.Gt)
	e2v.Exp(e2, v)

	rPrime := new(bls12381.Gt)
	rPrime.Mul(e1, e2v)

	vPrime := h(msg, rPrime)

	return vPrime.IsEqual(v) == 1
}

func encodeSignatureHESS(U *bls12381.G1, V *ff.Scalar) ([]byte, error) {
	vBytes, err := V.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal scalar V: %v", err)
	}

	sig := SignatureHess{
		U: U.BytesCompressed(),
		V: vBytes,
	}
	return asn1.Marshal(sig)
}

func decodeSignatureHESS(data []byte) (*bls12381.G1, *ff.Scalar, error) {
	var sig SignatureHess
	_, err := asn1.Unmarshal(data, &sig)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal signature: %v", err)
	}

	U := new(bls12381.G1)
	if err := U.SetBytes(sig.U); err != nil {
		return nil, nil, fmt.Errorf("invalid G1 point in U: %v", err)
	}

	V := new(ff.Scalar)
	if err := V.UnmarshalBinary(sig.V); err != nil {
		return nil, nil, fmt.Errorf("invalid scalar in V: %v", err)
	}

	return U, V, nil
}

func h_BN(m []byte, r *bn256.GT) *big.Int {
	hasher := bmw.New256()
	hasher.Write(m)
	hasher.Write(r.Marshal())

	hash := hasher.Sum(nil)
	v := new(big.Int).SetBytes(hash)
	return new(big.Int).Mod(v, bn256.Order)
}

func signHESS_BN(SID *bn256.G1, P1 *bn256.G1, msg []byte) (*bn256.G1, *big.Int) {
	k, err := rand.Int(rand.Reader, bn256.Order)
	if err != nil {
		panic(err)
	}

	e := bn256.Pair(P1, new(bn256.G2).ScalarBaseMult(big.NewInt(1)))
	r := new(bn256.GT).ScalarMult(e, k)

	v := h_BN(msg, r)

	vSID := new(bn256.G1).ScalarMult(SID, v)
	kP1 := new(bn256.G1).ScalarMult(P1, k)
	u := new(bn256.G1).Add(vSID, kP1)

	return u, v
}

func verifyHESS_BN(u *bn256.G1, v *big.Int, QTA *bn256.G2, id, msg []byte) bool {
	Qid := bn256.HashG1(id, nil)

	e1 := bn256.Pair(u, new(bn256.G2).ScalarBaseMult(big.NewInt(1)))

	e2 := bn256.Pair(Qid, QTA)
	e2.Neg(e2)
	e2v := new(bn256.GT).ScalarMult(e2, v)

	rPrime := new(bn256.GT).Add(e1, e2v)

	vPrime := h_BN(msg, rPrime)

	return v.Cmp(vPrime) == 0
}

func encodeSignatureHESS_BN(U *bn256.G1, V *big.Int) ([]byte, error) {
	sig := SignatureHess{
		U: U.Marshal(),
		V: V.Bytes(),
	}
	return asn1.Marshal(sig)
}

func decodeSignatureHESS_BN(data []byte) (*bn256.G1, *big.Int, error) {
	var sig SignatureHess
	_, err := asn1.Unmarshal(data, &sig)
	if err != nil {
		return nil, nil, fmt.Errorf("falha ao desserializar assinatura: %v", err)
	}

	U := new(bn256.G1)
	if _, err := U.Unmarshal(sig.U); err != nil {
		return nil, nil, fmt.Errorf("ponto G1 inválido em U: %v", err)
	}

	V := new(big.Int).SetBytes(sig.V)

	return U, V, nil
}

func scalarEqual(a, b *ff.Scalar) bool {
	aBytes, _ := a.MarshalBinary()
	bBytes, _ := b.MarshalBinary()

	if len(aBytes) != len(bBytes) {
		return false
	}
	return subtle.ConstantTimeCompare(aBytes, bBytes) == 1
}

func generateCommitment(secret *ff.Scalar, generator *bls12381.G2) *bls12381.G2 {
	commitment := new(bls12381.G2)
	commitment.ScalarMult(secret, generator)
	return commitment
}

func generateChallenge(commitment *bls12381.G2, message []byte) *ff.Scalar {
	hash := bmw.New256()
	hash.Write(commitment.Bytes())
	hash.Write(message)
	challenge := new(ff.Scalar)
	challenge.SetBytes(hash.Sum(nil))
	return challenge
}

func generateResponse(r, secret, challenge *ff.Scalar) *ff.Scalar {
	tmp := new(ff.Scalar)
	tmp.Mul(challenge, secret)
	response := new(ff.Scalar)
	response.Add(r, tmp)
	return response
}

func verifyProof(commitment *bls12381.G2, challenge *ff.Scalar, response *ff.Scalar, publicKey *bls12381.G2) bool {
	left := new(bls12381.G1)
	left.ScalarMult(response, bls12381.G1Generator())
	leftPair := bls12381.Pair(left, bls12381.G2Generator())

	right := new(bls12381.G2)
	tmp := new(bls12381.G2)
	tmp.ScalarMult(challenge, publicKey)
	right.Add(commitment, tmp)
	rightPair := bls12381.Pair(bls12381.G1Generator(), right)

	return leftPair.IsEqual(rightPair)
}

func generateChallengeIBE(C *bls12381.Gt, QID *bls12381.G1, message []byte) *ff.Scalar {
	h := bmw.New256()
	CBytes, _ := C.MarshalBinary()
	h.Write(CBytes)
	h.Write(QID.Bytes())
	h.Write(message)
	χ := new(ff.Scalar)
	χ.SetBytes(h.Sum(nil))
	return χ
}

func createProofIBE(dID, QID *bls12381.G1, message []byte) (*bls12381.Gt, *bls12381.G1) {
	k := new(ff.Scalar)
	k.Random(rand.Reader)

	R := new(bls12381.G1)
	R.ScalarMult(k, bls12381.G1Generator())

	C := bls12381.Pair(R, bls12381.G2Generator())

	χ := generateChallengeIBE(C, QID, message)

	χd := new(bls12381.G1)
	χd.ScalarMult(χ, dID)

	S := new(bls12381.G1)
	S.Add(R, χd)

	return C, S
}

func verifyProofIBE(C *bls12381.Gt, S *bls12381.G1, QID *bls12381.G1, Ppub *bls12381.G2, message []byte) bool {
	χ := generateChallengeIBE(C, QID, message)

	left := bls12381.Pair(S, bls12381.G2Generator())

	eQ := bls12381.Pair(QID, Ppub)
	eQχ := new(bls12381.Gt)
	eQχ.Exp(eQ, χ)

	right := new(bls12381.Gt)
	right.Mul(C, eQχ)

	return left.IsEqual(right)
}

func createProofShangMi(skid *bls12381.G1, message []byte) (*ff.Scalar, *bls12381.G1) {
	r := new(ff.Scalar)
	r.Random(rand.Reader)

	g := bls12381.Pair(bls12381.G1Generator(), bls12381.G2Generator())

	w := new(bls12381.Gt)
	w.Exp(g, r)

	wBytes, _ := w.MarshalBinary()
	χ := hashToScalar(append(message, wBytes...))

	r.Sub(r, χ)
	S := new(bls12381.G1)
	S.ScalarMult(r, skid)

	return χ, S
}

func verifyProofShangMi(mpk *bls12381.G2, id []byte, message []byte, χ *ff.Scalar, S *bls12381.G1) bool {
	hID := hashToScalar(id)

	g := bls12381.Pair(bls12381.G1Generator(), bls12381.G2Generator())

	hIDG2 := new(bls12381.G2)
	hIDG2.ScalarMult(hID, bls12381.G2Generator())

	temp := new(bls12381.G2)
	temp.Add(mpk, hIDG2)

	left := bls12381.Pair(S, temp)

	right := new(bls12381.Gt)
	right.Exp(g, χ)

	wPrime := new(bls12381.Gt)
	wPrime.Mul(left, right)

	wPrimeBytes, _ := wPrime.MarshalBinary()
	χPrime := hashToScalar(append(message, wPrimeBytes...))

	return scalarEqual(χ, χPrime)
}

type CiphertextASN struct {
	A   []byte
	B   []byte
	C1  []byte
	DEM []byte
}

func Setup() (*ff.Scalar, *ff.Scalar, *bls12381.G2, *bls12381.G1, *bls12381.G1, *bls12381.Gt) {
	s := new(ff.Scalar)
	s.Random(rand.Reader)

	x := new(ff.Scalar)
	x.Random(rand.Reader)

	Ppubs := new(bls12381.G2)
	Ppubs.ScalarMult(x, bls12381.G2Generator())

	Ppub := new(bls12381.G1)
	Ppub.ScalarMult(s, bls12381.G1Generator())

	Q := new(bls12381.G1)
	Q.ScalarMult(x, bls12381.G1Generator())

	v := bls12381.Pair(bls12381.G1Generator(), Ppubs)

	return s, x, Ppubs, Ppub, Q, v
}

func Extract(id string, s, x *ff.Scalar, Ppubs *bls12381.G2) (*ff.Scalar, *bls12381.G2) {
	h := hashToScalar([]byte("ID|" + id))

	z := new(ff.Scalar)
	z.Add(s, h)

	var r, sum, inv *ff.Scalar
	r = new(ff.Scalar)
	sum = new(ff.Scalar)

	for {
		r.Random(rand.Reader)

		sum.Mul(x, r)

		sum.Add(z, sum)

		if sum.IsZero() == 0 {
			inv = new(ff.Scalar)
			inv.Inv(sum)
			break
		}
	}

	Did := new(bls12381.G2)
	Did.ScalarMult(inv, Ppubs)

	return r, Did
}

func deriveKeyFromSigma(sigma []byte, length int, hashFunc func() hash.Hash) []byte {
	var result []byte
	counter := 0
	for len(result) < length {
		h := hashFunc()
		h.Write([]byte("K|"))
		h.Write(sigma)
		h.Write([]byte{byte(counter)})
		result = append(result, h.Sum(nil)...)
		counter++
	}
	return result[:length]
}

func EncryptBB(id string, msg []byte, Ppub, Q *bls12381.G1, v *bls12381.Gt) ([]byte, error) {
	sigma := make([]byte, 32)
	if _, err := rand.Read(sigma); err != nil {
		return nil, fmt.Errorf("failed to generate sigma: %v", err)
	}

	h := bmw.New256()
	h.Write(sigma)
	h.Write(msg)
	s := new(ff.Scalar)
	s.SetBytes(h.Sum(nil))

	symKey := deriveKeyFromSigma(sigma, len(msg), bmw.New256)

	vs := new(bls12381.Gt)
	vs.Exp(v, s)

	vsBytes, _ := vs.MarshalBinary()
	pad := bmw.Sum256(vsBytes)

	A := make([]byte, 32)
	for i := range sigma {
		A[i] = sigma[i] ^ pad[i]
	}

	B := new(bls12381.G1)
	B.ScalarMult(s, Q)
	Bbytes := B.Bytes()

	hid := hashToScalar([]byte("ID|" + id))

	g1hid := new(bls12381.G1)
	g1hid.ScalarMult(hid, bls12381.G1Generator())

	tmp := new(bls12381.G1)
	tmp.Add(Ppub, g1hid)

	C1 := new(bls12381.G1)
	C1.ScalarMult(s, tmp)
	C1bytes := C1.Bytes()

	dem := make([]byte, len(msg))
	for i := range msg {
		dem[i] = msg[i] ^ symKey[i%len(symKey)]
	}

	ctASN := CiphertextASN{
		A:   A,
		B:   Bbytes,
		C1:  C1bytes,
		DEM: dem,
	}

	ciphertext, err := asn1.Marshal(ctASN)
	if err != nil {
		return nil, fmt.Errorf("failed to encode ASN.1: %v", err)
	}

	return ciphertext, nil
}

func DecryptBB(ct []byte, r *ff.Scalar, Did *bls12381.G2, v *bls12381.Gt) ([]byte, error) {
	var ctASN CiphertextASN
	_, err := asn1.Unmarshal(ct, &ctASN)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ASN.1 from ciphertext: %v", err)
	}

	A := ctASN.A
	Bbytes := ctASN.B
	C1bytes := ctASN.C1
	dem := ctASN.DEM

	if len(A) != 32 || len(Bbytes) != 96 || len(C1bytes) != 96 {
		return nil, fmt.Errorf("invalid ciphertext components")
	}

	B := new(bls12381.G1)
	if err := B.SetBytes(Bbytes); err != nil {
		return nil, fmt.Errorf("invalid B: %v", err)
	}

	C1 := new(bls12381.G1)
	if err := C1.SetBytes(C1bytes); err != nil {
		return nil, fmt.Errorf("invalid C1: %v", err)
	}

	Br := new(bls12381.G1)
	Br.ScalarMult(r, B)

	tmp := new(bls12381.G1)
	tmp.Add(Br, C1)

	pair := bls12381.Pair(tmp, Did)

	pairBytes, _ := pair.MarshalBinary()
	pad := bmw.Sum256(pairBytes)

	sigma := make([]byte, 32)
	for i := range A {
		sigma[i] = A[i] ^ pad[i]
	}

	symKey := deriveKeyFromSigma(sigma, len(dem), bmw.New256)

	msg := make([]byte, len(dem))
	for i := range dem {
		msg[i] = dem[i] ^ symKey[i%len(symKey)]
	}

	h := bmw.New256()
	h.Write(sigma)
	h.Write(msg)
	s := new(ff.Scalar)
	s.SetBytes(h.Sum(nil))

	vs := new(bls12381.Gt)
	vs.Exp(v, s)
	vsBytes, _ := vs.MarshalBinary()
	checkPad := bmw.Sum256(vsBytes)

	kemCheck := make([]byte, 32)
	for i := 0; i < 32; i++ {
		kemCheck[i] = sigma[i] ^ checkPad[i]
	}
	if subtle.ConstantTimeCompare(kemCheck, A) != 1 {
		return nil, fmt.Errorf("KEM verification failed")
	}

	return msg, nil
}

type MasterPrivateKeyASN struct {
	S     []byte `asn1:"tag:0"`
	X     []byte `asn1:"tag:1"`
	Ppubs []byte `asn1:"tag:2"`
	V     []byte `asn1:"tag:3"`
}

type MasterPublicKeyASN struct {
	Ppub []byte `asn1:"tag:0"`
	Q    []byte `asn1:"tag:1"`
	V    []byte `asn1:"tag:2"`
}

type UserPrivateKeyASN struct {
	R   []byte `asn1:"tag:0"`
	Did []byte `asn1:"tag:1"`
	V   []byte `asn1:"tag:2"`
}

func SerializeMasterPrivateKey(s, x *ff.Scalar, Ppubs *bls12381.G2, v *bls12381.Gt) ([]byte, error) {
	sBytes, err := s.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal s: %w", err)
	}
	xBytes, err := x.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal x: %w", err)
	}
	ppubsBytes := Ppubs.BytesCompressed()

	vBytes, err := v.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal v: %w", err)
	}

	keyASN := MasterPrivateKeyASN{
		S:     sBytes,
		X:     xBytes,
		Ppubs: ppubsBytes,
		V:     vBytes,
	}
	return asn1.Marshal(keyASN)
}

func SerializeMasterPublicKey(Ppub, Q *bls12381.G1, v *bls12381.Gt) ([]byte, error) {
	ppubBytes := Ppub.BytesCompressed()
	qBytes := Q.BytesCompressed()

	vBytes, err := v.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal v: %w", err)
	}

	pubASN := MasterPublicKeyASN{
		Ppub: ppubBytes,
		Q:    qBytes,
		V:    vBytes,
	}
	return asn1.Marshal(pubASN)
}

func SerializeUserPrivateKey(r *ff.Scalar, Did *bls12381.G2, v *bls12381.Gt) ([]byte, error) {
	rBytes, err := r.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal r: %w", err)
	}
	didBytes := Did.BytesCompressed()

	vBytes, err := v.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal v: %w", err)
	}

	privASN := UserPrivateKeyASN{
		R:   rBytes,
		Did: didBytes,
		V:   vBytes,
	}
	return asn1.Marshal(privASN)
}

func DeserializeMasterPrivateKey(data []byte) (*ff.Scalar, *ff.Scalar, *bls12381.G2, *bls12381.Gt, error) {
	var keyASN MasterPrivateKeyASN
	if _, err := asn1.Unmarshal(data, &keyASN); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to unmarshal ASN.1: %w", err)
	}

	s := new(ff.Scalar)
	if err := s.UnmarshalBinary(keyASN.S); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to unmarshal s: %w", err)
	}

	x := new(ff.Scalar)
	if err := x.UnmarshalBinary(keyASN.X); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to unmarshal x: %w", err)
	}

	Ppubs := new(bls12381.G2)
	if err := Ppubs.SetBytes(keyASN.Ppubs); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to set Ppubs bytes: %w", err)
	}

	v := new(bls12381.Gt)
	if err := v.UnmarshalBinary(keyASN.V); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to unmarshal v: %w", err)
	}

	return s, x, Ppubs, v, nil
}

func DeserializeMasterPublicKey(data []byte) (*bls12381.G1, *bls12381.G1, *bls12381.Gt, error) {
	var pubASN MasterPublicKeyASN
	if _, err := asn1.Unmarshal(data, &pubASN); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to unmarshal ASN.1: %w", err)
	}

	Ppub := new(bls12381.G1)
	if err := Ppub.SetBytes(pubASN.Ppub); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to set Ppub bytes: %w", err)
	}

	Q := new(bls12381.G1)
	if err := Q.SetBytes(pubASN.Q); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to set Q bytes: %w", err)
	}

	v := new(bls12381.Gt)
	if err := v.UnmarshalBinary(pubASN.V); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to unmarshal v: %w", err)
	}

	return Ppub, Q, v, nil
}

func DeserializeUserPrivateKey(data []byte) (*ff.Scalar, *bls12381.G2, *bls12381.Gt, error) {
	var privASN UserPrivateKeyASN
	if _, err := asn1.Unmarshal(data, &privASN); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to unmarshal ASN.1: %w", err)
	}

	r := new(ff.Scalar)
	if err := r.UnmarshalBinary(privASN.R); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to unmarshal r: %w", err)
	}

	Did := new(bls12381.G2)
	if err := Did.SetBytes(privASN.Did); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to set Did bytes: %w", err)
	}

	v := new(bls12381.Gt)
	if err := v.UnmarshalBinary(privASN.V); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to unmarshal v: %w", err)
	}

	return r, Did, v, nil
}

func encryptECElGamal(curve elliptic.Curve, pubX, pubY, Mx, My *big.Int) (*CiphertextEC, error) {
	if pubX == nil || pubY == nil || Mx == nil || My == nil {
		return nil, errors.New("invalid input: null coordinates")
	}
	if pubX.Sign() == 0 && pubY.Sign() == 0 {
		return nil, errors.New("invalid public key: point at infinity")
	}
	if Mx.Sign() == 0 && My.Sign() == 0 {
		return nil, errors.New("invalid message: point at infinity")
	}
	if !curve.IsOnCurve(pubX, pubY) || !curve.IsOnCurve(Mx, My) {
		return nil, errors.New("invalid input: point not on curve")
	}

	var k *big.Int
	var err error
	for {
		k, err = rand.Int(rand.Reader, curve.Params().N)
		if err != nil {
			return nil, err
		}
		if k.Sign() != 0 {
			break
		}
	}

	C1x, C1y := curve.ScalarBaseMult(k.Bytes())

	kQx, kQy := curve.ScalarMult(pubX, pubY, k.Bytes())

	C2x, C2y := curve.Add(Mx, My, kQx, kQy)

	return &CiphertextEC{C1x, C1y, C2x, C2y}, nil
}

func decryptECElGamal(curve elliptic.Curve, priv *big.Int, ct *CiphertextEC) (*big.Int, *big.Int, error) {
	if ct == nil || ct.C1x == nil || ct.C1y == nil || ct.C2x == nil || ct.C2y == nil {
		return nil, nil, errors.New("invalid ciphertext: null points")
	}
	if ct.C1x.Sign() == 0 && ct.C1y.Sign() == 0 {
		return nil, nil, errors.New("invalid ciphertext: C1 is point at infinity")
	}
	if !curve.IsOnCurve(ct.C1x, ct.C1y) || !curve.IsOnCurve(ct.C2x, ct.C2y) {
		return nil, nil, errors.New("invalid ciphertext: point not on curve")
	}

	Sx, Sy := curve.ScalarMult(ct.C1x, ct.C1y, priv.Bytes())
	if Sx == nil || Sy == nil || !curve.IsOnCurve(Sx, Sy) {
		return nil, nil, errors.New("invalid shared secret")
	}

	negSy := new(big.Int).Neg(Sy)
	negSy.Mod(negSy, curve.Params().P)

	Mx, My := curve.Add(ct.C2x, ct.C2y, Sx, negSy)
	if Mx == nil || My == nil || !curve.IsOnCurve(Mx, My) {
		return nil, nil, errors.New("decrypted message is not on the curve")
	}

	return Mx, My, nil
}

type CiphertextEC struct {
	C1x, C1y *big.Int
	C2x, C2y *big.Int
}

func deriveKey(password string, salt []byte) ([]byte, error) {
	data := append([]byte(password), salt...)
	for i := 0; i < 32768; i++ {
		hash, err := lyra2re2.Sum(data)
		if err != nil {
			return nil, err
		}

		data = hash
	}
	return data[:24], nil
}

func encryptKey(plainKey []byte, password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	encryptionKey, err := deriveKey(password, salt)
	if err != nil {
		return "", err
	}
	if len(encryptionKey) != 12 && len(encryptionKey) != 18 && len(encryptionKey) != 24 {
		return "", errors.New("invalid key size for Curupira (must be 96, 144, or 192 bits)")
	}

	cipher, err := curupira1.NewCipher(encryptionKey)
	if err != nil {
		return "", err
	}

	aead := curupira1.NewLetterSoup(cipher)

	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	aead.SetIV(nonce)

	ciphertext := make([]byte, len(plainKey))
	aead.Encrypt(ciphertext, plainKey)

	tag := aead.GetTag(nil, 96)

	finalCiphertext := append(salt, nonce...)
	finalCiphertext = append(finalCiphertext, tag...)
	finalCiphertext = append(finalCiphertext, ciphertext...)

	return base64.StdEncoding.EncodeToString(finalCiphertext), nil
}

func decryptKey(encryptedKey string, password string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(encryptedKey)
	if err != nil {
		return nil, err
	}

	if len(data) < 40 {
		return nil, errors.New("ciphertext too short")
	}
	salt := data[:16]
	nonce := data[16:28]
	tag := data[28:40]
	ciphertext := data[40:]

	encryptionKey, err := deriveKey(password, salt)
	if err != nil {
		return nil, err
	}
	if len(encryptionKey) != 12 && len(encryptionKey) != 18 && len(encryptionKey) != 24 {
		return nil, errors.New("invalid key size for Curupira")
	}

	cipher, err := curupira1.NewCipher(encryptionKey)
	if err != nil {
		return nil, err
	}

	aead := curupira1.NewLetterSoup(cipher)
	aead.SetIV(nonce)

	decrypted := make([]byte, len(ciphertext))
	aead.Decrypt(decrypted, ciphertext)

	aead.Encrypt(ciphertext, decrypted)
	tagEnc := aead.GetTag(nil, 96)

	if len(tag) != len(tagEnc) || subtle.ConstantTimeCompare(tag, tagEnc) != 1 {
		return nil, errors.New("authentication verification failed")
	}

	return decrypted, nil
}

type PubPaths []string

func (p *PubPaths) String() string {
	return fmt.Sprintf("%v", *p)
}

func (p *PubPaths) Set(value string) error {
	*p = append(*p, value)
	return nil
}

type MsgsPaths []string

func (m *MsgsPaths) String() string {
	return fmt.Sprintf("%v", *m)
}

func (m *MsgsPaths) Set(value string) error {
	*m = append(*m, value)
	return nil
}

type KeysPaths []string

func (m *KeysPaths) String() string {
	return fmt.Sprintf("%v", *m)
}

func (m *KeysPaths) Set(value string) error {
	*m = append(*m, value)
	return nil
}

type CiphertextPHP struct {
	C1 *big.Int
	C2 *big.Int
}

type Signature struct {
	R *big.Int
	S *big.Int
}

type PublicKeyASN1 struct {
	P *big.Int
	G *big.Int
	Y *big.Int
}

type PrivateKeyASN1 struct {
	P *big.Int
	G *big.Int
	X *big.Int
}

func encodePublicKeyASN1(pub *elgamalphp.PublicKey) ([]byte, error) {
	return asn1.Marshal(PublicKeyASN1{P: pub.P, G: pub.G, Y: pub.Y})
}

func decodePublicKeyASN1(data []byte) (*elgamalphp.PublicKey, error) {
	var pubASN1 PublicKeyASN1
	_, err := asn1.Unmarshal(data, &pubASN1)
	if err != nil {
		return nil, err
	}
	return &elgamalphp.PublicKey{P: pubASN1.P, G: pubASN1.G, Y: pubASN1.Y}, nil
}

func encodePrivateKeyASN1(priv *elgamalphp.PrivateKey) ([]byte, error) {
	return asn1.Marshal(PrivateKeyASN1{P: priv.P, G: priv.G, X: priv.X})
}

func decodePrivateKeyASN1(data []byte) (*elgamalphp.PrivateKey, error) {
	var privASN1 PrivateKeyASN1
	_, err := asn1.Unmarshal(data, &privASN1)
	if err != nil {
		return nil, err
	}
	return &elgamalphp.PrivateKey{P: privASN1.P, G: privASN1.G, X: privASN1.X}, nil
}

func savePEM(filename, blockType string, data []byte) error {
	block := &pem.Block{
		Type:  blockType,
		Bytes: data,
	}
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	return pem.Encode(file, block)
}

func readPEM(filename string) ([]byte, error) {
	file, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(file)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block")
	}
	return block.Bytes, nil
}

func hashMessage(message []byte) []byte {
	h := whirlpool.New()
	h.Write(message)
	return h.Sum(nil)
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

func compressZlib(data []byte) ([]byte, error) {
	var b bytes.Buffer
	w := zlib.NewWriter(&b)
	_, err := w.Write(data)
	if err != nil {
		return nil, err
	}
	w.Close()
	return b.Bytes(), nil
}

func decompressZlib(data []byte) ([]byte, error) {
	b := bytes.NewReader(data)
	r, err := zlib.NewReader(b)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return ioutil.ReadAll(r)
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
