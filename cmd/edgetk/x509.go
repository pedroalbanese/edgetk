package main

import (
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"math/bits"
	"time"

	"github.com/pedroalbanese/e521"
)

// OID oficial do Ed521 conforme ITI/ICP-Brasil
var oidEd521 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44588, 2, 1}

type pkAlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// --- Estruturas ASN.1 para Certificate (X.509) ---

type tbsCertificate struct {
	Version            int `asn1:"optional,explicit,default:0,tag:0"`
	SerialNumber       *big.Int
	SignatureAlgorithm pkAlgorithmIdentifier
	Issuer             pkix.RDNSequence
	Validity           validity
	Subject            pkix.RDNSequence
	PublicKey          publicKeyInfo
	Extensions         asn1.RawValue `asn1:"optional"`
}

type validity struct {
	NotBefore, NotAfter time.Time
}

type publicKeyInfo struct {
	Algorithm pkAlgorithmIdentifier
	PublicKey asn1.BitString
}

type certificate struct {
	TBSCertificate     tbsCertificate
	SignatureAlgorithm pkAlgorithmIdentifier
	SignatureValue     asn1.BitString
}

// --- Estruturas ASN.1 para CSR (PKCS#10) ---

type certificationRequest struct {
	TBSCertificationRequest tbsCertificationRequest
	SignatureAlgorithm      pkAlgorithmIdentifier
	SignatureValue          asn1.BitString
}

type tbsCertificationRequest struct {
	Version       int
	Subject       pkix.RDNSequence
	SubjectPKInfo publicKeyInfo
	Attributes    []asn1.RawValue `asn1:"optional,explicit,tag:0"`
}

// --- Estruturas ASN.1 para CRL (X.509 v2) ---

type tbsCertList struct {
	Version             int `asn1:"optional,default:0"`
	Signature           pkAlgorithmIdentifier
	Issuer              pkix.RDNSequence
	ThisUpdate          time.Time
	NextUpdate          time.Time                `asn1:"optional"`
	RevokedCertificates []pkixRevokedCertificate `asn1:"optional"`
	Extensions          asn1.RawValue            `asn1:"optional"`
}

type pkixRevokedCertificate struct {
	SerialNumber   *big.Int
	RevocationTime time.Time
}

type certificateList struct {
	TBSCertList        tbsCertList
	SignatureAlgorithm pkAlgorithmIdentifier
	SignatureValue     asn1.BitString
}

// --- Funções que usam a API do e521 ---

// ed521Sign gera assinatura no formato ASN.1 exigido por X.509 / CSR / CRL.
func ed521Sign(priv *e521.PrivateKey, tbsBytes []byte) ([]byte, error) {
	return priv.Sign(tbsBytes)
}

// ed521PublicKeyInfo monta o SPKI usando EncodeE521PublicKey.
func ed521PublicKeyInfo(pub *e521.PublicKey) (publicKeyInfo, error) {
	spkiDER, err := EncodeE521PublicKey(pub)
	if err != nil {
		return publicKeyInfo{}, err
	}

	// Se o resultado já for PEM, decodifique primeiro para obter o DER interno
	if block, _ := pem.Decode(spkiDER); block != nil {
		spkiDER = block.Bytes
	}

	var spki publicKeyInfo
	if _, err := asn1.Unmarshal(spkiDER, &spki); err != nil {
		return publicKeyInfo{}, fmt.Errorf("unmarshal SPKI failed: %w (DER: %x)", err, spkiDER)
	}

	return spki, nil
}

// marshalEd521KeyUsage codifica o KeyUsage como o crypto/x509 do Go faz.
// No DER o bit 0 (digitalSignature) é o mais significativo do primeiro octeto
// (RFC 5280, 4.2.1.3), ao contrário da máscara x509.KeyUsage, e os bits zero
// do fim não são escritos. A raiz ICP-Brasil v7 tem 03 02 01 06
// (keyCertSign e cRLSign).
func marshalEd521KeyUsage(keyUsage x509.KeyUsage) ([]byte, error) {
	octets := []byte{bits.Reverse8(byte(keyUsage)), bits.Reverse8(byte(keyUsage >> 8))}
	if octets[1] == 0 {
		octets = octets[:1]
	}
	bitLength := len(octets) * 8
	for bitLength > 0 && octets[(bitLength-1)/8]&(0x80>>uint((bitLength-1)%8)) == 0 {
		bitLength--
	}
	return asn1.Marshal(asn1.BitString{Bytes: octets, BitLength: bitLength})
}

// buildEd521Extensions monta as extensões X.509 e retorna um RawValue com o
// [3] EXPLICIT já construído, pronto para ser embutido no TBSCertificate.
func buildEd521Extensions(
	pubInfo publicKeyInfo,
	isCA bool,
	keyUsage x509.KeyUsage,
	extKeyUsage []x509.ExtKeyUsage,
) (asn1.RawValue, error) {
	var exts []pkix.Extension

	// SubjectKeyIdentifier (2.5.29.14) — SHA-1 da chave pública
	ski := sha1.Sum(pubInfo.PublicKey.Bytes)
	skiDER, err := asn1.Marshal(ski[:])
	if err != nil {
		return asn1.RawValue{}, err
	}
	exts = append(exts, pkix.Extension{
		Id:    asn1.ObjectIdentifier{2, 5, 29, 14},
		Value: skiDER,
	})

	// AuthorityKeyIdentifier (2.5.29.35) — mesmo SKI (autoassinado)
	akiStruct := struct {
		ID []byte `asn1:"optional,tag:0"`
	}{ID: ski[:]}
	akiDER, err := asn1.Marshal(akiStruct)
	if err != nil {
		return asn1.RawValue{}, err
	}
	exts = append(exts, pkix.Extension{
		Id:    asn1.ObjectIdentifier{2, 5, 29, 35},
		Value: akiDER,
	})

	// BasicConstraints (2.5.29.19) — crítica
	bcStruct := struct {
		IsCA       bool `asn1:"optional"`
		MaxPathLen int  `asn1:"optional,default:-1"`
	}{IsCA: isCA, MaxPathLen: -1}
	bcDER, err := asn1.Marshal(bcStruct)
	if err != nil {
		return asn1.RawValue{}, err
	}
	exts = append(exts, pkix.Extension{
		Id:       asn1.ObjectIdentifier{2, 5, 29, 19},
		Critical: true,
		Value:    bcDER,
	})

	// KeyUsage (2.5.29.15) — crítica
	kuDER, err := marshalEd521KeyUsage(keyUsage)
	if err != nil {
		return asn1.RawValue{}, err
	}
	exts = append(exts, pkix.Extension{
		Id:       asn1.ObjectIdentifier{2, 5, 29, 15},
		Critical: true,
		Value:    kuDER,
	})

	// ExtendedKeyUsage (2.5.29.37) — opcional
	if len(extKeyUsage) > 0 {
		var oids []asn1.ObjectIdentifier
		for _, eku := range extKeyUsage {
			switch eku {
			case x509.ExtKeyUsageServerAuth:
				oids = append(oids, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1})
			case x509.ExtKeyUsageClientAuth:
				oids = append(oids, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2})
			}
		}
		ekuDER, err := asn1.Marshal(oids)
		if err != nil {
			return asn1.RawValue{}, err
		}
		exts = append(exts, pkix.Extension{
			Id:    asn1.ObjectIdentifier{2, 5, 29, 37},
			Value: ekuDER,
		})
	}

	// Marshal a SEQUENCE OF Extension
	extsDER, err := asn1.Marshal(exts)
	if err != nil {
		return asn1.RawValue{}, err
	}

	// Montar manualmente o [3] EXPLICIT em volta da SEQUENCE
	return asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        3,
		IsCompound: true,
		Bytes:      extsDER,
	}, nil
}

// --- Certificado Autoassinado ---

func CreateEd521SelfSignedCertificate(
	priv *e521.PrivateKey,
	serial *big.Int,
	subject, issuer pkix.RDNSequence,
	notBefore, notAfter time.Time,
	extensions asn1.RawValue,
) ([]byte, error) {
	pub := priv.GetPublic()

	pubInfo, err := ed521PublicKeyInfo(pub)
	if err != nil {
		return nil, err
	}

	algID := pkAlgorithmIdentifier{Algorithm: oidEd521}

	tbs := tbsCertificate{
		Version:            2,
		SerialNumber:       serial,
		SignatureAlgorithm: algID,
		Issuer:             issuer,
		Validity:           validity{NotBefore: notBefore, NotAfter: notAfter},
		Subject:            subject,
		PublicKey:          pubInfo,
		Extensions:         extensions,
	}

	tbsBytes, err := asn1.Marshal(tbs)
	if err != nil {
		return nil, err
	}

	signature, err := ed521Sign(priv, tbsBytes)
	if err != nil {
		return nil, err
	}

	cert := certificate{
		TBSCertificate:     tbs,
		SignatureAlgorithm: algID,
		SignatureValue:     asn1.BitString{Bytes: signature, BitLength: len(signature) * 8},
	}

	return asn1.Marshal(cert)
}

// --- CSR (PKCS#10) ---

func CreateEd521CSR(priv *e521.PrivateKey, subject pkix.RDNSequence) ([]byte, error) {
	pub := priv.GetPublic()

	pubInfo, err := ed521PublicKeyInfo(pub)
	if err != nil {
		return nil, err
	}

	algID := pkAlgorithmIdentifier{Algorithm: oidEd521}

	tbs := tbsCertificationRequest{
		Version:       0,
		Subject:       subject,
		SubjectPKInfo: pubInfo,
		Attributes:    []asn1.RawValue{},
	}

	tbsBytes, err := asn1.Marshal(tbs)
	if err != nil {
		return nil, err
	}

	signature, err := ed521Sign(priv, tbsBytes)
	if err != nil {
		return nil, err
	}

	csr := certificationRequest{
		TBSCertificationRequest: tbs,
		SignatureAlgorithm:      algID,
		SignatureValue:          asn1.BitString{Bytes: signature, BitLength: len(signature) * 8},
	}

	return asn1.Marshal(csr)
}

// --- CRL (X.509 v2) ---

func CreateEd521CRL(
	priv *e521.PrivateKey,
	issuer pkix.RDNSequence,
	thisUpdate, nextUpdate time.Time,
	revoked []pkixRevokedCertificate,
	crlNumber *big.Int,
	authorityKeyId []byte,
) ([]byte, error) {
	algID := pkAlgorithmIdentifier{Algorithm: oidEd521}

	var exts []pkix.Extension

	// crlNumber (2.5.29.20) — obrigatório em CRL v2
	if crlNumber != nil {
		numDER, err := asn1.Marshal(crlNumber)
		if err != nil {
			return nil, err
		}
		exts = append(exts, pkix.Extension{
			Id:    asn1.ObjectIdentifier{2, 5, 29, 20},
			Value: numDER,
		})
	}

	// authorityKeyIdentifier (2.5.29.35)
	if len(authorityKeyId) > 0 {
		akiStruct := struct {
			ID []byte `asn1:"optional,tag:0"`
		}{ID: authorityKeyId}
		akiDER, err := asn1.Marshal(akiStruct)
		if err != nil {
			return nil, err
		}
		exts = append(exts, pkix.Extension{
			Id:    asn1.ObjectIdentifier{2, 5, 29, 35},
			Value: akiDER,
		})
	}

	// Montar [0] EXPLICIT em volta da SEQUENCE OF Extension
	var extsRV asn1.RawValue
	if len(exts) > 0 {
		extsDER, err := asn1.Marshal(exts)
		if err != nil {
			return nil, err
		}
		extsRV = asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      extsDER,
		}
	}

	tbs := tbsCertList{
		Version:             1,
		Signature:           algID,
		Issuer:              issuer,
		ThisUpdate:          thisUpdate,
		NextUpdate:          nextUpdate,
		RevokedCertificates: revoked,
		Extensions:          extsRV,
	}

	tbsBytes, err := asn1.Marshal(tbs)
	if err != nil {
		return nil, err
	}

	signature, err := ed521Sign(priv, tbsBytes)
	if err != nil {
		return nil, err
	}

	crl := certificateList{
		TBSCertList:        tbs,
		SignatureAlgorithm: algID,
		SignatureValue:     asn1.BitString{Bytes: signature, BitLength: len(signature) * 8},
	}

	return asn1.Marshal(crl)
}

func pemEncode(der []byte, blockType string) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  blockType,
		Bytes: der,
	})
}

// ParseEd521Certificate analisa um certificado DER codificado em Ed521.
func ParseEd521Certificate(der []byte) (*certificate, error) {
	var cert certificate
	rest, err := asn1.Unmarshal(der, &cert)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal certificate: %w", err)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("trailing data after certificate: %d bytes", len(rest))
	}
	return &cert, nil
}

// CreateEd521CertificateFromCSR emite um certificado Ed521 assinado pela CA.
func CreateEd521CertificateFromCSR(
	caPriv *e521.PrivateKey,
	serial *big.Int,
	subject pkix.RDNSequence,
	issuer pkix.RDNSequence,
	pubInfo publicKeyInfo,
	notBefore, notAfter time.Time,
	extensions asn1.RawValue,
) ([]byte, error) {
	algID := pkAlgorithmIdentifier{Algorithm: oidEd521}

	tbs := tbsCertificate{
		Version:            2,
		SerialNumber:       serial,
		SignatureAlgorithm: algID,
		Issuer:             issuer,
		Validity:           validity{NotBefore: notBefore, NotAfter: notAfter},
		Subject:            subject,
		PublicKey:          pubInfo,
		Extensions:         extensions,
	}

	tbsBytes, err := asn1.Marshal(tbs)
	if err != nil {
		return nil, err
	}

	signature, err := ed521Sign(caPriv, tbsBytes)
	if err != nil {
		return nil, err
	}

	cert := certificate{
		TBSCertificate:     tbs,
		SignatureAlgorithm: algID,
		SignatureValue:     asn1.BitString{Bytes: signature, BitLength: len(signature) * 8},
	}

	return asn1.Marshal(cert)
}

// VerifyEd521CRLSignature verifica a assinatura de uma CRL Ed521
// usando a chave pública do certificado da CA.
func VerifyEd521CRLSignature(caCert *certificate, crlDER []byte) (bool, error) {
	// 1. Parsear a CRL preservando os bytes originais do TBSCertList
	var crlRaw struct {
		TBS       asn1.RawValue
		SigAlg    pkAlgorithmIdentifier
		Signature asn1.BitString
	}
	if _, err := asn1.Unmarshal(crlDER, &crlRaw); err != nil {
		return false, fmt.Errorf("failed to parse CRL: %w", err)
	}

	// 2. Os bytes assinados são exatamente os FullBytes do TBS
	tbsBytes := crlRaw.TBS.FullBytes

	// 3. Extrair a chave pública do certificado da CA via SPKI completo
	pubInfo := caCert.TBSCertificate.PublicKey
	spkiDER, err := asn1.Marshal(pubInfo)
	if err != nil {
		return false, fmt.Errorf("failed to marshal SPKI: %w", err)
	}

	pub, err := e521.ParsePublicKey(spkiDER)
	if err != nil {
		return false, fmt.Errorf("failed to parse Ed521 public key: %w", err)
	}

	// 4. Verificar a assinatura (formato ASN.1, gerado por SignASN1Compressed)
	valid := pub.Verify(tbsBytes, crlRaw.Signature.Bytes)
	return valid, nil
}

