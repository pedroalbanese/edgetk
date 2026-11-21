// SPDX-License-Identifier: ISC

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pedroalbanese/e521"
)

// The tests run the command itself: the test binary starts again with
// EDGETK_TEST_MAIN=1 and calls main() with the arguments under test, so the
// exit status and the output are the ones a person gets.
//
// testdata holds two public root certificates of ICP-Brasil (ITI), unchanged,
// from https://acraiz.icpbrasil.gov.br/credenciadas/RAIZ/:
//
//	ICP-Brasilv7.crt  Ed521, OID 1.3.6.1.4.1.44588.2.1
//	                  SHA-256 4fe1d8599fc00f0b61b12391c98d97af36bcada115bd894f8755e01e212bc4be
//	ICP-Brasilv5.crt  RSA 4096 with SHA-512
//	                  SHA-256 5bd85f219695dabe6cf3d4bd713d9bd8e41b2323194022acf1acd658daef148a
const (
	itiV7 = "testdata/ICP-Brasilv7.crt"
	itiV5 = "testdata/ICP-Brasilv5.crt"
)

func TestMain(m *testing.M) {
	if os.Getenv("EDGETK_TEST_MAIN") == "1" {
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func edgetk(t *testing.T, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = append(os.Environ(), "EDGETK_TEST_MAIN=1")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	if err == nil {
		return out.String(), 0
	}
	exit, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatal(err)
	}
	return out.String(), exit.ExitCode()
}

func readCertificate(t *testing.T, path string) *pem.Block {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatalf("%s: no PEM block", path)
	}
	return block
}

func writePEM(t *testing.T, name, kind string, der []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// A certificate that a parser cannot read ends in a message and status 1,
// not in a nil pointer panic.
func TestPkeyReportsCertificateParseError(t *testing.T) {
	// The v5 root cut in half: no parser reads it.
	cut := readCertificate(t, itiV5).Bytes
	truncated := writePEM(t, "truncated.crt", "CERTIFICATE", cut[:len(cut)/2])

	// The v7 root with its three algorithm OIDs changed to 1.3.6.1.4.1.44588.2.2,
	// which nothing implements: it is read as a certificate, and then no
	// parser knows its key.
	oid := []byte{0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xdc, 0x2c, 0x02, 0x01}
	other := append([]byte(nil), oid...)
	other[len(other)-1] = 0x02
	v7 := readCertificate(t, itiV7).Bytes
	if bytes.Count(v7, oid) != 3 {
		t.Fatalf("%s: %d Ed521 OIDs, want 3", itiV7, bytes.Count(v7, oid))
	}
	unknown := writePEM(t, "unknown.crt", "CERTIFICATE", bytes.ReplaceAll(v7, oid, other))

	tests := []struct {
		name string
		args []string
		want string
	}{
		{"text/unknown", []string{"-pkey", "text", "-cert", unknown}, "Failed to parse GOST certificate:"},
		{"modulus/unknown", []string{"-pkey", "modulus", "-cert", unknown}, "Failed to parse GOST certificate:"},
		{"check/unknown", []string{"-pkey", "check", "-cert", unknown, "-key", unknown}, "Failed to parse GOST certificate:"},
		{"text/truncated", []string{"-pkey", "text", "-cert", truncated}, "Failed to parse certificate:"},
		{"modulus/truncated", []string{"-pkey", "modulus", "-cert", truncated}, "Failed to parse certificate:"},
		{"check/truncated", []string{"-pkey", "check", "-cert", truncated, "-key", truncated}, "Failed to parse certificate:"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, status := edgetk(t, tt.args...)
			if strings.Contains(out, "panic:") {
				t.Fatalf("panic instead of an error message:\n%s", out)
			}
			if status != 1 {
				t.Errorf("exit status %d, want 1\n%s", status, out)
			}
			if !strings.Contains(out, tt.want) {
				t.Errorf("output lacks %q:\n%s", tt.want, out)
			}
		})
	}
}

// A certificate the parsers read is printed and checked as before.
func TestPkeyReadsRSACertificate(t *testing.T) {
	cert, err := x509.ParseCertificate(readCertificate(t, itiV5).Bytes)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pub := writePEM(t, "v5-public.pem", "PUBLIC KEY", spki)

	// -pkey text ends with status 1 once the certificate has expired
	// (2029-03-02 for v5), so only its output is compared.
	out, _ := edgetk(t, "-pkey", "text", "-cert", itiV5)
	for _, want := range []string{"Signature Algorithm: SHA512-RSA", "Autoridade Certificadora Raiz Brasileira v5"} {
		if !strings.Contains(out, want) {
			t.Errorf("-pkey text lacks %q:\n%s", want, out)
		}
	}

	out, status := edgetk(t, "-pkey", "modulus", "-cert", itiV5)
	if status != 0 || !strings.HasPrefix(out, "Modulus=F72D781A6D45AC17") {
		t.Errorf("-pkey modulus: status %d\n%s", status, out)
	}

	out, status = edgetk(t, "-pkey", "check", "-cert", itiV5, "-key", pub)
	if status != 0 || !strings.Contains(out, "Verified: true") {
		t.Errorf("-pkey check: status %d\n%s", status, out)
	}

	// The last octet of the signature altered: the check refuses it.
	tampered := append([]byte(nil), cert.Raw...)
	tampered[len(tampered)-1] ^= 0x01
	bad := writePEM(t, "v5-bad-signature.crt", "CERTIFICATE", tampered)
	out, status = edgetk(t, "-pkey", "check", "-cert", bad, "-key", pub)
	if status != 1 || !strings.Contains(out, "Verified: false") {
		t.Errorf("-pkey check with an altered signature: status %d\n%s", status, out)
	}
}

// The ICP-Brasil v7 root is an Ed521 certificate: it is printed, and its
// signature is checked with the Ed521 public key given in -key.
func TestPkeyReadsEd521Certificate(t *testing.T) {
	der := readCertificate(t, itiV7).Bytes
	var certificate struct {
		TBSCertificate struct {
			Version      int `asn1:"optional,explicit,default:0,tag:0"`
			SerialNumber asn1.RawValue
			Signature    pkix.AlgorithmIdentifier
			Issuer       asn1.RawValue
			Validity     asn1.RawValue
			Subject      asn1.RawValue
			PublicKey    asn1.RawValue
			Extensions   asn1.RawValue `asn1:"optional,explicit,tag:3"`
		}
		SignatureAlgorithm pkix.AlgorithmIdentifier
		SignatureValue     asn1.BitString
	}
	if _, err := asn1.Unmarshal(der, &certificate); err != nil {
		t.Fatal(err)
	}
	pub := writePEM(t, "v7-public.pem", "PUBLIC KEY", certificate.TBSCertificate.PublicKey.FullBytes)

	out, _ := edgetk(t, "-pkey", "text", "-cert", itiV7)
	for _, want := range []string{
		"Curve         : E-521",
		"Autoridade Certificadora Raiz Brasileira v7",
		"Not After : Dec 28 12:00:35 2038 UTC",
		"SubjectKeyId  : 75513119e1c71321873e415fa31be67bfdb0d9c8",
		"Signature Algorithm: Ed521",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("-pkey text lacks %q:\n%s", want, out)
		}
	}

	out, status := edgetk(t, "-pkey", "modulus", "-cert", itiV7)
	if status != 0 || !strings.HasPrefix(out, "Public.X=23EDDDD643698636") || !strings.Contains(out, "\nPublic.Y=12CE0B0C0EEAC841") {
		t.Errorf("-pkey modulus: status %d\n%s", status, out)
	}

	out, status = edgetk(t, "-pkey", "check", "-cert", itiV7, "-key", pub)
	if status != 0 || !strings.Contains(out, "Verified: true") {
		t.Errorf("-pkey check: status %d\n%s", status, out)
	}

	// The last octet of the signature altered: the check refuses it.
	tampered := append([]byte(nil), der...)
	tampered[len(tampered)-1] ^= 0x01
	bad := writePEM(t, "v7-bad-signature.crt", "CERTIFICATE", tampered)
	out, status = edgetk(t, "-pkey", "check", "-cert", bad, "-key", pub)
	if status != 1 || !strings.Contains(out, "Verified: false") {
		t.Errorf("-pkey check with an altered signature: status %d\n%s", status, out)
	}

	// One octet of the signed part altered (the last of the serial number).
	serial := certificate.TBSCertificate.SerialNumber.FullBytes
	at := bytes.Index(der, serial) + len(serial) - 1
	tampered = append([]byte(nil), der...)
	tampered[at] ^= 0x01
	bad = writePEM(t, "v7-bad-serial.crt", "CERTIFICATE", tampered)
	out, status = edgetk(t, "-pkey", "check", "-cert", bad, "-key", pub)
	if status != 1 || !strings.Contains(out, "Verified: false") {
		t.Errorf("-pkey check with an altered serial number: status %d\n%s", status, out)
	}

	// Another Ed521 key does not verify it.
	priv, err := e521.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	spki, err := priv.GetPublic().MarshalPKCS8PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	stranger := writePEM(t, "stranger.pem", "PUBLIC KEY", spki)
	out, status = edgetk(t, "-pkey", "check", "-cert", itiV7, "-key", stranger)
	if status != 1 || !strings.Contains(out, "Verified: false") {
		t.Errorf("-pkey check with another key: status %d\n%s", status, out)
	}

	// A key of another algorithm is refused with a message.
	v5, err := x509.ParseCertificate(readCertificate(t, itiV5).Bytes)
	if err != nil {
		t.Fatal(err)
	}
	spki, err = x509.MarshalPKIXPublicKey(v5.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey := writePEM(t, "v5-public.pem", "PUBLIC KEY", spki)
	out, status = edgetk(t, "-pkey", "check", "-cert", itiV7, "-key", rsaKey)
	if status != 1 || !strings.Contains(out, "Public key is not E-521") || strings.Contains(out, "panic:") {
		t.Errorf("-pkey check with an RSA key: status %d\n%s", status, out)
	}
}

// keyUsageValue returns the value of the KeyUsage extension (2.5.29.15) of an
// Ed521 certificate, as the octets inside its OCTET STRING.
func keyUsageValue(t *testing.T, der []byte) []byte {
	t.Helper()
	cert, err := ParseEd521Certificate(der)
	if err != nil {
		t.Fatal(err)
	}
	var extensions []pkix.Extension
	if _, err := asn1.Unmarshal(cert.TBSCertificate.Extensions.Bytes, &extensions); err != nil {
		t.Fatal(err)
	}
	for _, extension := range extensions {
		if extension.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 15}) {
			return extension.Value
		}
	}
	t.Fatal("no KeyUsage extension")
	return nil
}

// writtenKeyUsage returns the KeyUsage value that the extensions of a new
// Ed521 certificate carry for the given usage.
func writtenKeyUsage(t *testing.T, usage x509.KeyUsage) []byte {
	t.Helper()
	raw, err := buildEd521Extensions(publicKeyInfo{}, false, usage, nil)
	if err != nil {
		t.Fatal(err)
	}
	var extensions []pkix.Extension
	if _, err := asn1.Unmarshal(raw.Bytes, &extensions); err != nil {
		t.Fatal(err)
	}
	for _, extension := range extensions {
		if extension.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 15}) {
			return extension.Value
		}
	}
	t.Fatal("no KeyUsage extension")
	return nil
}

// The KeyUsage of an Ed521 certificate is written as RFC 5280, 4.2.1.3 numbers
// its bits (bit 0 is the most significant bit of the first octet), as the real
// ICP-Brasil v7 root has it and as crypto/x509 writes it.
func TestEd521CertificateKeyUsage(t *testing.T) {
	// The real root: keyCertSign and cRLSign.
	root := keyUsageValue(t, readCertificate(t, itiV7).Bytes)
	if !bytes.Equal(root, []byte{0x03, 0x02, 0x01, 0x06}) {
		t.Fatalf("ICP-Brasil v7 KeyUsage: % X", root)
	}
	ours := writtenKeyUsage(t, x509.KeyUsageCertSign|x509.KeyUsageCRLSign)
	if !bytes.Equal(ours, root) {
		t.Errorf("keyCertSign and cRLSign: % X, the ICP-Brasil v7 root has % X", ours, root)
	}

	// The same octets as crypto/x509 writes, for one bit, several bits and a
	// bit of the second octet.
	_, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, usage := range []x509.KeyUsage{
		x509.KeyUsageDigitalSignature,
		x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment | x509.KeyUsageKeyEncipherment |
			x509.KeyUsageDataEncipherment | x509.KeyUsageKeyAgreement | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		x509.KeyUsageDecipherOnly,
		x509.KeyUsageDigitalSignature | x509.KeyUsageDecipherOnly,
	} {
		template := &x509.Certificate{SerialNumber: big.NewInt(1), KeyUsage: usage}
		der, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
		if err != nil {
			t.Fatal(err)
		}
		reference, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		var want []byte
		for _, extension := range reference.Extensions {
			if extension.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 15}) {
				want = extension.Value
			}
		}
		got := writtenKeyUsage(t, usage)
		if !bytes.Equal(got, want) {
			t.Errorf("KeyUsage %#x: % X, crypto/x509 writes % X", int(usage), got, want)
		}
	}

	// The command: a certificate authority made by -pkey certgen -isca can
	// sign certificates and revocation lists.
	dir := t.TempDir()
	private, public, authority := filepath.Join(dir, "private.pem"), filepath.Join(dir, "public.pem"), filepath.Join(dir, "ca.crt")
	if out, status := edgetk(t, "-pkey", "keygen", "-algorithm", "ed521", "-prv", private, "-pub", public); status != 0 {
		t.Fatalf("-pkey keygen: status %d\n%s", status, out)
	}
	if out, status := edgetk(t, "-pkey", "certgen", "-algorithm", "ed521", "-key", private, "-pub", public, "-cert", authority,
		"-days", "1", "-subj", "/CN=Test/OU=/O=/ST=/L=/C=/emailAddress=", "-isca"); status != 0 {
		t.Fatalf("-pkey certgen: status %d\n%s", status, out)
	}
	var usage asn1.BitString
	if _, err := asn1.Unmarshal(keyUsageValue(t, readCertificate(t, authority).Bytes), &usage); err != nil {
		t.Fatal(err)
	}
	if usage.At(5) != 1 || usage.At(6) != 1 {
		t.Errorf("-pkey certgen -isca: keyCertSign %d, cRLSign %d in KeyUsage % X (%d bits)", usage.At(5), usage.At(6), usage.Bytes, usage.BitLength)
	}
	for bit := 9; bit < usage.BitLength; bit++ {
		if usage.At(bit) != 0 {
			t.Errorf("-pkey certgen -isca: KeyUsage sets bit %d, which RFC 5280 does not define", bit)
		}
	}
}

// ed521Extension returns the value of one extension of an Ed521 certificate,
// as the octets inside its OCTET STRING.
func ed521Extension(t *testing.T, der []byte, id asn1.ObjectIdentifier) []byte {
	t.Helper()
	cert, err := ParseEd521Certificate(der)
	if err != nil {
		t.Fatal(err)
	}
	var extensions []pkix.Extension
	if _, err := asn1.Unmarshal(cert.TBSCertificate.Extensions.Bytes, &extensions); err != nil {
		t.Fatal(err)
	}
	for _, extension := range extensions {
		if extension.Id.Equal(id) {
			return extension.Value
		}
	}
	t.Fatalf("no extension %v", id)
	return nil
}

// ed521KeyIdentifiers returns the SubjectKeyIdentifier (2.5.29.14) and the
// keyIdentifier of the AuthorityKeyIdentifier (2.5.29.35) of an Ed521
// certificate.
func ed521KeyIdentifiers(t *testing.T, der []byte) (subject, authority []byte) {
	t.Helper()
	if _, err := asn1.Unmarshal(ed521Extension(t, der, asn1.ObjectIdentifier{2, 5, 29, 14}), &subject); err != nil {
		t.Fatalf("SubjectKeyIdentifier: %v", err)
	}
	var aki struct {
		ID []byte `asn1:"optional,tag:0"`
	}
	if _, err := asn1.Unmarshal(ed521Extension(t, der, asn1.ObjectIdentifier{2, 5, 29, 35}), &aki); err != nil {
		t.Fatalf("AuthorityKeyIdentifier: %v", err)
	}
	return subject, aki.ID
}

// The AuthorityKeyIdentifier of a certificate identifies the key that signed
// it (RFC 5280, 4.2.1.1): in a certificate issued from a request it is the
// SubjectKeyIdentifier of the CA's certificate, not the certificate's own. In
// a self-signed certificate the two are equal, as in the real ICP-Brasil v7
// root.
func TestEd521IssuedCertificateAuthorityKeyIdentifier(t *testing.T) {
	rootSubject, rootAuthority := ed521KeyIdentifiers(t, readCertificate(t, itiV7).Bytes)
	if len(rootSubject) == 0 || !bytes.Equal(rootSubject, rootAuthority) {
		t.Fatalf("ICP-Brasil v7: SubjectKeyIdentifier % X, AuthorityKeyIdentifier % X", rootSubject, rootAuthority)
	}

	dir := t.TempDir()
	file := func(name string) string { return filepath.Join(dir, name) }
	run := func(args ...string) {
		t.Helper()
		if out, exit := edgetk(t, args...); exit != 0 {
			t.Fatalf("edgetk %s: exit %d\n%s", strings.Join(args, " "), exit, out)
		}
	}
	run("-pkey", "keygen", "-algorithm", "ed521", "-prv", file("ca.pem"), "-pub", file("capub.pem"))
	run("-pkey", "certgen", "-algorithm", "ed521", "-key", file("ca.pem"), "-pub", file("capub.pem"),
		"-cert", file("ca.crt"), "-days", "30", "-subj", "/CN=Teste AC/OU=/O=/ST=/L=/C=BR/emailAddress=", "-isca")
	run("-pkey", "keygen", "-algorithm", "ed521", "-prv", file("key.pem"), "-pub", file("pub.pem"))
	run("-pkey", "req", "-algorithm", "ed521", "-key", file("key.pem"), "-pub", file("pub.pem"),
		"-cert", file("cert.csr"), "-subj", "/CN=Teste/OU=/O=/ST=/L=/C=BR/emailAddress=")
	run("-pkey", "x509", "-algorithm", "ed521", "-key", file("ca.pem"), "-root", file("ca.crt"),
		"-cert", file("cert.csr"), "-days", "30", file("cert.crt"))

	caSubject, caAuthority := ed521KeyIdentifiers(t, readCertificate(t, file("ca.crt")).Bytes)
	if len(caSubject) == 0 || !bytes.Equal(caSubject, caAuthority) {
		t.Errorf("self-signed CA: SubjectKeyIdentifier % X, AuthorityKeyIdentifier % X", caSubject, caAuthority)
	}
	subject, authority := ed521KeyIdentifiers(t, readCertificate(t, file("cert.crt")).Bytes)
	if bytes.Equal(subject, caSubject) {
		t.Fatalf("the issued certificate has the CA's SubjectKeyIdentifier % X", subject)
	}
	if !bytes.Equal(authority, caSubject) {
		t.Errorf("issued certificate: AuthorityKeyIdentifier % X, the CA's SubjectKeyIdentifier is % X", authority, caSubject)
	}
	if bytes.Equal(authority, subject) {
		t.Errorf("issued certificate: AuthorityKeyIdentifier % X is its own SubjectKeyIdentifier", authority)
	}
}
