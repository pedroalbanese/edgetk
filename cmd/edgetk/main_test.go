// SPDX-License-Identifier: ISC

package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
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

	tests := []struct {
		name string
		args []string
		want string
	}{
		{"text/ed521", []string{"-pkey", "text", "-cert", itiV7}, "Failed to parse GOST certificate:"},
		{"modulus/ed521", []string{"-pkey", "modulus", "-cert", itiV7}, "Failed to parse GOST certificate:"},
		{"check/ed521", []string{"-pkey", "check", "-cert", itiV7, "-key", itiV7}, "Failed to parse GOST certificate:"},
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
