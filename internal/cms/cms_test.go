package cms

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type party struct {
	cert *x509.Certificate
	key  crypto.Signer
}

func newKey(t *testing.T, kind string) crypto.Signer {
	t.Helper()
	var key crypto.Signer
	var err error
	switch kind {
	case "p256":
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "p384":
		key, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "p521":
		key, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	case "rsa":
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	default:
		t.Fatalf("no key kind %s", kind)
	}
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func newCA(t *testing.T, cn string) party {
	t.Helper()
	key := newKey(t, "p384")
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return party{cert, key}
}

func (ca party) issue(t *testing.T, cn, kind string) party {
	t.Helper()
	key := newKey(t, kind)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, key.Public(), ca.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return party{cert, key}
}

func (p party) write(t *testing.T, dir, name string) (string, string) {
	t.Helper()
	keyDER, err := x509.MarshalPKCS8PrivateKey(p.key)
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, name+".pem")
	keyPath := filepath.Join(dir, name+".key")
	writeFile(t, certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.cert.Raw}))
	writeFile(t, keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	return certPath, keyPath
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func pool(certs ...*x509.Certificate) *x509.CertPool {
	p := x509.NewCertPool()
	for _, c := range certs {
		p.AddCert(c)
	}
	return p
}

var content = []byte("[system]\nhostname = \"dev\"\n\n[ssh]\nauthorized_keys = [\"ssh-ed25519 AAAA a@b\"]\n")

func TestSealOpensForEveryRecipientKind(t *testing.T) {
	ca := newCA(t, "test CA")
	for _, signerKind := range []string{"p256", "rsa"} {
		signer := ca.issue(t, SignerCN, signerKind)
		for _, kind := range []string{"p256", "p384", "p521", "rsa"} {
			dev := ca.issue(t, "dev", kind)
			sealed, err := Seal(content, signer.cert, signer.key, dev.cert, signer.cert)
			if err != nil {
				t.Fatalf("%s/%s: %v", signerKind, kind, err)
			}
			if !IsPEM(sealed) {
				t.Fatalf("%s/%s: not PEM", signerKind, kind)
			}
			for _, who := range []party{dev, signer} {
				got, by, err := Open(sealed, who.cert, who.key, pool(ca.cert), time.Now())
				if err != nil {
					t.Fatalf("%s/%s: %v", signerKind, kind, err)
				}
				if !bytes.Equal(got, content) || !by.Equal(signer.cert) {
					t.Fatalf("%s/%s: wrong content or signer", signerKind, kind)
				}
			}
		}
	}
}

func TestOpenRefuses(t *testing.T) {
	ca := newCA(t, "test CA")
	other := newCA(t, "other CA")
	signer := ca.issue(t, SignerCN, "p256")
	dev := ca.issue(t, "dev", "p256")
	dev2 := ca.issue(t, "dev2", "p256")
	sealed, err := Seal(content, signer.cert, signer.key, dev.cert)
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err := Open(sealed, dev2.cert, dev2.key, pool(ca.cert), time.Now()); !errors.Is(err, errNoMatchingRecipient) {
		t.Errorf("another device: %v", err)
	}
	if _, _, err := Open(sealed, dev.cert, dev.key, pool(other.cert), time.Now()); err == nil {
		t.Error("a signer from another CA is taken")
	}
	if got, _, err := Open(sealed, dev.cert, dev.key, nil, time.Now()); err != nil || !bytes.Equal(got, content) {
		t.Errorf("without a CA: %v", err)
	}

	imposter := ca.issue(t, "dev2", "p256")
	forged, err := Seal(content, imposter.cert, imposter.key, dev.cert)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Open(forged, dev.cert, dev.key, pool(ca.cert), time.Now()); !errors.Is(err, ErrNotSigner) {
		t.Errorf("a file signed by another certificate of the CA: %v", err)
	}

	der, _ := DecodePEM(sealed)
	for _, i := range []int{len(der) - 1, len(der) - 30} {
		tampered := append([]byte(nil), der...)
		tampered[i] ^= 1
		if _, _, err := Open(EncodePEM(tampered), dev.cert, dev.key, pool(ca.cert), time.Now()); err == nil {
			t.Errorf("a file changed at byte %d opens", i)
		}
	}
}

func TestVerifyRefusesChangedContent(t *testing.T) {
	ca := newCA(t, "test CA")
	signer := ca.issue(t, SignerCN, "p256")
	signed, err := Sign(content, signer.cert, signer.key)
	if err != nil {
		t.Fatal(err)
	}
	i := bytes.Index(signed, []byte("hostname"))
	tampered := append([]byte(nil), signed...)
	tampered[i] = 'H'
	if _, _, err := Verify(tampered, pool(ca.cert), time.Now()); !errors.Is(err, errMessageDigestMismatch) {
		t.Errorf("changed content: %v", err)
	}
}

func TestAESKeyWrapRFC3394(t *testing.T) {
	kek, _ := hex.DecodeString("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
	key, _ := hex.DecodeString("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F")
	want := "28c9f404c4b810f4cbccb35cfb87f8263f5786e2d80ed326cbc7f0e71a99f43bfb988b9b7a02dd21"
	wrapped, err := aesWrap(kek, key)
	if err != nil || hex.EncodeToString(wrapped) != want {
		t.Fatalf("wrap: %x, %v", wrapped, err)
	}
	unwrapped, err := aesUnwrap(kek, wrapped)
	if err != nil || !bytes.Equal(unwrapped, key) {
		t.Fatalf("unwrap: %x, %v", unwrapped, err)
	}
	wrapped[3] ^= 1
	if _, err := aesUnwrap(kek, wrapped); err == nil {
		t.Fatal("a changed wrapped key unwraps")
	}
}

func openssl(t *testing.T) string {
	t.Helper()
	for _, p := range []string{os.Getenv("OPENSSL"), "/opt/homebrew/bin/openssl", "/usr/local/bin/openssl", "openssl"} {
		if p == "" {
			continue
		}
		path, err := exec.LookPath(p)
		if err != nil {
			continue
		}
		out, err := exec.Command(path, "version").Output()
		if err == nil && strings.HasPrefix(string(out), "OpenSSL ") && !strings.HasPrefix(string(out), "OpenSSL 1.") {
			return path
		}
	}
	t.Skip("no OpenSSL 3 or later")
	return ""
}

func run(t *testing.T, name string, args ...string) []byte {
	t.Helper()
	cmd := exec.Command(name, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", filepath.Base(name), strings.Join(args, " "), err, stderr.String())
	}
	return out
}

func TestOpenSSLOpensWhatGoSeals(t *testing.T) {
	bin := openssl(t)
	dir := t.TempDir()
	ca := newCA(t, "test CA")
	caPath := filepath.Join(dir, "ca.pem")
	writeFile(t, caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw}))
	for _, signerKind := range []string{"p256", "rsa"} {
		signer := ca.issue(t, SignerCN, signerKind)
		for _, kind := range []string{"p256", "p384", "rsa"} {
			dev := ca.issue(t, "dev", kind)
			devCert, devKey := dev.write(t, dir, "dev-"+kind)
			sealed, err := Seal(content, signer.cert, signer.key, dev.cert, signer.cert)
			if err != nil {
				t.Fatal(err)
			}
			sealedPath := filepath.Join(dir, "sealed.cms")
			writeFile(t, sealedPath, sealed)
			signedPath := filepath.Join(dir, "signed")
			run(t, bin, "cms", "-decrypt", "-inform", "PEM", "-in", sealedPath, "-inkey", devKey,
				"-recip", devCert, "-out", signedPath)
			got := run(t, bin, "cms", "-verify", "-binary", "-inform", "DER", "-in", signedPath,
				"-purpose", "any", "-CAfile", caPath, "-out", "-")
			if !bytes.Equal(got, content) {
				t.Fatalf("%s/%s: openssl got %q", signerKind, kind, got)
			}
		}
	}
}

func TestGoOpensWhatOpenSSLSeals(t *testing.T) {
	bin := openssl(t)
	dir := t.TempDir()
	ca := newCA(t, "test CA")
	for _, signerKind := range []string{"p256", "rsa"} {
		signer := ca.issue(t, SignerCN, signerKind)
		signerCert, signerKey := signer.write(t, dir, "signer-"+signerKind)
		for _, kind := range []string{"p256", "p384", "rsa"} {
			dev := ca.issue(t, "dev", kind)
			devCert, _ := dev.write(t, dir, "dev-"+kind)
			plainPath := filepath.Join(dir, "dev.toml")
			writeFile(t, plainPath, content)
			signedPath := filepath.Join(dir, "signed")
			sealedPath := filepath.Join(dir, "sealed.cms")
			run(t, bin, "cms", "-sign", "-binary", "-nodetach", "-md", "sha256", "-in", plainPath,
				"-signer", signerCert, "-inkey", signerKey, "-outform", "DER", "-out", signedPath)
			run(t, bin, "cms", "-encrypt", "-binary", "-aes-256-gcm", "-in", signedPath, "-outform", "PEM",
				"-out", sealedPath, devCert, signerCert)
			sealed, _ := os.ReadFile(sealedPath)
			for _, who := range []party{dev, signer} {
				got, _, err := Open(sealed, who.cert, who.key, pool(ca.cert), time.Now())
				if err != nil || !bytes.Equal(got, content) {
					t.Fatalf("%s/%s: %v", signerKind, kind, err)
				}
			}
		}
	}
}

func cfgProvision(t *testing.T) string {
	t.Helper()
	for _, p := range []string{os.Getenv("CFG_PROVISION"), "../../../cfg-provision"} {
		if p == "" {
			continue
		}
		script := filepath.Join(p, "cfg-provision")
		if _, err := os.Stat(script); err == nil {
			abs, _ := filepath.Abs(script)
			return abs
		}
	}
	t.Skip("no cfg-provision checkout, set CFG_PROVISION")
	return ""
}

func TestCfgProvisionAndGoOpenEachOthersFiles(t *testing.T) {
	bin := openssl(t)
	script := cfgProvision(t)
	dir := t.TempDir()
	ca := newCA(t, "test CA")
	signer := ca.issue(t, SignerCN, "p256")
	dev := ca.issue(t, "dev", "p256")
	signer.write(t, filepath.Join(dir, "certs", SignerCN), SignerCN)
	dev.write(t, filepath.Join(dir, "certs", "dev"), "dev")
	writeFile(t, filepath.Join(dir, "certs", SignerCN, "ca.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw}))
	cfg := func(args ...string) {
		t.Helper()
		cmd := exec.Command(script, args...)
		cmd.Env = append(os.Environ(), "CFG_PROVISION_ENV=/dev/null",
			"CFG_PROVISION_CERTS="+filepath.Join(dir, "certs"),
			"CFG_PROVISION_PLAIN="+filepath.Join(dir, "plain"),
			"CFG_PROVISION_DEVICES="+filepath.Join(dir, "devices"),
			"PATH="+filepath.Dir(bin)+string(os.PathListSeparator)+os.Getenv("PATH"))
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("cfg-provision %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}

	writeFile(t, filepath.Join(dir, "plain", "dev.toml"), content)
	cfg("seal", "dev")
	sealed, err := os.ReadFile(filepath.Join(dir, "devices", "dev.cms"))
	if err != nil {
		t.Fatal(err)
	}
	if got, _, err := Open(sealed, dev.cert, dev.key, pool(ca.cert), time.Now()); err != nil || !bytes.Equal(got, content) {
		t.Fatalf("Go opening cfg-provision's file: %v", err)
	}

	ours, err := Seal(content, signer.cert, signer.key, dev.cert, signer.cert)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "devices", "dev.cms"), ours)
	os.Remove(filepath.Join(dir, "plain", "dev.toml"))
	cfg("open", "dev")
	got, err := os.ReadFile(filepath.Join(dir, "plain", "dev.toml"))
	if err != nil || !bytes.Equal(got, content) {
		t.Fatalf("cfg-provision opening Go's file: %v", err)
	}
}
