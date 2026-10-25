package pki

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"time"
)

func GenerateKey(keyType string) (crypto.Signer, error) {
	switch keyType {
	case "ec":
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "rsa":
		return rsa.GenerateKey(rand.Reader, 3072)
	}
	return nil, errors.New("KEY_TYPE must be ec or rsa")
}

func GenerateRSA(bits int) (crypto.Signer, error) {
	return rsa.GenerateKey(rand.Reader, bits)
}

func KeyPEM(key crypto.Signer) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func PublicPEM(key crypto.Signer) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

func CertPEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

func ParseKey(data []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("not a PEM key")
	}
	var key any
	var err error
	switch block.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("not a private key: %s", block.Type)
	}
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("cannot use a %T key", key)
	}
	return signer, nil
}

func ParseCerts(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, errors.New("no certificate")
	}
	return certs, nil
}

func ParseCert(data []byte) (*x509.Certificate, error) {
	certs, err := ParseCerts(data)
	if err != nil {
		return nil, err
	}
	return certs[0], nil
}

func ReadCert(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cert, err := ParseCert(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return cert, nil
}

func ReadKey(path string) (crypto.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key, err := ParseKey(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return key, nil
}

func CSR(key crypto.Signer, cn string) ([]byte, error) {
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

func serial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 159))
}

func SelfSignedCA(key crypto.Signer, cn string, days int) (*x509.Certificate, error) {
	n, err := serial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          n,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             now,
		NotAfter:              now.AddDate(0, 0, days),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

func IntermediateCA(pub crypto.PublicKey, cn string, days int, parent *x509.Certificate, parentKey crypto.Signer) (*x509.Certificate, error) {
	n, err := serial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          n,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             now,
		NotAfter:              now.AddDate(0, 0, days),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, parentKey)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

func Lifetime(parent *x509.Certificate, days int, now time.Time) (int, error) {
	left := int(parent.NotAfter.Sub(now) / (24 * time.Hour))
	if left < 1 {
		return 0, errors.New("the parent CA expires within a day")
	}
	return min(days, left), nil
}

func CACertHash(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return "sha256:" + hex.EncodeToString(sum[:])
}

const tokenAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789"

func randomString(n int) (string, error) {
	out := make([]byte, n)
	max := big.NewInt(int64(len(tokenAlphabet)))
	for i := range out {
		k, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		out[i] = tokenAlphabet[k.Int64()]
	}
	return string(out), nil
}

func BootstrapToken() (string, error) {
	id, err := randomString(6)
	if err != nil {
		return "", err
	}
	secret, err := randomString(16)
	if err != nil {
		return "", err
	}
	return id + "." + secret, nil
}

func WireGuardKeys() (private, public, psk string, err error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", "", err
	}
	shared := make([]byte, 32)
	if _, err := rand.Read(shared); err != nil {
		return "", "", "", err
	}
	enc := base64.StdEncoding.EncodeToString
	return enc(key.Bytes()), enc(key.PublicKey().Bytes()), enc(shared), nil
}

func SamePublicKey(cert *x509.Certificate, key crypto.Signer) bool {
	der, err := x509.MarshalPKIXPublicKey(key.Public())
	return err == nil && string(der) == string(cert.RawSubjectPublicKeyInfo)
}
