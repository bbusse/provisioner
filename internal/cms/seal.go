package cms

import (
	"crypto"
	"crypto/x509"
	"errors"
	"time"
)

const SignerCN = "cfg-provision"

var ErrNotSigner = errors.New("cms: not signed by " + SignerCN)

func Seal(content []byte, signerCert *x509.Certificate, signerKey crypto.Signer, recipients ...*x509.Certificate) ([]byte, error) {
	signed, err := Sign(content, signerCert, signerKey)
	if err != nil {
		return nil, err
	}
	enveloped, err := Encrypt(signed, recipients)
	if err != nil {
		return nil, err
	}
	return EncodePEM(enveloped), nil
}

func Open(sealed []byte, cert *x509.Certificate, key crypto.PrivateKey, roots *x509.CertPool, now time.Time) ([]byte, *x509.Certificate, error) {
	der, err := DecodePEM(sealed)
	if err != nil {
		return nil, nil, err
	}
	signed, err := Decrypt(der, cert, key)
	if err != nil {
		return nil, nil, err
	}
	if roots == nil {
		return VerifySignature(signed)
	}
	content, signer, err := Verify(signed, roots, now)
	if err != nil {
		return nil, nil, err
	}
	if signer.Subject.String() != "CN="+SignerCN {
		return nil, signer, ErrNotSigner
	}
	return content, signer, nil
}
