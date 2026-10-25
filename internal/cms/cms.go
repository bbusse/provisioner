package cms

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

var (
	oidData                  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidSignedData            = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidAuthEnvelopedData     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 23}
	oidAttrContentType       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidAttrMessageDigest     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidAttrSigningTime       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	oidSHA1                  = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidSHA224                = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 4}
	oidSHA256                = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384                = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512                = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
	oidECDSAWithSHA256       = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidECDSAWithSHA384       = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidECDSAWithSHA512       = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
	oidRSAEncryption         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidSHA256WithRSA         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSHA384WithRSA         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidSHA512WithRSA         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	oidECPublicKey           = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidStdDHSHA1KDF          = asn1.ObjectIdentifier{1, 3, 133, 16, 840, 63, 0, 2}
	oidStdDHSHA224KDF        = asn1.ObjectIdentifier{1, 3, 132, 1, 11, 0}
	oidStdDHSHA256KDF        = asn1.ObjectIdentifier{1, 3, 132, 1, 11, 1}
	oidStdDHSHA384KDF        = asn1.ObjectIdentifier{1, 3, 132, 1, 11, 2}
	oidStdDHSHA512KDF        = asn1.ObjectIdentifier{1, 3, 132, 1, 11, 3}
	oidAES128Wrap            = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 5}
	oidAES192Wrap            = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 25}
	oidAES256Wrap            = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 45}
	oidAES128GCM             = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 6}
	oidAES192GCM             = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 26}
	oidAES256GCM             = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 46}
	tagContext0Constructed   = cbasn1.Tag(0).ContextSpecific().Constructed()
	tagContext1Constructed   = cbasn1.Tag(1).ContextSpecific().Constructed()
	tagContext2Constructed   = cbasn1.Tag(2).ContextSpecific().Constructed()
	tagContext0              = cbasn1.Tag(0).ContextSpecific()
	errMalformed             = errors.New("cms: malformed structure")
	errUnsupportedContent    = errors.New("cms: unsupported content type")
	errNoMatchingRecipient   = errors.New("cms: not encrypted to this certificate")
	errUnsupportedAlgorithm  = errors.New("cms: unsupported algorithm")
	errMessageDigestMismatch = errors.New("cms: message digest does not match the content")
)

const pemType = "CMS"

func EncodePEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: pemType, Bytes: der})
}

func DecodePEM(data []byte) ([]byte, error) {
	trimmed := bytes.TrimLeft(data, " \t\r\n")
	if !bytes.HasPrefix(trimmed, []byte("-----BEGIN")) {
		return data, nil
	}
	block, _ := pem.Decode(trimmed)
	if block == nil || (block.Type != pemType && block.Type != "PKCS7") {
		return nil, errors.New("cms: not a PEM CMS file")
	}
	return block.Bytes, nil
}

func IsPEM(data []byte) bool {
	line, _, _ := bytes.Cut(data, []byte("\n"))
	return string(bytes.TrimRight(line, "\r")) == "-----BEGIN CMS-----"
}

func contentInfo(contentType asn1.ObjectIdentifier, content []byte) ([]byte, error) {
	b := cryptobyte.NewBuilder(nil)
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(contentType)
		b.AddASN1(tagContext0Constructed, func(b *cryptobyte.Builder) {
			b.AddBytes(content)
		})
	})
	return b.Bytes()
}

func parseContentInfo(der []byte) (asn1.ObjectIdentifier, cryptobyte.String, error) {
	input := cryptobyte.String(der)
	var ci cryptobyte.String
	var contentType asn1.ObjectIdentifier
	var content cryptobyte.String
	if !input.ReadASN1(&ci, cbasn1.SEQUENCE) || !input.Empty() ||
		!ci.ReadASN1ObjectIdentifier(&contentType) ||
		!ci.ReadASN1(&content, tagContext0Constructed) || !ci.Empty() {
		return nil, nil, errMalformed
	}
	return contentType, content, nil
}

func addAlgorithm(b *cryptobyte.Builder, oid asn1.ObjectIdentifier, params func(*cryptobyte.Builder)) {
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(oid)
		if params != nil {
			params(b)
		}
	})
}

func addNull(b *cryptobyte.Builder) {
	b.AddASN1(cbasn1.NULL, func(*cryptobyte.Builder) {})
}

func readAlgorithm(s *cryptobyte.String) (asn1.ObjectIdentifier, cryptobyte.String, error) {
	var alg cryptobyte.String
	var oid asn1.ObjectIdentifier
	if !s.ReadASN1(&alg, cbasn1.SEQUENCE) || !alg.ReadASN1ObjectIdentifier(&oid) {
		return nil, nil, errMalformed
	}
	return oid, alg, nil
}

func addIssuerAndSerial(b *cryptobyte.Builder, cert *x509.Certificate) {
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(cert.RawIssuer)
		b.AddASN1BigInt(cert.SerialNumber)
	})
}

type issuerAndSerial struct {
	issuer []byte
	serial *big.Int
}

func readIssuerAndSerial(s *cryptobyte.String) (issuerAndSerial, error) {
	var ias cryptobyte.String
	var issuer cryptobyte.String
	serial := new(big.Int)
	if !s.ReadASN1(&ias, cbasn1.SEQUENCE) ||
		!ias.ReadASN1Element(&issuer, cbasn1.SEQUENCE) ||
		!ias.ReadASN1Integer(serial) || !ias.Empty() {
		return issuerAndSerial{}, errMalformed
	}
	return issuerAndSerial{issuer: issuer, serial: serial}, nil
}

func (id issuerAndSerial) matches(cert *x509.Certificate) bool {
	return bytes.Equal(id.issuer, cert.RawIssuer) && id.serial.Cmp(cert.SerialNumber) == 0
}
