package cms

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"sort"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

func Sign(content []byte, cert *x509.Certificate, key crypto.Signer) ([]byte, error) {
	digest := crypto.SHA256.New()
	digest.Write(content)

	attrs, err := signedAttributes(digest.Sum(nil), time.Now())
	if err != nil {
		return nil, err
	}
	attrsDigest := crypto.SHA256.New()
	attrsDigest.Write(attrs)
	var attrsContent cryptobyte.String
	attrsSet := cryptobyte.String(attrs)
	if !attrsSet.ReadASN1(&attrsContent, cbasn1.SET) {
		return nil, errMalformed
	}

	var sigAlg asn1.ObjectIdentifier
	var sigNull bool
	switch key.Public().(type) {
	case *ecdsa.PublicKey:
		sigAlg = oidECDSAWithSHA256
	case *rsa.PublicKey:
		sigAlg = oidRSAEncryption
		sigNull = true
	default:
		return nil, fmt.Errorf("cms: cannot sign with a %T key", key.Public())
	}
	signature, err := key.Sign(rand.Reader, attrsDigest.Sum(nil), crypto.SHA256)
	if err != nil {
		return nil, err
	}

	b := cryptobyte.NewBuilder(nil)
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(1)
		b.AddASN1(cbasn1.SET, func(b *cryptobyte.Builder) {
			addAlgorithm(b, oidSHA256, nil)
		})
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(oidData)
			b.AddASN1(tagContext0Constructed, func(b *cryptobyte.Builder) {
				b.AddASN1OctetString(content)
			})
		})
		b.AddASN1(tagContext0Constructed, func(b *cryptobyte.Builder) {
			b.AddBytes(cert.Raw)
		})
		b.AddASN1(cbasn1.SET, func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1Int64(1)
				addIssuerAndSerial(b, cert)
				addAlgorithm(b, oidSHA256, nil)
				b.AddASN1(tagContext0Constructed, func(b *cryptobyte.Builder) {
					b.AddBytes(attrsContent)
				})
				if sigNull {
					addAlgorithm(b, sigAlg, addNull)
				} else {
					addAlgorithm(b, sigAlg, nil)
				}
				b.AddASN1OctetString(signature)
			})
		})
	})
	signedData, err := b.Bytes()
	if err != nil {
		return nil, err
	}
	return contentInfo(oidSignedData, signedData)
}

func signedAttributes(messageDigest []byte, now time.Time) ([]byte, error) {
	var attrs [][]byte
	for _, attr := range []struct {
		oid   asn1.ObjectIdentifier
		value func(*cryptobyte.Builder)
	}{
		{oidAttrContentType, func(b *cryptobyte.Builder) { b.AddASN1ObjectIdentifier(oidData) }},
		{oidAttrSigningTime, func(b *cryptobyte.Builder) { b.AddASN1UTCTime(now.UTC().Truncate(time.Second)) }},
		{oidAttrMessageDigest, func(b *cryptobyte.Builder) { b.AddASN1OctetString(messageDigest) }},
	} {
		b := cryptobyte.NewBuilder(nil)
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(attr.oid)
			b.AddASN1(cbasn1.SET, attr.value)
		})
		der, err := b.Bytes()
		if err != nil {
			return nil, err
		}
		attrs = append(attrs, der)
	}
	sort.Slice(attrs, func(i, j int) bool { return bytes.Compare(attrs[i], attrs[j]) < 0 })

	b := cryptobyte.NewBuilder(nil)
	b.AddASN1(cbasn1.SET, func(b *cryptobyte.Builder) {
		for _, attr := range attrs {
			b.AddBytes(attr)
		}
	})
	return b.Bytes()
}

type signedData struct {
	content []byte
	certs   []*x509.Certificate
	signers []signerInfo
}

type signerInfo struct {
	sid          issuerAndSerial
	digestAlg    asn1.ObjectIdentifier
	signedAttrs  []byte
	signatureAlg asn1.ObjectIdentifier
	signature    []byte
}

func parseSignedData(der []byte) (*signedData, error) {
	contentType, content, err := parseContentInfo(der)
	if err != nil {
		return nil, err
	}
	if !contentType.Equal(oidSignedData) {
		return nil, errUnsupportedContent
	}

	var sd cryptobyte.String
	var version int64
	var digestAlgs cryptobyte.String
	var encap cryptobyte.String
	var eContentType asn1.ObjectIdentifier
	if !content.ReadASN1(&sd, cbasn1.SEQUENCE) ||
		!sd.ReadASN1Integer(&version) ||
		!sd.ReadASN1(&digestAlgs, cbasn1.SET) ||
		!sd.ReadASN1(&encap, cbasn1.SEQUENCE) ||
		!encap.ReadASN1ObjectIdentifier(&eContentType) {
		return nil, errMalformed
	}
	if !eContentType.Equal(oidData) {
		return nil, errUnsupportedContent
	}
	var eContent cryptobyte.String
	var present bool
	if !encap.ReadOptionalASN1(&eContent, &present, tagContext0Constructed) || !present {
		return nil, errors.New("cms: the signed file carries no content")
	}
	out := &signedData{}
	if out.content, err = readOctets(&eContent); err != nil {
		return nil, err
	}

	var certs cryptobyte.String
	if !sd.ReadOptionalASN1(&certs, &present, tagContext0Constructed) {
		return nil, errMalformed
	}
	for present && !certs.Empty() {
		var raw cryptobyte.String
		var tag cbasn1.Tag
		if !certs.ReadAnyASN1Element(&raw, &tag) {
			return nil, errMalformed
		}
		if tag != cbasn1.SEQUENCE {
			continue
		}
		cert, err := x509.ParseCertificate(raw)
		if err != nil {
			return nil, err
		}
		out.certs = append(out.certs, cert)
	}
	var crls cryptobyte.String
	if !sd.ReadOptionalASN1(&crls, &present, tagContext1Constructed) {
		return nil, errMalformed
	}

	var infos cryptobyte.String
	if !sd.ReadASN1(&infos, cbasn1.SET) {
		return nil, errMalformed
	}
	for !infos.Empty() {
		var si cryptobyte.String
		var siVersion int64
		if !infos.ReadASN1(&si, cbasn1.SEQUENCE) || !si.ReadASN1Integer(&siVersion) {
			return nil, errMalformed
		}
		if !si.PeekASN1Tag(cbasn1.SEQUENCE) {
			return nil, errors.New("cms: signers named by key identifier are not supported")
		}
		var info signerInfo
		if info.sid, err = readIssuerAndSerial(&si); err != nil {
			return nil, err
		}
		if info.digestAlg, _, err = readAlgorithm(&si); err != nil {
			return nil, err
		}
		if si.PeekASN1Tag(tagContext0Constructed) {
			var attrs cryptobyte.String
			if !si.ReadASN1Element(&attrs, tagContext0Constructed) {
				return nil, errMalformed
			}
			info.signedAttrs = append([]byte{0x31}, attrs[1:]...)
		}
		if info.signatureAlg, _, err = readAlgorithm(&si); err != nil {
			return nil, err
		}
		if !si.ReadASN1Bytes(&info.signature, cbasn1.OCTET_STRING) {
			return nil, errMalformed
		}
		out.signers = append(out.signers, info)
	}
	return out, nil
}

func readOctets(s *cryptobyte.String) ([]byte, error) {
	if s.PeekASN1Tag(cbasn1.OCTET_STRING) {
		var octets []byte
		if !s.ReadASN1Bytes(&octets, cbasn1.OCTET_STRING) {
			return nil, errMalformed
		}
		return octets, nil
	}
	var chunks cryptobyte.String
	if !s.ReadASN1(&chunks, cbasn1.OCTET_STRING.Constructed()) {
		return nil, errMalformed
	}
	var out []byte
	for !chunks.Empty() {
		part, err := readOctets(&chunks)
		if err != nil {
			return nil, err
		}
		out = append(out, part...)
	}
	return out, nil
}

func hashFor(oid asn1.ObjectIdentifier) (crypto.Hash, error) {
	switch {
	case oid.Equal(oidSHA256):
		return crypto.SHA256, nil
	case oid.Equal(oidSHA384):
		return crypto.SHA384, nil
	case oid.Equal(oidSHA512):
		return crypto.SHA512, nil
	}
	return 0, fmt.Errorf("%w: digest %v", errUnsupportedAlgorithm, oid)
}

func (sd *signedData) signerCert(info signerInfo) (*x509.Certificate, error) {
	for _, cert := range sd.certs {
		if info.sid.matches(cert) {
			return cert, nil
		}
	}
	return nil, errors.New("cms: the signer's certificate is not in the file")
}

func (info signerInfo) verify(cert *x509.Certificate, content []byte) error {
	hash, err := hashFor(info.digestAlg)
	if err != nil {
		return err
	}
	h := hash.New()
	h.Write(content)
	signed := h.Sum(nil)

	if info.signedAttrs != nil {
		digest, err := messageDigest(info.signedAttrs)
		if err != nil {
			return err
		}
		if !bytes.Equal(digest, signed) {
			return errMessageDigestMismatch
		}
		h = hash.New()
		h.Write(info.signedAttrs)
		signed = h.Sum(nil)
	}

	switch pub := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		switch {
		case info.signatureAlg.Equal(oidECDSAWithSHA256), info.signatureAlg.Equal(oidECDSAWithSHA384),
			info.signatureAlg.Equal(oidECDSAWithSHA512), info.signatureAlg.Equal(oidECPublicKey):
		default:
			return fmt.Errorf("%w: signature %v", errUnsupportedAlgorithm, info.signatureAlg)
		}
		if !ecdsa.VerifyASN1(pub, signed, info.signature) {
			return errors.New("cms: bad signature")
		}
	case *rsa.PublicKey:
		switch {
		case info.signatureAlg.Equal(oidRSAEncryption), info.signatureAlg.Equal(oidSHA256WithRSA),
			info.signatureAlg.Equal(oidSHA384WithRSA), info.signatureAlg.Equal(oidSHA512WithRSA):
		default:
			return fmt.Errorf("%w: signature %v", errUnsupportedAlgorithm, info.signatureAlg)
		}
		if err := rsa.VerifyPKCS1v15(pub, hash, signed, info.signature); err != nil {
			return errors.New("cms: bad signature")
		}
	default:
		return fmt.Errorf("cms: cannot verify with a %T key", cert.PublicKey)
	}
	return nil
}

func messageDigest(attrs []byte) ([]byte, error) {
	s := cryptobyte.String(attrs)
	var set cryptobyte.String
	if !s.ReadASN1(&set, cbasn1.SET) {
		return nil, errMalformed
	}
	var digest []byte
	for !set.Empty() {
		var attr cryptobyte.String
		var oid asn1.ObjectIdentifier
		var values cryptobyte.String
		if !set.ReadASN1(&attr, cbasn1.SEQUENCE) || !attr.ReadASN1ObjectIdentifier(&oid) ||
			!attr.ReadASN1(&values, cbasn1.SET) {
			return nil, errMalformed
		}
		if oid.Equal(oidAttrMessageDigest) {
			if digest != nil || !values.ReadASN1Bytes(&digest, cbasn1.OCTET_STRING) || !values.Empty() {
				return nil, errMalformed
			}
		}
	}
	if digest == nil {
		return nil, errors.New("cms: signed attributes lack the message digest")
	}
	return digest, nil
}

func Verify(der []byte, roots *x509.CertPool, now time.Time) ([]byte, *x509.Certificate, error) {
	sd, cert, err := verifySignature(der)
	if err != nil {
		return nil, nil, err
	}
	intermediates := x509.NewCertPool()
	for _, c := range sd.certs {
		if c != cert {
			intermediates.AddCert(c)
		}
	}
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, nil, fmt.Errorf("cms: the signer does not chain to the CA: %w", err)
	}
	return sd.content, cert, nil
}

func VerifySignature(der []byte) ([]byte, *x509.Certificate, error) {
	sd, cert, err := verifySignature(der)
	if err != nil {
		return nil, nil, err
	}
	return sd.content, cert, nil
}

func verifySignature(der []byte) (*signedData, *x509.Certificate, error) {
	sd, err := parseSignedData(der)
	if err != nil {
		return nil, nil, err
	}
	if len(sd.signers) != 1 {
		return nil, nil, fmt.Errorf("cms: %d signers, want one", len(sd.signers))
	}
	cert, err := sd.signerCert(sd.signers[0])
	if err != nil {
		return nil, nil, err
	}
	if err := sd.signers[0].verify(cert, sd.content); err != nil {
		return nil, nil, err
	}
	return sd, cert, nil
}
