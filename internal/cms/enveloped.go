package cms

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

const (
	gcmNonceSize = 12
	gcmTagSize   = 16
)

func Encrypt(content []byte, recipients []*x509.Certificate) ([]byte, error) {
	if len(recipients) == 0 {
		return nil, errors.New("cms: no recipients")
	}
	cek := make([]byte, 32)
	nonce := make([]byte, gcmNonceSize)
	if _, err := rand.Read(cek); err != nil {
		return nil, err
	}
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCMWithTagSize(block, gcmTagSize)
	if err != nil {
		return nil, err
	}
	sealed := gcm.Seal(nil, nonce, content, nil)
	ciphertext, tag := sealed[:len(content)], sealed[len(content):]

	var infos [][]byte
	for _, cert := range recipients {
		info, err := recipientInfo(cert, cek)
		if err != nil {
			return nil, err
		}
		infos = append(infos, info)
	}

	b := cryptobyte.NewBuilder(nil)
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(0)
		b.AddASN1(cbasn1.SET, func(b *cryptobyte.Builder) {
			for _, info := range infos {
				b.AddBytes(info)
			}
		})
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(oidData)
			addAlgorithm(b, oidAES256GCM, func(b *cryptobyte.Builder) {
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
					b.AddASN1OctetString(nonce)
					b.AddASN1Int64(gcmTagSize)
				})
			})
			b.AddASN1(tagContext0, func(b *cryptobyte.Builder) {
				b.AddBytes(ciphertext)
			})
		})
		b.AddASN1OctetString(tag)
	})
	authEnveloped, err := b.Bytes()
	if err != nil {
		return nil, err
	}
	return contentInfo(oidAuthEnvelopedData, authEnveloped)
}

func recipientInfo(cert *x509.Certificate, cek []byte) ([]byte, error) {
	switch pub := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		return keyAgreeRecipientInfo(cert, pub, cek)
	case *rsa.PublicKey:
		encrypted, err := rsa.EncryptPKCS1v15(rand.Reader, pub, cek)
		if err != nil {
			return nil, err
		}
		b := cryptobyte.NewBuilder(nil)
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1Int64(0)
			addIssuerAndSerial(b, cert)
			addAlgorithm(b, oidRSAEncryption, addNull)
			b.AddASN1OctetString(encrypted)
		})
		return b.Bytes()
	}
	return nil, fmt.Errorf("cms: cannot encrypt to a %T key", cert.PublicKey)
}

func keyAgreeRecipientInfo(cert *x509.Certificate, pub *ecdsa.PublicKey, cek []byte) ([]byte, error) {
	recipient, err := pub.ECDH()
	if err != nil {
		return nil, err
	}
	ephemeral, err := recipient.Curve().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	shared, err := ephemeral.ECDH(recipient)
	if err != nil {
		return nil, err
	}
	kek, err := x963KDF(crypto.SHA1, shared, oidAES256Wrap, 32)
	if err != nil {
		return nil, err
	}
	wrapped, err := aesWrap(kek, cek)
	if err != nil {
		return nil, err
	}

	b := cryptobyte.NewBuilder(nil)
	b.AddASN1(tagContext1Constructed, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(3)
		b.AddASN1(tagContext0Constructed, func(b *cryptobyte.Builder) {
			b.AddASN1(tagContext1Constructed, func(b *cryptobyte.Builder) {
				addAlgorithm(b, oidECPublicKey, nil)
				b.AddASN1BitString(ephemeral.PublicKey().Bytes())
			})
		})
		addAlgorithm(b, oidStdDHSHA1KDF, func(b *cryptobyte.Builder) {
			addAlgorithm(b, oidAES256Wrap, nil)
		})
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				addIssuerAndSerial(b, cert)
				b.AddASN1OctetString(wrapped)
			})
		})
	})
	return b.Bytes()
}

func Decrypt(der []byte, cert *x509.Certificate, key crypto.PrivateKey) ([]byte, error) {
	contentType, content, err := parseContentInfo(der)
	if err != nil {
		return nil, err
	}
	if !contentType.Equal(oidAuthEnvelopedData) {
		return nil, errUnsupportedContent
	}

	var aed cryptobyte.String
	var version int64
	if !content.ReadASN1(&aed, cbasn1.SEQUENCE) || !aed.ReadASN1Integer(&version) {
		return nil, errMalformed
	}
	var skipped cryptobyte.String
	var present bool
	if !aed.ReadOptionalASN1(&skipped, &present, tagContext0Constructed) {
		return nil, errMalformed
	}
	var infos cryptobyte.String
	if !aed.ReadASN1(&infos, cbasn1.SET) {
		return nil, errMalformed
	}

	var cek []byte
	for !infos.Empty() && cek == nil {
		var info cryptobyte.String
		var tag cbasn1.Tag
		if !infos.ReadAnyASN1Element(&info, &tag) {
			return nil, errMalformed
		}
		switch tag {
		case cbasn1.SEQUENCE:
			cek, err = decryptKeyTransport(info, cert, key)
		case tagContext1Constructed:
			cek, err = decryptKeyAgreement(info, cert, key)
		default:
			continue
		}
		if err != nil {
			return nil, err
		}
	}
	if cek == nil {
		return nil, errNoMatchingRecipient
	}

	var eci cryptobyte.String
	var eContentType asn1.ObjectIdentifier
	if !aed.ReadASN1(&eci, cbasn1.SEQUENCE) || !eci.ReadASN1ObjectIdentifier(&eContentType) {
		return nil, errMalformed
	}
	alg, params, err := readAlgorithm(&eci)
	if err != nil {
		return nil, err
	}
	var keySize int
	switch {
	case alg.Equal(oidAES128GCM):
		keySize = 16
	case alg.Equal(oidAES192GCM):
		keySize = 24
	case alg.Equal(oidAES256GCM):
		keySize = 32
	default:
		return nil, fmt.Errorf("%w: content encryption %v", errUnsupportedAlgorithm, alg)
	}
	if len(cek) != keySize {
		return nil, errors.New("cms: content key has the wrong size")
	}
	var gcmParams cryptobyte.String
	var nonce []byte
	tagSize := int64(12)
	if !params.ReadASN1(&gcmParams, cbasn1.SEQUENCE) || !gcmParams.ReadASN1Bytes(&nonce, cbasn1.OCTET_STRING) {
		return nil, errMalformed
	}
	if !gcmParams.Empty() && !gcmParams.ReadASN1Integer(&tagSize) {
		return nil, errMalformed
	}

	var ciphertext []byte
	if eci.PeekASN1Tag(tagContext0) {
		if !eci.ReadASN1Bytes(&ciphertext, tagContext0) {
			return nil, errMalformed
		}
	} else {
		var chunks cryptobyte.String
		if !eci.ReadASN1(&chunks, tagContext0Constructed) {
			return nil, errors.New("cms: no encrypted content")
		}
		for !chunks.Empty() {
			part, err := readOctets(&chunks)
			if err != nil {
				return nil, err
			}
			ciphertext = append(ciphertext, part...)
		}
	}
	var authAttrs cryptobyte.String
	if !aed.ReadOptionalASN1(&authAttrs, &present, tagContext1Constructed) {
		return nil, errMalformed
	}
	if present {
		return nil, errors.New("cms: authenticated attributes are not supported")
	}
	var mac []byte
	if !aed.ReadASN1Bytes(&mac, cbasn1.OCTET_STRING) || int64(len(mac)) != tagSize {
		return nil, errMalformed
	}

	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, err
	}
	var gcm cipher.AEAD
	switch {
	case len(nonce) == gcmNonceSize:
		gcm, err = cipher.NewGCMWithTagSize(block, int(tagSize))
	case tagSize == gcmTagSize:
		gcm, err = cipher.NewGCMWithNonceSize(block, len(nonce))
	default:
		err = errors.New("cms: unsupported GCM nonce and tag sizes")
	}
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, nonce, append(ciphertext, mac...), nil)
	if err != nil {
		return nil, errors.New("cms: the content does not authenticate")
	}
	return plain, nil
}

func decryptKeyTransport(info cryptobyte.String, cert *x509.Certificate, key crypto.PrivateKey) ([]byte, error) {
	var ktri cryptobyte.String
	var version int64
	if !info.ReadASN1(&ktri, cbasn1.SEQUENCE) || !ktri.ReadASN1Integer(&version) {
		return nil, errMalformed
	}
	if !ktri.PeekASN1Tag(cbasn1.SEQUENCE) {
		return nil, nil
	}
	rid, err := readIssuerAndSerial(&ktri)
	if err != nil {
		return nil, err
	}
	if !rid.matches(cert) {
		return nil, nil
	}
	alg, _, err := readAlgorithm(&ktri)
	if err != nil {
		return nil, err
	}
	var encrypted []byte
	if !ktri.ReadASN1Bytes(&encrypted, cbasn1.OCTET_STRING) {
		return nil, errMalformed
	}
	priv, ok := key.(*rsa.PrivateKey)
	if !ok || !alg.Equal(oidRSAEncryption) {
		return nil, fmt.Errorf("%w: key transport %v", errUnsupportedAlgorithm, alg)
	}
	return rsa.DecryptPKCS1v15(nil, priv, encrypted)
}

func decryptKeyAgreement(info cryptobyte.String, cert *x509.Certificate, key crypto.PrivateKey) ([]byte, error) {
	var kari cryptobyte.String
	var version int64
	if !info.ReadASN1(&kari, tagContext1Constructed) || !kari.ReadASN1Integer(&version) {
		return nil, errMalformed
	}
	var originator cryptobyte.String
	var originatorKey cryptobyte.String
	if !kari.ReadASN1(&originator, tagContext0Constructed) {
		return nil, errMalformed
	}
	if !originator.ReadASN1(&originatorKey, tagContext1Constructed) {
		return nil, errors.New("cms: only ephemeral originator keys are supported")
	}
	if _, _, err := readAlgorithm(&originatorKey); err != nil {
		return nil, err
	}
	var point asn1.BitString
	if !originatorKey.ReadASN1BitString(&point) {
		return nil, errMalformed
	}
	var ukm cryptobyte.String
	var present bool
	if !kari.ReadOptionalASN1(&ukm, &present, tagContext1Constructed) {
		return nil, errMalformed
	}
	var ukmBytes []byte
	if present && !ukm.ReadASN1Bytes(&ukmBytes, cbasn1.OCTET_STRING) {
		return nil, errMalformed
	}
	kdfAlg, kdfParams, err := readAlgorithm(&kari)
	if err != nil {
		return nil, err
	}
	wrapAlg, _, err := readAlgorithm(&kdfParams)
	if err != nil {
		return nil, err
	}
	var keks cryptobyte.String
	if !kari.ReadASN1(&keks, cbasn1.SEQUENCE) {
		return nil, errMalformed
	}

	var wrapped []byte
	for !keks.Empty() {
		var rek cryptobyte.String
		if !keks.ReadASN1(&rek, cbasn1.SEQUENCE) {
			return nil, errMalformed
		}
		if !rek.PeekASN1Tag(cbasn1.SEQUENCE) {
			continue
		}
		rid, err := readIssuerAndSerial(&rek)
		if err != nil {
			return nil, err
		}
		var encrypted []byte
		if !rek.ReadASN1Bytes(&encrypted, cbasn1.OCTET_STRING) {
			return nil, errMalformed
		}
		if rid.matches(cert) {
			wrapped = encrypted
			break
		}
	}
	if wrapped == nil {
		return nil, nil
	}

	priv, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("cms: a key agreement recipient needs an EC key, not %T", key)
	}
	ecdhKey, err := priv.ECDH()
	if err != nil {
		return nil, err
	}
	peer, err := ecdhKey.Curve().NewPublicKey(point.RightAlign())
	if err != nil {
		return nil, err
	}
	shared, err := ecdhKey.ECDH(peer)
	if err != nil {
		return nil, err
	}

	var kdfHash crypto.Hash
	switch {
	case kdfAlg.Equal(oidStdDHSHA1KDF):
		kdfHash = crypto.SHA1
	case kdfAlg.Equal(oidStdDHSHA224KDF):
		kdfHash = crypto.SHA224
	case kdfAlg.Equal(oidStdDHSHA256KDF):
		kdfHash = crypto.SHA256
	case kdfAlg.Equal(oidStdDHSHA384KDF):
		kdfHash = crypto.SHA384
	case kdfAlg.Equal(oidStdDHSHA512KDF):
		kdfHash = crypto.SHA512
	default:
		return nil, fmt.Errorf("%w: key agreement %v", errUnsupportedAlgorithm, kdfAlg)
	}
	var kekSize int
	switch {
	case wrapAlg.Equal(oidAES128Wrap):
		kekSize = 16
	case wrapAlg.Equal(oidAES192Wrap):
		kekSize = 24
	case wrapAlg.Equal(oidAES256Wrap):
		kekSize = 32
	default:
		return nil, fmt.Errorf("%w: key wrap %v", errUnsupportedAlgorithm, wrapAlg)
	}
	kek, err := x963KDFWithUKM(kdfHash, shared, wrapAlg, kekSize, ukmBytes)
	if err != nil {
		return nil, err
	}
	return aesUnwrap(kek, wrapped)
}

func x963KDF(h crypto.Hash, shared []byte, wrapAlg asn1.ObjectIdentifier, size int) ([]byte, error) {
	return x963KDFWithUKM(h, shared, wrapAlg, size, nil)
}

func x963KDFWithUKM(h crypto.Hash, shared []byte, wrapAlg asn1.ObjectIdentifier, size int, ukm []byte) ([]byte, error) {
	b := cryptobyte.NewBuilder(nil)
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		addAlgorithm(b, wrapAlg, nil)
		if ukm != nil {
			b.AddASN1(tagContext0Constructed, func(b *cryptobyte.Builder) {
				b.AddASN1OctetString(ukm)
			})
		}
		b.AddASN1(tagContext2Constructed, func(b *cryptobyte.Builder) {
			var bits [4]byte
			binary.BigEndian.PutUint32(bits[:], uint32(size*8))
			b.AddASN1OctetString(bits[:])
		})
	})
	sharedInfo, err := b.Bytes()
	if err != nil {
		return nil, err
	}

	var out []byte
	var counter [4]byte
	for i := uint32(1); len(out) < size; i++ {
		binary.BigEndian.PutUint32(counter[:], i)
		var d hash.Hash = h.New()
		d.Write(shared)
		d.Write(counter[:])
		d.Write(sharedInfo)
		out = d.Sum(out)
	}
	return out[:size], nil
}

var keyWrapIV = []byte{0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6}

func aesWrap(kek, key []byte) ([]byte, error) {
	if len(key)%8 != 0 || len(key) < 16 {
		return nil, errors.New("cms: cannot wrap a key of this size")
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	n := len(key) / 8
	a := append([]byte(nil), keyWrapIV...)
	r := append([]byte(nil), key...)
	buf := make([]byte, 16)
	for j := 0; j < 6; j++ {
		for i := 1; i <= n; i++ {
			copy(buf, a)
			copy(buf[8:], r[(i-1)*8:i*8])
			block.Encrypt(buf, buf)
			t := uint64(n*j + i)
			binary.BigEndian.PutUint64(a, binary.BigEndian.Uint64(buf[:8])^t)
			copy(r[(i-1)*8:i*8], buf[8:])
		}
	}
	return append(a, r...), nil
}

func aesUnwrap(kek, wrapped []byte) ([]byte, error) {
	if len(wrapped)%8 != 0 || len(wrapped) < 24 {
		return nil, errors.New("cms: wrapped key has the wrong size")
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	n := len(wrapped)/8 - 1
	a := append([]byte(nil), wrapped[:8]...)
	r := append([]byte(nil), wrapped[8:]...)
	buf := make([]byte, 16)
	for j := 5; j >= 0; j-- {
		for i := n; i >= 1; i-- {
			t := uint64(n*j + i)
			binary.BigEndian.PutUint64(buf, binary.BigEndian.Uint64(a)^t)
			copy(buf[8:], r[(i-1)*8:i*8])
			block.Decrypt(buf, buf)
			copy(a, buf[:8])
			copy(r[(i-1)*8:i*8], buf[8:])
		}
	}
	if subtle.ConstantTimeCompare(a, keyWrapIV) != 1 {
		return nil, errors.New("cms: the content key does not unwrap with this key")
	}
	return r, nil
}
