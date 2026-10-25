package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"slices"
	"time"
)

// exampleTSA is a stand-in time-stamping authority: an example root CA and a
// TSA certificate under it, both derived from fixed seeds. It produces RFC
// 3161 responses for any genTime, which openssl cannot do (it always stamps
// the current time), and which the example timeline needs.
type exampleTSA struct {
	provider, url string
	root, cert    *x509.Certificate
	key           *ecdsa.PrivateKey
	policy        asn1.ObjectIdentifier
	serial        int64
}

var (
	oidSignedData      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidTSTInfo         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	oidContentType     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigest   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidSigningCertV2   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}
	oidSHA256          = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidExtKeyUsage     = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidKPTimeStamping  = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
)

func newExampleTSA(provider, url, label string, policy asn1.ObjectIdentifier) (*exampleTSA, error) {
	notBefore := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := time.Date(2036, 1, 1, 0, 0, 0, 0, time.UTC)
	rootKey := p256Key("example tsa root: " + provider)
	tsaKey := p256Key("example tsa signer: " + provider)
	org := []string{"diagnos audit examples"}

	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: label + " Root CA (example only - not a real CA)", Organization: org},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, err := x509.CreateCertificate(zeroReader{}, rootTmpl, rootTmpl, &rootKey.PublicKey, deterministic{rootKey})
	if err != nil {
		return nil, err
	}
	root, _ := x509.ParseCertificate(rootDER)

	// RFC 3161 section 2.3: the TSA certificate carries exactly one extended
	// key usage, timeStamping, in a critical extension. crypto/x509 writes
	// ExtKeyUsage as non-critical, so the extension is spelled out here.
	eku, _ := asn1.Marshal([]asn1.ObjectIdentifier{oidKPTimeStamping})
	tsaTmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(2),
		Subject:         pkix.Name{CommonName: label + " (example only - not a real TSA)", Organization: org},
		NotBefore:       notBefore,
		NotAfter:        notAfter,
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{{Id: oidExtKeyUsage, Critical: true, Value: eku}},
	}
	certDER, err := x509.CreateCertificate(zeroReader{}, tsaTmpl, root, &tsaKey.PublicKey, deterministic{rootKey})
	if err != nil {
		return nil, err
	}
	cert, _ := x509.ParseCertificate(certDER)
	return &exampleTSA{provider: provider, url: url, root: root, cert: cert, key: tsaKey, policy: policy, serial: 4096}, nil
}

// chainPEM is what keys/tsa/<provider>.pem holds: the CA chain to trust.
func (t *exampleTSA) chainPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: t.root.Raw})
}

type tstInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint messageImprint
	SerialNumber   *big.Int
	GenTime        time.Time `asn1:"generalized"`
	Accuracy       accuracy
	Nonce          *big.Int
}

type messageImprint struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	HashedMessage []byte
}

type accuracy struct {
	Seconds int
}

type attribute struct {
	Type   asn1.ObjectIdentifier
	Values []asn1.RawValue `asn1:"set"`
}

type issuerAndSerial struct {
	Issuer asn1.RawValue
	Serial *big.Int
}

type signerInfo struct {
	Version            int
	SID                issuerAndSerial
	DigestAlgorithm    pkix.AlgorithmIdentifier
	SignedAttrs        asn1.RawValue
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
}

type signedData struct {
	Version          int
	DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
	EncapContentInfo struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue
	}
	Certificates asn1.RawValue
	SignerInfos  []signerInfo `asn1:"set"`
}

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue
}

type timeStampResp struct {
	Status struct{ Status int }
	Token  contentInfo
}

// stamp returns a granted TimeStampResp (DER) for a SHA-256 imprint.
func (t *exampleTSA) stamp(imprint []byte, genTime time.Time, nonce *big.Int) (der []byte, serial *big.Int, err error) {
	t.serial++
	serial = big.NewInt(t.serial)
	sha256Alg := pkix.AlgorithmIdentifier{Algorithm: oidSHA256}
	tst, err := asn1.Marshal(tstInfo{
		Version:        1,
		Policy:         t.policy,
		MessageImprint: messageImprint{sha256Alg, imprint},
		SerialNumber:   serial,
		GenTime:        genTime.UTC(),
		Accuracy:       accuracy{Seconds: 1},
		Nonce:          nonce,
	})
	if err != nil {
		return nil, nil, err
	}

	// Signed attributes (RFC 5652 section 5.3): content type, message digest
	// and the ESS signing-certificate-v2 that binds the TSA certificate.
	certHash := sha256.Sum256(t.cert.Raw)
	tstHash := sha256.Sum256(tst)
	attrs, err := derSet(
		attr(oidContentType, oidTSTInfo),
		attr(oidMessageDigest, tstHash[:]),
		// SigningCertificateV2 { certs { ESSCertIDv2 { certHash } } }; the
		// hash algorithm is the DEFAULT (SHA-256), so DER omits it.
		attr(oidSigningCertV2, struct{ Certs []struct{ CertHash []byte } }{[]struct{ CertHash []byte }{{certHash[:]}}}),
	)
	if err != nil {
		return nil, nil, err
	}
	toSign := sha256.Sum256(append([]byte{0x31}, attrs[1:]...)) // the SET OF form is what gets signed
	sig, err := t.key.Sign(nil, toSign[:], crypto.SHA256)       // nil rand: RFC 6979, deterministic
	if err != nil {
		return nil, nil, err
	}

	var sd signedData
	sd.Version = 3
	sd.DigestAlgorithms = []pkix.AlgorithmIdentifier{sha256Alg}
	sd.EncapContentInfo.ContentType = oidTSTInfo
	octets, _ := asn1.Marshal(tst)
	sd.EncapContentInfo.Content = explicit(0, octets)
	sd.Certificates = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: t.cert.Raw}
	sd.SignerInfos = []signerInfo{{
		Version:            1,
		SID:                issuerAndSerial{asn1.RawValue{FullBytes: t.cert.RawIssuer}, t.cert.SerialNumber},
		DigestAlgorithm:    sha256Alg,
		SignedAttrs:        asn1.RawValue{FullBytes: attrs},
		SignatureAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidECDSAWithSHA256},
		Signature:          sig,
	}}
	sdDER, err := asn1.Marshal(sd)
	if err != nil {
		return nil, nil, err
	}
	var resp timeStampResp
	resp.Token = contentInfo{ContentType: oidSignedData, Content: explicit(0, sdDER)}
	der, err = asn1.Marshal(resp)
	return der, serial, err
}

func attr(oid asn1.ObjectIdentifier, value any) attribute {
	v, err := asn1.Marshal(value)
	if err != nil {
		panic(fmt.Sprintf("genexamples: attribute %v: %v", oid, err))
	}
	return attribute{Type: oid, Values: []asn1.RawValue{{FullBytes: v}}}
}

// derSet encodes attributes as the [0] IMPLICIT SET OF of signedAttrs, with
// the elements in DER order (sorted by their encodings).
func derSet(attrs ...attribute) ([]byte, error) {
	var elems [][]byte
	for _, a := range attrs {
		b, err := asn1.Marshal(a)
		if err != nil {
			return nil, err
		}
		elems = append(elems, b)
	}
	slices.SortFunc(elems, bytes.Compare)
	return asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: bytes.Join(elems, nil)})
}

func explicit(tag int, inner []byte) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: tag, IsCompound: true, Bytes: inner}
}

// deterministic signs with RFC 6979 nonces so that regenerating the
// examples reproduces them byte for byte.
type deterministic struct{ *ecdsa.PrivateKey }

func (d deterministic) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return d.PrivateKey.Sign(nil, digest, opts)
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}
