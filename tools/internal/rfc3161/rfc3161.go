// Package rfc3161 reads the fields of an RFC 3161 TimeStampResp that the
// records repeat (status, imprint, serial, genTime, policy), so the tools can
// check that a record describes its token faithfully.
//
// It does not verify the CMS signature or the certificate chain: that is
// `openssl ts -verify`'s job, a tool nobody has to trust us for. Keeping the
// two apart keeps this package to plain encoding/asn1.
package rfc3161

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"
)

var (
	oidSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidTSTInfo    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	// OIDSHA256 is the hash algorithm the records use for imprints.
	OIDSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
)

// Info is what a TimeStampResp says, minus the signature.
type Info struct {
	Status  int // 0 granted, 1 grantedWithMods; anything else carries no token
	Policy  asn1.ObjectIdentifier
	HashAlg asn1.ObjectIdentifier
	Imprint []byte
	Serial  *big.Int
	GenTime time.Time
	Nonce   *big.Int
}

type statusInfo struct {
	Status       int
	StatusString asn1.RawValue  `asn1:"optional"`
	FailInfo     asn1.BitString `asn1:"optional"`
}

type response struct {
	Status statusInfo
	Token  asn1.RawValue `asn1:"optional"`
}

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

type signedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue
	EncapContent     encapContentInfo
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	CRLs             asn1.RawValue `asn1:"optional,tag:1"`
	SignerInfos      asn1.RawValue
}

type encapContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     []byte `asn1:"explicit,tag:0"`
}

type accuracy struct {
	Seconds int `asn1:"optional"`
	Millis  int `asn1:"optional,tag:0"`
	Micros  int `asn1:"optional,tag:1"`
}

type tstInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint struct {
		HashAlgorithm pkix.AlgorithmIdentifier
		HashedMessage []byte
	}
	SerialNumber *big.Int
	GenTime      time.Time     `asn1:"generalized"`
	Accuracy     accuracy      `asn1:"optional"`
	Ordering     bool          `asn1:"optional"`
	Nonce        *big.Int      `asn1:"optional"`
	TSA          asn1.RawValue `asn1:"optional,explicit,tag:0"`
	Extensions   asn1.RawValue `asn1:"optional,tag:1"`
}

// ParseResponse decodes a DER TimeStampResp down to its TSTInfo.
func ParseResponse(der []byte) (*Info, error) {
	var resp response
	if rest, err := asn1.Unmarshal(der, &resp); err != nil {
		return nil, fmt.Errorf("rfc3161: TimeStampResp: %w", err)
	} else if len(rest) != 0 {
		return nil, errors.New("rfc3161: trailing data after TimeStampResp")
	}
	info := &Info{Status: resp.Status.Status}
	if info.Status > 1 || len(resp.Token.FullBytes) == 0 {
		return info, fmt.Errorf("rfc3161: response status %d carries no token", info.Status)
	}

	var ci contentInfo
	if _, err := asn1.Unmarshal(resp.Token.FullBytes, &ci); err != nil {
		return nil, fmt.Errorf("rfc3161: ContentInfo: %w", err)
	}
	if !ci.ContentType.Equal(oidSignedData) {
		return nil, fmt.Errorf("rfc3161: token content type %v is not SignedData", ci.ContentType)
	}
	var sd signedData // ci.Content.Bytes is what the [0] EXPLICIT tag wraps
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return nil, fmt.Errorf("rfc3161: SignedData: %w", err)
	}
	if !sd.EncapContent.ContentType.Equal(oidTSTInfo) {
		return nil, fmt.Errorf("rfc3161: signed content type %v is not TSTInfo", sd.EncapContent.ContentType)
	}
	var tst tstInfo
	if rest, err := asn1.Unmarshal(sd.EncapContent.Content, &tst); err != nil {
		return nil, fmt.Errorf("rfc3161: TSTInfo: %w", err)
	} else if len(rest) != 0 {
		return nil, errors.New("rfc3161: trailing data after TSTInfo")
	}

	info.Policy = tst.Policy
	info.HashAlg = tst.MessageImprint.HashAlgorithm.Algorithm
	info.Imprint = tst.MessageImprint.HashedMessage
	info.Serial = tst.SerialNumber
	info.GenTime = tst.GenTime.UTC()
	info.Nonce = tst.Nonce
	return info, nil
}
