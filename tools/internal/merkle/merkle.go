// Package merkle holds the RFC 6962/9162 Merkle tree hashing that
// transparency logs use, the verification of consistency proofs, and the
// construction of a consistency proof from the node hashes of a log.
//
// It is deliberately small: the witness itself uses transparency-dev/merkle,
// and this independent implementation exists so that anyone can check the
// witness's work with nothing but the Go standard library.
package merkle

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/bits"
)

// Hash is a SHA-256 tree hash.
type Hash = [sha256.Size]byte

// HashChildren returns the RFC 6962 interior node hash SHA-256(0x01 || l || r).
func HashChildren(l, r Hash) Hash {
	var buf [1 + 2*sha256.Size]byte
	buf[0] = 0x01
	copy(buf[1:], l[:])
	copy(buf[1+sha256.Size:], r[:])
	return sha256.Sum256(buf[:])
}

// HashLeaf returns the RFC 6962 leaf hash SHA-256(0x00 || data).
func HashLeaf(data []byte) Hash {
	return sha256.Sum256(append([]byte{0x00}, data...))
}

// EmptyRoot is the root hash of the empty tree, SHA-256 of nothing.
var EmptyRoot = sha256.Sum256(nil)

// ErrInconsistent means a consistency proof does not connect the two roots.
var ErrInconsistent = errors.New("merkle: consistency proof does not verify")

// VerifyConsistency checks an RFC 9162 section 2.1.4.2 consistency proof
// that the tree of size1 with root1 is a prefix of the tree of size2 with
// root2.
func VerifyConsistency(size1, size2 uint64, root1, root2 Hash, proof []Hash) error {
	switch {
	case size1 > size2:
		return fmt.Errorf("merkle: size %d is larger than size %d", size1, size2)
	case size1 == size2:
		if len(proof) != 0 {
			return fmt.Errorf("%w: proof between equal sizes must be empty", ErrInconsistent)
		}
		if root1 != root2 {
			return fmt.Errorf("%w: equal sizes with different roots", ErrInconsistent)
		}
		return nil
	case size1 == 0:
		// Every tree extends the empty tree.
		if len(proof) != 0 {
			return fmt.Errorf("%w: proof from the empty tree must be empty", ErrInconsistent)
		}
		return nil
	case len(proof) == 0:
		return fmt.Errorf("%w: empty proof", ErrInconsistent)
	}

	// When size1 is a power of two the old root is itself a node of the new
	// tree, and the proof omits it.
	if bits.OnesCount64(size1) == 1 {
		proof = append([]Hash{root1}, proof...)
	}

	fn, sn := size1-1, size2-1
	for fn&1 == 1 {
		fn >>= 1
		sn >>= 1
	}
	fr, sr := proof[0], proof[0]
	for _, c := range proof[1:] {
		if sn == 0 {
			return fmt.Errorf("%w: proof is too long", ErrInconsistent)
		}
		if fn&1 == 1 || fn == sn {
			fr = HashChildren(c, fr)
			sr = HashChildren(c, sr)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			sr = HashChildren(sr, c)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 {
		return fmt.Errorf("%w: proof is too short", ErrInconsistent)
	}
	if !bytes.Equal(fr[:], root1[:]) || !bytes.Equal(sr[:], root2[:]) {
		return fmt.Errorf("%w: computed roots do not match", ErrInconsistent)
	}
	return nil
}
