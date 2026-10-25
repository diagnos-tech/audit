package merkle

import (
	"fmt"
	"math/bits"
)

// NodeReader returns the hash of a perfect subtree: the node at level that
// covers leaves [index<<level, (index+1)<<level). Level 0 is the leaf hashes.
type NodeReader interface {
	Node(level uint, index uint64) (Hash, error)
}

// Root computes the root hash of the tree of the given size.
func Root(size uint64, r NodeReader) (Hash, error) {
	if size == 0 {
		return EmptyRoot, nil
	}
	return subtreeHash(0, size, r)
}

// ConsistencyProof builds the RFC 9162 section 2.1.4.1 consistency proof
// between size1 and size2 from a log's node hashes.
//
// Nothing here has to trust r: VerifyConsistency recomputes both roots from
// the same proof nodes, so a reader that lies about any node produces a proof
// that fails against at least one signed root.
func ConsistencyProof(size1, size2 uint64, r NodeReader) ([]Hash, error) {
	if size1 > size2 {
		return nil, fmt.Errorf("merkle: size %d is larger than size %d", size1, size2)
	}
	if size1 == 0 || size1 == size2 {
		return nil, nil
	}
	return subproof(size1, 0, size2, true, r)
}

// subproof is SUBPROOF(m, D[start:end], complete) from RFC 9162, with the
// subtree given by its leaf range instead of a copy of its leaves.
func subproof(m, start, end uint64, complete bool, r NodeReader) ([]Hash, error) {
	n := end - start
	if m == n {
		if complete {
			return nil, nil
		}
		h, err := subtreeHash(start, end, r)
		return []Hash{h}, err
	}
	k := splitPoint(n)
	var (
		proof []Hash
		other Hash
		err   error
	)
	if m <= k {
		if proof, err = subproof(m, start, start+k, complete, r); err != nil {
			return nil, err
		}
		other, err = subtreeHash(start+k, end, r)
	} else {
		if proof, err = subproof(m-k, start+k, end, false, r); err != nil {
			return nil, err
		}
		other, err = subtreeHash(start, start+k, r)
	}
	if err != nil {
		return nil, err
	}
	return append(proof, other), nil
}

// subtreeHash is MTH(D[start:end]). Perfect, aligned subtrees come straight
// from the reader; the ragged right edge of a tree is hashed up from them.
func subtreeHash(start, end uint64, r NodeReader) (Hash, error) {
	n := end - start
	if n == 0 {
		return Hash{}, fmt.Errorf("merkle: empty subtree at %d", start)
	}
	if level := uint(bits.TrailingZeros64(n)); n&(n-1) == 0 && start%n == 0 {
		return r.Node(level, start>>level)
	}
	k := splitPoint(n)
	left, err := subtreeHash(start, start+k, r)
	if err != nil {
		return Hash{}, err
	}
	right, err := subtreeHash(start+k, end, r)
	if err != nil {
		return Hash{}, err
	}
	return HashChildren(left, right), nil
}

// splitPoint is the largest power of two strictly smaller than n (n >= 2).
func splitPoint(n uint64) uint64 {
	return 1 << (bits.Len64(n-1) - 1)
}
