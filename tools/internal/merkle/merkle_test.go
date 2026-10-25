package merkle

import (
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
)

func buildTree(n int) *Tree {
	t := &Tree{}
	for i := range n {
		t.AppendLeaf(fmt.Appendf(nil, "leaf %d", i))
	}
	return t
}

// naiveRoot is MTH from RFC 9162 section 2.1.1, straight from the leaves.
func naiveRoot(leaves []Hash) Hash {
	switch len(leaves) {
	case 0:
		return EmptyRoot
	case 1:
		return leaves[0]
	}
	k := splitPoint(uint64(len(leaves)))
	return HashChildren(naiveRoot(leaves[:k]), naiveRoot(leaves[k:]))
}

func TestRootMatchesDefinition(t *testing.T) {
	tree := buildTree(70)
	for size := uint64(0); size <= tree.Size(); size++ {
		got, err := Root(size, tree.Prefix(size))
		if err != nil {
			t.Fatalf("Root(%d): %v", size, err)
		}
		if want := naiveRoot(tree.leaves[:size]); got != want {
			t.Fatalf("Root(%d) = %x, want %x", size, got, want)
		}
	}
}

// RFC 6962 reference values for the empty tree and a one-leaf tree.
func TestKnownHashes(t *testing.T) {
	if got := hex.EncodeToString(EmptyRoot[:]); got != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Errorf("EmptyRoot = %s", got)
	}
	leaf := HashLeaf(nil)
	if got := hex.EncodeToString(leaf[:]); got != "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d" {
		t.Errorf("HashLeaf(nil) = %s", got)
	}
}

func TestConsistencyRoundTrip(t *testing.T) {
	tree := buildTree(70)
	for size2 := uint64(1); size2 <= tree.Size(); size2++ {
		root2, _ := Root(size2, tree)
		for size1 := uint64(0); size1 <= size2; size1++ {
			root1, _ := Root(size1, tree)
			// The proof may only touch nodes inside the newer tree.
			proof, err := ConsistencyProof(size1, size2, tree.Prefix(size2))
			if err != nil {
				t.Fatalf("ConsistencyProof(%d, %d): %v", size1, size2, err)
			}
			if err := VerifyConsistency(size1, size2, root1, root2, proof); err != nil {
				t.Fatalf("VerifyConsistency(%d, %d): %v", size1, size2, err)
			}
		}
	}
}

func TestConsistencyRejectsTampering(t *testing.T) {
	tree := buildTree(70)
	for size2 := uint64(2); size2 <= tree.Size(); size2++ {
		root2, _ := Root(size2, tree)
		for size1 := uint64(1); size1 < size2; size1++ {
			root1, _ := Root(size1, tree)
			proof, _ := ConsistencyProof(size1, size2, tree)

			for i := range proof {
				bad := append([]Hash(nil), proof...)
				bad[i][0] ^= 1
				expectInconsistent(t, size1, size2, root1, root2, bad, "flipped node %d", i)
			}
			expectInconsistent(t, size1, size2, root1, root2, proof[:len(proof)-1], "truncated")
			expectInconsistent(t, size1, size2, root1, root2, append(proof, root2), "extended")

			wrong := root1
			wrong[31] ^= 1
			expectInconsistent(t, size1, size2, wrong, root2, proof, "wrong old root")
			expectInconsistent(t, size1, size2, root1, wrong, proof, "wrong new root")
		}
	}
}

func expectInconsistent(t *testing.T, s1, s2 uint64, r1, r2 Hash, proof []Hash, format string, args ...any) {
	t.Helper()
	if err := VerifyConsistency(s1, s2, r1, r2, proof); !errors.Is(err, ErrInconsistent) {
		t.Fatalf("(%d, %d) %s: got %v, want ErrInconsistent", s1, s2, fmt.Sprintf(format, args...), err)
	}
}

func TestConsistencyEdgeCases(t *testing.T) {
	tree := buildTree(8)
	r8, _ := Root(8, tree)
	r4, _ := Root(4, tree)
	if err := VerifyConsistency(8, 8, r8, r8, nil); err != nil {
		t.Errorf("equal sizes: %v", err)
	}
	if err := VerifyConsistency(8, 8, r8, r4, nil); err == nil {
		t.Error("equal sizes with different roots verified")
	}
	if err := VerifyConsistency(0, 8, EmptyRoot, r8, nil); err != nil {
		t.Errorf("from empty tree: %v", err)
	}
	if err := VerifyConsistency(8, 4, r8, r4, nil); err == nil {
		t.Error("shrinking tree verified")
	}
}
