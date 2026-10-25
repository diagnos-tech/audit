package merkle

import "fmt"

// Tree is an in-memory append-only Merkle tree. The example generator and the
// tests use it as a stand-in for a real log; it is not built for size.
type Tree struct {
	leaves []Hash
	nodes  map[nodeID]Hash // memoised perfect subtrees above level 0
}

type nodeID struct {
	level uint
	index uint64
}

// AppendLeaf adds the leaf hash of data and returns its index.
func (t *Tree) AppendLeaf(data []byte) uint64 {
	t.leaves = append(t.leaves, HashLeaf(data))
	return uint64(len(t.leaves) - 1)
}

// AppendHash adds a leaf whose hash is already known, e.g. to fork a tree.
func (t *Tree) AppendHash(h Hash) {
	t.leaves = append(t.leaves, h)
}

// Size is the number of leaves.
func (t *Tree) Size() uint64 { return uint64(len(t.leaves)) }

// Node implements NodeReader. Perfect subtrees never change once complete,
// so they are memoised.
func (t *Tree) Node(level uint, index uint64) (Hash, error) {
	if level >= 64 || (index+1)<<level > t.Size() || (index+1)<<level < index {
		return Hash{}, fmt.Errorf("merkle: node (%d, %d) is outside a tree of size %d", level, index, t.Size())
	}
	if level == 0 {
		return t.leaves[index], nil
	}
	id := nodeID{level, index}
	if h, ok := t.nodes[id]; ok {
		return h, nil
	}
	l, _ := t.Node(level-1, 2*index)
	r, _ := t.Node(level-1, 2*index+1)
	h := HashChildren(l, r)
	if t.nodes == nil {
		t.nodes = make(map[nodeID]Hash)
	}
	t.nodes[id] = h
	return h, nil
}

// Prefix returns a read-only view of the first size leaves, for computing
// roots and proofs of an older tree.
func (t *Tree) Prefix(size uint64) NodeReader {
	return prefix{t, size}
}

type prefix struct {
	t    *Tree
	size uint64
}

func (p prefix) Node(level uint, index uint64) (Hash, error) {
	if level >= 64 || (index+1)<<level > p.size {
		return Hash{}, fmt.Errorf("merkle: node (%d, %d) is outside a tree of size %d", level, index, p.size)
	}
	return p.t.Node(level, index)
}
