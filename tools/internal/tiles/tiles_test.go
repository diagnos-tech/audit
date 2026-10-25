package tiles

import (
	"context"
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/diagnos-tech/audit/tools/internal/merkle"
	"github.com/diagnos-tech/audit/tools/internal/tiles/tilestest"
)

func TestPath(t *testing.T) {
	for _, c := range []struct {
		level    uint
		n, width uint64
		want     string
	}{
		{0, 0, 256, "tile/0/000"},
		{0, 1234067, 256, "tile/0/x001/x234/067"},
		{1, 5, 17, "tile/1/005.p/17"},
		{2, 1000, 256, "tile/2/x001/000"},
	} {
		if got := Path(c.level, c.n, c.width); got != c.want {
			t.Errorf("Path(%d, %d, %d) = %q, want %q", c.level, c.n, c.width, got, c.want)
		}
		level, n, width, ok := tilestest.ParsePath(c.want)
		if !ok || level != c.level || n != c.n || width != c.width {
			t.Errorf("ParsePath(%q) = %d, %d, %d, %v", c.want, level, n, width, ok)
		}
	}
}

func newTree(n int) *merkle.Tree {
	t := &merkle.Tree{}
	for i := range n {
		t.AppendLeaf(fmt.Appendf(nil, "entry %d", i))
	}
	return t
}

func TestProofFromTiles(t *testing.T) {
	// 70_000 leaves reach the third tile level (2^16 = 65_536).
	tree := newTree(70_000)
	for _, drop := range []bool{false, true} {
		srv := httptest.NewServer(&tilestest.Log{Tree: tree, DropPartials: drop})
		defer srv.Close()

		r, err := NewReader(context.Background(), srv.Client(), srv.URL+"/log", tree.Size())
		if err != nil {
			t.Fatal(err)
		}
		for _, sizes := range [][2]uint64{{1, 2}, {255, 256}, {256, 257}, {1000, 65_536}, {65_535, 70_000}, {12_345, 69_999}, {70_000, 70_000}} {
			s1, s2 := sizes[0], sizes[1]
			root1, _ := merkle.Root(s1, tree)
			root2, _ := merkle.Root(s2, tree)
			proof, err := merkle.ConsistencyProof(s1, s2, r)
			if err != nil {
				t.Fatalf("drop=%v (%d, %d): %v", drop, s1, s2, err)
			}
			if err := merkle.VerifyConsistency(s1, s2, root1, root2, proof); err != nil {
				t.Fatalf("drop=%v (%d, %d): %v", drop, s1, s2, err)
			}
		}
		if r.Fetches > 40 {
			t.Errorf("drop=%v: %d fetches, expected the cache to keep it small", drop, r.Fetches)
		}
	}
}

func TestLyingTileIsCaught(t *testing.T) {
	tree := newTree(3000)
	// The last entry of tile 1/000.p/11 is the level-8 node over leaves
	// 2560-2815, which the proof below needs.
	srv := httptest.NewServer(&tilestest.Log{Tree: tree, Corrupt: "tile/1/000.p/11"})
	defer srv.Close()
	r, _ := NewReader(context.Background(), srv.Client(), srv.URL+"/log", tree.Size())

	root1, _ := merkle.Root(1024, tree)
	root2, _ := merkle.Root(3000, tree)
	proof, err := merkle.ConsistencyProof(1024, 3000, r)
	if err != nil {
		t.Fatal(err)
	}
	if err := merkle.VerifyConsistency(1024, 3000, root1, root2, proof); err == nil {
		t.Fatal("a proof built from a corrupted tile verified")
	}
}
