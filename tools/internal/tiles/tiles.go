// Package tiles reads the Merkle node hashes of a C2SP tlog-tiles log over
// HTTP, so a consistency proof can be rebuilt from the log itself instead of
// trusting the one the witness recorded.
//
// Only hash tiles (tile/<L>/<N>) are read, never entry bundles: the hashes
// are commitments, the entries are the log's data.
package tiles

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/diagnos-tech/audit/tools/internal/merkle"
)

const (
	height    = 8           // tree levels per tile
	tileWidth = 1 << height // hashes in a full tile
	hashSize  = 32
	maxNote   = 16 << 10 // a checkpoint is a few hundred bytes
)

// ErrNotFound is returned for a 404, which matters for partial tiles.
var ErrNotFound = errors.New("tiles: not found")

// Reader serves merkle.NodeReader from the tiles of a log at a fixed tree
// size (normally the size of the log's current checkpoint).
type Reader struct {
	base   *url.URL
	size   uint64
	client *http.Client
	ctx    context.Context
	cache  map[string][]byte

	// Fetches counts HTTP requests, for the report.
	Fetches int
}

// NewClient returns the HTTP client the tools use: a timeout and nothing else.
func NewClient() *http.Client { return &http.Client{Timeout: 30 * time.Second} }

// NewReader reads tiles under base (the log's public URL) for a tree of size.
func NewReader(ctx context.Context, client *http.Client, base string, size uint64) (*Reader, error) {
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, fmt.Errorf("tiles: bad log URL %q", base)
	}
	if !strings.HasSuffix(u.Path, "/") {
		u.Path += "/"
	}
	return &Reader{base: u, size: size, client: client, ctx: ctx, cache: map[string][]byte{}}, nil
}

// Checkpoint fetches the log's current checkpoint (still to be verified).
func (r *Reader) Checkpoint() ([]byte, error) {
	return r.get("checkpoint", maxNote)
}

// Node implements merkle.NodeReader. A node at tree level h lives in the tile
// at level h/8; when h is not a multiple of 8 it is hashed up from the
// 2^(h%8) consecutive entries of that tile that it covers.
func (r *Reader) Node(level uint, index uint64) (merkle.Hash, error) {
	tileLevel, within := level/height, level%height
	first := index << within // first covered entry at tree level 8*tileLevel
	count := uint64(1) << within
	if tileLevel*height >= 64 || first>>within != index {
		return merkle.Hash{}, fmt.Errorf("tiles: node (%d, %d) out of range", level, index)
	}
	available := r.size >> (tileLevel * height) // complete nodes at that level
	if first+count > available {
		return merkle.Hash{}, fmt.Errorf("tiles: node (%d, %d) is outside a tree of size %d", level, index, r.size)
	}

	n, offset := first/tileWidth, first%tileWidth
	width := min(tileWidth, available-n*tileWidth)
	tile, err := r.tile(tileLevel, n, width)
	if err != nil {
		return merkle.Hash{}, err
	}

	hashes := make([]merkle.Hash, count)
	for i := range hashes {
		copy(hashes[i][:], tile[(offset+uint64(i))*hashSize:])
	}
	for len(hashes) > 1 {
		for i := range len(hashes) / 2 {
			hashes[i] = merkle.HashChildren(hashes[2*i], hashes[2*i+1])
		}
		hashes = hashes[:len(hashes)/2]
	}
	return hashes[0], nil
}

// tile returns at least width hashes of tile (level, n). A partial tile can
// disappear once the log fills it, so a 404 falls back to the full tile,
// whose first entries are the same.
func (r *Reader) tile(level uint, n, width uint64) ([]byte, error) {
	full := Path(level, n, tileWidth)
	if b, ok := r.cache[full]; ok {
		return b, nil
	}
	path := Path(level, n, width)
	if b, ok := r.cache[path]; ok {
		return b, nil
	}
	b, err := r.get(path, width*hashSize)
	if errors.Is(err, ErrNotFound) && width < tileWidth {
		path, width = full, tileWidth
		b, err = r.get(path, width*hashSize)
	}
	if err != nil {
		return nil, err
	}
	if uint64(len(b)) != width*hashSize {
		return nil, fmt.Errorf("tiles: %s has %d bytes, want %d", path, len(b), width*hashSize)
	}
	r.cache[path] = b
	return b, nil
}

func (r *Reader) get(path string, limit uint64) ([]byte, error) {
	u := r.base.JoinPath(path)
	req, err := http.NewRequestWithContext(r.ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "diagnos-audit-verify (+https://github.com/diagnos-tech/audit)")
	r.Fetches++
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("tiles: GET %s: %w", u, err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, fmt.Errorf("%w: %s", ErrNotFound, u)
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("tiles: GET %s: %s", u, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, int64(limit)+1))
	if err != nil {
		return nil, fmt.Errorf("tiles: GET %s: %w", u, err)
	}
	if uint64(len(b)) > limit {
		return nil, fmt.Errorf("tiles: %s is larger than %d bytes", u, limit)
	}
	return b, nil
}

// Path is the tlog-tiles path of a hash tile: tile/<L>/<N>[.p/<W>], with N
// written in groups of three digits ("x001/x234/067").
func Path(level uint, n, width uint64) string {
	idx := fmt.Sprintf("%03d", n%1000)
	for n >= 1000 {
		n /= 1000
		idx = fmt.Sprintf("x%03d/%s", n%1000, idx)
	}
	p := fmt.Sprintf("tile/%d/%s", level, idx)
	if width < tileWidth {
		p += fmt.Sprintf(".p/%d", width)
	}
	return p
}
