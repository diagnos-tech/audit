// Package tilestest serves an in-memory Merkle tree as a C2SP tlog-tiles
// log, for tests of code that reads logs over HTTP.
package tilestest

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/diagnos-tech/audit/tools/internal/merkle"
)

const (
	height    = 8
	tileWidth = 1 << height
)

// Log serves the hash tiles of Tree and, if set, Checkpoint.
type Log struct {
	Tree       *merkle.Tree
	Checkpoint []byte

	// DropPartials 404s a partial tile once its full tile exists, as a log
	// is allowed to.
	DropPartials bool
	// Corrupt is the path of a tile to serve with its last byte flipped.
	Corrupt string
}

func (l *Log) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path[strings.LastIndex(r.URL.Path, "/tile/")+1:]
	if strings.HasSuffix(r.URL.Path, "/checkpoint") && l.Checkpoint != nil {
		w.Write(l.Checkpoint)
		return
	}
	level, n, width, ok := ParsePath(path)
	if !ok {
		http.NotFound(w, r)
		return
	}
	available := l.Tree.Size() >> (level * height)
	full := (n+1)*tileWidth <= available
	if (width == tileWidth && !full) ||
		(width < tileWidth && n*tileWidth+width > available) ||
		(width < tileWidth && full && l.DropPartials) {
		http.NotFound(w, r)
		return
	}
	body := make([]byte, 0, width*32)
	for i := range width {
		h, err := l.Tree.Node(level*height, n*tileWidth+i)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		body = append(body, h[:]...)
	}
	if path == l.Corrupt {
		body[len(body)-1] ^= 1
	}
	w.Write(body)
}

// ParsePath reads tile/<L>/<N>[.p/<W>].
func ParsePath(p string) (level uint, n, width uint64, ok bool) {
	rest, found := strings.CutPrefix(p, "tile/")
	if !found {
		return
	}
	l, rest, _ := strings.Cut(rest, "/")
	lv, err := strconv.ParseUint(l, 10, 8)
	if err != nil {
		return
	}
	width = tileWidth
	if idx, w, partial := strings.Cut(rest, ".p/"); partial {
		pw, err := strconv.ParseUint(w, 10, 16)
		if err != nil || pw == 0 || pw >= tileWidth {
			return
		}
		rest, width = idx, pw
	}
	for _, part := range strings.Split(rest, "/") {
		v, err := strconv.ParseUint(strings.TrimPrefix(part, "x"), 10, 16)
		if err != nil || len(part) < 3 {
			return
		}
		n = n*1000 + v
	}
	return uint(lv), n, width, true
}
