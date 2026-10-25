package record

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// maxFile bounds what the tools read: the largest legitimate file, a month
// index at its busiest, stays well under it.
const maxFile = 64 << 20

// ErrNotExist is returned for a path the source does not have.
var ErrNotExist = errors.New("file does not exist")

// Source reads repository files by their repository path ("data/v1/...").
// It is either a local clone or the published site, so the same commands
// work with or without cloning.
type Source interface {
	Read(path string) ([]byte, error)
	String() string
}

// Open returns a Source for root: an http(s) URL or a local directory.
func Open(ctx context.Context, client *http.Client, root string) (Source, error) {
	if strings.HasPrefix(root, "https://") || strings.HasPrefix(root, "http://") {
		u, err := url.Parse(root)
		if err != nil || u.Host == "" {
			return nil, fmt.Errorf("bad root URL %q", root)
		}
		if !strings.HasSuffix(u.Path, "/") {
			u.Path += "/"
		}
		return &httpSource{ctx: ctx, client: client, base: u}, nil
	}
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("root %s is not a directory", root)
	}
	return dirSource(root), nil
}

// Clean validates a repository path and normalises "./data/..." to
// "data/...". Paths may not leave the root.
func Clean(p string) (string, error) {
	c := path.Clean(filepath.ToSlash(p))
	if c == "." || path.IsAbs(c) || c == ".." || strings.HasPrefix(c, "../") {
		return "", fmt.Errorf("path %q is not inside the repository", p)
	}
	return c, nil
}

type dirSource string

func (d dirSource) String() string { return string(d) }

func (d dirSource) Read(p string) ([]byte, error) {
	c, err := Clean(p)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(filepath.Join(string(d), filepath.FromSlash(c)))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%w: %s", ErrNotExist, c)
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readAll(f, c)
}

type httpSource struct {
	ctx    context.Context
	client *http.Client
	base   *url.URL
}

func (h *httpSource) String() string { return h.base.String() }

func (h *httpSource) Read(p string) ([]byte, error) {
	c, err := Clean(p)
	if err != nil {
		return nil, err
	}
	u := h.base.JoinPath(c)
	req, err := http.NewRequestWithContext(h.ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "diagnos-audit-verify (+https://github.com/diagnos-tech/audit)")
	resp, err := h.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, fmt.Errorf("%w: %s", ErrNotExist, u)
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("GET %s: %s", u, resp.Status)
	}
	return readAll(resp.Body, c)
}

func readAll(r io.Reader, name string) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxFile+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxFile {
		return nil, fmt.Errorf("%s is larger than %d bytes", name, maxFile)
	}
	return b, nil
}
