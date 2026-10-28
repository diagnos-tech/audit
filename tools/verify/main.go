// Command verify checks the records of github.com/diagnos-tech/audit without
// trusting diagnos, the auditor, or any page that shows them.
//
//	go run ./tools/verify witness data/v1/audit/witness/2026/10/25/140503Z.json
//	go run ./tools/verify timestamp -openssl data/v1/timestamps/2026/10/25/14Z.json
//	go run ./tools/verify consistency data/v1/audit/witness/2026/10/25/140503Z.json
//	go run ./tools/verify cia [-complete]
//	go run ./tools/verify incidents incidents/*.md
//	go run ./tools/verify release [-cosign] data/v1/cia/releases/vault/<digest>
//	go run ./tools/verify all
//
// Without a clone, point -root at a web server that serves the repository's
// files at the same paths, such as raw GitHub:
//
//	go run github.com/diagnos-tech/audit/tools/verify@latest witness \
//	  -root https://raw.githubusercontent.com/diagnos-tech/audit/develop/ data/v1/audit/witness/...
//
// It depends on nothing but the Go standard library and
// golang.org/x/mod/sumdb/note. See VERIFY.md for what each check proves.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/diagnos-tech/audit/tools/internal/check"
	"github.com/diagnos-tech/audit/tools/internal/record"
	"github.com/diagnos-tech/audit/tools/internal/tiles"
)

const usage = `usage: verify <command> [flags] [files]

Commands:
  witness FILE...          log signature, witness cosignature and the consistency
                           proof from the previous witness record (either witness's)
  timestamp FILE...        hourly record: imprint, the records it names, the link to
                           the previous hour and the RFC 3161 token's contents
  finding FILE...          a finding is evidence: both checkpoints are signed and conflict
  consistency OLD [NEW]    rebuild consistency proofs from the log's own tiles: OLD → NEW,
                           and up to the log's current checkpoint
  cia [FILE...]            the CIA record of a local clone: run records (cia-run/v1 and v2, with
                           each witness's signed measurement) and their chain, the incident
                           snapshots and releases they point at, and the day files, summary,
                           latest and incidents views recomputed from them
  incidents FILE...        incident files (incidents/*.md): the grammar and rules of the
                           declaration format; says which are published
  release DIR...           an archived release (data/v1/cia/releases/<service>/<digest>): the
                           manifest hashes to the directory name and agrees with the verdict,
                           which names the identity pinned in keys/signers.json
  all                      every file under data/v1 of a local clone, the chains between
                           them, and state.json, latest.json and the month indexes

Flags (after the command):
  -root DIR|URL   repository to read files from (default "."); a URL such as
                  https://raw.githubusercontent.com/diagnos-tech/audit/develop/
                  works without a clone, but cannot be listed: cia and all need a clone
  -keys DIR       keys directory to trust (default: keys/ inside -root). Pin a copy
                  obtained elsewhere to make the check independent of this repository
  -openssl        timestamp, all: also verify each token's TSA signature and chain
                  with "openssl ts -verify" against keys/tsa/<provider>.pem
  -complete       cia, all: the files are the whole history (as in a clone of the real
                  record); the oldest run record must be the first run. Without it they
                  may be a slice, as the example data is
  -cosign         release, all: also re-check each release's Sigstore bundles with
                  cosign, against the identity pinned in keys/signers.json
  -log URL        consistency: read tiles from URL instead of the record's url
  -q              print only failures

Exit status: 0 if every check passed, 1 if any failed, 2 on bad usage.
`

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
}

type options struct {
	root, keys, logURL string
	openssl, quiet     bool
	complete, cosign   bool
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "-help" || args[0] == "help" {
		fmt.Fprint(stderr, usage)
		return 2
	}
	cmd := args[0]
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var o options
	fs.StringVar(&o.root, "root", ".", "")
	fs.StringVar(&o.keys, "keys", "", "")
	fs.StringVar(&o.logURL, "log", "", "")
	fs.BoolVar(&o.openssl, "openssl", false, "")
	fs.BoolVar(&o.quiet, "q", false, "")
	fs.BoolVar(&o.complete, "complete", false, "")
	fs.BoolVar(&o.cosign, "cosign", false, "")
	if err := fs.Parse(args[1:]); err != nil {
		fmt.Fprintf(stderr, "verify %s: %v\n\n%s", cmd, err, usage)
		return 2
	}
	if cmd == "incidents" {
		if fs.NArg() == 0 {
			fmt.Fprintln(stderr, "verify incidents: name at least one file")
			return 2
		}
		return report(stdout, check.Incidents(fs.Args(), time.Now()), o.quiet)
	}
	files, err := cleanAll(fs.Args())
	if err != nil {
		fmt.Fprintf(stderr, "verify: %v\n", err)
		return 2
	}

	client := tiles.NewClient()
	src, err := record.Open(ctx, client, o.root)
	if err != nil {
		fmt.Fprintf(stderr, "verify: %v\n", err)
		return 2
	}
	keys, keySrc, keyPrefix, err := keyring(ctx, client, src, o.keys)
	if err != nil {
		fmt.Fprintf(stderr, "verify: %v\n", err)
		return 2
	}
	var tsOpts check.TimestampOptions
	if o.openssl {
		tsOpts.OpenSSL = &check.OpenSSL{Keys: keySrc, Prefix: keyPrefix}
	}
	ciaOpts := check.CIAOptions{Complete: o.complete, Release: check.ReleaseOptions{Cosign: o.cosign}, Keys: keys}

	var reports []*check.Report
	switch cmd {
	case "witness", "timestamp", "finding":
		if len(files) == 0 {
			fmt.Fprintf(stderr, "verify %s: name at least one file\n", cmd)
			return 2
		}
		for _, f := range files {
			reports = append(reports, one(cmd, src, keys, f, tsOpts))
		}
	case "consistency":
		if len(files) < 1 || len(files) > 2 {
			fmt.Fprintln(stderr, "verify consistency: name one or two witness records")
			return 2
		}
		newer := ""
		if len(files) == 2 {
			newer = files[1]
		}
		reports = append(reports, check.FromLog(ctx, client, src, keys, files[0], newer, o.logURL))
	case "release":
		if len(files) == 0 {
			fmt.Fprintln(stderr, "verify release: name at least one release directory")
			return 2
		}
		for _, f := range files {
			reports = append(reports, check.Release(src, f, ciaOpts.Release))
		}
	case "cia", "all":
		if strings.Contains(o.root, "://") {
			fmt.Fprintf(stderr, "verify %s: listing files needs a clone of the repository: "+
				"git clone https://github.com/diagnos-tech/audit (then -root DIR)\n", cmd)
			return 2
		}
		if cmd == "cia" {
			reports, err = check.CIAFiles(o.root, src, files, ciaOpts)
		} else {
			reports, err = check.AllWith(o.root, src, keys, tsOpts, ciaOpts)
		}
		if err != nil {
			fmt.Fprintf(stderr, "verify %s: %v\n", cmd, err)
			return 2
		}
	default:
		fmt.Fprintf(stderr, "verify: unknown command %q\n\n%s", cmd, usage)
		return 2
	}
	return report(stdout, reports, o.quiet)
}

func one(cmd string, src record.Source, keys *check.Keyring, file string, opts check.TimestampOptions) *check.Report {
	switch cmd {
	case "witness":
		_, r := check.Witness(src, keys, file)
		return r
	case "timestamp":
		_, r := check.Timestamp(src, file, opts)
		return r
	default:
		_, r := check.Finding(src, keys, file)
		return r
	}
}

// keyring trusts dir when given, else keys/ inside the repository.
func keyring(ctx context.Context, client *http.Client, src record.Source, dir string) (*check.Keyring, record.Source, string, error) {
	if dir == "" {
		return check.NewKeyring(src, "keys/"), src, "keys/", nil
	}
	keySrc, err := record.Open(ctx, client, dir)
	if err != nil {
		return nil, nil, "", fmt.Errorf("-keys: %w", err)
	}
	return check.NewKeyring(keySrc, ""), keySrc, "", nil
}

func cleanAll(args []string) ([]string, error) {
	out := make([]string, len(args))
	for i, a := range args {
		c, err := record.Clean(a)
		if err != nil {
			return nil, err
		}
		out[i] = c
	}
	return out, nil
}

func report(w io.Writer, reports []*check.Report, quiet bool) int {
	failed, warned, checks := 0, 0, 0
	for i, r := range reports {
		if i > 0 && !quiet {
			fmt.Fprintln(w)
		}
		r.Print(w, quiet)
		checks += len(r.Results)
		switch r.Worst() {
		case check.Fail:
			failed++
		case check.Warn:
			warned++
		}
	}
	if len(reports) == 0 {
		fmt.Fprintln(w, "nothing to check: there is no data/v1 yet")
		return 0
	}
	if !quiet || failed+warned > 0 {
		fmt.Fprintln(w)
	}
	note := ""
	if warned > 0 {
		note = fmt.Sprintf(", %d with warnings", warned)
	}
	if failed > 0 {
		fmt.Fprintf(w, "FAILED: %d of %s%s (%d checks)\n", failed, plural(len(reports), "file"), note, checks)
		return 1
	}
	fmt.Fprintf(w, "OK: %s%s, %s\n", plural(len(reports), "file"), note, plural(checks, "check"))
	return 0
}

func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}
