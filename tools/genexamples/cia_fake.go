package main

import (
	"crypto/sha256"
	"encoding/hex"
	"hash/fnv"
	"time"
)

// fakeHex is a 40-digit hex id derived from a label: the stand-in for the Git
// commits, which the examples do not have.
func fakeHex(label string) string {
	h := sha256.Sum256([]byte("example commit: " + label))
	return hex.EncodeToString(h[:20])
}

// jitter is a deterministic pseudo-random number in [0, n) for a label and a
// time, so latencies vary from slot to slot without a random generator whose
// state would depend on the order of calls.
func jitter(label string, t time.Time, n int) int {
	h := fnv.New32a()
	h.Write([]byte(label + t.Format(time.RFC3339)))
	return int(h.Sum32() % uint32(n))
}
