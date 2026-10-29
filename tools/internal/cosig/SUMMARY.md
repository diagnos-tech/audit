# cosig

- `cosig.go` — C2SP `cosignature/v1` signer and verifier on top of `sumdb/note`, and the plain signed-note verifier of the same key
- `keyset.go` — a witness's key file: its current key and the keys it replaced, one per line, all of one witness and none twice
- `cosig_test.go` — a golden vector, round trips, malformed keys
- `keyset_test.go` — single and rotated key files, malformed lines, another witness's key, duplicates, who verifies what (with a fuzz target)
