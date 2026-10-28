# keys

Public keys and policy that decide what verifies. Changed only by reviewed pull request.
`logs/` and `witness/` are added when the witness goes live; `witness/latam.vkey`, the second
witness's key, is added by its own pull request, and until it is the verifier treats it as absent.

- `tsa/` — the CA chains of the time-stamping authorities
- `README.md` — what each key is, `signers.json` explained, rotation, copies outside GitHub
- `signers.json` — for each service, the GitHub Actions workflow whose signature a release must carry
