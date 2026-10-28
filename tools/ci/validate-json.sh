#!/usr/bin/env bash
# Validates data files against schemas/v1 with a pinned JSON Schema 2020-12
# validator (santhosh-tekuri/jsonschema's jv, fetched through the Go module
# proxy and checked against the Go checksum database, itself a transparency
# log).
#
#   tools/ci/validate-json.sh                     every file under data/
#   tools/ci/validate-json.sh -root examples      every file under examples/data/
#   tools/ci/validate-json.sh data/v1/latest.json ...   just these (paths relative to -root)
#
# Besides every file under data/, keys/signers.json is validated when it exists.
# A file under data/ that matches no known layout is an error: nothing gets
# into the public record without a schema. Sigstore bundles (.sig and
# provenance.sigstore.json) and RFC 3161 tokens (.tsr) have no schema; cosign
# and tools/verify check them.
set -euo pipefail

JV="github.com/santhosh-tekuri/jsonschema/cmd/jv@v0.7.0"
SCHEMA_URL="https://diagnos-tech.github.io/audit/schemas/"

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
root="."
if [[ "${1:-}" == "-root" ]]; then
  root="$2"
  shift 2
fi
root="$(cd "$root" && pwd)"

bin="$(mktemp -d)"
trap 'rm -rf "$bin"' EXIT
GOBIN="$bin" GOFLAGS=-mod=mod go install "$JV"

if [[ $# -eq 0 ]]; then
  if [[ ! -d "$root/data" && ! -f "$root/keys/signers.json" ]]; then
    echo "validate-json: no data/ under $root yet, nothing to validate"
    exit 0
  fi
  files=()
  if [[ -d "$root/data" ]]; then
    mapfile -t files < <(cd "$root" && find data -type f | LC_ALL=C sort)
  fi
  if [[ -f "$root/keys/signers.json" ]]; then
    files+=(keys/signers.json)
  fi
else
  files=("$@")
fi

declare -A groups=()
unknown=0
for f in "${files[@]}"; do
  f="${f#./}"
  case "$f" in
    data/v1/state.json) kind=state ;;
    data/v1/latest.json) kind=latest ;;
    data/v1/index/[0-9][0-9][0-9][0-9]/[0-9][0-9].json) kind=index ;;
    data/v1/timestamps/*/*/*/[0-2][0-9]Z.json) kind=timestamp ;;
    data/v1/timestamps/*/*/*/[0-2][0-9]Z.tsr) continue ;; # DER, checked by tools/verify
    data/v1/sync.json) kind=sync ;;
    data/v1/cia/latest.json) kind=cia-latest ;;
    data/v1/cia/summary.json) kind=cia-summary ;;
    data/v1/cia/incidents.json) kind=cia-incident-list ;;
    data/v1/cia/changes.json) kind=cia-changes ;;
    data/v1/cia/changes-recent.json) kind=cia-changes-recent ;;
    data/v1/cia/incidents/events/[0-9][0-9][0-9][0-9]/[0-9][0-9]/[0-9][0-9]/*.json) kind=cia-incident-event ;;
    data/v1/cia/days/[0-9][0-9][0-9][0-9]/[0-9][0-9]/[0-9][0-9].json) kind=cia-day ;;
    data/v1/cia/runs/[0-9][0-9][0-9][0-9]/[0-9][0-9]/[0-9][0-9]/[0-2][0-9][0-5][05]Z.json) kind=cia-run ;;
    data/v1/cia/incidents/[0-9][0-9][0-9][0-9]/[0-9][0-9]/[0-9][0-9]/[0-2][0-9][0-5][05]Z.json) kind=cia-incidents ;;
    data/v1/cia/releases/*/*/verdict.json) kind=cia-release ;;
    data/v1/cia/releases/*/*/manifest.json) kind=release-manifest ;;
    data/v1/cia/releases/*/*/manifest.json.sig | data/v1/cia/releases/*/*/provenance.sigstore.json) continue ;; # Sigstore bundles, checked by cosign
    keys/signers.json) kind=signers ;;
    data/v1/*/witness/*/*/*/[0-9][0-9][0-9][0-9][0-9][0-9]Z.json) kind=witness ;;
    data/v1/*/findings/*/*/*/[0-9][0-9][0-9][0-9][0-9][0-9]Z.json) kind=finding ;;
    *)
      echo "validate-json: $f has no place under data/ (see the layout in README.md)" >&2
      unknown=1
      continue
      ;;
  esac
  groups[$kind]+="$f"$'\n'
done

status=$unknown
for kind in "${!groups[@]}"; do
  count=$(printf '%s' "${groups[$kind]}" | grep -c .)
  echo "validate-json: $count $kind file(s) against schemas/v1/$kind.schema.json"
  # jv prints a line per valid file; keep only what is wrong.
  if ! (cd "$root" && printf '%s' "${groups[$kind]}" | tr '\n' '\0' |
    xargs -0 -n 500 "$bin/jv" --assert-format --map "$SCHEMA_URL=$repo/schemas" \
      "$repo/schemas/v1/$kind.schema.json" | { grep -v -e ': ok$' -e '^$' || true; }); then
    status=1
  fi
done
exit $status
