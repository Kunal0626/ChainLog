#!/usr/bin/env bash
#
# Cross-check ChainLog's hand-written HMAC-SHA256 against python's hmac
# module, over random keys and messages.
#
# Same reasoning as the other oracles: the implementation is ours, the
# reference is somebody else's. HMAC is easy to implement self-consistently
# and wrong -- swap ipad and opad, forget to hash an oversized key, pad the
# key with the wrong byte, and every test written against your own code still
# passes.
#
# Usage: tests/oracle_hmac.sh [path-to-cl-hmac]

set -uo pipefail

CL="${1:-build/release/cl-hmac}"

if [ ! -x "$CL" ]; then
  echo "oracle-hmac: $CL not found or not executable (run 'make' first)" >&2
  exit 2
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "oracle-hmac: python3 not found; cannot cross-check" >&2
  exit 2
fi

TMP="$(mktemp -d "${TMPDIR:-/tmp}/chainlog-oracle-hmac.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

checks=0
fails=0

# compare <key-hex> <message-file> <label>
compare() {
  local keyhex="$1"
  local msgfile="$2"
  local label="$3"
  local ours ref
  ours="$("$CL" "$keyhex" <"$msgfile")"
  ref="$(python3 -I -c '
import hmac, hashlib, sys
key = bytes.fromhex(sys.argv[1])
msg = open(sys.argv[2], "rb").read()
sys.stdout.write(hmac.new(key, msg, hashlib.sha256).hexdigest())
' "$keyhex" "$msgfile")"
  checks=$((checks + 1))
  if [ "$ours" != "$ref" ]; then
    echo "FAIL $label: cl-hmac=$ours python=$ref" >&2
    fails=$((fails + 1))
  fi
}

make_random() {
  local len="$1"
  local out="$2"
  if [ "$len" -eq 0 ]; then
    : >"$out"
  else
    head -c "$len" /dev/urandom >"$out"
  fi
}

echo "oracle-hmac: cross-checking $CL against python hmac"

# Key lengths around the 64-byte block boundary, where step 1 of HMAC changes
# behaviour: pad with zeros below it, hash the key above it.
for KLEN in 1 15 16 31 32 63 64 65 100 128 129 200; do
  KEYHEX="$(head -c "$KLEN" /dev/urandom | xxd -p | tr -d '\n')"
  for MLEN in 0 1 55 56 63 64 65 1000; do
    make_random "$MLEN" "$TMP/msg"
    compare "$KEYHEX" "$TMP/msg" "key=$KLEN msg=$MLEN"
  done
done

# Random sizes, so repeated runs are not testing the same shapes.
i=0
while [ "$i" -lt 25 ]; do
  KLEN=$(( RANDOM % 200 + 1 ))
  MLEN=$(( RANDOM % 5000 ))
  KEYHEX="$(head -c "$KLEN" /dev/urandom | xxd -p | tr -d '\n')"
  make_random "$MLEN" "$TMP/msg"
  compare "$KEYHEX" "$TMP/msg" "random key=$KLEN msg=$MLEN (run $i)"
  i=$((i + 1))
done

echo "oracle-hmac: $checks comparison(s), $fails failure(s)"
if [ "$fails" -ne 0 ]; then
  exit 1
fi
echo "oracle-hmac: OK"
