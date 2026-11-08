#!/usr/bin/env bash
#
# The tamper demo: build a 1,000-record log, attack it seven different ways,
# and show what `chainlog verify` says about each.
#
# Every case is also an ASSERTION. The script checks the exit status and the
# reported problem name, and fails loudly if they are not what this file says
# they should be. A demo that merely prints whatever happens is a demo that can
# quietly stop demonstrating anything.
#
# The attacks are carried out by demo/attacker.py, which shares no code with
# ChainLog and uses python's own hashlib and zlib. A real attacker would not be
# using our code either, and it keeps the demo from testing ChainLog against
# itself.
#
# Usage: demo/tamper.sh [path-to-chainlog] [--keep]
#
#   --keep   leave demo/work/ in place afterwards so you can poke at it

set -uo pipefail

CLI="${1:-build/release/chainlog}"
KEEP=0
for arg in "$@"; do
  if [ "$arg" = "--keep" ]; then
    KEEP=1
  fi
done

if [ ! -x "$CLI" ]; then
  echo "demo: $CLI not found or not executable (run 'make' first)" >&2
  exit 2
fi
case "$CLI" in
  /*) ;;
  *) CLI="$PWD/$CLI" ;;
esac

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
ATTACKER="$HERE/attacker.py"
WORK="$HERE/work"

RECORDS=1000
BLOCK=128
VICTIM=637

rm -rf "$WORK"
mkdir -p "$WORK"

fails=0
cases=0

say() { printf '%s\n' "$*"; }
rule() { say "--------------------------------------------------------------------------------"; }

fail() {
  say "    *** DEMO ASSERTION FAILED: $* ***"
  fails=$((fails + 1))
}

# A short name for the binary in the transcript, so the output does not carry
# this machine's directory layout around.
show_cli() { printf 'chainlog'; }

# run_verify <dir> [extra args...] -- prints the command and its real output,
# and leaves the exit status in VERIFY_RC and the output in VERIFY_OUT.
run_verify() {
  local dir="$1"
  shift
  say ""
  if [ "$#" -eq 0 ]; then
    say "\$ $(show_cli) --dir ${dir#"$REPO/"} verify"
  else
    say "\$ $(show_cli) --dir ${dir#"$REPO/"} verify $*"
  fi
  VERIFY_OUT="$("$CLI" --dir "$dir" verify "$@" 2>&1)"
  VERIFY_RC=$?
  printf '%s\n' "$VERIFY_OUT" | sed 's/^/| /'
  say "| exit status $VERIFY_RC"
}

# attack <dir> <attacker args...>
attack() {
  local dir="$1"
  shift
  say ""
  if [ "$#" -eq 1 ]; then
    say "\$ demo/attacker.py $1 ${dir#"$REPO/"}"
  else
    say "\$ demo/attacker.py $1 ${dir#"$REPO/"} ${*:2}"
  fi
  local out
  out="$(python3 -I "$ATTACKER" "$1" "$dir" "${@:2}" 2>&1)"
  local rc=$?
  printf '%s\n' "$out" | sed 's/^/| /'
  if [ "$rc" -ne 0 ]; then
    fail "the attack itself failed"
  fi
}

# check <wanted-exit> <wanted-pattern> <caught-by>
check() {
  local want_rc="$1"
  local pattern="$2"
  local caught="$3"
  cases=$((cases + 1))
  if [ "$VERIFY_RC" -ne "$want_rc" ]; then
    fail "expected exit $want_rc, got $VERIFY_RC"
  fi
  if ! printf '%s' "$VERIFY_OUT" | grep -Eq "$pattern"; then
    fail "expected the output to match /$pattern/"
  fi
  say ""
  say "  => $caught"
}

scenario() {
  say ""
  say "================================================================================"
  say "$*"
  say "================================================================================"
}

# ---------------------------------------------------------------------------
# Build the pristine log, once.
# ---------------------------------------------------------------------------

say "ChainLog tamper demo"
rule
say "machine:  $(uname -m) $(uname -s) $(sw_vers -productVersion 2>/dev/null || true)"
say "binary:   ${CLI#"$REPO/"}"
say "records:  $RECORDS"
say "block:    $BLOCK records per sealed Merkle checkpoint"
rule
say ""
say "Record data is fixed width (\"rec-000637\"), so every frame is the same"
say "size and the attacks below can swap or rewrite frames without shifting"
say "any offsets. Hashes differ from run to run because each record's"
say "timestamp is part of what it hashes."
say ""

PRISTINE="$WORK/pristine"
say "\$ for i in \$(seq 0 $((RECORDS - 1))); do $(show_cli) --dir demo/work/pristine --block-size $BLOCK append \"rec-\$i\"; done"
BUILD_START=$(date +%s)
i=0
while [ "$i" -lt "$RECORDS" ]; do
  if ! "$CLI" --dir "$PRISTINE" --block-size "$BLOCK" \
       append "$(printf 'rec-%06d' "$i")" >/dev/null; then
    echo "demo: append $i failed" >&2
    exit 2
  fi
  i=$((i + 1))
done
BUILD_END=$(date +%s)
say "| (built in $((BUILD_END - BUILD_START))s)"

say ""
say "\$ $(show_cli) --dir demo/work/pristine stats"
"$CLI" --dir "$PRISTINE" stats | sed 's/^/| /'

say ""
say "\$ $(show_cli) --dir demo/work/pristine verify"
"$CLI" --dir "$PRISTINE" verify | sed 's/^/| /'

say ""
say "\$ $(show_cli) --dir demo/work/pristine anchor"
ANCHOR="$("$CLI" --dir "$PRISTINE" anchor)"
say "| $ANCHOR"
say ""
say "That anchor is the one thing we now keep OUTSIDE the log directory. Cases"
say "(d2) and (f) below are invisible without it."

# copy_pristine <name> -> echoes the new directory
copy_pristine() {
  local name="$1"
  rm -rf "$WORK/$name"
  cp -R "$PRISTINE" "$WORK/$name"
  printf '%s' "$WORK/$name"
}

# ---------------------------------------------------------------------------
# (a) one byte flipped
# ---------------------------------------------------------------------------

scenario "(a) one byte flipped in record $VICTIM"
D="$(copy_pristine a)"
attack "$D" flip "$VICTIM"
run_verify "$D"
check 1 "bad-crc at index $VICTIM" \
  "caught by the frame CRC-32, and it names record $VICTIM exactly"

# ---------------------------------------------------------------------------
# (b) a record deleted
# ---------------------------------------------------------------------------

scenario "(b) record 500 deleted outright"
D="$(copy_pristine b)"
attack "$D" delete 500
run_verify "$D"
check 1 "bad-index at index 500" \
  "caught by the index sequence: record 501 is sitting where 500 should be"

# ---------------------------------------------------------------------------
# (c) two records swapped
# ---------------------------------------------------------------------------

scenario "(c) records 300 and 301 exchanged"
D="$(copy_pristine c)"
attack "$D" swap 300 301
run_verify "$D"
check 1 "bad-index at index 300" \
  "caught by the index sequence before the hashes are even consulted"

# ---------------------------------------------------------------------------
# (d) the tail cut off, two ways
# ---------------------------------------------------------------------------

scenario "(d1) the tail cut off part-way through the last frame"
D="$(copy_pristine d1)"
attack "$D" truncate-mid 40
run_verify "$D"
check 1 "torn-tail at index 999" \
  "caught by the framing, and reported as a torn tail -- the signature of a crash, not an edit"

scenario "(d2) the tail cut off cleanly, at a frame boundary"
D="$(copy_pristine d2)"
attack "$D" truncate 768
run_verify "$D"
check 0 "ok: 768 record" \
  "NOT caught. A prefix of a valid chain is itself a valid chain, so nothing inside the directory disagrees."
run_verify "$D" --anchor "$ANCHOR"
check 1 "anchor-missing at index 999" \
  "caught by the anchor: the log is shorter than the head we published"

# ---------------------------------------------------------------------------
# (e) the whole tail re-linked
# ---------------------------------------------------------------------------

scenario "(e) record $VICTIM rewritten and every record after it re-linked"
D="$(copy_pristine e)"
attack "$D" relink "$VICTIM"
run_verify "$D"
check 1 "bad-checkpoint at index 512" \
  "caught by the sealed Merkle roots, which still remember the original history"

# ---------------------------------------------------------------------------
# (f) re-linked and re-sealed
# ---------------------------------------------------------------------------

scenario "(f) ... and the checkpoints re-sealed to match"
D="$(copy_pristine f)"
attack "$D" relink "$VICTIM"
attack "$D" reseal
run_verify "$D"
check 0 "ok: $RECORDS record" \
  "NOT caught. Every part of the directory now agrees with every other part, because the attacker controlled all of it."
run_verify "$D" --anchor "$ANCHOR"
check 1 "anchor-mismatch at index 999" \
  "caught by the anchor, the one value the attacker never had access to"

# ---------------------------------------------------------------------------
# (g) the same attack against a signed log
# ---------------------------------------------------------------------------

scenario "(g) the same attack on a log whose checkpoints are HMAC-signed"
KEY="$WORK/chainlog.key"
printf '%s' \
  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" >"$KEY"
chmod 600 "$KEY"

SIGNED="$WORK/g"
rm -rf "$SIGNED"
say ""
say "\$ for i in \$(seq 0 255); do $(show_cli) --dir demo/work/g --block-size $BLOCK --key-file KEY append \"rec-\$i\"; done"
i=0
while [ "$i" -lt 256 ]; do
  "$CLI" --dir "$SIGNED" --block-size "$BLOCK" --key-file "$KEY" \
    append "$(printf 'rec-%06d' "$i")" >/dev/null
  i=$((i + 1))
done
say "| 256 records, 2 signed checkpoints"

attack "$SIGNED" relink 100
attack "$SIGNED" reseal
run_verify "$SIGNED"
check 0 "ok: 256 record" \
  "still not caught WITHOUT the key -- the attacker re-sealed valid unsigned checkpoints"
say ""
say "\$ $(show_cli) --dir demo/work/g --key-file KEY verify"
VERIFY_OUT="$("$CLI" --dir "$SIGNED" --key-file "$KEY" verify 2>&1)"
VERIFY_RC=$?
printf '%s\n' "$VERIFY_OUT" | sed 's/^/| /'
say "| exit status $VERIFY_RC"
check 1 "bad-checkpoint" \
  "caught by the key alone, no anchor needed: the attacker could not sign what they wrote"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

say ""
say "================================================================================"
say "Summary"
say "================================================================================"
say ""
say "  case                                    verify alone   with an anchor"
say "  ------------------------------------------------------------------------"
say "  (a) one byte flipped                    bad-crc        -"
say "  (b) a record deleted                    bad-index      -"
say "  (c) two records swapped                 bad-index      -"
say "  (d1) tail cut mid-frame                 torn-tail      -"
say "  (d2) tail cut at a frame boundary       OK (!)         anchor-missing"
say "  (e) tail re-linked                      bad-checkpoint -"
say "  (f) re-linked and re-sealed             OK (!)         anchor-mismatch"
say "  (g) (f) against a signed log            OK (!)         bad-checkpoint, with --key-file"
say ""
say "The three OK(!) rows are the point of the demo, and they are two"
say "different kinds of blindness."
say ""
say "(d2) is MISSING data. A prefix of a valid chain is itself a valid chain,"
say "so a log that has had its tail cut off verifies perfectly. Nothing inside"
say "the file records how long it was supposed to be."
say ""
say "(f) and (g) are REWRITTEN data. Every check up to that point compares one"
say "part of the directory against another part -- and an attacker with write"
say "access controls both sides of that comparison."
say ""
say "Both are closed the same way: by one value the attacker never touched."
say "An anchor closes both. A signing key closes the rewriting only, because"
say "nothing it signs says how many checkpoints there should be."
say ""

if [ "$KEEP" -eq 0 ]; then
  rm -rf "$WORK"
else
  say "demo/work/ kept for inspection."
fi

say "$cases case(s) asserted, $fails failure(s)"
if [ "$fails" -ne 0 ]; then
  exit 1
fi
say "demo: OK"
