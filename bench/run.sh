#!/usr/bin/env bash
#
# Runs every benchmark and writes bench/RESULTS.md.
#
# Rules this script exists to enforce:
#
#   * Every number in RESULTS.md comes from a program in this directory, run
#     here, on this machine. Nothing is typed in by hand.
#   * Medians over several runs, with the min and max shown, so the spread is
#     visible rather than hidden. One unlucky run moves a mean and barely
#     moves a median.
#   * The machine, the OS and the tool versions are captured automatically
#     into the same file, because a throughput figure without them is not a
#     measurement, it is a rumour.
#   * peak_rss_bytes() is checked against a known allocation first, and the
#     script REFUSES to write results if the check fails. getrusage reports
#     ru_maxrss in bytes on Darwin and kilobytes on Linux, and a silent 1024x
#     error in a memory figure is exactly the sort of thing that ends up
#     quoted where it cannot be corrected.
#
# Usage: bench/run.sh [--runs N] [--out FILE] [--quick]
#
#   --runs N   repetitions per measurement (default 5)
#   --quick    smaller corpora, for checking the script itself
#   --out F    where to write the report (default bench/RESULTS.md)

set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
BIN="$REPO/build/release"

RUNS=5
QUICK=0
OUT="$HERE/RESULTS.md"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --runs) RUNS="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --quick) QUICK=1; shift ;;
    *) echo "bench: unknown argument $1" >&2; exit 2 ;;
  esac
done

for b in bench_append bench_verify bench_merkle bench_sha256 bench_mem; do
  if [ ! -x "$BIN/$b" ]; then
    echo "bench: $BIN/$b missing; run 'make bench-build' first" >&2
    exit 2
  fi
done

if [ "$QUICK" -eq 1 ]; then
  SMALL_RECORDS=20000
  BIG_RECORDS=100000
  SYNC_RECORDS=100
  MERKLE_BIG=65536
  SHA_MIB=32
else
  SMALL_RECORDS=100000
  BIG_RECORDS=1000000
  SYNC_RECORDS=500
  MERKLE_BIG=1048576
  SHA_MIB=128
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/chainlog-bench.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

# median/min/max of whitespace-separated numbers on stdin.
stats() {
  python3 -I -c '
import sys
vals = sorted(float(x) for x in sys.stdin.read().split())
if not vals:
    print("0 0 0"); raise SystemExit
n = len(vals)
med = vals[n // 2] if n % 2 else (vals[n // 2 - 1] + vals[n // 2]) / 2.0
print("%.6f %.6f %.6f" % (med, vals[0], vals[-1]))
'
}

fmt() {
  python3 -I -c '
import sys
v = float(sys.argv[1])
if v >= 100: print("%.0f" % v)
elif v >= 10: print("%.1f" % v)
elif v >= 1: print("%.2f" % v)
else: print("%.4f" % v)
' "$1"
}

mib() {
  python3 -I -c 'import sys; print("%.1f" % (float(sys.argv[1]) / 1048576.0))' "$1"
}

# key_from <output-file> <key>
key_from() { sed -n "s/^$2=//p" "$1"; }

# Runs a command $RUNS times into $WORK/run.N, echoing a dot per run.
# repeat <fresh-dir-prefix-or-empty> -- <command...>
repeat() {
  local fresh="$1"; shift
  [ "$1" = "--" ] && shift
  local i=1
  while [ "$i" -le "$RUNS" ]; do
    if [ -n "$fresh" ]; then
      rm -rf "${fresh}${i}"
    fi
    if ! "$@" ${fresh:+--dir "${fresh}${i}"} >"$WORK/run.$i" 2>"$WORK/err.$i"; then
      echo "" >&2
      echo "bench: a run failed:" >&2
      sed 's/^/  /' "$WORK/err.$i" >&2
      exit 2
    fi
    printf '.' >&2
    i=$((i + 1))
  done
  printf ' \n' >&2
}

# collect <key> -> "median min max"
collect() {
  local i=1
  : >"$WORK/values"
  while [ "$i" -le "$RUNS" ]; do
    key_from "$WORK/run.$i" "$1" >>"$WORK/values"
    i=$((i + 1))
  done
  stats <"$WORK/values"
}

say() { printf '%s\n' "$*" >>"$OUT"; }
note() { printf '%s\n' "$*" >&2; }

# ---------------------------------------------------------------------------
# the memory unit check -- before anything else
# ---------------------------------------------------------------------------

note "bench: checking peak_rss_bytes() units"
"$BIN/bench_mem" --mib 256 >"$WORK/mem.txt" || exit 2
MEM_WANT="$(key_from "$WORK/mem.txt" mem_expected_bytes)"
MEM_GOT="$(key_from "$WORK/mem.txt" mem_rss_growth_bytes)"
if ! python3 -I -c '
import sys
want, got = float(sys.argv[1]), float(sys.argv[2])
sys.exit(0 if 0.5 * want <= got <= 2.0 * want else 1)
' "$MEM_WANT" "$MEM_GOT"; then
  note "bench: REFUSING to write results."
  note "bench: peak_rss_bytes() is wrong: touched $MEM_WANT bytes, measured a"
  note "bench: growth of $MEM_GOT. Check the bytes-vs-kilobytes branch in"
  note "bench/bench_util.cpp before trusting any memory figure."
  exit 1
fi
note "bench: ok -- touched $MEM_WANT bytes, measured $MEM_GOT"

# ---------------------------------------------------------------------------
# machine and tool versions
# ---------------------------------------------------------------------------

CPU="$(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo unknown)"
CORES="$(sysctl -n hw.ncpu 2>/dev/null || echo '?')"
MEMTOTAL="$(python3 -I -c '
import subprocess
try:
    b = int(subprocess.check_output(["sysctl", "-n", "hw.memsize"]).strip())
    print("%.0f GiB" % (b / 1073741824.0))
except Exception:
    print("unknown")
')"
OSNAME="$(uname -s) $(uname -r)"
OSVER="$(sw_vers -productVersion 2>/dev/null || echo '')"
OSBUILD="$(sw_vers -buildVersion 2>/dev/null || echo '')"
ARCH="$(uname -m)"
CXXVER="$(${CXX:-clang++} --version 2>/dev/null | head -1)"
MAKEVER="$(make --version 2>/dev/null | head -1)"
PYVER="$(python3 --version 2>&1)"
SSLVER="$(openssl version 2>/dev/null || echo 'not present')"
FSTYPE="$(df -T 2>/dev/null | tail -1 | awk '{print $2}' || true)"
if [ -z "$FSTYPE" ]; then
  FSTYPE="$(diskutil info / 2>/dev/null | awk -F': *' '/File System Personality/{print $2}' || echo unknown)"
fi
WHEN="$(date -u '+%Y-%m-%d %H:%M UTC')"
GITREV="$(cd "$REPO" && git rev-parse --short HEAD 2>/dev/null || echo unknown)"
if [ -n "$(cd "$REPO" && git status --porcelain 2>/dev/null)" ]; then
  # Said out loud, because otherwise the report names a commit whose contents
  # are not the ones that were measured.
  GITREV="$GITREV + uncommitted changes"
fi

# ---------------------------------------------------------------------------
# 1. SHA-256 throughput, ours against the system's
# ---------------------------------------------------------------------------

note "bench: SHA-256 throughput"
repeat "" -- "$BIN/bench_sha256" --mib "$SHA_MIB"
read -r SHA_MED SHA_MIN SHA_MAX <<<"$(collect sha256_mb_per_second)"

head -c $((SHA_MIB * 1024 * 1024)) /dev/urandom >"$WORK/blob.bin"

# time_tool <command...> -> MB/s over $RUNS runs, median
time_tool() {
  : >"$WORK/values"
  local i=1
  while [ "$i" -le "$RUNS" ]; do
    local secs
    secs="$( { /usr/bin/time -p "$@" >/dev/null; } 2>&1 | awk '/^real/{print $2}')"
    python3 -I -c '
import sys
s = float(sys.argv[1]); m = float(sys.argv[2])
print("%.6f" % (m / s if s > 0 else 0))
' "$secs" "$SHA_MIB" >>"$WORK/values"
    printf '.' >&2
    i=$((i + 1))
  done
  printf ' \n' >&2
  stats <"$WORK/values"
}

SHASUM_MED=""
if command -v shasum >/dev/null 2>&1; then
  note "bench: shasum -a 256"
  read -r SHASUM_MED _ _ <<<"$(time_tool shasum -a 256 "$WORK/blob.bin")"
fi
SSL_MED=""
if command -v openssl >/dev/null 2>&1; then
  note "bench: openssl dgst -sha256"
  read -r SSL_MED _ _ <<<"$(time_tool openssl dgst -sha256 "$WORK/blob.bin")"
fi

# ---------------------------------------------------------------------------
# 2. append throughput, per sync policy
# ---------------------------------------------------------------------------

note "bench: append, --sync every ($SYNC_RECORDS records x $RUNS)"
repeat "$WORK/ap-every-" -- "$BIN/bench_append" --count "$SYNC_RECORDS" \
  --policy every --size 100
read -r AP_EVERY_MED AP_EVERY_MIN AP_EVERY_MAX <<<"$(collect append_per_second)"
read -r AP_EVERY_US _ _ <<<"$(collect append_us_each)"

note "bench: append, --sync batch:100"
repeat "$WORK/ap-b100-" -- "$BIN/bench_append" --count "$SMALL_RECORDS" \
  --policy batch --batch 100 --size 100
read -r AP_B100_MED AP_B100_MIN AP_B100_MAX <<<"$(collect append_per_second)"

note "bench: append, --sync batch:1000"
repeat "$WORK/ap-b1k-" -- "$BIN/bench_append" --count "$SMALL_RECORDS" \
  --policy batch --batch 1000 --size 100
read -r AP_B1K_MED AP_B1K_MIN AP_B1K_MAX <<<"$(collect append_per_second)"

note "bench: append, --sync none"
repeat "$WORK/ap-none-" -- "$BIN/bench_append" --count "$SMALL_RECORDS" \
  --policy none --size 100
read -r AP_NONE_MED AP_NONE_MIN AP_NONE_MAX <<<"$(collect append_per_second)"
read -r AP_NONE_US _ _ <<<"$(collect append_us_each)"
AP_RSS="$(key_from "$WORK/run.1" peak_rss_bytes)"

# ---------------------------------------------------------------------------
# 3. verify, at two sizes
# ---------------------------------------------------------------------------

note "bench: building a $SMALL_RECORDS-record corpus (--sync none)"
"$BIN/bench_append" --dir "$WORK/small" --count "$SMALL_RECORDS" \
  --policy none --size 100 >"$WORK/small.txt" || exit 2
SMALL_BYTES="$(key_from "$WORK/small.txt" append_log_bytes)"

note "bench: verify, $SMALL_RECORDS records"
repeat "" -- "$BIN/bench_verify" --dir "$WORK/small"
read -r V_SMALL_MED V_SMALL_MIN V_SMALL_MAX <<<"$(collect verify_seconds)"
read -r V_SMALL_RPS _ _ <<<"$(collect verify_records_per_second)"
read -r V_SMALL_MBPS _ _ <<<"$(collect verify_mb_per_second)"
read -r O_SMALL_MED _ _ <<<"$(collect open_seconds)"
V_SMALL_RSS="$(key_from "$WORK/run.1" peak_rss_bytes)"

note "bench: building a $BIG_RECORDS-record corpus (--sync none; this takes a while)"
"$BIN/bench_append" --dir "$WORK/big" --count "$BIG_RECORDS" \
  --policy none --size 100 >"$WORK/big.txt" || exit 2
BIG_BYTES="$(key_from "$WORK/big.txt" append_log_bytes)"
BIG_BUILD="$(key_from "$WORK/big.txt" append_seconds)"

note "bench: verify, $BIG_RECORDS records"
repeat "" -- "$BIN/bench_verify" --dir "$WORK/big"
read -r V_BIG_MED V_BIG_MIN V_BIG_MAX <<<"$(collect verify_seconds)"
read -r V_BIG_RPS _ _ <<<"$(collect verify_records_per_second)"
read -r V_BIG_MBPS _ _ <<<"$(collect verify_mb_per_second)"
read -r O_BIG_MED _ _ <<<"$(collect open_seconds)"
V_BIG_RSS="$(key_from "$WORK/run.1" peak_rss_bytes)"

# ---------------------------------------------------------------------------
# 4. Merkle
# ---------------------------------------------------------------------------

note "bench: Merkle, 1024 leaves (the default block size)"
repeat "" -- "$BIN/bench_merkle" --leaves 1024 --proofs 1024
read -r M_1K_BUILD _ _ <<<"$(collect merkle_build_seconds)"
read -r M_1K_US _ _ <<<"$(collect merkle_proof_plus_verify_us_each)"
M_1K_STEPS="$(key_from "$WORK/run.1" merkle_proof_max_steps)"
M_1K_WIRE="$(key_from "$WORK/run.1" merkle_proof_max_wire_bytes)"
M_1K_RSS="$(key_from "$WORK/run.1" peak_rss_bytes)"
M_1K_LEVELS="$(key_from "$WORK/run.1" merkle_levels)"

note "bench: Merkle, $MERKLE_BIG leaves"
repeat "" -- "$BIN/bench_merkle" --leaves "$MERKLE_BIG" --proofs 2000
read -r M_BIG_BUILD M_BIG_BUILD_MIN M_BIG_BUILD_MAX <<<"$(collect merkle_build_seconds)"
read -r M_BIG_US M_BIG_US_MIN M_BIG_US_MAX <<<"$(collect merkle_proof_plus_verify_us_each)"
M_BIG_STEPS="$(key_from "$WORK/run.1" merkle_proof_max_steps)"
M_BIG_WIRE="$(key_from "$WORK/run.1" merkle_proof_max_wire_bytes)"
M_BIG_LEVELS="$(key_from "$WORK/run.1" merkle_levels)"
M_BIG_RSS="$(key_from "$WORK/run.1" peak_rss_bytes)"
M_BIG_LEAF_RSS="$(key_from "$WORK/run.1" merkle_rss_after_leaves_bytes)"

# ---------------------------------------------------------------------------
# the report
# ---------------------------------------------------------------------------

note "bench: writing $OUT"
: >"$OUT"

say "# ChainLog benchmark results"
say ""
say "**Generated by \`bench/run.sh\`. Do not edit by hand.** Every number below"
say "came from a program in \`bench/\`, run on the machine described here."
say "Regenerate with:"
say ""
say '```bash'
say "make bench"
say '```'
say ""
say "Medians over **$RUNS runs**, with the full range shown so the spread is"
say "visible. Medians rather than means: one unlucky run moves a mean and"
say "barely moves a median."
say ""
say "## Machine"
say ""
say "| | |"
say "|---|---|"
say "| measured | $WHEN |"
say "| commit | \`$GITREV\` |"
say "| CPU | $CPU ($CORES cores) |"
say "| memory | $MEMTOTAL |"
say "| arch | $ARCH |"
say "| OS | $OSNAME${OSVER:+, macOS $OSVER}${OSBUILD:+ ($OSBUILD)} |"
say "| filesystem | $FSTYPE |"
say "| compiler | $CXXVER |"
say "| make | $MAKEVER |"
say "| python | $PYVER |"
say "| openssl | $SSLVER |"
say ""
say "Built at \`-O2\`, no sanitizers. The test build uses ASan and UBSan, which"
say "roughly halve throughput; benchmarking that would measure the sanitizer."
say ""
say "## SHA-256 throughput"
say ""
say "| implementation | MB/s (median) | range |"
say "|---|---|---|"
say "| ChainLog, hand-written | **$(fmt "$SHA_MED")** | $(fmt "$SHA_MIN") – $(fmt "$SHA_MAX") |"
if [ -n "$SHASUM_MED" ]; then
  say "| \`shasum -a 256\` | $(fmt "$SHASUM_MED") | |"
fi
if [ -n "$SSL_MED" ]; then
  say "| \`openssl dgst -sha256\` | $(fmt "$SSL_MED") | |"
fi
say ""
say "Hashing $SHA_MIB MiB in 64 KiB chunks. The \`openssl\` figure includes"
say "process startup and file I/O, so it understates the library slightly."
say ""
say "This is the honest cost of the project's main constraint. \`openssl\` uses"
say "the ARMv8 cryptographic extensions -- single instructions for the SHA-256"
say "round function -- and this implementation does not. The gap is the price"
say "of writing it by hand, and it is the right trade for a project whose"
say "purpose is understanding the construction."
say ""
say "## Append throughput"
say ""
say "| sync policy | appends/s (median) | range | µs each |"
say "|---|---|---|---|"
say "| \`every\` (default, 3 fsyncs) | **$(fmt "$AP_EVERY_MED")** | $(fmt "$AP_EVERY_MIN") – $(fmt "$AP_EVERY_MAX") | $(fmt "$AP_EVERY_US") |"
say "| \`batch:100\` | $(fmt "$AP_B100_MED") | $(fmt "$AP_B100_MIN") – $(fmt "$AP_B100_MAX") | |"
say "| \`batch:1000\` | $(fmt "$AP_B1K_MED") | $(fmt "$AP_B1K_MIN") – $(fmt "$AP_B1K_MAX") | |"
say "| \`none\` | $(fmt "$AP_NONE_MED") | $(fmt "$AP_NONE_MIN") – $(fmt "$AP_NONE_MAX") | $(fmt "$AP_NONE_US") |"
say ""
say "100-byte records. \`every\` measured over $SYNC_RECORDS appends per run"
say "(it is slow enough that more would add minutes); the others over"
say "$SMALL_RECORDS. The final \`flush()\` is inside the measured window for"
say "every policy, so a batched run is not flattered by work it had not done"
say "yet."
say ""
say "**What this is actually measuring.** The default policy issues three"
say "\`fcntl(F_FULLFSYNC)\` calls per append -- one for the write-ahead log, one"
say "for the main log, one after clearing the WAL. At $(fmt "$AP_EVERY_US") µs"
say "per append that is roughly $(python3 -I -c "print('%.1f' % (float('$AP_EVERY_US')/3000.0))") ms"
say "per barrier, which is the drive being asked to flush its own write cache."
say "Plain \`fsync()\` on APFS does not do that, which is why this project uses"
say "\`F_FULLFSYNC\` and why the number looks the way it does."
say ""
say "Peak RSS for an append run: **$(mib "$AP_RSS") MiB**, independent of"
say "record count -- appending is O(1) in memory apart from the pending"
say "block's hashes."
say ""
say "## Verify"
say ""
say "| records | log size | open (s) | verify (s) | range | records/s | MB/s | peak RSS |"
say "|---|---|---|---|---|---|---|---|"
say "| $SMALL_RECORDS | $(mib "$SMALL_BYTES") MiB | $(fmt "$O_SMALL_MED") | **$(fmt "$V_SMALL_MED")** | $(fmt "$V_SMALL_MIN") – $(fmt "$V_SMALL_MAX") | $(fmt "$V_SMALL_RPS") | $(fmt "$V_SMALL_MBPS") | $(mib "$V_SMALL_RSS") MiB |"
say "| $BIG_RECORDS | $(mib "$BIG_BYTES") MiB | $(fmt "$O_BIG_MED") | **$(fmt "$V_BIG_MED")** | $(fmt "$V_BIG_MIN") – $(fmt "$V_BIG_MAX") | $(fmt "$V_BIG_RPS") | $(fmt "$V_BIG_MBPS") | $(mib "$V_BIG_RSS") MiB |"
say ""
say "\`open\` and \`verify\` are separated because they do different work."
say "\`open\` walks every frame checking the magic, the lengths and the CRC-32"
say "but computes no SHA-256. \`verify\` recomputes every record hash, every"
say "chain link and every Merkle root. The difference is the hashing."
say ""
say "**Peak RSS does not grow with the log.** Verify streams frames and holds"
say "only the current block's leaf hashes -- 1024 x 32 bytes at the default"
say "block size, so 32 KiB regardless of whether the log has a thousand"
say "records or a million. That is the one design decision in the project that"
say "shows up directly as a measured number."
say ""
say "The $BIG_RECORDS-record corpus was built with \`--sync none\` in"
say "$(fmt "$BIG_BUILD") s. At the default policy it would have taken about"
say "$(python3 -I -c "print('%.0f' % (float('$BIG_RECORDS')/float('$AP_EVERY_MED')/60.0))") minutes,"
say "which is itself a useful illustration of what the barriers cost."
say ""
say "## Merkle trees and proofs"
say ""
say "| leaves | levels | build (s) | proof steps | proof on the wire | proof+verify (µs) |"
say "|---|---|---|---|---|---|"
say "| 1024 | $M_1K_LEVELS | $(fmt "$M_1K_BUILD") | $M_1K_STEPS | $M_1K_WIRE B | **$(fmt "$M_1K_US")** |"
say "| $MERKLE_BIG | $M_BIG_LEVELS | $(fmt "$M_BIG_BUILD") | $M_BIG_STEPS | $M_BIG_WIRE B | **$(fmt "$M_BIG_US")** |"
say ""
say "1024 leaves is the real case: it is the default block size, so it is the"
say "tree an inclusion proof is actually built over. $MERKLE_BIG leaves is"
say "there because the brief asks for it, and because it shows the shape of"
say "the curve."
say ""
RATIO="$(python3 -I -c "print('%.0f' % ($MERKLE_BIG / 1024.0))")"
DOUBLINGS="$(python3 -I -c "
import math
print(int(round(math.log2($MERKLE_BIG / 1024.0))))")"
EXTRA_STEPS=$((M_BIG_STEPS - M_1K_STEPS))
say "**The proof grew from $M_1K_STEPS steps to $M_BIG_STEPS for a tree"
say "${RATIO}x larger.** That is the O(log n) claim as a measurement rather"
say "than an assertion: $DOUBLINGS doublings of the leaf count added"
say "$EXTRA_STEPS hashes. On the wire a proof for the $MERKLE_BIG-leaf tree is"
say "$M_BIG_WIRE bytes, including the 26-byte self-describing header and the"
say "4-byte CRC-32."
say ""
say "Build peak RSS at $MERKLE_BIG leaves was $(mib "$M_BIG_RSS") MiB, of"
say "which $(mib "$M_BIG_LEAF_RSS") MiB is the leaf array itself. The tree"
say "holds every level, so it is roughly 2n nodes. At the default block size"
say "of 1024 this is $(mib "$M_1K_RSS") MiB and entirely uninteresting; the"
say "large figure is the cost of the benchmark's unrealistic tree, not of the"
say "log."
say ""
say "## Not measured"
say ""
say "Stated explicitly so nothing here is read as covering it:"
say ""
say "- **Concurrent readers and writers.** The lock serialises writers and"
say "  nothing has been measured under contention."
say "- **Cold cache.** Every verify run above reads a file the OS has just"
say "  written, so the figures are warm-cache. A cold read would be bounded by"
say "  the device, not by hashing."
say "- **Spinning disks, network filesystems, or any machine but this one.**"
say "  \`F_FULLFSYNC\` costs are hardware-specific and these numbers do not"
say "  transfer."
say "- **\`prove\` on a large log.** \`prove\` walks the log from the start to"
say "  reach a block, which is O(records before it); only the in-memory tree"
say "  work is measured above."
say "- **HMAC signing overhead on append.** One MAC per sealed block is far"
say "  below the noise floor of a single fsync, so it was not isolated."

note ""
note "bench: done -- $OUT"
cat "$OUT"
