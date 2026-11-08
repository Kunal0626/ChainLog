# Resume bullets

Every number below is traceable to a script in this repo. The source for each
is named, so if a number is challenged you can regenerate it on the spot.

Machine for all performance figures: Apple M3, 8 GiB, macOS 26.6.2, APFS,
Apple clang 21.0.0 at `-O2`, medians over 5 runs.
Regenerate with `make bench` → [`bench/RESULTS.md`](../bench/RESULTS.md).

---

## Bullet 1 — the engine

> **ChainLog — tamper-evident audit log engine (C++17, 14k lines).** Built a
> hash-chained append-only log with hand-written SHA-256, RFC 6962 Merkle
> trees and a write-ahead log (no cryptography library); verifies a
> 1,000,000-record log in **1.72 s** at a **constant 2.3 MiB** peak memory by
> streaming frames and sealing fixed-size Merkle blocks, and emits **690-byte
> O(log n)** inclusion proofs that verify with no access to the log.

**Where each number comes from**

| claim | source |
|---|---|
| 1.72 s for 1M records | `bench_verify`, median of 5 — `bench/RESULTS.md` |
| constant 2.3 MiB peak RSS | same run; 2.3 MiB at *both* 100k and 1M records |
| 690-byte proof, O(log n) | `bench_merkle --leaves 1048576`; 20 steps vs 10 at 1,024 leaves |
| 14k lines | `git ls-files \| xargs cat \| wc -l` → 14,401 |
| "no cryptography library" | OpenSSL appears only in `tests/oracle_*.sh` |

**Why the memory figure is the strong part.** It is identical at 100k and 1M
records, which is a design decision (stream frames, hold only the current
block's 1,024 leaf hashes) showing up as a measurement. That is a better thing
to be asked about than a throughput number, because the answer is an
architectural one.

---

## Bullet 2 — the verification discipline

> Validated the implementation against **independent** implementations rather
> than against itself: **1,432 cross-checks** of SHA-256, CRC-32 and HMAC
> against `shasum`, OpenSSL and Python, plus a from-specification Python
> parser required to emit **byte-identical** Merkle proofs; **421 assertions**
> in total, including fault injection that kills the process at each step of
> the append protocol and asserts exactly-once crash recovery across 12
> consecutive crash-and-recover rounds.

**Where each number comes from**

| claim | source |
|---|---|
| 1,432 cross-checks | 1,197 SHA-256 + 121 HMAC + 86 CRC-32 + 28 format — `make oracle` |
| 421 assertions | 144 unit + 119 CLI + 147 crash + 11 demo — `make test` |
| byte-identical proofs | `tests/oracle_format.sh`; recursive RFC 6962 `PATH` in Python vs the iterative C++ build |
| fault injection, 12 rounds | `tests/crash.sh`, `$CHAINLOG_CRASH_AT` |

**Why "independent" is the operative word.** A suite written against the same
code it tests will agree with a construction that only exists in that code's
head. The format oracle was written from `docs/FORMAT.md` rather than from the
source, which is also the only real evidence that the specification is
complete enough for someone else to implement.

---

## If you only have room for one line

> **ChainLog (C++17):** tamper-evident audit log — hand-written SHA-256, RFC
> 6962 Merkle trees, write-ahead log. Verifies 1M records in 1.72 s at
> constant 2.3 MiB; 690-byte O(log n) inclusion proofs; 421 assertions and
> 1,432 cross-checks against independent implementations.

---

## Claims to avoid, and what each would need

These are the things it is tempting to write and that I cannot currently
support. Listed so the temptation is on the record rather than in a bullet.

| tempting claim | **needs:** |
|---|---|
| "detects 100% of tampering" | False as stated. Truncation at a record boundary and a fully re-signed rewrite are both undetectable without an anchor — both are *passing tests* asserting the gap. The accurate claim is "detects any modification to the records present, and detects truncation and wholesale rewriting when an anchor is published." |
| "faster than X" / any cross-tool throughput comparison | A benchmark of X on the same machine. The only comparison measured is SHA-256 against `shasum` (413 MB/s) and OpenSSL (2,133 MB/s) — both of which are **faster** than the hand-written 345 MB/s, which is stated in the README rather than omitted. |
| "handles N appends/second" without qualification | Which sync policy. Measured: 164/s with full durability (three `F_FULLFSYNC` per append), 29,129/s at `batch:1000`, 42,017/s with no barriers. Quoting the large number without the policy would be misleading. |
| "production-ready" / "used in production" | A deployment. It has no users. |
| "scales to a billion records" | A measurement at that size. Measured to 1M. `verify` is O(n) time and O(block) memory so it should extrapolate, but `read_checkpoints` loads the whole checkpoints file (~60 MB at a billion records) and would need streaming first. |
| "crash-safe" without qualification | True only at `--sync every`. Under `batch:N` or `none` a crash can lose records and leave a torn tail that nothing currently repairs. |
| "cryptographically signed" | HMAC is a *symmetric* MAC: the verifier needs the same secret the signer used, so it cannot prove anything to a third party. A public-key signature (Ed25519) would, and is listed under future work. |
| any "reduced X by Y%" business metric | A before/after measurement in a real setting. There isn't one. |
