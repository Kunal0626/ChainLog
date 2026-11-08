# ChainLog: design decisions and interview notes

Part 1 is every decision that had a real alternative, with the alternative and
why it lost. Part 2 is the fifteen hardest questions I think an interviewer
could ask, with short answers.

Where a claim here is backed by a test, the test is named, so it can be run.

---

# Part 1 — design decisions

## Scope

### Detection, not prevention

**Chosen:** make tampering *detectable*.
**Rejected:** try to make the log *immutable* — append-only file attributes,
a write-only daemon, a kernel module.

Prevention is a property of the operating system and the hardware, not of a
file format. If the attacker is root, or the service account that owns the
log, nothing in a file format stops them writing bytes. What a format *can*
do is guarantee that a modification leaves evidence — and for an audit log
that is usually the promise that matters: you are not trying to stop an
insider editing the log, you are trying to find out if they did.

The honest consequence, which I state up front rather than burying: the
guarantee only holds if **one value from the log has escaped the attacker's
control.** Everything else in the project is machinery for making that
sufficient.

## The record format

### The hashed bytes and the on-disk bytes are different

**Chosen:** a canonical *preimage* that gets hashed, wrapped in a *frame* that
gets written.
**Rejected:** hash the frame.

If framing were inside the hash, the framing could never change without
invalidating every historical hash. Keeping it outside means a future format
version can alter the magic, add a length field, or switch to a different
checksum, and every record ever written still verifies.

### The data length is written before the data

**Chosen:** fixed-width length prefix on `data`.
**Rejected:** no prefix, relying on the field layout.

The usual one-line justification — "so two different records can't hash to the
same bytes" — is **incomplete, and worth getting right** because it is exactly
what a good interviewer probes.

In *this* layout `data` is the only variable-length field and it sits between
two fixed-width runs, so its length is already recoverable from the total
preimage length — and SHA-256's padding commits to that total length. So for
version 1 the prefix is belt-and-braces.

It earns its place anyway, for the reason that generalises: the moment a second
variable-length field exists, the unprefixed encoding genuinely collides.
`actor="ab", data="c"` and `actor="a", data="bc"` both serialise to `abc`, and
nothing about the field layout warns you. The prefix makes injectivity a
property of the **encoding you can read off the page**, not one contingent on
an argument about the layout plus the hash function's padding rule.

→ `length_prefix_is_what_keeps_the_encoding_injective` in
`tests/test_record.cpp` exhibits that collision.

### Fixed-width little-endian integers

**Chosen:** explicit byte-by-byte little-endian.
**Rejected:** `memcpy` a `uint64_t`; varints.

`memcpy` is faster and gives different hashes on a big-endian machine — the
same record would verify on one architecture and fail on another. Varints
would save bytes and reintroduce an encoding where two byte strings can mean
the same number, which is the opposite of what a hash preimage needs.

→ `integers_are_little_endian_regardless_of_host` writes the expected bytes
out by hand rather than deriving them from the helper under test.

### The record's own hash is stored, though it is derivable

**Chosen:** store it. 32 bytes per record of pure redundancy.
**Rejected:** recompute on read and save the space.

It buys a better error message. When `verify` finds a mismatch, comparing
*stored* against *recomputed* distinguishes "the data was edited" from "the
hash field was edited". Without it, both look the same.

### CRC-32 as well as SHA-256

**Chosen:** both, answering different questions.
**Rejected:** SHA-256 alone (the CRC looks redundant); CRC alone (far cheaper).

**CRC-32 needs no secret**, so it provides zero tamper resistance — an
attacker recomputes it for free. What it provides is cheap detection of
*incomplete writes* and random corruption, and crucially the **position** of a
CRC failure is itself information: a bad CRC at end of file is a crash, the
identical bad CRC mid-file is corruption or an attack.

Drop the CRC and a half-written final record becomes indistinguishable from a
forged one — and recovery then has no safe way to decide whether to finish it
or discard it. That decision is the whole point of the WAL.

### Two independent length fields

**Chosen:** `payload_len` in the frame *and* `data_len` in the preimage, with
the decoder requiring `data_len + 88 == payload_len`.
**Rejected:** derive one from the other.

The redundancy becomes a consistency check rather than waste, and it is the
cheapest possible guard against a flipped bit in either field.

### A 16 MiB cap on record data

**Chosen:** reject any frame implying more.
**Rejected:** trust the length field.

A length read off disk must never be trusted enough to drive an allocation.
Without the cap, one flipped bit in `payload_len` becomes a multi-gigabyte
`malloc`; with it, it becomes a clean `bad-frame-length`.

→ `a_corrupted_frame_length_does_not_become_a_huge_allocation`.

## Verification

### Chain on the recomputed hash, never the stored one

**Chosen:** `prev = compute_record_hash(r)`.
**Rejected:** `prev = r.hash`.

This is the difference between a useful error and a misleading one. Edit
record *i*'s stored hash field and chaining on the recomputed value reports
`bad-hash` at exactly *i* — the record that was modified. Chaining on the
stored value reports a broken link at *i+1*, pointing the investigator at the
one record nobody touched.

→ `editing_a_stored_hash_blames_that_record_not_the_next_one`.

### Stop at the first failure

**Chosen:** report the first bad index, byte offset and reason.
**Rejected:** report every failure.

The chain is sequential, so one altered record makes every later link
mismatch. On a 100k-record log, "all failures" is 99,980 lines of consequence
and one line of cause.

### Check index before the link

**Chosen:** index sequence, then `prev_hash`, then the record hash.
**Rejected:** hashes first.

A deleted record fails both checks. `bad-index` says "a record is missing",
which is actionable; `broken-link` says "a hash did not match", which makes
you work out why.

### `verify` is O(block) in memory, not O(n)

**Chosen:** stream frames, hold only the current block's leaf hashes.
**Rejected:** load all record hashes and build one tree over the whole log.

At the default 1,024-record block that is 32 KiB regardless of the log's
length. The alternative is 32 MB of leaves at a million records and 32 GB at a
billion. **Measured: peak RSS 2.3 MiB at both 100k and 1M records** —
identical, which is this decision showing up as a number.

### An O(n) scan at `open()` rather than a cached head

**Chosen:** walk every frame on open (framing only, no SHA-256).
**Rejected:** keep the head index and hash in a small separate file.

A cache is a second source of truth that can disagree with the log — exactly
the class of bug this project exists to detect. If the cache said "10,000
records ending in hash X" and the log held 9,998, which do you believe? And
an attacker who can write the log can usually write the cache.
**Measured: 0.53 s to open a 1M-record log**, against 1.72 s to verify it, so
it is not the bottleneck.

## Merkle trees

### RFC 6962 domain separation

**Chosen:** `leaf = SHA256(0x00 ‖ x)`, `node = SHA256(0x01 ‖ l ‖ r)`.
**Rejected:** no prefixes.

An inner node hashes 64 bytes — two concatenated digests. Without the
prefixes that input is byte-identical to a *leaf* whose payload happens to be
64 bytes, so an attacker could hand over an interior node and have it accepted
as a leaf, proving membership of something never appended.

→ `domain_separation_keeps_leaves_and_inner_nodes_apart`.

### Promote a lone odd node; never duplicate it

**Chosen:** carry it up unchanged, as RFC 6962 does.
**Rejected:** hash it with a copy of itself, as Bitcoin does.

Duplication is **CVE-2012-2459**. Three leaves A, B, C give
`H(H(A,B), H(C,C))`, byte-identical to the root of the **four**-leaf tree
A, B, C, C. The root stops uniquely committing to the leaf list: two different
histories share a root and an inclusion proof becomes ambiguous. Promotion
avoids it because the tree's shape then depends only on *n*, and *n* is
committed in the checkpoint beside the root.

→ `duplicating_the_odd_node_collides` builds the unsafe variant and exhibits
the collision at sizes 3 and 5, rather than asserting the claim.

### Build bottom-up level by level, and prove it is the RFC's tree

**Chosen:** iterative level-by-level build in a flat vector.
**Rejected:** RFC 6962's recursive `MTH` in production.

They produce the same tree, and the reason is worth knowing: a partial node at
level *j* covers *r* leaves, and either `r ≤ 2^(j-1)` (promoted, so it *is*
its child) or `2^(j-1) < r ≤ 2^j` (splits at `2^(j-1)`, which is exactly the
largest power of two below *r*).

That is checked rather than assumed, twice:
`iterative_build_matches_rfc6962_recursive_mth` compares against the recursive
definition for every size up to 257, and `tests/oracle_format.py` re-derives
proofs in Python with the recursive `PATH` — `make oracle` requires
**byte-identical** output. Agreeing on bytes between a recursive and an
iterative implementation means the fast build really *is* RFC 6962's tree, not
merely *a* tree.

### A flat vector with level offsets

**Chosen:** one allocation, offsets per level.
**Rejected:** `vector<vector<Digest>>`.

Node count is under 2n, so a 1M-leaf tree is one ~67 MB allocation instead of
21 smaller ones. **Measured: 97.5 MiB peak for a 1,048,576-leaf tree**, of
which 33.3 MiB is the leaf array. At the real block size of 1,024 it is
1.5 MiB and uninteresting — the large figure is the benchmark's unrealistic
tree, not the log's.

### Proofs only for sealed blocks

**Chosen:** `prove` on an unsealed record fails, naming the last sealed index.
**Rejected:** build an ephemeral root over the partial block.

A Merkle root is worth something only if somebody already trusts it. A root
over the partial block exists nowhere else — not in the checkpoints file, not
in an anchor, not in anyone's email. A proof against it would be proving a
statement to the only party who computed both sides.

### `verify-proof` needs the whole record, not just the data

**Chosen:** require `--timestamp` and `--prev-hash` as well as the data.
**Rejected:** accept a bare leaf hash.

A leaf is
`SHA256(0x00 ‖ SHA256(index ‖ timestamp ‖ len ‖ data ‖ prev_hash))`. Taking a
leaf hash would be a smaller command line and would hide the fact that **a
leaf commits to the whole record** — the property that makes the proof worth
anything. `prove` prints a paste-ready command with every field filled in, so
the honest interface costs the user nothing.

### A self-describing proof blob with its own CRC-32

**Chosen:** version, `first_index`, `tree_size`, `leaf_index`, the steps, and
a CRC.
**Rejected:** just the sibling hashes.

The CRC means a mangled copy-paste reads as **"corrupt proof"** (exit 2)
rather than **"proof does not verify"** (exit 1). Those are different answers
and an operator needs to tell them apart — the same accident-versus-attack
split as the record frame.

## The write-ahead log

### A WAL at all

**Chosen:** stage every record in `log.wal` before touching `log`.
**Rejected:** write straight to the log and let `verify` report a torn tail.

The hash chain already makes a torn tail *detectable*. What it cannot do is
make an interrupted append *recoverable*. After a crash inside the main write,
the chain sees a half-written frame but cannot answer the only question that
matters: **was that record ever supposed to exist?** It can neither safely
finish it (it does not know the missing bytes) nor safely discard it (the
caller may have been told the append succeeded). The WAL holds that answer.

### The staged frame is byte-identical to the log's

**Chosen:** the same frame, same magic, same CRC.
**Rejected:** a separate WAL record format with its own header per entry.

There is no second format to get wrong, and recovery can compare the staged
frame against the log's tail directly.

### A torn WAL frame is dropped, not replayed

**Chosen:** discard it.
**Rejected:** try to salvage it; report it as damage.

A torn frame means step 1's fsync never returned, so `append()` never reported
success and **nobody was ever told the record existed**. Dropping it is the
correct resolution, not data loss. This is also why the staged frame needs its
own CRC: without one, a half-written staged record is indistinguishable from a
complete one.

→ `a_torn_staged_frame_is_dropped_at_every_cut_point`.

### At most one unsealed block is repaired; more is reported

**Chosen:** re-seal exactly one missing trailing checkpoint, report two or
more.
**Rejected:** always re-derive whatever is missing.

Sealing happens *inside* `append()`, after the record's fsync and before the
next record can be written, so a crash can leave one complete block unsealed
and never two. If two are missing, the file was truncated or edited — and
re-deriving those roots would **destroy the very evidence** that catches the
re-link attack, because the old roots are what contradict the attacker.

→ `deleting_the_last_two_checkpoints_is_reported_not_repaired`.

### `F_FULLFSYNC`, not `fsync`

**Chosen:** `fcntl(fd, F_FULLFSYNC)` with an `fsync` fallback.
**Rejected:** plain `fsync`.

On macOS/APFS, `fsync` pushes data to the drive but does **not** order the
drive to flush its own write cache. A log that calls plain `fsync` and claims
crash safety is lying on this hardware. **Measured: ~2 ms per barrier**, which
is what that correctness costs.

### `_exit`, not `exit`, in the injected crash

**Chosen:** `_exit(99)`.
**Rejected:** `exit(99)`, `abort()`, a signal.

`exit()` runs `atexit` handlers and flushes stdio, so the buffered
`index=7 hash=…` line would still reach the caller: the process would report a
successful append and *then* vanish. That is not a crash, it is a lie.
`_exit` is the closest thing available to pulling the power.

### Fault injection ships in the release binary

**Chosen:** `$CHAINLOG_CRASH_AT` compiled in, with an unrecognised value a
hard error.
**Rejected:** `-DFAULT_INJECTION`.

A separate build would exercise code paths nobody runs, which is the opposite
of what a crash test is for. The exposure is narrow: someone who can set your
environment variables can also replace your binary. And a mistyped crash
point must be loud, because a silent no-op would make every crash test pass
while injecting nothing.

## Locking and access

### Advisory `flock`, non-blocking, with a read-only fallback

**Chosen:** `LOCK_EX|LOCK_NB` for writers, `LOCK_SH` for read-only opens;
`O_RDWR` falling back to `O_RDONLY` when the filesystem or permissions refuse.
**Rejected:** blocking locks; `fcntl` record locks; refusing to open a log you
cannot write.

Non-blocking because a second writer should be *told* the log is busy, not
queued behind an appender that may run for hours. The read-only fallback
because refusing to inspect an archived log would make the verifier useless in
exactly the case where you most want it.

`flock` is advisory — it protects against two cooperating ChainLog processes
and nothing else. It does nothing about `dd`, and it is historically unreliable
over NFS. It is **not** an integrity mechanism.

An `flock` belongs to the *open file description*, not the process, so two
`open()` calls in one process contend exactly as two processes do. That is how
the tests check contention without forking — and why `Log::close()` exists.

## Anchoring and signing

### Anchors and keys close different holes

**Chosen:** both, and documented as non-interchangeable.
**Rejected:** treating them as alternatives.

- **An anchor** — a published `index:hash` — catches **truncation and
  rewriting**.
- **A key** — HMAC on each checkpoint — catches **rewriting only**.

A key does not catch truncation: an attacker who cuts the log at a block
boundary and drops the matching checkpoints leaves every surviving signature
perfectly genuine. **Nothing in the file says how many checkpoints there
should be.**

→ `signatures_do_NOT_catch_truncation_but_an_anchor_does`.

### The "must be signed" rule lives in the verifier

**Chosen:** `verify --key-file` *requires* every checkpoint signed; without a
key, signatures are not checked.
**Rejected:** a "signed" flag in the file header that readers must honour.

An attacker with write access can always rewrite a checkpoint as unsigned —
and rewrite the header bit that demanded signatures. A file cannot defend a
policy about itself. Only a verifier that insists catches the downgrade.

→ `stripping_the_signatures_is_caught_only_when_a_key_is_supplied`.

### HMAC, not `SHA256(key ‖ message)`

**Chosen:** HMAC-SHA256 (RFC 2104).
**Rejected:** a keyed hash by concatenation.

SHA-256 is Merkle–Damgård, so its output *is* its internal state. From
`H(key ‖ m)` and `len(key ‖ m)`, an attacker resumes that state and computes
`H(key ‖ m ‖ pad ‖ m')` for any `m'` — forging a tag without ever learning the
key. That is length extension, and it falls straight out of the padding rule
in `sha256.cpp`. HMAC's two nested hashes under different pads are immune.

### Key files hold hex

**Chosen:** hex, surrounding whitespace trimmed, minimum 16 bytes.
**Rejected:** raw bytes.

A key file written with `echo` picks up a trailing newline. Whether that
newline counts would silently change the key depending on how the file was
created — a bug that only shows up when someone regenerates the file a
different way. Hex is unambiguous and `openssl rand -hex 32` produces it.

### `sign` re-authenticates; it never re-derives

**Chosen:** HMAC the roots that are already on disk.
**Rejected:** recompute the roots from the records and sign those.

Recomputing would let `sign` launder a tampered log. As written, a stale root
stays stale and `verify` still reports the mismatch — signing authenticates
the *original* history, which is exactly right.

→ `sign_refuses_a_damaged_log` signs a re-linked log successfully and then
confirms `verify` still fails.

### Atomic replacement via `rename(2)`

**Chosen:** write `checkpoints.new`, fsync it, rename, fsync the directory.
**Rejected:** rewrite in place.

`sign` rewrites *every* frame, not just the tail, so there is no torn-tail
story to fall back on. `rename` is atomic within a filesystem, so a crash
leaves either the old file or the new one. The fsync *before* the rename is
what stops a crash leaving the published name pointing at an empty file.

## Interface

### Exit codes 0 / 1 / 2

**Chosen:** 0 ok, 1 does not verify, 2 could not check.
**Rejected:** 0 and non-zero.

"I checked and it is bad" and "I could not check" are different answers, and a
script that treats them alike will eventually report a permissions problem as
a security incident. A mangled proof is 2; an intact but wrong proof is 1.

### `verify` reports what it checked

**Chosen:** print `anchors_checked=` and `signatures_required=` on success.
**Rejected:** just print "ok".

"ok" means a great deal more with a key and an anchor behind it than without,
and an operator should not have to remember which flags they passed.

### A `SyncPolicy`, and a real user for it

**Chosen:** `kEveryAppend` / `kBatched(N)` / `kNone`, plus `chainlog import`.
**Rejected:** leaving batched sync as benchmark-only scaffolding; hiding a
flush so `--sync` appears safe.

The brief needed batched appends to measure. Rather than add an option with no
honest user, `import` reads one record per line of stdin, defaults to
`batch:1000`, and always flushes before reporting success — bulk migration is
a real need. A single `append` with `--sync` other than `every` prints a
warning that the record may not survive power loss, rather than silently
flushing and making the flag a lie.

### Timestamps are not verified

**Chosen:** store them; do not require them to increase.
**Rejected:** enforce monotonicity.

`CLOCK_REALTIME` legitimately steps backwards when NTP corrects it, so
enforcing monotonicity would turn a normal clock adjustment into a tamper
report. It would also buy nothing against the real attacker, who would fix the
timestamps too. Ordering comes from `index` and the chain. Provable *time*
needs a timestamping authority, which is outside this project.

## Testing

### Independent oracles for every hand-written primitive

**Chosen:** cross-check SHA-256, CRC-32, HMAC and the whole format against
other people's implementations — 1,432 comparisons.
**Rejected:** known-answer vectors only.

A suite written against the same code it tests will happily agree with a
construction that only exists in that code's head. The format oracle is the
strongest of the four: `tests/oracle_format.py` was written from
`docs/FORMAT.md`, not from the source, and it must agree on the head hash, the
record count, the *diagnosis name* for four kinds of damage, and byte-identical
proof blobs.

That last one also answers a question the C++ tests structurally cannot: **is
the format specified well enough for somebody else to implement it?**

### Limitations pinned as passing tests

**Chosen:** tests named `*_is_NOT_detected` that assert the gap exists.
**Rejected:** a prose list of caveats.

A caveat in a README rots silently. A green test named
`tamper_step6_rewriting_the_checkpoints_too_is_NOT_detected` cannot.

### Medians, and a unit check on the memory figure

**Chosen:** medians over 5 runs with the range shown; `bench_mem` gates the
whole report.
**Rejected:** means; trusting `ru_maxrss`.

One unlucky run moves a mean and barely moves a median. And `getrusage`
reports `ru_maxrss` in **bytes on Darwin and kilobytes on Linux** —
`bench/run.sh` touches a known 256 MiB and refuses to write any results unless
the measurement lands within a factor of two. A silent 1024× error in a memory
figure is exactly the number that ends up quoted where it cannot be corrected.

---

# Part 2 — the fifteen hardest questions

### 1. What exactly does your log guarantee, and what does it not?

It guarantees that **what is present has not changed** — given one value kept
outside the attacker's reach. It does *not* guarantee that nothing is missing
(truncation needs an anchor), that the records were *true* when written, that
they are confidential (data is plaintext), or that the log still exists
(anyone with write access can delete it). And if the attacker controls the
verifier or the machine you run it on, none of it helps.

### 2. Why length-prefix before hashing?

To make the encoding **injective** — one byte string per distinct record. Be
precise though: in my layout `data` is the only variable-length field between
two fixed-width runs, so its length is already recoverable, and SHA-256's
padding commits to the total length. The prefix matters because it makes
injectivity a property of the encoding you can check by looking at it, and
because the moment a second variable-length field exists the unprefixed
encoding genuinely collides — `("ab","c")` and `("a","bc")` both serialise to
`abc`.

### 3. Why domain-separate leaves and inner nodes?

An inner node hashes 64 bytes: two concatenated digests. Without the `0x00` /
`0x01` prefixes that is byte-identical to hashing a 64-byte *leaf payload*, so
an attacker could present an interior node as a leaf and "prove" membership of
something never appended. RFC 6962 §2.1 exists for this.

### 4. Why promote the odd node instead of duplicating it?

Duplication is CVE-2012-2459. Three leaves A,B,C give `H(H(A,B),H(C,C))`,
which is byte-identical to the root of the four-leaf tree A,B,C,C — so the root
stops uniquely committing to the leaf list, two histories share a root, and an
inclusion proof becomes ambiguous. Promotion makes the tree's shape a function
of *n* alone, and *n* is committed in the checkpoint.

### 5. Why is `fsync` needed, and what does `fsync` on a *directory* do?

`write()` returning means the kernel has the data, not the disk. `fsync` pushes
it down. A directory fsync is a different operation: a file's **name** is an
entry in its parent directory, which is separate metadata, so creating a file
and fsyncing only the file can leave you — after a crash — with a durable inode
that nothing points at. Since recovery consults the WAL *by name*, that would
defeat the point. On macOS there is a third layer: plain `fsync` does not order
the drive to flush its own write cache, so this project uses
`fcntl(F_FULLFSYNC)`.

### 6. What does the WAL protect against that the hash chain does not?

The chain makes a damaged log **detectable**; the WAL makes an interrupted
append **recoverable**. Those are different properties. After a crash inside
the main write, the chain sees a torn frame but cannot know whether that record
was ever meant to exist — so it can neither finish it nor discard it. The WAL
answers that: a *complete* staged frame means step 1's fsync returned, so the
record was durable before the log was touched and the append should be
completed; a *torn* staged frame means it never returned, nobody was told the
append succeeded, and the record is dropped.

### 7. What can a malicious admin with write access still do?

Rewrite the entire chain. Edit a record, re-hash it, re-link every record
after it, recompute every Merkle root, and — if they have the signing key —
re-sign every checkpoint. The result is a directory that is internally
flawless, because every check compares one part of it against another part the
attacker also controls. They can also truncate it, or delete it outright. The
*only* thing that catches them is a value they never had access to: a published
anchor. That is why `chainlog anchor` exists and why `docs/THREAT_MODEL.md`
leads with it.

### 8. Why is the proof O(log n)?

Verifying only requires recomputing the single path from leaf to root, and each
node on that path needs exactly one sibling to combine with. The tree has depth
⌈log₂ n⌉, so that is one 32-byte hash per level — fewer where a node was
promoted, since a promoted node has no sibling. **Measured: 10 steps at 1,024
leaves, 20 at 1,048,576.** Ten doublings added ten hashes.

### 9. Why does this resemble Certificate Transparency and git?

All three are the same structural idea. CT logs are append-only Merkle trees
with published *signed tree heads* — which is exactly what an anchor is here,
and CT's security argument is that monitors keep copies of old heads, i.e.
"store the anchor elsewhere". git is a hash chain of commits, each naming its
parent by hash; the reason you cannot quietly rewrite history in a repository
others have cloned is the same reason an anchor works — somebody else has the
old hash. A force-push is detectable for exactly the structural reason a
re-linked ChainLog is, and *undetectable* to someone who only ever sees the
rewritten copy.

### 10. Why HMAC instead of `SHA256(key ‖ message)`?

Length extension. SHA-256 is Merkle–Damgård, so its output is its internal
state. Given `H(key ‖ m)` and `len(key ‖ m)`, an attacker resumes from that
state and computes `H(key ‖ m ‖ pad ‖ m')` for a message of their choosing,
without knowing the key. HMAC's two nested hashes under the `0x36` and `0x5c`
pads break that: you can extend the inner hash but cannot produce the outer one
without the key.

### 11. Your verify peak RSS is identical at 100k and 1M records. Why isn't that suspicious?

Because it is what the code does by construction. `verify` drives a frame
cursor that buffers 256 KiB at a time and accumulates leaf hashes for the
**current block only** — 1,024 × 32 bytes — sealing and discarding at each
boundary. Nothing accumulates per record. The alternative, one tree over the
whole log, would be 32 MB of leaves at a million records. The constant figure
is the entire reason for sealing in fixed-size blocks.

### 12. Does a proof pin which tree it came from?

It pins the **position** exactly and the **tree size** only partly, and the
distinction is worth stating precisely. The left/right flags along a path are
the bits of the leaf index, least significant first, so within a given size no
two positions share a shape. But size changes the shape only where it changes
the *promotion pattern* on that path — leaf 19 has shape `LLRRLR` in trees of
36, 37, 38, 40, 48 and 64 leaves alike, and 36 of 37 leaves share a shape with
some other size. Forging membership is still infeasible (the root must come
out right), but a proof's self-reported `tree_size` is convenience, not a
committed fact. The size that counts comes from the trusted checkpoint.

### 13. You chain on the recomputed hash, not the stored one. Why does that matter?

Blame. Edit record *i*'s stored hash field: chaining on the recomputed value
reports `bad-hash` at exactly *i*, the record that was modified. Chaining on
the stored value would report a broken link at *i+1* — pointing the
investigator at the one record nobody touched. It also means a single tampered
record produces a single error rather than a cascade starting one record late.

### 14. If CRC-32 provides no tamper resistance, why is it in the format?

Because it answers a different question, cheaply: *did this write finish, and
did the bytes survive the disk?* It needs no secret, so an attacker recomputes
it for free — but a crash cannot. And the **position** of a CRC failure is
itself information: at end of file it is a torn write, mid-file it is
corruption or an attack. Without it, a half-written final record would be
indistinguishable from a forged one, and recovery would have no safe basis for
deciding between them.

### 15. If you had to make this 10× faster, where would you start, and what would you refuse to change?

Start with the thing I measured as dominant: the barriers. At `--sync every`
the log does 164 appends/s and 6.1 ms of that is three `F_FULLFSYNC` calls.
Group-commit — one barrier per batch of concurrent appends, acknowledging them
together — is the standard answer and buys most of the 42,000/s that `--sync
none` reaches, without giving up durability for acknowledged writes. Second,
SHA-256 via the ARMv8 extensions, behind the same interface with the
hand-written version kept as the reference the oracles check against; that is
a ~6× hashing win but only matters once the barriers are gone, since `verify`
is already bounded by framing at 111 MB/s. Third, `mmap` for the read path.

What I would refuse: storing a cached head in a second file, or dropping the
per-record stored hash. Both trade a measurable, bounded cost for a second
source of truth or a worse diagnosis — and on a tamper-evident log, a faster
answer that is harder to trust is not a better answer.

---

## Quick-fire, also likely

**How do you know your SHA-256 is right?** NIST known-answer vectors, plus
1,197 comparisons against `shasum` and `openssl` at every input length 0–130
and beyond. I also mutation-tested: a one-character off-by-one in the padding
boundary is caught by the oracle at lengths 56, 120 and 199,480, while the
chunk-consistency tests alone pass straight through it.

**Why not just use a database?** For an append-only integrity log a database is
mostly in the way — you would still implement the chain, the Merkle tree and
the anchoring yourself, and you would have added a server to trust. The pieces
I would genuinely borrow from a DBMS are the ones I did borrow: write-ahead
logging and a recovery protocol.

**What happens if two processes append at once?** The second fails to take the
exclusive `flock` and exits 2 with a message naming the directory. The lock is
advisory, so it protects against two cooperating ChainLog processes and nothing
else.

**Why is `block_size` in the file header?** Because the checkpoints are only
meaningful relative to it. If it were a compile-time constant, changing the
default would silently invalidate every existing log's checkpoints.

**What is the single weakest point?** Operational, not cryptographic: whether
anyone actually takes and stores anchors. Every interesting attack in the
threat model is caught by an anchor and by nothing else, and taking one is a
manual step that is easy to skip.
