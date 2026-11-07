# ChainLog threat model

## The one-sentence version

ChainLog **detects** tampering with an audit log. It does not **prevent** it.
Anyone who can write to the log file can change it; the point is that they
cannot change it without leaving evidence — provided at least one value from
the log has been kept somewhere they could not reach.

That last clause is the whole design. Everything else is machinery for making
it true.

## Why detection and not prevention

Prevention means an attacker cannot modify the bytes. That is a property of the
operating system, the filesystem permissions, the disk — not of a file format.
If the attacker is root, or the service account the log belongs to, or someone
with the backup tapes, no amount of hashing stops them from writing whatever
they like.

What a format *can* do is make modification **detectable**. That is a weaker
promise and a much more achievable one, and for an audit log it is usually the
one that matters: you are not trying to stop an insider from editing the log,
you are trying to make sure that if they do, you find out.

## Who the attacker is

Four tiers, in increasing order of access. The interesting line is between
tier 2 and tier 3.

### Tier 0 — the storage medium

Not an attacker at all: bit rot, a bad sector, a torn write from a power cut, a
truncated `scp`.

**Caught by:** the magic number, the length fields and the CRC-32 on every
frame. These are cheap and they are *not* security mechanisms — see "CRC-32 is
not a MAC" below.

**Recovered from:** a torn frame at the end of the log is repaired using the
write-ahead log. A torn trailing checkpoint is recomputed, because a checkpoint
is derived data.

### Tier 1 — a bug in the application

The program using ChainLog appends nonsense, or appends the same thing twice, or
crashes half way through.

**Caught by:** nothing, and this is worth being clear about. ChainLog records
what it is told to record. A log of wrong facts, faithfully recorded and
correctly hashed, verifies perfectly. ChainLog guarantees that *what was
written has not changed since*, not that what was written was true.

**Mitigated by:** the WAL makes a crash mid-append recoverable, so a bug that
kills the process cannot leave the log unreadable.

### Tier 2 — someone who can read the log but not write it

An attacker who has exfiltrated a copy, or a curious user with read access.

**Caught by:** not applicable — they cannot change anything. But note what they
*can* do: read every record. **ChainLog provides integrity, not
confidentiality.** Record data is stored in the clear. If your audit records
contain anything sensitive, encrypt the data before you append it, or encrypt
the filesystem; ChainLog will happily hash ciphertext.

### Tier 3 — someone with write access to the log directory

The important one. A malicious administrator, a compromised service account, an
attacker who has got root on the machine that holds the log.

They can rewrite any byte of `log`, `checkpoints`, `log.wal` and `lock`. They
can delete files. They can replace the whole directory.

**Caught by:** this is what the escalation ladder below is about. Briefly: the
hash chain catches everything short of a complete, consistent rewrite; the
checkpoints raise the cost of that rewrite; and an anchor or a signing key
catches the rewrite itself — *if* that anchor or key lives outside the
directory they control.

**Not caught by:** anything kept inside the directory. Every check that
compares one part of the directory against another part is a check the
attacker controls both sides of.

### Tier 4 — someone with write access *and* the signing key

They can produce a log directory that is internally perfect and correctly
signed.

**Caught by:** only an anchor. There is a passing test named
`an_attacker_with_the_key_is_caught_only_by_an_anchor` that demonstrates
exactly this.

**Not caught by:** signatures, obviously — they have the key. This is why the
key belongs on a different machine, or in an HSM, or at minimum in a file the
log's own service account cannot read.

## CRC-32 is not a MAC

The most common misreading of this format is that the CRC-32 on each frame
provides some tamper resistance. It provides none.

CRC-32 needs no secret. An attacker who edits a frame recomputes the CRC for
free; it costs them one function call. The CRC is there to answer a completely
different question — *did this write finish, and did the bytes survive the
disk?* — and it answers it cheaply and well.

The division of labour:

| Mechanism | Answers | Needs a secret? |
|---|---|---|
| magic + length + CRC-32 | did this write complete, and are the bytes intact? | no |
| SHA-256 chain | has history been edited? | no |
| Merkle checkpoints | has history been edited *and* re-linked? | no |
| HMAC on checkpoints | has history been edited by someone without the key? | **yes** |
| anchor | has history been edited or shortened at all? | no, but needs a value kept elsewhere |

The position of a failure carries information too. A bad CRC at the end of the
file is a crash. The identical bad CRC in the middle of the file is corruption
or an attack.

## The escalation ladder

Each rung defeats the layer above it. Every row is a passing test in
`tests/test_log.cpp`, `tests/test_checkpoint.cpp` or `tests/test_anchor.cpp` —
including the ones that say "not detected", so they cannot quietly stop being
true.

| # | What the attacker does | Caught by | Reported as |
|---|---|---|---|
| 1 | flips a byte in a record | CRC-32 on the frame | `bad-crc` at that record |
| 2 | flips a byte, recomputes the CRC | the record's own SHA-256 | `bad-hash` at that record |
| 3 | also recomputes that record's hash | the *next* record's `prev_hash` | `broken-link` at *i+1* |
| 4 | re-links every record after it | the sealed Merkle roots, which still hold the old history | `bad-checkpoint` at the block |
| 5 | also re-seals every checkpoint | an HMAC they cannot forge | `bad-checkpoint` (signature) |
| 6 | strips the signatures instead | the verifier insisting on them (`--key-file`) | `bad-checkpoint` (not signed) |
| 7 | truncates at a frame boundary | **an anchor only** | `anchor-missing` |
| 8 | has the key, and re-signs everything | **an anchor only** | `anchor-mismatch` |

Rungs 1–3 are the hash chain. Rung 4 is why checkpoints are more than a proof
substrate — they are a second, independent record of history that an attacker
has to find and rewrite too. Rungs 5–6 are the signing key. Rungs 7–8 are the
anchor, and nothing else reaches them.

## Anchors and keys are not interchangeable

They close different holes, and mixing them up is the subtle mistake available
here.

**An anchor** is a published head value: "record 1,048,575 hashed to `a3f2…`".
Store it in a ticket, a git commit, an email to yourself, a different
machine, a printed sheet of paper. `verify --anchor 1048575:a3f2…` then fails
if the log is shorter than that, or if that record now hashes to anything else.

An anchor catches **truncation and rewriting**.

**A signing key** makes each checkpoint carry an HMAC. `verify --key-file`
then requires every checkpoint to be signed and valid, so an attacker who
rewrites history cannot produce checkpoints that match it.

A key catches **rewriting only**. It does **not** catch truncation: an attacker
who cuts the log at a block boundary and deletes the matching checkpoints
leaves every surviving signature perfectly genuine. Nothing in the file says
how many checkpoints there *should* be. `signatures_do_NOT_catch_truncation_but_an_anchor_does`
is that fact, as a test.

So:

- anchor only → full coverage of tiers 3 and 4, but you have to remember to
  take anchors
- key only → covers rewriting continuously and automatically, but truncation
  is invisible
- both → what you want, if the operational cost is acceptable

### Why the "must be signed" rule lives in the verifier

An attacker with write access can always rewrite a checkpoint as *unsigned*. A
file format cannot stop that — the file is theirs. So the requirement that
checkpoints be signed cannot live in the file; it has to live with the person
checking. That is why `verify` only demands signatures when you pass
`--key-file`, and why it then refuses unsigned checkpoints outright rather than
skipping them.

### Where to keep the key

Not in the log directory. A key an attacker can read is a key an attacker can
sign with, and at that point you are at tier 4 with extra steps.

```bash
openssl rand -hex 32 > ~/chainlog.key && chmod 600 ~/chainlog.key
```

`chainlog` warns if the key file is group- or world-readable. It warns rather
than refuses, because it is your key and your call.

## What is explicitly not protected

**Confidentiality.** Record data is plaintext. Encrypt before appending if it
matters.

**Availability.** Anyone with write access can `rm -rf` the directory.
Detection tells you the log is gone; it does not bring it back. Back it up.

**Timestamps.** The timestamp in each record comes from `CLOCK_REALTIME` and is
informational only. `verify` does **not** require timestamps to increase,
because NTP legitimately steps the clock backwards and treating that as
tampering would cry wolf. It would also buy nothing: an administrator rewriting
history would fix the timestamps too. The *ordering* guarantee comes from
`index` and the chain, not from the clock. If you need provable time, you need
a timestamping authority, which is outside this project.

**The verifier itself.** If the attacker controls the `chainlog` binary, or the
machine you run it on, or the terminal you read the output in, none of this
helps. Verify on a machine you trust, with a binary you trust.

**Concurrent writers that do not cooperate.** The `flock` on `lock` is
*advisory*: it stops two ChainLog processes from interleaving, and does nothing
about `dd`. It has also historically been unreliable over NFS. It is not an
integrity mechanism.

**Records that are wrong.** Covered under tier 1, but worth repeating because it
is the single most common misunderstanding of what an audit log proves.
ChainLog says "these bytes have not changed since they were written". It says
nothing about whether they were true when written.

## Why this resembles Certificate Transparency and git

Both are the same idea with different motivations, and the comparison is useful
for understanding what the structure buys.

**Certificate Transparency** logs are append-only Merkle trees with published
signed tree heads. ChainLog uses the same RFC 6962 hashing (including the
promotion rule and the `0x00`/`0x01` domain separation) for the same reason: so
a root uniquely commits to one list of entries, and so inclusion can be proved
in `O(log n)` without revealing the rest. A CT log's signed tree head is
precisely what an anchor is here — a value published where the log operator
cannot quietly change it. CT's whole security argument is that *monitors* keep
copies of old heads, which is the same argument as "store the anchor
elsewhere".

**git** is a hash chain of commits, where each commit names its parent by hash.
`git log` is a chain exactly like ChainLog's records, and the reason you cannot
quietly rewrite history in a repository others have cloned is the reason an
anchor works: somebody else has the old hash. A force-push is detectable for
the same structural reason a re-linked ChainLog is — and *undetectable* to
someone who only ever looks at the rewritten copy, which is tier 3 exactly.

The shared lesson is the one worth carrying out of this project: **a hash chain
alone proves nothing to anybody. It becomes evidence only when one of its
values has escaped the control of whoever holds the data.**
