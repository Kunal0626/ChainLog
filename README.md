# ChainLog

**Tamper-evident audit log engine**

> Status: In progress. Code is being built and will be added here.

Any edit, deletion or reordering of past log records is detectable, and you can prove that a record is in the log with a short Merkle proof.

## How it works
1. Each record stores the SHA-256 hash of the previous record, forming a hash chain.
2. Records are batched into a Merkle tree; the root is stored as a checkpoint.
3. An inclusion proof is the list of sibling hashes along one path, so its size is O(log n).
4. Appends go through a write-ahead log first, so a crash mid-write cannot corrupt history.
5. A verifier CLI recomputes everything and reports the first record that does not match.

## Stack
- C++17
- SHA-256 (OpenSSL or hand-written)
- Make / CMake

## CS concepts
- Trees and hashing (DSA)
- Write-ahead logging (DBMS)
- Crash safety

## Roadmap
- [ ] SHA-256 wrapper (OpenSSL, or implemented from scratch)
- [ ] Hash-chained, append-only record format
- [ ] Merkle tree builder and root checkpoints
- [ ] Inclusion proof generation and verification
- [ ] Write-ahead log and crash recovery
- [ ] CLI: `append`, `verify`, `prove <index>`
- [ ] Tamper demo (edit one byte, show the exact record that breaks) and tests

## Usage
Coming soon.

---
Part of my portfolio: [github.com/Kunal0626](https://github.com/Kunal0626)
