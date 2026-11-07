// The append-only log, the write-ahead log and the checkpoints beside it,
// and the checks over all three.
//
// append() now routes every record through log.wal first, so a crash part-way
// through the main write is recoverable rather than merely detectable. See
// wal.h for the protocol and for why those are different properties.
#ifndef CHAINLOG_LOG_H
#define CHAINLOG_LOG_H

#include <cstdint>
#include <string>
#include <vector>

#include "checkpoint.h"
#include "faultinject.h"
#include "fileio.h"
#include "merkle.h"
#include "record.h"
#include "wal.h"

namespace chainlog {

class Log {
 public:
  struct Options {
    // Records per sealed Merkle block. Only used when creating a new log; for
    // an existing one the value in the file header wins, because the stored
    // checkpoints are only meaningful relative to it.
    uint64_t block_size = kDefaultBlockSize;

    // HMAC key for signing checkpoints. Empty means unsigned.
    //
    // When set, newly sealed checkpoints are signed, and verify() REQUIRES
    // every checkpoint to be signed and valid. The requirement belongs here
    // rather than in the file: an attacker with write access can always
    // rewrite a checkpoint as unsigned, so only a verifier that insists on a
    // signature catches that. Which also means the key must live outside the
    // log directory -- if it does not, signing buys nothing.
    std::string key;
  };

  struct Stats {
    uint64_t record_count = 0;
    uint64_t log_bytes = 0;   // including the 32-byte header
    uint64_t data_bytes = 0;  // sum of record payload sizes
    uint64_t block_size = 0;
    uint64_t sealed_blocks = 0;
    uint64_t checkpoint_count = 0;
    uint64_t pending_records = 0;  // appended but not yet in a sealed block
    bool wal_pending = false;      // a record is staged but not applied
    bool read_only = false;        // opened without write access
    bool locked = false;           // holding the flock
  };

  // A head value published somewhere the attacker cannot reach: "record i
  // hashed to h". Checking one closes both of the holes a hash chain has on
  // its own, and they are different holes:
  //
  //   truncation -- a prefix of a valid chain is a valid chain, so cutting
  //     records off the end is invisible from inside the file. An anchor for
  //     an index past the new end has nothing to match.
  //
  //   wholesale rewriting -- an attacker who re-links every record and
  //     re-seals every checkpoint leaves a directory that agrees with itself.
  //     An anchor disagrees with it.
  struct Anchor {
    uint64_t index = 0;
    Digest hash{};
  };

  // Why `prove` could not produce a proof, when it could not.
  enum class ProveOutcome {
    kOk,
    kOutOfRange,  // there is no such record
    kNotSealed,   // the record exists but its block has not been sealed yet
    kProblem,     // the log or the checkpoints do not check out; see `why`
  };

  struct ProveResult {
    ProveOutcome outcome = ProveOutcome::kOk;
    Proof proof;
    Checkpoint checkpoint;
    Record record;
    Verdict why;         // filled when outcome == kProblem
    std::string detail;  // filled for kOutOfRange and kNotSealed
  };

  Log() = default;
  Log(const Log&) = delete;
  Log& operator=(const Log&) = delete;

  // Opens `dir`, creating the directory, the log and the checkpoints file if
  // they are absent.
  //
  // Opening scans the whole log to find the tail. That is O(n) in records, and
  // it is a deliberate choice: the alternative is caching the head in a second
  // file, which creates a second source of truth that can disagree with the
  // log -- exactly the class of bug this project exists to detect. The scan
  // checks framing only (magic, lengths, CRC); it does not recompute SHA-256,
  // so it is far cheaper than verify().
  //
  // Opening also recovers and repairs, in this order:
  //
  //   * takes an exclusive flock, so two writers cannot interleave. If the
  //     directory is not writable it falls back to a shared lock and a
  //     read-only open, because an archived log must still be verifiable.
  //   * replays or discards a staged WAL record (see recover_wal).
  //   * seals a complete-but-unsealed trailing block, or trims a torn
  //     trailing checkpoint frame (see reconcile_checkpoints for why at most
  //     one block can ever be missing, and why anything more is reported
  //     rather than repaired).
  bool open(const std::string& dir, const Options& opt, std::string* err);

  bool is_open() const { return log_fd_.valid(); }

  // Releases every descriptor, and with them the flock -- an flock lives on
  // the open file description, so closing it IS unlocking. The object is
  // unusable afterwards until open() is called again.
  //
  // Worth having explicitly rather than relying on the destructor: holding
  // one Log open while opening a second on the same directory is refused by
  // the lock, so code that wants to hand the log over needs a way to say
  // when it is finished.
  void close();

  // Appends a record carrying `data` through the write-ahead log, and seals a
  // checkpoint if this record completes a block. Refuses if the log was
  // opened read-only, or if the open-time scan found damage.
  bool append(const std::string& data, Record* out, std::string* err);

  // Recomputes every record hash, every chain link and every checkpoint root
  // from the genesis record, and reports the FIRST inconsistency. *err is set
  // only for I/O failures; a tampered log is a Verdict, not an error -- a
  // verifier that returned "error" for a detected forgery would be conflating
  // "I could not check" with "I checked, and it is bad".
  bool verify(Verdict* out, std::string* err) const {
    return verify(std::vector<Anchor>(), out, err);
  }

  // As above, and additionally checks every anchor. Anchors are checked after
  // the chain and the checkpoints, because an anchor failure on a log that is
  // already internally broken is the less useful of the two findings.
  bool verify(const std::vector<Anchor>& anchors, Verdict* out,
              std::string* err) const;

  // Copies the last record into *out. Returns false if the log is empty.
  // O(1): the tail record is cached by open() and append().
  bool head(Record* out) const;

  // O(1): every field is accumulated during the open-time scan and by
  // append(), so this never touches the disk.
  Stats stats() const;

  // Reads the checkpoints file. *v is a verdict on that file alone; it is
  // non-ok if the file is damaged, in which case *out holds the checkpoints
  // read before the problem.
  // `end_offset`, when given, receives the byte offset just past the last
  // intact checkpoint. Signed and unsigned frames are different sizes, so
  // that offset cannot be computed by arithmetic any more.
  bool read_checkpoints(std::vector<Checkpoint>* out, Verdict* v,
                        std::string* err,
                        uint64_t* end_offset = nullptr) const;

  // Builds an inclusion proof for the record at `index` against its block's
  // checkpoint root. Returns false only for I/O failures.
  bool prove(uint64_t index, ProveResult* out, std::string* err) const;

  // Rewrites the checkpoints file with every checkpoint signed by the key
  // this log was opened with. Used by `chainlog sign` to add signatures to a
  // log that was not created with a key.
  //
  // Replaces the file atomically via rename(2), so a crash leaves either the
  // old file or the new one and never a half-written mixture. The roots
  // themselves are not recomputed: signing re-authenticates what is already
  // there, it does not re-derive it, so it cannot launder a tampered log.
  bool resign_checkpoints(std::string* err);

  uint64_t block_size() const { return header_.block_size; }
  uint64_t record_count() const { return record_count_; }
  uint64_t checkpoint_count() const { return checkpoint_count_; }
  bool read_only() const { return read_only_; }
  bool signing() const { return !key_.empty(); }
  bool locked() const { return locked_; }

  // True when a record is staged in the WAL and has not been applied. After
  // a read-write open this is always false, because open() recovers. It can
  // be true after a read-only open, which cannot write and so cannot replay.
  bool wal_pending() const { return wal_pending_; }

  // What the open-time scan concluded. ok() unless something is damaged.
  const Verdict& scan_verdict() const { return scan_verdict_; }

  // Standard file names inside the log directory.
  static std::string log_path(const std::string& dir);
  static std::string wal_path(const std::string& dir);
  static std::string checkpoints_path(const std::string& dir);
  static std::string lock_path(const std::string& dir);

  // Default directory: $CHAINLOG_DIR, else "./chainlog.d".
  static std::string default_dir();

 private:
  // Walks frames from the header to end of file, filling in next_index_,
  // last_hash_, log_end_ and the pending block's hashes, and recording any
  // structural problem found.
  bool scan_tail(std::string* err);

  // Takes an exclusive flock (shared, when read-only). Fails rather than
  // waiting: a second writer should be told so, not silently queued behind an
  // appender that might run for hours.
  bool take_lock(std::string* err);

  // Replays a staged WAL record, discards a torn one, or reports one that
  // does not fit. Returns false only on I/O failure.
  bool recover_wal(std::string* err);

  // Compares the number of checkpoints against the number of complete blocks
  // and repairs the one discrepancy a crash can produce.
  bool reconcile_checkpoints(std::string* err);

  // Writes a checkpoint over pending_hashes_ and clears nothing: the caller
  // owns the pending block's lifetime.
  bool seal_pending_block(std::string* err);

  std::string dir_;
  Fd log_fd_;
  Fd wal_fd_;
  Fd ckpt_fd_;
  // Held for the object's whole lifetime: an flock is released when its file
  // description is closed, so this descriptor IS the lock.
  Fd lock_fd_;
  Header header_;

  std::string key_;
  bool read_only_ = false;
  bool locked_ = false;
  bool wal_pending_ = false;

  // Cached tail state, so append() does not rescan the file every time.
  // next_index_ comes from the last frame's stored index + 1, not from the
  // record count: on a tampered log those differ, and appending should keep
  // the chain locally consistent while verify() reports the tampering.
  uint64_t next_index_ = 0;
  Digest last_hash_ = Digest{};
  uint64_t log_end_ = 0;  // byte offset just past the last intact frame
  uint64_t record_count_ = 0;
  uint64_t data_bytes_ = 0;
  Record last_record_;
  bool has_last_ = false;

  // The block being filled: at most block_size hashes, so 32 KB at the
  // default. Keeping them in memory is what makes sealing O(block) rather
  // than a re-read of the file.
  std::vector<Digest> pending_hashes_;
  uint64_t pending_first_index_ = 0;

  uint64_t checkpoint_count_ = 0;
  uint64_t ckpt_end_ = 0;  // byte offset just past the last intact checkpoint

  Verdict scan_verdict_;
};

// Parses an anchor written as "index:hash" -- a decimal record index, a
// colon, and 64 hex characters. This is exactly the form `chainlog anchor`
// prints, so an anchor can be copied from one machine to another without
// reformatting.
bool parse_anchor(const std::string& text, Log::Anchor* out,
                  std::string* detail);

}  // namespace chainlog

#endif  // CHAINLOG_LOG_H
