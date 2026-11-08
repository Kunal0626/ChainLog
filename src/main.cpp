// chainlog -- command line interface.
//
// Phase 3 subset: append, verify, head, stats, checkpoints, prove,
// verify-proof. Anchoring and the WAL arrive in later phases.
//
// Exit codes are part of the interface, because the demo and the crash tests
// branch on them:
//   0  the operation succeeded / the log or proof verified
//   1  it did NOT verify (tampering or damage was detected)
//   2  usage error, or an I/O failure that prevented checking at all
//
// Keeping 1 and 2 apart matters: "I checked and it is bad" and "I could not
// check" are different answers, and a script that treats them alike will
// eventually report a permissions problem as a security incident.

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include <sys/stat.h>

#include <iostream>

#include "hex.h"
#include "hmac.h"
#include "log.h"
#include "merkle.h"

namespace {

constexpr int kExitOk = 0;
constexpr int kExitTamper = 1;
constexpr int kExitUsage = 2;

void usage() {
  std::fprintf(
      stderr,
      "usage: chainlog [options] <command> [arguments]\n"
      "\n"
      "commands:\n"
      "  append <data>          append a record containing <data>\n"
      "  append -               append a record containing all of stdin\n"
      "  import                 append one record per line of stdin\n"
      "  verify                 recompute the whole chain and every "
      "checkpoint\n"
      "  head                   index and hash of the last record\n"
      "  anchor                 the head as \"index:hash\", for --anchor\n"
      "  stats                  record count, sizes and block state\n"
      "  checkpoints            list the sealed Merkle roots\n"
      "  prove <index>          inclusion proof for one record\n"
      "  verify-proof <index> <data> <root> <proof>\n"
      "                         check a proof with no access to the log\n"
      "  sign                   HMAC every existing checkpoint (needs "
      "--key-file)\n"
      "\n"
      "options:\n"
      "  --dir DIR              log directory (default: $CHAINLOG_DIR, else "
      "./chainlog.d)\n"
      "  --block-size N         records per sealed block, new logs only "
      "(default: %llu)\n"
      "  --anchor i:hash        verify: require record i to hash to hash.\n"
      "                         May be given more than once.\n"
      "  --sync MODE            every (default), batch:N, or none.\n"
      "                         Anything but `every` trades durability for\n"
      "                         speed; see below.\n"
      "  --key-file PATH        HMAC key, as hex. Signs new checkpoints on\n"
      "                         append; makes verify REQUIRE a valid "
      "signature\n"
      "                         on every checkpoint.\n"
      "  --timestamp N          verify-proof: the record's timestamp_ns\n"
      "  --prev-hash HEX        verify-proof: the record's prev_hash\n"
      "\n"
      "verify-proof takes <data> either literally or as hex with a \"hex:\"\n"
      "prefix. It also needs --timestamp and --prev-hash, because a leaf\n"
      "commits to the whole record and not just its payload; `prove` prints\n"
      "a ready-made command line with all of them filled in.\n"
      "\n"
      "An anchor is a head value kept somewhere the attacker cannot reach.\n"
      "It is what detects the two things a hash chain cannot see on its own:\n"
      "a log truncated at a record boundary, and a log rewritten end to end.\n"
      "Print one with `chainlog anchor`, store it elsewhere, and pass it back\n"
      "with --anchor.\n"
      "\n"
      "--sync every fsyncs at all three steps of the append protocol, and is\n"
      "the only mode in which an append that succeeded is guaranteed to\n"
      "survive power loss. batch:N and none skip those barriers: a crash can\n"
      "then lose records and leave a torn tail that this build does not repair\n"
      "automatically. They are for bulk import (`import` defaults to\n"
      "batch:1000 and always flushes when it finishes) and for benchmarking.\n"
      "\n"
      "Generate a key with:  openssl rand -hex 32 > chainlog.key\n"
      "Keep it OUTSIDE the log directory -- a key an attacker can read is\n"
      "a key an attacker can sign with.\n"
      "\n"
      "exit codes: 0 ok, 1 does not verify, 2 usage/IO error\n",
      static_cast<unsigned long long>(chainlog::kDefaultBlockSize));
}

// Reads all of stdin. Records are arbitrary bytes, so this must not stop at a
// NUL or translate newlines.
bool read_stdin(std::string* out, std::string* err) {
  char buf[65536];
  while (true) {
    const size_t n = std::fread(buf, 1, sizeof(buf), stdin);
    if (n > 0) {
      out->append(buf, n);
    }
    if (n < sizeof(buf)) {
      if (std::ferror(stdin) != 0) {
        *err = "read error on stdin";
        return false;
      }
      return true;
    }
  }
}

// Accepts either literal bytes or "hex:<even-length hex>". The prefix exists
// so that a record containing NULs or high bytes survives a round trip
// through a shell, which argv cannot do for literal NULs.
bool parse_data_argument(const std::string& arg, std::string* out,
                         std::string* err) {
  const std::string prefix = "hex:";
  if (arg.compare(0, prefix.size(), prefix) != 0) {
    *out = arg;
    return true;
  }
  std::string detail;
  if (!chainlog::from_hex(arg.substr(prefix.size()), out, &detail)) {
    *err = "bad hex in <data>: " + detail;
    return false;
  }
  return true;
}

// Printed for any command run against a log whose open-time scan found
// damage. Exit code 1 ("this log does not check out") rather than 2 ("I could
// not check"), because the damage *was* detected -- a script that saw 2 here
// would read a real finding as an infrastructure problem.
int report_damaged(const chainlog::Log& log) {
  std::fprintf(stderr, "chainlog: log does not check out: %s\n",
               log.scan_verdict().message().c_str());
  return kExitTamper;
}

int cmd_append(chainlog::Log* log, const std::string& arg) {
  std::string data;
  std::string err;
  if (arg == "-") {
    if (!read_stdin(&data, &err)) {
      std::fprintf(stderr, "chainlog: %s\n", err.c_str());
      return kExitUsage;
    }
  } else if (!parse_data_argument(arg, &data, &err)) {
    std::fprintf(stderr, "chainlog: %s\n", err.c_str());
    return kExitUsage;
  }

  chainlog::Record r;
  if (!log->append(data, &r, &err)) {
    std::fprintf(stderr, "chainlog: %s\n", err.c_str());
    // Refusing to extend a damaged chain is a detection, not an I/O failure.
    return log->scan_verdict().ok() ? kExitUsage : kExitTamper;
  }
  std::printf("index=%llu hash=%s\n", static_cast<unsigned long long>(r.index),
              chainlog::to_hex(r.hash).c_str());
  return kExitOk;
}

// Reads a hex HMAC key.
//
// Hex rather than raw bytes because a key file written with `echo` picks up a
// trailing newline, and silently keeping or stripping it would make the key
// depend on how the file happened to be created. Hex with surrounding
// whitespace trimmed is unambiguous, and `openssl rand -hex 32` produces it.
bool read_key_file(const std::string& path, std::string* key,
                   std::string* err) {
  struct stat st;
  if (::stat(path.c_str(), &st) != 0) {
    *err = "cannot read key file " + path;
    return false;
  }
  if ((st.st_mode & (S_IRGRP | S_IROTH)) != 0) {
    // A warning, not a refusal: it is the operator's key and their call. But
    // a signing key that the group can read is not doing the job it is for.
    std::fprintf(stderr,
                 "chainlog: warning: %s is readable by group or other; "
                 "chmod 600 it\n",
                 path.c_str());
  }

  std::FILE* f = std::fopen(path.c_str(), "rb");
  if (f == nullptr) {
    *err = "cannot open key file " + path;
    return false;
  }
  std::string text;
  char buf[1024];
  while (true) {
    const size_t n = std::fread(buf, 1, sizeof(buf), f);
    text.append(buf, n);
    if (n < sizeof(buf)) {
      break;
    }
  }
  std::fclose(f);

  // Trim surrounding whitespace, including the newline `echo` adds.
  const size_t first = text.find_first_not_of(" \t\r\n");
  const size_t last = text.find_last_not_of(" \t\r\n");
  if (first == std::string::npos) {
    *err = "key file " + path + " is empty";
    return false;
  }
  text = text.substr(first, last - first + 1);

  std::string detail;
  if (!chainlog::from_hex(text, key, &detail)) {
    *err = "key file " + path + " is not hex: " + detail +
           "\n       generate one with: openssl rand -hex 32 > " + path;
    return false;
  }
  if (key->size() < chainlog::kMinKeyBytes) {
    *err = "key file " + path + " holds only " + std::to_string(key->size()) +
           " byte(s); at least " + std::to_string(chainlog::kMinKeyBytes) +
           " are required";
    return false;
  }
  return true;
}

int cmd_anchor(const chainlog::Log& log) {
  chainlog::Record r;
  if (!log.head(&r)) {
    std::fprintf(stderr,
                 "chainlog: the log is empty, so there is nothing to "
                 "anchor yet\n");
    return kExitUsage;
  }
  // Printed in exactly the form --anchor accepts, so it can be copied
  // between machines without reformatting.
  std::printf("%llu:%s\n", static_cast<unsigned long long>(r.index),
              chainlog::to_hex(r.hash).c_str());
  return kExitOk;
}

int cmd_sign(chainlog::Log* log) {
  std::string err;
  if (!log->resign_checkpoints(&err)) {
    std::fprintf(stderr, "chainlog: %s\n", err.c_str());
    return log->scan_verdict().ok() ? kExitUsage : kExitTamper;
  }
  std::printf("signed %llu checkpoint(s)\n",
              static_cast<unsigned long long>(log->checkpoint_count()));
  return kExitOk;
}

// Appends one record per line of stdin. Batched by default, because the whole
// point of a bulk import is to amortise the barriers -- and it flushes before
// returning, so an import that reports success is durable.
int cmd_import(chainlog::Log* log) {
  std::string err;
  std::string line;
  uint64_t count = 0;
  chainlog::Record r;

  while (std::getline(std::cin, line)) {
    if (!log->append(line, &r, &err)) {
      std::fprintf(stderr, "chainlog: at line %llu: %s\n",
                   static_cast<unsigned long long>(count + 1), err.c_str());
      // Flush what did land, so a failed import leaves a durable prefix
      // rather than an indeterminate amount of unsynced data.
      std::string flush_err;
      log->flush(&flush_err);
      return log->scan_verdict().ok() ? kExitUsage : kExitTamper;
    }
    ++count;
  }
  if (std::cin.bad()) {
    std::fprintf(stderr, "chainlog: read error on stdin\n");
    std::string flush_err;
    log->flush(&flush_err);
    return kExitUsage;
  }

  if (!log->flush(&err)) {
    std::fprintf(stderr, "chainlog: %s\n", err.c_str());
    return kExitUsage;
  }
  std::printf("imported=%llu\n", static_cast<unsigned long long>(count));
  if (count > 0) {
    std::printf("index=%llu hash=%s\n",
                static_cast<unsigned long long>(r.index),
                chainlog::to_hex(r.hash).c_str());
  }
  return kExitOk;
}

int cmd_verify(const chainlog::Log& log,
               const std::vector<chainlog::Log::Anchor>& anchors) {
  chainlog::Verdict v;
  std::string err;
  if (!log.verify(anchors, &v, &err)) {
    std::fprintf(stderr, "chainlog: %s\n", err.c_str());
    return kExitUsage;
  }
  if (v.ok()) {
    std::printf("%s\n", v.message().c_str());
    // Say what was actually checked. "ok" means much more with a key and an
    // anchor behind it than without, and an operator should not have to
    // remember which flags they passed.
    std::printf("anchors_checked=%llu\n",
                static_cast<unsigned long long>(anchors.size()));
    std::printf("signatures_required=%d\n", log.signing() ? 1 : 0);
    if (log.wal_pending()) {
      // Only reachable after a read-only open, which cannot replay. Worth
      // saying out loud: the chain is intact, but one record is staged and
      // not yet part of it, so this count is not the final one.
      std::fprintf(stderr,
                   "chainlog: note: a record is staged in the write-ahead log "
                   "and has not been applied\n"
                   "chainlog: the log was opened read-only, so it could not "
                   "be replayed; reopen with write access to recover\n");
    }
    return kExitOk;
  }
  std::fprintf(stderr, "chainlog: verification FAILED: %s\n",
               v.message().c_str());
  std::fprintf(stderr, "chainlog: %llu record(s) verified before the failure\n",
               static_cast<unsigned long long>(v.records_verified));
  return kExitTamper;
}

int cmd_head(const chainlog::Log& log) {
  chainlog::Record r;
  if (!log.head(&r)) {
    std::printf("empty\n");
    return kExitOk;
  }
  std::printf("index=%llu hash=%s\n", static_cast<unsigned long long>(r.index),
              chainlog::to_hex(r.hash).c_str());
  return kExitOk;
}

int cmd_stats(const chainlog::Log& log) {
  const chainlog::Log::Stats s = log.stats();
  std::printf("records=%llu\n", static_cast<unsigned long long>(s.record_count));
  std::printf("log_bytes=%llu\n", static_cast<unsigned long long>(s.log_bytes));
  std::printf("data_bytes=%llu\n",
              static_cast<unsigned long long>(s.data_bytes));
  std::printf("block_size=%llu\n",
              static_cast<unsigned long long>(s.block_size));
  std::printf("sealed_blocks=%llu\n",
              static_cast<unsigned long long>(s.sealed_blocks));
  std::printf("checkpoints=%llu\n",
              static_cast<unsigned long long>(s.checkpoint_count));
  std::printf("pending_records=%llu\n",
              static_cast<unsigned long long>(s.pending_records));
  std::printf("wal_pending=%d\n", s.wal_pending ? 1 : 0);
  std::printf("read_only=%d\n", s.read_only ? 1 : 0);
  std::printf("locked=%d\n", s.locked ? 1 : 0);
  return kExitOk;
}

int cmd_checkpoints(const chainlog::Log& log) {
  std::vector<chainlog::Checkpoint> cps;
  chainlog::Verdict v;
  std::string err;
  if (!log.read_checkpoints(&cps, &v, &err)) {
    std::fprintf(stderr, "chainlog: %s\n", err.c_str());
    return kExitUsage;
  }
  for (size_t i = 0; i < cps.size(); ++i) {
    std::printf("block=%llu first_index=%llu last_index=%llu root=%s\n",
                static_cast<unsigned long long>(i),
                static_cast<unsigned long long>(cps[i].first_index),
                static_cast<unsigned long long>(cps[i].last_index),
                chainlog::to_hex(cps[i].root).c_str());
  }
  if (!v.ok()) {
    std::fprintf(stderr, "chainlog: checkpoints file FAILED: %s\n",
                 v.message().c_str());
    return kExitTamper;
  }
  return kExitOk;
}

int cmd_prove(const chainlog::Log& log, const std::string& arg,
              const std::string& dir) {
  char* end = nullptr;
  const unsigned long long index = std::strtoull(arg.c_str(), &end, 10);
  if (end == arg.c_str() || *end != '\0') {
    std::fprintf(stderr, "chainlog: \"%s\" is not a record index\n",
                 arg.c_str());
    return kExitUsage;
  }

  chainlog::Log::ProveResult res;
  std::string err;
  if (!log.prove(index, &res, &err)) {
    std::fprintf(stderr, "chainlog: %s\n", err.c_str());
    return kExitUsage;
  }

  switch (res.outcome) {
    case chainlog::Log::ProveOutcome::kOutOfRange:
    case chainlog::Log::ProveOutcome::kNotSealed:
      std::fprintf(stderr, "chainlog: cannot prove index %llu: %s\n", index,
                   res.detail.c_str());
      return kExitUsage;
    case chainlog::Log::ProveOutcome::kProblem:
      std::fprintf(stderr, "chainlog: cannot prove index %llu: %s\n", index,
                   res.why.message().c_str());
      return kExitTamper;
    case chainlog::Log::ProveOutcome::kOk:
      break;
  }

  const uint64_t tree_size = res.checkpoint.leaf_count();
  const uint64_t leaf_index = index - res.checkpoint.first_index;
  const std::string proof_hex = chainlog::encode_proof(
      res.checkpoint.first_index, tree_size, leaf_index, res.proof);
  const std::string data_hex =
      chainlog::to_hex(res.record.data.data(), res.record.data.size());
  const std::string root_hex = chainlog::to_hex(res.checkpoint.root);
  const std::string prev_hex = chainlog::to_hex(res.record.prev_hash);

  std::printf("index=%llu\n", index);
  std::printf("first_index=%llu\n",
              static_cast<unsigned long long>(res.checkpoint.first_index));
  std::printf("last_index=%llu\n",
              static_cast<unsigned long long>(res.checkpoint.last_index));
  std::printf("tree_size=%llu\n", static_cast<unsigned long long>(tree_size));
  std::printf("leaf_index=%llu\n",
              static_cast<unsigned long long>(leaf_index));
  std::printf("timestamp_ns=%llu\n",
              static_cast<unsigned long long>(res.record.timestamp_ns));
  std::printf("data_hex=%s\n", data_hex.c_str());
  std::printf("prev_hash=%s\n", prev_hex.c_str());
  std::printf("record_hash=%s\n",
              chainlog::to_hex(res.record.hash).c_str());
  std::printf("leaf_hash=%s\n",
              chainlog::to_hex(chainlog::merkle_leaf_hash(res.record.hash))
                  .c_str());
  std::printf("root=%s\n", root_hex.c_str());
  std::printf("proof_steps=%llu\n",
              static_cast<unsigned long long>(res.proof.size()));
  std::printf("proof=%s\n", proof_hex.c_str());

  // A ready-made command line, because a standalone verifier needs five
  // things (index, data, timestamp, prev_hash, root) and assembling them by
  // hand from the lines above is exactly where a demo goes wrong.
  std::printf(
      "verify_command=chainlog --dir %s verify-proof %llu hex:%s %s %s "
      "--timestamp %llu --prev-hash %s\n",
      dir.c_str(), index, data_hex.c_str(), root_hex.c_str(),
      proof_hex.c_str(),
      static_cast<unsigned long long>(res.record.timestamp_ns),
      prev_hex.c_str());
  return kExitOk;
}

struct VerifyProofArgs {
  std::string index;
  std::string data;
  std::string root;
  std::string proof;
  std::string timestamp;
  std::string prev_hash;
};

int cmd_verify_proof(const VerifyProofArgs& a) {
  std::string err;

  char* end = nullptr;
  const unsigned long long index = std::strtoull(a.index.c_str(), &end, 10);
  if (end == a.index.c_str() || *end != '\0') {
    std::fprintf(stderr, "chainlog: \"%s\" is not a record index\n",
                 a.index.c_str());
    return kExitUsage;
  }
  if (a.timestamp.empty() || a.prev_hash.empty()) {
    std::fprintf(stderr,
                 "chainlog: verify-proof needs --timestamp and --prev-hash.\n"
                 "A Merkle leaf commits to the whole record -- index, "
                 "timestamp, data and prev_hash --\nso the data alone is not "
                 "enough to recompute it. `chainlog prove` prints a\n"
                 "ready-made command line with every field filled in.\n");
    return kExitUsage;
  }
  end = nullptr;
  const unsigned long long timestamp =
      std::strtoull(a.timestamp.c_str(), &end, 10);
  if (end == a.timestamp.c_str() || *end != '\0') {
    std::fprintf(stderr, "chainlog: \"%s\" is not a timestamp\n",
                 a.timestamp.c_str());
    return kExitUsage;
  }

  chainlog::Record r;
  r.index = index;
  r.timestamp_ns = timestamp;
  if (!parse_data_argument(a.data, &r.data, &err)) {
    std::fprintf(stderr, "chainlog: %s\n", err.c_str());
    return kExitUsage;
  }
  std::string detail;
  if (!chainlog::digest_from_hex(a.prev_hash, &r.prev_hash, &detail)) {
    std::fprintf(stderr, "chainlog: bad --prev-hash: %s\n", detail.c_str());
    return kExitUsage;
  }
  chainlog::Digest root;
  if (!chainlog::digest_from_hex(a.root, &root, &detail)) {
    std::fprintf(stderr, "chainlog: bad <root>: %s\n", detail.c_str());
    return kExitUsage;
  }

  uint64_t first_index = 0;
  uint64_t tree_size = 0;
  uint64_t leaf_index = 0;
  chainlog::Proof proof;
  if (!chainlog::decode_proof(a.proof, &first_index, &tree_size, &leaf_index,
                              &proof, &detail)) {
    // A corrupt proof is a usage problem, not a tamper finding: the operator
    // mistyped or truncated the hex, which says nothing about the log.
    std::fprintf(stderr, "chainlog: corrupt <proof>: %s\n", detail.c_str());
    return kExitUsage;
  }

  if (first_index + leaf_index != index) {
    std::fprintf(stderr,
                 "chainlog: proof FAILED: the proof places leaf %llu of a "
                 "block starting at %llu, which is record %llu, not %llu\n",
                 static_cast<unsigned long long>(leaf_index),
                 static_cast<unsigned long long>(first_index),
                 static_cast<unsigned long long>(first_index + leaf_index),
                 index);
    return kExitTamper;
  }

  const chainlog::Digest record_hash = chainlog::compute_record_hash(r);
  if (!chainlog::merkle_verify_proof(record_hash, leaf_index, tree_size, proof,
                                     root, &detail)) {
    std::fprintf(stderr, "chainlog: proof FAILED: %s\n", detail.c_str());
    return kExitTamper;
  }

  std::printf("ok: record %llu is leaf %llu of %llu under root %s\n", index,
              static_cast<unsigned long long>(leaf_index),
              static_cast<unsigned long long>(tree_size),
              chainlog::to_hex(root).c_str());
  std::printf("record_hash=%s\n", chainlog::to_hex(record_hash).c_str());
  return kExitOk;
}

}  // namespace

int main(int argc, char** argv) {
  std::string dir = chainlog::Log::default_dir();
  chainlog::Log::Options opt;
  std::string opt_timestamp;
  std::string opt_prev_hash;
  std::string opt_key_file;
  std::string opt_sync;
  std::vector<std::string> anchor_args;
  std::vector<std::string> positional;

  // Options are accepted anywhere, so `prove 5 --dir D` works as well as
  // `--dir D prove 5`. Nothing after the command is positional-only, because
  // every option here is unambiguous.
  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    if (arg == "--help" || arg == "-h") {
      usage();
      return kExitOk;
    }
    if (arg == "--dir" && i + 1 < argc) {
      dir = argv[++i];
    } else if (arg == "--block-size" && i + 1 < argc) {
      const long long n = std::atoll(argv[++i]);
      if (n <= 0) {
        std::fprintf(stderr, "chainlog: --block-size must be positive\n");
        return kExitUsage;
      }
      opt.block_size = static_cast<uint64_t>(n);
    } else if (arg == "--timestamp" && i + 1 < argc) {
      opt_timestamp = argv[++i];
    } else if (arg == "--prev-hash" && i + 1 < argc) {
      opt_prev_hash = argv[++i];
    } else if (arg == "--anchor" && i + 1 < argc) {
      anchor_args.push_back(argv[++i]);
    } else if (arg == "--key-file" && i + 1 < argc) {
      opt_key_file = argv[++i];
    } else if (arg == "--sync" && i + 1 < argc) {
      opt_sync = argv[++i];
    } else if (arg.size() > 2 && arg[0] == '-' && arg[1] == '-') {
      std::fprintf(stderr, "chainlog: unknown option \"%s\"\n", arg.c_str());
      return kExitUsage;
    } else {
      positional.push_back(arg);
    }
  }

  if (positional.empty()) {
    usage();
    return kExitUsage;
  }
  const std::string cmd = positional[0];

  // `import` defaults to batching, because amortising the barriers is the
  // entire reason to have a bulk path. Everything else defaults to the safe
  // policy.
  if (cmd == "import" && opt_sync.empty()) {
    opt_sync = "batch:1000";
  }
  if (!opt_sync.empty()) {
    if (opt_sync == "every") {
      opt.sync = chainlog::Log::SyncPolicy::kEveryAppend;
    } else if (opt_sync == "none") {
      opt.sync = chainlog::Log::SyncPolicy::kNone;
    } else if (opt_sync.compare(0, 6, "batch:") == 0) {
      const long long n = std::atoll(opt_sync.c_str() + 6);
      if (n <= 0) {
        std::fprintf(stderr, "chainlog: --sync batch:N needs N > 0\n");
        return kExitUsage;
      }
      opt.sync = chainlog::Log::SyncPolicy::kBatched;
      opt.sync_batch = static_cast<uint64_t>(n);
    } else {
      std::fprintf(stderr,
                   "chainlog: --sync must be every, batch:N or none, "
                   "not \"%s\"\n",
                   opt_sync.c_str());
      return kExitUsage;
    }

    // A single `append` exits immediately after writing, so a skipped barrier
    // means the record may simply not be there after a power cut. Said out
    // loud rather than hidden behind a silent flush, which would make the
    // option a lie.
    if (opt.sync != chainlog::Log::SyncPolicy::kEveryAppend &&
        cmd == "append") {
      std::fprintf(stderr,
                   "chainlog: warning: --sync %s skips the fsync barriers, so "
                   "this record is NOT guaranteed to survive power loss\n",
                   opt_sync.c_str());
    }
  }

  // verify-proof never touches the log, so it must work with no log directory
  // present at all -- that is the entire point of a standalone verifier.
  if (cmd == "verify-proof") {
    if (positional.size() != 5) {
      std::fprintf(stderr,
                   "chainlog: verify-proof needs <index> <data> <root> "
                   "<proof>\n");
      return kExitUsage;
    }
    VerifyProofArgs a;
    a.index = positional[1];
    a.data = positional[2];
    a.root = positional[3];
    a.proof = positional[4];
    a.timestamp = opt_timestamp;
    a.prev_hash = opt_prev_hash;
    return cmd_verify_proof(a);
  }

  // Anchors are parsed before the log is touched, so a typo is reported as a
  // usage error rather than after a full verification run.
  std::vector<chainlog::Log::Anchor> anchors;
  for (size_t a = 0; a < anchor_args.size(); ++a) {
    chainlog::Log::Anchor parsed;
    std::string detail;
    if (!chainlog::parse_anchor(anchor_args[a], &parsed, &detail)) {
      std::fprintf(stderr, "chainlog: bad --anchor \"%s\": %s\n",
                   anchor_args[a].c_str(), detail.c_str());
      return kExitUsage;
    }
    anchors.push_back(parsed);
  }

  std::string err;
  if (!opt_key_file.empty()) {
    if (!read_key_file(opt_key_file, &opt.key, &err)) {
      std::fprintf(stderr, "chainlog: %s\n", err.c_str());
      return kExitUsage;
    }
  }

  if (!anchors.empty() && cmd != "verify") {
    std::fprintf(stderr, "chainlog: --anchor only applies to `verify`\n");
    return kExitUsage;
  }

  chainlog::Log log;
  if (!log.open(dir, opt, &err)) {
    std::fprintf(stderr, "chainlog: %s\n", err.c_str());
    return kExitUsage;
  }

  if (cmd == "append") {
    if (positional.size() < 2) {
      std::fprintf(stderr, "chainlog: append needs <data> or -\n");
      return kExitUsage;
    }
    return cmd_append(&log, positional[1]);
  }
  if (cmd == "import") {
    return cmd_import(&log);
  }
  if (cmd == "verify") {
    return cmd_verify(log, anchors);
  }
  if (cmd == "anchor") {
    const int rc = cmd_anchor(log);
    if (rc == kExitOk && !log.scan_verdict().ok()) {
      return report_damaged(log);
    }
    return rc;
  }
  if (cmd == "sign") {
    if (opt_key_file.empty()) {
      std::fprintf(stderr, "chainlog: `sign` needs --key-file\n");
      return kExitUsage;
    }
    return cmd_sign(&log);
  }
  if (cmd == "checkpoints") {
    return cmd_checkpoints(log);
  }
  if (cmd == "prove") {
    if (positional.size() < 2) {
      std::fprintf(stderr, "chainlog: prove needs <index>\n");
      return kExitUsage;
    }
    return cmd_prove(log, positional[1], dir);
  }
  if (cmd == "head" || cmd == "stats") {
    // Still print what can be read, so the operator has something to work
    // with, but exit non-zero so a script cannot mistake a damaged log for a
    // healthy one just because `head` happened to succeed.
    const int rc = (cmd == "head") ? cmd_head(log) : cmd_stats(log);
    if (rc == kExitOk && !log.scan_verdict().ok()) {
      return report_damaged(log);
    }
    return rc;
  }

  std::fprintf(stderr, "chainlog: unknown command \"%s\"\n", cmd.c_str());
  usage();
  return kExitUsage;
}
