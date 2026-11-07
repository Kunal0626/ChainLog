// Anchoring and signed checkpoints: the two things that close the last rungs
// of the tamper ladder.
//
// Everything up to phase 4 could be defeated by an attacker with write access
// to the whole log directory, because every check compared one part of the
// directory against another part the attacker also controlled. These two
// mechanisms bring in something from outside:
//
//   an anchor -- a head value stored somewhere else
//   a key     -- an HMAC secret stored somewhere else
//
// They are NOT interchangeable, and the difference is the most important thing
// in this file. An anchor catches truncation AND rewriting. A signature
// catches rewriting only: an attacker who truncates the log at a block
// boundary and drops the matching checkpoints leaves every remaining
// signature perfectly valid. There is nothing to sign that says how long the
// log was supposed to be.

#include <cctype>

#include <string>
#include <vector>

#include "checkpoint.h"
#include "crc32.h"
#include "hex.h"
#include "hmac.h"
#include "log.h"
#include "log_fixture.h"
#include "merkle.h"
#include "test.h"

using chainlog::Checkpoint;
using chainlog::Digest;
using chainlog::Log;
using chainlog::Problem;
using chainlog::Record;
using chainlog::Verdict;
using chainlog::to_hex;
using chainlog_test::FrameSpan;
using chainlog_test::TempDir;
using chainlog_test::build_log;
using chainlog_test::record_label;

namespace {

std::string pname(Problem p) { return chainlog::problem_name(p); }

std::string log_file(const TempDir& d) { return Log::log_path(d.path()); }
std::string ckpt_file(const TempDir& d) {
  return Log::checkpoints_path(d.path());
}

const char* kKey = "\x9e\x11\x22\x33\x44\x55\x66\x77"
                   "\x88\x99\xaa\xbb\xcc\xdd\xee\xff"
                   "\x01\x02\x03\x04\x05\x06\x07\x08"
                   "\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10";
std::string key() { return std::string(kKey, 32); }
std::string other_key() { return std::string(32, '\x5a'); }

// Builds a log, optionally signed, and returns the anchor for its head.
Log::Anchor build_and_anchor(const TempDir& d, uint64_t n, uint64_t bs,
                             const std::string& k = std::string()) {
  Log log;
  Log::Options opt;
  opt.block_size = bs;
  opt.key = k;
  std::string err;
  CHECK(log.open(d.path(), opt, &err));
  Record r;
  for (uint64_t i = 0; i < n; ++i) {
    CHECK(log.append(record_label(i), &r, &err));
  }
  Log::Anchor a;
  a.index = r.index;
  a.hash = r.hash;
  return a;
}

// Verifies `dir` with the given anchors and key.
Verdict check(const TempDir& d, const std::vector<Log::Anchor>& anchors,
              const std::string& k = std::string()) {
  Log log;
  Log::Options opt;
  opt.key = k;
  std::string err;
  CHECK(log.open(d.path(), opt, &err));
  Verdict v;
  CHECK(log.verify(anchors, &v, &err));
  return v;
}

std::vector<Checkpoint> read_cps(const TempDir& d,
                                 const std::string& k = std::string()) {
  Log log;
  Log::Options opt;
  opt.key = k;
  std::string err;
  CHECK(log.open(d.path(), opt, &err));
  std::vector<Checkpoint> cps;
  Verdict v;
  CHECK(log.read_checkpoints(&cps, &v, &err));
  return cps;
}

}  // namespace

// --- parsing ---------------------------------------------------------------

TEST(parse_anchor_accepts_the_form_anchor_prints) {
  Log::Anchor a;
  std::string detail;
  const std::string hex =
      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
  CHECK(chainlog::parse_anchor("637:" + hex, &a, &detail));
  CHECK_EQ(a.index, 637ull);
  CHECK_EQ(to_hex(a.hash), hex);

  CHECK(chainlog::parse_anchor("0:" + hex, &a, &detail));
  CHECK_EQ(a.index, 0ull);

  // Uppercase hex is accepted; anchors get copied between terminals.
  std::string upper = hex;
  for (size_t i = 0; i < upper.size(); ++i) {
    upper[i] = static_cast<char>(std::toupper(upper[i]));
  }
  CHECK(chainlog::parse_anchor("5:" + upper, &a, &detail));
  CHECK_EQ(to_hex(a.hash), hex);
}

TEST(parse_anchor_rejects_malformed_input) {
  Log::Anchor a;
  std::string detail;
  const std::string hex =
      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

  CHECK(!chainlog::parse_anchor(hex, &a, &detail));  // no colon
  CHECK(detail.find("index:hash") != std::string::npos);
  CHECK(!chainlog::parse_anchor(":" + hex, &a, &detail));       // no index
  CHECK(!chainlog::parse_anchor("-1:" + hex, &a, &detail));     // not decimal
  CHECK(!chainlog::parse_anchor("1a:" + hex, &a, &detail));     // not decimal
  CHECK(!chainlog::parse_anchor("5:", &a, &detail));            // no hash
  CHECK(!chainlog::parse_anchor("5:abcd", &a, &detail));        // short hash
  CHECK(!chainlog::parse_anchor("5:" + hex + "00", &a, &detail));  // long
  CHECK(!chainlog::parse_anchor("5:" + hex.substr(1) + "zz", &a, &detail));
}

// --- the happy path --------------------------------------------------------

TEST(a_correct_anchor_verifies) {
  TempDir d;
  const Log::Anchor a = build_and_anchor(d, 12, 4);
  const Verdict v = check(d, {a});
  CHECK_EQ(pname(v.problem), "ok");
  CHECK_EQ(v.records_verified, 12ull);
}

TEST(every_record_can_serve_as_an_anchor) {
  TempDir d;
  build_log(d.path(), 12, 4);
  const std::vector<Record> rs =
      chainlog_test::read_frames(chainlog_test::read_file(log_file(d)));

  for (size_t i = 0; i < rs.size(); ++i) {
    Log::Anchor a;
    a.index = rs[i].index;
    a.hash = rs[i].hash;
    CHECK_EQ(pname(check(d, {a}).problem), "ok");
  }

  // Including all of them at once, and the genesis record on its own.
  std::vector<Log::Anchor> all;
  for (size_t i = 0; i < rs.size(); ++i) {
    all.push_back({rs[i].index, rs[i].hash});
  }
  CHECK_EQ(pname(check(d, all).problem), "ok");
}

// --- the two holes, now closed ---------------------------------------------

// Phase 2's documented hole: a prefix of a valid chain is itself a valid
// chain, so cutting records off the end is invisible from inside the file.
TEST(truncation_at_a_frame_boundary_is_caught_by_an_anchor) {
  TempDir d;
  const Log::Anchor a = build_and_anchor(d, 12, 4);

  const std::string whole = chainlog_test::read_file(log_file(d));
  const std::vector<FrameSpan> spans = chainlog_test::frame_spans(whole);
  chainlog_test::write_file(
      log_file(d), whole.substr(0, static_cast<size_t>(spans[8].offset)));
  // Drop the now-orphaned checkpoint too, so the log is internally perfect.
  const std::string cps = chainlog_test::read_file(ckpt_file(d));
  chainlog_test::write_file(
      ckpt_file(d),
      cps.substr(0, chainlog::kCheckpointHeaderBytes +
                        2 * (chainlog::kCheckpointOverheadBytes +
                             chainlog::kCheckpointPayloadBytes)));

  // Without the anchor the log looks fine -- and it IS internally consistent.
  CHECK_EQ(pname(check(d, {}).problem), "ok");
  CHECK_EQ(check(d, {}).records_verified, 8ull);

  // With it, the loss is obvious.
  const Verdict v = check(d, {a});
  CHECK_EQ(pname(v.problem), "anchor-missing");
  CHECK_EQ(v.index, 11ull);
  CHECK(v.detail.find("shorter than this anchor") != std::string::npos);
}

// Phase 3's documented hole: an attacker who re-links the records AND re-seals
// the checkpoints leaves a directory that agrees with itself.
TEST(a_wholesale_rewrite_is_caught_by_an_anchor) {
  TempDir d;
  const Log::Anchor a = build_and_anchor(d, 12, 4);

  std::string bytes = chainlog_test::read_file(log_file(d));
  const std::vector<FrameSpan> spans = chainlog_test::frame_spans(bytes);
  std::vector<Record> rs = chainlog_test::read_frames(bytes);
  Record forged = rs[5];
  forged.data = "rec-HACKED";
  CHECK_EQ(forged.data.size(), rs[5].data.size());
  chainlog_test::rewrite_frame(&bytes, spans[5].offset, forged);
  chainlog_test::relink_from(&bytes, 5);
  chainlog_test::write_file(log_file(d), bytes);
  chainlog_test::reseal_all_checkpoints(d.path());

  // Internally flawless.
  CHECK_EQ(pname(check(d, {}).problem), "ok");

  // And caught the moment one value from outside is brought in.
  const Verdict v = check(d, {a});
  CHECK_EQ(pname(v.problem), "anchor-mismatch");
  CHECK_EQ(v.index, 11ull);
  CHECK(v.detail.find("but this anchor says") != std::string::npos);
}

TEST(an_anchor_catches_a_rewrite_even_at_an_earlier_index) {
  TempDir d;
  build_log(d.path(), 12, 4);
  const std::vector<Record> before =
      chainlog_test::read_frames(chainlog_test::read_file(log_file(d)));
  // An anchor taken at record 7, before the forgery at 5 happens.
  Log::Anchor a;
  a.index = 7;
  a.hash = before[7].hash;

  std::string bytes = chainlog_test::read_file(log_file(d));
  const std::vector<FrameSpan> spans = chainlog_test::frame_spans(bytes);
  std::vector<Record> rs = chainlog_test::read_frames(bytes);
  Record forged = rs[5];
  forged.data = "rec-HACKED";
  chainlog_test::rewrite_frame(&bytes, spans[5].offset, forged);
  chainlog_test::relink_from(&bytes, 5);
  chainlog_test::write_file(log_file(d), bytes);
  chainlog_test::reseal_all_checkpoints(d.path());

  const Verdict v = check(d, {a});
  CHECK_EQ(pname(v.problem), "anchor-mismatch");
  CHECK_EQ(v.index, 7ull);
}

TEST(anchors_are_reported_earliest_first) {
  TempDir d;
  build_log(d.path(), 12, 4);
  const std::vector<Record> rs =
      chainlog_test::read_frames(chainlog_test::read_file(log_file(d)));

  // Three anchors, two of them wrong. The lowest index must be reported,
  // whatever order they were supplied in.
  Log::Anchor good = {3, rs[3].hash};
  Log::Anchor bad_mid = {7, rs[7].hash};
  bad_mid.hash[0] = static_cast<uint8_t>(bad_mid.hash[0] ^ 0x01);
  Log::Anchor bad_high = {11, rs[11].hash};
  bad_high.hash[0] = static_cast<uint8_t>(bad_high.hash[0] ^ 0x01);

  Verdict v = check(d, {bad_high, good, bad_mid});
  CHECK_EQ(pname(v.problem), "anchor-mismatch");
  CHECK_EQ(v.index, 7ull);

  v = check(d, {bad_mid, bad_high});
  CHECK_EQ(v.index, 7ull);
}

TEST(an_anchor_past_the_end_is_anchor_missing) {
  TempDir d;
  build_log(d.path(), 5, 4);
  const std::vector<Record> rs =
      chainlog_test::read_frames(chainlog_test::read_file(log_file(d)));

  Log::Anchor a = {5, rs[4].hash};
  CHECK_EQ(pname(check(d, {a}).problem), "anchor-missing");
  a.index = 1000000;
  CHECK_EQ(pname(check(d, {a}).problem), "anchor-missing");
}

TEST(an_anchor_against_an_empty_log_is_anchor_missing) {
  TempDir d;
  Log log;
  Log::Options opt;
  std::string err;
  CHECK(log.open(d.path(), opt, &err));
  log.close();

  Log::Anchor a;
  a.index = 0;
  a.hash.fill(0x11);
  const Verdict v = check(d, {a});
  CHECK_EQ(pname(v.problem), "anchor-missing");
  CHECK_EQ(v.records_verified, 0ull);
}

// An anchor failure must not mask a real structural problem: the chain is
// checked first, because "your log is broken" is more useful than "your log
// disagrees with a value you gave me".
TEST(a_broken_chain_is_reported_before_an_anchor_mismatch) {
  TempDir d;
  const Log::Anchor a = build_and_anchor(d, 12, 4);

  std::string bytes = chainlog_test::read_file(log_file(d));
  const std::vector<FrameSpan> spans = chainlog_test::frame_spans(bytes);
  const size_t at = static_cast<size_t>(spans[3].offset) + 30;
  bytes[at] = static_cast<char>(bytes[at] ^ 0x01);
  chainlog_test::write_file(log_file(d), bytes);

  // The anchor is also unsatisfiable now, but the CRC failure comes first.
  const Verdict v = check(d, {a});
  CHECK_EQ(pname(v.problem), "bad-crc");
  CHECK_EQ(v.index, 3ull);
}

// --- signed checkpoints ----------------------------------------------------

TEST(a_log_opened_with_a_key_signs_its_checkpoints) {
  TempDir d;
  build_and_anchor(d, 12, 4, key());

  const std::vector<Checkpoint> cps = read_cps(d, key());
  CHECK_EQ(cps.size(), static_cast<size_t>(3));
  for (size_t i = 0; i < cps.size(); ++i) {
    CHECK(cps[i].is_signed());
    CHECK(chainlog::checkpoint_signature_valid(key(), cps[i]));
    CHECK(!chainlog::checkpoint_signature_valid(other_key(), cps[i]));
  }
  CHECK_EQ(pname(check(d, {}, key()).problem), "ok");
}

TEST(a_signed_log_still_verifies_without_the_key) {
  TempDir d;
  build_and_anchor(d, 12, 4, key());
  // Signatures are additional evidence, not a precondition: somebody without
  // the key can still check the chain and the roots.
  CHECK_EQ(pname(check(d, {}).problem), "ok");
}

TEST(a_wrong_key_does_not_verify) {
  TempDir d;
  build_and_anchor(d, 12, 4, key());
  const Verdict v = check(d, {}, other_key());
  CHECK_EQ(pname(v.problem), "bad-checkpoint");
  CHECK(v.detail.find("does not verify under the supplied key") !=
        std::string::npos);
}

TEST(a_key_makes_unsigned_checkpoints_unacceptable) {
  TempDir d;
  build_log(d.path(), 12, 4);  // no key: unsigned

  // Without a key, fine. With one, refused -- because an attacker with write
  // access can always rewrite a checkpoint as unsigned, so a verifier that
  // accepted unsigned ones would gain nothing from the key.
  CHECK_EQ(pname(check(d, {}).problem), "ok");
  const Verdict v = check(d, {}, key());
  CHECK_EQ(pname(v.problem), "bad-checkpoint");
  CHECK(v.detail.find("is not signed") != std::string::npos);
}

TEST(stripping_the_signatures_is_caught_only_when_a_key_is_supplied) {
  TempDir d;
  build_and_anchor(d, 12, 4, key());
  chainlog_test::strip_checkpoint_signatures(d.path());

  // The downgrade attack. Everything still checks out to a verifier that was
  // not told to expect signatures...
  CHECK_EQ(pname(check(d, {}).problem), "ok");
  // ... and is immediately obvious to one that was.
  CHECK_EQ(pname(check(d, {}, key()).problem), "bad-checkpoint");
}

TEST(a_rewrite_of_a_signed_log_is_caught_by_the_key_alone) {
  TempDir d;
  build_and_anchor(d, 12, 4, key());

  std::string bytes = chainlog_test::read_file(log_file(d));
  const std::vector<FrameSpan> spans = chainlog_test::frame_spans(bytes);
  std::vector<Record> rs = chainlog_test::read_frames(bytes);
  Record forged = rs[5];
  forged.data = "rec-HACKED";
  chainlog_test::rewrite_frame(&bytes, spans[5].offset, forged);
  chainlog_test::relink_from(&bytes, 5);
  chainlog_test::write_file(log_file(d), bytes);
  // The attacker re-seals, but cannot sign: they do not have the key.
  chainlog_test::reseal_all_checkpoints(d.path());

  // No anchor needed here. The key alone is enough.
  const Verdict v = check(d, {}, key());
  CHECK_EQ(pname(v.problem), "bad-checkpoint");
}

// The limit of signatures, stated as a passing test. Signatures authenticate
// the checkpoints that are present; nothing authenticates how many there
// should be. So an attacker who truncates at a block boundary and drops the
// matching checkpoints leaves every remaining signature valid.
TEST(signatures_do_NOT_catch_truncation_but_an_anchor_does) {
  TempDir d;
  const Log::Anchor a = build_and_anchor(d, 12, 4, key());

  const std::string whole = chainlog_test::read_file(log_file(d));
  const std::vector<FrameSpan> spans = chainlog_test::frame_spans(whole);
  chainlog_test::write_file(
      log_file(d), whole.substr(0, static_cast<size_t>(spans[8].offset)));
  const std::string cps = chainlog_test::read_file(ckpt_file(d));
  chainlog_test::write_file(
      ckpt_file(d),
      cps.substr(0, chainlog::kCheckpointHeaderBytes +
                        2 * (chainlog::kCheckpointOverheadBytes + 32 +
                             chainlog::kCheckpointPayloadBytes)));

  // Every surviving signature is genuine, so the key is satisfied.
  CHECK_EQ(pname(check(d, {}, key()).problem), "ok");
  // The anchor is not.
  CHECK_EQ(pname(check(d, {a}, key()).problem), "anchor-missing");
}

TEST(an_edited_root_breaks_its_signature) {
  TempDir d;
  build_and_anchor(d, 12, 4, key());
  std::vector<Checkpoint> cps = read_cps(d, key());

  // The MAC covers flags, both indexes and the root, so editing any of them
  // invalidates it even if the attacker leaves the HMAC bytes alone.
  for (int field = 0; field < 4; ++field) {
    Checkpoint c = cps[1];
    switch (field) {
      case 0: c.root[0] = static_cast<uint8_t>(c.root[0] ^ 0x01); break;
      case 1: c.first_index += 1; break;
      case 2: c.last_index += 1; break;
      case 3: c.hmac[31] = static_cast<uint8_t>(c.hmac[31] ^ 0x01); break;
    }
    CHECK(!chainlog::checkpoint_signature_valid(key(), c));
  }
}

TEST(a_flag_and_length_mismatch_is_rejected) {
  Checkpoint c;
  c.first_index = 0;
  c.last_index = 3;
  c.root.fill(0x22);

  // Flagged signed, but encoded without an HMAC: hand-build the frame so the
  // two disagree, which append_checkpoint_frame would never do.
  std::string frame;
  chainlog::append_checkpoint_frame(c, &frame);  // unsigned, 64 bytes
  uint8_t* p = reinterpret_cast<uint8_t*>(&frame[0]);
  chainlog::put_u32_le(p + 8, chainlog::kCheckpointFlagSigned);
  chainlog::put_u32_le(p + 8 + chainlog::kCheckpointPayloadBytes,
                       chainlog::crc32(p + 8,
                                       chainlog::kCheckpointPayloadBytes));

  Checkpoint out;
  std::string detail;
  CHECK_EQ(pname(chainlog::decode_checkpoint_frame(frame.data(), frame.size(),
                                                   &out, nullptr, &detail)),
           "bad-checkpoint");
  CHECK(detail.find("carries no HMAC") != std::string::npos);
}

// --- the sign command ------------------------------------------------------

TEST(sign_adds_signatures_without_changing_the_roots) {
  TempDir d;
  build_log(d.path(), 12, 4);
  const std::vector<Checkpoint> before = read_cps(d);
  CHECK_EQ(before.size(), static_cast<size_t>(3));
  for (size_t i = 0; i < before.size(); ++i) {
    CHECK(!before[i].is_signed());
  }

  {
    Log log;
    Log::Options opt;
    opt.key = key();
    std::string err;
    CHECK(log.open(d.path(), opt, &err));
    CHECK(log.resign_checkpoints(&err));
    CHECK_EQ(log.checkpoint_count(), 3ull);
  }

  const std::vector<Checkpoint> after = read_cps(d, key());
  CHECK_EQ(after.size(), static_cast<size_t>(3));
  for (size_t i = 0; i < after.size(); ++i) {
    CHECK(after[i].is_signed());
    CHECK(chainlog::checkpoint_signature_valid(key(), after[i]));
    // Signing re-authenticates what is there; it must not re-derive it.
    CHECK_EQ(to_hex(after[i].root), to_hex(before[i].root));
    CHECK_EQ(after[i].first_index, before[i].first_index);
    CHECK_EQ(after[i].last_index, before[i].last_index);
  }
  CHECK_EQ(pname(check(d, {}, key()).problem), "ok");

  // No temp file left behind by the atomic replace.
  CHECK_EQ(chainlog_test::read_file(ckpt_file(d)).size(),
           chainlog::kCheckpointHeaderBytes +
               3 * (chainlog::kCheckpointOverheadBytes + 32 +
                    chainlog::kCheckpointPayloadBytes));
}

TEST(sign_is_idempotent_and_keeps_appending_working) {
  TempDir d;
  build_log(d.path(), 12, 4);

  Log::Options opt;
  opt.key = key();
  std::string err;
  {
    Log log;
    CHECK(log.open(d.path(), opt, &err));
    CHECK(log.resign_checkpoints(&err));
    CHECK(log.resign_checkpoints(&err));  // twice
  }
  const std::string once = chainlog_test::read_file(ckpt_file(d));
  {
    Log log;
    CHECK(log.open(d.path(), opt, &err));
    CHECK(log.resign_checkpoints(&err));
  }
  CHECK(chainlog_test::read_file(ckpt_file(d)) == once);

  // And new blocks sealed afterwards are signed too, so the file does not
  // end up half signed.
  {
    Log log;
    CHECK(log.open(d.path(), opt, &err));
    Record r;
    for (uint64_t i = 0; i < 4; ++i) {
      CHECK(log.append("more", &r, &err));
    }
    CHECK_EQ(log.checkpoint_count(), 4ull);
  }
  const std::vector<Checkpoint> cps = read_cps(d, key());
  CHECK_EQ(cps.size(), static_cast<size_t>(4));
  for (size_t i = 0; i < cps.size(); ++i) {
    CHECK(cps[i].is_signed());
  }
  CHECK_EQ(pname(check(d, {}, key()).problem), "ok");
}

TEST(sign_refuses_a_damaged_log) {
  TempDir d;
  build_log(d.path(), 12, 4);

  // Re-link the records so the sealed roots are stale, then try to sign.
  // Signing a tampered log must not launder it.
  std::string bytes = chainlog_test::read_file(log_file(d));
  const std::vector<FrameSpan> spans = chainlog_test::frame_spans(bytes);
  std::vector<Record> rs = chainlog_test::read_frames(bytes);
  Record forged = rs[5];
  forged.data = "rec-HACKED";
  chainlog_test::rewrite_frame(&bytes, spans[5].offset, forged);
  chainlog_test::relink_from(&bytes, 5);
  chainlog_test::write_file(log_file(d), bytes);

  Log log;
  Log::Options opt;
  opt.key = key();
  std::string err;
  CHECK(log.open(d.path(), opt, &err));
  // The stale roots are still there, so signing them would authenticate the
  // ORIGINAL history -- which is exactly right, and verify() still reports
  // the mismatch. Signing succeeds; it just does not help the attacker.
  CHECK(log.resign_checkpoints(&err));
  Verdict v;
  CHECK(log.verify(&v, &err));
  CHECK_EQ(pname(v.problem), "bad-checkpoint");
}

TEST(sign_without_a_key_is_an_error) {
  TempDir d;
  build_log(d.path(), 8, 4);

  Log log;
  Log::Options opt;  // no key
  std::string err;
  CHECK(log.open(d.path(), opt, &err));
  CHECK(!log.resign_checkpoints(&err));
  CHECK(err.find("no key supplied") != std::string::npos);
}

// --- what neither mechanism can do ----------------------------------------

// The end of the line, pinned as a passing test. An attacker who has write
// access AND the signing key can produce a directory that is internally
// perfect and correctly signed. Only an anchor -- a value they never had the
// chance to touch -- still disagrees.
TEST(an_attacker_with_the_key_is_caught_only_by_an_anchor) {
  TempDir d;
  const Log::Anchor a = build_and_anchor(d, 12, 4, key());

  std::string bytes = chainlog_test::read_file(log_file(d));
  const std::vector<FrameSpan> spans = chainlog_test::frame_spans(bytes);
  std::vector<Record> rs = chainlog_test::read_frames(bytes);
  Record forged = rs[5];
  forged.data = "rec-HACKED";
  chainlog_test::rewrite_frame(&bytes, spans[5].offset, forged);
  chainlog_test::relink_from(&bytes, 5);
  chainlog_test::write_file(log_file(d), bytes);
  chainlog_test::reseal_all_checkpoints(d.path(), key());  // signed!

  // Internally perfect, and every signature genuine.
  CHECK_EQ(pname(check(d, {}, key()).problem), "ok");
  // The anchor is the only thing left that remembers.
  CHECK_EQ(pname(check(d, {a}, key()).problem), "anchor-mismatch");
}
