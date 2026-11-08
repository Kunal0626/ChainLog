// Merkle tree build, proof size, and proof generation + verification time.
//
// Run over synthetic leaves rather than a real log, so the numbers are about
// the tree and not about disk I/O. The 1M-leaf case is the one the brief asks
// for; it is far larger than any real block (the default is 1024 records per
// checkpoint), and it is here to show the shape of the log(n) curve.

#include <cstdio>
#include <string>
#include <vector>

#include "bench_util.h"
#include "merkle.h"
#include "sha256.h"

int main(int argc, char** argv) {
  const uint64_t leaves = bench::arg_u64(argc, argv, "--leaves", 1048576);
  const uint64_t proofs = bench::arg_u64(argc, argv, "--proofs", 10000);

  // Synthetic record hashes, generated before the clock starts.
  std::vector<chainlog::Digest> hashes;
  hashes.reserve(static_cast<size_t>(leaves));
  for (uint64_t i = 0; i < leaves; ++i) {
    hashes.push_back(chainlog::Sha256::hash(
        reinterpret_cast<const char*>(&i), sizeof(i)));
  }
  const uint64_t rss_after_leaves = bench::peak_rss_bytes();

  const double build_start = bench::now_seconds();
  const chainlog::MerkleTree tree = chainlog::MerkleTree::build(hashes);
  const double build_seconds = bench::now_seconds() - build_start;
  const uint64_t rss_after_tree = bench::peak_rss_bytes();

  // Spread the sampled positions across the tree rather than taking the first
  // N, so the promoted-node paths on the right edge are included.
  const uint64_t stride = (leaves / (proofs == 0 ? 1 : proofs)) + 1;

  uint64_t checked = 0;
  uint64_t total_steps = 0;
  uint64_t max_steps = 0;
  const double proof_start = bench::now_seconds();
  for (uint64_t i = 0; i < leaves && checked < proofs; i += stride) {
    chainlog::Proof p;
    if (!chainlog::merkle_prove(tree, i, &p)) {
      std::fprintf(stderr, "bench_merkle: prove(%llu) failed\n",
                   static_cast<unsigned long long>(i));
      return 2;
    }
    std::string detail;
    if (!chainlog::merkle_verify_proof(hashes[static_cast<size_t>(i)], i,
                                       leaves, p, tree.root(), &detail)) {
      std::fprintf(stderr, "bench_merkle: verify(%llu) failed: %s\n",
                   static_cast<unsigned long long>(i), detail.c_str());
      return 2;
    }
    total_steps += p.size();
    if (p.size() > max_steps) {
      max_steps = p.size();
    }
    ++checked;
  }
  const double proof_seconds = bench::now_seconds() - proof_start;

  bench::emit("merkle_leaves", leaves);
  bench::emit("merkle_levels", static_cast<uint64_t>(tree.levels()));
  bench::emit("merkle_build_seconds", build_seconds);
  bench::emit("merkle_build_leaves_per_second",
              build_seconds > 0 ? static_cast<double>(leaves) / build_seconds
                                : 0.0);
  bench::emit("merkle_proofs_checked", checked);
  bench::emit("merkle_proof_max_steps", max_steps);
  bench::emit("merkle_proof_mean_steps",
              checked > 0 ? static_cast<double>(total_steps) /
                                static_cast<double>(checked)
                          : 0.0);
  // 1 flag byte + 32 hash bytes per step, plus the 26-byte self-describing
  // header and a 4-byte CRC-32. This is the figure that matters to anyone
  // shipping a proof over a wire.
  bench::emit("merkle_proof_max_wire_bytes",
              max_steps * chainlog::kProofStepBytes +
                  chainlog::kProofHeaderBytes + chainlog::kProofTrailerBytes);
  bench::emit("merkle_proof_plus_verify_seconds", proof_seconds);
  bench::emit("merkle_proof_plus_verify_us_each",
              checked > 0 ? proof_seconds * 1e6 / static_cast<double>(checked)
                          : 0.0);
  bench::emit("merkle_rss_after_leaves_bytes", rss_after_leaves);
  bench::emit("merkle_rss_after_tree_bytes", rss_after_tree);
  bench::emit("peak_rss_bytes", bench::peak_rss_bytes());
  return 0;
}
