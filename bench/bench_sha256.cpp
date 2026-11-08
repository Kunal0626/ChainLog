// Throughput of the hand-written SHA-256.
//
// Reported so the README can be honest about the cost of not using a library.
// OpenSSL and shasum(1) use the ARMv8 cryptographic extensions -- single
// instructions for the round function -- and this implementation does not.
// run.sh measures shasum on the same input so the two appear side by side
// rather than as a number with no scale.

#include <cstdio>
#include <string>

#include "bench_util.h"
#include "sha256.h"

int main(int argc, char** argv) {
  const uint64_t mib = bench::arg_u64(argc, argv, "--mib", 256);
  const uint64_t chunk = bench::arg_u64(argc, argv, "--chunk", 65536);
  const uint64_t total = mib * 1024 * 1024;

  const std::string buf = bench::filler(static_cast<size_t>(chunk), 0xf00d);

  chainlog::Sha256 h;
  const double start = bench::now_seconds();
  uint64_t done = 0;
  while (done < total) {
    h.update(buf.data(), buf.size());
    done += buf.size();
  }
  const chainlog::Digest d = h.finish();
  const double elapsed = bench::now_seconds() - start;

  // Consume the digest so the whole loop cannot be optimised away.
  volatile uint8_t sink = d[0];
  (void)sink;

  bench::emit("sha256_bytes", done);
  bench::emit("sha256_chunk_bytes", chunk);
  bench::emit("sha256_seconds", elapsed);
  bench::emit("sha256_mb_per_second",
              elapsed > 0
                  ? static_cast<double>(done) / elapsed / (1024.0 * 1024.0)
                  : 0.0);
  return 0;
}
