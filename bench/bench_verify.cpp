// Time to verify an existing log, and to open one.
//
// Both are reported because both are O(n) and they measure different work:
// open() walks every frame checking magic, lengths and CRC-32 but computes no
// SHA-256, while verify() recomputes every record hash, every chain link and
// every Merkle root. The gap between them is the cost of the hashing.

#include <cstdio>
#include <string>

#include "bench_util.h"
#include "log.h"

int main(int argc, char** argv) {
  const std::string dir = bench::arg_str(argc, argv, "--dir", "");
  if (dir.empty()) {
    std::fprintf(stderr, "usage: bench_verify --dir D\n");
    return 2;
  }

  chainlog::Log::Options opt;
  chainlog::Log log;
  std::string err;

  const double open_start = bench::now_seconds();
  if (!log.open(dir, opt, &err)) {
    std::fprintf(stderr, "bench_verify: %s\n", err.c_str());
    return 2;
  }
  const double open_seconds = bench::now_seconds() - open_start;

  const uint64_t records = log.record_count();
  const uint64_t bytes = log.stats().log_bytes;

  const double start = bench::now_seconds();
  chainlog::Verdict v;
  if (!log.verify(&v, &err)) {
    std::fprintf(stderr, "bench_verify: %s\n", err.c_str());
    return 2;
  }
  const double elapsed = bench::now_seconds() - start;

  if (!v.ok()) {
    std::fprintf(stderr, "bench_verify: the log does not verify: %s\n",
                 v.message().c_str());
    return 1;
  }

  bench::emit("verify_records", records);
  bench::emit("verify_log_bytes", bytes);
  bench::emit("open_seconds", open_seconds);
  bench::emit("verify_seconds", elapsed);
  bench::emit("verify_records_per_second",
              elapsed > 0 ? static_cast<double>(records) / elapsed : 0.0);
  bench::emit("verify_mb_per_second",
              elapsed > 0
                  ? static_cast<double>(bytes) / elapsed / (1024.0 * 1024.0)
                  : 0.0);
  bench::emit("peak_rss_bytes", bench::peak_rss_bytes());
  return 0;
}
