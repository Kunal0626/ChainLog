// Append throughput, under each sync policy.
//
// This is the benchmark the sync policy exists for. The interesting number is
// not how fast appends can go, it is how much the durability barrier costs --
// because that is the trade an operator actually has to make.
//
// Drives the library directly rather than the CLI: one process spawn per
// record would dominate everything and measure fork(2), not the log.

#include <cstdio>
#include <string>
#include <vector>

#include "bench_util.h"
#include "log.h"

int main(int argc, char** argv) {
  const std::string dir = bench::arg_str(argc, argv, "--dir", "");
  const uint64_t count = bench::arg_u64(argc, argv, "--count", 1000);
  const uint64_t size = bench::arg_u64(argc, argv, "--size", 100);
  const uint64_t block = bench::arg_u64(argc, argv, "--block-size", 1024);
  const std::string policy = bench::arg_str(argc, argv, "--policy", "every");
  const uint64_t batch = bench::arg_u64(argc, argv, "--batch", 1000);

  if (dir.empty()) {
    std::fprintf(stderr,
                 "usage: bench_append --dir D [--count N] [--size S] "
                 "[--block-size B] [--policy every|batch|none] [--batch K]\n");
    return 2;
  }

  chainlog::Log::Options opt;
  opt.block_size = block;
  opt.sync_batch = batch;
  if (policy == "every") {
    opt.sync = chainlog::Log::SyncPolicy::kEveryAppend;
  } else if (policy == "batch") {
    opt.sync = chainlog::Log::SyncPolicy::kBatched;
  } else if (policy == "none") {
    opt.sync = chainlog::Log::SyncPolicy::kNone;
  } else {
    std::fprintf(stderr, "bench_append: unknown --policy %s\n", policy.c_str());
    return 2;
  }

  chainlog::Log log;
  std::string err;
  if (!log.open(dir, opt, &err)) {
    std::fprintf(stderr, "bench_append: %s\n", err.c_str());
    return 2;
  }

  // Built before the clock starts, so the measurement is of appending and not
  // of generating payloads.
  const std::string payload = bench::filler(static_cast<size_t>(size), 0x5eed);

  const double start = bench::now_seconds();
  chainlog::Record r;
  for (uint64_t i = 0; i < count; ++i) {
    if (!log.append(payload, &r, &err)) {
      std::fprintf(stderr, "bench_append: at %llu: %s\n",
                   static_cast<unsigned long long>(i), err.c_str());
      return 2;
    }
  }
  // Inside the measured window: a batched run that skipped its barriers has
  // not finished its work until they happen, and excluding the final flush
  // would flatter it.
  if (!log.flush(&err)) {
    std::fprintf(stderr, "bench_append: flush: %s\n", err.c_str());
    return 2;
  }
  const double elapsed = bench::now_seconds() - start;

  const uint64_t bytes_on_disk = log.stats().log_bytes;

  bench::emit("append_policy", policy);
  if (policy == "batch") {
    bench::emit("append_batch", batch);
  }
  bench::emit("append_count", count);
  bench::emit("append_record_bytes", size);
  bench::emit("append_seconds", elapsed);
  bench::emit("append_per_second",
              elapsed > 0 ? static_cast<double>(count) / elapsed : 0.0);
  bench::emit("append_us_each",
              count > 0 ? elapsed * 1e6 / static_cast<double>(count) : 0.0);
  bench::emit("append_log_bytes", bytes_on_disk);
  bench::emit("append_checkpoints", log.checkpoint_count());
  bench::emit("peak_rss_bytes", bench::peak_rss_bytes());
  return 0;
}
