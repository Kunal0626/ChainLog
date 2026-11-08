// Checks that peak_rss_bytes() reports the unit it claims to.
//
// Allocates and TOUCHES a known amount, then reports the measured peak. Just
// allocating would not do: untouched pages may never be resident. run.sh
// compares the measured growth against the expected figure and refuses to
// publish any results if the two disagree by more than a factor of two --
// because every memory number in RESULTS.md depends on this one function
// being right about bytes versus kilobytes.

#include <cstdint>
#include <vector>

#include "bench_util.h"

int main(int argc, char** argv) {
  const uint64_t mib = bench::arg_u64(argc, argv, "--mib", 256);
  const uint64_t want = mib * 1024 * 1024;

  const uint64_t before = bench::peak_rss_bytes();

  // volatile so the touch loop cannot be optimised away.
  std::vector<unsigned char> block(static_cast<size_t>(want));
  volatile unsigned char sink = 0;
  for (size_t i = 0; i < block.size(); i += 4096) {
    block[i] = static_cast<unsigned char>(i);
    sink = static_cast<unsigned char>(sink + block[i]);
  }
  (void)sink;

  const uint64_t after = bench::peak_rss_bytes();

  bench::emit("mem_expected_bytes", want);
  bench::emit("mem_rss_before_bytes", before);
  bench::emit("mem_rss_after_bytes", after);
  bench::emit("mem_rss_growth_bytes", after > before ? after - before : 0);
  return 0;
}
