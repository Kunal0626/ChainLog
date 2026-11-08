// Shared measurement helpers for the benchmarks.
//
// Every benchmark prints nothing but "key=value" lines, so bench/run.sh can
// aggregate them without parsing prose, and so a number in bench/RESULTS.md
// can always be traced back to the program that produced it.
#ifndef CHAINLOG_BENCH_UTIL_H
#define CHAINLOG_BENCH_UTIL_H

#include <cstdint>
#include <string>
#include <vector>

namespace bench {

// Monotonic seconds. steady_clock, not system_clock: an NTP step during a
// benchmark would otherwise produce a negative or wildly wrong duration.
double now_seconds();

// Peak resident set size of this process, in BYTES.
//
// getrusage(2) reports ru_maxrss in bytes on Darwin and in kilobytes on
// Linux. Getting that wrong is a silent 1024x error in whichever direction,
// and a memory figure is exactly the sort of number that ends up quoted
// somewhere it cannot be corrected. bench_mem checks this against a known
// allocation, and run.sh refuses to publish results if the check fails.
uint64_t peak_rss_bytes();

// Median of a copy of `values`.
//
// Medians rather than means throughout: one unlucky run -- a background
// process waking up, a thermal throttle, a page cache miss -- moves a mean
// and barely moves a median. The min and max are reported alongside so the
// spread is visible rather than hidden.
double median(std::vector<double> values);
double minimum(const std::vector<double>& values);
double maximum(const std::vector<double>& values);

void emit(const std::string& key, double value);
void emit(const std::string& key, uint64_t value);
void emit(const std::string& key, const std::string& value);

// Deterministic pseudo-random bytes, so a benchmark run is reproducible and
// two runs are comparing the same work. Not for anything cryptographic.
std::string filler(size_t len, uint64_t seed);

// Minimal argument parsing: --name value. Returns `fallback` if absent.
std::string arg_str(int argc, char** argv, const std::string& name,
                    const std::string& fallback);
uint64_t arg_u64(int argc, char** argv, const std::string& name,
                 uint64_t fallback);
bool arg_flag(int argc, char** argv, const std::string& name);

}  // namespace bench

#endif  // CHAINLOG_BENCH_UTIL_H
