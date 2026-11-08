#include "bench_util.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <sys/resource.h>

namespace bench {

double now_seconds() {
  const auto t = std::chrono::steady_clock::now().time_since_epoch();
  return std::chrono::duration<double>(t).count();
}

uint64_t peak_rss_bytes() {
  struct rusage ru;
  if (::getrusage(RUSAGE_SELF, &ru) != 0) {
    return 0;
  }
#if defined(__APPLE__)
  // Darwin: bytes.
  return static_cast<uint64_t>(ru.ru_maxrss);
#else
  // Linux and most other POSIX systems: kilobytes.
  return static_cast<uint64_t>(ru.ru_maxrss) * 1024;
#endif
}

double median(std::vector<double> values) {
  if (values.empty()) {
    return 0.0;
  }
  std::sort(values.begin(), values.end());
  const size_t mid = values.size() / 2;
  if (values.size() % 2 == 1) {
    return values[mid];
  }
  return (values[mid - 1] + values[mid]) / 2.0;
}

double minimum(const std::vector<double>& values) {
  if (values.empty()) {
    return 0.0;
  }
  return *std::min_element(values.begin(), values.end());
}

double maximum(const std::vector<double>& values) {
  if (values.empty()) {
    return 0.0;
  }
  return *std::max_element(values.begin(), values.end());
}

void emit(const std::string& key, double value) {
  std::printf("%s=%.6f\n", key.c_str(), value);
}

void emit(const std::string& key, uint64_t value) {
  std::printf("%s=%llu\n", key.c_str(), static_cast<unsigned long long>(value));
}

void emit(const std::string& key, const std::string& value) {
  std::printf("%s=%s\n", key.c_str(), value.c_str());
}

std::string filler(size_t len, uint64_t seed) {
  // xorshift64*, which is plenty for producing bytes that do not compress and
  // are the same on every run.
  std::string out;
  out.reserve(len);
  uint64_t x = seed | 1;
  while (out.size() < len) {
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    const uint64_t v = x * 0x2545F4914F6CDD1Dull;
    for (int b = 0; b < 8 && out.size() < len; ++b) {
      out.push_back(static_cast<char>((v >> (8 * b)) & 0xff));
    }
  }
  return out;
}

std::string arg_str(int argc, char** argv, const std::string& name,
                    const std::string& fallback) {
  for (int i = 1; i + 1 < argc; ++i) {
    if (name == argv[i]) {
      return argv[i + 1];
    }
  }
  return fallback;
}

uint64_t arg_u64(int argc, char** argv, const std::string& name,
                 uint64_t fallback) {
  const std::string s = arg_str(argc, argv, name, "");
  if (s.empty()) {
    return fallback;
  }
  return std::strtoull(s.c_str(), nullptr, 10);
}

bool arg_flag(int argc, char** argv, const std::string& name) {
  for (int i = 1; i < argc; ++i) {
    if (name == argv[i]) {
      return true;
    }
  }
  return false;
}

}  // namespace bench
