// cl-hmac -- HMAC-SHA256 of stdin under a hex key, printed as hex.
// Exists so tests/oracle_hmac.sh can cross-check against python's hmac.

#include <cstdio>
#include <string>
#include <vector>

#include "hex.h"
#include "hmac.h"

int main(int argc, char** argv) {
  if (argc != 2) {
    std::fprintf(stderr, "usage: cl-hmac <key-hex> < message\n");
    return 2;
  }

  std::string key;
  std::string detail;
  if (!chainlog::from_hex(argv[1], &key, &detail)) {
    std::fprintf(stderr, "cl-hmac: bad key hex: %s\n", detail.c_str());
    return 2;
  }

  std::string msg;
  char buf[65536];
  while (true) {
    const size_t n = std::fread(buf, 1, sizeof(buf), stdin);
    msg.append(buf, n);
    if (n < sizeof(buf)) {
      if (std::ferror(stdin) != 0) {
        std::fprintf(stderr, "cl-hmac: read error on stdin\n");
        return 2;
      }
      break;
    }
  }

  std::printf("%s\n",
              chainlog::to_hex(chainlog::hmac_sha256(key, msg)).c_str());
  return 0;
}
