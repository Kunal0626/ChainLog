#include "hmac.h"

#include <cstring>

namespace chainlog {
namespace {

constexpr size_t kBlock = Sha256::kBlockSize;  // 64
constexpr uint8_t kIpad = 0x36;
constexpr uint8_t kOpad = 0x5c;

}  // namespace

Digest hmac_sha256(const void* key, size_t key_len, const void* msg,
                   size_t msg_len) {
  // Step 1: bring the key to exactly one block.
  //
  // A key longer than the block is hashed first. That is what makes
  // HMAC well defined for any key length -- and it has a consequence worth
  // knowing: a 64-byte key and the 64-byte SHA-256 digest of a longer key
  // produce the same MAC, so those two keys are interchangeable. It is a
  // documented property of HMAC, not a bug here.
  uint8_t k0[kBlock];
  std::memset(k0, 0, sizeof(k0));
  if (key_len > kBlock) {
    const Digest hashed = Sha256::hash(key, key_len);
    std::memcpy(k0, hashed.data(), hashed.size());
  } else if (key_len > 0) {
    std::memcpy(k0, key, key_len);
  }

  // Step 2: inner hash over (K0 ^ ipad) || message.
  uint8_t pad[kBlock];
  for (size_t i = 0; i < kBlock; ++i) {
    pad[i] = static_cast<uint8_t>(k0[i] ^ kIpad);
  }
  Sha256 inner;
  inner.update(pad, sizeof(pad));
  inner.update(msg, msg_len);
  const Digest inner_digest = inner.finish();

  // Step 3: outer hash over (K0 ^ opad) || inner.
  //
  // Two distinct pads, so the inner and outer hashes are keyed differently.
  // That is the whole trick: an attacker who can length-extend the inner hash
  // still cannot produce the outer one without the key.
  for (size_t i = 0; i < kBlock; ++i) {
    pad[i] = static_cast<uint8_t>(k0[i] ^ kOpad);
  }
  Sha256 outer;
  outer.update(pad, sizeof(pad));
  outer.update(inner_digest.data(), inner_digest.size());
  return outer.finish();
}

Digest hmac_sha256(const std::string& key, const std::string& msg) {
  return hmac_sha256(key.data(), key.size(), msg.data(), msg.size());
}

bool digests_equal_constant_time(const Digest& a, const Digest& b) {
  // OR the differences together and test once at the end, so the loop runs
  // the same number of iterations whatever the inputs are.
  uint8_t diff = 0;
  for (size_t i = 0; i < a.size(); ++i) {
    diff = static_cast<uint8_t>(diff | (a[i] ^ b[i]));
  }
  return diff == 0;
}

}  // namespace chainlog
