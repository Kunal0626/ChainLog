// HMAC-SHA256 known-answer tests.
//
// The expected values are the published RFC 4231 vectors, which also means
// they confirm the key-padding and double-hashing structure rather than just
// the arithmetic. tests/oracle_hmac.sh re-checks against python's hmac module
// over random keys and messages, for the same reason the SHA-256 oracle
// exists: a self-consistent implementation of the wrong construction passes
// every test you write against itself.

#include <string>

#include "hex.h"
#include "hmac.h"
#include "test.h"

using chainlog::Digest;
using chainlog::hmac_sha256;
using chainlog::to_hex;

namespace {

std::string repeat_byte(uint8_t b, size_t n) {
  return std::string(n, static_cast<char>(b));
}

std::string mac(const std::string& key, const std::string& msg) {
  return to_hex(hmac_sha256(key, msg));
}

}  // namespace

TEST(rfc4231_vector_1) {
  CHECK_EQ(mac(repeat_byte(0x0b, 20), "Hi There"),
           "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
}

TEST(rfc4231_vector_2_short_key) {
  // A 4-byte key: exercises the zero-padding path.
  CHECK_EQ(mac("Jefe", "what do ya want for nothing?"),
           "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
}

TEST(rfc4231_vector_3) {
  CHECK_EQ(mac(repeat_byte(0xaa, 20), repeat_byte(0xdd, 50)),
           "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");
}

TEST(rfc4231_vector_4) {
  std::string key;
  for (int i = 1; i <= 25; ++i) {
    key.push_back(static_cast<char>(i));
  }
  CHECK_EQ(mac(key, repeat_byte(0xcd, 50)),
           "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b");
}

TEST(rfc4231_vector_5) {
  CHECK_EQ(mac(repeat_byte(0x0c, 20), "Test With Truncation"),
           "a3b6167473100ee06e0c796c2955552bfa6f7c0a6a8aef8b93f860aab0cd20c5");
}

// A key LONGER than the 64-byte block is hashed down first. These two vectors
// are the ones that catch getting that branch wrong.
TEST(rfc4231_vector_6_oversized_key) {
  CHECK_EQ(mac(repeat_byte(0xaa, 131),
               "Test Using Larger Than Block-Size Key - Hash Key First"),
           "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
}

TEST(rfc4231_vector_7_oversized_key_and_message) {
  CHECK_EQ(mac(repeat_byte(0xaa, 131),
               "This is a test using a larger than block-size key and a "
               "larger than block-size data. The key needs to be hashed "
               "before being used by the HMAC algorithm."),
           "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2");
}

// The block boundary in the key padding: 63, 64 and 65 bytes take three
// different paths through step 1.
TEST(key_length_block_boundaries) {
  CHECK_EQ(mac(repeat_byte(0x5a, 64), "exactly one block of key"),
           "e2108745b8fc71fdceb054392be748dbd5c87841c94dfb07b0071f15b15e3fb4");
  CHECK_EQ(mac(repeat_byte(0x5a, 65), "one byte over a block"),
           "e6c710d1558ced67c4d950c96be57b1714298b76349edbefa120dbec9a2b9dca");
  CHECK_EQ(mac("", ""),
           "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad");
}

// A 64-byte key and the SHA-256 digest of a longer key give the same MAC,
// because step 1 hashes an oversized key down to 32 bytes and then zero-pads
// to 64. Pinned because it is a real documented property of HMAC and someone
// reading the code will wonder whether it is a bug.
TEST(an_oversized_key_is_equivalent_to_its_digest) {
  const std::string long_key = repeat_byte(0x77, 200);
  const Digest digest = chainlog::Sha256::hash(long_key);
  std::string padded(reinterpret_cast<const char*>(digest.data()),
                     digest.size());
  CHECK_EQ(mac(long_key, "a message"), mac(padded, "a message"));
}

TEST(a_different_key_gives_a_different_mac) {
  const std::string msg = "block 7 root abc123";
  const std::string a = mac(repeat_byte(0x01, 32), msg);
  const std::string b = mac(repeat_byte(0x02, 32), msg);
  CHECK(a != b);

  // And one flipped bit in a 32-byte key changes the whole output.
  std::string key = repeat_byte(0x01, 32);
  key[17] = static_cast<char>(key[17] ^ 0x01);
  CHECK(mac(key, msg) != a);
}

TEST(a_flipped_bit_in_the_message_changes_the_mac) {
  const std::string key = repeat_byte(0x9e, 32);
  std::string msg(64, 'm');
  const std::string base = mac(key, msg);
  for (size_t i = 0; i < msg.size(); ++i) {
    std::string mutated = msg;
    mutated[i] = static_cast<char>(mutated[i] ^ 0x80);
    CHECK(mac(key, mutated) != base);
  }
}

TEST(constant_time_compare_agrees_with_equality) {
  Digest a = chainlog::Sha256::hash("one");
  Digest b = chainlog::Sha256::hash("one");
  Digest c = chainlog::Sha256::hash("two");
  CHECK(chainlog::digests_equal_constant_time(a, b));
  CHECK(!chainlog::digests_equal_constant_time(a, c));

  // Differing in only the last byte must still compare unequal -- the obvious
  // way to get this wrong is to return early and miss the tail.
  Digest d = a;
  d[31] = static_cast<uint8_t>(d[31] ^ 0x01);
  CHECK(!chainlog::digests_equal_constant_time(a, d));

  // And in only the first.
  Digest e = a;
  e[0] = static_cast<uint8_t>(e[0] ^ 0x01);
  CHECK(!chainlog::digests_equal_constant_time(a, e));
}
