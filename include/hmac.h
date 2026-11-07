// HMAC-SHA256 (RFC 2104), by hand on top of the hand-written SHA-256.
//
// Used to sign checkpoints so that an attacker with write access to the log
// directory cannot forge one. The key lives outside the directory; if it does
// not, signing buys nothing.
//
// Why HMAC rather than SHA256(key || message): SHA-256 is a Merkle-Damgard
// construction, so from H(key || m) and the length of key||m an attacker can
// compute H(key || m || pad || m') for a message m' of their choosing --
// without knowing the key. That is the length-extension attack, and it is
// exactly the hazard the padding discussion in sha256.cpp sets up. HMAC's two
// nested hashes with distinct pads make the construction immune to it.
#ifndef CHAINLOG_HMAC_H
#define CHAINLOG_HMAC_H

#include <cstddef>
#include <cstdint>
#include <string>

#include "sha256.h"

namespace chainlog {

// A key shorter than 16 bytes is refused by the CLI rather than silently
// accepted: the whole point of signing is that the attacker cannot guess it.
constexpr size_t kMinKeyBytes = 16;

Digest hmac_sha256(const void* key, size_t key_len, const void* msg,
                   size_t msg_len);

Digest hmac_sha256(const std::string& key, const std::string& msg);

// Compares two digests without an early exit.
//
// Not because a local timing attack on a log file is likely, but because
// "compare MACs in constant time" is the kind of habit that has to be
// unconditional to be worth anything -- the moment it is applied selectively,
// the one place it was skipped is the one that mattered.
bool digests_equal_constant_time(const Digest& a, const Digest& b);

}  // namespace chainlog

#endif  // CHAINLOG_HMAC_H
