#include "checkpoint.h"

#include <cstdio>
#include <cstring>

#include "crc32.h"
#include "hmac.h"

namespace chainlog {
namespace {

const char kMagic[8] = {'C', 'H', 'L', 'G', 'C', 'K', 'P', 'T'};

// The 52 bytes an HMAC is computed over, and the first 52 bytes of every
// payload on disk. One function so the signer and the verifier cannot
// disagree about what is being signed.
void encode_unsigned_payload(const Checkpoint& c, uint8_t out[52]) {
  put_u32_le(out, c.flags);
  put_u64_le(out + 4, c.first_index);
  put_u64_le(out + 12, c.last_index);
  std::memcpy(out + 20, c.root.data(), c.root.size());
}

}  // namespace

void sign_checkpoint(const std::string& key, Checkpoint* c) {
  c->flags |= kCheckpointFlagSigned;
  uint8_t payload[kCheckpointPayloadBytes];
  encode_unsigned_payload(*c, payload);
  c->hmac = hmac_sha256(key.data(), key.size(), payload, sizeof(payload));
}

bool checkpoint_signature_valid(const std::string& key, const Checkpoint& c) {
  if (!c.is_signed()) {
    return false;
  }
  uint8_t payload[kCheckpointPayloadBytes];
  encode_unsigned_payload(c, payload);
  const Digest expected =
      hmac_sha256(key.data(), key.size(), payload, sizeof(payload));
  return digests_equal_constant_time(expected, c.hmac);
}

void encode_checkpoint_header(const CheckpointHeader& h, std::string* out) {
  uint8_t buf[kCheckpointHeaderBytes];
  std::memset(buf, 0, sizeof(buf));
  std::memcpy(buf, kMagic, sizeof(kMagic));
  put_u32_le(buf + 8, h.format_version);
  put_u32_le(buf + 12, h.flags);
  put_u64_le(buf + 16, h.block_size);
  put_u32_le(buf + 24, 0);
  put_u32_le(buf + 28, crc32(buf, 28));
  out->append(reinterpret_cast<const char*>(buf), sizeof(buf));
}

Problem decode_checkpoint_header(const void* buf, size_t len,
                                 CheckpointHeader* out, std::string* detail) {
  if (len < kCheckpointHeaderBytes) {
    if (detail != nullptr) {
      *detail = "checkpoints file is shorter than its 32-byte header";
    }
    return Problem::kBadCheckpoint;
  }
  const uint8_t* p = static_cast<const uint8_t*>(buf);

  if (std::memcmp(p, kMagic, sizeof(kMagic)) != 0) {
    if (detail != nullptr) {
      *detail = "checkpoints magic is not \"CHLGCKPT\"";
    }
    return Problem::kBadCheckpoint;
  }
  if (get_u32_le(p + 28) != crc32(p, 28)) {
    if (detail != nullptr) {
      *detail = "checkpoints header crc32 mismatch";
    }
    return Problem::kBadCheckpoint;
  }

  CheckpointHeader h;
  h.format_version = get_u32_le(p + 8);
  h.flags = get_u32_le(p + 12);
  h.block_size = get_u64_le(p + 16);

  if (h.format_version != kCheckpointFormatVersion) {
    if (detail != nullptr) {
      *detail = "checkpoints format version " +
                std::to_string(h.format_version) +
                ", this build understands " +
                std::to_string(kCheckpointFormatVersion);
    }
    return Problem::kBadCheckpoint;
  }
  if (h.flags != 0) {
    if (detail != nullptr) {
      *detail = "unknown flags in the checkpoints header: " +
                std::to_string(h.flags);
    }
    return Problem::kBadCheckpoint;
  }
  if (h.block_size == 0) {
    if (detail != nullptr) {
      *detail = "checkpoints header block_size is 0";
    }
    return Problem::kBadCheckpoint;
  }

  *out = h;
  return Problem::kOk;
}

void append_checkpoint_frame(const Checkpoint& c, std::string* out) {
  uint8_t payload[kCheckpointSignedPayloadBytes];
  encode_unsigned_payload(c, payload);
  size_t payload_len = kCheckpointPayloadBytes;
  if (c.is_signed()) {
    std::memcpy(payload + kCheckpointPayloadBytes, c.hmac.data(),
                c.hmac.size());
    payload_len = kCheckpointSignedPayloadBytes;
  }

  uint8_t frame_head[8];
  put_u32_le(frame_head, kCheckpointMagic);
  put_u32_le(frame_head + 4, static_cast<uint32_t>(payload_len));
  out->append(reinterpret_cast<const char*>(frame_head), sizeof(frame_head));
  out->append(reinterpret_cast<const char*>(payload), payload_len);

  uint8_t crc[4];
  put_u32_le(crc, crc32(payload, payload_len));
  out->append(reinterpret_cast<const char*>(crc), sizeof(crc));
}

Problem decode_checkpoint_frame(const void* buf, size_t len, Checkpoint* out,
                                size_t* consumed, std::string* detail) {
  if (len < 8) {
    if (detail != nullptr) {
      *detail = "fewer than 8 bytes available for a checkpoint prologue";
    }
    return Problem::kTornCheckpointTail;
  }

  const uint8_t* p = static_cast<const uint8_t*>(buf);
  if (get_u32_le(p) != kCheckpointMagic) {
    if (detail != nullptr) {
      *detail = "checkpoint frame does not start with \"CKPT\"";
    }
    return Problem::kBadCheckpoint;
  }

  const uint32_t payload_len = get_u32_le(p + 4);
  // Exactly two sizes are legal: unsigned, and signed with an HMAC appended.
  if (payload_len != kCheckpointPayloadBytes &&
      payload_len != kCheckpointSignedPayloadBytes) {
    if (detail != nullptr) {
      *detail = "checkpoint payload length " + std::to_string(payload_len) +
                ", expected " + std::to_string(kCheckpointPayloadBytes) +
                " (unsigned) or " +
                std::to_string(kCheckpointSignedPayloadBytes) + " (signed)";
    }
    return Problem::kBadCheckpoint;
  }

  const size_t frame_len = kCheckpointOverheadBytes + payload_len;
  if (len < frame_len) {
    if (detail != nullptr) {
      *detail = "checkpoint frame needs " + std::to_string(frame_len) +
                " bytes, only " + std::to_string(len) + " available";
    }
    return Problem::kTornCheckpointTail;
  }

  const uint8_t* payload = p + 8;
  const uint32_t stored_crc = get_u32_le(payload + payload_len);
  const uint32_t actual_crc = crc32(payload, payload_len);
  if (stored_crc != actual_crc) {
    if (detail != nullptr) {
      char msg[96];
      std::snprintf(msg, sizeof(msg),
                    "checkpoint crc32 stored %08x, computed %08x", stored_crc,
                    actual_crc);
      *detail = msg;
    }
    return Problem::kBadCheckpoint;
  }

  Checkpoint c;
  c.flags = get_u32_le(payload);
  c.first_index = get_u64_le(payload + 4);
  c.last_index = get_u64_le(payload + 12);
  std::memcpy(c.root.data(), payload + 20, 32);

  if ((c.flags & ~kCheckpointFlagSigned) != 0) {
    if (detail != nullptr) {
      *detail = "unknown checkpoint flags: " + std::to_string(c.flags);
    }
    return Problem::kBadCheckpoint;
  }
  // The flag and the length have to agree. Letting them disagree would mean a
  // 52-byte payload could claim to be signed (with no MAC to check) or an
  // 84-byte one could hide 32 bytes nothing looks at.
  const bool claims_signed = c.is_signed();
  const bool has_mac = (payload_len == kCheckpointSignedPayloadBytes);
  if (claims_signed != has_mac) {
    if (detail != nullptr) {
      *detail = claims_signed
                    ? "checkpoint is flagged signed but carries no HMAC"
                    : "checkpoint carries an HMAC but is not flagged signed";
    }
    return Problem::kBadCheckpoint;
  }
  if (has_mac) {
    std::memcpy(c.hmac.data(), payload + kCheckpointPayloadBytes, 32);
  }
  if (c.last_index < c.first_index) {
    if (detail != nullptr) {
      *detail = "checkpoint range runs backwards: " +
                std::to_string(c.first_index) + ".." +
                std::to_string(c.last_index);
    }
    return Problem::kBadCheckpoint;
  }

  *out = c;
  if (consumed != nullptr) {
    *consumed = frame_len;
  }
  return Problem::kOk;
}

}  // namespace chainlog
