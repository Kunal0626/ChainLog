#!/usr/bin/env python3
"""The attacker's toolkit: byte surgery on a ChainLog directory.

Deliberately standalone. It imports nothing from this project and uses
python's own hashlib and zlib, because a real attacker would not be using our
code either -- they would read the format and write their own tool, exactly as
this does. That also means the demo is not quietly testing ChainLog against
itself.

Subcommands, in increasing order of effort:

    flip DIR INDEX        flip one bit inside record INDEX's data
    reframe DIR INDEX     rewrite record INDEX's data and fix the frame CRC
    rehash DIR INDEX      ... and recompute that record's own hash
    relink DIR INDEX      ... and re-link every record after it
    reseal DIR [KEYHEX]   recompute every checkpoint root (signed, with a key)
    delete DIR INDEX      remove record INDEX's frame entirely
    swap DIR I J          exchange two records' frames
    truncate DIR N        keep only records 0..N-1, and trim the checkpoints
    truncate-mid DIR N    cut N bytes off the end, mid-frame
    strip-signatures DIR  drop the HMAC from every checkpoint
"""

import hashlib
import os
import struct
import sys
import zlib

HEADER = 32
FRAME_OVERHEAD = 12
PAYLOAD_FIXED = 88

CKPT_HEADER = 32
CKPT_OVERHEAD = 12
CKPT_PAYLOAD = 52
CKPT_FLAG_SIGNED = 1


def crc(b):
    return zlib.crc32(b) & 0xFFFFFFFF


def read(path):
    with open(path, "rb") as f:
        return bytearray(f.read())


def write(path, data):
    with open(path, "wb") as f:
        f.write(bytes(data))


def log_path(d):
    return os.path.join(d, "log")


def ckpt_path(d):
    return os.path.join(d, "checkpoints")


def block_size(blob):
    return struct.unpack_from("<Q", blob, 16)[0]


def spans(blob):
    """[(offset, payload_len)] for every frame."""
    out, off = [], HEADER
    while off < len(blob):
        plen = struct.unpack_from("<I", blob, off + 4)[0]
        out.append((off, plen))
        off += FRAME_OVERHEAD + plen
    return out


def payload_of(blob, off, plen):
    return bytearray(blob[off + 8:off + 8 + plen])


def put_payload(blob, off, plen, payload):
    blob[off + 8:off + 8 + plen] = payload
    struct.pack_into("<I", blob, off + 8 + plen, crc(bytes(payload)))


def fields(payload):
    """(index, timestamp, data_len) and the offsets of data/prev/hash."""
    index, ts, dlen = struct.unpack_from("<QQQ", payload, 0)
    return index, ts, dlen


def record_hash(payload, dlen):
    return hashlib.sha256(bytes(payload[:24 + dlen + 32])).digest()


def set_data(payload, dlen, new):
    """Replaces the data in place; new must be exactly dlen bytes."""
    assert len(new) == dlen, "data length must not change"
    payload[24:24 + dlen] = new


def hacked_bytes(dlen):
    return b"rec-HACKED".ljust(dlen, b"!")[:dlen]


# --- Merkle, per docs/FORMAT.md --------------------------------------------

def mth(leaves):
    if not leaves:
        return hashlib.sha256(b"").digest()
    if len(leaves) == 1:
        return hashlib.sha256(b"\x00" + leaves[0]).digest()
    k = 1
    while k * 2 < len(leaves):
        k *= 2
    return hashlib.sha256(b"\x01" + mth(leaves[:k]) + mth(leaves[k:])).digest()


def hmac_sha256(key, msg):
    block = 64
    if len(key) > block:
        key = hashlib.sha256(key).digest()
    key = key.ljust(block, b"\x00")
    inner = hashlib.sha256(bytes(b ^ 0x36 for b in key) + msg).digest()
    return hashlib.sha256(bytes(b ^ 0x5C for b in key) + inner).digest()


def all_record_hashes(blob):
    out = []
    for off, plen in spans(blob):
        pay = payload_of(blob, off, plen)
        _, _, dlen = fields(pay)
        out.append(bytes(pay[24 + dlen + 32:24 + dlen + 64]))
    return out


def write_checkpoints(d, hashes, bs, key=None):
    old = read(ckpt_path(d))
    out = bytearray(old[:CKPT_HEADER])
    for blk in range(len(hashes) // bs):
        leaves = hashes[blk * bs:(blk + 1) * bs]
        flags = CKPT_FLAG_SIGNED if key else 0
        pay = struct.pack("<IQQ", flags, blk * bs, blk * bs + bs - 1)
        pay += mth(leaves)
        if key:
            pay += hmac_sha256(key, pay)
        out += b"CKPT" + struct.pack("<I", len(pay)) + pay
        out += struct.pack("<I", crc(pay))
    write(ckpt_path(d), out)
    return len(hashes) // bs


# --- subcommands ------------------------------------------------------------

def cmd_flip(d, index):
    blob = read(log_path(d))
    off, plen = spans(blob)[index]
    pay = payload_of(blob, off, plen)
    _, _, dlen = fields(pay)
    at = off + 8 + 24          # first byte of the data
    blob[at] ^= 0x20           # flips 'r' to 'R' in "rec-000637"
    write(log_path(d), blob)
    return "flipped one bit in record %d's data (byte offset %d); the frame " \
           "CRC was left alone" % (index, at)


def _rewrite(d, index, fix_crc=True, fix_hash=False, relink=False, bs=None):
    blob = read(log_path(d))
    sp = spans(blob)
    prev = None
    for i, (off, plen) in enumerate(sp):
        pay = payload_of(blob, off, plen)
        _, _, dlen = fields(pay)
        touched = False
        if i == index:
            set_data(pay, dlen, hacked_bytes(dlen))
            touched = True
        if relink and i > index:
            pay[24 + dlen:24 + dlen + 32] = prev
            touched = True
        if touched and (fix_hash or relink):
            h = record_hash(pay, dlen)
            pay[24 + dlen + 32:24 + dlen + 64] = h
        if touched and fix_crc:
            put_payload(blob, off, plen, pay)
        prev = bytes(
            payload_of(blob, off, plen)[24 + dlen + 32:24 + dlen + 64])
    write(log_path(d), blob)
    return blob


def cmd_reframe(d, index):
    _rewrite(d, index, fix_crc=True, fix_hash=False)
    return "rewrote record %d's data and recomputed the frame CRC; the " \
           "record's own hash was left stale" % index


def cmd_rehash(d, index):
    _rewrite(d, index, fix_crc=True, fix_hash=True)
    return "rewrote record %d's data, the frame CRC and the record's own " \
           "hash; records after it still point at the old hash" % index


def cmd_relink(d, index):
    _rewrite(d, index, fix_crc=True, fix_hash=True, relink=True)
    return "rewrote record %d and re-linked every record after it; the " \
           "chain is now internally consistent" % index


def cmd_reseal(d, keyhex=None):
    blob = read(log_path(d))
    key = bytes.fromhex(keyhex) if keyhex else None
    n = write_checkpoints(d, all_record_hashes(blob), block_size(blob), key)
    return "recomputed %d checkpoint root(s)%s" % (
        n, " and signed them" if key else " (unsigned: no key)")


def cmd_delete(d, index):
    blob = read(log_path(d))
    off, plen = spans(blob)[index]
    size = FRAME_OVERHEAD + plen
    del blob[off:off + size]
    write(log_path(d), blob)
    return "deleted record %d's whole frame (%d bytes at offset %d)" % (
        index, size, off)


def cmd_swap(d, i, j):
    blob = read(log_path(d))
    sp = spans(blob)
    oi, pi = sp[i]
    oj, pj = sp[j]
    si = FRAME_OVERHEAD + pi
    sj = FRAME_OVERHEAD + pj
    assert si == sj, "frames must be the same size to swap in place"
    a = bytes(blob[oi:oi + si])
    b = bytes(blob[oj:oj + sj])
    blob[oi:oi + si] = b
    blob[oj:oj + sj] = a
    write(log_path(d), blob)
    return "exchanged the frames of records %d and %d" % (i, j)


def cmd_truncate(d, keep):
    blob = read(log_path(d))
    bs = block_size(blob)
    sp = spans(blob)
    total = len(sp)
    cut = sp[keep][0]
    del blob[cut:]
    write(log_path(d), blob)
    # Drop the now-orphaned checkpoints too, so the directory stays
    # internally consistent -- a careless attacker would forget this.
    cps = read(ckpt_path(d))
    blocks = keep // bs
    frames = []
    off = CKPT_HEADER
    while off < len(cps):
        plen = struct.unpack_from("<I", cps, off + 4)[0]
        frames.append((off, CKPT_OVERHEAD + plen))
        off += CKPT_OVERHEAD + plen
    if blocks < len(frames):
        write(ckpt_path(d), cps[:frames[blocks][0]])
    return "cut the log from %d records to %d, at a frame boundary, and " \
           "trimmed the checkpoints to %d" % (total, keep, blocks)


def cmd_truncate_mid(d, nbytes):
    blob = read(log_path(d))
    before = len(blob)
    del blob[len(blob) - nbytes:]
    write(log_path(d), blob)
    return "cut %d bytes off the end of the log (%d -> %d), part-way " \
           "through the last frame" % (nbytes, before, len(blob))


def cmd_strip_signatures(d):
    cps = read(ckpt_path(d))
    out = bytearray(cps[:CKPT_HEADER])
    off, n = CKPT_HEADER, 0
    while off < len(cps):
        plen = struct.unpack_from("<I", cps, off + 4)[0]
        pay = bytearray(cps[off + 8:off + 8 + CKPT_PAYLOAD])
        struct.pack_into("<I", pay, 0, 0)  # clear the signed flag
        out += b"CKPT" + struct.pack("<I", CKPT_PAYLOAD) + pay
        out += struct.pack("<I", crc(bytes(pay)))
        off += CKPT_OVERHEAD + plen
        n += 1
    write(ckpt_path(d), out)
    return "stripped the HMAC from %d checkpoint(s), leaving valid " \
           "unsigned ones" % n


def main(argv):
    if len(argv) < 3:
        sys.stderr.write(__doc__)
        return 2
    cmd, d = argv[1], argv[2]
    rest = argv[3:]
    table = {
        "flip": lambda: cmd_flip(d, int(rest[0])),
        "reframe": lambda: cmd_reframe(d, int(rest[0])),
        "rehash": lambda: cmd_rehash(d, int(rest[0])),
        "relink": lambda: cmd_relink(d, int(rest[0])),
        "reseal": lambda: cmd_reseal(d, rest[0] if rest else None),
        "delete": lambda: cmd_delete(d, int(rest[0])),
        "swap": lambda: cmd_swap(d, int(rest[0]), int(rest[1])),
        "truncate": lambda: cmd_truncate(d, int(rest[0])),
        "truncate-mid": lambda: cmd_truncate_mid(d, int(rest[0])),
        "strip-signatures": lambda: cmd_strip_signatures(d),
    }
    if cmd not in table:
        sys.stderr.write("attacker.py: unknown subcommand %r\n" % cmd)
        return 2
    print(table[cmd]())
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
