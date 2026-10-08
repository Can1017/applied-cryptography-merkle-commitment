"""Byte-oriented SHA-256 and SHA3-256, implemented from the FIPS specifications.

No calls to hash libraries, external executables, or downloaded implementations.
The round constants are public algorithm parameters, not imported code.
"""

MASK32 = (1 << 32) - 1
MASK64 = (1 << 64) - 1

_SHA256_IV = (
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
)
_SHA256_K = (
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
)


def _rotr32(value: int, count: int) -> int:
    return ((value >> count) | (value << (32 - count))) & MASK32


def sha256(message: bytes) -> bytes:
    """Return the 32-byte SHA-256 digest of a byte string (one-shot API)."""
    if type(message) is not bytes:
        raise TypeError("message must be bytes")
    if len(message) >= 1 << 61:
        raise ValueError("SHA-256 requires a bit length below 2**64")
    padded = message + b"\x80"
    padded += b"\x00" * ((56 - len(padded)) % 64)
    padded += (len(message) * 8).to_bytes(8, "big")
    state = list(_SHA256_IV)
    for offset in range(0, len(padded), 64):
        block = padded[offset:offset + 64]
        words = [int.from_bytes(block[i:i + 4], "big") for i in range(0, 64, 4)]
        for i in range(16, 64):
            x, y = words[i - 15], words[i - 2]
            s0 = _rotr32(x, 7) ^ _rotr32(x, 18) ^ (x >> 3)
            s1 = _rotr32(y, 17) ^ _rotr32(y, 19) ^ (y >> 10)
            words.append((words[i - 16] + s0 + words[i - 7] + s1) & MASK32)
        a, b, c, d, e, f, g, h = state
        for i in range(64):
            big1 = _rotr32(e, 6) ^ _rotr32(e, 11) ^ _rotr32(e, 25)
            choice = (e & f) ^ ((~e) & g)
            t1 = (h + big1 + choice + _SHA256_K[i] + words[i]) & MASK32
            big0 = _rotr32(a, 2) ^ _rotr32(a, 13) ^ _rotr32(a, 22)
            majority = (a & b) ^ (a & c) ^ (b & c)
            t2 = (big0 + majority) & MASK32
            a, b, c, d, e, f, g, h = (
                (t1 + t2) & MASK32, a, b, c, (d + t1) & MASK32, e, f, g
            )
        state = [(old + new) & MASK32
                 for old, new in zip(state, (a, b, c, d, e, f, g, h))]
    return b"".join(word.to_bytes(4, "big") for word in state)


_KECCAK_RC = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)
# Flattened lane index = x + 5*y; rotation offsets in that same order.
_KECCAK_ROT = (
    0, 1, 62, 28, 27,
    36, 44, 6, 55, 20,
    3, 10, 43, 25, 39,
    41, 45, 15, 21, 8,
    18, 2, 61, 56, 14,
)


def _rotl64(value: int, count: int) -> int:
    return ((value << count) | (value >> ((64 - count) % 64))) & MASK64


def _keccak_f1600(state: list[int]) -> None:
    """Apply all 24 rounds in place: theta, rho/pi, chi, iota."""
    for rc in _KECCAK_RC:
        columns = [state[x] ^ state[x + 5] ^ state[x + 10]
                   ^ state[x + 15] ^ state[x + 20] for x in range(5)]
        delta = [columns[(x - 1) % 5] ^ _rotl64(columns[(x + 1) % 5], 1)
                 for x in range(5)]
        for y in range(5):
            for x in range(5):
                state[x + 5 * y] ^= delta[x]
        moved = [0] * 25
        for y in range(5):
            for x in range(5):
                old_index = x + 5 * y
                new_index = y + 5 * ((2 * x + 3 * y) % 5)
                moved[new_index] = _rotl64(state[old_index], _KECCAK_ROT[old_index])
        for y in range(5):
            row = moved[5 * y:5 * y + 5]
            for x in range(5):
                state[x + 5 * y] = (
                    row[x] ^ ((~row[(x + 1) % 5]) & row[(x + 2) % 5])
                ) & MASK64
        state[0] ^= rc


def sha3_256(message: bytes) -> bytes:
    """FIPS 202 SHA3-256, rate 136 bytes, capacity 512 bits; not Keccak-256."""
    if type(message) is not bytes:
        raise TypeError("message must be bytes")
    rate = 136
    padding = bytearray(rate - (len(message) % rate))
    padding[0] = 0x06
    padding[-1] |= 0x80  # One-byte case becomes 0x86.
    padded = message + bytes(padding)
    state = [0] * 25
    for offset in range(0, len(padded), rate):
        block = padded[offset:offset + rate]
        for i in range(rate // 8):
            state[i] ^= int.from_bytes(block[8 * i:8 * i + 8], "little")
        _keccak_f1600(state)
    # 32 < rate, so the first squeeze block is sufficient.
    return b"".join(lane.to_bytes(8, "little") for lane in state[:4])


HASHES = {"sha256": sha256, "sha3-256": sha3_256}
SUITE_IDS = {"sha256": b"\x01", "sha3-256": b"\x02"}
