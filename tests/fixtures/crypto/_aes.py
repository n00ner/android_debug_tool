"""Minimal pure-Python AES-128 (CBC, PKCS#7) for the apkdbg crypto
fixture (issue #28): encrypts the generated payload DEX into the
committed asset at build time and derives the ground-truth plaintext
host-side at validation time. Stdlib-only; NOT for production use.

Self-test: `python _aes.py` checks the NIST SP 800-38A F.2.1 AES-128-CBC
vector (the same vector the fixture exercises at runtime).
"""

from __future__ import annotations


def _build_tables():
    exp = [0] * 255
    log = [0] * 256
    x = 1
    for i in range(255):
        exp[i] = x
        log[x] = i
        x2 = x << 1
        if x2 & 0x100:
            x2 ^= 0x11B
        x = (x2 & 0xFF) ^ x
    sbox = [0] * 256
    for b in range(256):
        s = 0 if b == 0 else exp[(255 - log[b]) % 255]
        r = s
        for k in (1, 2, 3, 4):
            r ^= ((s << k) | (s >> (8 - k))) & 0xFF
        sbox[b] = r ^ 0x63
    inv = [0] * 256
    for b, s in enumerate(sbox):
        inv[s] = b
    return sbox, inv


_SBOX, _INV_SBOX = _build_tables()


def _gmul(a: int, b: int) -> int:
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p


_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def _expand_key(key: bytes) -> list[list[int]]:
    """AES-128 key schedule -> 44 words (11 round keys of 4 words)."""
    w = [list(key[4 * i:4 * i + 4]) for i in range(4)]
    for i in range(4, 44):
        t = list(w[i - 1])
        if i % 4 == 0:
            t = t[1:] + t[:1]
            t = [_SBOX[b] for b in t]
            t[0] ^= _RCON[i // 4 - 1]
        w.append([a ^ b for a, b in zip(w[i - 4], t)])
    return w


def _add_round_key(s: list[int], w: list[list[int]], rnd: int) -> None:
    for c in range(4):
        for r in range(4):
            s[4 * c + r] ^= w[4 * rnd + c][r]


def _sub_bytes(s, box):
    for i in range(16):
        s[i] = box[s[i]]


def _shift_rows(s):
    for r in (1, 2, 3):
        row = [s[4 * c + r] for c in range(4)]
        for c in range(4):
            s[4 * c + r] = row[(c + r) % 4]


def _inv_shift_rows(s):
    for r in (1, 2, 3):
        row = [s[4 * c + r] for c in range(4)]
        for c in range(4):
            s[4 * c + r] = row[(c - r) % 4]


def _mix_columns(s, factors):
    for c in range(4):
        col = s[4 * c:4 * c + 4]
        for r in range(4):
            s[4 * c + r] = 0
            for k in range(4):
                s[4 * c + r] ^= _gmul(factors[(r - k) % 4], col[k])


def encrypt_block(key_sched, block: bytes) -> bytes:
    s = list(block)
    _add_round_key(s, key_sched, 0)
    for rnd in range(1, 10):
        _sub_bytes(s, _SBOX)
        _shift_rows(s)
        _mix_columns(s, (2, 1, 1, 3))
        _add_round_key(s, key_sched, rnd)
    _sub_bytes(s, _SBOX)
    _shift_rows(s)
    _add_round_key(s, key_sched, 10)
    return bytes(s)


def decrypt_block(key_sched, block: bytes) -> bytes:
    s = list(block)
    _add_round_key(s, key_sched, 10)
    for rnd in range(9, 0, -1):
        _inv_shift_rows(s)
        _sub_bytes(s, _INV_SBOX)
        _add_round_key(s, key_sched, rnd)
        _mix_columns(s, (14, 9, 13, 11))
    _inv_shift_rows(s)
    _sub_bytes(s, _INV_SBOX)
    _add_round_key(s, key_sched, 0)
    return bytes(s)


def cbc_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    if len(key) != 16 or len(iv) != 16:
        raise ValueError("AES-128-CBC needs 16-byte key and IV")
    sched = _expand_key(key)
    pad = 16 - len(data) % 16
    data = data + bytes([pad]) * pad
    out, prev = bytearray(), iv
    for off in range(0, len(data), 16):
        block = bytes(a ^ b for a, b in zip(data[off:off + 16], prev))
        prev = encrypt_block(sched, block)
        out += prev
    return bytes(out)


def cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    if len(key) != 16 or len(iv) != 16 or len(data) % 16:
        raise ValueError("AES-128-CBC needs 16-byte key/IV, blocks of 16")
    sched = _expand_key(key)
    out, prev = bytearray(), iv
    for off in range(0, len(data), 16):
        block = data[off:off + 16]
        dec = decrypt_block(sched, block)
        out += bytes(a ^ b for a, b in zip(dec, prev))
        prev = block
    pad = out[-1]
    if not 1 <= pad <= 16 or out[-pad:] != bytes([pad]) * pad:
        raise ValueError("bad PKCS#7 padding")
    return bytes(out[:-pad])


if __name__ == "__main__":
    # NIST SP 800-38A F.2.1 AES-128-CBC (first block and full message)
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    pt = bytes.fromhex(
        "6bc1bee22e409f96e93d7e117393172a"
        "ae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411e5fbc1191a0a52ef"
        "f69f2445df4f9b17ad2b417be66c3710")
    # raw CBC without padding for the vector check
    sched = _expand_key(key)
    out, prev = bytearray(), iv
    for off in range(0, len(pt), 16):
        blk = bytes(a ^ b for a, b in zip(pt[off:off + 16], prev))
        prev = encrypt_block(sched, blk)
        out += prev
    want = ("7649abac8119b246cee98e9b12e9197d"
            "5086cb9b507219ee95db113a917678b2"
            "73bed6b8e3c1743b7116e69e22229516"
            "3ff1caa1681fac09120eca307586e1a7")
    assert out.hex() == want, out.hex()
    # padded round trip
    blob = cbc_encrypt(key, iv, pt + b"apkdbg")
    assert cbc_decrypt(key, iv, blob) == pt + b"apkdbg"
    print("AES-128-CBC self-test ok (NIST F.2.1 + padded round trip)")
