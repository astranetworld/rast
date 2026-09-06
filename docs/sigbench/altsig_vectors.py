#!/usr/bin/env python3
"""Independent check of the 0x50 (AltSig) transaction test vectors.

Reads crates/n42/tx-types/testdata/altsig_vectors.json and recomputes, with no
code shared with the Rust crate: the RLP encoding, the signing hash (keccak-256),
the Ed25519 signature (deterministic, so it must match byte for byte), the
sender derivation keccak(alg_type || pubkey)[12:], the full encoded bytes and
the transaction hash. Needs only the `cryptography` package.
"""
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


# --- keccak-256 (pure Python; SHA3 in `cryptography` pads differently) ---------
_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
_ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
_M = (1 << 64) - 1


def _rol(x, n):
    return ((x << n) | (x >> (64 - n))) & _M


def _keccak_f(a):
    for rc in _RC:
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        a = [[a[x][y] ^ d[x] for y in range(5)] for x in range(5)]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rol(a[x][y], _ROT[x][y])
        a = [[b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y]) for y in range(5)] for x in range(5)]
        a[0][0] ^= rc
    return a


def keccak256(data: bytes) -> bytes:
    rate = 136
    data = bytearray(data)
    data.append(0x01)
    while len(data) % rate:
        data.append(0)
    data[-1] |= 0x80
    a = [[0] * 5 for _ in range(5)]
    for off in range(0, len(data), rate):
        block = data[off:off + rate]
        for i in range(rate // 8):
            x, y = i % 5, i // 5
            a[x][y] ^= int.from_bytes(block[8 * i:8 * i + 8], "little")
        a = _keccak_f(a)
    out = b""
    for i in range(4):
        out += a[i % 5][i // 5].to_bytes(8, "little")
    return out


# --- RLP ----------------------------------------------------------------------
def _len_prefix(n, short, long_):
    if n < 56:
        return bytes([short + n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([long_ + len(b)]) + b


def rlp_bytes(b: bytes) -> bytes:
    if len(b) == 1 and b[0] < 0x80:
        return b
    return _len_prefix(len(b), 0x80, 0xB7) + b


def rlp_int(n: int) -> bytes:
    return rlp_bytes(b"" if n == 0 else n.to_bytes((n.bit_length() + 7) // 8, "big"))


def rlp_list(items) -> bytes:
    payload = b"".join(items)
    return _len_prefix(len(payload), 0xC0, 0xF7) + payload


def unhex(s: str) -> bytes:
    return bytes.fromhex(s[2:] if s.startswith("0x") else s)


def qty(s) -> int:
    return int(s, 16) if isinstance(s, str) else int(s)


def fields(tx):
    access = rlp_list([
        rlp_list([rlp_bytes(unhex(item["address"])), rlp_list([rlp_bytes(unhex(k)) for k in item["storageKeys"]])])
        for item in tx["accessList"]
    ])
    return [
        rlp_int(qty(tx["chainId"])), rlp_int(qty(tx["nonce"])), rlp_int(qty(tx["maxPriorityFeePerGas"])),
        rlp_int(qty(tx["maxFeePerGas"])), rlp_int(qty(tx["gasLimit"])), rlp_bytes(unhex(tx["to"])),
        rlp_int(qty(tx["value"])), rlp_bytes(unhex(tx["input"])), access, rlp_int(qty(tx["algType"])),
        rlp_bytes(unhex(tx["pubkey"])),
    ]


def main(path):
    vectors = json.loads(Path(path).read_text())
    for i, v in enumerate(vectors):
        tx = v["tx"]
        sk = Ed25519PrivateKey.from_private_bytes(unhex(v["secretKey"]))
        pk = sk.public_key().public_bytes_raw()
        assert pk == unhex(tx["pubkey"]), f"#{i}: pubkey"
        unsigned = b"\x50" + rlp_list(fields(tx))
        signing_hash = keccak256(unsigned)
        assert signing_hash == unhex(v["signingHash"]), f"#{i}: signing hash"
        sig = sk.sign(signing_hash)
        assert sig == unhex(v["signature"]), f"#{i}: signature"
        Ed25519PublicKey.from_public_bytes(pk).verify(sig, signing_hash)
        sender = keccak256(bytes([qty(tx["algType"])]) + pk)[12:]
        assert sender == unhex(v["sender"]), f"#{i}: sender"
        encoded = b"\x50" + rlp_list(fields(tx) + [rlp_bytes(sig)])
        assert encoded == unhex(v["encoded"]), f"#{i}: encoded bytes"
        assert keccak256(encoded) == unhex(v["hash"]), f"#{i}: hash"
        print(f"#{i}: ok ({len(encoded)} bytes, sender 0x{sender.hex()})")
    print(f"{len(vectors)} vectors match")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "crates/n42/tx-types/testdata/altsig_vectors.json")
