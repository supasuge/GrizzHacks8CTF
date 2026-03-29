#!/usr/bin/env python3
from __future__ import annotations
from pwn import *
from dataclasses import dataclass
from typing import List, Tuple
import re
import sys
log.level = 'DEBUG'
HEX_RE = re.compile(rb"^[0-9a-fA-F]+$")

MASK32 = 0xFFFFFFFF
BLOCK_SIZE = 8
ROUNDS = 5


def log(msg):
    print(msg, flush=True)


def rotl32(x, n):
    n &= 31
    return ((x << n) | (x >> (32 - n))) & MASK32


def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def split_lr(b):
    return int.from_bytes(b[:4], "big"), int.from_bytes(b[4:], "big")


def join_lr(L, R):
    return L.to_bytes(4, "big") + R.to_bytes(4, "big")


def F(R, k):
    return rotl32(R, k) ^ k


def diff_forward(dL, dR, k):
    return dR, (dL ^ rotl32(dR, k)) & MASK32


def diff_backward(dL_next, dR_next, k):
    dR_prev = dL_next
    dL_prev = (dR_next ^ rotl32(dR_prev, k)) & MASK32
    return dL_prev, dR_prev


@dataclass(frozen=True)
class DiffVec:
    in_diff: Tuple[int, int]
    out_diff: Tuple[int, int]


class Oracle:
    def __init__(self, tube):
        log("[+] Starting challenge")
        self.p = tube
        self._drain_banner()

    def _drain_banner(self):
        # Eat initial banner lines quickly; don't block forever.
        for _ in range(40):
            try:
                line = self.p.recvline(timeout=0.15)
            except EOFError:
                break
            if not line:
                break
            # Uncomment if you want to see banner lines:
            # log(f"[banner] {line.strip().decode(errors='ignore')}")

    def _recv_hex_line(self, *, exact_len: int | None = None) -> bytes:
        """
        Read lines until we see a hex-only response.
        If exact_len is set, require that many hex characters.
        """
        for _ in range(500):
            line = self.p.recvline(timeout=2)
            if not line:
                continue
            s = line.strip()
            if not s:
                continue

            if s.startswith(b"ERROR"):
                raise RuntimeError(s.decode(errors="ignore"))

            if not HEX_RE.fullmatch(s):
                # banner/help/noise
                continue

            if len(s) % 2 != 0:
                continue

            if exact_len is not None and len(s) != exact_len:
                continue

            return bytes.fromhex(s.decode())

        raise RuntimeError("Timed out waiting for hex response")

    def enc(self, pt: bytes) -> bytes:
        self.p.sendline(b"enc " + pt.hex().encode())
        return self._recv_hex_line(exact_len=16)  # 8 bytes => 16 hex chars

    def flag(self) -> bytes:
        self.p.sendline(b"flag")
        return self._recv_hex_line(exact_len=None)

    def close(self):
        self.p.sendline(b"quit")
        self.p.close()


def collect_diffs(oracle) -> List[DiffVec]:
    base = b"\x00" * 8
    deltas = [
        join_lr(0, 1),
        join_lr(1, 0),
        join_lr(0x80000000, 0x10000),
    ]

    out = []
    for i, d in enumerate(deltas):
        c0 = oracle.enc(base)
        c1 = oracle.enc(xor_bytes(base, d))
        in_d = split_lr(d)
        out_d = split_lr(xor_bytes(c0, c1))
        log(f"[Δ{i}] in={in_d} out={out_d}")
        out.append(DiffVec(in_d, out_d))
    return out


def recover_keys(dv: List[DiffVec]) -> List[int]:
    log("[+] Brute-forcing last round key k4")

    for k4 in range(32):
        peeled = []
        for v in dv:
            dLr, dRr = v.out_diff
            prev = diff_backward(dLr, dRr, k4)
            peeled.append((v.in_diff, prev))

        fwd = {}
        for k0 in range(32):
            for k1 in range(32):
                sig = []
                for (dL, dR), _ in peeled:
                    a, b = diff_forward(dL, dR, k0)
                    a, b = diff_forward(a, b, k1)
                    sig.append((a, b))
                fwd[tuple(sig)] = (k0, k1)

        for k3 in range(32):
            for k2 in range(32):
                sig = []
                for _, (dL, dR) in peeled:
                    a, b = diff_backward(dL, dR, k3)
                    a, b = diff_backward(a, b, k2)
                    sig.append((a, b))
                sig = tuple(sig)
                if sig in fwd:
                    k0, k1 = fwd[sig]
                    log("[+] KEY FOUND")
                    return [k0, k1, k2, k3, k4]

    raise RuntimeError("No key found")


def decrypt_block(ct, keys):
    L, R = split_lr(ct)
    for k in reversed(keys):
        f = F(L, k)
        L, R = (R ^ f) & MASK32, L
    return join_lr(L, R)


def unpad_pkcs7(data: bytes) -> bytes:
    pad_len = data[-1]
    if pad_len < 1 or pad_len > BLOCK_SIZE:
        raise ValueError("Bad padding")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Bad padding")
    return data[:-pad_len]


def decrypt(ct: bytes, keys: List[int]) -> bytes:
    out = bytearray()
    for i in range(0, len(ct), BLOCK_SIZE):
        out += decrypt_block(ct[i:i + BLOCK_SIZE], keys)
    return unpad_pkcs7(bytes(out))


def main():
    # Usage:
    #   python solve.py               (local)
    #   python solve.py local         (local)
    #   python solve.py remote host port
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        host, port = sys.argv[2], int(sys.argv[3])
        tube = remote(host, port)
    else:
        tube = process(["python3", "../build/chal.py"])

    oracle = Oracle(tube)
    try:
        dv = collect_diffs(oracle)
        keys = recover_keys(dv)
        log(f"[+] Round keys: {keys}")

        ct = oracle.flag()
        pt = decrypt(ct, keys)
        log(f"[+] Flag: {pt.decode(errors='replace')}")
    finally:
        oracle.close()


if __name__ == "__main__":
    main()
