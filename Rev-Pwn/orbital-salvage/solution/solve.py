#!/usr/bin/env python3
"""Orbital Salvage reference solver.

Connects to the challenge service, parses the per-session leaks and ciphertext,
recovers full 64-bit LCG states via Z3, derives the ChaCha20-Poly1305 key,
and decrypts the sealed operator token.
"""
from __future__ import annotations

import argparse
import hashlib
import re
import struct
from typing import List, Tuple

from pwn import remote
from z3 import BitVec, BitVecVal, LShR, Solver, sat
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

A = 6364136223846793005
C = 1442695040888963407
MASK = (1 << 64) - 1


def lcg_next(state: int) -> int:
    return (state * A + C) & MASK


def mix64(z: int) -> int:
    z ^= z >> 30
    z = (z * 0xBF58476D1CE4E5B9) & MASK
    z ^= z >> 27
    z = (z * 0x94D049BB133111EB) & MASK
    z ^= z >> 31
    return z & MASK


def derive_key(last_state: int) -> bytes:
    state = last_state
    material = bytearray()
    for _ in range(4):
        state = lcg_next(state)
        material.extend(struct.pack("<Q", mix64(state)))
    return hashlib.sha256(material).digest()


def decrypt_token(last_state: int, nonce: bytes, ct: bytes) -> str:
    key = derive_key(last_state)
    return ChaCha20Poly1305(key).decrypt(nonce, ct, None).decode()


def recover_states_from_hi48(leaks: List[int]) -> List[int]:
    xs = [BitVec(f"x{i}", 64) for i in range(len(leaks))]
    s = Solver()

    for i, leak in enumerate(leaks):
        s.add(LShR(xs[i], 16) == BitVecVal(leak, 64))

    for i in range(len(xs) - 1):
        s.add(xs[i + 1] == xs[i] * BitVecVal(A, 64) + BitVecVal(C, 64))

    assert s.check() == sat, "state recovery failed"
    model = s.model()
    return [model.evaluate(x).as_long() for x in xs]


def parse_banner(text: bytes) -> Tuple[List[int], bytes, bytes]:
    leaks = []
    for m in re.finditer(rb"echo\[(\d+)\]:\s*0x([0-9a-fA-F]+)", text):
        leaks.append(int(m.group(2), 16))
    if len(leaks) != 8:
        raise ValueError(f"expected 8 leaks, got {len(leaks)}")

    nonce_match = re.search(rb"nonce\s*=\s*([0-9a-fA-F]+)", text)
    if not nonce_match:
        raise ValueError("nonce not found in banner")
    nonce = bytes.fromhex(nonce_match.group(1).decode())

    ct_match = re.search(rb"sealed_token\s*=\s*([0-9a-fA-F]+)", text)
    if not ct_match:
        raise ValueError("sealed_token not found in banner")
    ct = bytes.fromhex(ct_match.group(1).decode())

    return leaks, nonce, ct


def solve_remote(host: str, port: int) -> None:
    io = remote(host, port)
    banner = io.recvuntil(b"operator_token>\n")
    leaks, nonce, ct = parse_banner(banner)

    states = recover_states_from_hi48(leaks)
    last_state = states[-1]
    token = decrypt_token(last_state, nonce, ct)

    print("[+] recovered states:")
    for idx, st in enumerate(states):
        print(f"    x{idx} = 0x{st:016x}")
    print(f"[+] token: {token}")

    io.sendline(token.encode())
    print(io.recvall().decode(errors="replace"))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Orbital Salvage reference solver")
    parser.add_argument("host")
    parser.add_argument("port", type=int)
    args = parser.parse_args()
    solve_remote(args.host, args.port)
