#!/usr/bin/env python3
from __future__ import annotations
import secrets
from typing import List, Tuple
import sys

flag = open("flag.txt", "rb").read().strip()

BANNER = r"""
  _____         ____                    __   
 / ___/__  ____/ __ \_______ ________ _/ /__ 
/ /__/ _ \/ __/ /_/ / __/ _ `/ __/ _ `/ / -_)
\___/\___/\__/\____/_/  \_,_/\__/\_,_/_/\__/ 

COCNUT98 Remote Encryption Service
---------------------------------
Commands:
  help              -> show help + examples
  flag              -> get encrypted flag (hex)
  enc <16-hex>      -> encrypt exactly 8 bytes (returns 16-hex)
  quit              -> disconnect
"""

HELP = r"""
Available commands:

  help
    Show this help message

  flag
    Get the encrypted flag (hex-encoded, PKCS#7 padded)

  enc <16-hex>
    Encrypt exactly 8 bytes (16 hex characters)

Examples:
  enc 0000000000000000
  enc 4141414142424242
  flag
  quit
"""

MASK32 = 0xFFFFFFFF
BLOCK_SIZE = 8
ROUNDS = 5


def die(msg: str):
    print(msg, flush=True)
    sys.exit(0)


def rotl32(x: int, n: int) -> int:
    n &= 31
    return ((x << n) | (x >> (32 - n))) & MASK32


def pad_pkcs7(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return data + bytes([pad_len] * pad_len)


def genkey() -> bytes:
    return secrets.token_bytes(16)


def keySchedule(key: bytes) -> List[int]:
    if len(key) != 16:
        raise ValueError("Key must be 16 bytes")

    seed = int.from_bytes(key[:8], "big") ^ int.from_bytes(key[8:], "big")

    def next_u64(x: int) -> int:
        x ^= (x >> 12) & 0xFFFFFFFFFFFFFFFF
        x ^= (x << 25) & 0xFFFFFFFFFFFFFFFF
        x ^= (x >> 27) & 0xFFFFFFFFFFFFFFFF
        return (x * 0x2545F4914F6CDD1D) & 0xFFFFFFFFFFFFFFFF

    rk = []
    x = seed & 0xFFFFFFFFFFFFFFFF
    for _ in range(ROUNDS):
        x = next_u64(x)
        rk.append(x & 0x1F)
    return rk


def F(R: int, k5: int) -> int:
    return rotl32(R, k5) ^ k5


def feistel_round(L: int, R: int, k5: int) -> Tuple[int, int]:
    return R, (L ^ F(R, k5)) & MASK32


def encrypt_block(block8: bytes, round_keys: List[int]) -> bytes:
    L = int.from_bytes(block8[:4], "big")
    R = int.from_bytes(block8[4:], "big")
    for i in range(ROUNDS):
        L, R = feistel_round(L, R, round_keys[i])
    return L.to_bytes(4, "big") + R.to_bytes(4, "big")


def encrypt(key: bytes, plaintext: bytes) -> bytes:
    rks = keySchedule(key)
    pt = pad_pkcs7(plaintext, BLOCK_SIZE)
    out = bytearray()
    for i in range(0, len(pt), BLOCK_SIZE):
        out += encrypt_block(pt[i:i + BLOCK_SIZE], rks)
    return bytes(out)


def main():
    INTERACTIVE = sys.stdin.isatty()
    PROMPT = "cocoracle> " if INTERACTIVE else ""

    key = genkey()
    flag_ct = encrypt(key, flag)

    print(BANNER, flush=True)

    while True:
        try:
            if INTERACTIVE:
                line = input(PROMPT)
            else:
                line = sys.stdin.readline()
                if not line:
                    break
                line = line.rstrip("\n")
        except EOFError:
            break

        line = line.strip()

        match line.split(maxsplit=1):
            case ["quit"]:
                die("bye")

            case ["help"]:
                print(HELP, flush=True)

            case ["flag"]:
                print(flag_ct.hex(), flush=True)

            case ["enc", hx]:
                try:
                    pt = bytes.fromhex(hx)
                except ValueError:
                    print("ERR: bad hex", flush=True)
                    continue

                if len(pt) != 8:
                    print("ERR: must be exactly 8 bytes (16 hex chars)", flush=True)
                    continue

                ct = encrypt(key, pt)[:8]
                print(ct.hex(), flush=True)

            case _:
                print("ERR: unknown command (try `help`)", flush=True)




if __name__ == "__main__":
    main()
