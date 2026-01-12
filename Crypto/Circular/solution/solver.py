#!/usr/bin/env python3
from __future__ import annotations
import ast
from pathlib import Path
from typing import List
MOD = (119 << 23) + 1  # 998244353
N = 1 << 8            # 256


def modinv(x: int) -> int:
    return pow(x, MOD - 2, MOD)


def _unique_prime_factors(n: int) -> List[int]:
    factors: List[int] = []
    d = 2
    while d * d <= n:
        if n % d == 0:
            factors.append(d)
            while n % d == 0:
                n //= d
        d += 1 if d == 2 else 2
    if n > 1:
        factors.append(n)
    return factors


def _primitive_root(mod: int) -> int:
    if mod == 2:
        return 1
    phi = mod - 1
    factors = _unique_prime_factors(phi)
    for g in range(2, mod):
        if all(pow(g, phi // q, mod) != 1 for q in factors):
            return g
    raise RuntimeError("Failed to find primitive root")


def root_of_unity(order: int) -> int:
    if (MOD - 1) % order != 0:
        raise ValueError(f"order={order} does not divide MOD-1")
    g = _primitive_root(MOD)
    return pow(g, (MOD - 1) // order, MOD)


_OMEGA_N = root_of_unity(N)


def _transform(a: List[int], invert: bool = False) -> None:
    n = len(a)
    if n != N:
        raise ValueError(f"Transform size must be exactly {N}, got {n}")
    if n & (n - 1):
        raise ValueError("N must be a power of two")

    j = 0
    for i in range(1, n):
        bit = n >> 1
        while j & bit:
            j ^= bit
            bit >>= 1
        j |= bit
        if i < j:
            a[i], a[j] = a[j], a[i]

    length = 2
    while length <= n:
        wlen = pow(_OMEGA_N, N // length, MOD)
        if invert:
            wlen = modinv(wlen)

        for i in range(0, n, length):
            w = 1
            half = length // 2
            for j in range(i, i + half):
                u = a[j]
                v = (a[j + half] * w) % MOD
                a[j] = (u + v) % MOD
                a[j + half] = (u - v) % MOD
                w = (w * wlen) % MOD

        length <<= 1

    if invert:
        inv_n = modinv(n)
        for i in range(n):
            a[i] = (a[i] * inv_n) % MOD


def pad(v: List[int]) -> List[int]:
    if len(v) > N:
        v = v[:N]
    return v + [0] * (N - len(v))


def recover_effective_key_hat(plaintext: bytes, ciphertext: List[int]) -> List[int]:
    P = pad(list(plaintext))
    C = pad(ciphertext)

    _transform(P)
    _transform(C)

    K_hat = [0] * N
    for i in range(N):
        if P[i] == 0:
            raise ValueError(f"Zero frequency bin at {i}; cannot invert.")
        K_hat[i] = (C[i] * modinv(P[i])) % MOD
    return K_hat


def decrypt(ciphertext: List[int], K_hat: List[int]) -> bytes:
    C = pad(ciphertext)
    _transform(C)

    P_hat = [0] * N
    for i in range(N):
        if K_hat[i] == 0:
            raise ValueError(f"Effective key has zero bin at {i}")
        P_hat[i] = (C[i] * modinv(K_hat[i])) % MOD

    _transform(P_hat, invert=True)

    out = []
    for idx, x in enumerate(P_hat):
        if not (0 <= x < 256):
            raise ValueError(f"Non-byte value at {idx}: {x}")
        out.append(x)

    return bytes(out).rstrip(b"\x00")


def _load_output(path: str = "output.txt") -> tuple[List[int], List[int]]:
    txt = Path(path).read_text()
    ct1 = None
    flag_ct = None
    for line in txt.splitlines():
        if line.startswith("ct1"):
            ct1 = ast.literal_eval(line.split("=", 1)[1].strip())
        elif line.startswith("flag_ct"):
            flag_ct = ast.literal_eval(line.split("=", 1)[1].strip())
    if ct1 is None or flag_ct is None:
        raise ValueError("output.txt must contain ct1 = [...] and flag_ct = [...]")
    return ct1, flag_ct


def main() -> None:
    known_pt = b"Honey, where's my supaaasuit?!"
    ct1, flag_ct = _load_output("output.txt")

    K_hat = recover_effective_key_hat(known_pt, ct1)
    flag = decrypt(flag_ct, K_hat)

    print(flag.decode("utf-8", errors="replace"))


if __name__ == "__main__":
    main()
