#!/usr/bin/python3
import secrets
import hashlib
from pathlib import Path
from typing import List
MOD = (119 << 23) + 1        # 998244353 = 119*2^23 + 1
N = 1 << 8                  # 256 (must be power of two)
ROUNDS = 5
G = 3  

def _unique_prime_factors(n: int) -> List[int]:
    factors: List[int] = []
    d = 2
    while d * d <= n:
        if n % d == 0:
            while n % d == 0:
                n //= d
        d +=1 if d == 2 else 2
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
        raise ValueError(
            f"No non-trivial {order}-th roots of unity in F_{MOD} "
            f"because (MOD-1) % order = {(MOD - 1) % order}."
        )
    g = _primitive_root(MOD)
    return pow(g, (MOD - 1) // order, MOD)

def modinv(x):
    return pow(x, MOD - 2, MOD)

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
        wlen = pow(G, (MOD - 1) // length, MOD)
        if invert:
            wlen = modinv(wlen)
        for i in range(0, n, length):
            w = 1
            for j in range(i, i + length // 2):
                u = a[j]
                v = a[j + length // 2] * w % MOD
                a[j] = (u + v) % MOD
                a[j + length // 2] = (u - v) % MOD
                w = w * wlen % MOD
        length <<= 1

    if invert:
        inv_n = modinv(n)
        for i in range(n):
            a[i] = a[i] * inv_n % MOD

def _pad(v: List[int]) -> List[int]:
    if len(v) > N:
        v = v[:N]
    return v + [0] * (N - len(v))


def _circ_convolve(a, b):
    fa = _pad(a[:])
    fb = _pad(b[:])
    _transform(fa)
    _transform(fb)
    for i in range(N):
        fa[i] = fa[i] * fb[i] % MOD
    _transform(fa, invert=True)
    return fa

def _expand_round_key(seed: bytes, round_idx: int) -> List[int]:
    """
    Deterministically derive a per-round key from a secret seed.
    
    """
    shake = hashlib.shake_256(seed + round_idx.to_bytes(4, "little"))
    raw = shake.digest(N * 4)  # 4 bytes per coefficient
    key = [
        int.from_bytes(raw[i * 4 : (i + 1) * 4], "little") % MOD
        for i in range(N)
    ]
    return key

def encrypt(pt: bytes, seed: bytes) -> List[int]:
    state = _pad(list(pt))
    for r in range(ROUNDS):
        k = _expand_round_key(seed, r)
        state = _circ_convolve(state, k)
    return state

def main():
    with open("flag.txt") as f:
        flag = f.read().strip().encode()

    key = secrets.token_bytes(32)

    sample = b'Honey, where\'s my supaaasuit?!'

    pt = list(sample)
    ct = encrypt(pt, key)
    
    flag_ct = encrypt(list(flag), key)

    with open("output.txt", "w") as f:
        f.write(f"ct1 = {ct}\n")
        f.write(f"flag_ct = {flag_ct}")
        f.close()


if __name__ == "__main__":
    main()
