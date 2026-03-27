#!/usr/bin/env python3
import random
from math import gcd

FLAG = open('flag.txt', 'rb').read()
e = 3
gift = 384
where_they_at_tho = 112

RNG = random.SystemRandom()

def b2l(data: bytes) -> int:
    return int.from_bytes(data, "big")

def _maybe_prime(n: int, rounds: int = 32) -> bool:

