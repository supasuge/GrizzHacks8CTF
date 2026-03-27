#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║           SchrodingerSeed — Full Exploit / Solver                ║
╚══════════════════════════════════════════════════════════════════╝

This solver exploits knowledge of the secret factorisation N = P*Q
(where P and Q are Crandall primes) to recover the MS-DRBG seed via
exhaustive search over the reduced-entropy state space, then decrypts
the AES-CTR encrypted flag.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ATTACK THEORY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

MS-DRBG Step (one iteration)
─────────────────────────────
Given internal state  s  (STATE_BITS wide):

    padded  =  s << OUTPUT_BITS       # zero-pad low OUTPUT_BITS bits
    y       =  padded^E  mod  N       # RSA encryption
    output  =  y  &  MASK_128         # low 128 bits  → published
    s_new   =  y  >>  OUTPUT_BITS     # high bits     → next state (secret)

What the attacker observes
──────────────────────────
    observed[0], observed[1], …, observed[k-1]    (k = 4 blocks of 128 bits each)
    encrypted_flag                                  (AES-CTR, key = observed[k])

What the attacker knows (the backdoor)
───────────────────────────────────────
    N = P * Q  where  P = 2^256 + 297,  Q = 2^256 + 301   (Crandall primes)

Why Crandall primes matter (the Crandall reduction)
────────────────────────────────────────────────────
For any prime of the form  p = 2^k + c  (c tiny):

    x  mod  p  ≡  (x mod 2^k)  −  c * (x >> k)    (mod p)

This is the "Crandall / pseudo-Mersenne" fast reduction.  When the input
x is small (x << p), no reduction is needed: x mod p = x.

In our DRBG, the padded input to RSA is:

    padded = s << 128

Because the seed s < 2^CHALLENGE_BITS = 2^24:
    padded < 2^(24+128) = 2^152  <<  P ≈ 2^257

So  padded mod P = padded  (no reduction at all).
And  padded mod Q = padded  (same reason).

This means:
    r_p  =  padded^E  mod  P     (RSA mod the smaller prime P)
    r_q  =  padded^E  mod  Q     (RSA mod the smaller prime Q)

And by CRT:
    y  =  padded^E  mod  N  =  CRT(r_p, r_q)

The CRT formula (Garner's algorithm):
    h  =  (r_p − r_q) * Q^{-1}  mod  P
    y  =  r_q  +  Q * h

The observed output is:
    output  =  y  &  MASK_128  =  (r_q + Q*h)  &  MASK_128

The Search
──────────────────────────────────────────────────────────────────
Since s ∈ [2, 2^24), we simply iterate every candidate s and compute
the DRBG output.  We accept a candidate when its output matches the
first observed block AND its next output matches the second observed
block (double-check eliminates false positives with overwhelming
probability).

The Crandall prime speedup
──────────────────────────
Instead of computing  pow(padded, E, N)  (modular exponentiation with
the 514-bit composite modulus N), we compute the two halves separately:

    r_p  =  pow(padded, E, P)    ← 257-bit prime modulus (~4× faster mul)
    r_q  =  pow(padded, E, Q)    ← 257-bit prime modulus (~4× faster mul)
    y    =  CRT(r_p, r_q)        ← one cheap combine step

Two 257-bit exponentiations are faster than one 514-bit exponentiation
because Montgomery multiplication cost scales as O(k^2) for a k-bit
modulus.  This is the CRT-RSA speedup: the mathematical machinery that
makes the backdoor exploitable in practice (not just in theory).

In the full-entropy version (no CHALLENGE_BITS restriction), the solver
would use lattice methods (LLL/BKZ applied to the Hidden Number Problem)
because the search space is too large for brute force.  The Crandall
prime structure is what makes such a lattice attack viable; ordinary RSA
primes without special form do not provide this algebraic foothold.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
DEPENDENCIES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    pip install pycryptodome gmpy2

gmpy2 wraps GMP for fast arbitrary-precision arithmetic.  The solver
works without it (falls back to Python's built-in pow) but runs ~5-8×
slower.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
USAGE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    python chal.py > challenge.json
    python solve.py challenge.json
"""

import sys
import json
import time
from Crypto.Cipher import AES
from Crypto.Util import Counter

# ── Optional fast arithmetic backend ─────────────────────────────────────────
try:
    import gmpy2

    def _powmod(base: int, exp: int, mod: int) -> int:
        """Fast modular exponentiation via GMP."""
        return int(gmpy2.powmod(gmpy2.mpz(base), gmpy2.mpz(exp), gmpy2.mpz(mod)))

    def _mpz(x: int) -> "gmpy2.mpz":
        return gmpy2.mpz(x)

    HAVE_GMPY2 = True
except ImportError:
    def _powmod(base: int, exp: int, mod: int) -> int:      # type: ignore[misc]
        """Fallback: Python built-in (slower for large integers)."""
        return pow(base, exp, mod)

    def _mpz(x: int) -> int:                                # type: ignore[misc]
        return x

    HAVE_GMPY2 = False


# ─────────────────────────────────────────────────────────────────────────────
# Backdoor Parameters  (known to the attacker, secret in the real world)
# ─────────────────────────────────────────────────────────────────────────────

_C_P: int = 297
_C_Q: int = 301

P: int = (1 << 256) + _C_P
Q: int = (1 << 256) + _C_Q
N: int = P * Q
E: int = 65537

OUTPUT_BITS: int = 128
OUTPUT_MASK: int = (1 << OUTPUT_BITS) - 1
CHALLENGE_BITS: int = 24    # must match chal.py

# Precomputed CRT constant for combining residues mod P and mod Q.
# Q_INV_MOD_P = Q^{-1}  mod  P  (Garner's algorithm coefficient).
# pow(Q, P-2, P) computes the modular inverse via Fermat's little theorem
# since P is prime.  Computed once at module load.
Q_INV_MOD_P: int = pow(Q, P - 2, P)


# ─────────────────────────────────────────────────────────────────────────────
# Module 1: DRBG Arithmetic
# ─────────────────────────────────────────────────────────────────────────────

def _crt_combine(r_p: int, r_q: int) -> int:
    """
    Garner's CRT: given  x ≡ r_p (mod P)  and  x ≡ r_q (mod Q),
    return the unique  x  in  [0, N)  satisfying both congruences.

    Garner's formula avoids computing with N-sized intermediates until
    the final step:
        h  =  (r_p − r_q) * Q_INV_MOD_P  mod  P
        x  =  r_q + Q * h

    This is equivalent to the textbook CRT formula but numerically cleaner.

    Correctness: h ∈ [0, P) so Q*h < Q*P = N, meaning r_q + Q*h < N + N = 2N.
    Since r_q < Q < N and Q*h < N, we have x < 2N.  One subtraction gives
    x mod N, but in practice x < N always holds for our use case.
    """
    h = (r_p - r_q) * Q_INV_MOD_P % P
    return r_q + Q * h


def drbg_step_from_state(state: int) -> tuple[int, int]:
    """
    Compute one DRBG step from a given state using the CRT-RSA technique.

    The computation is split as two exponentiations modulo P and Q
    (each ~257 bits) rather than one exponentiation modulo N (~514 bits).
    This is the CRT-RSA optimisation; the Crandall prime form of P and Q
    is what makes it both fast and cryptanalytically significant.

    Parameters
    ----------
    state : int
        Current STATE_BITS-wide internal state.

    Returns
    -------
    (output, new_state) : tuple[int, int]
        output    — the OUTPUT_BITS-wide block for this step
        new_state — the STATE_BITS-wide internal state for the next step
    """
    padded = state << OUTPUT_BITS        # s||000…0  (128 trailing zeros)

    # CRT-RSA: exponentiate mod each prime separately (faster than mod N).
    r_p = _powmod(padded, E, P)
    r_q = _powmod(padded, E, Q)

    # Reconstruct y mod N via Garner's algorithm.
    y = _crt_combine(r_p, r_q)

    output    = y & OUTPUT_MASK
    new_state = y >> OUTPUT_BITS
    return output, new_state


def advance_state(state: int, n_steps: int = 1) -> tuple[list[int], int]:
    """
    Advance the DRBG state by n_steps steps.

    Parameters
    ----------
    state  : int   Starting state.
    n_steps: int   Number of steps to advance.

    Returns
    -------
    (outputs, final_state) : tuple[list[int], int]
        outputs      — list of n_steps output blocks
        final_state  — the state after all n_steps
    """
    outputs = []
    for _ in range(n_steps):
        out, state = drbg_step_from_state(state)
        outputs.append(out)
    return outputs, state


# ─────────────────────────────────────────────────────────────────────────────
# Module 2: Seed Recovery
# ─────────────────────────────────────────────────────────────────────────────

def recover_seed(
    observed: list[int],
    *,
    progress_every: int = 1 << 18,
) -> int | None:
    """
    Exhaustively search for the seed s ∈ [2, 2^CHALLENGE_BITS) whose DRBG
    output sequence matches the observed blocks.

    Strategy
    --------
    For each candidate s:
        1. Compute the first DRBG output using CRT-RSA (two 257-bit powmods).
        2. If it matches observed[0], compute the second output and check.
        3. If both match, accept s as the recovered seed.

    The double-check (two consecutive outputs) makes false positives
    cryptographically impossible: a random 128-bit value matches a specific
    128-bit target with probability 2^{-128}; two independent matches have
    probability 2^{-256}.

    Why CRT-RSA helps
    -----------------
    Each loop iteration does 2× powmod(257-bit prime) instead of 1× powmod(514-bit N).
    Modular multiplication cost scales as O(k^2) for k-bit operands, so:
        2 × (257^2) ≈ 132 000   vs   514^2 ≈ 264 000
    That is, the CRT split halves the per-iteration cost, directly attributable
    to the Crandall prime factorisation of N.

    Parameters
    ----------
    observed       : list[int]  At least 2 output blocks.
    progress_every : int        Print progress after this many iterations.

    Returns
    -------
    int | None
        The recovered seed, or None if not found in [2, 2^CHALLENGE_BITS).
    """
    if len(observed) < 2:
        raise ValueError("Need at least 2 observed blocks to verify candidates.")

    target_0 = observed[0]
    target_1 = observed[1]

    print(f"[*] Searching seed space [2, 2^{CHALLENGE_BITS}) = "
          f"{(1 << CHALLENGE_BITS) - 2:,} candidates")
    print(f"[*] Backend: {'gmpy2 (fast)' if HAVE_GMPY2 else 'Python built-in (slow)'}")
    if not HAVE_GMPY2:
        print("[!] Install gmpy2 for a ~5-8× speedup:  pip install gmpy2")
    print()

    t_start = time.perf_counter()

    for s in range(2, 1 << CHALLENGE_BITS):

        # ── First-block check (fast reject) ───────────────────────────────
        padded = s << OUTPUT_BITS

        # CRT-RSA split: two 257-bit exponentiations.
        r_p = _powmod(padded, E, P)
        r_q = _powmod(padded, E, Q)
        y   = _crt_combine(r_p, r_q)

        if y & OUTPUT_MASK != target_0:
            # Progress heartbeat (fires rarely, minimal overhead).
            if s % progress_every == 0:
                elapsed = time.perf_counter() - t_start
                frac    = (s - 2) / ((1 << CHALLENGE_BITS) - 2)
                eta     = elapsed / frac - elapsed if frac > 0 else float("inf")
                print(f"    {frac * 100:5.1f}%  s={s:>10,}  "
                      f"elapsed={elapsed:6.1f}s  ETA={eta:6.1f}s")
            continue

        # ── Second-block check (confirm; eliminates all false positives) ───
        state_1  = y >> OUTPUT_BITS
        padded_1 = state_1 << OUTPUT_BITS

        r_p1 = _powmod(padded_1, E, P)
        r_q1 = _powmod(padded_1, E, Q)
        y1   = _crt_combine(r_p1, r_q1)

        if y1 & OUTPUT_MASK == target_1:
            elapsed = time.perf_counter() - t_start
            print(f"[+] Seed recovered: s = {s}  ({elapsed:.2f}s, "
                  f"{s - 2:,} iterations)")
            return s

    return None


# ─────────────────────────────────────────────────────────────────────────────
# Module 3: Flag Decryption
# ─────────────────────────────────────────────────────────────────────────────

def decrypt_flag(key_block: int, ciphertext_hex: str) -> bytes:
    """
    Decrypt the flag using the recovered DRBG key block.

    The challenge encrypted the flag as:
        AES-128-CTR(key=key_block_as_16_bytes_big_endian, nonce=0)

    We reverse this exactly.

    Parameters
    ----------
    key_block       : int   The 128-bit DRBG output block used as the AES key.
    ciphertext_hex  : str   Hex-encoded ciphertext from the challenge JSON.

    Returns
    -------
    bytes
        Decrypted flag.
    """
    key_bytes = key_block.to_bytes(OUTPUT_BITS // 8, byteorder="big")
    ct        = bytes.fromhex(ciphertext_hex)
    ctr       = Counter.new(128, initial_value=0)
    cipher    = AES.new(key_bytes, AES.MODE_CTR, counter=ctr)
    return cipher.decrypt(ct)


# ─────────────────────────────────────────────────────────────────────────────
# Module 4: Full Solve Pipeline
# ─────────────────────────────────────────────────────────────────────────────

def solve(challenge: dict) -> None:
    """
    End-to-end exploit pipeline.

    Phase 1 — Parse & validate
        Read n, e, observed blocks, and the ciphertext from the challenge JSON.
        Confirm the parameters match our backdoor knowledge.

    Phase 2 — Seed recovery
        Brute-force the seed s ∈ [2, 2^CHALLENGE_BITS) using CRT-RSA.

    Phase 3 — State advancement
        Starting from the recovered seed, step through each observed block to
        verify correctness and advance to the state that produced the key block.

    Phase 4 — Flag decryption
        Compute the key block (next DRBG output), decrypt with AES-128-CTR.

    Parameters
    ----------
    challenge : dict
        Parsed JSON from the challenge server.
    """
    # ── Phase 1: Parse ────────────────────────────────────────────────────
    n_given   = int(challenge["n"])
    e_given   = int(challenge["e"])
    observed  = [int(x) for x in challenge["observed"]]
    enc_flag  = challenge["encrypted_flag"]
    n_obs     = len(observed)

    print("=" * 65)
    print("  SchrodingerSeed — MS-DRBG Crandall Backdoor Exploit")
    print("=" * 65)
    print(f"  N (first 32 hex chars): {hex(n_given)[:34]}…")
    print(f"  E                     : {e_given}")
    print(f"  Output blocks given   : {n_obs} × {OUTPUT_BITS} bits")
    print(f"  P = 2^256 + {_C_P}  (Crandall prime — backdoor)")
    print(f"  Q = 2^256 + {_C_Q}  (Crandall prime — backdoor)")
    print()

    # Sanity-check: confirm we have the right backdoor parameters.
    if n_given != N:
        sys.exit("[-] N in challenge does not match our backdoor parameters. Abort.")
    if e_given != E:
        sys.exit("[-] E in challenge does not match our parameters. Abort.")

    # ── Phase 2: Seed Recovery ────────────────────────────────────────────
    print("─" * 65)
    print("[Phase 2] Brute-forcing seed via CRT-RSA split…")
    print()

    seed = recover_seed(observed)

    if seed is None:
        sys.exit("[-] Seed not found in search space. "
                 "Check CHALLENGE_BITS matches chal.py.")

    # ── Phase 3: State Advancement ────────────────────────────────────────
    print()
    print("─" * 65)
    print("[Phase 3] Advancing state through observed blocks…")
    print()

    state = seed
    for i, expected in enumerate(observed):
        actual, state = drbg_step_from_state(state)
        status = "✓" if actual == expected else "✗ MISMATCH"
        print(f"  observed[{i}] = {hex(expected)[:18]}…  {status}")
        if actual != expected:
            sys.exit(f"[-] Block {i} mismatch. Something went wrong.")

    print(f"\n[+] All {n_obs} blocks verified. Current state = {hex(state)[:18]}…")

    # ── Phase 4: Predict Key Block & Decrypt ─────────────────────────────
    print()
    print("─" * 65)
    print("[Phase 4] Predicting AES key block (next DRBG output)…")

    key_block, _next_state = drbg_step_from_state(state)
    print(f"[+] Key block = {hex(key_block)[:18]}…")

    print()
    print("[Phase 5] Decrypting flag…")
    flag = decrypt_flag(key_block, enc_flag)

    print()
    print("=" * 65)
    try:
        print(f"  FLAG: {flag.decode()}")
    except UnicodeDecodeError:
        print(f"  FLAG (raw bytes): {flag!r}")
    print("=" * 65)


# ─────────────────────────────────────────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} challenge.json")
        print()
        print("Generate a challenge first:")
        print("    python chal.py > challenge.json")
        sys.exit(1)

    with open(sys.argv[1]) as fh:
        data = json.load(fh)

    solve(data)