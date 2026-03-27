# SchrodingerSeed

**Category:** Cryptography  
**Difficulty:** Hard (500 pts)  
**Author:** supasuge / Fortify Vector Labs
 
---
 
## Challenge Description
 
> The government assures you this random number generator is perfectly
> secure. They published the modulus. They even told you the exponent.
>
> What they didn't tell you is *who chose the primes*.
>
> Observe the oracle. Predict the future. Steal the flag.
 
**Files given to players:**
- `chal.py` — the challenge server (run to get a fresh instance)
- `challenge.json` — one pre-generated sample output
 
---
 
## Background: The Micali-Schnorr DRBG
 
The **Micali-Schnorr DRBG (MS-DRBG)** is a real NIST-standardised
deterministic random bit generator (FIPS SP 800-90A, Appendix E.3) based
on RSA. Its operation is elegantly simple:
 
```
Parameters:  N = p·q (RSA modulus),  e (RSA public exponent)
State:       s  (secret, never revealed)
 
Each step:
    padded  =  s  <<  OUTPUT_BITS        # zero-pad low bits
    y       =  padded^e  mod  N          # RSA "encrypt" the state
    output  =  y  &  MASK_OUTPUT         # low bits → caller
    s       =  y  >>  OUTPUT_BITS        # high bits → new state
```
 
Security rests on: *without the factorisation of N, you cannot invert RSA,
so you cannot recover s from output — the generator is a one-way function.*
 
**The catch:** what if the party who built the standard secretly chose
p and q with exploitable algebraic structure?
 
This challenge is directly inspired by
[Antonio Sanso's 2017 blog post](https://blog.intothesymmetry.com/2017/10/how-to-try-to-predict-output-of-micali.html)
exploring exactly this scenario — itself a response to Matthew Green's
observation that MS-DRBG, like the infamous Dual_EC_DRBG, could carry a
backdoor if the prime choices weren't generated transparently.
 
---
 
## Challenge Parameters
 
| Parameter      | Value                           | Visible to player? |
|---------------|---------------------------------|--------------------|
| `N`           | `P × Q`  (~514 bits)            | ✅ Yes              |
| `E`           | `65537`                         | ✅ Yes              |
| `OUTPUT_BITS` | `128`                           | ✅ Yes              |
| `STATE_BITS`  | `386`                           | ✅ Yes              |
| observed      | 4 consecutive 128-bit blocks    | ✅ Yes              |
| encrypted flag | AES-128-CTR ciphertext         | ✅ Yes              |
| `P`           | `2^256 + 297`  (Crandall prime) | ❌ Hidden           |
| `Q`           | `2^256 + 301`  (Crandall prime) | ❌ Hidden           |
| seed entropy  | 24 bits  (not 386)              | ❌ Hidden           |
 
The flag is encrypted as:
```
AES-128-CTR(
    key   = (next DRBG output after observed blocks).to_bytes(16, 'big'),
    nonce = 0
)
```
 
---
 
## The Vulnerability: Crandall Prime Backdoor
 
### What is a Crandall Prime?
 
A **Crandall prime** (pseudo-Mersenne prime) has the form:
 
```
p = 2^k + c        (|c| tiny, typically fitting in 32 bits)
```
 
They enable extremely fast modular reduction via the identity:
 
```
x mod (2^k + c)  ≡  (x mod 2^k)  −  c · (x >> k)    (mod p)
```
 
Because `c` is tiny, this reduces to a single multiply-and-subtract
instead of a full multi-precision division — a significant hardware win.
Examples in real cryptography: the field primes used by Curve25519
(`2^255 − 19`) and secp256k1 (`2^256 − 2^32 − 977`).
 
In this challenge:
```
P = 2^256 + 297
Q = 2^256 + 301
```
 
### The CRT-RSA Speedup (Why This Matters)
 
The exploit splits the RSA exponentiation using the **Chinese Remainder
Theorem** (CRT-RSA, a standard technique in RSA implementations):
 
```
r_p  =  padded^E  mod  P           # 257-bit prime modulus
r_q  =  padded^E  mod  Q           # 257-bit prime modulus
y    =  CRT(r_p, r_q)  mod  N      # Garner's algorithm to recombine
```
 
Modular multiplication cost scales as O(k²) for k-bit operands.
 
```
Two 257-bit powmods:   2 × (257²) ≈ 132,000 "units"
One 514-bit powmod:    1 × (514²) ≈ 264,000 "units"
```
 
**The CRT split halves the per-iteration cost.** This is the mathematical
mechanism behind the backdoor's exploitability: the Crandall prime structure
directly enables efficient CRT decomposition that someone without the
factorisation cannot perform.
 
Garner's CRT recombination formula:
```python
# Q_inv = Q^{-1} mod P  (precomputed once)
h = (r_p - r_q) * Q_inv % P
y = r_q + Q * h                    # exact, no reduction needed since y < N
```
 
### The "Small Seed" Attack Surface
 
A real MS-DRBG seed would be `STATE_BITS = 386` bits of entropy — brute
forcing `2^386` candidates is impossible.
 
This challenge seeds the generator with only **24 bits of entropy**
(`CHALLENGE_BITS = 24`), simulating a weak implementation.  The solver
exhaustively tries all `2^24 ≈ 16.7 million` candidates using the CRT-RSA
split, verifying each against the first two observed output blocks.
 
In a real-world attack against the full-entropy generator, you would use
**lattice methods** (LLL/BKZ applied to the Hidden Number Problem).  The
Crandall prime structure is what makes such a lattice attack tractable for
an adversary with the factorisation — ordinary RSA primes don't provide
this algebraic foothold.  This is Antonio Sanso's research insight: the
Crandall property leaks ~128 bits of partial information about each RSA
residue mod p and mod q, which can seed a lattice attack.
 
---
 
## Attack Chain (Step-by-Step)
 
```
┌────────────────────────────────────────────────────────────────┐
│  Attacker knows (backdoor):                                    │
│    P = 2^256 + 297,  Q = 2^256 + 301                          │
│    Q_inv_mod_P  =  Q^{-1} mod P  (precompute once)            │
└────────────────────────────────────────────────────────────────┘
 
Phase 1 — Seed Recovery
────────────────────────
```
for s in range(2, 2^24):
 
    padded = s << 128
 
    # CRT-RSA split (2× faster than mod-N)
    r_p = pow(padded, E, P)
    r_q = pow(padded, E, Q)
 
    # Garner recombination
    h = (r_p - r_q) * Q_inv_mod_P % P
    y = r_q + Q * h
 
    # First filter: does this match observed[0]?
    if y & MASK_128 != observed[0]:
        continue
 
    # Second filter: verify observed[1] (eliminates false positives)
    state_1 = y >> 128
    r_p1 = pow(state_1 << 128, E, P)
    r_q1 = pow(state_1 << 128, E, Q)
    y1   = r_q1 + Q * ((r_p1 - r_q1) * Q_inv_mod_P % P)
 
    if y1 & MASK_128 == observed[1]:
        SEED FOUND → s
        break
```


Phase 2 — State Advancement
─────────────────────────────
Starting from seed s, advance the DRBG through all 4 observed blocks
using the same CRT-RSA step.  This both verifies correctness and
lands us at the state that will produce the AES key block.
 
Phase 3 — Key Block Prediction
────────────────────────────────
Execute one more DRBG step.  The 128-bit output is the AES key.
 
Phase 4 — Flag Decryption
───────────────────────────
key_bytes = key_block.to_bytes(16, 'big')
flag = AES-128-CTR(key=key_bytes, nonce=0).decrypt(ciphertext)
```
 
---
 
## Setup
 
### Requirements
 
```bash
pip install pycryptodome gmpy2
```
 
`gmpy2` links against GMP for fast big-integer arithmetic.  The solver
works without it (falls back to Python's built-in `pow`) but runs 5-8×
slower, making the worst-case solve time around 3-4 minutes instead of ~40 s.
 
### Generate a fresh challenge
 
```bash
python chal.py > challenge.json
cat challenge.json
```
 
Sample output:
```json
{
  "n": "13407807929...",
  "e": 65537,
  "n_bits": 514,
  "output_bits": 128,
  "state_bits": 386,
  "observed": ["1234567...", "8901234...", "5678901...", "2345678..."],
  "encrypted_flag": "a1b2c3d4...",
  "note": "DRBG step: padded = state << output_bits; ..."
}
```
 
### Solve it
 
```bash
python solve.py challenge.json
```
 
Expected output:
```
═════════════════════════════════════════════════════════════════
  SchrodingerSeed — MS-DRBG Crandall Backdoor Exploit
═════════════════════════════════════════════════════════════════
  N (first 32 hex chars): 0x1800000000000000000…
  E                     : 65537
  Output blocks given   : 4 × 128 bits
  P = 2^256 + 297  (Crandall prime — backdoor)
  Q = 2^256 + 301  (Crandall prime — backdoor)
 
─────────────────────────────────────────────────────────────────
[Phase 2] Brute-forcing seed via CRT-RSA split…
 
[*] Searching seed space [2, 2^24) = 16,777,214 candidates
[*] Backend: gmpy2 (fast)
 
[+] Seed recovered: s = 9123456  (22.73s, 9,123,454 iterations)
 
─────────────────────────────────────────────────────────────────
[Phase 3] Advancing state through observed blocks…
 
  observed[0] = 0x3f9a1b2c4e5d6f7a…  ✓
  observed[1] = 0xdeadbeef01234567…  ✓
  observed[2] = 0xcafebabe89abcdef…  ✓
  observed[3] = 0x0011223344556677…  ✓
 
[+] All 4 blocks verified.
 
─────────────────────────────────────────────────────────────────
[Phase 4] Predicting AES key block (next DRBG output)…
[+] Key block = 0xfeedfacedeadbeef…
 
[Phase 5] Decrypting flag…
 
═════════════════════════════════════════════════════════════════
  FLAG: GrizzHacks{Cr4nd4ll_Pr1m3s_MS_DRBG_B4ckd00r_CRT_pwn3d!}
═════════════════════════════════════════════════════════════════
```
 
---
 
## Difficulty Tuning
|
| Adjustment                       | Effect                                                       |
|-----------------:----------------|--------------------------------:-----------------------------|
| `CHALLENGE_BITS`: 24 → 28        | 16× harder brute force; ~10 min with gmpy2                  |
| `CHALLENGE_BITS`: 24 → 32        | 256× harder; requires parallelism or C implementation        |
| `CHALLENGE_BITS`: full (386)     | Requires lattice attack (LLL/BKZ) — research difficulty      |
| `n_observed`: 4 → 2              | Only 1 verification oracle; slightly harder to confirm state |
| `n_observed`: 4 → 1              | Cannot verify without trying AES decryption as oracle        |
 
### Scaling to the Full Lattice Attack
 
For full-entropy seeds the solver must solve the **Hidden Number Problem**
(HNP) via lattice reduction:
 
1. Collect `t` observed output blocks.
2. Express each as:
   `obs[i] = CRT(f_p(s_i), f_q(s_i)) mod 2^128`
   where `f_p(s) = (s << 128)^E mod P`.
3. Since `s_{i+1}` is a deterministic function of `s_i` (via RSA), the
   sequence `s_0, s_1, …` satisfies polynomial relations modulo P and Q.
4. Construct a lattice basis encoding these relations.
5. Apply **LLL reduction** to find the short vector corresponding to `s_0`.
6. The Crandall prime structure (small `c` in `p = 2^256 + c`) ensures the
   relevant sublattice has a sufficiently short basis for LLL to succeed.
 
See: Boneh-Venkatesan (HNP, 1996) and Heninger-Shacham (RSA key bits, 2009)
for the foundational lattice techniques.
 
---
 
## References
 
1. **Antonio Sanso** — *How to try to predict the output of the Micali-Schnorr Generator*  
   https://blog.intothesymmetry.com/2017/10/how-to-try-to-predict-output-of-micali.html
 
2. **Matthew Green** — *A few more notes on NSA random number generators*  
   https://blog.cryptographyengineering.com/2013/12/28/a-few-more-notes-on-nsa-random-number/
 
3. **NIST FIPS SP 800-90A Rev 1** — Recommendation for Random Number Generation  
   https://csrc.nist.gov/publications/detail/sp/800-90a/rev-1/final
 
4. **Cohen et al.** — *Handbook of Elliptic and Hyperelliptic Curve Cryptography*,  
   Chapter 10: Special Moduli and Crandall Primes
 
5. **Boneh, Venkatesan** — *Hardness of Computing the Most Significant Bits of  
   Secret Keys in Diffie-Hellman* (Hidden Number Problem), CRYPTO 1996
 
6. **Heninger, Shacham** — *Reconstructing RSA Private Keys from Random Key Bits*,  
   CRYPTO 2009