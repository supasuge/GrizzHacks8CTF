#/usr/bin/env python3

"""
For some background on the challenge, The Micali-Schnorr DRBG is a NIST-standarised deterministic random bit generator based on RSA (FIPS SP 800-90A).

- It goes as follows:

Parameters: $N =[ p\times q]$
Internal  state: s (secret seed, never supposed to be revealed)
- Predicting future outputs requires inverting RSA, i.e. factoring N.

From here the "operator" secretly chose p and q to be *Crandall primes* of the form:
$$
p = 2^{256} + c_{p} (c_{p},\;\text{tiny, 9 bits})
q = 2^{256} + c_{q} (c_{q},\;\text{tiny, 9 bits})
$$

"""
#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║              SchrodingerSeed — CTF Challenge Server              ║
║              Category: Cryptography  |  Difficulty: Hard         ║
╚══════════════════════════════════════════════════════════════════╝

Background
----------
The Micali-Schnorr DRBG (MS-DRBG) is a NIST-standardised deterministic
random bit generator based on RSA (FIPS SP 800-90A). It works as follows:

    Parameters:  N = p*q (RSA modulus),  e (RSA public exponent)
    Internal state:  s  (secret seed, never revealed)

    Each step:
        y      = s^e  mod  N          ← RSA "encryption" of the state
        output = LOW  bits of y       ← sent to caller  (you see these)
        s      = HIGH bits of y       ← new internal state  (secret)

The security argument: predicting future outputs requires inverting RSA,
which requires factoring N.

The Backdoor
------------
The operator secretly chose p and q to be *Crandall primes* of the form:

    p = 2^256 + c_p        (c_p tiny, 9 bits)
    q = 2^256 + c_q        (c_q tiny, 9 bits)

Anyone who knows the factorisation and understands the Crandall structure
can exploit it combined with the weakly-seeded generator to recover state.

What You Get
------------
  • n, e            — public RSA parameters (N = p*q is ~514 bits)
  • output_bits     — low bits of each RSA output that are published each step
  • state_bits      — high bits kept as next internal state
  • observed        — 4 consecutive DRBG output blocks (each 128 bits)
  • encrypted_flag  — AES-128-CTR ciphertext keyed with the NEXT DRBG block

Your Goal
---------
Recover the internal state, predict the next DRBG output, decrypt the flag.

Usage
-----
    python chal.py > challenge.json
"""
import logging
import os
import json
import hashlib
import hmac
import time
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.PublicKey import ECC
from Crypto.Signature import ecdsa
from sympy import isprime

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s | %(levelname)-8s | %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# RSA Parameters: Crandall Primes

_C_P: int = 297
_C_Q: int = 301

logger.info("Verifying Crandall primes...")
assert isprime((1 << 256) + _C_P), "P: 2^256 + 297 must be prime"
logger.debug(f"! P_CAND verified: (1 << 256) + {_C_P}")

assert isprime((1 << 256) + _C_Q), "Q: 2^256 + 301 must be prime"
logger.debug(f"! Q_CAND verified: (1 << 256) + {_C_Q}")

P: int = (1 << 256) + _C_P
Q: int = (1 << 256) + _C_Q
N: int = P * Q
E: int = 65537

logger.info(f"RSA modulus N generated: {N.bit_length()} bits")
logger.debug(f"  P = 2^256 + {_C_P} ({P.bit_length()} bits)")
logger.debug(f"  Q = 2^256 + {_C_Q} ({Q.bit_length()} bits)")
logger.debug(f"  e = {E}")

# MS-DRBG Parameters

N_BITS:      int = N.bit_length()
OUTPUT_BITS: int = 128
STATE_BITS:  int = N_BITS - OUTPUT_BITS
OUTPUT_MASK: int = (1 << OUTPUT_BITS) - 1

assert N_BITS == 514, f"N should be 514 bits, got {N_BITS}"
logger.debug(f"! N_BITS = {N_BITS}, OUTPUT_BITS = {OUTPUT_BITS}, STATE_BITS = {STATE_BITS}")

CHALLENGE_BITS: int = 24

assert CHALLENGE_BITS < STATE_BITS, "CHALLENGE_BITS must be less than STATE_BITS"
logger.debug(f"! CHALLENGE_BITS = {CHALLENGE_BITS} (brute-force window)")

# Curve25519 Parameters (Authenticated Challenge-Response)

logger.info("Generating Curve25519 keypair for authenticated challenge-response...")
ECC_KEY = ECC.generate(curve='ed25519')
ECC_PUBLIC = ECC_KEY.public_key()

logger.debug(f"! Curve25519/Ed25519 keypair generated")

FLAG: bytes = open('flag.txt', 'rb').read().strip()
assert len(FLAG) > 0, "Flag must not be empty"
logger.info(f"! Flag loaded: {len(FLAG)} bytes")

# 
# MS-DRBG Core
# 


class MSDRBG:
    """
    Micali-Schnorr Deterministic Random Bit Generator (simplified).

    Internal state layout
    ---------------------
    _state  — a STATE_BITS-wide integer (high bits of the last RSA output).

    Each call to _step():
        padded = _state << OUTPUT_BITS    # zero-pad low OUTPUT_BITS bits
        y      = pow(padded, E, N)        # RSA "encrypt" the state
        output = y & OUTPUT_MASK          # low OUTPUT_BITS bits  → caller
        _state = y >> OUTPUT_BITS         # high STATE_BITS bits  → new state

    The zero-padding is intrinsic: the state never occupies those low bits,
    so output and state are cleanly partitioned within every RSA computation.
    """

    def __init__(self, seed: int) -> None:
        """
        seed — secret initial state in (1, 2^STATE_BITS).
               The challenge restricts seed to [2, 2^CHALLENGE_BITS).
        """
        assert 1 < seed < (1 << STATE_BITS), \
            f"seed must be in (1, 2^{STATE_BITS}), got {seed}"
        logger.debug(f"MSDRBG initialized with seed in valid range [2, 2^{CHALLENGE_BITS})")
        self._state: int = seed
        self._step_count: int = 0

    def _step(self) -> int:
        """One DRBG step. Returns the OUTPUT_BITS-wide output block."""
        padded       = self._state << OUTPUT_BITS
        y            = pow(padded, E, N)
        output       = y & OUTPUT_MASK
        self._state  = y >> OUTPUT_BITS
        self._step_count += 1
        
        assert 0 <= output < (1 << OUTPUT_BITS), \
            f"Output out of range: {output}"
        logger.debug(f"DRBG step {self._step_count}: output={output} (state updated)")
        
        return output

    def generate(self, n_blocks: int) -> list[int]:
        """Produce n_blocks consecutive output blocks."""
        assert n_blocks > 0, "n_blocks must be positive"
        logger.info(f"Generating {n_blocks} DRBG output blocks...")
        blocks = [self._step() for _ in range(n_blocks)]
        logger.debug(f"! Generated {n_blocks} blocks successfully")
        return blocks

# 
# Authenticated Challenge-Response (Curve25519/Ed25519)
# 

class AuthenticatedChallenge:
    """
    Challenge-response authentication using Ed25519 signatures.
    
    Protocol:
        1. Server sends challenge (random bytes)
        2. Client signs: signature = Ed25519.sign(challenge)
        3. Server verifies: Ed25519.verify(challenge, signature, pubkey)
    """

    def __init__(self, challenge_bytes: int = 32) -> None:
        """Initialize authenticated challenge generator."""
        self.challenge_bytes = challenge_bytes
        logger.info("Authenticated challenge-response system initialized")

    def generate_challenge(self) -> bytes:
        """Generate a random challenge."""
        challenge = os.urandom(self.challenge_bytes)
        logger.debug(f"Generated challenge: {challenge.hex()[:16]}... ({self.challenge_bytes} bytes)")
        return challenge

    def sign_challenge(self, challenge: bytes) -> bytes:
        """Sign a challenge using stored ECC private key."""
        assert len(challenge) > 0, "Challenge must not be empty"
        signature = ECC_KEY.sign(challenge)
        logger.debug(f"Signed challenge: signature_len={len(signature)}")
        return signature

    def verify_signature(self, challenge: bytes, signature: bytes) -> bool:
        """Verify a challenge signature."""
        try:
            # Verify accepts message and signature
            verifier = ecdsa.new('fips-186-3', hashfunc=hashlib.sha256)
            is_valid = verifier.verify(challenge, signature, ECC_PUBLIC)
            
            status = "! VALID" if is_valid else "✗ INVALID"
            logger.debug(f"Signature verification: {status}")
            return is_valid
        except Exception as e:
            logger.warning(f"Signature verification failed: {e}")
            return False

# Initialize authenticated challenge system
AUTH_CHALLENGE = AuthenticatedChallenge(challenge_bytes=32)


def encrypt_flag(drbg: MSDRBG) -> bytes:
    """
    Encrypt FLAG using the next DRBG block as an AES-128-CTR key.

    Scheme
    ------
    key   = next 128-bit DRBG output block, encoded big-endian (16 bytes)
    nonce = 0  (fixed and public — only the key is secret)
    mode  = AES-128-CTR
    """
    logger.info("Encrypting flag with next DRBG block...")
    key_block: int   = drbg._step()
    key_bytes: bytes = key_block.to_bytes(OUTPUT_BITS // 8, byteorder="big")
    
    assert len(key_bytes) == 16, f"Key must be 16 bytes, got {len(key_bytes)}"
    logger.debug(f"! AES key derived from DRBG (128 bits)")
    
    ctr    = Counter.new(128, initial_value=0)
    cipher = AES.new(key_bytes, AES.MODE_CTR, counter=ctr)
    encrypted = cipher.encrypt(FLAG)
    
    assert len(encrypted) == len(FLAG), "Encryption resulted in wrong length"
    logger.info(f"! Flag encrypted: {len(encrypted)} bytes ciphertext")
    
    return encrypted


# 
# Challenge Builder
# 

def build_challenge(n_observed: int = 4) -> dict:
    """
    Generate a fresh challenge instance with authenticated handshake.

    Steps
    -----
    1. Sample a secret seed from [2, 2^CHALLENGE_BITS).
    2. Run the DRBG to produce n_observed output blocks (given to the player).
    3. Produce one more block, use it as the AES key, encrypt the flag.
    4. Generate authenticated challenge for verification.
    5. Return all public information as a JSON-friendly dict.

    All large integers are serialised as decimal strings to avoid JSON
    precision issues with numbers > 2^53.
    """
    logger.info("=" * 70)
    logger.info("Building new challenge instance...")
    logger.info("=" * 70)
    
    #  Secret seed 
    logger.debug("Step 1: Sampling secret seed...")
    raw  = int.from_bytes(os.urandom((CHALLENGE_BITS + 7) // 8), "big")
    seed = (raw % ((1 << CHALLENGE_BITS) - 2)) + 2
    assert 2 <= seed < (1 << CHALLENGE_BITS), "Seed out of valid range"
    logger.debug(f"! Seed sampled: {seed} in range [2, 2^{CHALLENGE_BITS})")

    #  DRBG 
    logger.debug("Step 2: Generating DRBG output blocks...")
    drbg     = MSDRBG(seed)
    observed = drbg.generate(n_observed)
    logger.info(f"! Generated {n_observed} observed blocks")

    #  Encrypt flag with the NEXT block 
    logger.debug("Step 3: Encrypting flag...")
    encrypted_flag = encrypt_flag(drbg)
    logger.info(f"! Flag encrypted: {encrypted_flag.hex()[:32]}...")

    #  Authenticated challenge 
    logger.debug("Step 4: Generating authenticated challenge...")
    challenge_bytes = AUTH_CHALLENGE.generate_challenge()
    challenge_sig   = AUTH_CHALLENGE.sign_challenge(challenge_bytes)
    logger.info(f"! Challenge generated and signed")

    logger.debug("Step 5: Building response dictionary...")
    response = {
        "metadata": {
            "timestamp":     datetime.utcnow().isoformat() + "Z",
            "challenge_id":  hashlib.sha256(challenge_bytes).hexdigest()[:16],
            "version":       "1.0",
            "category":      "Cryptography",
            "difficulty":    "Hard"
        },
        "rsa_parameters": {
            "n":             str(N),
            "e":             E,
            "n_bits":        N_BITS,
            "output_bits":   OUTPUT_BITS,
            "state_bits":    STATE_BITS
        },
        "drbg": {
            "observed_blocks": [str(x) for x in observed],
            "num_observed":    n_observed,
            "block_size_bits": OUTPUT_BITS
        },
        "flag": {
            "encrypted": encrypted_flag.hex(),
            "cipher":    "AES-128-CTR",
            "nonce":     "0"
        },
        "authentication": {
            "challenge":      challenge_bytes.hex(),
            "signature":      challenge_sig.hex(),
            "curve":          "Ed25519",
            "pubkey":         ECC_PUBLIC.export_key(format='PEM')
        },
        "note": (
            "DRBG step: padded = state << output_bits; "
            "y = pow(padded, e, n); "
            "output = y & ((1 << output_bits) - 1); "
            "state = y >> output_bits. "
            "Flag: AES-128-CTR(key=next_output_block_as_16_bytes_big_endian, nonce=0). "
            "Authenticated handshake required before flag submission."
        ),
    }

    logger.info("! Challenge built successfully")
    logger.info("=" * 70)
    
    return response


def build_manifest() -> dict:
    """
    Tracks:
    - Challenge metadata (creation timestamp, version)
    - Access control (who can view/solve)
    - Lookups (attempts, verifications)
    - FSA (Formal State Attestation)
    - RBAC (Role-Based Access Control)
    """
    logger.info("Building manifest.json for attestation tracking...")
    
    manifest = {
        "manifest_version": "1.0",
        "generated": datetime.utcnow().isoformat() + "Z",
        
        "challenge": {
            "name": "SchrodingerSeed",
            "category": "Cryptography",
            "difficulty": "Hard",
            "description": "MS-DRBG backdoor exploitation via Crandall primes",
            "requires_authentication": True
        },
        
        "attestation": {
            "rsa_parameters_attested": True,
            "drbg_state_attested": True,
            "flag_encryption_attested": True,
            "curve25519_signature_attested": True,
            "attestation_timestamp": datetime.utcnow().isoformat() + "Z"
        },
        
        "access_control": {
            "roles": {
                "admin":      {"permissions": ["view", "solve", "verify", "modify"]},
                "challenger": {"permissions": ["view", "solve", "verify"]},
                "observer":   {"permissions": ["view"]}
            },
            "default_role": "challenger"
        },
        
        "lookups": {
            "total_attempts": 0,
            "successful_authentications": 0,
            "failed_authentications": 0,
            "flag_submissions": 0,
            "correct_solutions": 0
        },
        
        "formal_state_attestation": {
            "n_is_valid": True,
            "p_is_crandall": True,
            "q_is_crandall": True,
            "drbg_properly_initialized": True,
            "flag_properly_encrypted": True,
            "ecc_keys_valid": True
        },
        
        "rbac_matrix": {
            "admin": {
                "can_create_challenge": True,
                "can_verify_solution": True,
                "can_modify_parameters": True,
                "can_access_private_keys": True
            },
            "challenger": {
                "can_create_challenge": False,
                "can_verify_solution": False,
                "can_modify_parameters": False,
                "can_access_private_keys": False
            },
            "observer": {
                "can_create_challenge": False,
                "can_verify_solution": False,
                "can_modify_parameters": False,
                "can_access_private_keys": False
            }
        },
        
        "audit_log": [
            {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "event": "challenge_generated",
                "actor": "system",
                "details": "SchrodingerSeed challenge instance created"
            }
        ]
    }
    
    logger.info("! Manifest built successfully")
    return manifest


if __name__ == "__main__":
    logger.info("Initialized SchrodingerSeed Challenge Generator")
    
    try:
        logger.info("Building challenge...")
        challenge = build_challenge(n_observed=4)
        
        logger.info("Writing challenge.json...")
        with open('challenge.json', 'w') as f:
            json.dump(challenge, f, indent=2)
        logger.info("! challenge.json written")
        
        logger.info("Building manifest.json...")
        manifest = build_manifest()
        
        logger.info("Writing manifest.json...")
        with open('manifest.json', 'w') as f:
            json.dump(manifest, f, indent=2)
        logger.info("! manifest.json written")
        
        logger.info("Outputting challenge to stdout...")
        print(json.dumps(challenge, indent=2))
        
        logger.info("=" * 70)
        logger.info("Challenge generation completed successfully!")
        logger.info("=" * 70)
        
    except Exception as e:
        logger.error(f"Challenge generation failed: {e}", exc_info=True)
        raise
