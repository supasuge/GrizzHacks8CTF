#!/usr/bin/env python3
"""
ECBeast Solution - ECB Byte-at-a-Time Oracle Attack
====================================================

## Vulnerability Overview

AES-ECB mode is deterministic: the same plaintext block always encrypts to the 
same ciphertext block under the same key. This challenge prepends user input to 
a secret flag before encryption:

    ciphertext = AES_ECB_ENCRYPT(user_input || flag || padding)

Since we control `user_input`, we can:
1. Align the flag bytes at specific positions within block boundaries
2. Create "reference" ciphertexts with unknown bytes at predictable positions
3. Brute-force each byte by comparing block encryptions

## Attack Strategy

For each byte position `i` in the flag:

1. **Reference Query**: Send a prefix that places flag[i] at the END of a block
   - Prefix length = (BLOCK_SIZE - 1 - i) % BLOCK_SIZE
   - Block contains: prefix + flag[0:i+1] (where flag[i] is unknown)

2. **Test Query**: For each candidate byte `g`:
   - Send: prefix + known_flag_bytes + g
   - Compare the target block against the reference
   - Match means g == flag[i]

## Block Alignment Examples

BLOCK_SIZE = 16 bytes

For flag[0] (i=0):
  Prefix: 15 bytes of 'A'
  Reference block 0: [AAAAAAAAAAAAAAA?] where ? = flag[0]
  Test block 0:      [AAAAAAAAAAAAAAg] where g = our guess

For flag[15] (i=15):
  Prefix: 0 bytes (empty)
  Reference block 0: [flag[0:16]]
  Test block 0:      [known_15_bytes + g]

For flag[16] (i=16):
  Prefix: 15 bytes of 'A'
  Reference block 1: [flag[1:17]]
  Test block 1:      [known[1:16] + g]
"""

from pwn import *
import sys
import os

# =============================================================================
# Configuration
# =============================================================================
LOCAL = False              # Set to False for remote connection
HOST = "172.237.157.114"
PORT = 5337

BLOCK_SIZE = 16            # AES block size
PAD_BLOCK = 32             # Challenge's padding boundary
FLAG_LEN = 32              # Expected flag length
KNOWN_PREFIX = b"GRIZZ{"   # Known flag prefix for verification

# Padding character candidates (must match challenge)
PAD_CANDIDATES = b"_#@!$%&*"

# Set log level (debug, info, warn, error)
context.log_level = 'info'


# =============================================================================
# Utility Functions
# =============================================================================
def get_blocks(data: bytes, block_size: int = BLOCK_SIZE) -> list:
    """Split data into blocks of specified size."""
    return [data[i:i+block_size] for i in range(0, len(data), block_size)]


def connect():
    """Establish connection to the challenge."""
    if LOCAL:
        # For local testing, run the challenge as a process
        script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "chal.py")
        return process(["python3", script_path])
    else:
        return remote(HOST, PORT)


# =============================================================================
# Oracle Interface
# =============================================================================
def oracle(r, payload: bytes, max_retries: int = 3) -> bytes:
    """
    Send a payload to the encryption oracle and receive the ciphertext.
    
    Args:
        r: pwntools connection object
        payload: bytes to send as user input
        max_retries: number of retry attempts on failure
    
    Returns:
        bytes: the hex-decoded ciphertext
    
    Raises:
        RuntimeError: if communication fails after all retries
    """
    last_error = None
    
    for attempt in range(max_retries):
        try:
            # Wait for prompt and send payload
            r.sendlineafter(b"Submit your scroll fragment: ", payload, timeout=5)
            
            # Receive response
            r.recvuntil(b"Sealed scroll (hex):\n", timeout=5)
            ct_hex = r.recvline(timeout=5).strip().decode('ascii')
            
            # Validate and decode
            if not ct_hex:
                raise ValueError("Received empty ciphertext")
            
            return bytes.fromhex(ct_hex)
            
        except Exception as e:
            last_error = e
            log.debug(f"Oracle attempt {attempt + 1} failed: {e}")
            
            # Small delay before retry
            if attempt < max_retries - 1:
                import time
                time.sleep(0.1)
    
    raise RuntimeError(f"Oracle failed after {max_retries} retries: {last_error}")


# =============================================================================
# Padding Character Discovery
# =============================================================================
def find_padding_char(r) -> int:
    """
    Determine the random padding character used by this connection.
    
    Strategy:
    ---------
    Send enough copies of a candidate character to create recognizable patterns.
    If we send 33 bytes of character 'X', the plaintext becomes:
    
        X * 33 + flag(32 bytes) = 65 bytes
        Padded to 96 bytes = 31 bytes of padding
    
    Block layout (assuming 'X' is the padding character):
        Block 0: XXXXXXXXXXXXXXXX  (our input)
        Block 1: XXXXXXXXXXXXXXXX  (our input)
        Block 2: X + flag[0:15]    (1 byte input + 15 flag bytes)
        Block 3: flag[15:31]       (16 flag bytes)
        Block 4: flag[31] + XXXXXXXXXXXXXXX (1 flag + 15 padding)
        Block 5: XXXXXXXXXXXXXXXX  (16 padding bytes)
    
    If X == padding_char: blocks 0, 1, and 5 will all be identical!
    
    Returns:
        int: the padding character byte value
    """
    log.info("Discovering padding character...")
    
    for candidate in PAD_CANDIDATES:
        # Send 33 copies of the candidate
        payload = bytes([candidate]) * 33
        
        try:
            ct = oracle(r, payload)
            blocks = get_blocks(ct)
            
            # We expect at least 6 blocks (96 bytes / 16 bytes per block)
            if len(blocks) >= 6:
                # Check if blocks 0, 1, and 5 are identical
                if blocks[0] == blocks[1] == blocks[5]:
                    log.success(f"Found padding character: '{chr(candidate)}' (0x{candidate:02x})")
                    return candidate
                    
        except Exception as e:
            log.debug(f"Error testing candidate '{chr(candidate)}': {e}")
            continue
    
    # Fallback: try alternative detection method
    log.warning("Primary detection failed, trying alternative method...")
    return find_padding_char_alternative(r)


def find_padding_char_alternative(r) -> int:
    """
    Alternative padding detection using 48-byte payloads.
    
    With 48 bytes input + 32 byte flag = 80 bytes → padded to 96 bytes (16 padding)
    
    Block layout (if 'X' is padding char):
        Block 0-2: Our input (48 bytes)
        Block 3-4: Flag (32 bytes, possibly split with padding)
        Block 5: Last block with padding
        
    Send 48 of each candidate. For the actual padding char, block 5 will match
    the pattern of a full block of that character.
    """
    log.info("Trying alternative padding detection...")
    
    # First, get a reference for each candidate's full block encryption
    references = {}
    for candidate in PAD_CANDIDATES:
        payload = bytes([candidate]) * 48
        ct = oracle(r, payload)
        blocks = get_blocks(ct)
        # Blocks 0, 1, 2 should be identical
        if len(blocks) >= 3 and blocks[0] == blocks[1] == blocks[2]:
            references[candidate] = blocks[0]
    
    # Now send 1 byte (to maximize padding to 31 bytes)
    # Layout: 1 + 32 = 33 bytes → padded to 64 bytes
    # Block 3 (last block) = 16 bytes of padding
    for candidate in PAD_CANDIDATES:
        if candidate not in references:
            continue
            
        payload = bytes([ord('X')])  # arbitrary single byte
        ct = oracle(r, payload)
        blocks = get_blocks(ct)
        
        if len(blocks) >= 4:
            # Block 3 should be 16 bytes of padding
            if blocks[3] == references[candidate]:
                log.success(f"Found padding character (alt): '{chr(candidate)}' (0x{candidate:02x})")
                return candidate
    
    raise RuntimeError("Could not determine padding character with any method")


# =============================================================================
# Byte-at-a-Time Attack
# =============================================================================
def recover_flag(r, pad_char: int) -> bytes:
    """
    Recover the flag one byte at a time using ECB oracle attack.
    
    For each byte position i in the flag:
    1. Calculate prefix length to align flag[i] at block boundary
    2. Get reference ciphertext with unknown byte at that position  
    3. Brute-force all 256 possible byte values
    4. Match indicates correct guess
    
    Args:
        r: pwntools connection
        pad_char: the padding character (for potential optimization)
    
    Returns:
        bytes: the recovered flag
    """
    flag = b""
    
    log.info(f"Starting byte-at-a-time attack (expecting {FLAG_LEN} bytes)...")
    
    for i in range(FLAG_LEN):
        found = False
        
        # Calculate prefix length to put flag[i] at end of a block
        # We want: len(prefix) + i ≡ BLOCK_SIZE - 1 (mod BLOCK_SIZE)
        # Therefore: prefix_len = (BLOCK_SIZE - 1 - i) % BLOCK_SIZE
        prefix_len = (BLOCK_SIZE - 1 - i) % BLOCK_SIZE
        
        # Determine which block contains our target byte
        # Target block index = (prefix_len + i) // BLOCK_SIZE
        target_block_idx = (prefix_len + i) // BLOCK_SIZE
        
        # Create prefix (using 'A' as our known byte)
        prefix = b'A' * prefix_len
        
        # Get reference ciphertext
        # Plaintext: prefix + FLAG → block[target_block_idx] contains prefix + flag[0:?] + flag[i]
        ct_ref = oracle(r, prefix)
        blocks_ref = get_blocks(ct_ref)
        
        if target_block_idx >= len(blocks_ref):
            log.error(f"Target block {target_block_idx} out of range (got {len(blocks_ref)} blocks)")
            break
        
        target_block = blocks_ref[target_block_idx]
        
        # Try all possible byte values (printable ASCII first for efficiency)
        # Prioritize printable characters since flags are usually printable
        candidates = list(range(32, 127)) + list(range(0, 32)) + list(range(127, 256))
        
        for guess in candidates:
            # Construct test payload: prefix + known_flag + guess_byte
            test_payload = prefix + flag + bytes([guess])
            
            # Get ciphertext for test
            # Plaintext: (prefix + known_flag + guess) + FLAG + padding
            ct_test = oracle(r, test_payload)
            blocks_test = get_blocks(ct_test)
            
            # Compare target block
            if target_block_idx < len(blocks_test) and blocks_test[target_block_idx] == target_block:
                flag += bytes([guess])
                
                # Progress display
                char_display = chr(guess) if 32 <= guess < 127 else f"\\x{guess:02x}"
                log.info(f"[{i+1:2d}/{FLAG_LEN}] Found byte: '{char_display}' → {flag.decode('latin-1', errors='replace')}")
                
                found = True
                break
        
        if not found:
            log.error(f"Could not find byte at position {i}")
            log.warning(f"Partial flag recovered: {flag}")
            break
    
    return flag


# =============================================================================
# Verification
# =============================================================================
def verify_known_prefix(flag: bytes) -> bool:
    """Verify that the recovered flag starts with the expected prefix."""
    if flag.startswith(KNOWN_PREFIX):
        log.success(f"Flag prefix verified: starts with '{KNOWN_PREFIX.decode()}'")
        return True
    else:
        log.warning(f"Flag prefix mismatch! Expected '{KNOWN_PREFIX.decode()}', got '{flag[:len(KNOWN_PREFIX)]}'")
        return False


# =============================================================================
# Main
# =============================================================================
def main():
    log.info("=" * 60)
    log.info("ECBeast Solver - ECB Byte-at-a-Time Oracle Attack")
    log.info("=" * 60)
    
    # Connect to challenge
    r = connect()
    
    try:
        # Skip banner
        log.info("Waiting for banner...")
        r.recvuntil(b"=========================================\n\n", timeout=10)
        log.success("Connected to oracle")
        
        # Step 1: Discover padding character
        pad_char = find_padding_char(r)
        
        # Step 2: Recover flag byte by byte
        flag = recover_flag(r, pad_char)
        
        # Step 3: Verify and display result
        log.info("=" * 60)
        if len(flag) == FLAG_LEN:
            verify_known_prefix(flag)
            log.success(f"FLAG: {flag.decode('latin-1', errors='replace')}")
        else:
            log.warning(f"Incomplete flag ({len(flag)}/{FLAG_LEN} bytes): {flag}")
        log.info("=" * 60)
        
        return flag
        
    except Exception as e:
        log.error(f"Attack failed: {e}")
        import traceback
        traceback.print_exc()
        return None
        
    finally:
        r.close()


if __name__ == "__main__":
    main()