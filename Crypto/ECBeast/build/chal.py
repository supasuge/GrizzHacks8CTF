#!/usr/bin/env python3
import os
import sys
import secrets
from Crypto.Cipher import AES

INTRO = r"""
=========================================
| ANCIENT ARCHIVE ENCRYPTION TERMINAL   |
=========================================
You may submit a scroll fragment.
I will seal it together with the relic.

The relic is ancient.
The cipher is perfect.
Do not embarrass yourself.
=========================================
"""

BLOCK_SIZE = AES.block_size  
PAD_BLOCK = 32   


def read_flag() -> bytes:
    flag_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "flag.txt")
    try:
        with open(flag_path, "rb") as f:
            data = f.read().strip()
            return data
    except FileNotFoundError:
        print("Relic vault corrupted (flag.txt not found). Contact the archivists.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Relic vault corrupted: {e}", file=sys.stderr)
        sys.exit(1)


def pad_plaintext(plaintext: bytes, pad_char: int) -> bytes:
    length = len(plaintext)
    if length % PAD_BLOCK == 0:
        pad_len = PAD_BLOCK
    else:
        pad_len = PAD_BLOCK - (length % PAD_BLOCK)
    return plaintext + bytes([pad_char]) * pad_len


def main():
    flag = read_flag()
    key = secrets.token_bytes(32)
    pad_char = secrets.choice(b"_#@!$%&*")
    cipher = AES.new(key[:16], AES.MODE_ECB)
    sys.stdout.write(INTRO)
    sys.stdout.flush()
    
    while True:
        try:
            sys.stdout.write("Submit your scroll fragment: ")
            sys.stdout.flush()
            user_input = sys.stdin.readline()
            if not user_input:
                break
            user_bytes = user_input.rstrip("\n").encode('latin-1')
            plaintext = user_bytes + flag
            padded_plaintext = pad_plaintext(plaintext, pad_char)
            ciphertext = cipher.encrypt(padded_plaintext)
            sys.stdout.write(f"Sealed scroll (hex):\n{ciphertext.hex()}\n\n")
            sys.stdout.flush()
            
        except KeyboardInterrupt:
            break
        except Exception as e:
            sys.stderr.write(f"Error processing input: {e}\n")
            sys.stderr.flush()
            continue

if __name__ == "__main__":
    main()