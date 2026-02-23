#!/usr/bin/env python3
from __future__ import annotations

import argparse
import string
from PIL import Image

FLAG_FORMAT = "GRIZZ{STEGO_BACON_LAYERED}"
ALPHA = string.ascii_uppercase

def bacon_encode_letters_only(text: str) -> str:
    bits = ""
    for c in text.upper():
        if c in ALPHA:
            bits += format(ord(c) - ord("A"), "05b")
    return bits

def expected_embedded_bitlen() -> int:
    pre_bits = bacon_encode_letters_only(FLAG_FORMAT)
    return ((len(pre_bits) + 7) // 8) * 8  # padded to multiple of 8

def extract_embedded_bits(img: Image.Image, bitlen: int, mod: int = 7, channel: str = "b", verbose: bool = False) -> str:
    px = img.load()
    w, h = img.width, img.height
    ch_i = {"r": 0, "g": 1, "b": 2}[channel]

    bits = []
    eligible_seen = 0

    for x in range(w):
        for y in range(h):
            r, g, b = px[x, y]

            # ✅ must match generator predicate
            if (r + g + (b & 0xFE)) % mod == 0:
                eligible_seen += 1
                bits.append(str(px[x, y][ch_i] & 1))
                if len(bits) >= bitlen:
                    if verbose:
                        print(f"[dbg] Extracted {len(bits)} bits after scanning {eligible_seen} eligible pixels.")
                    return "".join(bits)

    raise RuntimeError(f"Not enough eligible pixels to extract {bitlen} bits (got {len(bits)}).")

def bits_to_bytes(bits: str) -> bytes:
    if len(bits) % 8 != 0:
        raise ValueError("bit length must be multiple of 8")
    return bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))

def bytes_to_bits(data: bytes) -> str:
    return "".join(format(b, "08b") for b in data)

def bacon_decode(bits: str) -> str:
    out = []
    for i in range(0, len(bits), 5):
        chunk = bits[i:i+5]
        if len(chunk) < 5:
            break
        v = int(chunk, 2)
        if 0 <= v < 26:
            out.append(chr(v + ord("A")))
    return "".join(out)

def reconstruct_flag(letters: str) -> str:
    # bacon removed braces/underscores; restore canonical format if it matches expected letters-only
    expected = "".join(c for c in FLAG_FORMAT.upper() if c in ALPHA)
    if letters.startswith(expected):
        return FLAG_FORMAT
    return letters

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("image", help="challenge.png")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--mod", type=int, default=7)
    ap.add_argument("--channel", choices=["r", "g", "b"], default="b")
    args = ap.parse_args()

    img = Image.open(args.image).convert("RGB")
    bitlen = expected_embedded_bitlen()

    if args.verbose:
        pre_bits = bacon_encode_letters_only(FLAG_FORMAT)
        print(f"[dbg] Bacon bit length: {len(pre_bits)}")
        print(f"[dbg] Embedded/padded bit length: {bitlen}")

    raw_bits = extract_embedded_bits(img, bitlen, mod=args.mod, channel=args.channel, verbose=args.verbose)
    cipher_bytes = bits_to_bytes(raw_bits)

    if args.verbose:
        print(f"[dbg] Cipher bytes hex: {cipher_bytes.hex()}")

    for key in range(256):
        plain_bytes = bytes(b ^ key for b in cipher_bytes)
        plain_bits = bytes_to_bits(plain_bytes)

        letters = bacon_decode(plain_bits)
        if letters.startswith("GRIZZ"):
            print(f"[+] XOR_KEY={key} (0x{key:02x})")
            print(f"[+] Letters: {letters}")
            print(f"[+] Flag: {reconstruct_flag(letters)}")
            return 0

    print("[-] No key produced plaintext starting with GRIZZ. Check generator/predicate/channel/mod.")
    return 1

if __name__ == "__main__":
    raise SystemExit(main())