#!/usr/bin/env python3

import string

def bacon_encode(text):
    result = ""
    for c in text.upper():
        if c in string.ascii_uppercase:
            val = ord(c) - ord('A')
            result += format(val, "05b")
    return result

def bits_to_symbols(bits):
    return bits.replace("0", ".").replace("1", "-")

def rotate_left(s, n):
    return s[n:] + s[:n]

if __name__ == "__main__":
    flag = "GRIZZ{BACON_IS_BACK}"
    shift = 3

    bits = bacon_encode(flag)
    symbols = bits_to_symbols(bits)
    rotated = rotate_left(symbols, shift)

    print("Ciphertext:")
    print(rotated)