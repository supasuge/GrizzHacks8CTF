#!/usr/bin/env python3

import string

def rotate_right(s, n):
    return s[-n:] + s[:-n]

def symbols_to_bits(s):
    return s.replace(".", "0").replace("-", "1")

def bacon_decode(bits):
    result = ""
    for i in range(0, len(bits), 5):
        chunk = bits[i:i+5]
        if len(chunk) < 5:
            continue
        val = int(chunk, 2)
        if 0 <= val < 26:
            result += chr(val + ord('A'))
    return result

ciphertext = "-.-...-.-...--..---..-....-........-..---..--.-.-...-..-.....-........-..-.-...-"

for shift in range(5):
    candidate = rotate_right(ciphertext, shift)
    bits = symbols_to_bits(candidate)
    decoded = bacon_decode(bits)

    if decoded.startswith("GRIZZ"):
        print("Shift:", shift)
        print("Flag:", decoded)
        break