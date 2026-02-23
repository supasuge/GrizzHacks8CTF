#!/usr/bin/env python3

from PIL import Image
import random
import string

FLAG = open("flag.txt").read().strip()
XOR_KEY = random.randint(0, 255)
WIDTH, HEIGHT = 400, 400

def bacon_encode(text):
    bits = ""
    for c in text.upper():
        if c in string.ascii_uppercase:
            val = ord(c) - ord('A')
            bits += format(val, "05b")
    return bits

def xor_bits(bits, key):
    result = ""
    for i in range(0, len(bits), 8):
        byte = bits[i:i+8]
        if len(byte) < 8:
            byte = byte.ljust(8, "0")
        val = int(byte, 2) ^ key
        result += format(val, "08b")
    return result

def embed():
    img = Image.new("RGB", (WIDTH, HEIGHT))
    pixels = img.load()
    for x in range(WIDTH):
        for y in range(HEIGHT):
            pixels[x, y] = (
                random.randint(0,255),
                random.randint(0,255),
                random.randint(0,255),
            )
    bits = bacon_encode(FLAG)
    bits = xor_bits(bits, XOR_KEY)
    bit_index = 0
    for x in range(WIDTH):
        for y in range(HEIGHT):
            if bit_index >= len(bits):
                break
            r, g, b = pixels[x, y]
            if (r + g + (b & 0xFE)) % 7 == 0:
                b = (b & ~1) | int(bits[bit_index])
                pixels[x, y] = (r, g, b)
                bit_index += 1

    img.save("challenge.png")
    print("challenge.png generated.")

if __name__ == "__main__":
    embed()