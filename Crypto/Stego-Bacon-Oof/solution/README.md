# 🥓 Bacon Steg… Oof — Solution Writeup

## Challenge Summary

This challenge combines:

- Selective LSB steganography
- XOR obfuscation
- Classical Baconian encoding

The provided file:

`challenge.png`


contains a hidden payload embedded at the bit level.

The flag format is:

`GRIZZ......`


The XOR key used during generation is **randomized per challenge instance**, meaning it must be brute-forced.

---

# SStep 1 — Understanding the Embedding Method

The generator embeds data as follows:

1. The flag is first transformed using a Baconian cipher:
   - Each letter A–Z is encoded into a 5-bit binary value.
   - Non-letter characters (such as `{`, `}`, `_`) are ignored during encoding.

2. The resulting bitstream is grouped into bytes and XOR’d with a single-byte key.
   - The XOR key is randomized at generation time.
   - Key space: 0–255 (trivial brute-force range).

3. The XOR’d bitstream is embedded into the image:
   - Only pixels where `(R + G + B) % 7 == 0`
   - The least significant bit of the **blue channel**
   - Bits are embedded sequentially in scan order (x, then y)

The embedded payload is very small (only the encoded flag).

---

# SStep 2 — Extracting the Bitstream

To recover the payload:

1. Iterate through every pixel in the image.
2. Select only those where:

```python
(r + g + b) % 7 == 0
```

> This must match the generator logic, which isn't given to the challenge participant although the hints should provide enough information that it's a LSB Steg challenge with a bit of a "Twist" so-to-speak.

3. From each eligible pixel, extract:

```python
blue_channel & 1
```

4. Collect bits until you have enough to reconstruct the embedded payload.

Because the payload size is deterministic, you should extract only the number of bits required to encode the Baconian flag (after XOR padding).

If you extract thousands of bits, you are likely decoding noise.

---

# Step 3 — Brute-Forcing the XOR Key

The extracted bytes are XOR’d with a single-byte key.

Because the key is randomized but only 1 byte there is 256 possible keys.

For each key we use a `crib dragging` technique:

- XOR the ciphertext bytes with the candidate key
- Convert the result back to a bitstream
- Decode the 5-bit groups using the Baconian mapping
- Check if the text begins with `GRIZZ`.

The correct key will immediately produce a readable plaintext beginning with `GRIZZ`.

---

# Step 4 — Baconian Decoding

The Baconian cipher maps:

```
A = 00000
B = 00001
...
Z = 11001
```


Decoding is done in 5-bit chunks.

Note:
Because only letters A–Z are encoded, special characters (`{}`, `_`) are removed during encoding.

Once decoded, reconstruct the full flag format:

`GRIZZ{STEGO_BACON_LAYERED}`

---

# Automated Solver Overview

The provided solver script performs:

- LSB extraction from eligible pixels
- Bitstream reconstruction
- XOR brute-force (0–255)
- Baconian decode
- Prefix validation (`GRIZZ`)
- Flag reconstruction

Solve time is effectively instant.

---

## Intended Takeaways

This challenge demonstrates:

- Why steganography must use stable pixel predicates
- How layered encoding can appear complex but remain reversible
- How known plaintext (a flag prefix) makes brute-force practical
- How XOR obfuscation is weak when the keyspace is small
- How classical ciphers can be hidden inside modern formats

---

### Common Mistakes

1. Extracting all LSBs instead of only eligible pixels.
2. Ignoring the pixel selection condition.
3. Attempting to decode before XOR removal.
4. Not limiting extraction to the actual payload length.
5. Expecting `{}` and `_` to appear directly in Bacon output.

---

#### Final Result

After correct extraction and key recovery:

```
GRIZZ{STEGO_BACON_LAYERED}
```