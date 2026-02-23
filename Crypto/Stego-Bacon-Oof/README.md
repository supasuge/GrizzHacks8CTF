# 🥓 Bacon Steg... Oof

## Difficulty

Hard (Steganography + Classical Crypto)

## Flag Format

`GRIZZ....`

- `{` and `}` are omitted from this challenge...

---

## Description

You’ve been served something crispy.

An innocent-looking PNG image has been recovered from an internal system. No obvious strings. No suspicious metadata. Nothing visible to the naked eye.

But someone clearly hid something inside.

The challenge combines:

- Image steganography  
- Selective LSB extraction  
- XOR obfuscation  
- A modified Baconian cipher  

---

## What You’re Given (handout)

```
handout/challenge.png
```

## Technical Overview (Without Spoiling It)

The hidden data is:

1. Embedded inside the image using LSB steganography  
2. Only inside specific pixels meeting a mathematical condition  
3. XOR-obfuscated with a small key  
4. Encoded using a classical cipher  

Each layer is individually simple.  
Together? Slightly annoying.

---

## Intended Learning Objectives

This challenge tests your ability to:

- Identify steganographic LSB patterns
- Reverse engineer pixel-selection predicates
- Extract controlled bitstreams from images
- Brute force small XOR keys
- Decode classical binary encodings
- Handle layered transformations cleanly

This is not a brute-force-the-image-with-strings challenge.

You must understand what you're extracting.

---

## Recommended Approach

1. Analyze pixel distributions.
2. Determine how bits are selected.
3. Reconstruct the hidden bitstream.
4. Reverse any XOR transformation.
5. Decode the classical cipher.
6. Reconstruct the original flag.

If you find yourself decoding thousands of bytes of garbage — you are probably extracting too much.

---

## Notes

- The payload is small.
- The encoding is deterministic.
- The key space is intentionally limited.
- If your decode looks almost right, you're close.

---

## Final Words/Hints

It’s bacon. It’s steg. It’s layered... brain pain.

Good luck

---