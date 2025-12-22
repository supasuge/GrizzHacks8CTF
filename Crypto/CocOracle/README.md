# CocOracle
- **Author: [supasuge](https://github.com/supasuge) | [Evan Pardon](https://linkedin.com/in/evan-pardon)** 
- **Category:** Crypto
- **Difficulty:** {Easy | Medium | Hard | Expert} - TBD
- **Flag Format:** `GrizzCTF{...}`

## Description

5-round implementation of COCONUT98 with an encryption oracle to facilitate a [Boomerang Attack](https://link.springer.com/content/pdf/10.1007/3-540-48519-8_12.pdf)()
- Rounds were reduced so that not as many oracle queries are needed for plaintext recovery.
  

## Build Instructions

```bash
cd build
docker build -t coco-oracle .
```

## Running

```bash
docker run --rm -p 1347:1347 coco-oracle
```

### Solution

See: `../solution/solve.py`


Proof of Concept/Verification:

```bash
:: Crypto/CocOracle/solution » python solve.py remote localhost 1347
[+] Opening connection to localhost on port 1347: Done
[+] Starting challenge
[Δ0] in=(0, 1) out=(2416447489, 1208221952)
[Δ1] in=(1, 0) out=(9437200, 4718593)
[Δ2] in=(2147483648, 65536) out=(273256448, 2166638596)
[+] Brute-forcing last round key k4
[+] KEY FOUND
[+] Round keys: [8, 4, 31, 20, 31]
[+] Flag: GrizzCTF{cocnut98_differentials_are_deterministic}
[*] Closed connection to localhost port 1347
```

Writeup... another time.