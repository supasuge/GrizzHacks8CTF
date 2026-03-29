# Orbital Salvage

A Rust CTF reversing/crypto challenge built around:

- truncated 64-bit LCG state leakage
- AES-256-CBC key derivation from subsequent PRNG state
- weak anti-debug heuristics
- decoy validation and fake crypto material

## Layout

- `src/` — Rust challenge source
- `handout/` — files intended for players
- `solution/` — solver and reference exploit
- `Dockerfile` — network service image
- `Makefile` — local build and packaging targets

## Local build

```bash
cargo build --release
./target/release/orbital-salvage
```

## Docker service

```bash
make docker-build
make docker-run
```

The service listens on `31337/tcp` and prints the truncated PRNG leaks to the client.

## Challenge flow

Players receive a stripped binary and a short prompt. The intended solve path is:

1. Reverse constants and challenge logic from the binary.
2. Recover the exact internal LCG states from the leaked top 48 bits.
3. Derive the AES key from the next PRNG states after the final leak.
4. Decrypt the embedded ciphertext to recover the real token.
5. Submit the token to the service.

## Design note

The primitive is "lattice-flavored" because the service leaks truncated LCG states, but the included reference solve uses Z3 rather than LLL. That is deliberate: it is more deterministic for a reference solver while preserving the exact challenge primitive.
