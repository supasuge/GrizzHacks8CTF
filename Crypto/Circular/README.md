# Circulant Cipher (NTT Edition)

> *A linear cipher pretending to be cryptography.*
> *Spoiler: linear algebra always snitches.*

---

## Handout files for challenge participants

- `handout/circular-handout.tar.xz`, Contains:
  - `flag.example.txt`: Example flag format for local testing
  - `output.txt`: Challenge output of encrypted known plaintext + flag ciphertext
  - `chal.py`: Circulant cipher implementation for participants.

## Overview

This challenge implements a **circulant-matrix–based encryption scheme** over a finite field using an exact **Number Theoretic Transform (NTT)**.

```
.
├── src/chal.py            # Encryption + flag generation
├── solution/solver.py      # Intended solution
├── src/flag.txt            # Secret flag
├── handout/circular-handout.tar.xz # handout for participants
```

### Flag Format

```txt
GRIZZ{........}
```