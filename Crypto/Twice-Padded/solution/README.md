---
title: Twice Padded
summary:


---

## Challenge overview

The challenge encrypts **two different plaintext messages using the same OTP keystream**. This completely defeats the purpose of a **one**-time-pad. The key must be used exactly once. In this case:

$$
\begin{aligned}
c_1 &= p_1 \oplus k \\
c_2 &= p_2 \oplus k
\end{aligned}
$$

### Key Observation

Simply XOR the two ciphertexts together, and the keystream cancels out:

$$
c_1 \oplus c_2 = (p_1 \oplus k) \oplus (p_2 \oplus k) = p_1 \oplus p_2
$$

### Keystream Recovery

Since `msg1` is known, we can simply recover the keysteam for the entire length of msg1:

$$
k = c_1 \oplus p_1
$$

This gives us the exact OTP keystream bytes used to decrypt `msg1`. To get the flag from here, we simply use the same keystream starting at position 0, and decrypt the second message.

$$
p_2 = c_2 \oplus k
$$

#### Solution output + source code

- **Solution source code**

```python
#!/usr/bin/env python3
import re
from pathlib import Path
from pwn import xor
# can use pwnlib's xor function instead of defining our own
'''
def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))
'''
def parse_output(path="output.txt"):
    text = Path(path).read_text().strip().splitlines()
    kv = {}
    for line in text:
        if "=" in line:
            k, v = line.split("=", 1)
            kv[k.strip()] = v.strip()
    if "c1" not in kv or "c2" not in kv:
        raise ValueError("output.txt must contain lines like c1=<hex> and c2=<hex>")
    return bytes.fromhex(kv["c1"]), bytes.fromhex(kv["c2"])

def solve():
    c1, c2 = parse_output("output.txt")

    # MUST match chal.py exactly
    msg1 = (
        b"From: admin@company.internal\n"
        b"To: ops@company.internal\n"
        b"Subject: deployment status\n\n"
        b"All services are online. No action required at this time.\n"
    )

    key_prefix = xor(c1, msg1)    
    msg2_prefix = xor(c2, key_prefix)
    print("[+] Decrypted msg2 prefix:\n")
    print(msg2_prefix.decode(errors="replace"))
    m = re.search(rb"(GRIZZ\{[A-Za-z]+\})", msg2_prefix)
    if m:
        print("\n[+] FLAG:", m.group(1).decode())
        return
if __name__ == "__main__":
    solve()
```

- **Output**
```python
python solve.py
[+] Decrypted msg2 prefix:

From: ops@company.internal
To: admin@company.internal
Subject: re: deployment status

Audit reference: GRIZZ{tw0_t1me_p4d_12_s1lly_y4_kn0w}
```
