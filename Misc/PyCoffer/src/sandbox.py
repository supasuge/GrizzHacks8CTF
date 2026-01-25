#!/usr/bin/env python3
import sys
import ast
import types
import re

FLAG = open("flag.txt").read().strip()

class SandboxError(Exception):
    pass

class SecureSandbox:
    BLOCKED_NAMES = {
        'import', 'exec', 'eval', 'compile', 'open', 'file',
        'input', 'raw_input', '__import__', 'execfile',
        'os', 'sys', 'subprocess', 'commands', 'pty', 'posix',
        'builtins', '__builtins__', 'breakpoint', 'help',
        'exit', 'quit', 'license', 'credits', 'copyright',
        'globals', 'locals', 'vars', 'dir', 'getattr', 'setattr',
        'delattr', 'hasattr', 'type', 'super', 'object',
    }

    BLOCKED_PATTERNS = [
        r'__\w+__',
        r'\bimport\b',
        r'\bexec\b',
        r'\beval\b',
        r'\bopen\b',
        r'\bcompile\b',
        r'\.__class__',
        r'\.__base',
        r'\.__subclasses',
        r'\.__mro',
        r'\.__globals',
        r'\.__code',
        r'\.__dict__',
        r'func_',
        r'im_',
    ]

    def __init__(self):
        self.safe_builtins = {
            'int': int,
            'float': float,
            'str': str,
            'bool': bool,
            'list': list,
            'dict': dict,
            'tuple': tuple,
            'set': set,
            'frozenset': frozenset,
            'bytes': bytes,
            'bytearray': bytearray,
            'len': len,
            'range': range,
            'enumerate': enumerate,
            'zip': zip,
            'map': map,
            'filter': filter,
            'sorted': sorted,
            'reversed': reversed,
            'sum': sum,
            'min': min,
            'max': max,
            'abs': abs,
            'round': round,
            'pow': pow,
            'divmod': divmod,
            'hex': hex,
            'oct': oct,
            'bin': bin,
            'chr': chr,
            'ord': ord,
            'repr': repr,
            'ascii': ascii,
            'format': format,
            'print': print,
            'isinstance': isinstance,
            'issubclass': issubclass,
            'callable': callable,
            'iter': iter,
            'next': next,
            'slice': slice,
            'any': any,
            'all': all,
            'True': True,
            'False': False,
            'None': None,
            'Exception': Exception,
            'ValueError': ValueError,
            'TypeError': TypeError,
            'KeyError': KeyError,
            'IndexError': IndexError,
            'AttributeError': AttributeError,
            'StopIteration': StopIteration,
            'FunctionType': types.FunctionType,
            'CodeType': types.CodeType,
        }

    def _check_ast(self, code):
        tree = ast.parse(code)
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                raise SandboxError("Import statements are forbidden")
            if isinstance(node, ast.Name) and node.id in self.BLOCKED_NAMES:
                raise SandboxError(f"Access to '{node.id}' is forbidden")
            if isinstance(node, ast.Attribute) and node.attr in self.BLOCKED_NAMES:
                raise SandboxError(f"Attribute '{node.attr}' is forbidden")
        return tree

    def _check_patterns(self, code):
        for pattern in self.BLOCKED_PATTERNS:
            if re.search(pattern, code):
                raise SandboxError("Forbidden pattern detected")

    def execute(self, code):
        self._check_patterns(code)
        self._check_ast(code)
        namespace = {'__builtins__': self.safe_builtins}
        exec(compile(code, '<sandbox>', 'exec'), namespace)
        return namespace


def main():
    print("PyCoffer Sandbox")
    print("Read the flag from flag.txt\n")
    sandbox = SecureSandbox()

    while True:
        print("[src | <python code>\\nEND | exit]\n>>> ", end="", flush=True)
        lines = []

        try:
            while True:
                line = input()
                if line.strip() == "END":
                    break
                if line.strip() == "src":
                    print(open(__file__).read())
                    lines = []
                    break
                if line.strip() == "exit":
                    return
                lines.append(line)
        except EOFError:
            return

        code = "\n".join(lines).strip()
        if not code:
            continue

        try:
            sandbox.execute(code)
        except SandboxError as e:
            print(f"Sandbox violation: {e}")
        except Exception as e:
            print(f"Runtime error: {type(e).__name__}: {e}")
        print()


if __name__ == "__main__":
    main()
