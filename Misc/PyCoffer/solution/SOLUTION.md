# PyCoffer Solution Writeup

- Difficulty: Hard (500 Points)
- Author: [supasuge](https://github.com/supasuge) | [Evan Pardon](https://linkedin.com/in/evan-pardon)

The sandbox blocks all the usual escape vectors (imports, `__class__`, `__subclasses__`, `exec`, `eval`, etc.) with regex patterns and AST inspection. However, it exposes `FunctionType` and `CodeType` from the `types` module.

**The exploit:**

1. **Build forbidden attribute names dynamically** using `chr(95)` for underscores
2. **Create raw Python bytecode** that traverses `().__class__.__bases__[0].__subclasses__()`
3. **The key insight:** Bytecode references attribute names by **numeric index** into `co_names`, not by string - so the regex never sees `__class__` in the source!
4. Iterate subclasses to find one with `__builtins__` access
5. Extract `open()` and read the flag

## How it works

While the `__class__.__mro__.__subclasses__()` chain is well-known, **directly crafting bytecode to bypass string filters** is a more advanced technique. Most techniques simply involve:

- Unicode tricks
- Format string exploits  
- Attribute name obfuscation