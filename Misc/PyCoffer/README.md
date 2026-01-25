# PyCoffer

- Category: Misc
- Difficulty: Hard
- Requirements/Hints: Requires python3.14
    - May be possible without, though bytecode is interpreted differently in python3.14.

## Building the challenge container

```bash
cd src && docker build -t pycoffer:latest .
```

## Running the challenge container

```bash
docker run -d --rm -p 1337:1337 pycoffer:latest
```

### Flag format

```
GRIZZ{.....}
```