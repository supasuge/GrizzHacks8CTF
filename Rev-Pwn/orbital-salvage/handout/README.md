# Handout

Distribute the following to players after building:

- `orbital-salvage` — stripped release binary
- `challenge.txt` — prompt text

## Build the binary for handout

From the project root:

```bash
make handout
```

This copies the stripped binary into `handout/orbital-salvage`.

## Suggested prompt

A recovery node from a dead orbital tug is still broadcasting. The guidance computer is gone, but eight truncated PRNG state samples survived in the telemetry buffer. Recover the operator token.
