#!/usr/bin/env python3
import hashlib
import json
import random
from pathlib import Path

STATE_BITS = 48
OUT_BITS = 24
ROWS_PER_AUDIT = 6
TARGET_AUDIT_RANK = 36

PUBLIC_MQ_SEED = 0xC0FFEE_F00D_BAAD
PUBLIC_AUDIT_SEED = 0xDEC0DE

MODULUS_N = 0x7D6D7848F8DBFB93B6134641E13333D383D5BD7AFB9F26F1
PUBLIC_EXPONENT_E = 11

MASK = (1 << STATE_BITS) - 1


def gf2_rank(rows: list[int], nbits: int = STATE_BITS) -> int:
    rows = [row for row in rows if row]
    rank = 0
    work = rows[:]
    for bit in range(nbits - 1, -1, -1):
        pivot_idx = None
        for i, row in enumerate(work):
            if (row >> bit) & 1:
                pivot_idx = i
                break
        if pivot_idx is None:
            continue
        pivot = work.pop(pivot_idx)
        reduced = []
        for row in work:
            if (row >> bit) & 1:
                row ^= pivot
            if row:
                reduced.append(row)
        work = reduced
        rank += 1
    return rank


def build_public_params() -> dict:
    rng = random.Random(PUBLIC_MQ_SEED)

    quadratic_terms: list[list[tuple[int, int]]] = []
    linear_masks: list[int] = []
    constant_bits: list[int] = []

    for _ in range(STATE_BITS):
        terms: set[tuple[int, int]] = set()
        while len(terms) < 12:
            a, b = sorted(rng.sample(range(STATE_BITS), 2))
            terms.add((a, b))
        quadratic_terms.append(sorted(terms))

        linear_mask = 0
        for idx in rng.sample(range(STATE_BITS), 7):
            linear_mask ^= 1 << idx
        linear_masks.append(linear_mask)
        constant_bits.append(rng.getrandbits(1))

    audit_rng = random.Random(PUBLIC_AUDIT_SEED)
    audit_masks: list[int] = []
    audit_projections: list[list[int]] = []
    accumulated_equations: list[int] = []

    def derivative_matrix_for_mask(mask: int) -> list[int]:
        rows: list[int] = []
        for bit_terms in quadratic_terms:
            row = 0
            for a, b in bit_terms:
                if (mask >> b) & 1:
                    row ^= 1 << a
                if (mask >> a) & 1:
                    row ^= 1 << b
            rows.append(row)
        return rows

    while len(accumulated_equations) < TARGET_AUDIT_RANK:
        while True:
            audit_mask = 0
            for idx in audit_rng.sample(range(STATE_BITS), 12):
                audit_mask ^= 1 << idx
            if audit_mask not in audit_masks:
                break

        matrix_rows = derivative_matrix_for_mask(audit_mask)
        projections_for_mask: list[int] = []

        while len(projections_for_mask) < ROWS_PER_AUDIT:
            projection = 0
            for idx in audit_rng.sample(range(STATE_BITS), 10):
                projection ^= 1 << idx

            equation = 0
            for j, row in enumerate(matrix_rows):
                if (projection >> j) & 1:
                    equation ^= row

            if equation and gf2_rank(accumulated_equations + [equation]) > gf2_rank(accumulated_equations):
                projections_for_mask.append(projection)
                accumulated_equations.append(equation)

        audit_masks.append(audit_mask)
        audit_projections.append(projections_for_mask)

    return {
        "quadratic_terms": quadratic_terms,
        "linear_masks": linear_masks,
        "constant_bits": constant_bits,
        "audit_masks": audit_masks,
        "audit_projections": audit_projections,
    }


def apply_mq(state: int, params: dict) -> int:
    out = 0
    for j in range(STATE_BITS):
        bit = params["constant_bits"][j] ^ ((state & params["linear_masks"][j]).bit_count() & 1)
        for a, b in params["quadratic_terms"][j]:
            bit ^= ((state >> a) & 1) & ((state >> b) & 1)
        out |= bit << j
    return out


def derivative_value(state: int, mask: int, params: dict) -> int:
    return (
        apply_mq(state ^ mask, params)
        ^ apply_mq(state, params)
        ^ apply_mq(mask, params)
        ^ apply_mq(0, params)
    )


def rotl(x: int, r: int) -> int:
    return ((x << r) & MASK) | (x >> (STATE_BITS - r))


def diffuse(x: int) -> int:
    return x ^ rotl(x, 7) ^ rotl(x, 13)


def next_state(state: int, params: dict) -> int:
    return diffuse(apply_mq(state, params))


def ms_project(state: int) -> int:
    message = (state << 1) | 1
    return pow(message, PUBLIC_EXPONENT_E, MODULUS_N)


def truncated_output(state: int) -> int:
    return ms_project(state) & ((1 << OUT_BITS) - 1)


def derive_secret_seed(flag: bytes) -> int:
    digest = hashlib.sha256(flag + b"|boot-seed").digest()
    return int.from_bytes(digest[: STATE_BITS // 8], "big") & MASK


def keystream(seed: int, size: int, params: dict, skip_rounds: int = 3) -> bytes:
    buf = bytearray()
    state = seed
    round_idx = 0

    while len(buf) < size:
        state = next_state(state, params)
        z = ms_project(state)

        if round_idx >= skip_rounds:
            block = hashlib.sha256(
                z.to_bytes((MODULUS_N.bit_length() + 7) // 8, "big")
                + round_idx.to_bytes(2, "big")
            ).digest()
            buf.extend(block)

        round_idx += 1

    return bytes(buf[:size])


def emit_public_instance(flag: bytes) -> dict:
    params = build_public_params()
    seed = derive_secret_seed(flag)

    audit_tags: list[int] = []
    for mask, projections in zip(params["audit_masks"], params["audit_projections"]):
        deriv = derivative_value(seed, mask, params)
        packed_tag = 0
        for i, projection in enumerate(projections):
            packed_tag |= ((deriv & projection).bit_count() & 1) << i
        audit_tags.append(packed_tag)

    filter_outputs: list[int] = []
    state = seed
    for _ in range(3):
        state = next_state(state, params)
        filter_outputs.append(truncated_output(state))

    stream = keystream(seed, len(flag), params, skip_rounds=3)
    ciphertext = bytes(a ^ b for a, b in zip(flag, stream))

    return {
        "state_bits": STATE_BITS,
        "out_bits": OUT_BITS,
        "modulus_n": hex(MODULUS_N),
        "public_exponent_e": PUBLIC_EXPONENT_E,
        "audit_rows_per_mask": ROWS_PER_AUDIT,
        "audit_masks": [hex(x) for x in params["audit_masks"]],
        "audit_projections": [[hex(x) for x in row] for row in params["audit_projections"]],
        "audit_tags": [hex(x) for x in audit_tags],
        "filter_outputs": [hex(x) for x in filter_outputs],
        "ciphertext": ciphertext.hex(),
    }


def main() -> None:
    flag_path = Path("flag.txt")
    output_path = Path("output.txt")

    flag = flag_path.read_bytes().strip()
    instance = emit_public_instance(flag)
    output_path.write_text(json.dumps(instance, indent=2) + "\n")


if __name__ == "__main__":
    main()
