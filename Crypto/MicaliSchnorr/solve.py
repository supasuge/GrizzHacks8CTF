#!/usr/bin/env python3
import json
import sys
from pathlib import Path

import chal


def derivative_matrix_for_mask(mask: int, params: dict) -> list[int]:
    rows: list[int] = []
    for bit_terms in params["quadratic_terms"]:
        row = 0
        for a, b in bit_terms:
            if (mask >> b) & 1:
                row ^= 1 << a
            if (mask >> a) & 1:
                row ^= 1 << b
        rows.append(row)
    return rows


def projected_equation(mask: int, projection: int, params: dict) -> int:
    equation = 0
    for bit_index, row in enumerate(derivative_matrix_for_mask(mask, params)):
        if (projection >> bit_index) & 1:
            equation ^= row
    return equation


def solve_affine_system(rows: list[int], rhs: list[int], nbits: int) -> tuple[int, list[int]]:
    rows = rows[:]
    rhs = rhs[:]
    where = [-1] * nbits
    pivot_row = 0

    for bit in range(nbits - 1, -1, -1):
        pivot = None
        for r in range(pivot_row, len(rows)):
            if (rows[r] >> bit) & 1:
                pivot = r
                break
        if pivot is None:
            continue

        rows[pivot_row], rows[pivot] = rows[pivot], rows[pivot_row]
        rhs[pivot_row], rhs[pivot] = rhs[pivot], rhs[pivot_row]

        pivot_value = rows[pivot_row]
        for r in range(len(rows)):
            if r != pivot_row and ((rows[r] >> bit) & 1):
                rows[r] ^= pivot_value
                rhs[r] ^= rhs[pivot_row]

        where[bit] = pivot_row
        pivot_row += 1
        if pivot_row == len(rows):
            break

    for r in range(pivot_row, len(rows)):
        if rows[r] == 0 and rhs[r]:
            raise ValueError("inconsistent linear system")

    base_solution = 0
    for bit in range(nbits):
        if where[bit] != -1 and rhs[where[bit]]:
            base_solution |= 1 << bit

    free_bits = [bit for bit in range(nbits) if where[bit] == -1]
    nullspace_basis: list[int] = []

    for free_bit in free_bits:
        vector = 1 << free_bit
        for bit in range(nbits):
            row_index = where[bit]
            if row_index != -1 and ((rows[row_index] >> free_bit) & 1):
                vector |= 1 << bit
        nullspace_basis.append(vector)

    return base_solution, nullspace_basis


def enumerate_candidates(base_solution: int, basis: list[int]):
    count = 1 << len(basis)
    for mask in range(count):
        candidate = base_solution
        for i, vec in enumerate(basis):
            if (mask >> i) & 1:
                candidate ^= vec
        yield candidate


def first_filter_outputs(seed: int, params: dict, count: int) -> list[int]:
    state = seed
    outs: list[int] = []
    for _ in range(count):
        state = chal.next_state(state, params)
        outs.append(chal.truncated_output(state))
    return outs


def recover_seed(public_data: dict) -> int:
    params = chal.build_public_params()

    audit_masks = [int(x, 16) for x in public_data["audit_masks"]]
    audit_projections = [[int(x, 16) for x in row] for row in public_data["audit_projections"]]
    audit_tags = [int(x, 16) for x in public_data["audit_tags"]]
    expected_filter = [int(x, 16) for x in public_data["filter_outputs"]]

    rows: list[int] = []
    rhs: list[int] = []

    for mask, projections, tag in zip(audit_masks, audit_projections, audit_tags):
        for bit_index, projection in enumerate(projections):
            rows.append(projected_equation(mask, projection, params))
            rhs.append((tag >> bit_index) & 1)

    base_solution, basis = solve_affine_system(rows, rhs, chal.STATE_BITS)

    matches: list[int] = []
    for candidate in enumerate_candidates(base_solution, basis):
        if first_filter_outputs(candidate, params, len(expected_filter)) == expected_filter:
            matches.append(candidate)

    if len(matches) != 1:
        raise ValueError(f"expected exactly one seed, got {len(matches)}")

    return matches[0]


def main() -> None:
    output_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("output.txt")
    public_data = json.loads(output_path.read_text())

    seed = recover_seed(public_data)
    params = chal.build_public_params()

    ciphertext = bytes.fromhex(public_data["ciphertext"])
    stream = chal.keystream(seed, len(ciphertext), params, skip_rounds=3)
    flag = bytes(a ^ b for a, b in zip(ciphertext, stream))

    print(flag.decode())


if __name__ == "__main__":
    main()
