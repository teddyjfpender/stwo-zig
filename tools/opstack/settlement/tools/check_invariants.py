"""Discharge local bit-vector invariants used by the Solidity verifier."""

from z3 import (
    ULE,
    ULT,
    BitVec,
    BitVecVal,
    Concat,
    Extract,
    Int,
    LShR,
    Or,
    RotateRight,
    Solver,
    ZeroExt,
    unsat,
)


def prove(name, assumptions, violation):
    solver = Solver()
    solver.set(timeout=10_000)
    solver.add(*assumptions, violation)
    outcome = solver.check()
    if outcome != unsat:
        raise AssertionError(f"{name}: expected unsat, got {outcome}")
    print(f"PASS {name}")


def lane(value, index):
    return Extract(64 * index + 31, 64 * index, value)


def check_packed_blake():
    lanes = [[BitVec(f"x_{group}_{i}", 32) for i in range(4)] for group in range(3)]
    a, b, c = (
        Concat(*(ZeroExt(32, word) for word in reversed(group))) for group in lanes
    )
    mask = BitVecVal(int("00000000ffffffff" * 4, 16), 256)
    for operands, result in ((2, a + b), (3, a + b + c)):
        prove(
            f"packed add of {operands} words is lane-local",
            [],
            Or(
                *(
                    lane(result & mask, i)
                    != sum(group[i] for group in lanes[:operands])
                    for i in range(4)
                )
            ),
        )
    for shift in (7, 8, 12, 16):
        result = (LShR(a, shift) | (a << (32 - shift))) & mask
        prove(
            f"packed rotate-right {shift} is lane-local",
            [],
            Or(*(lane(result, i) != RotateRight(lanes[0][i], shift) for i in range(4))),
        )


def check_query_projection():
    pos = BitVec("position", 32)
    domain = BitVec("domain_log", 32)
    tree = BitVec("tree_log", 32)
    bounds = [ULE(1, domain), ULE(domain, 30), ULE(tree, 30), ULT(pos, 1 << domain)]

    pair = LShR(pos, 1)
    for expands in (True, False):
        if expands:
            extra = [ULT(domain, tree)]
            projected = ((pair << (tree - domain)) << 1) | (pos & 1)
            native = (LShR(pos, 1) << (tree - domain + 1)) + (pos & 1)
        else:
            extra = [ULE(tree, domain), ULT(0, tree)]
            projected = (LShR(pair, domain - tree) << 1) | (pos & 1)
            native = (LShR(pos, domain - tree + 1) << 1) + (pos & 1)
        prove(
            f"query {'expansion' if expands else 'reduction'} matches Zig and stays in range",
            bounds + extra,
            Or(projected != native, ULE(1 << tree, projected)),
        )
    prove("depth-zero query is in range", [tree == 0], ULE(1 << tree, 0))


def check_opening_bounds():
    length = BitVec("positions_length", 256)
    ones = BitVecVal((1 << 256) - 1, 256)
    prove(
        "exact-set mask includes all positions, including 256",
        [ULE(1, length), ULE(length, 256)],
        LShR(ones, 256 - length) != (1 << length) - 1,
    )
    read = Int("read_before")
    write = Int("write")
    consumed = Int("consumed")
    prove(
        "in-place Merkle reduction does not overwrite unread entries",
        [0 <= write, write <= read, 1 <= consumed, consumed <= 2],
        write + 1 > read + consumed,
    )


if __name__ == "__main__":
    check_packed_blake()
    check_query_projection()
    check_opening_bounds()
