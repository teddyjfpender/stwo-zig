"""Independent Python arithmetic oracle for the pinned Stark-V M31 Poseidon2."""

import hashlib
import re
from pathlib import Path


P = (1 << 31) - 1
CONSTANTS_FILE = Path(__file__).resolve().parents[1] / "riscv/air/memory_commitment/poseidon2_constants.zig"


def constants() -> tuple[list[list[int]], list[int], list[int]]:
    source = CONSTANTS_FILE.read_text()

    def values(name: str, count: int) -> list[int]:
        body = source.split(f"pub const {name}:", 1)[1].split("= .{", 1)[1].split("\n};", 1)[0]
        result = [int(number) for number in re.findall(r"\b\d+\b", body)]
        if len(result) != count or any(number >= P for number in result):
            raise AssertionError(f"unexpected pinned {name} constants")
        return result

    external = values("EXTERNAL_ROUND", 8 * 16)
    return [external[i * 16:(i + 1) * 16] for i in range(8)], values("INTERNAL_ROUND", 14), values("INTERNAL_MATRIX", 16)


EXTERNAL, INTERNAL, DIAGONAL = constants()
CONSTANTS_SHA256 = hashlib.sha256(CONSTANTS_FILE.read_bytes()).hexdigest()


def m4(v: list[int]) -> list[int]:
    t0 = (v[0] + v[1]) % P
    t1 = (v[2] + v[3]) % P
    t2 = (2 * v[1] + t1) % P
    t3 = (2 * v[3] + t0) % P
    t4 = (4 * t1 + t3) % P
    t5 = (4 * t0 + t2) % P
    return [(t3 + t5) % P, t5, (t2 + t4) % P, t4]


def external_layer(state: list[int]) -> list[int]:
    blocks = [m4(state[i:i + 4]) for i in range(0, 16, 4)]
    return [(blocks[block][lane] + sum(group[lane] for group in blocks)) % P
            for block in range(4) for lane in range(4)]


def permute(initial: list[int]) -> list[int]:
    if len(initial) != 16 or any(not 0 <= word < P for word in initial):
        raise ValueError("Poseidon2 state must have sixteen canonical M31 words")
    state = external_layer(initial)
    for round_constants in EXTERNAL[:4]:
        state = external_layer([pow((word + constant) % P, 5, P) for word, constant in zip(state, round_constants)])
    for constant in INTERNAL:
        state[0] = pow((state[0] + constant) % P, 5, P)
        total = sum(state) % P
        state = [(word * diagonal + total) % P for word, diagonal in zip(state, DIAGONAL)]
    for round_constants in EXTERNAL[4:]:
        state = external_layer([pow((word + constant) % P, 5, P) for word, constant in zip(state, round_constants)])
    return state


def leaf(words: list[int]) -> list[int]:
    if len(words) not in (4, 8, 12, 16) or any(not 0 <= word < P for word in words):
        raise ValueError("leaf must contain 4, 8, 12, or 16 canonical M31 words")
    state = [0] * 16
    state[15] = 1
    filled = 0
    for word in [*words, 1]:
        state[filled] = (state[filled] + word) % P
        filled += 1
        if filled == 8:
            state = permute(state)
            filled = 0
    if filled:
        state = permute(state)
    return state[:8]


def pair(left: list[int], right: list[int]) -> list[int]:
    if len(left) != 8 or len(right) != 8:
        raise ValueError("parent requires two eight-word digests")
    return permute(left + right)[:8]


def self_check() -> None:
    state = [1, 2] + [0] * 14
    if permute(state)[0] != 1975699496:
        raise AssertionError("pinned Stark-V hashPair(1, 2) vector disagrees")


if __name__ == "__main__":
    self_check()
    left = leaf(list(range(1, 9)))
    right = leaf(list(range(9, 17)))
    print("constants_sha256", CONSTANTS_SHA256)
    print("left", left)
    print("right", right)
    print("root", pair(left, right))
