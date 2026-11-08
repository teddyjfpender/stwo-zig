"""Classic guest programs for the release trace corpus.

Each builder receives the encoder namespace from riscv_trace_vectors.py so the
single instruction-encoding authority stays in the gate script.
"""

from __future__ import annotations


def _rel(src_index: int, dst_index: int) -> int:
    """Byte offset between instruction indices, for branch/jump targets."""
    return (dst_index - src_index) * 4


def _prog_fib_iter(ops) -> list[int]:
    """Classic iterative Fibonacci, 20480 wrapping iterations (~102k steps)."""
    return [
        ops.ADDI(1, 0, 0),  # 0: a = 0
        ops.ADDI(2, 0, 1),  # 1: b = 1
        ops.ADDI(3, 0, 0),  # 2: i = 0
        ops.LUI(4, 0x5000),  # 3: n = 20480
        ops.ADD(5, 1, 2),  # 4: loop: t = a + b
        ops.ADDI(1, 2, 0),  # 5: a = b
        ops.ADDI(2, 5, 0),  # 6: b = t
        ops.ADDI(3, 3, 1),  # 7: i += 1
        ops.BLT(3, 4, _rel(8, 4)),  # 8: while i < n
    ] + ops.EPILOGUE()


def _prog_gcd_euclid(ops) -> list[int]:
    """Euclid by subtraction on (999424, 32) (~125k steps)."""
    return [
        ops.LUI(1, 0xF4000),  # 0: a = 999424
        ops.ADDI(2, 0, 32),  # 1: b = 32
        ops.BEQ(1, 2, _rel(2, 8)),  # 2: loop: a == b -> done
        ops.BLT(1, 2, _rel(3, 6)),  # 3: a < b -> reduce b
        ops.SUB(1, 1, 2),  # 4: a -= b
        ops.JAL(0, _rel(5, 2)),  # 5: continue
        ops.SUB(2, 2, 1),  # 6: b -= a
        ops.JAL(0, _rel(7, 2)),  # 7: continue
    ] + ops.EPILOGUE()  # 8: done


def _prog_bubble_sort(ops) -> list[int]:
    """Bubble sort of 48 descending words in the io RW region (~13k steps)."""
    return [
        ops.LUI(1, 0x00100000),  # 0: io region
        ops.ADDI(1, 1, 0x100),  # 1: arr = io + 0x100
        ops.ADDI(2, 0, 48),  # 2: n = 48
        ops.ADDI(3, 0, 0),  # 3: i = 0
        ops.ADDI(4, 1, 0),  # 4: p = arr
        ops.SUB(5, 2, 3),  # 5: init: v = n - i (descending)
        ops.SW(5, 4, 0),  # 6: *p = v
        ops.ADDI(4, 4, 4),  # 7: p += 4
        ops.ADDI(3, 3, 1),  # 8: i += 1
        ops.BLT(3, 2, _rel(9, 5)),  # 9: while i < n
        ops.ADDI(6, 2, -1),  # 10: pass = n - 1
        ops.ADDI(3, 0, 0),  # 11: outer: j = 0
        ops.ADDI(4, 1, 0),  # 12: p = arr
        ops.LW(7, 4, 0),  # 13: inner: lhs = arr[j]
        ops.LW(8, 4, 4),  # 14: rhs = arr[j+1]
        ops.BGE(8, 7, _rel(15, 18)),  # 15: ordered -> skip swap
        ops.SW(8, 4, 0),  # 16: arr[j] = rhs
        ops.SW(7, 4, 4),  # 17: arr[j+1] = lhs
        ops.ADDI(4, 4, 4),  # 18: skip: p += 4
        ops.ADDI(3, 3, 1),  # 19: j += 1
        ops.BLT(3, 6, _rel(20, 13)),  # 20: while j < pass
        ops.ADDI(6, 6, -1),  # 21: pass -= 1
        ops.BLT(0, 6, _rel(22, 11)),  # 22: while pass > 0
    ] + ops.EPILOGUE()


def _prog_sieve_primes(ops) -> list[int]:
    """Sieve of Eratosthenes over 256 byte flags in the io RW region."""
    return [
        ops.LUI(1, 0x00100000),  # 0: io region
        ops.ADDI(1, 1, 0x200),  # 1: sieve = io + 0x200
        ops.ADDI(2, 0, 256),  # 2: n = 256
        ops.ADDI(10, 0, 1),  # 3: composite mark
        ops.ADDI(11, 0, 16),  # 4: sqrt bound
        ops.ADDI(3, 0, 0),  # 5: i = 0
        ops.ADD(4, 1, 3),  # 6: clear: addr = sieve + i
        ops.SB(0, 4, 0),  # 7: sieve[i] = 0
        ops.ADDI(3, 3, 1),  # 8: i += 1
        ops.BLT(3, 2, _rel(9, 6)),  # 9: while i < n
        ops.ADDI(5, 0, 2),  # 10: p = 2
        ops.ADD(6, 1, 5),  # 11: outer: addr = sieve + p
        ops.LBU(7, 6, 0),  # 12: flag = sieve[p]
        ops.BNE(7, 0, _rel(13, 20)),  # 13: composite -> next p
        ops.ADD(8, 5, 5),  # 14: m = 2p
        ops.BGE(8, 2, _rel(15, 20)),  # 15: mark: m >= n -> next p
        ops.ADD(9, 1, 8),  # 16: addr = sieve + m
        ops.SB(10, 9, 0),  # 17: sieve[m] = 1
        ops.ADD(8, 8, 5),  # 18: m += p
        ops.JAL(0, _rel(19, 15)),  # 19: continue marking
        ops.ADDI(5, 5, 1),  # 20: next: p += 1
        ops.BLT(5, 11, _rel(21, 11)),  # 21: while p < 16
    ] + ops.EPILOGUE()


def _prog_xorshift_prng(ops) -> list[int]:
    """xorshift32 PRNG, 8192 rounds (~66k steps)."""
    return [
        ops.LUI(1, 0x2545F000),  # 0: seed high
        ops.ADDI(1, 1, 0x491),  # 1: seed = 0x2545F491
        ops.ADDI(2, 0, 0),  # 2: i = 0
        ops.LUI(3, 0x2000),  # 3: n = 8192
        ops.SLLI(4, 1, 13),  # 4: loop: x ^= x << 13
        ops.XOR(1, 1, 4),  # 5:
        ops.SRLI(4, 1, 17),  # 6: x ^= x >> 17
        ops.XOR(1, 1, 4),  # 7:
        ops.SLLI(4, 1, 5),  # 8: x ^= x << 5
        ops.XOR(1, 1, 4),  # 9:
        ops.ADDI(2, 2, 1),  # 10: i += 1
        ops.BLT(2, 3, _rel(11, 4)),  # 11: while i < n
    ] + ops.EPILOGUE()


def _prog_collatz(ops) -> list[int]:
    """Total Collatz flight length over seeds 2..127 (~29k steps)."""
    return [
        ops.ADDI(1, 0, 2),  # 0: seed = 2
        ops.ADDI(2, 0, 128),  # 1: seed limit
        ops.ADDI(3, 0, 0),  # 2: total = 0
        ops.ADDI(5, 0, 1),  # 3: one
        ops.ADDI(4, 1, 0),  # 4: outer: n = seed
        ops.BEQ(4, 5, _rel(5, 15)),  # 5: inner: n == 1 -> next seed
        ops.ANDI(6, 4, 1),  # 6: parity
        ops.BNE(6, 0, _rel(7, 10)),  # 7: odd -> 3n+1
        ops.SRLI(4, 4, 1),  # 8: even: n >>= 1
        ops.JAL(0, _rel(9, 13)),  # 9: -> count
        ops.SLLI(7, 4, 1),  # 10: odd: 2n
        ops.ADD(4, 7, 4),  # 11: 3n
        ops.ADDI(4, 4, 1),  # 12: 3n + 1
        ops.ADDI(3, 3, 1),  # 13: count: total += 1
        ops.JAL(0, _rel(14, 5)),  # 14: continue flight
        ops.ADDI(1, 1, 1),  # 15: next: seed += 1
        ops.BLT(1, 2, _rel(16, 4)),  # 16: while seed < limit
    ] + ops.EPILOGUE()


def _prog_memcpy_loop(ops) -> list[int]:
    """Fill 192 words then copy them to a second io-region buffer."""
    return [
        ops.LUI(1, 0x00100000),  # 0: io region
        ops.ADDI(2, 1, 0x400),  # 1: src = io + 0x400
        ops.ADDI(3, 0, 192),  # 2: n = 192
        ops.ADDI(4, 0, 0),  # 3: i = 0
        ops.ADDI(5, 2, 0),  # 4: p = src
        ops.ADDI(6, 0, 0),  # 5: v = 0
        ops.SW(6, 5, 0),  # 6: fill: *p = v
        ops.ADDI(6, 6, 2657),  # 7: v += 2657
        ops.ADDI(5, 5, 4),  # 8: p += 4
        ops.ADDI(4, 4, 1),  # 9: i += 1
        ops.BLT(4, 3, _rel(10, 6)),  # 10: while i < n
        ops.LUI(7, 0x00100000),  # 11:
        ops.ADDI(7, 7, 0x700),  # 12: dst = io + 0x700
        ops.ADDI(4, 0, 0),  # 13: i = 0
        ops.ADDI(5, 2, 0),  # 14: p = src
        ops.LW(8, 5, 0),  # 15: copy: v = *p
        ops.SW(8, 7, 0),  # 16: *dst = v
        ops.ADDI(5, 5, 4),  # 17: p += 4
        ops.ADDI(7, 7, 4),  # 18: dst += 4
        ops.ADDI(4, 4, 1),  # 19: i += 1
        ops.BLT(4, 3, _rel(20, 15)),  # 20: while i < n
    ] + ops.EPILOGUE()



def all_programs(ops) -> dict[str, list[int]]:
    return {
        "fib_iter": _prog_fib_iter(ops),
        "gcd_euclid": _prog_gcd_euclid(ops),
        "bubble_sort": _prog_bubble_sort(ops),
        "sieve_primes": _prog_sieve_primes(ops),
        "xorshift_prng": _prog_xorshift_prng(ops),
        "collatz": _prog_collatz(ops),
        "memcpy_loop": _prog_memcpy_loop(ops),
    }
