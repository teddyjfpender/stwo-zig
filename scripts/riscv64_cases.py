"""Deterministic RV64 instruction cases shared by independent oracle runners."""
MASK = (1 << 64) - 1
EDGES = [0, 1, 2, 31, 32, 63, 64, 0x7fffffff, 0x80000000,
         0xffffffff, 0x100000000, (1 << 63) - 1, 1 << 63, MASK - 1, MASK]


def r(major, f3, f7):
    return major | (3 << 7) | (f3 << 12) | (1 << 15) | (2 << 20) | (f7 << 25)


def immediate(major, f3, imm):
    return major | (3 << 7) | (f3 << 12) | (1 << 15) | ((imm & 4095) << 20)


def cases(rng, samples):
    # Cartesian edge cases exercise all four signed/unsigned multiplication
    # combinations and division corner cases independently of our Zig helpers.
    specs = [(0x33, f3, 0) for f3 in range(8)]
    specs += [(0x33, f3, 32) for f3 in (0, 5)]
    specs += [(0x33, f3, 1) for f3 in range(8)]
    specs += [(0x3b, f3, 0) for f3 in (0, 1, 5)]
    specs += [(0x3b, f3, 32) for f3 in (0, 5)]
    specs += [(0x3b, f3, 1) for f3 in (0, 4, 5, 6, 7)]
    for major, f3, f7 in specs:
        for a in EDGES:
            for b in EDGES:
                yield r(major, f3, f7), a, b, False
        for _ in range(samples):
            yield r(major, f3, f7), rng.getrandbits(64), rng.getrandbits(64), False
    for major, f3 in [(0x13, f) for f in (0, 2, 3, 4, 6, 7)] + [(0x1b, 0)]:
        for a in EDGES:
            for imm in (-2048, -1, 0, 1, 2047):
                yield immediate(major, f3, imm), a, rng.getrandbits(64), False
    for major, width in ((0x13, 64), (0x1b, 32)):
        for f3, high in ((1, 0), (5, 0), (5, 0x400)):
            for shift in range(width):
                for a in EDGES:
                    yield immediate(major, f3, high | shift), a, 0, False
    for f3 in range(7):
        # Signed/unsigned loads, including data above bit 31 and bit 63.
        for _ in range(samples):
            yield immediate(3, f3, 0), None, rng.getrandbits(64), True
    for f3 in range(4):
        word = 0x23 | (f3 << 12) | (1 << 15) | (2 << 20)
        for b in EDGES:
            yield word, None, b, True
    for f3 in (0, 1, 4, 5, 6, 7):
        for a in EDGES:
            for b in EDGES:
                # Branch +8; both paths remain in mapped instruction memory.
                yield 0x63 | (f3 << 12) | (1 << 15) | (2 << 20) | (4 << 8), a, b, False
    for upper in (0, 1, 0x7ffff, 0x80000, 0xfffff):
        for major in (0x37, 0x17):
            yield (upper << 12) | (3 << 7) | major, 0, 0, False
    yield 0x008001ef, 0, 0, False  # jal x3,+8
    yield 0x000081e7, "jump", 0, False  # jalr x3,x1,0
    yield 0x000080e7, "jump", 0, False  # jalr x1,x1,0 alias
    yield 0x0ff0000f, 0, 0, False  # fence iorw,iorw
    # x0 writes and operand/destination aliasing must match the oracle too.
    for word, a, b in ((r(0x33, 0, 0), MASK, 2), (r(0x33, 0, 1), MASK, MASK)):
        for rd in (0, 1, 2):
            yield (word & ~(31 << 7)) | (rd << 7), a, b, False
