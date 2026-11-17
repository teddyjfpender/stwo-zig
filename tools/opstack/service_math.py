"""Independent pure service arithmetic used by the OP Unicorn oracle.

Extracted unchanged from the retired RV64 analysis CLI at 2b16da21b. No
execution driver, host result, guest implementation or proof acceptance logic.
"""

FIELD_MODULUS = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
ROUND_CONSTANTS = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
ROTATIONS = [
    [0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14],
]
MASK64 = (1 << 64) - 1


def rotl(value, shift):
    return ((value << shift) | (value >> (64 - shift))) & MASK64 if shift else value


def keccak_f1600(lanes):
    """Keccak-f[1600] on 25 lanes in the standard x + 5*y order."""
    a = list(lanes)
    for rc in ROUND_CONSTANTS:
        c = [a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ rotl(c[(x + 1) % 5], 1) for x in range(5)]
        a = [a[i] ^ d[i % 5] for i in range(25)]
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = rotl(a[x + 5 * y], ROTATIONS[x][y])
        a = [b[i] ^ ((~b[(i % 5 + 1) % 5 + 5 * (i // 5)]) & b[(i % 5 + 2) % 5 + 5 * (i // 5)]) for i in range(25)]
        a[0] ^= rc
    return a


def reduce_once(value):
    return value - FIELD_MODULUS if value >= FIELD_MODULUS else value


def secp_add(x1, y1, z1, x2, y2, z2):
    """RCB complete addition for secp256k1 (b = 7), same program as the executor."""
    p = FIELD_MODULUS
    xx, yy, zz = x1 * x2 % p, y1 * y2 % p, z1 * z2 % p
    xy = ((x1 + y1) * (x2 + y2) - xx - yy) % p
    yz = ((y1 + z1) * (y2 + z2) - yy - zz) % p
    xz = ((x1 + z1) * (x2 + z2) - xx - zz) % p
    bzz3 = zz * 21 % p
    ym, yp = (yy - bzz3) % p, (yy + bzz3) % p
    byz3 = yz * 21 % p
    xx3, bxx9 = xx * 3 % p, xx * 63 % p
    return ((xy * ym - byz3 * xz) % p, (yp * ym + bxx9 * xz) % p, (yz * yp + xx3 * xy) % p)


def secp_double(x, y, z):
    p = FIELD_MODULUS
    yy, zz = y * y % p, z * z % p
    xy2 = x * y * 2 % p
    bzz3, bzz9 = zz * 21 % p, zz * 63 % p
    ym, yp = (yy - bzz9) % p, (yy + bzz3) % p
    t = yy * zz * 168 % p
    return (xy2 * ym % p, (ym * yp + t) % p, yy * y % p * z % p * 8 % p)
