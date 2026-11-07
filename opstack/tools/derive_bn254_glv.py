#!/usr/bin/env python3
"""Reproduce the BN254 GLV constants from the pinned Ark G1 lattice.

The matrix rows are (-A, B), (-B, -C), C=A+B. Determinant AC+B²=r.
For 0<=k<r, u=floor(kC/r), v=floor(kB/r), k1=k-uA-vB,
k2=uB-vC. Therefore k1+lambda*k2=k (mod r), 0<=k1<C and -B<k2<C.
A reciprocal truncated at 256 bits underestimates each quotient by at most one:
its error is <k/2^256<1, so one exact residual comparison completes division.
"""

P = 21888242871839275222246405745257275088696311157297823662689037894645226208583
R = 21888242871839275222246405745257275088548364400416034343698204186575808495617
A = 147946756881789319000765030803803410728
B = 9931322734385697763
C = A + B
LAMBDA = 21888242871839275217838484774961031246154997185409878258781734729429964517155
BETA = 21888242871839275220042445260109153167277707414472061641714758635765020556616


def main():
    assert A * C + B * B == R
    assert (LAMBDA * B - A) % R == (LAMBDA * C + B) % R == 0
    assert pow(BETA, 3, P) == 1 and BETA != 1
    assert C < 1 << 127 and R < 1 << 254
    for name, value in [
        ("A", A),
        ("B", B),
        ("C", C),
        ("RECIP_C", (C << 256) // R),
        ("RECIP_B", (B << 256) // R),
        ("BETA", BETA),
    ]:
        print(f"{name} = 0x{value:x}")


if __name__ == "__main__":
    main()
