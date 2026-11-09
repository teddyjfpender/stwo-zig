#!/usr/bin/env python3
"""Generate the immutable EIP-4844 roots in Arkworks' four-limb Montgomery form.

The program image authenticates these constants; no witness supplies them.
Run with --check to compare the committed bytes without rewriting them.
"""

import argparse
from pathlib import Path

MODULUS = 52435875175126190479447740508185965837690552500527637822603658699938581184513
SIZE = 4096
DESTINATION = Path(__file__).resolve().parents[1] / "kona/src/blob_roots/montgomery.bin"


def roots(canonical=False):
    step = pow(7, (MODULUS - 1) // SIZE, MODULUS)
    assert pow(step, SIZE, MODULUS) == 1
    assert pow(step, SIZE // 2, MODULUS) == MODULUS - 1
    value = 1
    encoded = bytearray()
    radix = 1 if canonical else pow(2, 256, MODULUS)
    for _ in range(SIZE):
        encoded.extend((value * radix % MODULUS).to_bytes(32, "little"))
        value = value * step % MODULUS
    assert value == 1
    return bytes(encoded)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--canonical", action="store_true")
    args = parser.parse_args()
    destination = DESTINATION.with_name("canonical.bin") if args.canonical else DESTINATION
    encoded = roots(args.canonical)
    if args.check:
        if destination.read_bytes() != encoded:
            raise SystemExit("committed EIP-4844 roots differ from generated values")
    else:
        destination.write_bytes(encoded)


if __name__ == "__main__":
    main()
