#!/usr/bin/env python3
"""Small fixed vectors for the Cairo1-to-leaf commitment boundary."""

import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from prepare_leaf import validate_bootloader_commitment


PROGRAM_HASH = int("16780ae892f9a6115cf6b99aa6116ff81d520cfb339e78af3f73ff515223239", 16)
QEC_OUTPUT = [
    int("177d40f699ad2c81ef65530fe9d9896a", 16),
    int("489137a25ce1a756805322d2f383eb40", 16),
]
BOOT_OUTPUT = [
    int("762281c82b02fb205681c9c6a3859ad0", 16),
    int("d5c7fac54373727e334efa07691a91c1", 16),
]


class LeafCommitmentTest(unittest.TestCase):
    def test_pinned_real_execution(self) -> None:
        validate_bootloader_commitment([PROGRAM_HASH, *QEC_OUTPUT], BOOT_OUTPUT,
                                       PROGRAM_HASH, QEC_OUTPUT)

    def test_mutated_program_or_output_is_rejected(self) -> None:
        for index in range(3):
            mutated = [PROGRAM_HASH, *QEC_OUTPUT]
            mutated[index] += 1
            with self.subTest(index=index), self.assertRaises(ValueError):
                validate_bootloader_commitment(mutated, BOOT_OUTPUT,
                                               PROGRAM_HASH, QEC_OUTPUT)
        with self.assertRaises(ValueError):
            validate_bootloader_commitment([PROGRAM_HASH, *QEC_OUTPUT],
                                           [BOOT_OUTPUT[0] ^ 1, BOOT_OUTPUT[1]],
                                           PROGRAM_HASH, QEC_OUTPUT)


if __name__ == "__main__":
    unittest.main()
