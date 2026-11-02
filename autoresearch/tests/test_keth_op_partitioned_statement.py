"""Reject substitution between independently verified execution phases."""
import copy
import unittest

import keth_types.patches
from eth_hash.auto import keccak
from autoresearch.experiments.evm_keth.proof_statement import DOMAIN, PRIME, limbs
from autoresearch.experiments.evm_keth.verify_op_block import PARTITION_DOMAIN, join_partitioned


def statements():
    empty = limbs('0x' + keccak(b'').hex())
    common = [PARTITION_DOMAIN, 0, 2, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 21000]
    auth = common + [0, *empty, 0, 17, 18, 0, 0]
    body = common + [100000, 10, 11, 40000, 17, 18, 19, 20]
    update = common + [0, *empty, 0, 0, 0, 19, 20]
    body[1], update[1] = 1, 2
    return [auth, body, update]


class PartitionedStatementTests(unittest.TestCase):
    def test_join_requires_authenticated_view_and_complete_diff(self):
        values = statements()
        self.assertEqual(join_partitioned(values), [DOMAIN, *values[1][2:18]])
        for phase in range(3):
            for field in range(22):
                if phase == 1 and field in (14, 15, 16, 17):
                    # These are execution outputs checked against the block.
                    continue
                changed = copy.deepcopy(values)
                changed[phase][field] += 1
                with self.subTest(phase=phase, field=field), self.assertRaises(ValueError):
                    join_partitioned(changed)

    def test_missing_duplicate_reordered_and_noncanonical_phases_reject(self):
        values = statements()
        for bad in (values[:2], values + values[:1], [values[1], values[0], values[2]],
                    [values[0], values[0], values[2]]):
            with self.assertRaises(ValueError):
                join_partitioned(bad)
        values[1][14] = PRIME
        with self.assertRaises(ValueError):
            join_partitioned(values)


if __name__ == '__main__':
    unittest.main()
