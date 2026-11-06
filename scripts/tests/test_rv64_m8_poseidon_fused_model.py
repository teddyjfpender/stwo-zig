import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import rv64_m8_poseidon_fused_model as model  # noqa: E402


class FusedPoseidonModelTest(unittest.TestCase):
    def test_weak_u32_model_matches_dense_reference(self):
        self.assertGreater(model.check(samples=32), 32)

    def test_reordered_m4_is_detected(self):
        original = model.m4
        try:
            model.m4 = lambda z: (lambda o: [o[1], o[0], o[2], o[3]])(original(z))
            with self.assertRaises(AssertionError):
                model.check(samples=1)
        finally:
            model.m4 = original

    def test_fold_precondition_is_enforced(self):
        with self.assertRaises(AssertionError):
            model.fold32((1 << 32) - 1)


if __name__ == "__main__":
    unittest.main()
