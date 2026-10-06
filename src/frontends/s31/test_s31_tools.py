"""Checks that agent-facing measurements distinguish proving from PoW time."""

import unittest
from tempfile import TemporaryDirectory
from pathlib import Path

import s31


class ProverLogTests(unittest.TestCase):
    def test_pins_the_runtime_stage_format(self) -> None:
        log = (
            "S31 demo: proof=123 bytes, witness=0.000200s, setup=0.000500s, "
            "prove=0.040000s, total through verification=0.050000s\n"
            "S31 demo proof: interaction_pow=0.003000s fri_pow=0.032000s\n"
        )
        stages = s31.prover_stages(log)
        self.assertIsNotNone(stages)
        non_pow = stages.pop("prove_excluding_pow_seconds")
        self.assertAlmostEqual(non_pow, 0.005)
        self.assertEqual(stages, {
            "witness_seconds": 0.0002,
            "setup_seconds": 0.0005,
            "prove_seconds": 0.04,
            "interaction_pow_seconds": 0.003,
            "fri_pow_seconds": 0.032,
        })

    def test_missing_pow_timers_do_not_imply_zero_pow(self) -> None:
        log = "witness=0.001s, setup=0.002s, prove=0.030s"
        stages = s31.prover_stages(log)
        self.assertIsNotNone(stages)
        self.assertNotIn("prove_excluding_pow_seconds", stages)
        self.assertIsNone(s31.prover_stages("proof accepted"))

    def test_distinct_assignment_detection_ignores_json_formatting(self) -> None:
        with TemporaryDirectory() as directory:
            first = Path(directory) / "first.json"
            second = Path(directory) / "second.json"
            changed = Path(directory) / "changed.json"
            first.write_text('{"public_inputs":{"x":[1]},"public_outputs":{"y":[2]}}')
            second.write_text('{"public_outputs": {"y": [2]}, "public_inputs": {"x": [1]}}\n')
            changed.write_text('{"public_inputs":{"x":[1]},"public_outputs":{"y":[3]}}')
            self.assertEqual(s31.assignment_digest(first), s31.assignment_digest(second))
            self.assertNotEqual(s31.assignment_digest(first), s31.assignment_digest(changed))


if __name__ == "__main__":
    unittest.main()
