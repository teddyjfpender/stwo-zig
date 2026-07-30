"""The secure PCS profile has one definition across two languages.

`src/frontends/riscv/prover.zig` owns `SECURE_PCS_CONFIG`; the CSP harness owns a
Python mirror it cannot import. Before this gate existed the benchmark CLI's
`--production` flag set pow_bits=24 while the mirror said 26, and numbers were
published from the wrong profile (issue #152 item 7). The mechanism is a parse
plus a refusal, and these tests pin both the parse and the refusal's call site.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from scripts.riscv_csp_benchmark_lib import contract


class SecurePcsConfigAgreementTest(unittest.TestCase):
    def test_zig_and_python_profiles_agree_in_the_tree(self) -> None:
        self.assertEqual(
            contract.SECURE_PCS_CONFIG,
            contract.secure_pcs_config_from_zig(),
        )
        contract.assert_secure_pcs_config_agrees()

    def test_parsed_profile_reports_the_published_parameters(self) -> None:
        parsed = contract.secure_pcs_config_from_zig()
        self.assertEqual(26, parsed["pow_bits"])
        self.assertEqual(70, parsed["fri_config"]["n_queries"])
        self.assertIsNone(parsed["lifting_log_size"])

    def _doctored(self, directory: str, replacement: tuple[str, str]) -> Path:
        source = contract.PROVER_SOURCE.read_text(encoding="utf-8")
        block = contract._ZIG_SECURE_PCS_BLOCK.search(source)
        assert block is not None, "the real source must declare the constant"
        old, new = replacement
        body = block.group("body")
        self.assertIn(old, body)
        doctored = source.replace(block.group(0), block.group(0).replace(old, new))
        self.assertNotEqual(source, doctored)
        path = Path(directory) / "prover.zig"
        path.write_text(doctored, encoding="utf-8")
        return path

    def test_a_changed_zig_pow_bits_is_rejected(self) -> None:
        with TemporaryDirectory() as directory:
            path = self._doctored(directory, (".pow_bits = 26", ".pow_bits = 24"))
            self.assertEqual(24, contract.secure_pcs_config_from_zig(path)["pow_bits"])
            with self.assertRaises(contract.BenchmarkError) as raised:
                contract.assert_secure_pcs_config_agrees(path)
            self.assertIn("secure PCS profile drifted", str(raised.exception))

    def test_a_changed_zig_query_count_is_rejected(self) -> None:
        with TemporaryDirectory() as directory:
            path = self._doctored(directory, (".n_queries = 70", ".n_queries = 50"))
            with self.assertRaises(contract.BenchmarkError):
                contract.assert_secure_pcs_config_agrees(path)

    def test_a_dropped_zig_field_is_rejected_rather_than_defaulted(self) -> None:
        with TemporaryDirectory() as directory:
            path = self._doctored(directory, (".fold_step = 1,\n", ""))
            with self.assertRaises(contract.BenchmarkError) as raised:
                contract.secure_pcs_config_from_zig(path)
            self.assertIn("fold_step", str(raised.exception))

    def test_an_absent_constant_is_rejected(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "prover.zig"
            path.write_text("//! no secure profile here\n", encoding="utf-8")
            with self.assertRaises(contract.BenchmarkError) as raised:
                contract.secure_pcs_config_from_zig(path)
            self.assertIn("SECURE_PCS_CONFIG", str(raised.exception))

    def test_an_unreadable_source_is_rejected(self) -> None:
        with TemporaryDirectory() as directory:
            with self.assertRaises(contract.BenchmarkError):
                contract.secure_pcs_config_from_zig(Path(directory) / "absent.zig")

    def test_manifest_validation_refuses_while_the_profiles_disagree(self) -> None:
        """Pins the call site, not only the predicate.

        Deleting `assert_secure_pcs_config_agrees()` from `validate_manifest`
        must fail a test; a predicate nobody calls is not a mechanism.
        """
        with TemporaryDirectory() as directory:
            path = self._doctored(directory, (".pow_bits = 26", ".pow_bits = 24"))
            original = contract.PROVER_SOURCE
            contract.PROVER_SOURCE = path
            try:
                with self.assertRaises(contract.BenchmarkError) as raised:
                    contract.validate_manifest()
            finally:
                contract.PROVER_SOURCE = original
            self.assertIn("secure PCS profile drifted", str(raised.exception))

    def test_the_real_manifest_still_validates(self) -> None:
        """The refusal above must be the drift, not a manifest the suite broke."""
        _, cases, negative = contract.validate_manifest()
        self.assertTrue(cases)
        self.assertTrue(negative)


class BenchFlagNamingTest(unittest.TestCase):
    """The benchmark CLI must not offer a flag that connotes unearned authority."""

    RUNNER = contract.ROOT / "src" / "tools" / "riscv" / "bench" / "runner.zig"

    def test_secure_flag_reads_the_shared_constant(self) -> None:
        text = self.RUNNER.read_text(encoding="utf-8")
        self.assertIn('"--secure"', text)
        self.assertIn('"--pow24-q70"', text)
        self.assertIn("riscv_prover.SECURE_PCS_CONFIG.pow_bits", text)
        self.assertIn("riscv_prover.SECURE_PCS_CONFIG.fri_config.n_queries", text)

    def test_the_secure_profile_numbers_are_not_restated(self) -> None:
        """No second `.pow_bits = 26` literal: that is how the two diverged."""
        text = self.RUNNER.read_text(encoding="utf-8")
        self.assertIsNone(re.search(r"\.pow_bits\s*=\s*26\b", text))

    def test_production_no_longer_selects_a_profile(self) -> None:
        text = self.RUNNER.read_text(encoding="utf-8")
        match = re.search(r'"--production"\)\)\s*\{(?P<body>.*?)\n        \}', text, re.DOTALL)
        self.assertIsNotNone(match, "--production must still be recognised to be refused")
        body = match.group("body")
        self.assertIn("return error.InvalidArgument", body)
        self.assertNotIn("pow_bits =", body)

    def test_no_repository_caller_passes_production(self) -> None:
        offenders: list[str] = []
        for path in sorted((contract.ROOT / "scripts").rglob("*.py")):
            if "__pycache__" in path.parts or path.name == Path(__file__).name:
                continue
            if '"--production"' in path.read_text(encoding="utf-8"):
                offenders.append(str(path.relative_to(contract.ROOT)))
        self.assertEqual([], offenders)


if __name__ == "__main__":
    unittest.main()
