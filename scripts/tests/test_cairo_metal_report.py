import copy
import unittest

from scripts.check_cairo_metal_report import validate


class CairoMetalReportTest(unittest.TestCase):
    def setUp(self) -> None:
        self.digest = "ab" * 32
        self.report = {
            "schema_version": 2,
            "backend": "metal",
            "product": {
                "name": "stwo-cairo-metal",
                "backend": "metal",
                "runtime": {
                    "manifest": "metal-runtime-v2:mode=source-jit",
                    "aot": "none",
                },
            },
            "proof": {
                "format": "json",
                "bytes": 123,
                "sha256": self.digest,
            },
            "verification": {"requested": True, "zig": True},
            "backend_evidence": {
                "execution": "metal-pcs",
                "classification": "accelerated_without_fallbacks",
                "metal_dispatches": 7,
                "cpu_fallbacks": 0,
                "runtime_initializations": 1,
                "runtime_shutdowns": 1,
            },
        }

    def test_accepts_exact_fallback_free_receipt(self) -> None:
        validate(self.report, self.digest, 123, "source-jit", "json")

    def test_rejects_fallback_and_lifecycle_drift(self) -> None:
        for field, value in (
            ("cpu_fallbacks", 1),
            ("runtime_initializations", 2),
            ("runtime_shutdowns", 0),
        ):
            with self.subTest(field=field):
                drifted = copy.deepcopy(self.report)
                drifted["backend_evidence"][field] = value
                with self.assertRaises(ValueError):
                    validate(
                        drifted,
                        self.digest,
                        123,
                        "source-jit",
                        "json",
                    )

    def test_rejects_proof_digest_drift(self) -> None:
        with self.assertRaises(ValueError):
            validate(self.report, "cd" * 32, 123, "source-jit", "json")

    def test_requires_a_real_program_execution_receipt(self) -> None:
        executed = copy.deepcopy(self.report)
        executed["execution"] = {
            "program_type": "executable",
            "wall_ns": 1234,
        }
        validate(
            executed,
            self.digest,
            123,
            "source-jit",
            "json",
            require_execution=True,
        )
        with self.assertRaises(ValueError):
            validate(
                self.report,
                self.digest,
                123,
                "source-jit",
                "json",
                require_execution=True,
            )

    def test_rejects_proof_format_drift(self) -> None:
        with self.assertRaises(ValueError):
            validate(self.report, self.digest, 123, "source-jit", "binary")


if __name__ == "__main__":
    unittest.main()
