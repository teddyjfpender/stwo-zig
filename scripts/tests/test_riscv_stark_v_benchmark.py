import unittest

from scripts.riscv_csp_benchmark_lib import host as csp_host
from scripts.riscv_stark_v_benchmark import (
    MIN_RUST_PARALLELISM,
    PHASE_MARKERS,
    SCHEMA,
    collect_host_environment,
    parse_phase_seconds,
    power_evidence_block,
)

FIXTURE = """\
\x1b[2m2026-07-19T23:06:20.000000Z\x1b[0m \x1b[32m INFO\x1b[0m \x1b[2mstark_v_bench\x1b[0m\x1b[2m:\x1b[0m Running guest program...
2026-07-19T23:06:20.100000Z  INFO stark_v_bench: Guest program completed with 144 cycles
2026-07-19T23:06:20.150000Z  INFO stark_v_bench: Preprocessing...
2026-07-19T23:06:20.200000Z  INFO stark_v_bench: Generating proof...
2026-07-19T23:06:22.700000Z  INFO stark_v_bench: Verifying proof...
2026-07-19T23:06:22.800000Z  INFO stark_v_bench: Proof verified successfully
"""


class PhaseParsingTests(unittest.TestCase):
    def test_durations_come_from_tracing_timestamps(self) -> None:
        phases = parse_phase_seconds(FIXTURE)
        self.assertAlmostEqual(phases["execution_seconds"], 0.2)
        self.assertAlmostEqual(phases["prove_seconds"], 2.5)
        self.assertAlmostEqual(phases["verify_seconds"], 0.1)

    def test_missing_markers_fail_closed(self) -> None:
        truncated = "\n".join(FIXTURE.splitlines()[:4])
        with self.assertRaisesRegex(ValueError, "phase markers"):
            parse_phase_seconds(truncated)

    def test_first_marker_occurrence_wins(self) -> None:
        # A second prove line (e.g. from a nested span) must not shift phases.
        doubled = FIXTURE.replace(
            "2026-07-19T23:06:22.700000Z  INFO stark_v_bench: Verifying proof...",
            "2026-07-19T23:06:22.600000Z  INFO stark_v_bench: Generating proof...\n"
            "2026-07-19T23:06:22.700000Z  INFO stark_v_bench: Verifying proof...",
        )
        phases = parse_phase_seconds(doubled)
        self.assertAlmostEqual(phases["prove_seconds"], 2.5)

    def test_marker_set_is_complete(self) -> None:
        self.assertEqual(
            set(PHASE_MARKERS), {"run_start", "prove_start", "verify_start", "verify_done"}
        )

    def test_parallelism_floor_rejects_serial_rust(self) -> None:
        # The floor must sit above a single core so a non-parallel Rust build
        # (cpu/wall ~ 1.0) fails, while a genuinely threaded one clears it.
        self.assertGreater(MIN_RUST_PARALLELISM, 1.0)


class HostEnvironmentTests(unittest.TestCase):
    def test_report_is_self_describing_on_any_host(self) -> None:
        env = collect_host_environment()
        self.assertEqual(env["schema"], "riscv_benchmark_host_environment_v1")
        # The platform block is always populated so a report never lands
        # without machine context, even off macOS where sysctl fields are null.
        for key in ("system", "release", "machine"):
            self.assertTrue(env["platform"][key])
        self.assertIsNotNone(env["hardware"]["logical_cpu_count"])
        self.assertIn("chip", env["hardware"])

    def test_field_set_stays_exactly_what_the_matrix_contract_admits(self) -> None:
        """Power evidence must not be smuggled into this block.

        ``riscv_benchmark_matrix_contract`` admits ``report.host_environment``
        through ``exact_fields`` with precisely these five names, and two
        sibling harnesses embed this same block, so a sixth field here breaks
        them at report-validation time rather than here.  That is why the run's
        power conditions ride in the report's own ``power_conditions`` block.
        """
        self.assertEqual(
            {"schema", "platform", "hardware", "toolchain", "stark_v_commit"},
            set(collect_host_environment()),
        )


class SharedPowerEvidenceTests(unittest.TestCase):
    """The power question is answered by one implementation, not two."""

    def test_the_power_block_is_the_csp_harness_implementation(self) -> None:
        # A sibling that captured its own power state would drift from the CSP
        # harness silently, which is the defect this sharing exists to remove.
        self.assertIs(csp_host.power_evidence_block, power_evidence_block)

    def test_the_block_carries_its_evidence_and_its_verdict(self) -> None:
        self.assertEqual(
            {"power_source", "low_power_mode", "admissible", "reasons"},
            set(power_evidence_block()),
        )

    def test_the_report_schema_records_that_the_shape_changed(self) -> None:
        # The `power_conditions` block is new evidence in the report body, so a
        # consumer must be able to tell a report that has it from one that
        # cannot: v1 reports predate power certification entirely.
        self.assertEqual("riscv_starkv_benchmark_v2", SCHEMA)
