import inspect
import unittest
from unittest import mock

from autoresearch.benchmarks import riscv_benchmark_host_contract as contract
from autoresearch.benchmarks import riscv_crypto_benchmark as crypto
from scripts.riscv_csp_benchmark_lib import host as csp_host
from autoresearch.benchmarks.riscv_stark_v_benchmark import (
    MIN_RUST_PARALLELISM,
    PHASE_MARKERS,
    SCHEMA,
    collect_host_environment,
    main as stark_v_main,
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
        self.assertEqual(env["schema"], "riscv_benchmark_host_environment_v2")
        # The platform block is always populated so a report never lands
        # without machine context, even off macOS where sysctl fields are null.
        for key in ("system", "release", "machine"):
            self.assertTrue(env["platform"][key])
        self.assertIsNotNone(env["hardware"]["logical_cpu_count"])
        self.assertIn("chip", env["hardware"])

    def test_field_set_stays_exactly_what_the_matrix_contract_admits(self) -> None:
        """The producer and the consuming contract are pinned to each other.

        ``riscv_benchmark_host_contract`` admits the shared host block, and the
        two retained comparison harnesses embed this same block -- so
        a field added on one side and not the other breaks the others at
        report-validation time rather than here.  Asserted against the contract's
        own constant rather than a restated literal, because a restated literal is
        what let the two definitions of this field set drift.
        """
        self.assertEqual(
            contract.HOST_ENVIRONMENT_FIELDS,
            set(collect_host_environment()),
        )
        self.assertEqual(
            contract.HOST_ENVIRONMENT_SCHEMA,
            collect_host_environment()["schema"],
        )

    def test_every_harness_that_publishes_timings_records_power_conditions(self) -> None:
        """The evidence issue #152 item 6c exists to require, on all three paths.

        The block is embedded, not restated: the sibling harnesses could publish
        battery-throttled numbers with nothing in the report saying so, and a
        second power capture written per harness would drift from this one.
        """
        self.assertEqual(
            contract.POWER_CONDITION_FIELDS,
            set(collect_host_environment()["power_conditions"]),
        )
        self.assertIs(csp_host.power_evidence_block, crypto.power_evidence_block)
        self.assertIs(csp_host.power_evidence_block, crypto.power_evidence_block)

    def test_a_precaptured_verdict_is_reused_rather_than_recaptured(self) -> None:
        # One run must report one power capture. A harness that warns an operator
        # up front and then lets the report capture again could publish a verdict
        # that contradicts the warning it printed.
        with mock.patch.object(
            csp_host, "power_evidence", lambda: ("Battery Power", True),
        ):
            captured = power_evidence_block()
        with mock.patch.object(
            csp_host, "power_evidence", lambda: ("AC Power", False),
        ):
            env = collect_host_environment(power_conditions=captured)
        self.assertEqual(captured, env["power_conditions"])
        self.assertEqual("Battery Power", env["power_conditions"]["power_source"])


class HostEnvironmentContractTests(unittest.TestCase):
    """The contract must admit the v2 block and refuse a forged verdict."""

    @staticmethod
    def host_environment(**overrides: object) -> dict:
        env = collect_host_environment(
            power_conditions={
                "power_source": "AC Power",
                "low_power_mode": False,
                "admissible": True,
                "reasons": [],
            },
        )
        env["stark_v_commit"] = "d478f783055aa0d73a93768a433a3c6c31c91d1c"
        env.update(overrides)
        return env

    def test_the_v2_block_is_admitted(self) -> None:
        contract.validate_host_environment(self.host_environment(), "host")

    def test_each_publishing_harness_captures_power_before_it_measures(self) -> None:
        """Reachability, per harness: captured up front, reported as captured.

        An operator must be told about a throttled host while the run is still
        worth aborting, and the report must carry that same capture rather than a
        second one taken after the fact.
        """
        # KNOWN GAP (issue #152): "before it measures" is asserted by two
        # unordered `assertIn`s, so moving the capture after the sampling loop
        # leaves this green. A per-harness measurement marker is the fix.
        for label, entry in (
            ("stark-v corpus", stark_v_main),
            ("crypto guests", crypto.main),
        ):
            with self.subTest(label):
                source = inspect.getsource(entry)
                self.assertIn("power = power_evidence_block()", source)
                self.assertIn("power_conditions=power", source)

    def test_a_v1_block_is_refused(self) -> None:
        env = self.host_environment()
        del env["power_conditions"]
        env["schema"] = "riscv_benchmark_host_environment_v1"
        with self.assertRaisesRegex(contract.HostContractError, "fields drifted"):
            contract.validate_host_environment(env, "host")

    def test_a_v1_schema_string_on_a_v2_shape_is_refused(self) -> None:
        with self.assertRaisesRegex(contract.HostContractError, "schema drifted"):
            contract.validate_host_environment(
                self.host_environment(schema="riscv_benchmark_host_environment_v1"),
                "host",
            )

    def test_a_verdict_that_does_not_follow_from_the_evidence_is_refused(self) -> None:
        # The defect this whole block exists to expose: battery-captured timings
        # published as if they were valid measurements.
        forged = self.host_environment(power_conditions={
            "power_source": "Battery Power",
            "low_power_mode": True,
            "admissible": True,
            "reasons": [],
        })
        with self.assertRaisesRegex(
            contract.HostContractError, "does not follow from",
        ):
            contract.validate_host_environment(forged, "host")

    def test_an_honest_non_publishable_verdict_is_admitted(self) -> None:
        # Recording a throttled run is not the defect; claiming it was fine is.
        observed = {"power_source": "Battery Power", "low_power_mode": True}
        admissible, reasons = csp_host.power_conditions_admissible(observed)
        contract.validate_host_environment(
            self.host_environment(power_conditions={
                **observed, "admissible": admissible, "reasons": reasons,
            }),
            "host",
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
