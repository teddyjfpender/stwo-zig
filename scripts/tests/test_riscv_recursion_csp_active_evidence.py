from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scripts.tests.test_riscv_recursion_csp_benchmark import (
    EvidenceError,
    _active_outer_output,
    _initialize_probe_repository,
    _plan,
    _recursive_report,
    atomic_write_new,
    build_comparison,
    canonical_bytes,
    collect_active_outer_probe,
    decode_json,
    parse_active_outer_output,
    seal_document,
    validate_active_outer_probe,
    validate_recursive_report,
)


class RecursionCspActiveEvidenceTests(unittest.TestCase):
    def test_active_outer_probe_parser_requires_complete_verified_output(self) -> None:
        parsed = parse_active_outer_output(
            _active_outer_output(),
            requested_workers=4,
        )
        self.assertEqual(parsed["outer"]["poseidon_calls"], 99)
        self.assertEqual(parsed["outer"]["proof_estimate"], 500)
        self.assertFalse(parsed["canonical_recursive_artifact_available"])
        for mutated, message in (
            (
                _active_outer_output().replace(b"mutations=5/5", b"mutations=4/5"),
                "mutation fleet",
            ),
            (
                _active_outer_output().replace(b"All 1 tests passed.", b"test failed"),
                "test-pass summary",
            ),
            (
                _active_outer_output().replace(b"capture=ok", b"capture=missing"),
                "capture record",
            ),
        ):
            with self.subTest(message=message):
                with self.assertRaisesRegex(EvidenceError, message):
                    parse_active_outer_output(mutated, requested_workers=4)

    def test_active_outer_collector_uses_fresh_verified_processes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan = _plan(root)
            _initialize_probe_repository(root)
            fake_zig = root / "fake-zig"
            encoded_output = _active_outer_output().decode().replace("'", "'\"'\"'")
            fake_zig.write_text(
                "#!/bin/sh\nprintf '%s' '" + encoded_output + "'\n",
                encoding="utf-8",
            )
            fake_zig.chmod(0o755)
            probe = collect_active_outer_probe(
                plan,
                repo_root=root,
                zig_executable=fake_zig,
                workers=4,
                timeout_seconds=5,
            )
            comparison = build_comparison(
                plan,
                recursive_report=None,
                repo_root=root,
                active_outer_probe=probe,
            )
            mutated_probe = decode_json(canonical_bytes(probe), label="probe copy")
            mutated_probe["attempts"][1]["observation"]["outer"][
                "poseidon_calls"
            ] += 1
            mutated_probe.pop("canonical_digest")
            mutated_probe = seal_document(mutated_probe)
            with self.assertRaisesRegex(EvidenceError, "retained log"):
                validate_active_outer_probe(mutated_probe, plan=plan)
        self.assertEqual(probe["status"], "verified_non_csp_probe")
        self.assertFalse(probe["comparison_eligible"])
        self.assertEqual(len(probe["attempts"]), 4)
        self.assertEqual(probe["attempts"][0]["classification"], "excluded_warmup")
        self.assertEqual(probe["summary"]["outer_prove_ns"], 100_000_000)
        self.assertIsNone(probe["summary"]["canonical_recursive_proof_bytes"])
        self.assertEqual(
            comparison["active_outer_probe"]["canonical_digest"],
            probe["canonical_digest"],
        )
        self.assertFalse(
            comparison["comparability"]["active_outer_probe_is_csp_evidence"]
        )
        self.assertTrue(
            all(
                metric["status"] == "unavailable"
                for metric in comparison["rows"][0][
                    "aggregate_comparisons"
                ].values()
            )
        )

    def test_active_outer_collector_fails_closed_without_synthetic_samples(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan = _plan(root)
            _initialize_probe_repository(root)
            fake_zig = root / "fake-zig"
            fake_zig.write_text("#!/bin/sh\nexit 7\n", encoding="utf-8")
            fake_zig.chmod(0o755)
            probe = collect_active_outer_probe(
                plan,
                repo_root=root,
                zig_executable=fake_zig,
                workers=4,
                timeout_seconds=5,
            )
        self.assertEqual(probe["status"], "unavailable")
        self.assertFalse(probe["comparison_eligible"])
        self.assertEqual(len(probe["attempts"]), 1)
        self.assertEqual(probe["attempts"][0]["return_code"], 7)
        self.assertIsNone(probe["summary"])

    def test_complete_recursive_report_yields_raw_diagnostic_ratios(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan = _plan(root)
            recursive = _recursive_report(plan)
            validate_recursive_report(recursive, plan=plan)
            comparison = build_comparison(plan, recursive_report=recursive, repo_root=root)
        row = comparison["rows"][0]
        end_to_end = row["aggregate_comparisons"]["verified_end_to_end_ns"]
        generation = row["aggregate_comparisons"]["published_proof_generation_ns"]
        proof_bytes = row["aggregate_comparisons"]["published_proof_bytes"]
        poseidon = row["aggregate_comparisons"][
            "proof_generation_poseidon2_permutations"
        ]
        peak_rss = row["aggregate_comparisons"]["peak_rss_bytes"]
        self.assertEqual(end_to_end["native_value"], 11_000_000)
        self.assertEqual(end_to_end["recursive_value"], 37_000_000)
        self.assertEqual(generation["status"], "available")
        self.assertEqual(generation["recursive_over_native_ppm"], 4_666_667)
        self.assertEqual(proof_bytes["recursive_over_native_ppm"], 500_000)
        self.assertEqual(peak_rss["recursive_over_native_ppm"], 500_000)
        self.assertEqual(poseidon["status"], "unavailable")
        self.assertTrue(comparison["comparability"]["same_sampling_schedule"])
        self.assertTrue(comparison["comparability"]["same_compiler_version"])
        self.assertTrue(comparison["comparability"]["comparable_peak_rss_scope"])
        self.assertFalse(comparison["comparability"]["publication_comparison_authority"])

    def test_absent_recursive_report_emits_no_ratios(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan = _plan(root)
            comparison = build_comparison(plan, recursive_report=None, repo_root=root)
        self.assertFalse(comparison["recursive_evidence_present"])
        self.assertTrue(
            all(
                metric["status"] == "unavailable"
                for metric in comparison["rows"][0]["aggregate_comparisons"].values()
            )
        )

    def test_recursive_report_rejects_workload_method_and_boundary_claim_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan = _plan(root)
        for mutate, message in (
            (
                lambda report: report["samples"][0]["workload"].update(input_size=129),
                "bind its workload",
            ),
            (
                lambda report: report["samples"][0]["phases"]["base_prove"][
                    "duration_ns"
                ].update(method="wrapper_wall_clock"),
                "method",
            ),
            (
                lambda report: report["boundary"].update(full_pipeline=False),
                "complete verified pipeline",
            ),
        ):
            report = _recursive_report(plan)
            mutate(report)
            report.pop("canonical_digest")
            report = seal_document(report)
            with self.assertRaisesRegex(EvidenceError, message):
                validate_recursive_report(report, plan=plan)

    def test_recursive_report_rejects_float_bool_negative_and_partition_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan = _plan(root)
        for invalid in (True, -1, 1.5):
            report = _recursive_report(plan)
            report["samples"][0]["phases"]["base_prove"]["duration_ns"]["value"] = invalid
            report.pop("canonical_digest")
            report = seal_document(report)
            with self.assertRaises(EvidenceError):
                validate_recursive_report(report, plan=plan)
        report = _recursive_report(plan)
        report["samples"][0]["aggregates"]["published_proof_generation_ns"]["value"] += 1
        report.pop("canonical_digest")
        report = seal_document(report)
        with self.assertRaisesRegex(EvidenceError, "partition"):
            validate_recursive_report(report, plan=plan)

    def test_recursive_report_rejects_attempt_artifact_and_rss_evidence_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan = _plan(root)
        mutations = (
            (
                lambda report: report["samples"][0]["attempts"].pop(),
                "exactly 4 attempts",
            ),
            (
                lambda report: report["samples"][0]["attempts"][0].update(
                    classification="measured"
                ),
                "pinned schedule",
            ),
            (
                lambda report: report["samples"][0]["attempts"][1]["phases"][
                    "base_prove"
                ]["duration_ns"].update(value=4_000_000),
                "duration mean",
            ),
            (
                lambda report: report["producer"]["artifact_contract"].update(
                    artifact_schema_version=2
                ),
                "artifact contract",
            ),
            (
                lambda report: report["producer"].update(invocation_sha256="f" * 64),
                "invocation digest",
            ),
            (
                lambda report: report["samples"][0]["attempts"][2][
                    "verification_receipt"
                ].update(payload_sha256="f" * 64),
                "does not bind the attempt",
            ),
            (
                lambda report: report["samples"][0]["aggregates"][
                    "peak_rss_bytes"
                ].update(method="wrapper_wall_clock"),
                "method",
            ),
        )
        for mutate, message in mutations:
            with self.subTest(message=message):
                report = _recursive_report(plan)
                mutate(report)
                report.pop("canonical_digest")
                report = seal_document(report)
                with self.assertRaisesRegex(EvidenceError, message):
                    validate_recursive_report(report, plan=plan)

    def test_atomic_publication_never_overwrites(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "report.json"
            atomic_write_new(destination, b"first\n")
            with self.assertRaisesRegex(EvidenceError, "overwrite"):
                atomic_write_new(destination, b"second\n")
            self.assertEqual(destination.read_bytes(), b"first\n")

    def test_canonical_report_has_no_floating_point_values(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan = _plan(root)
            encoded = canonical_bytes(plan)
        self.assertEqual(encoded, canonical_bytes(decode_json(encoded, label="round trip")))
        self.assertNotIn(b"NaN", encoded)
