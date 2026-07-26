"""Unit contracts for the installed RISC-V prove/verify/benchmark smoke."""

from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import riscv_staged_smoke as smoke
from scripts.riscv_staged_smoke_lib import contracts, mutations, profiles


DIGEST = "ab" * 32


def available_resources() -> dict[str, object]:
    return {
        "availability": "available",
        "source": "darwin.proc_pid_rusage.RUSAGE_INFO_V6",
        "scope": "self_process_lifetime",
        "unavailable_reason": None,
        "before_warmups": {
            "lifetime_max_phys_footprint_bytes": 1024,
            "energy_nj": 10,
            "instructions": 20,
            "cycles": 30,
        },
        "after_verified_samples": {
            "lifetime_max_phys_footprint_bytes": 2048,
            "energy_nj": 17,
            "instructions": 31,
            "cycles": 43,
        },
        "interval_delta": {"energy_nj": 7, "instructions": 11, "cycles": 13},
    }


def artifact() -> dict[str, object]:
    return {
        "artifact_kind": "stwo_riscv_proof",
        "schema_version": 4,
        "exchange_mode": "riscv_proof_json_wire_v4",
        "release_status": "not_release_gated",
        "generator": "zig",
        "air": "sail_rv32im_zkvm_v1",
        "backend": "cpu",
        "protocol": "functional",
        "source": {"elf_sha256": DIGEST, "input_sha256": DIGEST},
        "provenance": {
            "oracle_repository": "oracle",
            "oracle_commit": "cd" * 20,
            "implementation_repository": "implementation",
            "implementation_commit": "ef" * 20,
            "implementation_dirty": False,
            "witness_layout_sha256": DIGEST,
        },
        "pcs_config": {},
        "statement": {},
        "interaction_claim": {},
        "proof_bytes_hex": "01" * 32,
    }


class JsonContractTests(unittest.TestCase):
    def test_benchmark_elf_digest_matches_the_cross_verified_manifest(self) -> None:
        manifest = json.loads(
            (smoke.ROOT / "vectors/riscv_elfs/trace_vectors.json").read_text()
        )
        vector = next(item for item in manifest["vectors"] if item["name"] == "branch_fib")
        digest = hashlib.sha256((smoke.ROOT / smoke.ELF).read_bytes()).hexdigest()
        self.assertEqual(smoke.ELF_SHA256, digest)
        self.assertEqual(smoke.ELF_SHA256, vector["elf_sha256"])

    def test_strict_json_requires_one_object_and_rejects_nested_duplicates(self) -> None:
        self.assertEqual({"value": 1}, contracts.strict_json_object('{"value":1}', "test"))
        with self.assertRaisesRegex(contracts.ContractError, "duplicate JSON field value"):
            contracts.strict_json_object('{"nested":{"value":1,"value":2}}', "test")
        with self.assertRaisesRegex(contracts.ContractError, "one JSON object"):
            contracts.strict_json_object("[]", "test")
        with self.assertRaisesRegex(contracts.ContractError, "invalid JSON"):
            contracts.strict_json_object("{} {}", "test")

    def test_artifact_contract_binds_exact_fields_source_and_build(self) -> None:
        payload = artifact()
        contracts.validate_artifact(
            payload,
            expected_status="not_release_gated",
            expected_commit="ef" * 20,
            expected_dirty=False,
            elf_sha256=DIGEST,
            input_sha256=DIGEST,
            witness_layout_sha256=DIGEST,
        )
        payload["verified"] = True
        with self.assertRaisesRegex(contracts.ContractError, "fields drifted"):
            contracts.validate_artifact(
                payload,
                expected_status="not_release_gated",
                expected_commit="ef" * 20,
                expected_dirty=False,
                elf_sha256=DIGEST,
                input_sha256=DIGEST,
                witness_layout_sha256=DIGEST,
            )

    def test_verify_receipt_binds_statement_policy_and_proof_digest(self) -> None:
        proof = b"proof-wire"
        receipt = {
            "schema": "riscv_verify_v1",
            "status": "verified",
            "artifact_kind": "stwo_riscv_proof",
            "artifact_schema_version": 4,
            "release_status": "not_release_gated",
            "security_policy": "functional",
            "statement_sha256": DIGEST,
            "proof_bytes": len(proof),
            "proof_sha256": hashlib.sha256(proof).hexdigest(),
            "transcript_state_blake2s": DIGEST,
            "implementation_commit": "ef" * 20,
            "implementation_dirty": False,
            "executable_sha256": DIGEST,
        }
        contracts.validate_verify_receipt(
            receipt,
            expected_status="not_release_gated",
            policy="functional",
            statement_sha256=DIGEST,
            proof_bytes=proof,
            transcript_state_blake2s=DIGEST,
            expected_commit="ef" * 20,
            expected_dirty=False,
            executable_sha256=DIGEST,
        )
        receipt["security_policy"] = "smoke"
        with self.assertRaisesRegex(contracts.ContractError, "values drifted"):
            contracts.validate_verify_receipt(
                receipt,
                expected_status="not_release_gated",
                policy="functional",
                statement_sha256=DIGEST,
                proof_bytes=proof,
                transcript_state_blake2s=DIGEST,
                expected_commit="ef" * 20,
                expected_dirty=False,
                executable_sha256=DIGEST,
            )

    def test_prove_report_has_phase_neutral_exact_schema(self) -> None:
        report = {
            "schema": "riscv_prove_v1",
            "release_status": "not_release_gated",
            "experimental": True,
            "verified_in_process": True,
            "total_steps": 8,
            "n_components": 3,
            "execution_seconds": 0.1,
            "witness_seconds": 0.2,
            "proving_seconds": 0.3,
            "verification_seconds": 0.4,
            "total_seconds": 1.0,
            "statement_sha256": DIGEST,
            "transcript_state_blake2s": DIGEST,
            "implementation_commit": "ef" * 20,
            "implementation_dirty": False,
            "executable_sha256": DIGEST,
            "proof_path": "proof.json",
        }
        contracts.validate_prove_report(
            report,
            expected_status="not_release_gated",
            experimental=True,
            statement_sha256=DIGEST,
            proof_path="proof.json",
            expected_commit="ef" * 20,
            expected_dirty=False,
            executable_sha256=DIGEST,
        )
        report["schema"] = "riscv-staged-report-v1"
        with self.assertRaisesRegex(contracts.ContractError, "schema/release status drifted"):
            contracts.validate_prove_report(
                report,
                expected_status="not_release_gated",
                experimental=True,
                statement_sha256=DIGEST,
                proof_path="proof.json",
                expected_commit="ef" * 20,
                expected_dirty=False,
                executable_sha256=DIGEST,
            )

    def test_benchmark_report_binds_samples_timing_and_retained_artifact(self) -> None:
        report = {
            "schema": "riscv_proof_v2",
            "release_status": "not_release_gated",
            "mode": "bench",
            "experimental": True,
            "profiled": False,
            "warmups": 0,
            "samples": 2,
            "verified_samples": 2,
            "total_steps": 8,
            "n_components": 3,
            "throughput_numerator": "vm_steps",
            "median_seconds": 1.0,
            "throughput_mhz": 0.1,
            "mean_execution_seconds": 0.1,
            "mean_witness_seconds": 0.2,
            "mean_proving_seconds": 0.3,
            "mean_verification_seconds": 0.4,
            "sample_seconds": [0.9, 1.0],
            "statement_sha256": DIGEST,
            "transcript_state_blake2s": DIGEST,
            "implementation_commit": "ef" * 20,
            "implementation_dirty": False,
            "executable_sha256": DIGEST,
            "artifact_sha256": DIGEST,
            "proof_path": "bench-proof.json",
            "resources": available_resources(),
        }
        contracts.validate_benchmark_report(
            report,
            expected_status="not_release_gated",
            experimental=True,
            warmups=0,
            samples=2,
            proof_path="bench-proof.json",
            expected_commit="ef" * 20,
            expected_dirty=False,
            executable_sha256=DIGEST,
        )
        report["verified_samples"] = 1
        with self.assertRaisesRegex(contracts.ContractError, "sample accounting drifted"):
            contracts.validate_benchmark_report(
                report,
                expected_status="not_release_gated",
                experimental=True,
                warmups=0,
                samples=2,
                proof_path="bench-proof.json",
                expected_commit="ef" * 20,
                expected_dirty=False,
                executable_sha256=DIGEST,
            )

    def test_benchmark_resources_fail_closed_and_allow_explicit_nondarwin_state(self) -> None:
        unavailable = {
            "availability": "unavailable",
            "source": "darwin.proc_pid_rusage.RUSAGE_INFO_V6",
            "scope": "self_process_lifetime",
            "unavailable_reason": "unsupported_platform",
            "before_warmups": None,
            "after_verified_samples": None,
            "interval_delta": None,
        }
        contracts.validate_resource_usage(unavailable, require_available=False)
        with self.assertRaisesRegex(contracts.ContractError, "V6 counters are required"):
            contracts.validate_resource_usage(unavailable, require_available=True)

        inconsistent = available_resources()
        inconsistent["interval_delta"]["energy_nj"] = 8
        with self.assertRaisesRegex(contracts.ContractError, "energy_nj: inconsistent"):
            contracts.validate_resource_usage(inconsistent, require_available=True)

    def test_registry_requires_exact_single_riscv_phase_entry(self) -> None:
        payload = {
            "schema_version": 1,
            "backend_availability": {"cpu": True, "metal-hybrid": True},
            "product_matrix": {
                "native_cpu": {
                    "product_id": "stwo-native-cpu",
                    "state": "released",
                },
                "native_metal": {
                    "product_id": "stwo-native-metal",
                    "state": "parity_gated",
                    "selected": True,
                },
            },
            "applications": [],
            "deferred_adapters": [{
                "adapter": "sail-rv32im-zkvm-elf",
                "status": "not_release_gated",
                "isa": "rv32im",
                "backends": ["cpu"],
            }],
        }
        contracts.validate_registry(payload, "not_release_gated")
        payload["applications"] = list(payload["deferred_adapters"])
        with self.assertRaisesRegex(contracts.ContractError, "release status drifted"):
            contracts.validate_registry(payload, "not_release_gated")

    def test_registry_product_matrix_is_exact_and_tracks_metal_selection(self) -> None:
        payload = {
            "schema_version": 1,
            "backend_availability": {"cpu": True, "metal-hybrid": False},
            "product_matrix": {
                "native_cpu": {
                    "product_id": "stwo-native-cpu",
                    "state": "released",
                },
                "native_metal": {
                    "product_id": "stwo-native-metal",
                    "state": "parity_gated",
                    "selected": False,
                },
            },
            "applications": [],
            "deferred_adapters": [{
                "adapter": "sail-rv32im-zkvm-elf",
                "status": "not_release_gated",
                "isa": "rv32im",
                "backends": ["cpu"],
            }],
        }
        contracts.validate_registry(payload, "not_release_gated")

        payload["product_matrix"]["native_metal"]["selected"] = True
        with self.assertRaisesRegex(contracts.ContractError, "Native Metal"):
            contracts.validate_registry(payload, "not_release_gated")

        payload["product_matrix"]["native_metal"]["selected"] = False
        payload["product_matrix"]["native_cpu"]["extra"] = True
        with self.assertRaisesRegex(contracts.ContractError, "fields drifted"):
            contracts.validate_registry(payload, "not_release_gated")


class MutationTests(unittest.TestCase):
    def test_same_family_claim_swap_preserves_indices_and_global_multiset(self) -> None:
        payload = artifact()
        payload["statement"] = {"components": [
            {"family": 1, "family_shard_count": 2, "family_shard_index": 0},
            {"family": 1, "family_shard_count": 2, "family_shard_index": 1},
            {"family": 2, "family_shard_count": 1, "family_shard_index": 0},
        ]}
        payload["interaction_claim"] = {"opcode_claims": [
            {"component_index": 0, "claimed_sums": [[1, 2, 3, 4], [5, 6, 7, 8]]},
            {"component_index": 1, "claimed_sums": [[9, 10, 11, 12], [13, 14, 15, 16]]},
            {"component_index": 2, "claimed_sums": [[17, 18, 19, 20]]},
        ]}
        original_claims = payload["interaction_claim"]["opcode_claims"]
        before = sorted(
            json.dumps(value)
            for claim in original_claims
            for value in claim["claimed_sums"]
        )

        mutated, indices = mutations.swap_same_family_opcode_claims(payload)

        self.assertEqual((0, 1), indices)
        self.assertEqual([0, 1, 2], [
            claim["component_index"]
            for claim in mutated["interaction_claim"]["opcode_claims"]
        ])
        self.assertEqual(
            original_claims[1]["claimed_sums"],
            mutated["interaction_claim"]["opcode_claims"][0]["claimed_sums"],
        )
        after = sorted(
            json.dumps(value)
            for claim in mutated["interaction_claim"]["opcode_claims"]
            for value in claim["claimed_sums"]
        )
        self.assertEqual(before, after)
        self.assertEqual(0, payload["interaction_claim"]["opcode_claims"][0]["component_index"])

    def test_same_family_claim_swap_rejects_a_noop(self) -> None:
        payload = artifact()
        payload["statement"] = {"components": [
            {"family": 1, "family_shard_count": 2, "family_shard_index": 0},
            {"family": 1, "family_shard_count": 2, "family_shard_index": 1},
        ]}
        payload["interaction_claim"] = {"opcode_claims": [
            {"component_index": 0, "claimed_sums": [[1, 2, 3, 4]]},
            {"component_index": 1, "claimed_sums": [[1, 2, 3, 4]]},
        ]}
        with self.assertRaisesRegex(ValueError, "no distinct adjacent same-family"):
            mutations.swap_same_family_opcode_claims(payload)

    def test_hostile_artifact_set_covers_routing_shape_and_relabel(self) -> None:
        payload = artifact()
        rendered = json.dumps(payload, separators=(",", ":"))
        cases = mutations.hostile_json(rendered, payload)
        self.assertEqual({
            "corrupt-json", "legacy-schema-v2", "duplicate-header", "unknown-field",
            "omitted-claim", "release-relabel",
        }, set(cases))
        self.assertIn('"schema_version":4,"schema_version":4', cases["duplicate-header"][0])
        self.assertEqual("not_release_gated", payload["release_status"])

    def test_proof_wire_mutations_are_distinct_and_bounded(self) -> None:
        # Five config integers, absent lifting log, zero commitments, and payload.
        proof = bytes([1, 1, 1, 1, 1, 0, 0, 9, 8, 7])
        cases = mutations.proof_wire(proof.hex())
        self.assertEqual({"trailing", "truncated", "length-bomb"}, set(cases))
        self.assertEqual(proof + b"\x00", bytes.fromhex(cases["trailing"]))
        self.assertEqual(proof[:-1], bytes.fromhex(cases["truncated"]))


class ProcessBoundaryTests(unittest.TestCase):
    def test_command_has_a_finite_timeout_and_captures_both_streams(self) -> None:
        completed = subprocess.CompletedProcess(["cli"], 0, "{}\n", "")
        with mock.patch("scripts.riscv_staged_smoke.subprocess.run", return_value=completed) as run:
            self.assertIs(completed, smoke.command(Path("cli"), "applications"))
        self.assertEqual(smoke.COMMAND_TIMEOUT_SECONDS, run.call_args.kwargs["timeout"])
        self.assertTrue(run.call_args.kwargs["capture_output"])
        self.assertTrue(run.call_args.kwargs["text"])

    def test_rejection_requires_nonzero_exit_no_outputs_and_named_error(self) -> None:
        result = subprocess.CompletedProcess(["cli"], 1, "", "error: InvalidMagic\n")
        evidence = smoke.require_rejection(result, (), "malformed", ("InvalidMagic",))
        self.assertEqual(1, evidence["returncode"])
        with self.assertRaisesRegex(contracts.ContractError, "published output"):
            smoke.require_rejection(
                subprocess.CompletedProcess(["cli"], 0, "{}", ""), (), "accepted",
            )

    def test_prebuilt_cli_skips_the_build_and_timing_counts_commands(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cli = Path(directory) / "stwo-zig"
            cli.write_bytes(b"prebuilt")
            with mock.patch("scripts.riscv_staged_smoke.subprocess.run") as run:
                resolved, origin, build_count, build_duration = smoke.prepare_cli(cli)
            self.assertEqual(cli.resolve(), resolved)
            self.assertEqual("prebuilt", origin)
            self.assertEqual(0, build_count)
            self.assertGreaterEqual(build_duration, 0)
            run.assert_not_called()

        metrics = [
            {"ordinal": 0, "argv": ["applications"], "duration_ns": 7, "returncode": 0},
            {"ordinal": 1, "argv": ["verify"], "duration_ns": 11, "returncode": 1},
        ]
        with mock.patch("scripts.riscv_staged_smoke.time.monotonic_ns", return_value=100):
            timing = smoke.timing_evidence(
                metrics, smoke_started=20, build_command_count=0, build_duration_ns=3,
            )
        self.assertEqual(2, timing["cli_command_count"])
        self.assertEqual(18, timing["cli_command_duration_ns"])
        self.assertEqual(80, timing["wall_duration_ns"])


class ProfileContractTests(unittest.TestCase):
    COMMIT = "c" * 40

    @staticmethod
    def exhaustive_summary(executable_sha256: str) -> dict[str, object]:
        return {
            "schema": "riscv_cli_evidence_v1",
            "phase": "candidate",
            "release_status": "not_release_gated",
            "implementation_commit": ProfileContractTests.COMMIT,
            "implementation_dirty": False,
            "executable_sha256": executable_sha256,
            "total_steps": 131_078,
            "artifact_sha256": DIGEST,
            "report_sha256": DIGEST,
            "benchmark_report_sha256": DIGEST,
            "benchmark_artifact_sha256": DIGEST,
            "verify_receipt_sha256": DIGEST,
            "benchmark_verify_receipt_sha256": DIGEST,
            "independent_verify_returncode": 0,
            "tamper_returncode": 1,
            "proof_wire_mutation_returncodes": {
                name: {"returncode": 1} for name in profiles.PROOF_WIRE_MUTATIONS
            },
            "hostile_artifact_results": {
                name: {"returncode": 1} for name in profiles.HOSTILE_ARTIFACT_MUTATIONS
            },
            "boundary_rejection_results": {"malformed-elf": {"returncode": 1}},
        }

    def bundle(self, root: Path) -> tuple[Path, Path]:
        cli = root / "bin" / "stwo-zig"
        cli.parent.mkdir(parents=True)
        cli.write_bytes(b"exact prebuilt executable")
        executable_sha256 = profiles.sha256_file(cli)
        summary = root / "cli" / "summary.json"
        summary.parent.mkdir(parents=True)
        summary.write_text(
            json.dumps(self.exhaustive_summary(executable_sha256)), encoding="utf-8",
        )
        manifest = {
            "schema": profiles.PRODUCER_SCHEMA,
            "phase": "candidate",
            "candidate_commit": self.COMMIT,
            "coverage": dict(profiles.REQUIRED_COVERAGE),
            "producer": {"repository": "owner/repo", "run_id": "1"},
            "release_policy": {
                "schema": "riscv-release-policy-match-v1",
                "candidate_commit": self.COMMIT,
            },
            "domains": {"repository": {"sha256": DIGEST}},
            "files": {
                "bin/stwo-zig": {
                    "sha256": executable_sha256,
                    "size": cli.stat().st_size,
                },
                "cli/summary.json": {
                    "sha256": profiles.sha256_file(summary),
                    "size": summary.stat().st_size,
                },
            },
        }
        receipt = root / "manifest.json"
        receipt.write_text(json.dumps(manifest), encoding="utf-8")
        return cli, receipt

    def test_fast_profile_authenticates_cli_and_exhaustive_summary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cli, receipt = self.bundle(Path(directory))
            link = profiles.validate_producer_receipt(
                receipt,
                cli,
                phase="candidate",
                candidate_commit=self.COMMIT,
                implementation_dirty=False,
            )
            self.assertEqual(profiles.PRODUCER_SCHEMA, link["schema"])
            self.assertEqual(profiles.sha256_file(cli), link["executable"]["sha256"])
            self.assertEqual(
                profiles.sha256_file(receipt), link["manifest_sha256"],
            )

    def test_fast_profile_fails_closed_on_dirty_or_drifted_producer(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cli, receipt = self.bundle(Path(directory))
            with self.assertRaisesRegex(contracts.ContractError, "clean checkout"):
                profiles.validate_producer_receipt(
                    receipt,
                    cli,
                    phase="candidate",
                    candidate_commit=self.COMMIT,
                    implementation_dirty=True,
                )
            cli.write_bytes(b"drifted")
            with self.assertRaisesRegex(contracts.ContractError, "bundled file drifted"):
                profiles.validate_producer_receipt(
                    receipt,
                    cli,
                    phase="candidate",
                    candidate_commit=self.COMMIT,
                    implementation_dirty=False,
                )

    def test_fast_profile_rejects_non_exhaustive_linkage(self) -> None:
        summary = self.exhaustive_summary(DIGEST)
        summary["schema"] = "riscv_cli_evidence_v2"
        summary["profile"] = "fast"
        with self.assertRaisesRegex(contracts.ContractError, "not exhaustive"):
            profiles.validate_exhaustive_summary(
                summary,
                phase="candidate",
                candidate_commit=self.COMMIT,
                executable_sha256=DIGEST,
            )


if __name__ == "__main__":
    unittest.main()
