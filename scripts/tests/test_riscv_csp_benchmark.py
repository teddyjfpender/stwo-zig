from __future__ import annotations

import argparse
import copy
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import riscv_cli_admission
from scripts import riscv_csp_benchmark as csp
from scripts.riscv_csp_benchmark_lib import build_identity as csp_build_identity
from scripts.riscv_csp_benchmark_lib import contract as csp_contract
from scripts.riscv_csp_benchmark_lib import host as csp_host


class ManifestContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest, cls.cases, cls.negative_cases = csp.validate_manifest()

    def test_checked_manifest_is_the_complete_pinned_workload_matrix(self) -> None:
        self.assertEqual(
            "269c43cc32d3127e3d9ce74d20652887d894cca3",
            self.manifest["upstream"]["commit"],
        )
        self.assertEqual(
            [
                (target, size)
                for target in csp.TARGET_ORDER
                for size in csp.TARGET_SIZES[target]
            ],
            [(case.target, case.input_size) for case in self.cases],
        )
        self.assertTrue(all(not case.uses_precompile for case in self.cases))
        self.assertEqual(
            [("ecdsa_secp256k1_bad_signature", "ecdsa_secp256k1")],
            [(case.name, case.target) for case in self.negative_cases],
        )

    def test_every_committed_fixture_is_authenticated(self) -> None:
        for case in self.cases:
            self.assertEqual(case.input_sha256, csp.sha256_file(case.input_path))
            self.assertEqual(case.guest_sha256, csp.sha256_file(case.guest_path))
        for case in self.negative_cases:
            self.assertEqual(case.input_sha256, csp.sha256_file(case.input_path))

    def test_manifest_rejects_duplicate_json_fields(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "duplicate.json"
            path.write_text(
                '{"schema":"stwo_riscv_csp_suite_v2","schema":"substitution"}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(csp.BenchmarkError, "repeats field"):
                csp.load_json(path)

    def test_manifest_target_substitution_fails_closed(self) -> None:
        changed = copy.deepcopy(self.manifest)
        changed["targets"]["sha256"]["uses_precompile"] = True
        with mock.patch.object(csp_contract, "load_json", return_value=changed):
            with self.assertRaisesRegex(csp.BenchmarkError, "explicit RV32IM"):
                csp.validate_manifest()

    def test_unsupported_target_ledger_cannot_silently_shrink(self) -> None:
        changed = copy.deepcopy(self.manifest)
        del changed["unsupported_targets"]["ecdsa_p256"]
        with mock.patch.object(csp_contract, "load_json", return_value=changed):
            with self.assertRaisesRegex(csp.BenchmarkError, "ledger drifted"):
                csp.validate_manifest()

    def test_poseidon_extension_cannot_be_relabelled_canonical(self) -> None:
        changed = copy.deepcopy(self.manifest)
        changed["targets"]["poseidon2_m31"]["comparison_class"] = "csp_canonical"
        with mock.patch.object(csp_contract, "load_json", return_value=changed):
            with self.assertRaisesRegex(csp.BenchmarkError, "workload contract"):
                csp.validate_manifest()

    def test_repository_guest_source_mutation_fails_closed(self) -> None:
        changed = copy.deepcopy(self.manifest)
        changed["targets"]["ecdsa_secp256k1"]["guest"]["source_files"][0][
            "sha256"
        ] = "0" * 64
        with mock.patch.object(csp_contract, "load_json", return_value=changed):
            with self.assertRaisesRegex(
                csp.BenchmarkError,
                "repository source binding drifted",
            ):
                csp.validate_manifest()

    def test_input_fixture_bit_flip_is_rejected(self) -> None:
        target = csp.ROOT / "vectors" / "riscv_csp" / "inputs" / "msg_128.bin"
        original_read_bytes = Path.read_bytes

        def read_with_mutation(path: Path) -> bytes:
            value = original_read_bytes(path)
            if path.resolve() == target.resolve():
                mutated = bytearray(value)
                mutated[-1] ^= 1
                return bytes(mutated)
            return value

        with mock.patch.object(Path, "read_bytes", read_with_mutation):
            with self.assertRaisesRegex(csp.BenchmarkError, "input digest drifted"):
                csp.validate_manifest()

    def test_negative_signature_fixture_bit_flip_is_rejected(self) -> None:
        target = (
            csp.ROOT
            / "vectors"
            / "riscv_csp"
            / "inputs"
            / "ecdsa_secp256k1_bad_signature.bin"
        )
        original_read_bytes = Path.read_bytes

        def read_with_mutation(path: Path) -> bytes:
            value = original_read_bytes(path)
            if path.resolve() == target.resolve():
                mutated = bytearray(value)
                mutated[-2] ^= 1
                return bytes(mutated)
            return value

        with mock.patch.object(Path, "read_bytes", read_with_mutation):
            with self.assertRaisesRegex(
                csp.BenchmarkError,
                "negative fixture 0 binding drifted",
            ):
                csp.validate_manifest()

    def test_noncanonical_m31_fixture_is_rejected_before_hash_check(self) -> None:
        target = (
            csp.ROOT
            / "vectors"
            / "riscv_csp"
            / "inputs"
            / "field_m31_2.bin"
        )
        original_read_bytes = Path.read_bytes

        def read_with_mutation(path: Path) -> bytes:
            value = original_read_bytes(path)
            if path.resolve() == target.resolve():
                mutated = bytearray(value)
                mutated[4:8] = ((1 << 31) - 1).to_bytes(4, "little")
                return bytes(mutated)
            return value

        with mock.patch.object(Path, "read_bytes", read_with_mutation):
            with self.assertRaisesRegex(csp.BenchmarkError, "noncanonical M31"):
                csp.validate_manifest()


class PublicOutputContractTests(unittest.TestCase):
    @staticmethod
    def diagnostic(last_word: int = 0x00000065) -> dict:
        return {
            "schema": "riscv-public-values-diagnostic-v1",
            "public_data": {
                "io_entries": {
                    "output_len": 5,
                    "output_len_addr": 0x2000,
                    "output_data_addr": 0x2004,
                    "output_words": [
                        {"addr": 0x2000, "value": 5},
                        {"addr": 0x2004, "value": 0x64636261},
                        {"addr": 0x2008, "value": last_word},
                    ],
                }
            },
        }

    def test_output_words_reconstruct_exact_little_endian_bytes(self) -> None:
        self.assertEqual(b"abcde", csp.reconstruct_public_output(self.diagnostic()))

    def test_nonzero_output_padding_is_rejected(self) -> None:
        with self.assertRaisesRegex(csp.BenchmarkError, "padding is nonzero"):
            csp.reconstruct_public_output(self.diagnostic(last_word=0x00000165))


class VerificationReceiptContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.case = csp.validate_manifest()[1][0]

    @staticmethod
    def receipt() -> dict:
        return {
            "schema": "riscv_verify_v1",
            "status": "verified",
            "statement_sha256": "a" * 64,
            "proof_bytes": 3,
            "proof_sha256": csp.sha256_bytes(b"air"),
            "implementation_commit": "b" * 40,
            "implementation_dirty": False,
        }

    def validate(self, receipt: dict) -> None:
        csp.validate_verify_receipt(
            receipt,
            self.case,
            statement_digest="a" * 64,
            proof_bytes=b"air",
            proof_sha256=csp.sha256_bytes(b"air"),
            implementation_commit="b" * 40,
        )

    def test_production_receipt_contract_is_accepted(self) -> None:
        self.validate(self.receipt())

    def test_boolean_verified_substitution_is_rejected(self) -> None:
        changed = self.receipt()
        changed.pop("status")
        changed["verified"] = True
        with self.assertRaisesRegex(csp.BenchmarkError, "receipt drifted"):
            self.validate(changed)

    def test_wrong_proof_binding_is_rejected(self) -> None:
        changed = self.receipt()
        changed["proof_sha256"] = "0" * 64
        with self.assertRaisesRegex(csp.BenchmarkError, "receipt drifted"):
            self.validate(changed)


class HostEvidenceTests(unittest.TestCase):
    def test_report_host_metadata_excludes_network_identity(self) -> None:
        host = csp.collect_host()
        self.assertNotIn("hostname", host)
        self.assertEqual(
            {
                "architecture",
                "cpu",
                "gpu",
                "kernel",
                "logical_cpu_count",
                "low_power_mode",
                "memory_bytes",
                "os",
                "os_version",
                "power_source",
                "python",
            },
            set(host),
        )

    def test_gpu_evidence_has_one_schema_across_backends(self) -> None:
        host = csp.collect_host()
        self.assertEqual(
            {"name", "core_count", "metal_support", "unified_memory"},
            set(host["gpu"]),
        )

    def test_power_evidence_is_captured_like_gpu_evidence(self) -> None:
        host = csp.collect_host()
        self.assertIn(type(host["power_source"]), (str, type(None)))
        self.assertIn(type(host["low_power_mode"]), (bool, type(None)))


class PowerEvidenceCaptureTests(unittest.TestCase):
    BATTERY = "Now drawing from 'Battery Power'\n -InternalBattery-0 90%\n"
    SETTINGS = "System-wide power settings:\nCurrently in use:\n powermode 1\n"

    @staticmethod
    def pmset(outputs: dict[tuple[str, ...], str]):
        def run(command, **_: object):
            key = tuple(command[1:])
            if key not in outputs:
                raise OSError("pmset is unavailable")
            return subprocess.CompletedProcess(command, 0, outputs[key], "")

        return run

    def test_pmset_output_becomes_power_evidence(self) -> None:
        run = self.pmset(
            {
                ("-g", "batt"): self.BATTERY,
                ("-g",): self.SETTINGS,
            }
        )
        with mock.patch.object(csp_host.subprocess, "run", run):
            self.assertEqual(("Battery Power", True), csp_host._power_evidence())

    def test_absent_pmset_degrades_to_unknown_instead_of_failing(self) -> None:
        with mock.patch.object(csp_host.subprocess, "run", self.pmset({})):
            self.assertEqual((None, None), csp_host._power_evidence())


class PowerConditionTests(unittest.TestCase):
    @staticmethod
    def host(**overrides: object) -> dict:
        host: dict = {"power_source": "AC Power", "low_power_mode": False}
        host.update(overrides)
        return host

    def test_ac_power_without_low_power_mode_is_admissible(self) -> None:
        self.assertEqual(
            (True, []),
            csp.power_conditions_admissible(self.host()),
        )

    def test_battery_power_is_refused(self) -> None:
        admissible, reasons = csp.power_conditions_admissible(
            self.host(power_source="Battery Power")
        )
        self.assertFalse(admissible)
        self.assertEqual(
            ["CSP-comparable timings require AC power (observed: Battery Power)"],
            reasons,
        )

    def test_low_power_mode_on_ac_is_refused(self) -> None:
        admissible, reasons = csp.power_conditions_admissible(
            self.host(low_power_mode=True)
        )
        self.assertFalse(admissible)
        self.assertEqual(
            [
                "CSP-comparable timings require low power mode disabled "
                "(observed: enabled)"
            ],
            reasons,
        )

    def test_missing_power_evidence_fails_closed(self) -> None:
        admissible, reasons = csp.power_conditions_admissible(
            self.host(power_source=None, low_power_mode=None)
        )
        self.assertFalse(admissible)
        self.assertEqual(2, len(reasons))
        self.assertIn("no power-source evidence", reasons[0])
        self.assertIn("no evidence", reasons[1])


class ResultClassTests(unittest.TestCase):
    @staticmethod
    def classify(**overrides: bool) -> str:
        arguments = {
            "host_matches": True,
            "power_admissible": True,
            "complete_matrix": True,
            "memory_available": True,
        }
        arguments.update(overrides)
        return csp.classify_result(**arguments)

    def test_clean_official_host_run_is_comparable(self) -> None:
        self.assertEqual("official-host-comparable", self.classify())

    def test_battery_run_is_never_reported_as_a_clean_measurement(self) -> None:
        self.assertEqual(
            "power-condition-non-publishable",
            self.classify(power_admissible=False),
        )

    def test_power_condition_outranks_the_host_comparison(self) -> None:
        # A throttled run on a non-official host must not be filed under the
        # ordinary host qualification: it is not a valid measurement at all.
        self.assertEqual(
            "power-condition-non-publishable",
            self.classify(host_matches=False, power_admissible=False),
        )

    def test_incomplete_evidence_stays_host_qualified(self) -> None:
        for field in ("host_matches", "complete_matrix", "memory_available"):
            with self.subTest(field=field):
                self.assertEqual(
                    "host-qualified-non-comparable",
                    self.classify(**{field: False}),
                )


class BuildIdentityTests(unittest.TestCase):
    @staticmethod
    def registry(**overrides: object) -> bytes:
        product = {
            "schema_version": 2,
            "name": "stwo-riscv-cpu",
            "frontend": "sail-rv32im-zkvm",
            "backend": "cpu",
            "target": {
                "arch": "aarch64",
                "os": "macos",
                "abi": "none",
                "cpu_model": "apple_m1",
                "cpu_features_sha256": "0" * 64,
            },
            "optimize": "ReleaseFast",
        }
        product["target"].update(overrides.pop("target", {}))
        product.update(overrides)
        return json.dumps({"schema_version": 1, "product": product}).encode()

    def validate(self, raw: bytes) -> dict:
        identity = csp_build_identity.parse_build_identity(raw)
        csp_build_identity.validate_build_identity(
            identity,
            machine="arm64",
            system="Darwin",
        )
        return identity

    def test_optimize_mode_is_recoverable_from_the_admitted_identity(self) -> None:
        # The check reads the same focused-product surface admission already
        # authenticates, rather than a second provenance channel.
        self.assertLessEqual(
            {"target", "optimize"},
            riscv_cli_admission.FOCUSED_PRODUCT_FIELDS,
        )

    def test_release_fast_host_binary_is_admitted(self) -> None:
        self.assertEqual(
            {
                "arch": "aarch64",
                "os": "macos",
                "abi": "none",
                "cpu_model": "apple_m1",
                "optimize": "ReleaseFast",
            },
            self.validate(self.registry()),
        )

    def test_debug_binary_is_refused(self) -> None:
        for mode in ("Debug", "ReleaseSafe", "ReleaseSmall"):
            with self.subTest(optimize=mode):
                with self.assertRaisesRegex(
                    csp.BenchmarkError,
                    "require -Doptimize=ReleaseFast",
                ):
                    self.validate(self.registry(optimize=mode))

    def test_translated_foreign_architecture_binary_is_refused(self) -> None:
        with self.assertRaisesRegex(csp.BenchmarkError, "targets x86_64-macos"):
            self.validate(self.registry(target={"arch": "x86_64"}))

    def test_foreign_operating_system_binary_is_refused(self) -> None:
        with self.assertRaisesRegex(csp.BenchmarkError, "targets aarch64-linux"):
            self.validate(self.registry(target={"os": "linux"}))

    def test_unmappable_host_fails_closed(self) -> None:
        identity = csp_build_identity.parse_build_identity(self.registry())
        with self.assertRaisesRegex(csp.BenchmarkError, "cannot map host"):
            csp_build_identity.validate_build_identity(
                identity,
                machine="riscv64",
                system="Darwin",
            )

    def test_registry_without_a_build_identity_fails_closed(self) -> None:
        aggregate = json.dumps(
            {
                "schema_version": 1,
                "backend_availability": {"cpu": True, "metal-hybrid": False},
                "product_matrix": {},
            }
        ).encode()
        with self.assertRaisesRegex(
            csp.BenchmarkError,
            "publishes no build identity",
        ):
            csp_build_identity.parse_build_identity(aggregate)

    def test_partial_build_identity_is_refused(self) -> None:
        with self.assertRaisesRegex(csp.BenchmarkError, "identity is incomplete"):
            csp_build_identity.parse_build_identity(
                self.registry(target={"cpu_model": None})
            )

    def test_registry_rejects_duplicate_json_fields(self) -> None:
        raw = b'{"schema_version":1,"product":{},"product":{}}'
        with self.assertRaisesRegex(csp.BenchmarkError, "repeats field"):
            csp_build_identity.parse_build_identity(raw)

    def test_unexecutable_binary_names_the_architecture_hypothesis(self) -> None:
        def run(command, **_: object):
            raise OSError(8, "Exec format error")

        with mock.patch.object(csp_build_identity.subprocess, "run", run):
            with self.assertRaisesRegex(
                csp.BenchmarkError,
                "built for another architecture",
            ):
                csp_build_identity.read_build_identity(Path("/opt/example/prover"))


class RetainedReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.report = csp.load_json(csp.DEFAULT_REPORT)
        cls.manifest_path = csp.MANIFEST
        cls.manifest, _, cls.negative_cases = csp.validate_manifest()
        cls.raw_cases = [
            (target, case, spec["guest"])
            for target, spec in cls.manifest["targets"].items()
            for case in spec["cases"]
        ]

    def test_report_is_the_complete_verified_standard_matrix(self) -> None:
        report = self.report
        self.assertEqual(csp.SCHEMA, report["schema"])
        self.assertEqual(
            str(csp.MANIFEST.relative_to(csp.ROOT)),
            report["suite_manifest"],
        )
        self.assertEqual(report["measurement_commit"], report["repository_head"])
        self.assertRegex(report["measurement_commit"], csp.HEX_40)
        self.assertEqual(
            csp.sha256_file(self.manifest_path),
            report["suite_manifest_sha256"],
        )
        summary = report["summary"]
        self.assertTrue(summary["all_outputs_match"])
        self.assertTrue(summary["all_peak_memory_available"])
        self.assertTrue(summary["all_proofs_verified"])
        self.assertEqual(len(self.raw_cases), summary["row_count"])
        self.assertEqual(len(self.manifest["targets"]), summary["target_count"])
        self.assertEqual(
            list(self.manifest["targets"]),
            report["run"]["targets"],
        )
        self.assertEqual(
            sorted({case["input_size"] for _, case, _ in self.raw_cases}),
            report["run"]["sizes"],
        )
        self.assertEqual(1, report["run"]["warmups"])
        self.assertEqual(10, report["run"]["samples"])
        self.assertTrue(report["run"]["complete_matrix"])
        # Transitional: the committed report predates the backend dimension.
        # Make this strict (report["run"]["backend"]) once the committed CPU
        # evidence is regenerated with the full secure-profile matrix.
        self.assertEqual("cpu", report["run"].get("backend", "cpu"))

        measurements = report["measurements"]
        self.assertEqual(
            [
                (target, case["input_size"])
                for target, case, _ in self.raw_cases
            ],
            [(row["target"], row["input_size"]) for row in measurements],
        )
        for (target, case, guest), row in zip(
            self.raw_cases,
            measurements,
            strict=True,
        ):
            with self.subTest(target=target, size=case["input_size"]):
                # Transitional, as with run.backend above.
                self.assertEqual("cpu", row.get("backend", "cpu"))
                self.assertEqual(case["expected_cycles"], row["cycles"])
                self.assertEqual(guest["bytes"], row["preprocessing_size"])
                self.assertFalse(row["uses_precompile"])
                self.assertGreater(row["proof_duration"], 0)
                self.assertGreater(row["verify_duration"], 0)
                self.assertGreater(row["proof_size"], 0)
                self.assertGreater(row["peak_memory"], 0)

                evidence = row["evidence"]
                self.assertEqual("verified", evidence["status"])
                self.assertEqual(case["input_sha256"], evidence["input_sha256"])
                self.assertEqual(guest["sha256"], evidence["guest_sha256"])
                self.assertEqual(case["expected_digest"], evidence["output_digest"])
                self.assertEqual(
                    case["expected_digest"],
                    evidence["expected_output_digest"],
                )
                self.assertRegex(evidence["proof_sha256"], csp.HEX_32)
                self.assertRegex(evidence["statement_sha256"], csp.HEX_32)
                receipt = evidence["retained_verify_receipt"]
                self.assertEqual("verified", receipt["status"])
                self.assertEqual(
                    evidence["statement_sha256"],
                    receipt["statement_sha256"],
                )
                self.assertEqual(evidence["proof_sha256"], receipt["proof_sha256"])
                self.assertEqual(
                    report["measurement_commit"],
                    receipt["implementation_commit"],
                )
                self.assertFalse(receipt["implementation_dirty"])

        self.assertTrue(summary["all_negative_fixtures_rejected"])
        self.assertEqual(
            [
                (case.name, case.target, "rejected_as_expected")
                for case in self.negative_cases
            ],
            [
                (item["name"], item["target"], item["status"])
                for item in report["negative_validation"]
            ],
        )

    def test_report_preserves_security_and_host_qualification(self) -> None:
        report = self.report
        self.assertEqual("secure", report["security"]["profile"])
        self.assertEqual(csp.SECURE_PCS_CONFIG, report["security"]["pcs_config"])
        self.assertEqual("not_requested", report["source_audit"]["status"])
        self.assertNotIn("hostname", report["host"])
        self.assertEqual(
            report["host_matches_official_csp"],
            report["result_class"] == "official-host-comparable",
        )
        self.assertRegex(
            report["identities"]["prover_executable_sha256"],
            csp.HEX_32,
        )
        self.assertRegex(
            report["identities"]["trace_executable_sha256"],
            csp.HEX_32,
        )


class ArtifactBackendTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.case = csp.validate_manifest()[1][0]
        cls.admission = riscv_cli_admission.Admission(
            "promoted", "release_gated", False
        )

    @staticmethod
    def artifact(backend: str) -> dict:
        return {
            "schema_version": 4,
            "artifact_kind": "stwo_riscv_proof",
            "exchange_mode": "riscv_proof_json_wire_v4",
            "protocol": "secure",
            "release_status": "release_gated",
            "backend": backend,
            "pcs_config": copy.deepcopy(csp.SECURE_PCS_CONFIG),
            "proof_bytes_hex": "0a0b",
        }

    def validate(self, artifact: dict, expected_backend: str) -> tuple[bytes, str]:
        return csp.validate_artifact(
            artifact,
            self.case,
            admission=self.admission,
            expected_backend=expected_backend,
        )

    def test_each_backend_accepts_only_its_own_artifact(self) -> None:
        for backend, spec in csp.BACKENDS.items():
            with self.subTest(backend=backend):
                proof_bytes, proof_sha256 = self.validate(
                    self.artifact(spec.artifact_backend),
                    spec.artifact_backend,
                )
                self.assertEqual(b"\x0a\x0b", proof_bytes)
                self.assertEqual(csp.sha256_bytes(proof_bytes), proof_sha256)

    def test_cpu_artifact_is_rejected_by_a_metal_run(self) -> None:
        with self.assertRaisesRegex(csp.BenchmarkError, "proof artifact drifted"):
            self.validate(self.artifact("cpu"), "metal")

    def test_metal_artifact_is_rejected_by_a_cpu_run(self) -> None:
        with self.assertRaisesRegex(csp.BenchmarkError, "proof artifact drifted"):
            self.validate(self.artifact("metal"), "cpu")

    def test_matching_backend_cannot_relax_the_secure_pcs_config(self) -> None:
        artifact = self.artifact("metal")
        artifact["pcs_config"]["pow_bits"] = 20
        with self.assertRaisesRegex(csp.BenchmarkError, "proof artifact drifted"):
            self.validate(artifact, "metal")


class BackendResolutionTests(unittest.TestCase):
    @staticmethod
    def arguments(
        backend: str,
        cli: Path | None = None,
        report_out: Path | None = None,
    ) -> argparse.Namespace:
        return argparse.Namespace(backend=backend, cli=cli, report_out=report_out)

    def test_cpu_defaults_are_the_committed_evidence_paths(self) -> None:
        cli, report_out = csp._resolve_backend_paths(self.arguments("cpu"))
        self.assertEqual(csp.DEFAULT_CLI.resolve(), cli)
        self.assertEqual(csp.DEFAULT_REPORT.resolve(), report_out)

    def test_metal_defaults_never_clobber_cpu_evidence(self) -> None:
        cli, report_out = csp._resolve_backend_paths(self.arguments("metal"))
        self.assertEqual(
            (csp.ROOT / "zig-out" / "bin" / "stwo-zig-riscv-metal").resolve(),
            cli,
        )
        self.assertEqual(
            (
                csp.ROOT
                / "vectors"
                / "reports"
                / "riscv_csp_benchmark_report.metal.json"
            ).resolve(),
            report_out,
        )
        self.assertNotEqual(csp.DEFAULT_REPORT.resolve(), report_out)

    def test_explicit_paths_win_for_every_backend(self) -> None:
        explicit_cli = Path("/opt/example/prover")
        explicit_report = Path("/opt/example/report.json")
        for backend in csp.BACKENDS:
            with self.subTest(backend=backend):
                cli, report_out = csp._resolve_backend_paths(
                    self.arguments(backend, explicit_cli, explicit_report)
                )
                self.assertEqual(explicit_cli, cli)
                self.assertEqual(explicit_report, report_out)


class MetalHostMatchTests(unittest.TestCase):
    @staticmethod
    def official_host(**overrides: object) -> dict:
        host: dict = {
            "cpu": "Apple M1",
            "logical_cpu_count": 8,
            "memory_bytes": 16 * 1024 * 1024 * 1024,
            "gpu": {
                "name": "Apple M1",
                "core_count": 8,
                "metal_support": "spdisplays_metal3",
                "unified_memory": True,
            },
        }
        host.update(overrides)
        return host

    @staticmethod
    def empty_gpu() -> dict:
        return {
            "name": None,
            "core_count": None,
            "metal_support": None,
            "unified_memory": None,
        }

    def test_official_host_passes_the_metal_gate(self) -> None:
        self.assertEqual(
            (True, []),
            csp.official_host_match(self.official_host(), backend="metal"),
        )

    def test_missing_gpu_identity_adds_gpu_reasons(self) -> None:
        without_gpu = self.official_host()
        del without_gpu["gpu"]
        for label, host in (
            ("all-none gpu", self.official_host(gpu=self.empty_gpu())),
            ("absent gpu", without_gpu),
        ):
            with self.subTest(host=label):
                matches, reasons = csp.official_host_match(host, backend="metal")
                self.assertFalse(matches)
                self.assertEqual(
                    [
                        "CSP publication host requires an Apple M1 GPU",
                        "CSP publication host requires 8 GPU cores",
                        "CSP publication host requires Metal support evidence",
                    ],
                    reasons,
                )

    def test_wrong_gpu_identity_is_a_reason(self) -> None:
        gpu = dict(
            self.official_host()["gpu"],
            name="Apple M4 Max",
            core_count=32,
        )
        matches, reasons = csp.official_host_match(
            self.official_host(gpu=gpu),
            backend="metal",
        )
        self.assertFalse(matches)
        self.assertIn("CSP publication host requires an Apple M1 GPU", reasons)
        self.assertIn("CSP publication host requires 8 GPU cores", reasons)

    def test_cpu_backend_ignores_gpu_identity_entirely(self) -> None:
        host = self.official_host(gpu=self.empty_gpu())
        self.assertEqual((True, []), csp.official_host_match(host))
        self.assertEqual((True, []), csp.official_host_match(host, backend="cpu"))


class AdmissionPassthroughTests(unittest.TestCase):
    def test_backend_is_forwarded_once_admission_supports_it(self) -> None:
        recorded: dict = {}

        def resolve(cli, *, cwd=None, timeout_seconds=30, backend="cpu"):
            recorded["backend"] = backend
            return riscv_cli_admission.Admission(
                "promoted", "release_gated", False
            )

        with mock.patch.object(csp.riscv_cli_admission, "resolve", resolve):
            csp._resolve_admission(Path("/opt/example/prover"), "metal")
        self.assertEqual("metal", recorded["backend"])

    def test_metal_fails_closed_until_admission_learns_backends(self) -> None:
        def resolve(cli, *, cwd=None, timeout_seconds=30):
            return riscv_cli_admission.Admission(
                "promoted", "release_gated", False
            )

        with mock.patch.object(csp.riscv_cli_admission, "resolve", resolve):
            admission = csp._resolve_admission(Path("/opt/example/prover"), "cpu")
            self.assertEqual("release_gated", admission.release_status)
            with self.assertRaisesRegex(
                csp.BenchmarkError,
                "cannot authenticate a metal",
            ):
                csp._resolve_admission(Path("/opt/example/prover"), "metal")


class BuildRegistrationTests(unittest.TestCase):
    def test_standard_build_step_is_registered_once(self) -> None:
        product = (
            csp.ROOT / "build_support" / "products" / "riscv_cpu.zig"
        ).read_text(encoding="utf-8")
        catalog = (
            csp.ROOT / "build_support" / "products" / "catalog.zig"
        ).read_text(encoding="utf-8")
        self.assertEqual(1, product.count('"riscv-csp-bench"'))
        self.assertEqual(1, catalog.count('.name = "riscv-csp-bench"'))


if __name__ == "__main__":
    unittest.main()
