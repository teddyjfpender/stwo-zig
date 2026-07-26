import json
import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from scripts.riscv_release_gate_lib.contract import (
    BOUNDARIES,
    PINNED_ORACLE,
    core_purity_errors,
    divergence_errors,
    divergence_ledger_errors,
    frontend_layering_errors,
    receipt_errors,
    _relation_case_errors,
)
from scripts.riscv_release_gate_lib import controller
from scripts.riscv_release_gate_lib.controller import command_plan
from scripts.riscv_release_evidence import _strict_object
from scripts.tests.riscv_release_receipt_fixture import (
    TEST_COMMIT as COMMIT,
    TEST_DIGEST as DIGEST,
    air_divergence,
    valid_receipt,
)


AIR_ROW = (
    f"| {air_divergence.LEDGER_LANE} | {air_divergence.LEDGER_BOUNDARY} | zig | rust "
    "| Allowed only with the pinned divergence shape. |"
)


class DivergenceContractTests(unittest.TestCase):
    @staticmethod
    def ledger(*rows: str) -> str:
        return "\n".join((
            "# Upstream divergence ledger",
            "",
            "## Active divergences",
            "",
            "| Lane | Boundary | Current | Oracle | Release status |",
            "| --- | --- | --- | --- | --- |",
            *rows,
            "",
            "## Closure requirements",
        ))

    def test_only_code_owned_conditional_rows_are_allowlisted(self) -> None:
        ledger = self.ledger(
            "| RISC-V | PCS geometry | zig | rust | Allowed only with the self-check. |",
            "| RISC-V | Interaction transcript | zig | rust | Allowed only with the transcript receipt. |",
            AIR_ROW,
        )
        self.assertEqual([], divergence_ledger_errors(ledger, pinned_oracle="f" * 40))

        invented = self.ledger(
            "| RISC-V | Invented waiver | zig | rust | Allowed only with tests. |"
        )
        self.assertIn(
            "release-blocking divergence remains active: RISC-V / Invented waiver",
            divergence_ledger_errors(invented, pinned_oracle="f" * 40),
        )

    def test_architectural_divergences_cannot_be_hidden(self) -> None:
        ledger = self.ledger(
            "| RISC-V | PCS geometry | zig | rust | Allowed only with the self-check. |",
            AIR_ROW,
        )
        self.assertIn(
            "required architectural divergence is missing: RISC-V / Interaction transcript",
            divergence_ledger_errors(ledger, pinned_oracle="f" * 40),
        )

    def test_air_soundness_row_is_required_not_merely_permitted(self) -> None:
        """Deleting the row would hide the under-constraints the oracle admits."""
        ledger = self.ledger(
            "| RISC-V | PCS geometry | zig | rust | Allowed only with the self-check. |",
            "| RISC-V | Interaction transcript | zig | rust | Allowed only with the transcript receipt. |",
        )
        self.assertIn(
            "required architectural divergence is missing: "
            f"{air_divergence.LEDGER_REFERENCE}",
            divergence_ledger_errors(ledger, pinned_oracle="f" * 40),
        )

    def test_live_ledger_satisfies_the_machine_read_policy(self) -> None:
        self.assertEqual([], divergence_errors(Path(__file__).resolve().parents[2]))


class LayeringContractTests(unittest.TestCase):
    @staticmethod
    def write(root: Path, relative: str, source: str) -> None:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")

    def test_core_purity_resolves_and_rejects_concrete_dependency_edges(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write(root, "src/frontends/riscv/air.zig", "pub const ok = true;\n")
            self.write(
                root,
                "src/core/protocol.zig",
                'const air = @import("../frontends/riscv/air.zig");\n',
            )
            errors = core_purity_errors(root)
            self.assertEqual(1, len(errors))
            self.assertIn("src/core/protocol.zig imports frontends/riscv/air.zig", errors[0])

    def test_frontend_layering_rejects_cli_backend_placeholders_and_giant_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write(root, "src/tools/prove/cli.zig", "pub const ok = true;\n")
            self.write(
                root,
                "src/frontends/riscv/prover.zig",
                'const cli = @import("../../tools/prove/cli.zig");\n'
                "const Mode = enum { silent };\n"
                + "const value = 0;\n" * 850,
            )
            errors = frontend_layering_errors(root)
            self.assertTrue(any("imports tools/prove/cli.zig" in error for error in errors))
            self.assertTrue(any("manual ceiling 850" in error for error in errors))
            self.assertTrue(any("active placeholder markers: silent" in error for error in errors))

    def test_comments_and_strings_do_not_create_placeholder_findings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write(
                root,
                "src/frontends/riscv/air.zig",
                '// legacy placeholder silent\nconst label = "silent";\n',
            )
            self.assertEqual([], frontend_layering_errors(root))


class ReceiptContractTests(unittest.TestCase):
    def test_receipt_json_rejects_duplicate_fields_at_every_depth(self) -> None:
        with self.assertRaisesRegex(ValueError, "duplicate JSON field: status"):
            json.loads(
                '{"oracle":{"status":"clean","status":"dirty"}}',
                object_pairs_hook=_strict_object,
            )

    def test_complete_current_candidate_receipt_passes(self) -> None:
        now = int(time.time())
        self.assertEqual(
            [],
            receipt_errors(valid_receipt(now), COMMIT, now=now, vector_names=("alu",)),
        )

    def test_receipt_rejects_wrong_candidate_staleness_and_missing_boundary(self) -> None:
        now = int(time.time())
        receipt = valid_receipt(now - 90_000)
        receipt["candidate_commit"] = "c" * 40
        receipt["boundaries"]["relation_sums"] = {"status": "unimplemented"}
        errors = receipt_errors(receipt, COMMIT, now=now, vector_names=("alu",))
        self.assertIn("oracle receipt belongs to another candidate", errors)
        self.assertIn("oracle receipt is expired or from the future", errors)
        self.assertIn("boundary relation_sums is unimplemented", errors)

    def test_legacy_pass_bit_cannot_substitute_for_required_provenance(self) -> None:
        receipt = {
            "schema": "riscv-oracle-receipt-v1",
            "candidate_commit": COMMIT,
            "verdict": "PASS",
            "oracle": {"commit": PINNED_ORACLE},
            "boundaries": {name: {"status": "pass"} for name in BOUNDARIES},
        }
        errors = receipt_errors(receipt, COMMIT, now=0, vector_names=("alu",))
        self.assertIn("unknown oracle receipt schema", errors)
        self.assertIn("oracle receipt does not attest a clean source tree", errors)
        self.assertIn("witness layout digest is not a lowercase SHA-256 digest", errors)
        self.assertIn("per-case result digests are missing", errors)

    def test_case_digest_manifest_must_cover_every_boundary_and_vector_exactly(self) -> None:
        now = int(time.time())
        receipt = valid_receipt(now)
        receipt["expected_case_result_keys"] = receipt["expected_case_result_keys"][:-1]
        receipt["case_result_digests"].pop("shared_transcript_prefix/alu")
        receipt["case_result_digests"]["invented/case"] = DIGEST
        errors = receipt_errors(receipt, COMMIT, now=now, vector_names=("alu",))
        self.assertIn("expected case-result key manifest is incomplete or non-canonical", errors)
        self.assertIn("case-result digest keys do not exactly cover the declared corpus", errors)

    def test_per_corpus_rows_and_digests_are_bound_not_only_declared(self) -> None:
        now = int(time.time())
        receipt = valid_receipt(now)
        receipt["boundaries"]["execution"]["corpus"] = [
            {"name": "alu", "agree": False}
        ]
        errors = receipt_errors(receipt, COMMIT, now=now, vector_names=("alu",))
        self.assertIn("case-result digest does not bind execution/alu", errors)
        self.assertIn("boundary case execution/alu does not attest agreement", errors)

        receipt = valid_receipt(now)
        receipt["boundaries"]["execution"]["corpus"] = []
        errors = receipt_errors(receipt, COMMIT, now=now, vector_names=("alu",))
        self.assertIn(
            "boundary execution corpus is incomplete, duplicated, or non-canonical",
            errors,
        )

    def test_nonempty_relation_case_rejects_every_parity_binding_mutation(self) -> None:
        mutations = (
            ("relation_tuples", "elf_sha256", "c" * 64, "invalid elf_sha256"),
            ("relation_tuples", "input_sha256", "c" * 64, "invalid input_sha256"),
            ("relation_tuples", "agree", False, "invalid agree"),
            ("relation_sums", "balanced_sum", [1, 0, 0, 0], "does not balance"),
        )
        for boundary, field, value, expected in mutations:
            with self.subTest(boundary=boundary, field=field):
                receipt = valid_receipt(int(time.time()))
                receipt["boundaries"][boundary]["nonempty_public_input"][field] = value
                errors = receipt_errors(receipt, COMMIT, now=receipt["created_at_unix"])
                self.assertTrue(any(expected in error for error in errors), errors)

        for field, value, expected in (
            ("implementation_commit", "c" * 40, "binding has invalid implementation_commit"),
            ("input_sha256", "c" * 64, "binding has invalid input_sha256"),
        ):
            receipt = valid_receipt(int(time.time()))
            case = receipt["boundaries"]["relation_tuples"]["nonempty_public_input"]
            case["zig_binding"][field] = value
            errors = receipt_errors(receipt, COMMIT, now=receipt["created_at_unix"])
            self.assertTrue(any(expected in error for error in errors), errors)

        receipt = valid_receipt(int(time.time()))
        public = receipt["boundaries"]["relation_sums"]["nonempty_public_input"][
            "public_data"
        ]
        public["agree"] = False
        public["mismatches"] = ["io_entries"]
        errors = receipt_errors(receipt, COMMIT, now=receipt["created_at_unix"])
        self.assertTrue(any("lacks public-data agreement" in error for error in errors))

    def test_every_relation_case_is_balanced_and_proof_admitted(self) -> None:
        admission = {"status": "supported"}
        case = {
            "name": "mul_div",
            "proof_admission": admission,
            "proof_admitted": True,
            "evidence_mode": "balanced_full",
            "agree": True,
        }
        self.assertEqual([], _relation_case_errors(case, "relation_tuples", admission))
        case["proof_admitted"] = False
        case["limitation_evidence"] = {}
        errors = _relation_case_errors(case, "relation_tuples", admission)
        self.assertTrue(any("proof-admission verdict" in error for error in errors))
        self.assertTrue(any("obsolete Stark-V limitation" in error for error in errors))

    def test_relation_cases_bind_the_live_manifest_elf_digest(self) -> None:
        now = int(time.time())
        receipt = valid_receipt(now)
        receipt["boundaries"]["relation_tuples"]["corpus"][0]["elf_sha256"] = "c" * 64
        with mock.patch(
            "scripts.riscv_release_gate_lib.contract.trace_vector_contract",
            return_value=(("alu",), {"alu": {"status": "supported"}}, {"alu": DIGEST}),
        ):
            errors = receipt_errors(receipt, COMMIT, now=now, vector_names=("alu",))
        self.assertIn(
            "boundary case relation_tuples/alu is not bound to the live ELF digest",
            errors,
        )


class CommandPlanTests(unittest.TestCase):
    def test_candidate_plan_contains_phase_smoke_but_no_oracle_in_non_strict_mode(self) -> None:
        plan = command_plan(
            strict=False,
            phase="candidate",
            formal_workspace=None,
            candidate=COMMIT,
            evidence_dir=Path("/evidence"),
            host_system="Linux",
        )
        rendered = [" ".join(command) for command in plan]
        self.assertTrue(any("check_riscv_release_contract.py --all --phase candidate" in row for row in rendered))
        self.assertTrue(any("check_riscv_release_contract.py --structure" in row for row in rendered))
        self.assertTrue(any("check_riscv_release_contract.py --core-purity" in row for row in rendered))
        self.assertTrue(any("check_riscv_release_contract.py --frontend-layering" in row for row in rendered))
        self.assertTrue(any("riscv_staged_smoke.py --phase candidate" in row for row in rendered))
        self.assertTrue(any("unittest discover -s scripts/tests -p test_*.py" in row for row in rendered))
        self.assertFalse(any("riscv_release_oracle.py" in row for row in rendered))
        self.assertEqual("zig build release-gate -Doptimize=ReleaseFast", rendered[-1])
        self.assertFalse(any("test-riscv-prover" in row for row in rendered))

    def test_macos_plan_prepares_metal_immediately_before_discovery(self) -> None:
        plan = command_plan(
            strict=False,
            phase="candidate",
            formal_workspace=None,
            candidate=COMMIT,
            evidence_dir=Path("/evidence"),
            host_system="Darwin",
        )
        rendered = [" ".join(command) for command in plan]
        loader = "zig build metal-eval-prepare -Doptimize=ReleaseFast"
        self.assertEqual(1, rendered.count(loader))
        loader_index = rendered.index(loader)
        discovery_index = next(
            index for index, row in enumerate(rendered) if "unittest discover" in row
        )
        self.assertEqual(loader_index + 1, discovery_index)

    def test_linux_plan_executes_discovery_without_a_metal_only_build_step(self) -> None:
        plan = command_plan(
            strict=False,
            phase="candidate",
            formal_workspace=None,
            candidate=COMMIT,
            evidence_dir=Path("/evidence"),
            host_system="Linux",
        )
        rendered = [" ".join(command) for command in plan]
        self.assertNotIn(
            "zig build metal-eval-prepare -Doptimize=ReleaseFast", rendered
        )
        self.assertTrue(
            any("unittest discover -s scripts/tests -p test_*.py" in row for row in rendered)
        )

    def test_strict_plan_generates_then_validates_candidate_bound_oracle_evidence(self) -> None:
        source = Path("/formal")
        plan = command_plan(
            strict=True,
            phase="candidate",
            formal_workspace=source,
            candidate=COMMIT,
            evidence_dir=Path("/evidence"),
            host_system="Linux",
        )
        rendered = [" ".join(command) for command in plan]
        self.assertNotIn("zig build release-gate -Doptimize=ReleaseFast", rendered)
        self.assertEqual(1, rendered.count("zig build release-gate-strict -Doptimize=ReleaseFast"))
        strict_index = rendered.index("zig build release-gate-strict -Doptimize=ReleaseFast")
        tools_index = next(i for i, row in enumerate(rendered) if "riscv_formal_tools.py verify" in row)
        corpus_index = next(i for i, row in enumerate(rendered) if "riscv_trace_vectors.py" in row)
        build_index = next(i for i, row in enumerate(rendered) if "riscv_arch_tests.py build" in row)
        audit_index = next(i for i, row in enumerate(rendered) if "riscv_arch_tests.py audit" in row)
        self.assertLess(strict_index, tools_index)
        self.assertLess(tools_index, corpus_index)
        self.assertLess(corpus_index, build_index)
        self.assertLess(build_index, audit_index)
        self.assertIn("--workspace /formal", rendered[tools_index])
        self.assertIn("--sail-bin /formal/source/sail-riscv", rendered[corpus_index])
        self.assertIn("riscv_arch_tests.py audit", rendered[-1])

    def test_strict_plan_refuses_an_opaque_oracle_location(self) -> None:
        with self.assertRaisesRegex(ValueError, "--formal-workspace"):
            command_plan(
                strict=True,
                phase="candidate",
                formal_workspace=None,
                candidate=COMMIT,
                evidence_dir=Path("/evidence"),
            )


class ExecutionEvidenceTests(unittest.TestCase):
    @staticmethod
    def repository(path: Path) -> str:
        subprocess.run(["git", "init", "-q"], cwd=path, check=True)
        subprocess.run(["git", "config", "user.email", "gate@example.invalid"], cwd=path, check=True)
        subprocess.run(["git", "config", "user.name", "Gate Test"], cwd=path, check=True)
        subprocess.run(["git", "commit", "--allow-empty", "-qm", "candidate"], cwd=path, check=True)
        return subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=path, check=True, capture_output=True, text=True
        ).stdout.strip()

    def test_candidate_and_promoted_controllers_refuse_any_active_blocker(self) -> None:
        blocker = "release-blocking divergence remains active: RISC-V / Public statement"
        for phase in ("candidate", "promoted"):
            with (
                self.subTest(phase=phase),
                tempfile.TemporaryDirectory() as repository,
                tempfile.TemporaryDirectory() as output,
            ):
                root = Path(repository)
                candidate = self.repository(root)
                calls: list[list[str]] = []

                def runner(command: list[str], _: Path) -> dict[str, object]:
                    calls.append(command)
                    raise AssertionError("controller executed commands after a contract failure")

                evidence_dir = Path(output) / "session"
                report = evidence_dir / "gate.json"
                with (
                    mock.patch.object(controller, "repository_contract_errors", return_value=[blocker]),
                    mock.patch.object(controller, "_tool_versions", return_value={}),
                    mock.patch.object(controller, "_artifact_digests", return_value={}),
                ):
                    code = controller.run_gate(
                        [["must-not-run"]],
                        phase=phase,
                        candidate=candidate,
                        evidence_dir=evidence_dir,
                        report_out=report,
                        root=root,
                        runner=runner,
                    )
                payload = json.loads(report.read_text(encoding="utf-8"))
                self.assertEqual(1, code)
                self.assertEqual([], calls)
                self.assertEqual("FAIL", payload["status"])
                self.assertIn(blocker, payload["failures"])

    def test_controller_rejects_the_hosted_no_device_allowance(self) -> None:
        with tempfile.TemporaryDirectory() as repository, tempfile.TemporaryDirectory() as output:
            root = Path(repository)
            candidate = self.repository(root)
            calls: list[list[str]] = []

            def runner(command: list[str], _: Path) -> dict[str, object]:
                calls.append(command)
                raise AssertionError("controller executed with the hosted-only allowance")

            evidence_dir = Path(output) / "session"
            report = evidence_dir / "gate.json"
            with (
                mock.patch.dict(
                    os.environ,
                    {controller.HOSTED_NO_DEVICE_ALLOWANCE: "1"},
                ),
                mock.patch.object(controller, "repository_contract_errors", return_value=[]),
                mock.patch.object(controller, "_tool_versions", return_value={}),
                mock.patch.object(controller, "_artifact_digests", return_value={}),
            ):
                code = controller.run_gate(
                    [["must-not-run"]],
                    phase="candidate",
                    candidate=candidate,
                    evidence_dir=evidence_dir,
                    report_out=report,
                    root=root,
                    runner=runner,
                )
            payload = json.loads(report.read_text(encoding="utf-8"))
            self.assertEqual(1, code)
            self.assertEqual([], calls)
            self.assertTrue(payload["host"]["hosted_no_device_allowance_present"])
            self.assertIn(
                "forbidden hosted-only environment variable is set: "
                + controller.HOSTED_NO_DEVICE_ALLOWANCE,
                payload["failures"],
            )

    def test_execution_is_fail_fast_and_report_names_only_executed_commands(self) -> None:
        with tempfile.TemporaryDirectory() as repository, tempfile.TemporaryDirectory() as output:
            root = Path(repository)
            candidate = self.repository(root)
            calls: list[list[str]] = []

            def runner(command: list[str], _: Path) -> dict[str, object]:
                calls.append(command)
                return {
                    "command": command,
                    "command_shell": " ".join(command),
                    "exit_code": 9,
                    "started_at_unix_ns": 1,
                    "duration_ns": 1,
                    "skipped_tests": 0,
                    "stdout_sha256": DIGEST,
                    "stderr_sha256": DIGEST,
                    "stdout_tail": "",
                    "stderr_tail": "failed",
                }

            evidence_dir = Path(output) / "session"
            report = evidence_dir / "gate.json"
            with (
                mock.patch.object(controller, "repository_contract_errors", return_value=[]),
                mock.patch.object(controller, "_tool_versions", return_value={}),
                mock.patch.object(controller, "_artifact_digests", return_value={}),
            ):
                code = controller.run_gate(
                    [["first"], ["must-not-run"]],
                    phase="candidate",
                    candidate=candidate,
                    evidence_dir=evidence_dir,
                    report_out=report,
                    root=root,
                    runner=runner,
                )
            payload = json.loads(report.read_text(encoding="utf-8"))
            self.assertEqual(1, code)
            self.assertEqual([["first"]], calls)
            self.assertEqual("FAIL", payload["status"])
            self.assertEqual(1, len(payload["commands"]))
            self.assertIn("command failed: first", payload["failures"])

    def test_clean_success_records_every_executed_command(self) -> None:
        with tempfile.TemporaryDirectory() as repository, tempfile.TemporaryDirectory() as output:
            root = Path(repository)
            candidate = self.repository(root)

            def runner(command: list[str], _: Path) -> dict[str, object]:
                return {
                    "command": command,
                    "command_shell": " ".join(command),
                    "exit_code": 0,
                    "started_at_unix_ns": 1,
                    "duration_ns": 1,
                    "skipped_tests": 0,
                    "stdout_sha256": DIGEST,
                    "stderr_sha256": DIGEST,
                    "stdout_tail": "ok",
                    "stderr_tail": "",
                }

            evidence_dir = Path(output) / "session"
            report = evidence_dir / "gate.json"
            with (
                mock.patch.object(controller, "repository_contract_errors", return_value=[]),
                mock.patch.object(controller, "_tool_versions", return_value={}),
                mock.patch.object(controller, "_artifact_digests", return_value={}),
            ):
                code = controller.run_gate(
                    [["one"], ["two"]],
                    phase="candidate",
                    candidate=candidate,
                    evidence_dir=evidence_dir,
                    report_out=report,
                    root=root,
                    runner=runner,
                )
            payload = json.loads(report.read_text(encoding="utf-8"))
            self.assertEqual(0, code)
            self.assertEqual("PASS", payload["status"])
            self.assertEqual(["one", "two"], [row["command"][0] for row in payload["commands"]])
            self.assertEqual("", payload["git"]["initial_porcelain"])
            self.assertEqual("", payload["git"]["final_porcelain"])
            self.assertFalse(payload["host"]["hosted_no_device_allowance_present"])
            self.assertEqual([], list(evidence_dir.glob(".*.tmp")))

    def test_zero_exit_with_skipped_required_tests_still_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as repository, tempfile.TemporaryDirectory() as output:
            root = Path(repository)
            candidate = self.repository(root)
            calls: list[list[str]] = []

            def runner(command: list[str], _: Path) -> dict[str, object]:
                calls.append(command)
                return {
                    "command": command,
                    "command_shell": " ".join(command),
                    "exit_code": 0,
                    "started_at_unix_ns": 1,
                    "duration_ns": 1,
                    "skipped_tests": 1,
                    "stdout_sha256": DIGEST,
                    "stderr_sha256": DIGEST,
                    "stdout_tail": "1 skipped",
                    "stderr_tail": "",
                }

            evidence_dir = Path(output) / "session"
            report = evidence_dir / "gate.json"
            with (
                mock.patch.object(controller, "repository_contract_errors", return_value=[]),
                mock.patch.object(controller, "_tool_versions", return_value={}),
                mock.patch.object(controller, "_artifact_digests", return_value={}),
            ):
                code = controller.run_gate(
                    [["tests"], ["must-not-run"]],
                    phase="candidate",
                    candidate=candidate,
                    evidence_dir=evidence_dir,
                    report_out=report,
                    root=root,
                    runner=runner,
                )
            payload = json.loads(report.read_text(encoding="utf-8"))
            self.assertEqual(1, code)
            self.assertEqual([["tests"]], calls)
            self.assertIn("required tests were skipped: tests", payload["failures"])

    def test_subprocess_timeout_is_an_explicit_failed_command_receipt(self) -> None:
        timeout = subprocess.TimeoutExpired(
            ["slow"],
            0.25,
            output="partial output",
            stderr="partial error",
        )
        with mock.patch.object(controller.subprocess, "run", side_effect=timeout):
            record = controller._capture(["slow"], Path.cwd(), 0.25)
        self.assertEqual(124, record["exit_code"])
        self.assertTrue(record["timed_out"])
        self.assertEqual(0.25, record["timeout_seconds"])
        self.assertIn("partial output", record["stdout_tail"])
        self.assertIn("timed out after 0.25s", record["stderr_tail"])

    def test_existing_evidence_directory_is_rejected_without_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as repository, tempfile.TemporaryDirectory() as output:
            root = Path(repository)
            candidate = self.repository(root)
            evidence_dir = Path(output) / "session"
            evidence_dir.mkdir()
            marker = evidence_dir / "prior.json"
            marker.write_text("prior", encoding="utf-8")
            code = controller.run_gate(
                [],
                phase="candidate",
                candidate=candidate,
                evidence_dir=evidence_dir,
                report_out=evidence_dir / "gate.json",
                root=root,
            )
            self.assertEqual(1, code)
            self.assertEqual("prior", marker.read_text(encoding="utf-8"))
            self.assertFalse((evidence_dir / "gate.json").exists())


if __name__ == "__main__":
    unittest.main()
