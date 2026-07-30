"""Contracts for the fail-closed Sail differential gate.

Runtime: under two seconds, no external toolchain. The committed-binding test
doubles as the always-on staleness gate: it runs in the static lane on every
PR, so corpus or pin movement without regenerated live evidence goes red even
on hosts that have never built Sail. The live differential itself is
exercised by the hosted riscv-sail-differential workflow and by
`riscv_sail_gate.py run`; nothing here pretends to consult Sail.

The workflow contracts at the bottom are the other half of the same idea:
the hosted job must not be able to report success without having run, so the
receipts the gate writes and the verdict job reads are asserted end to end.
The preflight tests do the same for the step that a warm cache would
otherwise make vacuous -- they require the pinned Sail compiler to be
executed here, not assumed -- and ContractDocumentTest ties the NORMATIVE
gate document to the workflow, because a normative document that disagrees
with the gate it governs is worse than no document at all.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import re
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import riscv_sail_gate as gate

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_PATH = Path(".github/workflows/riscv-sail-differential.yml")
CONTRACT_PATH = Path("conformance/riscv-sail-differential-gate.md")
SAVE_STEP = "Save pinned formal toolchain workspace"
# Read from the pinned formal profile rather than restated: a compiler bump
# must move these assertions with the gate, not silently past it.
PINNED_COMPILER = gate.formal_tools.load_profile().sail_compiler


def _workflow_step(job: str, name: str) -> str:
    """The YAML of one named step, up to the next step in the same job."""
    return job.split(f"- name: {name}", 1)[1].split("      - name:", 1)[0]


def _comment_above(job: str, name: str) -> str:
    """The comment block immediately above a named step.

    Read so a test can require the prose and the condition beneath it to say
    the same thing: a comment that outlived the behavior it describes is how
    the next reader concludes the gate does something it stopped doing.
    """
    block: list[str] = []
    for line in reversed(job.split(f"- name: {name}", 1)[0].splitlines()):
        stripped = line.strip()
        if not stripped:
            if block:
                break
            continue
        if not stripped.startswith("#"):
            break
        block.append(stripped)
    return "\n".join(reversed(block))


def _copy_binding_inputs(destination: Path) -> tuple[Path, Path]:
    """Copy exactly the files bind_errors reads into an isolated tree."""
    evidence = destination / gate.EVIDENCE_PATH
    manifest = destination / gate.MANIFEST_PATH
    patch = destination / "conformance" / "riscv" / "sail-rvfi-zkvm-entry.patch"
    for source, target in (
        (ROOT / gate.EVIDENCE_PATH, evidence),
        (ROOT / gate.MANIFEST_PATH, manifest),
        (ROOT / "conformance" / "riscv" / "sail-rvfi-zkvm-entry.patch", patch),
    ):
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    return evidence, manifest


class BindingTest(unittest.TestCase):
    def test_committed_evidence_binds_to_committed_corpus(self) -> None:
        self.assertEqual(gate.bind_errors(ROOT), [])

    def _tampered_errors(self, mutate) -> list[str]:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence_path, manifest_path = _copy_binding_inputs(root)
            evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            mutate(evidence, manifest)
            evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            return gate.bind_errors(root)

    def test_fixture_drift_without_fresh_evidence_fails(self) -> None:
        def mutate(evidence, manifest):
            manifest["vectors"][0]["trace_sha256"] = "0" * 64

        errors = self._tampered_errors(mutate)
        self.assertTrue(any("comparison_digest" in error for error in errors))
        self.assertTrue(any("re-run" in error for error in errors))

    def test_pin_drift_without_fresh_evidence_fails(self) -> None:
        def mutate(evidence, manifest):
            evidence["sail"]["model_tag"] = "2099-01-01-deadbee"

        errors = self._tampered_errors(mutate)
        self.assertTrue(any("sail.model_tag" in error for error in errors))

    def test_dropped_vector_breaks_counts_and_digest(self) -> None:
        def mutate(evidence, manifest):
            manifest["vectors"].pop()

        errors = self._tampered_errors(mutate)
        joined = "\n".join(errors)
        for field in ("programs", "retirements", "comparison_digest"):
            self.assertIn(f"evidence {field}", joined)

    def test_binary_hash_is_volatile_but_must_stay_a_sha256(self) -> None:
        def rebuild(evidence, manifest):
            evidence["sail"]["binary_sha256"] = "f" * 64

        self.assertEqual(self._tampered_errors(rebuild), [])

        def corrupt(evidence, manifest):
            evidence["sail"]["binary_sha256"] = "not-a-hash"

        errors = self._tampered_errors(corrupt)
        self.assertTrue(any("binary_sha256" in error for error in errors))


class EvidenceDriftTest(unittest.TestCase):
    def setUp(self) -> None:
        self.committed = json.loads(
            (ROOT / gate.EVIDENCE_PATH).read_text(encoding="utf-8")
        )

    def test_rebuilt_binaries_are_the_only_tolerated_difference(self) -> None:
        fresh = json.loads(json.dumps(self.committed))
        fresh["sail"]["binary_sha256"] = "a" * 64
        fresh["spike"]["binary_sha256"] = "b" * 64
        self.assertEqual(gate.evidence_drift(fresh, self.committed), [])

    def test_any_semantic_difference_is_drift(self) -> None:
        fresh = json.loads(json.dumps(self.committed))
        fresh["comparison_digest"] = "c" * 64
        fresh["retirements"] += 1
        drift = gate.evidence_drift(fresh, self.committed)
        joined = "\n".join(drift)
        self.assertIn("comparison_digest", joined)
        self.assertIn("retirements", joined)

    def test_identity_differences_are_drift(self) -> None:
        fresh = json.loads(json.dumps(self.committed))
        fresh["sail"]["model_tag"] = "other-tag"
        drift = gate.evidence_drift(fresh, self.committed)
        self.assertTrue(any("sail.model_tag" in line for line in drift))


class ScopeTest(unittest.TestCase):
    def test_semantics_bearing_paths_require_the_live_gate(self) -> None:
        for path in (
            "vectors/riscv_elfs/alu_test.elf",
            "conformance/riscv/rv32im-sail-profile.json",
            "conformance/upstream.md",
            "scripts/riscv_equivalence.py",
            "scripts/riscv_trace_vectors_lib/corpus.py",
            "src/frontends/riscv/isa/authority.zig",
            "src/frontends/riscv/runner/trace_dump.zig",
            ".github/workflows/riscv-sail-differential.yml",
        ):
            required, matched = gate.live_scope([path])
            self.assertTrue(required, path)
            self.assertIn(path, matched)

    def test_unrelated_paths_do_not(self) -> None:
        required, matched = gate.live_scope(
            [
                "README.md",
                "src/core/fields/m31.zig",
                "src/frontends/riscv/air/component.zig",
                "scripts/riscv_sail_oracle.py",
            ]
        )
        self.assertFalse(required)
        self.assertEqual(matched, {})

    def test_prefixes_stay_files_or_directories_that_exist(self) -> None:
        # A deleted trigger path would quietly stop selecting the live gate;
        # tie the policy to the tree so renames must update it.
        for prefix in gate.LIVE_TRIGGER_PREFIXES:
            self.assertTrue((ROOT / prefix).exists(), prefix)


class PreflightTest(unittest.TestCase):
    """The unconditional half: the pinned toolchain must work on this host.

    A warm toolchain cache must not be able to stand in for a functional
    toolchain, so these run against the real dependency resolution rather
    than against a recorded verdict.
    """

    def test_absent_dependencies_are_all_named_and_leave_no_receipt(self) -> None:
        # An empty PATH is every provisioning fault at once: no SMT solver,
        # no Sail compiler, no dtc. Each must be named -- "the differential
        # step did not run" is exactly the diagnosis this step exists to
        # replace -- and nothing may be written that the workflow's verdict
        # job could mistake for a functional toolchain.
        with tempfile.TemporaryDirectory() as tmp:
            receipts = Path(tmp) / "github-output"
            stderr = io.StringIO()
            with (
                mock.patch.dict(os.environ, {"PATH": tmp}),
                contextlib.redirect_stderr(stderr),
            ):
                returncode = gate.preflight(
                    workspace=Path(tmp) / "never-prepared",
                    sail_compiler=None,
                    cache_hit=True,
                    github_output=receipts,
                )
            self.assertEqual(returncode, gate.EXIT_TOOLCHAIN_UNAVAILABLE)
            self.assertFalse(receipts.exists())
        output = stderr.getvalue()
        self.assertIn(gate.SMT_SOLVER, output)
        # The compiler diagnostic, not the substring "Sail compiler": the
        # missing-z3 message contains that phrase too, so asserting on it
        # would pass for a preflight that never looks at the compiler.
        self.assertIn(f"pinned Sail compiler {PINNED_COMPILER} does not run", output)
        self.assertIn("dtc", output)
        self.assertIn("NOT FUNCTIONAL", output)

    def _functional_toolchain(
        self, stack: contextlib.ExitStack, state: str, **compiler: object
    ) -> mock.Mock:
        """Every pinned dependency resolves; the workspace is in `state`.

        Keyword arguments are forwarded to the `resolve_sail_compiler` mock,
        so a test can make the pinned compiler alone fail. The mock is
        returned because the call is itself part of the contract: this step
        exists to execute the pinned compiler on this runner, not to assume
        that whatever the cache restored can run.
        """
        compiler.setdefault("return_value", Path("/opt/sail/bin/sail"))
        resolve = mock.Mock(**compiler)
        for patch in (
            mock.patch.object(gate.shutil, "which", return_value="/usr/bin/z3"),
            mock.patch.object(
                gate.formal_tools, "resolve_sail_compiler", resolve
            ),
            mock.patch.object(
                gate.formal_tools,
                "require_device_tree_compiler",
                return_value=Path("/usr/bin/dtc"),
            ),
            mock.patch.object(gate, "workspace_state", return_value=state),
        ):
            stack.enter_context(patch)
        return resolve

    def test_the_pinned_compiler_is_executed_here_not_assumed(self) -> None:
        # The mutation this exists to catch: replace the resolve_sail_compiler
        # call with a constant path. Nothing else notices -- the
        # absent-dependency tests are still red for z3 and dtc, and every
        # other preflight test mocks the resolution away -- while the step
        # stops proving anything about the one binary that defines RV32IM
        # semantics, which is precisely the warm-cache hole it was added for.
        with tempfile.TemporaryDirectory() as tmp:
            release_binary = Path(tmp) / "release" / "bin" / "sail"
            stdout = io.StringIO()
            with contextlib.ExitStack() as stack:
                resolve = self._functional_toolchain(stack, "warm")
                stack.enter_context(contextlib.redirect_stdout(stdout))
                returncode = gate.preflight(
                    workspace=Path(tmp) / "workspace",
                    sail_compiler=release_binary,
                    cache_hit=True,
                    github_output=None,
                )
            self.assertEqual(returncode, gate.EXIT_PASS)
            # The binary the workflow downloaded, checked against the pinned
            # version from the formal profile -- not some `sail` on PATH.
            resolve.assert_called_once_with(release_binary, PINNED_COMPILER)
        self.assertIn(
            f"Sail {PINNED_COMPILER} at /opt/sail/bin/sail", stdout.getvalue()
        )

    def test_a_pinned_compiler_that_will_not_run_here_is_red(self) -> None:
        # Warm cache, z3 present, dtc present, workspace verifiable: the shape
        # of a run that used to sail through. The compiler alone fails, and
        # that is a red gate with no receipt, not a cached-toolchain green.
        with tempfile.TemporaryDirectory() as tmp:
            receipts = Path(tmp) / "github-output"
            stderr = io.StringIO()
            with contextlib.ExitStack() as stack:
                self._functional_toolchain(
                    stack,
                    "warm",
                    side_effect=gate.formal_tools.FormalToolsError(
                        f"Sail compiler {PINNED_COMPILER} was not found"
                    ),
                )
                stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
                stack.enter_context(contextlib.redirect_stderr(stderr))
                returncode = gate.preflight(
                    workspace=Path(tmp) / "workspace",
                    sail_compiler=None,
                    cache_hit=True,
                    github_output=receipts,
                )
            self.assertEqual(returncode, gate.EXIT_TOOLCHAIN_UNAVAILABLE)
            self.assertFalse(receipts.exists())
        output = stderr.getvalue()
        self.assertIn(f"pinned Sail compiler {PINNED_COMPILER} does not run", output)
        self.assertIn("NOT FUNCTIONAL", output)

    def test_a_functional_toolchain_writes_the_receipt_the_verdict_reads(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            receipts = Path(tmp) / "github-output"
            with contextlib.ExitStack() as stack:
                self._functional_toolchain(stack, "warm")
                stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
                returncode = gate.preflight(
                    workspace=Path(tmp) / "workspace",
                    sail_compiler=None,
                    cache_hit=True,
                    github_output=receipts,
                )
            self.assertEqual(returncode, gate.EXIT_PASS)
            self.assertEqual(
                "toolchain_health=functional\ncache_state=warm\n",
                receipts.read_text(encoding="utf-8"),
            )

    def test_a_corrupt_restored_cache_is_reported_and_left_to_the_rebuild(self) -> None:
        # Fail-closed here would mean fail-shut: `run --prepare-on-miss`
        # rebuilds from pins and the differential still runs, which is the
        # outcome this gate wants. Silence is what it cannot afford.
        with tempfile.TemporaryDirectory() as tmp:
            receipts = Path(tmp) / "github-output"
            stderr = io.StringIO()
            with contextlib.ExitStack() as stack:
                self._functional_toolchain(stack, "corrupt")
                stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
                stack.enter_context(contextlib.redirect_stderr(stderr))
                returncode = gate.preflight(
                    workspace=Path(tmp) / "workspace",
                    sail_compiler=None,
                    cache_hit=True,
                    github_output=receipts,
                )
            self.assertEqual(returncode, gate.EXIT_PASS)
            self.assertIn("cache_state=corrupt", receipts.read_text(encoding="utf-8"))
        self.assertIn("restored toolchain cache is corrupt", stderr.getvalue())

    def test_workspace_state_separates_never_built_from_unusable(self) -> None:
        profile = gate.formal_tools.load_profile()
        compiler = Path("/opt/sail/bin/sail")
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            self.assertEqual("cold", gate.workspace_state(workspace, profile, compiler))
            paths = gate.formal_tools.ToolPaths(workspace.resolve())
            paths.sail_binary.parent.mkdir(parents=True)
            paths.sail_binary.write_bytes(b"")
            self.assertEqual(
                "corrupt", gate.workspace_state(workspace, profile, compiler)
            )


class RunFailClosedTest(unittest.TestCase):
    def test_missing_workspace_is_red_and_names_what_was_not_checked(self) -> None:
        # Regardless of whether this host has the pinned Sail compiler, an
        # absent workspace must be the unavailability exit code with the
        # not-checked inventory -- never a pass and never a silent skip.
        with tempfile.TemporaryDirectory() as tmp:
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                returncode = gate.run_gate(
                    workspace=Path(tmp) / "never-prepared",
                    sail_compiler=None,
                    prepare_on_miss=False,
                    jobs=1,
                    trace_dump_bin=None,
                    report_out=None,
                )
        self.assertEqual(returncode, gate.EXIT_TOOLCHAIN_UNAVAILABLE)
        output = stderr.getvalue()
        self.assertIn("did NOT run", output)
        committed = json.loads(
            (ROOT / gate.EVIDENCE_PATH).read_text(encoding="utf-8")
        )
        self.assertIn(
            f"{committed['retirements']} retirements were NOT re-checked",
            output,
        )

    def test_an_unavailable_toolchain_refuses_to_warm_the_next_run(self) -> None:
        # The workflow's save step keys on this receipt. A cache entry is
        # immutable once written under its key, so publishing the workspace
        # of a run whose toolchain never came up would hand every later run a
        # restore it cannot replace.
        with tempfile.TemporaryDirectory() as tmp:
            receipts = Path(tmp) / "github-output"
            with contextlib.redirect_stderr(io.StringIO()):
                returncode = gate.run_gate(
                    workspace=Path(tmp) / "never-prepared",
                    sail_compiler=None,
                    prepare_on_miss=False,
                    jobs=1,
                    trace_dump_bin=None,
                    report_out=None,
                    github_output=receipts,
                )
            self.assertEqual(returncode, gate.EXIT_TOOLCHAIN_UNAVAILABLE)
            self.assertEqual(
                "differential_ran=false\ntoolchain_state=unavailable\n",
                receipts.read_text(encoding="utf-8"),
            )


class WorkflowContractTest(unittest.TestCase):
    """The hosted job must not be able to report success without running.

    These read the workflow text because that text is what GitHub executes.
    Each assertion pins one link of the chain: a receipt that no step writes,
    a step that stops running unconditionally, or a verdict that stops
    reading a receipt would each restore the failure this gate was built to
    remove -- a green check that means "the cache was warm".
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = (ROOT / WORKFLOW_PATH).read_text(encoding="utf-8")
        cls.live_job = cls.workflow.split("  differential:", 1)[1].split(
            "  verdict:", 1
        )[0]
        cls.verdict_job = cls.workflow.split("  verdict:", 1)[1]

    def _step(self, job: str, name: str) -> str:
        return _workflow_step(job, name)

    def test_provisioning_and_preflight_run_on_every_path(self) -> None:
        # A cache hit must not be able to bypass either the install steps or
        # the assertion that the pinned toolchain actually works, and the
        # assertion has to come before the expensive gate so a provisioning
        # fault reads as one.
        for step in (
            "Install the pinned Spike and Sail system dependencies",
            "Install the pinned Sail compiler release binary",
            "Assert the pinned toolchain is functional (cache hit or miss)",
        ):
            with self.subTest(step=step):
                self.assertNotIn("if:", self._step(self.live_job, step))
        self.assertLess(
            self.live_job.index("riscv_sail_gate.py preflight"),
            self.live_job.index("riscv_sail_gate.py run"),
        )
        for command in ("preflight", "run"):
            self.assertIn(
                f"riscv_sail_gate.py {command}",
                self.live_job,
            )
        self.assertEqual(2, self.live_job.count('--github-output "$GITHUB_OUTPUT"'))

    def test_every_receipt_is_written_exported_and_required(self) -> None:
        for receipt, step_id in (
            ("toolchain_health", "preflight"),
            ("differential_ran", "differential"),
            ("sail_leg", "sail_leg"),
        ):
            with self.subTest(receipt=receipt):
                self.assertIn(f"id: {step_id}\n", self.live_job)
                self.assertIn(
                    f"{receipt}: ${{{{ steps.{step_id}.outputs.{receipt} }}}}",
                    self.live_job,
                )
                self.assertIn(
                    f"needs.differential.outputs.{receipt}", self.verdict_job
                )
        self.assertIn('echo "sail_leg=required" >> "$GITHUB_OUTPUT"', self.live_job)
        for requirement in (
            'require "$DIFFERENTIAL_RESULT" success',
            'require "$TOOLCHAIN_HEALTH" functional',
            'require "$DIFFERENTIAL_RAN" true',
            'require "$SAIL_LEG" required',
        ):
            with self.subTest(requirement=requirement):
                self.assertIn(requirement, self.verdict_job)

    def test_a_scope_that_did_not_decide_is_not_read_as_out_of_scope(self) -> None:
        # An unset or garbled live_required would otherwise fall into the
        # not-selected arm, where a skipped job is the expected shape, and
        # pass with nothing having run anywhere.
        self.assertIn("true|false)", self.verdict_job)
        self.assertIn("no live_required decision", self.verdict_job)
        self.assertIn(
            'require "$TOOLCHAIN_HEALTH$DIFFERENTIAL_RAN$SAIL_LEG" ""',
            self.verdict_job,
        )

    def test_one_cache_key_covers_the_whole_toolchain_recipe(self) -> None:
        keys = re.findall(r"^ +key: (riscv-formal-.+)$", self.workflow, re.MULTILINE)
        self.assertEqual(2, len(keys))
        self.assertEqual(keys[0], keys[1], "restore and save keys must match")
        for ingredient in (
            "conformance/riscv/rv32im-sail-profile.json",
            "conformance/riscv/sail-rvfi-zkvm-entry.patch",
            "conformance/riscv/sail-rv32im-override.json",
            "conformance/riscv/sail-rv32im-tagged-options.json",
            "scripts/riscv_formal_tools.py",
        ):
            with self.subTest(ingredient=ingredient):
                self.assertIn(ingredient, keys[0])

    def _save_condition(self) -> str:
        lines = [
            line.strip()
            for line in self._step(self.live_job, SAVE_STEP).splitlines()
            if line.strip().startswith("if:")
        ]
        self.assertEqual(1, len(lines), "the save step needs exactly one condition")
        return lines[0]

    def test_only_a_workspace_the_gate_proved_usable_is_cached(self) -> None:
        condition = self._save_condition()
        # `always()`: a red run must still warm the next one. Dropping it
        # would deny a divergence investigation the toolchain it most needs.
        self.assertIn("always()", condition)
        for state in ("verified", "rebuilt"):
            with self.subTest(state=state):
                self.assertIn(
                    f"steps.differential.outputs.toolchain_state == '{state}'",
                    condition,
                )
        # The states that must NOT publish a workspace: the gate ran and the
        # toolchain never came up, or the preflight went red and the gate step
        # never ran, leaving the receipt empty. A cache entry is immutable
        # under its key, so either would be permanent until the epoch is bumped.
        self.assertNotIn("unavailable", condition)

    def test_the_save_condition_and_the_comment_above_it_agree(self) -> None:
        # This step was `if: always()`; the narrowing is deliberate, and the
        # only place its reason survives is the prose directly above it. A
        # comment that outlived the behavior it describes is worse than none:
        # it is what the next reader trusts while editing the condition back.
        condition = self._save_condition()
        comment = _comment_above(self.live_job, SAVE_STEP)
        self.assertIn("always()", comment)
        self.assertIn("toolchain_state", comment)
        for state in ("verified", "rebuilt", "unavailable"):
            with self.subTest(state=state):
                self.assertIn(state, comment)
        self.assertIn("preflight", comment)
        for state in re.findall(r"toolchain_state == '(\w+)'", condition):
            with self.subTest(accepted=state):
                self.assertIn(state, comment)


class ContractDocumentTest(unittest.TestCase):
    """The NORMATIVE document must describe the gate that actually runs.

    `conformance/riscv-sail-differential-gate.md` names this workflow and is
    marked normative, so it is what a reader consults before changing the
    gate. When the two disagree the document does active harm: it licenses
    edits the workflow no longer permits. These tie the document to the
    workflow on exactly the facts that move -- the receipts the verdict
    requires, and the toolchain states the cache save keys on.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.document = (ROOT / CONTRACT_PATH).read_text(encoding="utf-8")
        cls.workflow = (ROOT / WORKFLOW_PATH).read_text(encoding="utf-8")
        cls.live_job = cls.workflow.split("  differential:", 1)[1].split(
            "  verdict:", 1
        )[0]
        section = cls.document.split("## Fail-closed contract", 1)[1].split(
            "\n## ", 1
        )[0]
        # The table specifically, not the section: the surrounding prose
        # discusses the same mechanisms, so a row deleted from the enumeration
        # of red paths would still be "mentioned somewhere" and go unnoticed.
        cls.rows = [
            line for line in section.splitlines() if line.startswith("| ")
        ]
        cls.section = section

    def _row(self, *terms: str) -> str:
        """The one contract row naming every term, asserted to exist."""
        matches = [row for row in self.rows if all(term in row for term in terms)]
        self.assertEqual(
            1, len(matches), f"exactly one fail-closed row must name {terms}"
        )
        return matches[0]

    def test_the_document_governs_this_workflow_and_this_check(self) -> None:
        self.assertIn("**Status:** NORMATIVE", self.document)
        self.assertIn(WORKFLOW_PATH.as_posix(), self.document)
        self.assertIn("Sail differential gates", self.document)
        self.assertGreater(len(self.rows), 8)  # header, separator, red paths

    def test_every_receipt_the_verdict_requires_is_a_contract_row(self) -> None:
        # Derived from the workflow, so a receipt the verdict starts requiring
        # without a row here is red rather than merely undocumented.
        receipts = set(
            re.findall(r"needs\.differential\.outputs\.(\w+)", self.workflow)
        )
        self.assertIn("toolchain_health", receipts)
        for receipt in sorted(receipts - {"cache_state"}):
            with self.subTest(receipt=receipt):
                self.assertTrue(
                    any(f"`{receipt}`" in row for row in self.rows),
                    f"{receipt} is required by the verdict job",
                )

    def test_the_preflight_red_path_is_a_contract_row(self) -> None:
        # The row the wave-1 change owed and did not write: a toolchain that
        # will not run is red at the preflight, on the warm path too.
        row = self._row("preflight", "cache hit")
        for dependency in (gate.SMT_SOLVER, "dtc", "sail"):
            with self.subTest(dependency=dependency):
                self.assertIn(dependency, row)

    def test_the_cache_hygiene_states_are_documented_as_written(self) -> None:
        condition = _workflow_step(self.live_job, SAVE_STEP)
        states = set(re.findall(r"toolchain_state == '(\w+)'", condition))
        self.assertEqual({"verified", "rebuilt"}, states)
        row = self._row("`toolchain_state`")
        for state in sorted(states):
            with self.subTest(state=state):
                self.assertIn(f"`{state}`", row)
        self.assertIn("`unavailable`", row)

    def test_the_three_provisioning_paths_are_reasoned_through(self) -> None:
        # Cache hit, cache miss, and dependency failure are the three shapes
        # this gate's soundness turns on; the document enumerates them so the
        # warm path is never assumed to be the cold path minus a build.
        for path in ("Cache miss", "Cache hit", "Dependency failure"):
            with self.subTest(path=path):
                self.assertIn(f"**{path}.**", self.section)


if __name__ == "__main__":
    unittest.main()
