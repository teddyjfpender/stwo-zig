from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

from scripts.autoresearch_workflow_policy import (
    PolicyError,
    finalize_verdict,
    inspect_candidate,
)
from autoresearch.bots.validate_action import author_identity_findings


ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = (
    ROOT / ".github/workflows/judge.yml",
    ROOT / ".github/workflows/promote.yml",
    ROOT / "autoresearch/workflows/judge.yml",
    ROOT / "autoresearch/workflows/promote.yml",
)
AUDIT_WORKFLOWS = (
    ROOT / ".github/workflows/audit.yml",
    ROOT / "autoresearch/workflows/audit.yml",
)
QUALIFY_WORKFLOWS = (
    ROOT / ".github/workflows/qualify-fork.yml",
    ROOT / "autoresearch/workflows/qualify-fork.yml",
)
ACTION_RE = re.compile(r"uses:\s+[^@\s]+@([^\s]+)")


def git(repo: Path, *args: str) -> str:
    process = subprocess.run(
        ["git", *args], cwd=repo, capture_output=True, text=True, check=True,
    )
    return process.stdout.strip()


class WorkflowContractTest(unittest.TestCase):
    def test_all_third_party_actions_are_commit_pinned(self) -> None:
        for path in (*WORKFLOWS, *AUDIT_WORKFLOWS, *QUALIFY_WORKFLOWS):
            text = path.read_text(encoding="utf-8")
            pins = ACTION_RE.findall(text)
            self.assertTrue(pins, path)
            self.assertTrue(all(re.fullmatch(r"[0-9a-f]{40}", pin) for pin in pins), path)

    def test_fork_qualification_is_board_scoped_and_uses_fixed_harness(self) -> None:
        installed, source = QUALIFY_WORKFLOWS
        self.assertEqual(installed.read_bytes(), source.read_bytes())
        text = source.read_text(encoding="utf-8")
        self.assertIn("candidate_commit:", text)
        self.assertIn("Check out fixed qualification harness", text)
        self.assertIn("Check out exact candidate", text)
        self.assertIn("path: orchestration", text)
        self.assertIn("path: candidate", text)
        self.assertIn("ref: '${{ inputs.candidate_commit }}'", text)
        self.assertIn("python3 ../orchestration/autoresearch/cli/stwo-perf setup", text)
        self.assertGreaterEqual(text.count("--board '${{ inputs.board }}'"), 4)
        self.assertIn("--guards none", text)
        self.assertIn("path: candidate/qualification/", text)
        self.assertIn("subject-path: candidate/qualification/receipt.json", text)
        self.assertIn(
            "locked central judge\n"
            "        # independently reruns the mandatory regression-guard portfolio",
            text,
        )

    def test_audit_ingestion_is_exact_serialized_and_least_privilege(self) -> None:
        self.assertEqual(AUDIT_WORKFLOWS[0].read_bytes(), AUDIT_WORKFLOWS[1].read_bytes())
        for path in AUDIT_WORKFLOWS:
            text = path.read_text(encoding="utf-8")
            evaluate, remainder = text.split("\n  sign:\n", 1)
            sign, ingest = remainder.split("\n  ingest:\n", 1)
            self.assertIn("group: autoresearch-audit-${{ github.repository }}", text)
            self.assertIn("cancel-in-progress: false", text)
            self.assertIn("contents: read", evaluate)
            self.assertNotIn("contents: write", evaluate)
            self.assertNotIn("secrets.JUDGE_HMAC_SECRET", evaluate)
            self.assertIn("contents: write", sign)
            self.assertIn("contents: write", ingest)
            self.assertNotIn("pull-requests: write", text)
            self.assertNotIn("issues: write", text)
            self.assertIn("needs: [evaluate, sign]", ingest)
            self.assertIn("ref: ${{ needs.evaluate.outputs.candidate_sha }}", ingest)
            self.assertIn(
                'origin/audit-verdicts:bundles/${GITHUB_RUN_ID}.json', ingest,
            )
            self.assertIn("python3 -m stwo_perf.audits append", ingest)
            self.assertIn('test "$candidate" = "$(git rev-parse origin/main)"', ingest)
            self.assertIn(
                'test "$(git diff --cached --name-only)" = '
                "autoresearch/ledger/promotions.tsv",
                ingest,
            )
            self.assertLess(
                ingest.index("Fetch the exact signed bundle"),
                ingest.index("Revalidate main and append"),
            )

    def test_judge_identity_runner_and_authority_order(self) -> None:
        self.assertEqual(WORKFLOWS[0].read_bytes(), WORKFLOWS[2].read_bytes())
        for path in (WORKFLOWS[0], WORKFLOWS[2]):
            text = path.read_text(encoding="utf-8")
            self.assertIn("name: autoresearch-judge", text)
            self.assertIn(
                "types: [opened, reopened, labeled, unlabeled, synchronize]", text,
            )
            self.assertIn("runs-on: [self-hosted, macOS, stwo-judge]", text)
            evaluate, remainder = text.split("\n  publish:\n", 1)
            publish, required = remainder.split("\n  required:\n", 1)
            header = text.split("jobs:", 1)[0]
            self.assertNotIn("concurrency:", header)
            self.assertIn("group: autoresearch-judge-${{ github.repository }}", evaluate)
            self.assertIn("cancel-in-progress: false", evaluate)
            self.assertIn("contents: read", evaluate)
            self.assertNotIn("secrets.JUDGE_HMAC_SECRET", evaluate)
            self.assertNotIn("contents: write", evaluate)
            self.assertIn("persist-credentials: false", evaluate)
            self.assertLess(
                evaluate.index("Validate event identity and locked paths"),
                evaluate.index("Evaluate with no promotion authority"),
            )
            self.assertIn("contents: write", publish)
            self.assertIn("name: autoresearch-publish", publish)
            self.assertIn("if: needs.evaluate.result == 'success'", publish)
            self.assertLess(
                publish.index("Revalidate immutable candidate and evidence binding"),
                publish.index("secrets.JUDGE_HMAC_SECRET"),
            )
            self.assertLess(
                publish.index("Sign the identity-bound verdict"),
                publish.index("Publish to the judge-only branch"),
            )
            self.assertIn("name: autoresearch-judge", required)
            self.assertIn("needs: [evaluate, publish]", required)
            self.assertIn("if: always()", required)
            self.assertIn("permissions: {}", required)
            self.assertNotIn("contents: write", required)
            self.assertIn('if [[ "$IS_SUBMISSION" != "true" ]]', required)
            self.assertIn('if [[ "$EVALUATE_RESULT" != "success" ]]', required)
            self.assertIn('if [[ "$PUBLISH_RESULT" != "success" ]]', required)

    def test_required_judge_check_is_fail_closed_for_submissions(self) -> None:
        cases = (
            ("false", "skipped", "skipped", 0),
            ("true", "success", "success", 0),
            ("true", "failure", "skipped", 1),
            ("true", "success", "failure", 1),
        )
        for path in (WORKFLOWS[0], WORKFLOWS[2]):
            required = path.read_text(encoding="utf-8").split(
                "\n  required:\n", 1,
            )[1]
            script = textwrap.dedent(required.split("        run: |\n", 1)[1])
            for submission, evaluate, publish, expected in cases:
                with self.subTest(
                    path=path,
                    submission=submission,
                    evaluate=evaluate,
                    publish=publish,
                ):
                    result = subprocess.run(
                        ["bash", "-c", script],
                        env={
                            **os.environ,
                            "IS_SUBMISSION": submission,
                            "EVALUATE_RESULT": evaluate,
                            "PUBLISH_RESULT": publish,
                        },
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    self.assertEqual(result.returncode, expected, result.stderr)

    def test_promote_identity_signature_and_board_authority(self) -> None:
        for path in (WORKFLOWS[1], WORKFLOWS[3]):
            text = path.read_text(encoding="utf-8")
            self.assertIn("name: autoresearch-promote", text)
            self.assertIn("permissions: {}", text)
            self.assertIn("contents: write", text)
            self.assertNotIn("pull-requests: write", text)
            self.assertNotIn("issues: write", text)
            self.assertLess(
                text.index("Validate main identity and refresh queued authority"),
                text.index("secrets.JUDGE_HMAC_SECRET"),
            )
            self.assertIn("python3 autoresearch/bots/promote_action.py", text)

    def test_required_check_names_are_stable(self) -> None:
        paths = (
            ROOT / ".github/workflows/validate.yml",
            ROOT / "autoresearch/workflows/validate.yml",
        )
        self.assertEqual(paths[0].read_bytes(), paths[1].read_bytes())
        for path in paths:
            text = path.read_text(encoding="utf-8")
            self.assertIn(
                "name: autoresearch-validate",
                text,
            )
            self.assertIn("group: autoresearch-validate-${{ github.event.pull_request.number }}", text)
            self.assertIn("id: harness-scope", text)
            self.assertIn("if: steps.harness-scope.outputs.required == 'true'", text)

        source = (ROOT / "autoresearch/bots/promote_action.py").read_text(encoding="utf-8")
        self.assertIn("signing.verify(verdict)", source)
        self.assertIn("require_current_promotion_authority(repo, verdict)", source)


class WorkflowPolicyTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.repo = Path(temporary.name)
        git(self.repo, "init", "-q")
        git(self.repo, "config", "user.name", "Test")
        git(self.repo, "config", "user.email", "test@example.com")
        source = self.repo / "src/prover"
        source.mkdir(parents=True)
        (source / "fri.zig").write_text("const value = 1;\n", encoding="utf-8")
        git(self.repo, "add", ".")
        git(self.repo, "commit", "-qm", "base")
        self.base = git(self.repo, "rev-parse", "HEAD")

        (source / "fri.zig").write_text("const value = 2;\n", encoding="utf-8")
        submission = self.repo / "autoresearch/submissions/20260721-test"
        submission.mkdir(parents=True)
        (submission / "note.md").write_text("# Test\n", encoding="utf-8")
        (submission / "verdict.json").write_text("{}\n", encoding="utf-8")
        (submission / "delta.json").write_text("{}\n", encoding="utf-8")
        git(self.repo, "add", ".")
        git(self.repo, "commit", "-qm", "candidate")
        self.candidate = git(self.repo, "rev-parse", "HEAD")

    def test_preflight_binds_candidate_tree_and_submission(self) -> None:
        receipt = inspect_candidate(self.repo, ROOT, self.base, self.candidate)
        self.assertEqual(receipt["base_commit"], self.base)
        self.assertEqual(receipt["candidate_commit"], self.candidate)
        self.assertEqual(receipt["submission_id"], "20260721-test")
        self.assertRegex(receipt["receipt_sha256"], r"^[0-9a-f]{64}$")

    def test_new_placeholder_author_identity_fails_closed(self) -> None:
        findings = author_identity_findings(self.base, self.repo)
        self.assertEqual(len(findings), 1)
        self.assertIn("Test <test@example.com>", findings[0])

        git(self.repo, "config", "user.name", "Alice Example")
        git(
            self.repo, "config", "user.email",
            "101+alice@users.noreply.github.com",
        )
        git(self.repo, "commit", "--allow-empty", "-qm", "attributable")
        self.assertEqual(author_identity_findings(self.candidate, self.repo), [])

    def test_locked_candidate_change_is_rejected(self) -> None:
        workflow = self.repo / ".github/workflows"
        workflow.mkdir(parents=True)
        (workflow / "attack.yml").write_text("name: attack\n", encoding="utf-8")
        git(self.repo, "add", ".")
        git(self.repo, "commit", "-qm", "locked change")
        with self.assertRaisesRegex(PolicyError, "locked paths changed"):
            inspect_candidate(self.repo, ROOT, self.base, "HEAD")

    def test_finalizer_rejects_identity_mismatch_and_replaces_sentinel(self) -> None:
        receipt = inspect_candidate(self.repo, ROOT, self.base, self.candidate)
        unsigned = self.repo / "unsigned.json"
        signed = self.repo / "signed.json"
        verdict = {
            "kind": "judged",
            "repo_commit": self.candidate[:12],
            "predecessor_commit": self.base[:12],
            "submission_id": receipt["submission_id"],
            "judge_signature": "sentinel",
        }
        unsigned.write_text(json.dumps(verdict), encoding="utf-8")
        with mock.patch.dict(os.environ, {"JUDGE_HMAC_SECRET": "test-authority"}):
            finalize_verdict(unsigned, receipt, signed)
        self.assertRegex(
            json.loads(signed.read_text(encoding="utf-8"))["judge_signature"],
            r"^[0-9a-f]{64}$",
        )

        verdict["repo_commit"] = "0" * 12
        unsigned.write_text(json.dumps(verdict), encoding="utf-8")
        with self.assertRaisesRegex(PolicyError, "repo_commit"):
            finalize_verdict(unsigned, receipt, signed)


if __name__ == "__main__":
    unittest.main()
