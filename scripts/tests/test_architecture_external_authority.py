from __future__ import annotations

import copy
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from scripts import architecture_external_authority as authority
from scripts import architecture_native_oracle_selection as native_selection
from scripts.build_architecture_receipt_lib.model import ReceiptError


AUTHORITY = "a" * 40
CANDIDATE = "b" * 40
TREE = "c" * 40
RUN_ID = 71
ATTEMPT = 2


def protocol() -> dict[str, object]:
    return {
        "trust": {
            "repository": "teddyjfpender/stwo-zig",
            "repository_id": 1152389958,
            "repository_owner_id": 92999717,
            "workflow_ref": (
                "teddyjfpender/stwo-zig/.github/workflows/"
                "architecture-authority.yml@refs/heads/main"
            ),
        },
        "host_roles": {
            "linux": {"producer_job": "architecture-authority-linux"},
            "macos": {"producer_job": "architecture-authority-macos"},
        },
        "aggregate_job": "architecture-authority-verify",
    }


def environment(job: str) -> dict[str, str]:
    trust = protocol()["trust"]
    assert isinstance(trust, dict)
    return {
        "ARCHITECTURE_AUTHORITY_SHA": AUTHORITY,
        "GITHUB_ACTIONS": "true",
        "GITHUB_REPOSITORY": str(trust["repository"]),
        "GITHUB_REPOSITORY_ID": str(trust["repository_id"]),
        "GITHUB_REPOSITORY_OWNER_ID": str(trust["repository_owner_id"]),
        "GITHUB_WORKFLOW_REF": str(trust["workflow_ref"]),
        "GITHUB_WORKFLOW_SHA": AUTHORITY,
        "GITHUB_JOB": job,
        "STWO_ARCHITECTURE_DISPATCH_ACTOR_ID": str(trust["repository_owner_id"]),
        "GITHUB_RUN_ID": str(RUN_ID),
        "GITHUB_RUN_ATTEMPT": str(ATTEMPT),
    }


def native_api() -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    run = {
        "id": RUN_ID,
        "run_attempt": ATTEMPT,
        "path": ".github/workflows/native-oracle.yml",
        "event": "workflow_dispatch",
        "head_branch": "main",
        "head_sha": AUTHORITY,
        "head_commit": {"tree_id": TREE},
        "repository": {"full_name": "teddyjfpender/stwo-zig", "id": 1152389958},
        "actor": {"id": 92999717},
        "triggering_actor": {"id": 92999717},
        "status": "completed",
        "conclusion": "success",
    }
    jobs = {"jobs": [{
        "id": 91,
        "name": "Native oracle producer (linux)",
        "status": "completed",
        "conclusion": "success",
        "run_id": RUN_ID,
        "run_attempt": ATTEMPT,
        "head_sha": AUTHORITY,
    }]}
    artifacts = {"artifacts": [{
        "id": 101,
        "name": f"native-oracle-linux-{AUTHORITY}-{RUN_ID}-{ATTEMPT}",
        "digest": "sha256:" + "d" * 64,
        "expired": False,
        "workflow_run": {"id": RUN_ID, "head_sha": AUTHORITY},
    }]}
    return run, jobs, artifacts


class ArchitectureProducerSelectionTest(unittest.TestCase):
    def test_native_selection_binds_run_job_artifact_and_workflow(self) -> None:
        run, jobs, artifacts = native_api()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            workflow = root / ".github/workflows/native-oracle.yml"
            workflow.parent.mkdir(parents=True)
            workflow.write_text("name: trusted\n", encoding="utf-8")
            selected = native_selection.select(
                role="linux", run=run, jobs=jobs, artifacts=artifacts,
                authority_commit=AUTHORITY, authority_root=root,
            )
        self.assertEqual(101, selected["artifact_id"])
        self.assertEqual(AUTHORITY, selected["producer"]["workflow_sha"])

        for target, field, value in (
            (run, "status", "in_progress"),
            (jobs["jobs"][0], "head_sha", CANDIDATE),
            (artifacts["artifacts"][0]["workflow_run"], "head_sha", CANDIDATE),
        ):
            changed_run, changed_jobs, changed_artifacts = copy.deepcopy(native_api())
            choices = {
                id(run): changed_run,
                id(jobs["jobs"][0]): changed_jobs["jobs"][0],
                id(artifacts["artifacts"][0]["workflow_run"]): (
                    changed_artifacts["artifacts"][0]["workflow_run"]
                ),
            }
            choices[id(target)][field] = value
            with tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                workflow = root / ".github/workflows/native-oracle.yml"
                workflow.parent.mkdir(parents=True)
                workflow.write_text("name: trusted\n", encoding="utf-8")
                with self.assertRaises(native_selection.SelectionError):
                    native_selection.select(
                        role="linux", run=changed_run, jobs=changed_jobs,
                        artifacts=changed_artifacts, authority_commit=AUTHORITY,
                        authority_root=root,
                    )

class ArchitectureExternalAuthorityTest(unittest.TestCase):
    def test_authentication_requires_distinct_protected_authority(self) -> None:
        candidate_root = Path("/tmp/candidate-fixture").resolve()
        git_values = {
            (str(authority.AUTHORITY_ROOT), ("rev-parse", "HEAD")): AUTHORITY,
            (str(authority.AUTHORITY_ROOT), ("status", "--porcelain=v1", "--untracked-files=all")): "",
            (str(authority.AUTHORITY_ROOT), ("rev-parse", "HEAD^{tree}")): "d" * 40,
            (str(candidate_root), ("rev-parse", "HEAD")): CANDIDATE,
            (str(candidate_root), ("status", "--porcelain=v1", "--untracked-files=all")): "",
            (str(candidate_root), ("rev-parse", "HEAD^{tree}")): TREE,
        }
        with (
            mock.patch.object(authority, "load_contract", return_value={
                "authority_workflow": {"path": ".github/workflows/architecture-authority.yml"},
            }),
            mock.patch.object(authority, "load_protocol", return_value=(protocol(), "digest")),
            mock.patch.object(authority, "_require_authority_modules"),
            mock.patch.object(
                authority, "_git",
                side_effect=lambda root, *args: git_values[(str(root), args)],
            ),
            mock.patch.object(
                authority, "_git_bytes", return_value=authority.AUTHORITY_WORKFLOW.read_bytes(),
            ),
            mock.patch.object(authority, "sha256_file", return_value="f" * 64),
        ):
            identity = authority.authenticate(
                candidate_root=candidate_root, candidate=CANDIDATE,
                expected_job="architecture-authority-linux",
                environment=environment("architecture-authority-linux"),
            )
            self.assertEqual(CANDIDATE, identity["candidate"])
            changed = environment("architecture-authority-linux")
            changed["ARCHITECTURE_AUTHORITY_SHA"] = CANDIDATE
            with self.assertRaisesRegex(ReceiptError, "equals candidate"):
                authority.authenticate(
                    candidate_root=candidate_root, candidate=CANDIDATE,
                    expected_job="architecture-authority-linux", environment=changed,
                )

    def test_authority_module_shadowing_is_rejected(self) -> None:
        name = "scripts.shadow_fixture"
        sys_modules = __import__("sys").modules
        sys_modules[name] = types.SimpleNamespace(__file__="/tmp/candidate/scripts/shadow.py")
        try:
            with self.assertRaisesRegex(ReceiptError, "shadowed"):
                authority._require_authority_modules()
        finally:
            del sys_modules[name]

    def test_run_host_reauthenticates_after_candidate_execution(self) -> None:
        role = "macos" if sys.platform == "darwin" else "linux"
        first = {
            "candidate": CANDIDATE, "candidate_tree": TREE,
            "authority_commit": AUTHORITY, "authority_tree": "d" * 40,
            "authority_plan_sha256": "e" * 64,
            "workflow_path": ".github/workflows/architecture-authority.yml",
        }
        changed = {**first, "candidate_tree": "f" * 40}
        with (
            mock.patch.object(authority, "load_protocol", return_value=(protocol(), "digest")),
            mock.patch.object(authority, "authenticate", side_effect=[first, changed]) as authenticate,
            mock.patch.object(
                authority.host_controller, "execute", return_value=(Path("evidence.json"), {}),
            ),
        ):
            with self.assertRaisesRegex(ReceiptError, "changed during"):
                authority.run_host(
                    role=role, candidate_root=Path("candidate"), candidate=CANDIDATE,
                    output_dir=Path("output"), receipt_root=Path("receipts"),
                    session_nonce="1" * 64,
                    native_oracle_bundle=Path("native"),
                    native_oracle_trust=Path("native-trust.json"),
                    environment=environment(f"architecture-authority-{role}"),
                )
        self.assertEqual(2, authenticate.call_count)


if __name__ == "__main__":
    unittest.main()
