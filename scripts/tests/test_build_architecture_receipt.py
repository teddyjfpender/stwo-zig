from __future__ import annotations

import copy
import hashlib
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts.architecture.build_architecture_receipt_lib import codec, producer, receipt, verifier
from scripts.architecture.build_architecture_receipt_lib.model import (
    EVIDENCE_NAMES,
    HOST_SCHEMA,
    STATUS_NO_GO,
    STATUS_NOT_ALLOCATED,
    STATUS_PASS,
    ReceiptError,
)
from scripts.architecture.build_architecture_receipt_lib.protocol import load_protocol
from scripts.architecture.build_architecture_receipt_lib.trust import canonical_artifact_name


COMMIT = "1" * 40
TREE = "2" * 40
WORKFLOW_SHA = "3" * 40
SESSION = "4" * 64
AUTHORITY_COMMIT = "a" * 40
AUTHORITY_TREE = "b" * 40
RUN_ID = "12345"
RUN_ATTEMPT = "2"
NOW = 1_800_000_000


def digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


class ReceiptFixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.protocol_path = root / "conformance/build-architecture-receipt-protocol-v1.json"
        self.product_schema_path = root / "build_support/graph/product.zig"
        self.workflow_path = root / ".github/workflows/architecture-authority.yml"
        self.plan_path = root / "conformance/build-architecture-ci-plan-v1.json"
        for destination, source in (
            (
                self.protocol_path,
                Path("conformance/build-architecture-receipt-protocol-v1.json"),
            ),
            (self.product_schema_path, Path("build_support/graph/product.zig")),
            (self.workflow_path, Path(".github/workflows/architecture-authority.yml")),
            (self.plan_path, Path("conformance/build-architecture-ci-plan-v1.json")),
            (
                root / "conformance/build-architecture-external-verifier-v1.json",
                Path("conformance/build-architecture-external-verifier-v1.json"),
            ),
        ):
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(source.read_bytes())
        self.protocol, self.protocol_sha256 = load_protocol(self.protocol_path)
        self.product_schema_sha256 = codec.sha256_file(self.product_schema_path)
        self.workflow_sha256 = codec.sha256_file(self.workflow_path)
        self.authority_plan_sha256 = codec.sha256_file(self.plan_path)
        self.preimages = {}
        for role in ("linux", "macos"):
            path = root / f"{role}-preimages.json"
            path.write_text(f'{{"role":"{role}"}}', encoding="utf-8")
            self.preimages[role] = path
        trust = self.protocol["trust"]
        self.source = {
            "repository": trust["repository"],
            "commit": COMMIT,
            "tree": TREE,
            "clean": True,
            "dirty_content_sha256": digest("clean"),
        }
        self.environment = {
            "GITHUB_ACTIONS": "true",
            "GITHUB_REPOSITORY": trust["repository"],
            "GITHUB_REPOSITORY_ID": str(trust["repository_id"]),
            "GITHUB_REPOSITORY_OWNER_ID": str(trust["repository_owner_id"]),
            "GITHUB_WORKFLOW_REF": trust["workflow_ref"],
            "GITHUB_WORKFLOW_SHA": WORKFLOW_SHA,
            "GITHUB_RUN_ID": RUN_ID,
            "GITHUB_RUN_ATTEMPT": RUN_ATTEMPT,
            "GITHUB_JOB": self.protocol["aggregate_job"],
            "STWO_ARCHITECTURE_AUTHORITY_COMMIT": AUTHORITY_COMMIT,
            "STWO_ARCHITECTURE_AUTHORITY_TREE": AUTHORITY_TREE,
            "STWO_ARCHITECTURE_AUTHORITY_PLAN_SHA256": self.authority_plan_sha256,
        }

    def host_receipt(self, role: str) -> dict[str, object]:
        role_policy = self.protocol["host_roles"][role]
        allocated = set(role_policy["allocated_checkpoints"])
        checkpoints = {}
        for checkpoint in self.protocol["checkpoint_order"][:-1]:
            if checkpoint in allocated:
                checkpoints[checkpoint] = {
                    "status": STATUS_PASS,
                    "reason": f"synthetic policy fixture passed {checkpoint}",
                    "evidence_sha256": [digest(f"{role}-{checkpoint}")],
                }
            else:
                checkpoints[checkpoint] = {
                    "status": STATUS_NOT_ALLOCATED,
                    "reason": f"{checkpoint} is not allocated to {role}",
                    "evidence_sha256": [],
                }
        products = []
        for product_id in sorted(role_policy["required_products"]):
            artifact = digest(f"{role}-{product_id}-artifact")
            products.append({
                "product_id": product_id,
                "product_identity_sha256": digest(f"{role}-{product_id}-identity"),
                "artifact_sha256": artifact,
                "executable_sha256": (
                    artifact if self.protocol["products"][product_id] == "executable" else None
                ),
                "status": STATUS_PASS,
                "reason": "synthetic policy fixture",
            })
        commands = []
        for ordinal, phase in enumerate(role_policy["allocated_checkpoints"]):
            commands.append({
                "ordinal": ordinal,
                "phase": phase,
                "argv": ["fixture-gate", phase],
                "duration_ms": ordinal + 1,
                "exit_code": 0,
                "skipped_tests": 0,
                "stdout_sha256": digest(f"{role}-{phase}-stdout"),
                "stderr_sha256": digest(f"{role}-{phase}-stderr"),
            })
        evidence = {
            name: {
                "status": STATUS_PASS,
                "reason": "synthetic policy fixture",
                "sha256": digest(f"{role}-{name}"),
            }
            for name in EVIDENCE_NAMES
        }
        raw_host = {
            "role": role,
            "os": role_policy["os"],
            "os_release": "fixture-os",
            "architecture": "fixture-arch",
            "platform": "fixture-platform",
            "runner_name": "fixture-runner",
            "runner_environment": "github-hosted",
        }
        host = {
            **raw_host,
            "identity_sha256": codec.sha256_bytes(codec.canonical_bytes(raw_host)),
        }
        run = {
            "provider": "github-actions",
            "repository": self.protocol["trust"]["repository"],
            "repository_id": self.protocol["trust"]["repository_id"],
            "repository_owner_id": self.protocol["trust"]["repository_owner_id"],
            "run_id": RUN_ID,
            "run_attempt": RUN_ATTEMPT,
            "job": role_policy["producer_job"],
            "session_nonce": SESSION,
        }
        value = codec.with_content_digest({
            "schema": HOST_SCHEMA,
            "schema_version": 1,
            "created_at_unix": NOW,
            "source": copy.deepcopy(self.source),
            "authority": {
                "repository": self.protocol["trust"]["repository"],
                "commit": AUTHORITY_COMMIT,
                "tree": AUTHORITY_TREE,
                "plan_sha256": self.authority_plan_sha256,
            },
            "evidence_preimages_sha256": codec.sha256_file(self.preimages[role]),
            "product_schema_sha256": self.product_schema_sha256,
            "protocol_manifest_sha256": self.protocol_sha256,
            "workflow": {
                "path": self.protocol["trust"]["workflow_path"],
                "definition_sha256": self.workflow_sha256,
                "ref": self.protocol["trust"]["workflow_ref"],
                "sha": WORKFLOW_SHA,
            },
            "run": run,
            "host": host,
            "toolchains": {"python": "fixture", "zig": "fixture", "rustc": "fixture"},
            "checkpoints": checkpoints,
            "products": products,
            "commands": commands,
            "evidence": evidence,
            "attestation": {
                "kind": "github-actions-artifact-v1",
                "artifact_name": canonical_artifact_name(role, COMMIT, RUN_ID, RUN_ATTEMPT),
            },
            "verdict": STATUS_PASS,
        })
        receipt.validate_host_receipt(value, self.protocol, expected_role=role)
        return value

    def write_host(self, role: str, value: dict[str, object] | None = None) -> Path:
        path = self.root / "artifacts" / COMMIT / role / f"{RUN_ID}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(codec.canonical_bytes(value or self.host_receipt(role)))
        return path

    def rebind(self, value: dict[str, object]) -> dict[str, object]:
        without = {key: item for key, item in value.items() if key != "content_sha256"}
        return codec.with_content_digest(without)

    def verify(self, linux: Path, macos: Path, output: Path | None = None):
        with (
            mock.patch(
                "scripts.architecture.build_architecture_receipt_lib.verifier.source_identity",
                return_value=self.source,
            ),
            mock.patch("scripts.architecture.architecture_host_gate_lib.preimages.verify"),
        ):
            return verifier.verify(
                root=self.root,
                protocol_path=self.protocol_path,
                product_schema_path=self.product_schema_path,
                workflow_path=self.workflow_path,
                linux_receipt_path=linux,
                macos_receipt_path=macos,
                output_root=output or self.root / "out",
                candidate=COMMIT,
                session_nonce=SESSION,
                linux_preimages_path=self.preimages["linux"],
                macos_preimages_path=self.preimages["macos"],
                environment=self.environment,
                now=NOW,
            )


class BuildArchitectureReceiptTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.fixture = ReceiptFixture(Path(self.temporary.name))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_valid_synthetic_pair_exercises_pass_policy(self) -> None:
        output, aggregate, digest_value = self.fixture.verify(
            self.fixture.write_host("linux"), self.fixture.write_host("macos"),
        )
        self.assertEqual(STATUS_PASS, aggregate["verdict"])
        self.assertEqual(STATUS_PASS, aggregate["checkpoints"]["BG-15"]["status"])
        self.assertEqual(output, (self.fixture.root / "out" / COMMIT / "receipt.json").resolve())
        self.assertEqual(digest_value, codec.sha256_file(output))

    def test_host_producer_derives_trusted_pass_and_local_no_go(self) -> None:
        root = self.fixture.root
        subprocess.run(["git", "init", "-q"], cwd=root, check=True)
        subprocess.run(["git", "config", "user.email", "fixture@example.com"], cwd=root, check=True)
        subprocess.run(["git", "config", "user.name", "Fixture"], cwd=root, check=True)
        role = producer.detected_role()
        host = self.fixture.host_receipt(role)
        evidence = {
            "schema": "build-architecture-host-evidence-v1",
            "checkpoints": {
                checkpoint: host["checkpoints"][checkpoint]
                for checkpoint in self.fixture.protocol["host_roles"][role]["allocated_checkpoints"]
            },
            "products": host["products"],
            "commands": host["commands"],
            "evidence": host["evidence"],
        }
        evidence_path = root / "evidence.json"
        evidence_path.write_bytes(codec.canonical_bytes(evidence))
        subprocess.run(["git", "add", "."], cwd=root, check=True)
        subprocess.run(["git", "commit", "-qm", "fixture"], cwd=root, check=True)
        candidate = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=root, check=True, capture_output=True, text=True,
        ).stdout.strip()
        environment = {
            **self.fixture.environment,
            "GITHUB_JOB": self.fixture.protocol["host_roles"][role]["producer_job"],
        }
        with mock.patch.dict("os.environ", environment, clear=False):
            output, trusted, _ = producer.produce(
                root=root,
                protocol_path=self.fixture.protocol_path,
                product_schema_path=self.fixture.product_schema_path,
                workflow_path=self.fixture.workflow_path,
                evidence_path=evidence_path,
                output_root=root / "trusted-out",
                role=role,
                candidate=candidate,
                run_id=RUN_ID,
                run_attempt=RUN_ATTEMPT,
                session_nonce=SESSION,
                attestation_mode="github-actions-artifact",
                authority_commit=AUTHORITY_COMMIT,
                authority_tree=AUTHORITY_TREE,
                authority_plan_sha256=self.fixture.authority_plan_sha256,
                evidence_preimages_path=self.fixture.preimages[role],
                now=NOW,
            )
        self.assertEqual(STATUS_PASS, trusted["verdict"])
        self.assertTrue(output.is_file())

        local, local_receipt, _ = producer.produce(
            root=root,
            protocol_path=self.fixture.protocol_path,
            product_schema_path=self.fixture.product_schema_path,
            workflow_path=self.fixture.workflow_path,
            evidence_path=evidence_path,
            output_root=root / "local-out",
            role=role,
            candidate=candidate,
            run_id="999",
            run_attempt="1",
            session_nonce="a" * 64,
            attestation_mode="local-unsigned",
            now=NOW,
        )
        self.assertEqual(STATUS_NO_GO, local_receipt["verdict"])
        self.assertTrue(local.is_file())

    def test_local_unsigned_receipt_cannot_enter_aggregate(self) -> None:
        linux = self.fixture.host_receipt("linux")
        linux["attestation"] = {"kind": "local-unsigned-v1", "artifact_name": None}
        linux["run"] = {**linux["run"], "provider": "local", "job": "local-diagnostic"}
        linux["workflow"] = {
            **linux["workflow"], "ref": "local", "sha": COMMIT,
        }
        linux["verdict"] = STATUS_NO_GO
        linux = self.fixture.rebind(linux)
        with self.assertRaisesRegex(ReceiptError, "local unsigned"):
            self.fixture.verify(
                self.fixture.write_host("linux", linux), self.fixture.write_host("macos"),
            )

    def test_incomplete_checkpoint_stays_no_go_and_cannot_write_final_receipt(self) -> None:
        linux = self.fixture.host_receipt("linux")
        linux["checkpoints"]["BG-03"] = {
            "status": STATUS_NO_GO,
            "reason": "real gate is not implemented",
            "evidence_sha256": [],
        }
        linux["verdict"] = STATUS_NO_GO
        linux = self.fixture.rebind(linux)
        output, aggregate, _ = self.fixture.verify(
            self.fixture.write_host("linux", linux), self.fixture.write_host("macos"),
        )
        self.assertEqual(STATUS_NO_GO, aggregate["verdict"])
        self.assertIn("attempts", output.parts)
        self.assertFalse((self.fixture.root / "out" / COMMIT / "receipt.json").exists())

    def test_duplicate_key_and_noncanonical_json_are_rejected(self) -> None:
        path = self.fixture.root / "duplicate.json"
        path.write_text('{"schema":"one","schema":"two"}', encoding="utf-8")
        with self.assertRaisesRegex(ReceiptError, "duplicate JSON field schema"):
            codec.strict_json(path, 1024)
        path.write_text('{"schema": "one"}\n', encoding="utf-8")
        with self.assertRaisesRegex(ReceiptError, "canonical wire form"):
            codec.strict_json(path, 1024)

    def test_role_swap_and_same_path_replay_are_rejected(self) -> None:
        linux = self.fixture.write_host("linux")
        macos = self.fixture.write_host("macos")
        with self.assertRaisesRegex(ReceiptError, "role is invalid or misplaced"):
            self.fixture.verify(macos, linux)
        with self.assertRaisesRegex(ReceiptError, "paths are identical"):
            self.fixture.verify(linux, linux)

    def test_commit_tree_product_protocol_and_workflow_mismatches_are_rejected(self) -> None:
        mutations = (
            ("source", "commit", "5" * 40, "canonical bounded layout"),
            ("source", "tree", "6" * 40, "candidate commit/tree mismatch"),
            (None, "product_schema_sha256", "7" * 64, "product schema mismatch"),
            (None, "protocol_manifest_sha256", "8" * 64, "protocol manifest mismatch"),
            ("workflow", "definition_sha256", "9" * 64, "workflow identity mismatch"),
        )
        for parent, field, changed, message in mutations:
            with self.subTest(field=field):
                linux_value = self.fixture.host_receipt("linux")
                target = linux_value if parent is None else linux_value[parent]
                target[field] = changed
                linux_value = self.fixture.rebind(linux_value)
                with self.assertRaisesRegex(ReceiptError, message):
                    self.fixture.verify(
                        self.fixture.write_host("linux", linux_value),
                        self.fixture.write_host("macos"),
                    )
                (self.fixture.root / "artifacts").mkdir(exist_ok=True)

    def test_run_session_artifact_and_role_replay_mutations_are_rejected(self) -> None:
        mutations = (
            ("run", "run_id", "999", "canonical bounded layout"),
            ("run", "run_attempt", "3", "run identity mismatch or replay"),
            ("run", "session_nonce", "a" * 64, "run identity mismatch or replay"),
            ("attestation", "artifact_name", "wrong-artifact", "artifact-channel name mismatch"),
        )
        for parent, field, changed, message in mutations:
            with self.subTest(field=field):
                linux_value = self.fixture.host_receipt("linux")
                linux_value[parent][field] = changed
                linux_value = self.fixture.rebind(linux_value)
                with self.assertRaisesRegex(ReceiptError, message):
                    self.fixture.verify(
                        self.fixture.write_host("linux", linux_value),
                        self.fixture.write_host("macos"),
                    )

    def test_authority_and_bounded_preimage_mutations_are_rejected(self) -> None:
        for field, changed in (
            ("commit", "d" * 40),
            ("tree", "e" * 40),
            ("plan_sha256", "f" * 64),
        ):
            with self.subTest(field=field):
                linux = self.fixture.host_receipt("linux")
                linux["authority"][field] = changed
                linux = self.fixture.rebind(linux)
                with self.assertRaisesRegex(ReceiptError, "authority identity mismatch"):
                    self.fixture.verify(
                        self.fixture.write_host("linux", linux),
                        self.fixture.write_host("macos"),
                    )

        linux_path = self.fixture.write_host("linux")
        macos_path = self.fixture.write_host("macos")
        self.fixture.preimages["linux"].write_text('{"role":"substituted"}')
        with self.assertRaisesRegex(ReceiptError, "preimage digest mismatch"):
            self.fixture.verify(linux_path, macos_path)

    def test_aggregate_authority_requires_exact_protected_workflow_environment(self) -> None:
        linux = self.fixture.write_host("linux")
        macos = self.fixture.write_host("macos")
        mutations = (
            ("GITHUB_REPOSITORY", "attacker/fork", "environment mismatch"),
            ("GITHUB_REPOSITORY_ID", "999", "environment mismatch"),
            ("GITHUB_REPOSITORY_OWNER_ID", "999", "environment mismatch"),
            (
                "GITHUB_WORKFLOW_REF",
                "attacker/fork/.github/workflows/ci.yml@refs/heads/main",
                "environment mismatch",
            ),
            ("GITHUB_WORKFLOW_SHA", "a" * 40, "workflow identity mismatch"),
            ("GITHUB_RUN_ID", "999", "run identity mismatch or replay"),
            ("GITHUB_RUN_ATTEMPT", "3", "run identity mismatch or replay"),
            ("GITHUB_JOB", "architecture-linux", "environment mismatch"),
        )
        for field, changed, message in mutations:
            with self.subTest(field=field):
                environment = {**self.fixture.environment, field: changed}
                with mock.patch(
                    "scripts.architecture.build_architecture_receipt_lib.verifier.source_identity",
                    return_value=self.fixture.source,
                ):
                    with self.assertRaisesRegex(ReceiptError, message):
                        verifier.verify(
                            root=self.fixture.root,
                            protocol_path=self.fixture.protocol_path,
                            product_schema_path=self.fixture.product_schema_path,
                            workflow_path=self.fixture.workflow_path,
                            linux_receipt_path=linux,
                            macos_receipt_path=macos,
                            output_root=self.fixture.root / "out-trust",
                            candidate=COMMIT,
                            session_nonce=SESSION,
                            environment=environment,
                            now=NOW,
                        )

    def test_stale_future_dirty_and_unsupported_host_are_rejected(self) -> None:
        mutations = (
            ("created_at_unix", NOW - 21601, "stale"),
            ("created_at_unix", NOW + 301, "future"),
        )
        for field, changed, message in mutations:
            with self.subTest(field=field):
                linux_value = self.fixture.host_receipt("linux")
                linux_value[field] = changed
                linux_value = self.fixture.rebind(linux_value)
                with self.assertRaisesRegex(ReceiptError, message):
                    self.fixture.verify(
                        self.fixture.write_host("linux", linux_value),
                        self.fixture.write_host("macos"),
                    )

        linux_value = self.fixture.host_receipt("linux")
        linux_value["source"] = {**linux_value["source"], "clean": False}
        linux_value["verdict"] = STATUS_NO_GO
        linux_value = self.fixture.rebind(linux_value)
        with self.assertRaisesRegex(ReceiptError, "source is dirty"):
            self.fixture.verify(
                self.fixture.write_host("linux", linux_value), self.fixture.write_host("macos"),
            )

        linux_value = self.fixture.host_receipt("linux")
        raw_host = {**linux_value["host"], "os": "macos"}
        raw_host.pop("identity_sha256")
        linux_value["host"] = {
            **raw_host,
            "identity_sha256": codec.sha256_bytes(codec.canonical_bytes(raw_host)),
        }
        linux_value["verdict"] = STATUS_NO_GO
        linux_value = self.fixture.rebind(linux_value)
        with self.assertRaisesRegex(ReceiptError, "unsupported host"):
            self.fixture.verify(
                self.fixture.write_host("linux", linux_value), self.fixture.write_host("macos"),
            )

    def test_reordered_phases_skips_and_missing_product_force_rejection_or_no_go(self) -> None:
        linux_value = self.fixture.host_receipt("linux")
        linux_value["commands"][0], linux_value["commands"][1] = (
            linux_value["commands"][1], linux_value["commands"][0],
        )
        linux_value["commands"][0]["ordinal"] = 0
        linux_value["commands"][1]["ordinal"] = 1
        linux_value = self.fixture.rebind(linux_value)
        with self.assertRaisesRegex(ReceiptError, "phases are reordered"):
            self.fixture.verify(
                self.fixture.write_host("linux", linux_value), self.fixture.write_host("macos"),
            )

        for mutation in ("skip", "product"):
            with self.subTest(mutation=mutation):
                linux_value = self.fixture.host_receipt("linux")
                if mutation == "skip":
                    linux_value["commands"][0]["skipped_tests"] = 1
                else:
                    linux_value["products"].pop()
                linux_value["verdict"] = STATUS_NO_GO
                linux_value = self.fixture.rebind(linux_value)
                _, aggregate, _ = self.fixture.verify(
                    self.fixture.write_host("linux", linux_value),
                    self.fixture.write_host("macos"),
                    self.fixture.root / f"out-{mutation}",
                )
                self.assertEqual(STATUS_NO_GO, aggregate["verdict"])

    def test_unknown_fields_content_mutation_size_and_path_escape_are_rejected(self) -> None:
        linux_value = self.fixture.host_receipt("linux")
        linux_value["unexpected"] = True
        with self.assertRaisesRegex(ReceiptError, "fields drifted"):
            receipt.validate_host_receipt(linux_value, self.fixture.protocol)

        linux_value = self.fixture.host_receipt("linux")
        linux_value["verdict"] = STATUS_NO_GO
        with self.assertRaisesRegex(ReceiptError, "verdict is not derived|content digest"):
            receipt.validate_host_receipt(linux_value, self.fixture.protocol)

        oversized = self.fixture.root / "oversized.json"
        oversized.write_bytes(b"x" * 1025)
        with self.assertRaisesRegex(ReceiptError, "exceeds 1024 bytes"):
            codec.strict_json(oversized, 1024)
        with self.assertRaisesRegex(ReceiptError, "escapes"):
            codec.bounded_child(self.fixture.root / "out", "..", "escape.json")

    def test_final_receipt_is_immutable_against_aggregate_replay(self) -> None:
        linux = self.fixture.write_host("linux")
        macos = self.fixture.write_host("macos")
        self.fixture.verify(linux, macos)
        with self.assertRaisesRegex(ReceiptError, "replay or replace"):
            self.fixture.verify(linux, macos)

    def test_protocol_manifest_rejects_duplicate_allocations_and_unknown_products(self) -> None:
        changed = copy.deepcopy(self.fixture.protocol)
        changed["host_roles"]["linux"]["required_products"].append("stwo-core")
        from scripts.architecture.build_architecture_receipt_lib.protocol import validate_protocol

        with self.assertRaisesRegex(ReceiptError, "contains duplicates"):
            validate_protocol(changed)
        changed = copy.deepcopy(self.fixture.protocol)
        changed["host_roles"]["linux"]["required_products"][0] = "unknown"
        with self.assertRaisesRegex(ReceiptError, "unknown product"):
            validate_protocol(changed)


if __name__ == "__main__":
    unittest.main()
