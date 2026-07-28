"""Archived pre-Sail bundle identities and fail-closed forensic validation."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import stat
import subprocess
import time
from pathlib import Path
from typing import Any


SCHEMA = "riscv-release-bundle-v3"
TRUSTED_REPOSITORY = "teddyjfpender/stwo-zig"
TRUSTED_REPOSITORY_ID = 1_152_389_958
TRUSTED_OWNER_ID = 92_999_717
ORACLE_BOUNDARY_COUNT = 11
MAX_JSON_BYTES = 64 * 1024 * 1024
BUNDLE_RETENTION_SECONDS = 30 * 24 * 60 * 60
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
FILE_LAYOUT = {
    "release-gate.json": "release-gate.json",
    "oracle-receipt.json": "oracle-receipt.json",
    "cli/summary.json": "cli/summary.json",
    "bin/stwo-zig": "bin/stwo-zig",
    "bin/cp11_dump": "bin/cp11_dump",
    "bin/riscv-trace-dump": "bin/riscv-trace-dump",
}
COVERAGE = {
    "exhaustive_gate": "PASS",
    "cross_shard_cli_smoke": "PASS",
    "benchmark_cli_smoke": "PASS",
    "oracle_boundaries": f"{ORACLE_BOUNDARY_COUNT}/{ORACLE_BOUNDARY_COUNT}",
}
BOUNDARY_REJECTION_KEYS = {
    "phase-admission",
    "irrelevant-experimental",
    "malformed-elf",
    "undeclared-release-abi",
    "self-loop-completion",
    "unsupported-instruction",
    "oversized-input",
    "missing-input",
    "unsupported-backend",
    "existing-proof",
    "existing-report",
}
RELEASE_POLICY_PATHS = [
    ".github/workflows/ci.yml",
    "CONTRIBUTING.md",
    "autoresearch/MANIFEST.json",
    "build.zig",
    "build.zig.zon",
    "build_support",
    "conformance",
    "scripts",
    "vectors/riscv_elfs",
]
DOMAIN_PATHS = {
    "repository": (),
    "prover": (
        "build.zig",
        "build.zig.zon",
        "build_support",
        "src",
        "tools",
        "vectors/riscv_elfs",
    ),
    "cli_admission": (
        "src/tools/prove",
        "src/interop/riscv_artifact.zig",
        "scripts/riscv_staged_smoke.py",
        "scripts/riscv_staged_smoke_lib",
        "scripts/riscv_trace_vectors_lib/admission.py",
        "vectors/riscv_elfs",
    ),
    "release_gate": (
        ".github/workflows/ci.yml",
        "build.zig",
        "build_support",
        "scripts",
        "conformance",
        "autoresearch/MANIFEST.json",
    ),
    "oracle_adapter": (
        "scripts/riscv_release_oracle.py",
        "scripts/riscv_release_oracle_lib",
        "scripts/riscv_release_gate_lib/contract.py",
        "vectors/riscv_elfs",
    ),
}


class BundleError(ValueError):
    """The bundle cannot authorize the requested release gate."""


def canonical_sha256(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def exact_keys(value: object, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise BundleError(f"{label} fields drifted")
    return value


def require_commit(value: object, label: str) -> str:
    if not isinstance(value, str) or COMMIT_RE.fullmatch(value) is None:
        raise BundleError(f"{label} is not a full commit SHA")
    return value


def require_sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise BundleError(f"{label} is not a lowercase SHA-256")
    return value


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def strict_json(path: Path) -> dict[str, Any]:
    if path.stat().st_size > MAX_JSON_BYTES:
        raise BundleError(f"{path}: exceeds {MAX_JSON_BYTES} bytes")

    def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise BundleError(f"{path}: duplicate JSON field {key}")
            result[key] = value
        return result

    try:
        payload = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=strict_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise BundleError(f"cannot read {path}: {error}") from error
    if not isinstance(payload, dict):
        raise BundleError(f"{path}: root must be an object")
    return payload


def git_output(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=root, check=True, capture_output=True, text=True,
    ).stdout.strip()


def require_clean_head(root: Path, candidate: str) -> str:
    head = git_output(root, "rev-parse", "HEAD")
    if head != candidate:
        raise BundleError(f"candidate {candidate} does not match HEAD {head}")
    dirty = git_output(root, "status", "--porcelain=v1", "--untracked-files=all")
    if dirty:
        raise BundleError("candidate checkout is dirty")
    return git_output(root, "rev-parse", f"{candidate}^{{tree}}")


def tracked_domain(root: Path, paths: tuple[str, ...]) -> dict[str, object]:
    command = ["git", "ls-files", "--stage", "-z"]
    if paths:
        command.extend(("--", *paths))
    raw = subprocess.run(command, cwd=root, check=True, capture_output=True).stdout
    entries: list[tuple[str, str, bytes]] = []
    for entry in raw.split(b"\0"):
        if not entry:
            continue
        metadata, path_bytes = entry.split(b"\t", 1)
        mode, object_id, stage = metadata.decode("ascii").split(" ")
        if stage != "0":
            raise BundleError(f"unmerged path in content domain: {path_bytes!r}")
        entries.append((mode, object_id, path_bytes))
    if not entries:
        raise BundleError(f"empty content domain for paths {paths}")

    process = subprocess.Popen(
        ["git", "cat-file", "--batch"], cwd=root,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    if process.stdin is None or process.stdout is None or process.stderr is None:
        process.kill()
        raise BundleError("cannot open git cat-file batch pipes")
    digest = hashlib.sha256()
    records: list[dict[str, object]] = []
    try:
        for mode, object_id, path_bytes in entries:
            process.stdin.write(object_id.encode("ascii") + b"\n")
            process.stdin.flush()
            header = process.stdout.readline().rstrip(b"\n").decode("ascii").split(" ")
            if len(header) != 3 or header[0] != object_id:
                raise BundleError("git cat-file batch identity drifted")
            expected_type = "commit" if mode == "160000" else "blob"
            if header[1] != expected_type:
                raise BundleError(f"tracked mode/object type drifted: {path_bytes!r}")
            try:
                size = int(header[2])
            except ValueError as error:
                raise BundleError("invalid git cat-file batch size") from error
            for value in (mode.encode(), path_bytes):
                digest.update(len(value).to_bytes(8, "big"))
                digest.update(value)
            digest.update(size.to_bytes(8, "big"))
            remaining = size
            while remaining:
                chunk = process.stdout.read(min(1024 * 1024, remaining))
                if not chunk:
                    raise BundleError("truncated git cat-file batch object")
                digest.update(chunk)
                remaining -= len(chunk)
            if process.stdout.read(1) != b"\n":
                raise BundleError("truncated git cat-file batch terminator")
            records.append({"path": path_bytes.decode("utf-8"), "mode": mode})
        process.stdin.close()
        if process.wait() != 0:
            diagnostic = process.stderr.read().decode("utf-8", errors="replace").strip()
            raise BundleError(f"git cat-file batch failed: {diagnostic}")
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        for stream in (process.stdin, process.stdout, process.stderr):
            if not stream.closed:
                stream.close()
    return {
        "schema": "git-tracked-content-v2",
        "sha256": digest.hexdigest(),
        "file_count": len(records),
        "paths": list(paths),
    }


def source_domains(root: Path) -> dict[str, dict[str, object]]:
    return {name: tracked_domain(root, paths) for name, paths in DOMAIN_PATHS.items()}


def oracle_domain(receipt: dict[str, Any]) -> dict[str, object]:
    oracle = receipt.get("oracle")
    if not isinstance(oracle, dict):
        raise BundleError("oracle receipt lacks oracle identity")
    identity = {
        key: oracle.get(key)
        for key in (
            "repository",
            "commit",
            "tree_digest_sha256",
            "submodule_status",
            "lockfile_sha256",
            "toolchain",
            "build_command",
            "build_mode",
            "adapter_overlay",
            "executable_sha256",
            "host_arch",
            "host_os",
        )
    }
    return {"schema": "pinned-oracle-build-v1", "sha256": canonical_sha256(identity)}


def validate_trust_context(
    trust: dict[str, Any], *, candidate: str, phase: str, tree: str,
) -> None:
    exact_keys(
        trust,
        {
            "schema", "repository", "candidate", "workflow", "workflow_base",
            "trust_root", "event", "run", "actor", "triggering_actor", "phase",
            "artifact",
        },
        "producer trust",
    )
    if trust.get("schema") != "riscv-release-producer-trust-v1":
        raise BundleError("producer trust schema drifted")
    if trust.get("trust_root") != "repository-owner-dispatch":
        raise BundleError("producer trust root is not repository-owner dispatch")
    repository = exact_keys(trust["repository"], {"full_name", "id"}, "repository")
    candidate_identity = exact_keys(
        trust["candidate"],
        {"sha", "tree_oid", "source_repository", "source_repository_id", "source_ref"},
        "candidate",
    )
    workflow = exact_keys(
        trust["workflow"],
        {"path", "repository", "repository_id", "ref", "commit_sha"},
        "workflow",
    )
    workflow_base = exact_keys(
        trust["workflow_base"], {"ref", "sha"}, "workflow base",
    )
    run = exact_keys(trust["run"], {"id", "attempt"}, "producer run")
    actor = exact_keys(trust["actor"], {"login", "id"}, "producer actor")
    triggering = exact_keys(
        trust["triggering_actor"], {"login", "id"}, "producer triggering actor",
    )
    artifact = exact_keys(
        trust["artifact"], {"name", "retention_days"}, "producer artifact",
    )
    if repository != {"full_name": TRUSTED_REPOSITORY, "id": TRUSTED_REPOSITORY_ID}:
        raise BundleError("producer repository is not the canonical repository")
    if repository["full_name"] != candidate_identity["source_repository"] or \
            repository["id"] != candidate_identity["source_repository_id"]:
        raise BundleError("candidate source repository is not the trusted repository")
    if candidate_identity["sha"] != candidate or candidate_identity["tree_oid"] != tree:
        raise BundleError("candidate commit/tree trust identity drifted")
    require_commit(candidate_identity["sha"], "candidate SHA")
    if not isinstance(candidate_identity["source_ref"], str) or not \
            candidate_identity["source_ref"].startswith("refs/heads/"):
        raise BundleError("candidate source ref is not an explicit branch")
    if workflow != {
        "path": ".github/workflows/ci.yml",
        "repository": repository["full_name"],
        "repository_id": repository["id"],
        "ref": "refs/heads/main",
        "commit_sha": workflow["commit_sha"],
    }:
        raise BundleError("producer workflow is not canonical main CI")
    require_commit(workflow["commit_sha"], "workflow commit SHA")
    if workflow_base != {"ref": "refs/heads/main", "sha": workflow["commit_sha"]}:
        raise BundleError("workflow base is not the workflow definition commit")
    if trust["event"] != "workflow_dispatch":
        raise BundleError("producer event is not owner-dispatched")
    if not isinstance(run["id"], int) or run["id"] <= 0 or \
            not isinstance(run["attempt"], int) or run["attempt"] <= 0:
        raise BundleError("producer run identity is invalid")
    for identity, label in ((actor, "actor"), (triggering, "triggering actor")):
        if not isinstance(identity["login"], str) or not identity["login"] or \
                not isinstance(identity["id"], int) or identity["id"] <= 0:
            raise BundleError(f"producer {label} identity is invalid")
        if identity["id"] != TRUSTED_OWNER_ID:
            raise BundleError(f"producer {label} is not the repository owner")
    if trust["phase"] != phase:
        raise BundleError("producer phase drifted")
    expected_name = f"riscv-exhaustive-bundle-{candidate}-{run['id']}-{run['attempt']}"
    if artifact != {"name": expected_name, "retention_days": 30}:
        raise BundleError("producer artifact policy drifted")


def validate_lifetime(manifest: dict[str, Any], now: int | None = None) -> None:
    created = manifest.get("created_at_unix")
    expires = manifest.get("expires_at_unix")
    if isinstance(created, bool) or not isinstance(created, int) or \
            isinstance(expires, bool) or not isinstance(expires, int):
        raise BundleError("bundle lifetime is missing")
    if expires - created != BUNDLE_RETENTION_SECONDS:
        raise BundleError("bundle lifetime does not match artifact retention")
    current = int(time.time()) if now is None else now
    if current < created - 300:
        raise BundleError("bundle creation time is in the future")
    if current > expires:
        raise BundleError("bundle evidence has expired")


def validate_policy_context(
    policy: dict[str, Any], *, candidate: str, workflow_commit: str,
) -> None:
    exact_keys(
        policy,
        {"schema", "trusted_workflow_commit", "candidate_commit", "domain"},
        "release policy match",
    )
    if policy.get("schema") != "riscv-release-policy-match-v1":
        raise BundleError("release policy match schema drifted")
    if policy.get("trusted_workflow_commit") != workflow_commit:
        raise BundleError("release policy is not bound to the producer workflow")
    if policy.get("candidate_commit") != candidate:
        raise BundleError("release policy is not bound to the candidate")
    domain = exact_keys(
        policy["domain"], {"schema", "sha256", "file_count", "paths"},
        "release policy domain",
    )
    if domain.get("schema") != "riscv-release-policy-domain-v1":
        raise BundleError("release policy domain schema drifted")
    require_sha256(domain.get("sha256"), "release policy domain digest")
    if isinstance(domain.get("file_count"), bool) or not \
            isinstance(domain.get("file_count"), int) or domain["file_count"] <= 0:
        raise BundleError("release policy domain file count is invalid")
    if domain.get("paths") != RELEASE_POLICY_PATHS:
        raise BundleError("release policy domain paths drifted")


def canonical_commands(report: dict[str, Any], candidate: str, phase: str) -> list[list[str]]:
    records = report.get("commands")
    if not isinstance(records, list) or not records:
        raise BundleError("release gate commands are missing")
    host = report.get("host")
    is_darwin = isinstance(host, dict) and host.get("system") == "Darwin"
    if len(records) != (14 if is_darwin else 13):
        raise BundleError("release gate command count is not canonical")
    commands = [record.get("command") if isinstance(record, dict) else None for record in records]
    if any(not isinstance(command, list) or not all(isinstance(item, str) for item in command)
           for command in commands):
        raise BundleError("release gate command argv is malformed")
    python = commands[1][0]
    evidence_command = commands[-1]
    try:
        receipt = evidence_command[evidence_command.index("--receipt") + 1]
    except (ValueError, IndexError) as error:
        raise BundleError("release evidence receipt argument is missing") from error
    evidence_dir = str(Path(receipt).parent)
    cli_evidence = str(Path(evidence_dir) / "cli")
    oracle_command = commands[-3]
    try:
        stark_v_source = oracle_command[oracle_command.index("--stark-v-source") + 1]
    except (ValueError, IndexError) as error:
        raise BundleError("oracle source argument is missing") from error
    expected = [
        ["zig", "fmt", "--check", "build.zig", "src", "tools"],
        [python, "scripts/check_upstream_pins.py"],
        [python, "scripts/check_source_conformance.py"],
        [python, "scripts/check_riscv_release_contract.py", "--all", "--phase", phase],
        [python, "scripts/check_riscv_release_contract.py", "--structure"],
        [python, "scripts/check_riscv_release_contract.py", "--core-purity"],
        [python, "scripts/check_riscv_release_contract.py", "--frontend-layering"],
    ]
    if is_darwin:
        expected.append(["zig", "build", "metal-eval-prepare", "-Doptimize=ReleaseFast"])
    expected.extend([
        [python, "-m", "unittest", "discover", "-s", "scripts/tests", "-p", "test_*.py"],
        [
            python, "scripts/riscv_staged_smoke.py", "--phase", phase,
            "--evidence-dir", cli_evidence,
        ],
        ["zig", "build", "release-gate-strict", "-Doptimize=ReleaseFast"],
        [
            python, "scripts/riscv_release_oracle.py", "build-and-compare",
            "--stark-v-source", stark_v_source, "--candidate", candidate,
            "--receipt-out", receipt,
        ],
        [python, "scripts/riscv_release_oracle.py", "validate", "--receipt", receipt],
        [
            python, "scripts/riscv_release_evidence.py", "--receipt", receipt,
            "--candidate", candidate,
        ],
    ])
    return expected


def validate_gate_report(report: dict[str, Any], candidate: str, phase: str) -> None:
    if report.get("schema") != "riscv-release-gate-evidence-v1":
        raise BundleError("release gate evidence schema drifted")
    if (report.get("status"), report.get("phase"), report.get("candidate_commit")) != (
        "PASS", phase, candidate,
    ):
        raise BundleError("release gate did not pass for this exact candidate and phase")
    git = report.get("git")
    if not isinstance(git, dict) or git.get("head") != candidate or any(
        git.get(field) for field in ("initial_porcelain", "final_porcelain")
    ):
        raise BundleError("release gate did not run from a clean exact candidate")
    commands = report.get("commands")
    expected_commands = canonical_commands(report, candidate, phase)
    if [record["command"] for record in commands] != expected_commands:
        raise BundleError("release gate command plan is not canonical and ordered")
    for record in commands:
        if not isinstance(record, dict) or record.get("exit_code") != 0:
            raise BundleError("release gate contains a failed command")
        if record.get("skipped_tests") != 0:
            raise BundleError("release gate contains skipped required tests")
        if record.get("command_shell") != shlex.join(record["command"]):
            raise BundleError("release gate shell rendering drifted from argv")


def validate_cli_summary(
    summary: dict[str, Any], candidate: str, phase: str, executable_sha256: str,
) -> None:
    expected_status = "not_release_gated" if phase == "candidate" else "release_gated"
    expected = (
        summary.get("schema"), summary.get("phase"), summary.get("release_status"),
        summary.get("implementation_commit"), summary.get("implementation_dirty"),
        summary.get("executable_sha256"),
    )
    if expected[0] not in {"riscv_cli_evidence_v1", "riscv_cli_evidence_v2"} or expected[1:] != (
        phase, expected_status, candidate, False, executable_sha256,
    ):
        raise BundleError("exhaustive CLI summary identity drifted")
    if summary.get("profile") not in (None, "exhaustive"):
        raise BundleError("linked CLI summary is not exhaustive")
    if summary.get("multi_shard_addi_rows", 0) <= 65_536 or summary.get("total_steps") != 131_078:
        raise BundleError("exhaustive CLI summary did not cross a shard boundary")
    required_successes = (
        "artifact_sha256", "benchmark_artifact_sha256", "benchmark_report_sha256",
        "verify_receipt_sha256", "benchmark_verify_receipt_sha256",
    )
    if any(not isinstance(summary.get(field), str) for field in required_successes):
        raise BundleError("exhaustive CLI or benchmark evidence is incomplete")
    if summary.get("independent_verify_returncode") != 0 or summary.get("tamper_returncode") == 0:
        raise BundleError("exhaustive CLI verification/tamper result drifted")
    expected_mutations = {
        "proof_wire_mutation_returncodes": {"trailing", "truncated", "length-bomb"},
        "hostile_artifact_results": {
            "corrupt-json", "legacy-schema-v2", "duplicate-header", "unknown-field",
            "omitted-claim", "release-relabel",
        },
    }
    for field, names in expected_mutations.items():
        results = summary.get(field)
        if not isinstance(results, dict) or set(results) != names or any(
            not isinstance(result, dict) or result.get("returncode") == 0
            for result in results.values()
        ):
            raise BundleError(f"exhaustive CLI {field} coverage drifted")
    boundary = summary.get("boundary_rejection_results")
    if not isinstance(boundary, dict) or set(boundary) != BOUNDARY_REJECTION_KEYS or any(
        not isinstance(result, dict) or result.get("returncode") == 0
        for result in boundary.values()
    ):
        raise BundleError("exhaustive CLI boundary rejection matrix is missing")
    claim_swap = summary.get("claim_order_swap")
    if not isinstance(claim_swap, dict) or claim_swap.get("returncode") == 0 or \
            claim_swap.get("expected_error") != "OodsNotMatching":
        raise BundleError("exhaustive CLI claim-order mutation is missing")
    for field in required_successes:
        require_sha256(summary[field], f"exhaustive CLI {field}")


def validate_executable_digests(
    oracle: dict[str, Any], *, cli: Path, oracle_cli: Path, trace_cli: Path,
) -> None:
    oracle_identity = oracle.get("oracle")
    implementation = oracle.get("implementation")
    if not isinstance(oracle_identity, dict) or not isinstance(implementation, dict):
        raise BundleError("oracle receipt executable identities are missing")
    executables = implementation.get("executables")
    if not isinstance(executables, dict):
        raise BundleError("oracle receipt implementation executables are missing")
    expected = {
        "pinned Rust cp11_dump": oracle_identity.get("executable_sha256"),
        "candidate stwo-zig": executables.get("stwo-zig"),
        "candidate riscv-trace-dump": executables.get("riscv-trace-dump"),
    }
    paths = {
        "pinned Rust cp11_dump": oracle_cli,
        "candidate stwo-zig": cli,
        "candidate riscv-trace-dump": trace_cli,
    }
    for label, expected_digest in expected.items():
        require_sha256(expected_digest, f"{label} receipt digest")
        if sha256_file(paths[label]) != expected_digest:
            raise BundleError(f"{label} digest differs from exhaustive oracle receipt")


def regular_bundle_file(bundle: Path, relative: str) -> Path:
    path = bundle / relative
    try:
        metadata = path.lstat()
    except OSError as error:
        raise BundleError(f"missing bundle file {relative}: {error}") from error
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
        raise BundleError(f"bundle entry is not a regular file: {relative}")
    if not path.resolve().is_relative_to(bundle.resolve()):
        raise BundleError(f"bundle entry escapes bundle root: {relative}")
    return path


def file_record(path: Path) -> dict[str, object]:
    return {"sha256": sha256_file(path), "size": path.stat().st_size}


def validate_files(bundle: Path, manifest: dict[str, Any]) -> dict[str, Path]:
    files = manifest.get("files")
    if not isinstance(files, dict) or set(files) != set(FILE_LAYOUT):
        raise BundleError("bundle file manifest drifted")
    resolved: dict[str, Path] = {}
    for name, relative in FILE_LAYOUT.items():
        path = regular_bundle_file(bundle, relative)
        if files[name] != file_record(path):
            raise BundleError(f"bundle file digest or size drifted: {name}")
        resolved[name] = path
    return resolved


def atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
