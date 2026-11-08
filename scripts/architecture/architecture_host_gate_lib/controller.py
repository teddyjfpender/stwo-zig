"""Architecture host gate orchestration and evidence derivation."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable

from scripts.architecture_host_gate_lib import capture, plan, preimages, products, validators
from scripts.build_architecture_receipt_lib.codec import atomic_write, canonical_bytes
from scripts.build_architecture_receipt_lib.model import (
    DEFAULT_PROTOCOL,
    EVIDENCE_NAMES,
    ReceiptError,
)
from scripts.build_architecture_receipt_lib.protocol import load_protocol
from scripts.build_architecture_receipt_lib.receipt import validate_evidence_manifest


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PLAN = ROOT / "conformance/build-architecture-ci-plan-v1.json"


def _git(root: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", *arguments], cwd=root, check=False, capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise ReceiptError(f"git {' '.join(arguments)} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def _owned_path(root: Path, raw: str) -> Path:
    path = Path(raw)
    resolved = (path if path.is_absolute() else root / path).resolve()
    if not resolved.is_relative_to(root.resolve()):
        raise ReceiptError(f"architecture output escapes the repository: {raw}")
    return resolved


def _clean(root: Path) -> bool:
    return _git(root, "status", "--porcelain=v1", "--untracked-files=all") == ""


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def execute(
    *, root: Path, role: str, plan_path: Path, protocol_path: Path,
    authority_root: Path | None = None,
    output_dir: Path, candidate: str,
    timeout: float, run_id: str, run_attempt: str, repository: str,
    repository_id: str, workflow_sha: str, native_oracle_bundle: Path,
    native_oracle_trust: Path,
    executor: Callable[[list[str], Path, float], tuple[int, bytes, bytes, int]] = capture.run,
) -> tuple[Path, dict[str, Any]]:
    root = root.resolve()
    authority_root = (authority_root or root).resolve()
    protocol, _ = load_protocol(protocol_path)
    architecture_plan = plan.load(plan_path, protocol)
    if role not in protocol["host_roles"]:
        raise ReceiptError(f"unsupported architecture host role: {role}")
    tree = _git(root, "rev-parse", f"{candidate}^{{tree}}")
    if _git(root, "rev-parse", "HEAD") != candidate:
        raise ReceiptError("architecture candidate differs from HEAD")
    output_dir = output_dir.resolve()
    if not output_dir.is_relative_to(root.resolve()):
        raise ReceiptError("architecture evidence output must remain inside the repository")
    output_dir.mkdir(parents=True, exist_ok=False)
    log_dir = output_dir / "commands"
    log_dir.mkdir()
    replacements = {
        "authority_root": str(authority_root),
        "candidate": candidate,
        "candidate_root": str(root),
        "evidence_dir": output_dir.relative_to(root.resolve()).as_posix(),
        "repository": repository,
        "repository_id": repository_id,
        "native_oracle_bundle": str(native_oracle_bundle.resolve()),
        "native_oracle_trust": str(native_oracle_trust.resolve()),
        "run_attempt": run_attempt,
        "run_id": run_id,
        "tree": tree,
        "workflow_sha": workflow_sha,
    }
    source_clean = _clean(root)
    command_records: list[dict[str, Any]] = []
    command_outputs: dict[str, Path] = {}
    captured_paths: set[Path] = set()
    result_details: dict[str, dict[str, Any]] = {}
    role_plan = architecture_plan["roles"][role]
    if source_clean:
        for raw in role_plan["commands"]:
            expanded_argv = [plan.expand(argument, replacements) for argument in raw["argv"]]
            argv = plan.authority_argv(
                raw["id"], expanded_argv,
                authority_root=authority_root, candidate_root=root,
            )
            inputs = [
                Path(plan.expand(path, replacements)).resolve()
                if Path(plan.expand(path, replacements)).is_absolute()
                else (root / plan.expand(path, replacements)).resolve()
                for path in raw["required_inputs"]
            ]
            captured_paths.update(inputs)
            outputs = [
                _owned_path(root, plan.expand(path, replacements))
                for path in raw["generated_outputs"]
            ]
            overlap = set(inputs) & set(outputs)
            if overlap:
                raise ReceiptError(
                    "architecture plan declares immutable input as generated output: "
                    + ", ".join(str(path) for path in sorted(overlap))
                )
            input_digests: dict[str, str] = {}
            input_failures: list[str] = []
            for required in inputs:
                try:
                    input_digests[str(required)] = validators.input_digest(required)
                except (OSError, UnicodeError, json.JSONDecodeError, ReceiptError) as error:
                    input_failures.append(str(error))
            for output in outputs:
                if output.exists():
                    if not output.is_file() and not output.is_symlink():
                        raise ReceiptError(f"refusing to replace non-file output: {output}")
                    output.unlink()
                output.parent.mkdir(parents=True, exist_ok=True)
            command_executor = executor
            if input_failures:
                diagnostic = ("required input admission failed: " + "; ".join(input_failures)).encode()
                command_executor = lambda _argv, _root, _timeout: (125, b"", diagnostic, 0)
            record, stdout_path = capture.capture_command(
                ordinal=len(command_records), command_id=raw["id"], phase=raw["phase"],
                argv=argv, root=root, log_dir=log_dir, timeout=timeout,
                executor=command_executor,
            )
            command_records.append(record)
            command_outputs[raw["id"]] = stdout_path
            captured_paths.add(stdout_path)
            captured_paths.add(log_dir / f"{len(command_records) - 1:03d}-{raw['id']}.stderr")
            replacements[f"stdout_{raw['id'].replace('-', '_')}"] = (
                stdout_path.relative_to(root).as_posix()
            )
            failures: list[str] = list(input_failures)
            try:
                validators.validate_stdout(raw["id"], stdout_path, host_role=role)
            except (OSError, UnicodeError, json.JSONDecodeError, ReceiptError, ValueError) as error:
                failures.append(str(error))
            output_digests: dict[str, str] = {}
            if outputs:
                captured_paths.update(outputs)
                try:
                    output_digests = validators.validate_outputs(
                    raw["id"], outputs, inputs, root=root, candidate=candidate,
                    host_role=role,
                    )
                    captured_paths.update(
                        validators.preimage_dependencies(raw["id"], outputs, root=root)
                    )
                except (OSError, UnicodeError, json.JSONDecodeError, ReceiptError, ValueError) as error:
                    failures.append(str(error))
            for required in inputs:
                try:
                    after = validators.input_digest(required)
                    if input_digests.get(str(required)) != after:
                        failures.append(f"required input changed during command: {required}")
                except (OSError, UnicodeError, json.JSONDecodeError, ReceiptError) as error:
                    failures.append(str(error))
            result_details[raw["id"]] = {
                "record": record,
                "stdout_path": stdout_path.relative_to(root).as_posix(),
                "stderr_path": (
                    log_dir / f"{len(command_records) - 1:03d}-{raw['id']}.stderr"
                ).relative_to(root).as_posix(),
                "inputs": input_digests,
                "outputs": output_digests,
                "failures": failures,
            }
    product_records = [
        products.collect(
            spec, root=root, command_outputs=command_outputs,
            candidate=candidate, tree=tree,
        )
        for spec in role_plan["products"]
    ]
    checkpoints = _checkpoints(
        role=role, protocol=protocol, role_plan=role_plan,
        details=result_details, product_records=product_records,
        plan_sha256=capture.sha256_file(plan_path), source_clean=source_clean,
    )
    evidence = _evidence(
        role=role, protocol=protocol, architecture_plan=architecture_plan,
        checkpoints=checkpoints, details=result_details,
    )
    if not _clean(root):
        for checkpoint in checkpoints.values():
            checkpoint.update({
                "status": "NO-GO", "reason": "architecture commands dirtied the source tree",
            })
        for item in evidence.values():
            item.update({"status": "NO-GO", "reason": "source tree is dirty"})
    manifest = {
        "schema": "build-architecture-host-evidence-v1",
        "checkpoints": checkpoints,
        "products": product_records,
        "commands": command_records,
        "evidence": evidence,
    }
    validate_evidence_manifest(manifest, protocol, role)
    output = output_dir / f"{role}-{run_id}-evidence.json"
    atomic_write(output, manifest, protocol["limits"]["max_json_bytes"])
    captured_paths.add(output)
    preimages.create(
        output_dir / f"{role}-{run_id}-preimages.zip",
        root=root, role=role, candidate=candidate, tree=tree,
        plan_sha256=capture.sha256_file(plan_path), details=result_details,
        manifest=manifest, captured_paths=captured_paths,
    )
    return output, manifest


def _checkpoints(
    *, role: str, protocol: dict[str, Any], role_plan: dict[str, Any],
    details: dict[str, dict[str, Any]], product_records: list[dict[str, Any]],
    plan_sha256: str, source_clean: bool,
) -> dict[str, Any]:
    products_by_phase: dict[str, list[dict[str, Any]]] = {}
    for spec, product in zip(role_plan["products"], product_records, strict=True):
        products_by_phase.setdefault(spec["phase"], []).append(product)
    checkpoints = {}
    for phase in protocol["host_roles"][role]["allocated_checkpoints"]:
        planned = [item for item in role_plan["commands"] if item["phase"] == phase]
        results = [details.get(item["id"]) for item in planned]
        complete = source_clean and all(result is not None for result in results)
        valid = complete and all(
            result["record"]["exit_code"] == 0
            and result["record"]["skipped_tests"] == 0
            and not result["failures"]
            for result in results
            if result is not None
        )
        valid = valid and all(
            item["status"] == "PASS" for item in products_by_phase.get(phase, [])
        )
        evidence_document = {
            "schema": "build-architecture-checkpoint-evidence-v1",
            "phase": phase,
            "plan_sha256": plan_sha256,
            "commands": results,
            "products": products_by_phase.get(phase, []),
        }
        checkpoints[phase] = {
            "status": "PASS" if valid else "NO-GO",
            "reason": (
                f"{len(planned)} planned commands and required artifacts passed"
                if valid else "planned commands, outputs, or products are incomplete"
            ),
            "evidence_sha256": [_digest(evidence_document)] if results else [],
        }
    return checkpoints


def _evidence(
    *, role: str, protocol: dict[str, Any], architecture_plan: dict[str, Any],
    checkpoints: dict[str, Any], details: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    allocated = set(protocol["host_roles"][role]["allocated_checkpoints"])
    result = {}
    for name in EVIDENCE_NAMES:
        phases = [
            phase for phase in architecture_plan["evidence_phases"][name]
            if phase in allocated
        ]
        passed = bool(phases) and all(checkpoints[phase]["status"] == "PASS" for phase in phases)
        document = {
            "schema": "build-architecture-evidence-category-v1",
            "category": name,
            "phases": phases,
            "checkpoint_evidence": {
                phase: checkpoints[phase]["evidence_sha256"] for phase in phases
            },
            "command_output_digests": {
                command_id: {
                    "inputs": detail["inputs"], "outputs": detail["outputs"],
                } for command_id, detail in sorted(details.items())
                if detail["record"]["phase"] in phases
            },
        }
        result[name] = {
            "status": "PASS" if passed else "NO-GO",
            "reason": (
                f"allocated phases {','.join(phases)} passed"
                if passed else f"allocated phases {','.join(phases)} are incomplete"
            ),
            "sha256": _digest(document),
        }
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root", type=Path, default=ROOT,
        help="exact candidate checkout against which the authority plan executes",
    )
    parser.add_argument(
        "--authority-root", type=Path, default=None,
        help="authenticated checkout containing plan and policy executables",
    )
    parser.add_argument("--role", choices=("linux", "macos"), required=True)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-attempt", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--repository-id", required=True)
    parser.add_argument("--workflow-sha", required=True)
    parser.add_argument(
        "--native-oracle-bundle", type=Path,
        default=ROOT.parent / "native-oracle-bundle",
    )
    parser.add_argument("--native-oracle-trust", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--plan", type=Path, default=DEFAULT_PLAN)
    parser.add_argument("--protocol", type=Path, default=DEFAULT_PROTOCOL)
    parser.add_argument("--command-timeout-seconds", type=float, default=3600.0)
    args = parser.parse_args(argv)
    try:
        output, manifest = execute(
            root=args.root, authority_root=args.authority_root, role=args.role,
            plan_path=args.plan, protocol_path=args.protocol,
            output_dir=args.output_dir, candidate=args.candidate,
            timeout=args.command_timeout_seconds,
            run_id=args.run_id, run_attempt=args.run_attempt,
            repository=args.repository, repository_id=args.repository_id,
            workflow_sha=args.workflow_sha,
            native_oracle_bundle=args.native_oracle_bundle,
            native_oracle_trust=args.native_oracle_trust,
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ReceiptError) as error:
        print(f"architecture host gate: FAIL: {error}", file=sys.stderr)
        return 2
    passed = all(item["status"] == "PASS" for item in manifest["checkpoints"].values())
    print(f"architecture host gate: {'PASS' if passed else 'NO-GO'} {output}")
    return 0 if passed else 1
