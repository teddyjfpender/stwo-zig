#!/usr/bin/env python3
"""Validate the immutable BG-00 build-monorepo migration baseline."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BASELINE = ROOT / "conformance/build-monorepo-baseline-v1.json"
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")


class DuplicateKeyError(ValueError):
    pass


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object)
    if not isinstance(value, dict):
        raise ValueError("baseline root must be an object")
    return value


def git(repo: Path, *args: str) -> bytes:
    result = subprocess.run(
        ["git", *args], cwd=repo, check=False, capture_output=True
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise ValueError(f"git {' '.join(args)} failed: {detail}")
    return result.stdout


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def require_hex(errors: list[str], value: Any, pattern: re.Pattern[str], name: str) -> None:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        errors.append(f"{name} is not canonical lowercase hex")


def validate(repo: Path, baseline: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if baseline.get("schema") != "build-monorepo-baseline-v1":
        errors.append("schema must be build-monorepo-baseline-v1")
    if baseline.get("status") != "frozen":
        errors.append("baseline status must be frozen")

    source = baseline.get("source")
    if not isinstance(source, dict):
        return errors + ["source must be an object"]
    commit = source.get("commit")
    tree = source.get("tree")
    require_hex(errors, commit, HEX40, "source.commit")
    require_hex(errors, tree, HEX40, "source.tree")
    if source.get("clean") is not True or source.get("worktree_status") != "":
        errors.append("baseline source must record a clean worktree")
    if isinstance(commit, str) and HEX40.fullmatch(commit):
        try:
            actual_tree = git(repo, "rev-parse", f"{commit}^{{tree}}").decode().strip()
        except ValueError as error:
            errors.append(str(error))
        else:
            if actual_tree != tree:
                errors.append("source tree does not match source commit")

    build_surface = baseline.get("build_surface")
    if not isinstance(build_surface, dict):
        errors.append("build_surface must be an object")
    else:
        steps = build_surface.get("steps")
        if not isinstance(steps, list) or not all(isinstance(item, str) for item in steps):
            errors.append("build_surface.steps must be a string array")
        else:
            if len(steps) != build_surface.get("step_count"):
                errors.append("build step_count does not match steps")
            if len(steps) != len(set(steps)):
                errors.append("build steps contain duplicates")
            for required in ("stwo-zig", "release-gate", "metal-test", "riscv-release-gate"):
                if required not in steps:
                    errors.append(f"baseline build surface omits {required}")
        require_hex(errors, build_surface.get("stdout_sha256"), HEX64, "build_surface.stdout_sha256")

    aggregate = baseline.get("aggregate_product")
    if not isinstance(aggregate, dict):
        errors.append("aggregate_product must be an object")
    else:
        binary = aggregate.get("binary", {})
        require_hex(errors, binary.get("sha256"), HEX64, "aggregate_product.binary.sha256")
        linkage = binary.get("dynamic_linkage")
        if not isinstance(linkage, list) or not any("Metal.framework" in item for item in linkage):
            errors.append("pre-migration aggregate linkage must record host-selected Metal")
    proofs = baseline.get("proof_baselines")
    if not isinstance(proofs, dict):
        errors.append("proof_baselines must be an object")
    else:
        for product in ("native_cpu", "riscv_cpu"):
            proof = proofs.get(product)
            if not isinstance(proof, dict):
                errors.append(f"missing proof baseline {product}")
                continue
            if proof.get("verified") is not True:
                errors.append(f"{product} baseline proof is not verified")
            for field in ("proof_artifact_sha256", "canonical_proof_sha256", "report_sha256", "verify_receipt_sha256"):
                require_hex(errors, proof.get(field), HEX64, f"proof_baselines.{product}.{field}")

    conformance = baseline.get("source_conformance")
    if not isinstance(conformance, dict):
        errors.append("source_conformance must be an object")
    elif isinstance(commit, str) and HEX40.fullmatch(commit):
        path = conformance.get("baseline_path")
        expected_hash = conformance.get("baseline_sha256")
        if isinstance(path, str):
            try:
                actual = sha256(git(repo, "show", f"{commit}:{path}"))
            except ValueError as error:
                errors.append(str(error))
            else:
                if actual != expected_hash:
                    errors.append("source-conformance baseline digest does not match pinned source")
        if conformance.get("finding_count") != (
            conformance.get("active_native_backend_findings", 0)
            + conformance.get("deferred_todo_findings", 0)
        ):
            errors.append("source-conformance finding counts do not add up")
    return errors


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", type=Path, default=DEFAULT_BASELINE)
    parser.add_argument("--repo", type=Path, default=ROOT)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        baseline = load(args.baseline)
        errors = validate(args.repo.resolve(), baseline)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"build-monorepo baseline: FAIL: {error}")
        return 1
    if errors:
        print("\n".join(f"build-monorepo baseline: FAIL: {error}" for error in errors))
        return 1
    print(f"build-monorepo baseline: PASS ({baseline['source']['commit']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
