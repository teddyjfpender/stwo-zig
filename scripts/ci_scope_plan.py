#!/usr/bin/env python3
"""Select conservative focused CI lanes from the product catalog and a Git diff."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "conformance/ci-touchpoints-v1.json"
CATALOG = ROOT / "zig-out/identity/product-matrix.json"
ALL_HOSTS = ("linux", "macos")


class PlanError(ValueError):
    pass


def strict_json(path: Path) -> dict[str, Any]:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise PlanError(f"duplicate JSON field in {path}: {key}")
            value[key] = item
        return value

    value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique)
    if not isinstance(value, dict):
        raise PlanError(f"JSON root is not an object: {path}")
    return value


def normalize_path(raw: str) -> str:
    path = PurePosixPath(raw.replace("\\", "/"))
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise PlanError(f"unsafe changed path: {raw}")
    return path.as_posix()


def owns(path: str, candidate: str) -> bool:
    candidate = candidate.rstrip("/")
    return path == candidate or path.startswith(candidate + "/")


def validate_policy(policy: dict[str, Any]) -> None:
    if policy.get("schema") != "ci-touchpoints-v1":
        raise PlanError("CI touchpoint policy schema drifted")
    lanes = policy.get("lanes")
    if not isinstance(lanes, dict) or not lanes:
        raise PlanError("CI touchpoint policy has no lanes")
    for lane, spec in lanes.items():
        if not isinstance(lane, str) or not isinstance(spec, dict):
            raise PlanError("CI lane is malformed")
        if spec.get("host") not in ALL_HOSTS:
            raise PlanError(f"CI lane {lane} has an invalid host")
        if spec.get("local", "run") not in {"run", "hosted"}:
            raise PlanError(f"CI lane {lane} has an invalid local execution policy")
        if not isinstance(spec.get("hosted", True), bool):
            raise PlanError(f"CI lane {lane} has an invalid hosted flag")
        commands = spec.get("commands")
        if not isinstance(commands, list) or not commands:
            raise PlanError(f"CI lane {lane} has no commands")
        if not all(
            isinstance(command, list) and command
            and all(isinstance(argument, str) and argument for argument in command)
            for command in commands
        ):
            raise PlanError(f"CI lane {lane} has a malformed command")
    always_lanes = policy.get("always_lanes")
    scope_lanes = policy.get("product_scope_lanes")
    rules = policy.get("rules")
    documentation = policy.get("documentation_prefixes")
    if not isinstance(always_lanes, list) or not all(isinstance(item, str) for item in always_lanes):
        raise PlanError("CI policy always_lanes is malformed")
    if not isinstance(scope_lanes, dict) or not all(
        isinstance(scope, str) and isinstance(values, list)
        and all(isinstance(value, str) for value in values)
        for scope, values in scope_lanes.items()
    ):
        raise PlanError("CI policy product_scope_lanes is malformed")
    if not isinstance(rules, list) or not all(
        isinstance(rule, dict)
        and isinstance(rule.get("prefixes"), list) and rule["prefixes"]
        and all(isinstance(prefix, str) and prefix for prefix in rule["prefixes"])
        and isinstance(rule.get("lanes"), list) and rule["lanes"]
        and all(isinstance(value, str) and value for value in rule["lanes"])
        for rule in rules
    ):
        raise PlanError("CI policy rules are malformed")
    externally_validated = policy.get("externally_validated_prefixes", [])
    if not isinstance(externally_validated, list) or not all(
        isinstance(prefix, str) and prefix for prefix in externally_validated
    ):
        raise PlanError("CI policy externally_validated_prefixes is malformed")
    if not isinstance(documentation, list) or not all(
        isinstance(prefix, str) and prefix for prefix in documentation
    ):
        raise PlanError("CI policy documentation prefixes are malformed")
    referenced: set[str] = set(always_lanes)
    for values in scope_lanes.values():
        referenced.update(values)
    for rule in rules:
        referenced.update(rule.get("lanes", []))
    unknown = referenced - set(lanes)
    if unknown:
        raise PlanError(f"CI policy references unknown lanes: {sorted(unknown)}")


def validate_catalog(catalog: dict[str, Any], policy: dict[str, Any]) -> None:
    if catalog.get("schema") != "stwo-product-catalog-v2":
        raise PlanError("product catalog schema drifted")
    products = catalog.get("products")
    if not isinstance(products, list) or not products:
        raise PlanError("product catalog has no products")
    mapped = policy["product_scope_lanes"]
    represented = {
        product.get("scope") for product in products
        if isinstance(product, dict)
    }
    missing = sorted(scope for scope in represented if not isinstance(scope, str) or scope not in mapped)
    if missing:
        raise PlanError(f"product scopes lack CI lanes: {missing}")


def catalog_lanes(path: str, catalog: dict[str, Any], policy: dict[str, Any]) -> set[str]:
    selected: set[str] = set()
    for product in catalog["products"]:
        if not isinstance(product, dict) or product.get("state") == "unavailable":
            continue
        owned = [
            *product.get("module_roots", []),
            *product.get("allowed_files", []),
            *product.get("configure_allowed_files", []),
        ]
        prefixes = [
            *product.get("allowed_prefixes", []),
            *product.get("configure_allowed_prefixes", []),
        ]
        if path in owned or any(owns(path, prefix) for prefix in prefixes):
            selected.update(policy["product_scope_lanes"].get(product.get("scope"), []))
    return selected


def is_documentation(path: str, policy: dict[str, Any]) -> bool:
    return any(owns(path, prefix) for prefix in policy["documentation_prefixes"])


def is_externally_validated(path: str, policy: dict[str, Any]) -> bool:
    """Paths whose correctness is enforced by a different pipeline (e.g. the
    autoresearch harness's validate workflow) and which construct no product;
    they must not trip the conservative unknown-path fallback."""
    return any(
        owns(path, prefix)
        for prefix in policy.get("externally_validated_prefixes", [])
    )


def select_lanes(
    changed_paths: Iterable[str], catalog: dict[str, Any], policy: dict[str, Any],
) -> tuple[list[str], dict[str, list[str]]]:
    validate_policy(policy)
    validate_catalog(catalog, policy)
    paths = sorted({normalize_path(path) for path in changed_paths})
    if not paths:
        raise PlanError("CI diff contains no changed paths")
    selected = set(policy["always_lanes"])
    reasons: dict[str, list[str]] = {lane: ["always"] for lane in selected}
    all_lanes = set(policy["lanes"])
    for path in paths:
        path_lanes = catalog_lanes(path, catalog, policy)
        for rule in policy["rules"]:
            if any(owns(path, prefix) for prefix in rule["prefixes"]):
                path_lanes.update(rule["lanes"])
        if (
            not path_lanes
            and not is_documentation(path, policy)
            and not is_externally_validated(path, policy)
        ):
            path_lanes = all_lanes - set(policy["always_lanes"])
        for lane in path_lanes:
            selected.add(lane)
            reasons.setdefault(lane, []).append(path)
    return sorted(selected), {lane: sorted(set(values)) for lane, values in sorted(reasons.items())}


def git_changed_paths(root: Path, base: str, head: str) -> list[str]:
    result = subprocess.run(
        ["git", "diff", "--name-status", "-z", "--find-renames", base, head],
        cwd=root, check=False, capture_output=True,
    )
    if result.returncode != 0:
        raise PlanError(result.stderr.decode("utf-8", errors="replace").strip())
    fields = result.stdout.decode("utf-8", errors="strict").split("\0")
    if fields and fields[-1] == "":
        fields.pop()
    paths: list[str] = []
    index = 0
    while index < len(fields):
        status = fields[index]
        index += 1
        count = 2 if status[:1] in {"R", "C"} else 1
        if index + count > len(fields):
            raise PlanError("truncated git diff name-status output")
        paths.extend(fields[index:index + count])
        index += count
    return paths


def source_identity(root: Path, revision: str) -> tuple[str, str]:
    commit = subprocess.run(
        ["git", "rev-parse", revision], cwd=root, check=True,
        capture_output=True, text=True,
    ).stdout.strip()
    tree = subprocess.run(
        ["git", "rev-parse", f"{revision}^{{tree}}"], cwd=root, check=True,
        capture_output=True, text=True,
    ).stdout.strip()
    return commit, tree


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def emit_github_output(path: Path, plan: dict[str, Any], policy: dict[str, Any]) -> None:
    with path.open("a", encoding="utf-8") as stream:
        for host in ALL_HOSTS:
            # Capability partition: lanes marked hosted=false (they need
            # hardware the hosted runners cannot provide, e.g. a real Metal
            # device) stay in the plan artifact but never enter a hosted
            # matrix; local pre-push and the judge host run them instead.
            lanes = [
                lane for lane in plan["lanes"]
                if policy["lanes"][lane]["host"] == host
                and policy["lanes"][lane].get("hosted", True)
            ]
            stream.write(f"{host}_matrix={json.dumps({'lane': lanes}, separators=(',', ':'))}\n")
            stream.write(f"{host}_count={len(lanes)}\n")
        stream.write(
            "cuda_required="
            f"{'true' if 'native_cuda_device' in plan['lanes'] else 'false'}\n"
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--policy", type=Path, default=POLICY)
    parser.add_argument("--catalog", type=Path, default=CATALOG)
    parser.add_argument("--base")
    parser.add_argument("--head", default="HEAD")
    parser.add_argument("--changed-file", action="append", default=[])
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--github-output", type=Path)
    args = parser.parse_args(argv)
    try:
        policy = strict_json(args.policy)
        catalog = strict_json(args.catalog)
        changed = args.changed_file or git_changed_paths(
            args.root, args.base or f"{args.head}^", args.head,
        )
        lanes, reasons = select_lanes(changed, catalog, policy)
        head, tree = source_identity(args.root, args.head)
        plan = {
            "schema": "ci-scope-plan-v1",
            "base": args.base,
            "head": head,
            "tree": tree,
            "changed_paths": sorted({normalize_path(path) for path in changed}),
            "lanes": lanes,
            "reasons": reasons,
        }
        write_json(args.output, plan)
        if args.github_output is not None:
            emit_github_output(args.github_output, plan, policy)
    except (OSError, UnicodeError, json.JSONDecodeError, subprocess.CalledProcessError, PlanError) as error:
        print(f"CI scope plan: FAIL: {error}", file=sys.stderr)
        return 2
    print(f"CI scope plan: {len(lanes)} lanes ({','.join(lanes)})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
