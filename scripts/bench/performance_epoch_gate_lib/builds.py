"""Recompute focused build, binary, cache, and link-surface budgets."""

from __future__ import annotations

import math
from pathlib import Path
from typing import Any

try:
    from scripts.product_identity_lib import ProductIdentityError, validate_canonical_identity
except ModuleNotFoundError:
    from product_identity_lib import ProductIdentityError, validate_canonical_identity

from .artifacts import require_artifact
from .codec import strict_json
from .model import EvidenceError, exact_object, require_hex, require_int, require_number, require_relative_path
from .session import require_successful_attempt


BUILD_FIELDS = {"id", "host_role", "baseline", "candidate", "verdict"}
PRODUCT_FIELDS = {
    "arm", "product", "source", "product_identity", "executable_artifact",
    "installed_manifest_artifact", "link_surface_artifact", "source_closure_artifact",
    "cold_attempt_sequence", "warm_attempt_sequence", "cold_seconds", "warm_seconds",
}
SOURCE_FIELDS = {"repository", "commit", "tree", "clean", "worktree_status"}


def build_budget_pass(
    protocol: dict[str, Any],
    spec: dict[str, Any],
    *,
    baseline_cold_seconds: float | None,
    candidate_cold_seconds: float,
    candidate_warm_seconds: float,
    candidate_link_entries: list[str],
) -> bool:
    budgets = protocol["budgets"]
    passed = True
    if baseline_cold_seconds is not None and spec["relative_cold_budget"]:
        passed &= candidate_cold_seconds <= baseline_cold_seconds * budgets["maximum_focused_cold_build_ratio"]
    if spec["absolute_cold_seconds"] is not None:
        passed &= candidate_cold_seconds <= spec["absolute_cold_seconds"]
    if spec["absolute_warm_seconds"] is not None:
        passed &= candidate_warm_seconds <= spec["absolute_warm_seconds"]
    folded_links = "\n".join(candidate_link_entries).lower()
    passed &= all(token.lower() not in folded_links for token in spec["forbidden_link_tokens"])
    return bool(passed)


def _product(
    value: object,
    *,
    arm: str,
    role: str,
    spec: dict[str, Any],
    source: dict[str, Any],
    artifacts: dict[str, dict[str, Any]],
    attempts: dict[tuple[str, int], dict[str, Any]],
    raw_root: Path,
    max_bytes: int,
) -> dict[str, Any]:
    product = exact_object(value, PRODUCT_FIELDS, f"{spec['id']} {arm}")
    if product["arm"] != arm:
        raise EvidenceError("build product arm mismatch")
    if product["product"] != spec[f"{arm}_step"]:
        raise EvidenceError("build product name differs from its planned step")
    if exact_object(product["source"], SOURCE_FIELDS, "build source") != source:
        raise EvidenceError("build product source identity mismatch")
    if source["clean"] is not True or source["worktree_status"] != "":
        raise EvidenceError("build product source is dirty")
    executable = require_artifact(
        artifacts, product["executable_artifact"], "executable", "build executable",
    )
    evidence: dict[str, dict[str, Any]] = {}
    for field, kind in (
        ("installed_manifest_artifact", "installed-manifest"),
        ("link_surface_artifact", "link-surface"),
        ("source_closure_artifact", "source-closure"),
    ):
        artifact = require_artifact(artifacts, product[field], kind, f"build {field}")
        evidence[kind] = strict_json(raw_root / artifact["path"], max_bytes)
    installed = exact_object(
        evidence["installed-manifest"],
        {"schema", "installed_files", "warm_rebuilt_files"},
        "installed manifest",
    )
    if installed["schema"] != "build-installed-manifest-v1":
        raise EvidenceError("installed manifest schema is unsupported")
    if not isinstance(installed["installed_files"], list) or not installed["installed_files"]:
        raise EvidenceError("installed manifest has no files")
    for installed_file in installed["installed_files"]:
        exact_object(installed_file, {"path", "sha256", "bytes"}, "installed file")
        require_relative_path(installed_file["path"], "installed file path")
        require_hex(installed_file["sha256"], 64, "installed file digest")
        require_int(installed_file["bytes"], "installed file bytes")
    if not any(
        item["sha256"] == executable["sha256"] and item["bytes"] == executable["bytes"]
        for item in installed["installed_files"]
    ):
        raise EvidenceError("installed manifest does not contain the exact executable")
    if not isinstance(installed["warm_rebuilt_files"], list):
        raise EvidenceError("warm rebuilt file set must be a list")
    links = exact_object(evidence["link-surface"], {"schema", "entries"}, "link surface")
    if links["schema"] != "build-link-surface-v1" or not isinstance(links["entries"], list):
        raise EvidenceError("link surface schema is unsupported")
    if not all(isinstance(item, str) for item in links["entries"]):
        raise EvidenceError("link surface entries must be strings")
    closure = exact_object(
        evidence["source-closure"],
        {"schema", "compiled_sources", "unrelated_sources"},
        "source closure",
    )
    if closure["schema"] != "build-source-closure-v1":
        raise EvidenceError("source closure schema is unsupported")
    if not isinstance(closure["compiled_sources"], list) or not isinstance(closure["unrelated_sources"], list):
        raise EvidenceError("source closure file sets must be lists")
    for field in ("compiled_sources", "unrelated_sources"):
        for source_path in closure[field]:
            require_relative_path(source_path, f"source closure {field}")
    if arm == "candidate":
        try:
            identity = validate_canonical_identity(product["product_identity"])
        except ProductIdentityError as error:
            raise EvidenceError(f"candidate product identity is invalid: {error}") from error
        if identity["implementation_commit"] != source["commit"] or identity["implementation_tree"] != source["tree"]:
            raise EvidenceError("candidate product identity source mismatch")
        if identity["name"] != product["product"]:
            raise EvidenceError("candidate canonical identity names a different product")
        expected_frontend = "riscv" if "riscv" in spec["id"] else "native"
        expected_backend = "metal_hybrid" if "metal" in spec["id"] else "cpu_native"
        if (identity["frontend"], identity["backend"], identity["role"]) != (
            expected_frontend, expected_backend, "cli",
        ):
            raise EvidenceError("candidate canonical identity capability mismatch")
        if identity["implementation_dirty"] or identity["optimize"] != "ReleaseFast":
            raise EvidenceError("candidate product identity is not clean ReleaseFast")
    elif product["product_identity"] is not None:
        raise EvidenceError("historical product must not invent a schema-v2 identity")
    cold_id = f"build:{spec['id']}:{arm}:cold"
    warm_id = f"build:{spec['id']}:{arm}:warm"
    cold_attempt = require_successful_attempt(
        attempts, product["cold_attempt_sequence"], role=role, arm=arm,
        command_id=cold_id, stage="build-cold",
    )
    warm_attempt = require_successful_attempt(
        attempts, product["warm_attempt_sequence"], role=role, arm=arm,
        command_id=warm_id, stage="build-warm",
    )
    cold_seconds = require_number(product["cold_seconds"], "cold build seconds")
    warm_seconds = require_number(product["warm_seconds"], "warm build seconds")
    for attempt, claimed, label in (
        (cold_attempt, cold_seconds, "cold"), (warm_attempt, warm_seconds, "warm"),
    ):
        timing_artifact = require_artifact(
            artifacts, attempt["artifacts"]["timing"], "timing", f"{label} timing",
        )
        timing = strict_json(raw_root / timing_artifact["path"], max_bytes)
        exact_object(timing, {"schema", "wall_seconds"}, f"{label} timing")
        if timing["schema"] != "process-timing-v1" or not math.isclose(
            require_number(timing["wall_seconds"], f"{label} wall seconds"),
            claimed, rel_tol=1e-12, abs_tol=1e-12,
        ):
            raise EvidenceError(f"{label} build seconds differ from raw timing")
        resource = require_artifact(
            artifacts, attempt["artifacts"]["resource"], "resource", f"{label} resource",
        )
        resource_value = strict_json(raw_root / resource["path"], max_bytes)
        exact_object(resource_value, {"schema", "peak_rss_bytes"}, f"{label} resource")
        if resource_value["schema"] != "process-resource-v1":
            raise EvidenceError("build resource schema is unsupported")
        require_int(resource_value["peak_rss_bytes"], f"{label} peak RSS", 1)
    if arm == "candidate" and closure["unrelated_sources"]:
        raise EvidenceError("focused build compiled unrelated sources")
    if arm == "candidate" and installed["warm_rebuilt_files"] != []:
        raise EvidenceError("warm no-op build rebuilt files")
    product["_executable_bytes"] = executable["bytes"]
    product["_link_entries"] = links["entries"]
    return product


def validate_builds(
    values: object,
    protocol: dict[str, Any],
    sources: dict[str, dict[str, Any]],
    artifacts: dict[str, dict[str, Any]],
    attempts: dict[tuple[str, int], dict[str, Any]],
    raw_root: Path,
) -> list[dict[str, Any]]:
    if not isinstance(values, list):
        raise EvidenceError("build comparisons must be a list")
    specs = {item["id"]: item for item in protocol["build_comparisons"]}
    if {item.get("id") for item in values if isinstance(item, dict)} != set(specs):
        raise EvidenceError("build comparison set differs from protocol")
    for item in values:
        build = exact_object(item, BUILD_FIELDS, "build comparison")
        spec = specs[build["id"]]
        role = spec["host_role"]
        if build["host_role"] != role:
            raise EvidenceError("build host role mismatch")
        baseline = build["baseline"]
        if baseline is None:
            if spec["baseline_required"]:
                raise EvidenceError("required historical build is absent")
        else:
            baseline = _product(
                baseline, arm="baseline", role=role, spec=spec,
                source=sources["baseline"], artifacts=artifacts, attempts=attempts,
                raw_root=raw_root, max_bytes=protocol["limits"]["max_json_bytes"],
            )
        candidate = _product(
            build["candidate"], arm="candidate", role=role, spec=spec,
            source=sources["candidate"], artifacts=artifacts, attempts=attempts,
            raw_root=raw_root, max_bytes=protocol["limits"]["max_json_bytes"],
        )
        if spec["binary_size_diagnostic"] is not True:
            raise EvidenceError("build comparison must retain binary-size diagnostics")
        passed = build_budget_pass(
            protocol, spec,
            baseline_cold_seconds=None if baseline is None else baseline["cold_seconds"],
            candidate_cold_seconds=candidate["cold_seconds"],
            candidate_warm_seconds=candidate["warm_seconds"],
            candidate_link_entries=candidate["_link_entries"],
        )
        expected = "PASS" if passed else "NO-GO"
        if build["verdict"] != expected:
            raise EvidenceError("build verdict does not match recomputed budgets")
        if not passed:
            raise EvidenceError(f"build budget failed: {build['id']}")
        candidate.pop("_executable_bytes")
        candidate.pop("_link_entries")
        if baseline is not None:
            baseline.pop("_executable_bytes")
            baseline.pop("_link_entries")
    return values
