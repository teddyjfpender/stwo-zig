"""BG-14 architecture readiness for the separately operated epoch-two gate."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

EXPECTED_COMMANDS = ["create-plan", "validate-plan", "capture-host", "validate-receipt"]
EXPECTED_WORKLOADS = [
    "wide_fibonacci:log_n_rows=10,sequence_len=8",
    "xor:log_size=10,log_step=2,offset=3",
    "plonk:log_n_rows=10",
    "state_machine:log_n_rows=10,initial_x=9,initial_y=3",
    "blake:log_n_rows=8,n_rounds=2",
    "poseidon:log_n_instances=13",
]
REQUIRED_TESTS = [
    "scripts/tests/test_performance_epoch_gate.py",
    "scripts/tests/performance_epoch_fixture.py",
]
STATE_PATH = "conformance/build-architecture-performance-state-v1.json"
FORBIDDEN_ARCHITECTURE_OPERATIONS = (
    "performance_epoch_gate.py capture-host",
    "performance_epoch_gate.py validate-receipt",
)


class ReadinessError(ValueError):
    """The epoch-two harness is not ready for its separate promotion workflow."""


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_protocol(root: Path, path: Path) -> tuple[dict[str, Any], str]:
    raw = path.read_bytes()
    if not raw or len(raw) > 1024 * 1024 or not path.is_relative_to(root):
        raise ReadinessError("epoch-two protocol path or size is invalid")
    value = json.loads(raw.decode("utf-8"))
    required = {
        "schema", "schema_version", "receipt_schema", "plan_schema", "repository",
        "authority", "baseline_source", "statistics", "budgets", "workloads",
        "performance_lanes", "build_comparisons", "host_roles", "trusted_stark_v",
        "artifact_kinds", "limits",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise ReadinessError("epoch-two protocol fields drifted")
    if value["schema"] != "build-monorepo-performance-baseline-v2-protocol-v2":
        raise ReadinessError("epoch-two protocol schema drifted")
    if value["schema_version"] != 2:
        raise ReadinessError("epoch-three protocol version drifted")
    authority = value["authority"]
    if not isinstance(authority, dict):
        raise ReadinessError("epoch-two authority is malformed")
    for prefix in ("amendment", "baseline_receipt", "runner", "stats", "autoresearch_manifest"):
        relative = authority.get(f"{prefix}_path")
        expected = authority.get(f"{prefix}_sha256")
        if not isinstance(relative, str) or not isinstance(expected, str):
            raise ReadinessError(f"epoch-two {prefix} authority is malformed")
        owned = (root / relative).resolve()
        if not owned.is_relative_to(root) or not owned.is_file() or _sha256(owned) != expected:
            raise ReadinessError(f"epoch-two {prefix} authority digest drifted")
    return value, hashlib.sha256(raw).hexdigest()


def inspect(root: Path, protocol_path: Path) -> dict[str, Any]:
    root = root.resolve()
    protocol_path = protocol_path.resolve()
    protocol, protocol_sha256 = _load_protocol(root, protocol_path)
    workloads = [item["id"] for item in protocol["workloads"]]
    if workloads != EXPECTED_WORKLOADS:
        raise ReadinessError("epoch-two canonical workload coverage drifted")
    lanes = protocol["performance_lanes"]
    expected_lanes = {("linux", "cpu"), ("macos", "cpu"), ("macos", "metal-hybrid")}
    if {(item["host_role"], item["backend"]) for item in lanes} != expected_lanes:
        raise ReadinessError("epoch-two host/backend lane coverage drifted")
    if protocol["baseline_source"] != {
        "commit": "c1c70db5d8846183e36edcfd9a21c28fafc1c098",
        "tree": "7bbe343342db578dc5ff8e1d9ed2ebec3d2ed06e",
    }:
        raise ReadinessError("epoch-two frozen baseline identity drifted")
    tests = {}
    for relative in REQUIRED_TESTS:
        path = root / relative
        if not path.is_file():
            raise ReadinessError(f"epoch-two required test is missing: {relative}")
        tests[relative] = _sha256(path)
    state_path = root / STATE_PATH
    state = json.loads(state_path.read_text(encoding="utf-8"))
    if state != {
        "architecture_checkpoint": "BG-14",
        "performance_promotion_enabled": False,
        "reason": (
            "Performance promotion is owned by a separate autoresearch goal and is not "
            "an architecture completion gate."
        ),
        "schema": "build-architecture-performance-state-v1",
    }:
        raise ReadinessError("architecture performance deferral marker drifted")
    workflow = (root / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    if any(operation in workflow for operation in FORBIDDEN_ARCHITECTURE_OPERATIONS):
        raise ReadinessError("architecture CI attempts to operate the deferred performance gate")
    return {
        "schema": "build-architecture-performance-readiness-v1",
        "status": "DEFERRED",
        "architecture_status": "PASS",
        "scope": "interface-and-history-presence-only",
        "performance_promotion_enabled": False,
        "performance_promotion": "deferred-to-separate-autoresearch-goal",
        "state_sha256": _sha256(state_path),
        "protocol_sha256": protocol_sha256,
        "commands": EXPECTED_COMMANDS,
        "workloads": EXPECTED_WORKLOADS,
        "lanes": [f"{item['host_role']}:{item['backend']}" for item in lanes],
        "tests": tests,
    }


def validate(path: Path, root: Path, protocol_path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    expected = inspect(root, protocol_path)
    if value != expected:
        raise ReadinessError("performance readiness receipt differs from live epoch-two contract")
    return value
