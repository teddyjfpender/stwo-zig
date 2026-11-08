"""Closed provenance subtree validator for H-010 reports."""

from __future__ import annotations

import re
import hashlib
import json
from typing import Any

from .environment import ARTIFACT_PATH, SOURCE_MANIFEST
from .pins import ARTIFACT_DIGEST


DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
PROVENANCE_KEYS = frozenset(
    {
        "repository",
        "source_closure",
        "executable",
        "artifact",
        "host",
        "build_expectation",
        "environment_allowlist",
        "worker_count",
        "clock_adapter",
        "rss_adapter",
    }
)


class ProvenanceValidationError(ValueError):
    """A supposedly admissible provenance subtree is incomplete."""


def _object(value: Any, name: str, keys: frozenset[str]) -> dict[str, Any]:
    if type(value) is not dict:
        raise ProvenanceValidationError(f"{name} must be an object")
    actual = frozenset(value)
    if actual != keys:
        raise ProvenanceValidationError(
            f"{name} key set mismatch; missing={sorted(keys - actual)}, "
            f"unknown={sorted(actual - keys)}"
        )
    return value


def _exact(value: Any, expected: Any, name: str) -> None:
    if type(value) is not type(expected) or value != expected:
        raise ProvenanceValidationError(f"{name} must equal {expected!r}")


def _positive_int(value: Any, name: str) -> int:
    if type(value) is not int or value <= 0:
        raise ProvenanceValidationError(f"{name} must be a positive integer")
    return value


def _digest(value: Any, name: str) -> str:
    if type(value) is not str or DIGEST_RE.fullmatch(value) is None:
        raise ProvenanceValidationError(f"{name} must be one lowercase SHA-256 digest")
    return value


def _git_oid(value: Any, name: str) -> str:
    if (
        type(value) is not str
        or len(value) not in (40, 64)
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ProvenanceValidationError(f"{name} must be a lowercase Git object ID")
    return value


def validate_provenance(value: Any) -> dict[str, Any]:
    provenance = _object(value, "provenance", PROVENANCE_KEYS)
    repository = _object(
        provenance["repository"],
        "provenance.repository",
        frozenset({"commit", "tree", "clean", "status_porcelain"}),
    )
    _git_oid(repository["commit"], "provenance.repository.commit")
    _git_oid(repository["tree"], "provenance.repository.tree")
    _exact(repository["clean"], True, "provenance.repository.clean")
    _exact(repository["status_porcelain"], [], "provenance.repository.status")

    closure = _object(
        provenance["source_closure"],
        "provenance.source_closure",
        frozenset(
            {"manifest", "manifest_sha256", "source_count", "content_sha256", "sources"}
        ),
    )
    if type(closure["manifest"]) is not dict:
        raise ProvenanceValidationError("source-closure manifest must be an object")
    _exact(
        closure["manifest"],
        SOURCE_MANIFEST.canonical(),
        "source-closure manifest",
    )
    _digest(closure["manifest_sha256"], "source-closure manifest digest")
    manifest_digest = hashlib.sha256(
        json.dumps(
            closure["manifest"], sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    ).hexdigest()
    _exact(
        closure["manifest_sha256"],
        manifest_digest,
        "source-closure manifest digest",
    )
    _digest(closure["content_sha256"], "source-closure content digest")
    count = _positive_int(closure["source_count"], "source-closure count")
    sources = closure["sources"]
    if (
        type(sources) is not list
        or len(sources) != count
        or any(type(path) is not str or not path for path in sources)
        or sources != sorted(set(sources))
    ):
        raise ProvenanceValidationError(
            "source-closure list must be sorted, unique, and complete"
        )

    for key in ("executable", "artifact"):
        identity = _object(
            provenance[key],
            f"provenance.{key}",
            frozenset({"path", "bytes", "sha256"}),
        )
        if type(identity["path"]) is not str or not identity["path"]:
            raise ProvenanceValidationError(f"provenance.{key}.path is empty")
        _positive_int(identity["bytes"], f"provenance.{key}.bytes")
        _digest(identity["sha256"], f"provenance.{key}.sha256")
    _exact(
        provenance["artifact"]["sha256"],
        ARTIFACT_DIGEST,
        "provenance.artifact.sha256",
    )
    _exact(
        provenance["artifact"]["path"],
        str(ARTIFACT_PATH),
        "provenance artifact path",
    )
    _exact(provenance["artifact"]["bytes"], 275_153, "provenance artifact bytes")

    host = _object(
        provenance["host"],
        "provenance.host",
        frozenset(
            {
                "target_arch",
                "expected_native_target_prefix",
                "os",
                "os_version",
                "kernel_release",
                "cpu_model",
                "logical_cores",
                "physical_cores",
                "memory_bytes",
                "power_state",
            }
        ),
    )
    for key in (
        "target_arch",
        "expected_native_target_prefix",
        "os",
        "os_version",
        "kernel_release",
        "cpu_model",
    ):
        if type(host[key]) is not str or not host[key]:
            raise ProvenanceValidationError(f"provenance.host.{key} is empty")
    for key in ("logical_cores", "physical_cores", "memory_bytes"):
        _positive_int(host[key], f"provenance.host.{key}")
    power = _object(
        host["power_state"],
        "provenance.host.power_state",
        frozenset({"operator_declaration", "machine_verified"}),
    )
    if type(power["operator_declaration"]) is not str or not power["operator_declaration"]:
        raise ProvenanceValidationError("power-state declaration is empty")
    _exact(power["machine_verified"], False, "power-state machine verification")

    expectation = _object(
        provenance["build_expectation"],
        "provenance.build_expectation",
        frozenset(
            {"zig_version", "optimization_mode", "target_prefix", "allocator", "monotonic_clock"}
        ),
    )
    for key in expectation:
        if type(expectation[key]) is not str or not expectation[key]:
            raise ProvenanceValidationError(f"build expectation {key} is empty")
    _exact(expectation["optimization_mode"], "ReleaseFast", "optimization mode")
    _exact(expectation["allocator"], "libc-c-allocator", "allocator")
    _exact(expectation["monotonic_clock"], "std.time.Timer", "clock")
    _exact(
        provenance["environment_allowlist"],
        {"LC_ALL": "C", "LANG": "C", "TZ": "UTC"},
        "provenance environment",
    )
    _exact(provenance["worker_count"], 1, "provenance worker count")
    _exact(provenance["clock_adapter"], "std.time.Timer", "clock adapter")
    _exact(
        provenance["rss_adapter"],
        "getrusage(RUSAGE_SELF).ru_maxrss",
        "RSS adapter",
    )
    return provenance
