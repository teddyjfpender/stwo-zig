"""Canonical product collection from built receipts and exact CLI output."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from scripts.architecture_host_gate_lib.capture import sha256_file
from scripts.product_identity_lib import ProductIdentityError, validate_canonical_identity


class ProductError(ValueError):
    """A built product cannot support architecture evidence."""


def _strict_json(path: Path) -> dict[str, object]:
    def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ProductError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique)
    if not isinstance(value, dict):
        raise ProductError(f"{path} must contain a JSON object")
    return value


def _normalize(value: dict[str, object]) -> tuple[dict[str, object], str | None, str | None]:
    if value.get("schema") == "stwo-product-artifact-identity-v1":
        return value, value.get("artifact_sha256"), value.get("executable_sha256")
    product = value.get("product")
    if not isinstance(product, dict):
        raise ProductError("identity is neither an artifact receipt nor applications output")
    source = product.get("source") if isinstance(product.get("source"), dict) else {}
    target = product.get("target") if isinstance(product.get("target"), dict) else {}
    runtime = product.get("runtime") if isinstance(product.get("runtime"), dict) else {}
    return {
        "product_id": product.get("name"),
        "identity_schema_version": product.get("schema_version"),
        "product_identity_sha256": product.get("identity_sha256"),
        "frontend": product.get("frontend"), "backend": product.get("backend"),
        "role": product.get("role"), "protocol_manifest": product.get("protocol_features"),
        "protocol_manifest_sha256": product.get("protocol_manifest_sha256"),
        "implementation_repository": source.get("repository", product.get("implementation_repository")),
        "implementation_commit": source.get("commit", product.get("implementation_commit")),
        "implementation_tree": source.get("tree", product.get("implementation_tree")),
        "implementation_dirty": source.get("dirty", product.get("implementation_dirty")),
        "dirty_content_sha256": source.get("dirty_content_sha256", product.get("dirty_content_sha256")),
        "zig_version": product.get("zig_version"),
        "target_arch": target.get("arch", product.get("target_arch")),
        "target_os": target.get("os", product.get("target_os")),
        "target_abi": target.get("abi", product.get("target_abi")),
        "cpu_model": target.get("cpu_model", product.get("cpu_model")),
        "cpu_features_sha256": target.get("cpu_features_sha256", product.get("cpu_features_sha256")),
        "optimize": product.get("optimize"),
        "runtime_manifest": runtime.get("manifest", product.get("runtime_manifest")),
        "sdk_manifest": runtime.get("sdk", product.get("sdk_manifest")),
        "aot_manifest": runtime.get("aot", product.get("aot_manifest")),
    }, None, None


def _canonical(identity: dict[str, object]) -> dict[str, object]:
    result = {
        "schema_version": identity.get("identity_schema_version"),
        "name": identity.get("product_id"),
        "protocol_features": identity.get("protocol_manifest"),
        "identity_sha256": identity.get("product_identity_sha256"),
    }
    result.update({
        key: value for key, value in identity.items()
        if key not in {
            "schema", "identity_schema_version", "product_id", "protocol_manifest",
            "product_identity_sha256", "artifact_sha256", "executable_sha256",
        }
    })
    return result


def _load_command(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ProductError(f"cannot parse applications output: {error}") from error
    if not isinstance(value, dict):
        raise ProductError("applications output is not an object")
    return value


def collect(
    spec: dict[str, Any], *, root: Path, command_outputs: dict[str, Path],
    candidate: str, tree: str,
) -> dict[str, object]:
    product_id = spec["product_id"]
    try:
        raw = (
            _strict_json(root / spec["identity_path"])
            if spec["identity_path"] is not None
            else _load_command(command_outputs[spec["identity_command"]])
        )
        identity, receipt_artifact, receipt_executable = _normalize(raw)
        canonical = validate_canonical_identity(_canonical(identity), context=product_id)
        if canonical["name"] != product_id:
            raise ProductError("product name differs from allocation")
        if canonical["implementation_commit"] != candidate:
            raise ProductError("product commit differs from candidate")
        if canonical["implementation_tree"] != tree:
            raise ProductError("product tree differs from candidate")
        if canonical["implementation_dirty"] or canonical["dirty_content_sha256"] is not None:
            raise ProductError("product identity is dirty")
        artifact_path = spec["artifact_path"]
        artifact = sha256_file(root / artifact_path) if artifact_path is not None else receipt_artifact
        if not isinstance(artifact, str):
            raise ProductError("product artifact digest is unavailable")
        if receipt_artifact is not None and receipt_artifact != artifact:
            raise ProductError("identity receipt artifact digest differs from exact artifact")
        if artifact_path is not None and receipt_executable not in (None, artifact):
            raise ProductError("identity receipt executable digest differs from exact binary")
        return {
            "product_id": product_id,
            "product_identity_sha256": canonical["identity_sha256"],
            "artifact_sha256": artifact,
            "executable_sha256": artifact if artifact_path is not None else None,
            "status": "PASS",
            "reason": "descriptor-issued canonical identity and exact artifact agree",
        }
    except (KeyError, OSError, ProductError, ProductIdentityError, ValueError) as error:
        return {
            "product_id": product_id,
            "product_identity_sha256": None,
            "artifact_sha256": None,
            "executable_sha256": None,
            "status": "NO-GO",
            "reason": f"product evidence incomplete: {error}",
        }
