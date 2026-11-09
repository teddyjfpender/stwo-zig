"""Load the checked-in architecture allocation and trust policy."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .codec import canonical_bytes, sha256_bytes, sha256_file, strict_json
from .model import (
    CHECKPOINT_RE,
    PROTOCOL_SCHEMA,
    ReceiptError,
    exact_object,
    require_non_negative_int,
    require_hex64,
    require_safe_component,
    require_string,
)


PROTOCOL_FIELDS = {
    "schema",
    "checkpoint_order",
    "products",
    "host_roles",
    "aggregate_job",
    "limits",
    "trust",
}
LIMIT_FIELDS = {
    "max_json_bytes",
    "max_commands",
    "max_products",
    "max_argv_items",
    "max_argument_bytes",
    "receipt_freshness_seconds",
    "future_clock_skew_seconds",
}
TRUST_FIELDS = {
    "repository",
    "repository_id",
    "repository_owner_id",
    "workflow_path",
    "workflow_ref",
    "external_verifier_contract_path",
    "external_verifier_contract_sha256",
}
ROLE_FIELDS = {"os", "producer_job", "allocated_checkpoints", "required_products"}


def _string_list(value: object, label: str) -> list[str]:
    if not isinstance(value, list) or not value:
        raise ReceiptError(f"{label} must be a non-empty string array")
    result = [require_string(item, f"{label}[]") for item in value]
    if len(result) != len(set(result)):
        raise ReceiptError(f"{label} contains duplicates")
    return result


def validate_protocol(value: dict[str, Any]) -> dict[str, Any]:
    exact_object(value, PROTOCOL_FIELDS, "protocol")
    if value["schema"] != PROTOCOL_SCHEMA:
        raise ReceiptError(f"protocol schema must be {PROTOCOL_SCHEMA}")

    checkpoints = _string_list(value["checkpoint_order"], "checkpoint_order")
    expected = [f"BG-{index:02d}" for index in range(16)]
    if checkpoints != expected or any(CHECKPOINT_RE.fullmatch(item) is None for item in checkpoints):
        raise ReceiptError("checkpoint_order must be the exact BG-00 through BG-15 sequence")

    products = value["products"]
    if not isinstance(products, dict) or not products:
        raise ReceiptError("products must be a non-empty object")
    for product, kind in products.items():
        require_safe_component(product, "product id")
        if kind not in {"library", "executable"}:
            raise ReceiptError(f"product {product} has an unsupported artifact kind")

    roles = value["host_roles"]
    if not isinstance(roles, dict) or set(roles) != {"linux", "macos"}:
        raise ReceiptError("host_roles must contain exactly linux and macos")
    allocated_union: set[str] = set()
    for role, raw in roles.items():
        policy = exact_object(raw, ROLE_FIELDS, f"host_roles.{role}")
        if policy["os"] != role:
            raise ReceiptError(f"host_roles.{role}.os must be {role}")
        require_safe_component(policy["producer_job"], f"host_roles.{role}.producer_job")
        allocated = _string_list(
            policy["allocated_checkpoints"], f"host_roles.{role}.allocated_checkpoints",
        )
        if any(item not in checkpoints[:-1] for item in allocated):
            raise ReceiptError(f"host_roles.{role} allocates an invalid checkpoint")
        if allocated != sorted(allocated, key=checkpoints.index):
            raise ReceiptError(f"host_roles.{role} checkpoints are reordered")
        allocated_union.update(allocated)
        required_products = _string_list(
            policy["required_products"], f"host_roles.{role}.required_products",
        )
        if any(item not in products for item in required_products):
            raise ReceiptError(f"host_roles.{role} names an unknown product")
    if allocated_union != set(checkpoints[:-1]):
        raise ReceiptError("host allocations do not cover BG-00 through BG-14")

    require_safe_component(value["aggregate_job"], "aggregate_job")
    limits = exact_object(value["limits"], LIMIT_FIELDS, "limits")
    for field in LIMIT_FIELDS:
        number = require_non_negative_int(limits[field], f"limits.{field}")
        if number == 0:
            raise ReceiptError(f"limits.{field} must be positive")
    if limits["max_json_bytes"] > 16 * 1024 * 1024:
        raise ReceiptError("max_json_bytes exceeds the hard protocol ceiling")
    if limits["max_commands"] > 1024 or limits["max_products"] > 256:
        raise ReceiptError("protocol collection bounds exceed hard controller ceilings")

    trust = exact_object(value["trust"], TRUST_FIELDS, "trust")
    require_string(trust["repository"], "trust.repository")
    for field in ("repository_id", "repository_owner_id"):
        number = require_non_negative_int(trust[field], f"trust.{field}")
        if number == 0:
            raise ReceiptError(f"trust.{field} must be positive")
    require_string(trust["workflow_path"], "trust.workflow_path")
    require_string(trust["workflow_ref"], "trust.workflow_ref")
    require_string(
        trust["external_verifier_contract_path"],
        "trust.external_verifier_contract_path",
    )
    require_hex64(
        trust["external_verifier_contract_sha256"],
        "trust.external_verifier_contract_sha256",
    )
    return value


def load_protocol(path: Path) -> tuple[dict[str, Any], str]:
    if not path.is_file():
        raise ReceiptError(f"protocol manifest does not exist: {path}")
    # Protocol files are deliberately much smaller than receipt limits.
    value = strict_json(path, 256 * 1024, require_canonical=False)
    validate_protocol(value)
    trust = value["trust"]
    root = path.resolve().parent.parent
    contract = (root / trust["external_verifier_contract_path"]).resolve()
    if not contract.is_relative_to(root) or not contract.is_file():
        raise ReceiptError("external verifier contract is not repository-owned")
    if sha256_file(contract) != trust["external_verifier_contract_sha256"]:
        raise ReceiptError("external verifier contract digest mismatch")
    return value, sha256_bytes(canonical_bytes(value))
