"""Host and aggregate receipt structural and verdict validation."""

from __future__ import annotations

from typing import Any

from .codec import canonical_bytes, content_digest, sha256_bytes
from .model import (
    AGGREGATE_SCHEMA,
    EVIDENCE_NAMES,
    EVIDENCE_SCHEMA,
    HOST_SCHEMA,
    STATUS_NO_GO,
    STATUS_NOT_ALLOCATED,
    STATUS_PASS,
    ReceiptError,
    exact_object,
    require_hex40,
    require_hex64,
    require_non_negative_int,
    require_safe_component,
    require_string,
    require_timestamp,
)
from .trust import validate_attestation, validate_run, validate_workflow


SOURCE_FIELDS = {"repository", "commit", "tree", "clean", "dirty_content_sha256"}
HOST_FIELDS = {
    "role", "os", "os_release", "architecture", "platform",
    "runner_name", "runner_environment", "identity_sha256",
}
TOOLCHAIN_FIELDS = {"python", "zig", "rustc"}
CHECKPOINT_FIELDS = {"status", "reason", "evidence_sha256"}
PRODUCT_FIELDS = {
    "product_id", "product_identity_sha256", "artifact_sha256",
    "executable_sha256", "status", "reason",
}
COMMAND_FIELDS = {
    "ordinal", "phase", "argv", "duration_ms", "exit_code", "skipped_tests",
    "stdout_sha256", "stderr_sha256",
}
EVIDENCE_REF_FIELDS = {"status", "reason", "sha256"}
EVIDENCE_MANIFEST_FIELDS = {"schema", "checkpoints", "products", "commands", "evidence"}
AUTHORITY_FIELDS = {
    "repository", "commit", "tree", "plan_sha256",
}
HOST_RECEIPT_FIELDS = {
    "schema", "schema_version", "created_at_unix", "source",
    "product_schema_sha256", "protocol_manifest_sha256", "workflow", "run",
    "host", "toolchains", "checkpoints", "products", "commands", "evidence",
    "authority", "evidence_preimages_sha256", "attestation", "verdict", "content_sha256",
}
AGGREGATE_FIELDS = {
    "schema", "schema_version", "created_at_unix", "source",
    "product_schema_sha256", "protocol_manifest_sha256", "workflow", "run",
    "host_receipts", "hosts", "toolchains", "checkpoints", "products",
    "commands", "evidence", "authority", "verdict", "content_sha256",
}
HOST_PARENT_FIELDS = {
    "file_sha256", "content_sha256", "artifact_name", "evidence_preimages_sha256",
}


def validate_source(value: object, label: str) -> dict[str, Any]:
    source = exact_object(value, SOURCE_FIELDS, label)
    require_string(source["repository"], f"{label}.repository")
    require_hex40(source["commit"], f"{label}.commit")
    require_hex40(source["tree"], f"{label}.tree")
    if not isinstance(source["clean"], bool):
        raise ReceiptError(f"{label}.clean must be boolean")
    require_hex64(source["dirty_content_sha256"], f"{label}.dirty_content_sha256")
    return source


def validate_authority(value: object, label: str) -> dict[str, Any]:
    authority = exact_object(value, AUTHORITY_FIELDS, label)
    require_string(authority["repository"], f"{label}.repository")
    require_hex40(authority["commit"], f"{label}.commit")
    require_hex40(authority["tree"], f"{label}.tree")
    require_hex64(authority["plan_sha256"], f"{label}.plan_sha256")
    return authority


def validate_host(value: object, role: str, label: str) -> dict[str, Any]:
    host = exact_object(value, HOST_FIELDS, label)
    if host["role"] != role:
        raise ReceiptError(f"{label}.role does not match receipt role")
    for field in HOST_FIELDS - {"identity_sha256"}:
        require_string(host[field], f"{label}.{field}")
    require_hex64(host["identity_sha256"], f"{label}.identity_sha256")
    identity = {key: item for key, item in host.items() if key != "identity_sha256"}
    if host["identity_sha256"] != sha256_bytes(canonical_bytes(identity)):
        raise ReceiptError(f"{label}.identity_sha256 does not bind host fields")
    return host


def validate_toolchains(value: object, label: str) -> dict[str, Any]:
    toolchains = exact_object(value, TOOLCHAIN_FIELDS, label)
    for field in TOOLCHAIN_FIELDS:
        require_string(toolchains[field], f"{label}.{field}")
    return toolchains


def validate_checkpoint(
    value: object, label: str, *, statuses: set[str],
) -> dict[str, Any]:
    checkpoint = exact_object(value, CHECKPOINT_FIELDS, label)
    if checkpoint["status"] not in statuses:
        raise ReceiptError(f"{label}.status is unsupported")
    require_string(checkpoint["reason"], f"{label}.reason")
    evidence = checkpoint["evidence_sha256"]
    if not isinstance(evidence, list) or len(evidence) > 32:
        raise ReceiptError(f"{label}.evidence_sha256 must be a bounded array")
    for index, digest in enumerate(evidence):
        require_hex64(digest, f"{label}.evidence_sha256[{index}]")
    if len(evidence) != len(set(evidence)):
        raise ReceiptError(f"{label}.evidence_sha256 contains duplicates")
    if checkpoint["status"] == STATUS_PASS and not evidence:
        raise ReceiptError(f"{label} PASS requires evidence")
    if checkpoint["status"] == STATUS_NOT_ALLOCATED and evidence:
        raise ReceiptError(f"{label} NOT-ALLOCATED cannot carry evidence")
    return checkpoint


def validate_product(
    value: object, protocol: dict[str, Any], label: str,
) -> dict[str, Any]:
    product = exact_object(value, PRODUCT_FIELDS, label)
    product_id = require_safe_component(product["product_id"], f"{label}.product_id")
    kind = protocol["products"].get(product_id)
    if kind is None:
        raise ReceiptError(f"{label} names an unknown product")
    if product["status"] not in {STATUS_PASS, STATUS_NO_GO}:
        raise ReceiptError(f"{label}.status is unsupported")
    require_string(product["reason"], f"{label}.reason")
    for field in ("product_identity_sha256", "artifact_sha256", "executable_sha256"):
        digest = product[field]
        if digest is not None:
            require_hex64(digest, f"{label}.{field}")
    if product["status"] == STATUS_PASS:
        require_hex64(product["product_identity_sha256"], f"{label}.product_identity_sha256")
        artifact = require_hex64(product["artifact_sha256"], f"{label}.artifact_sha256")
        if kind == "executable":
            executable = require_hex64(
                product["executable_sha256"], f"{label}.executable_sha256",
            )
            if artifact != executable:
                raise ReceiptError(f"{label} executable and artifact digests differ")
        elif product["executable_sha256"] is not None:
            raise ReceiptError(f"{label} library cannot carry an executable digest")
    return product


def validate_command(
    value: object, protocol: dict[str, Any], label: str,
) -> dict[str, Any]:
    command = exact_object(value, COMMAND_FIELDS, label)
    require_non_negative_int(command["ordinal"], f"{label}.ordinal")
    phase = require_string(command["phase"], f"{label}.phase")
    if phase not in protocol["checkpoint_order"][:-1]:
        raise ReceiptError(f"{label}.phase is not a host checkpoint")
    argv = command["argv"]
    limits = protocol["limits"]
    if not isinstance(argv, list) or not argv or len(argv) > limits["max_argv_items"]:
        raise ReceiptError(f"{label}.argv is not a bounded non-empty array")
    for index, argument in enumerate(argv):
        require_string(argument, f"{label}.argv[{index}]")
        if len(argument.encode("utf-8")) > limits["max_argument_bytes"]:
            raise ReceiptError(f"{label}.argv[{index}] exceeds the protocol bound")
    require_non_negative_int(command["duration_ms"], f"{label}.duration_ms")
    if not isinstance(command["exit_code"], int) or isinstance(command["exit_code"], bool):
        raise ReceiptError(f"{label}.exit_code must be an integer")
    require_non_negative_int(command["skipped_tests"], f"{label}.skipped_tests")
    require_hex64(command["stdout_sha256"], f"{label}.stdout_sha256")
    require_hex64(command["stderr_sha256"], f"{label}.stderr_sha256")
    return command


def validate_evidence_ref(value: object, label: str) -> dict[str, Any]:
    evidence = exact_object(value, EVIDENCE_REF_FIELDS, label)
    if evidence["status"] not in {STATUS_PASS, STATUS_NO_GO}:
        raise ReceiptError(f"{label}.status is unsupported")
    require_string(evidence["reason"], f"{label}.reason")
    if evidence["sha256"] is not None:
        require_hex64(evidence["sha256"], f"{label}.sha256")
    if evidence["status"] == STATUS_PASS and evidence["sha256"] is None:
        raise ReceiptError(f"{label} PASS requires a digest")
    return evidence


def validate_evidence_set(value: object, label: str) -> dict[str, Any]:
    evidence = exact_object(value, set(EVIDENCE_NAMES), label)
    for name in EVIDENCE_NAMES:
        validate_evidence_ref(evidence[name], f"{label}.{name}")
    return evidence


def validate_collections(
    *,
    checkpoints: object,
    products: object,
    commands: object,
    evidence: object,
    protocol: dict[str, Any],
    role: str,
    receipt: bool,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    role_policy = protocol["host_roles"][role]
    checkpoint_order = protocol["checkpoint_order"][:-1]
    allocated = set(role_policy["allocated_checkpoints"])
    if not isinstance(checkpoints, dict):
        raise ReceiptError("checkpoints must be an object")
    expected_checkpoint_keys = set(checkpoint_order) if receipt else allocated
    if receipt and set(checkpoints) != expected_checkpoint_keys:
        raise ReceiptError("host receipt checkpoint set drifted")
    if not receipt and not set(checkpoints).issubset(allocated):
        raise ReceiptError("host evidence contains an unallocated checkpoint")
    for checkpoint, value in checkpoints.items():
        statuses = {STATUS_PASS, STATUS_NO_GO}
        if receipt and checkpoint not in allocated:
            statuses = {STATUS_NOT_ALLOCATED}
        validate_checkpoint(value, f"checkpoints.{checkpoint}", statuses=statuses)

    if not isinstance(products, list) or len(products) > protocol["limits"]["max_products"]:
        raise ReceiptError("products must be a bounded array")
    product_values = [
        validate_product(item, protocol, f"products[{index}]")
        for index, item in enumerate(products)
    ]
    product_ids = [item["product_id"] for item in product_values]
    if len(product_ids) != len(set(product_ids)):
        raise ReceiptError("products contain duplicate product IDs")
    if product_ids != sorted(product_ids):
        raise ReceiptError("products must use canonical product-ID order")
    if not set(product_ids).issubset(set(role_policy["required_products"])):
        raise ReceiptError("products include an item not allocated to the host")

    if not isinstance(commands, list) or len(commands) > protocol["limits"]["max_commands"]:
        raise ReceiptError("commands must be a bounded array")
    command_values = [
        validate_command(item, protocol, f"commands[{index}]")
        for index, item in enumerate(commands)
    ]
    if [item["ordinal"] for item in command_values] != list(range(len(command_values))):
        raise ReceiptError("command ordinals must be contiguous and zero-based")
    phases = [item["phase"] for item in command_values]
    if any(phase not in allocated for phase in phases):
        raise ReceiptError("commands include a phase not allocated to the host")
    phase_order = {name: index for index, name in enumerate(checkpoint_order)}
    if phases != sorted(phases, key=phase_order.__getitem__):
        raise ReceiptError("mandatory command phases are reordered")
    validate_evidence_set(evidence, "evidence")
    return checkpoints, product_values, command_values, evidence


def collection_verdict(
    *,
    source: dict[str, Any],
    host: dict[str, Any],
    attestation: dict[str, Any],
    checkpoints: dict[str, Any],
    products: list[dict[str, Any]],
    commands: list[dict[str, Any]],
    evidence: dict[str, Any],
    toolchains: dict[str, Any],
    protocol: dict[str, Any],
    role: str,
) -> str:
    policy = protocol["host_roles"][role]
    allocated = policy["allocated_checkpoints"]
    by_phase: dict[str, list[dict[str, Any]]] = {phase: [] for phase in allocated}
    for command in commands:
        by_phase[command["phase"]].append(command)
    complete_phases = all(
        by_phase[phase]
        and all(item["exit_code"] == 0 and item["skipped_tests"] == 0 for item in by_phase[phase])
        for phase in allocated
    )
    complete_checkpoints = all(
        checkpoints.get(phase, {}).get("status") == STATUS_PASS for phase in allocated
    )
    products_by_id = {item["product_id"]: item for item in products}
    complete_products = all(
        products_by_id.get(product, {}).get("status") == STATUS_PASS
        for product in policy["required_products"]
    )
    complete_evidence = all(item["status"] == STATUS_PASS for item in evidence.values())
    complete_toolchain = all(
        toolchains[name] != "unavailable" for name in ("python", "zig")
    )
    trusted = attestation["kind"] == "github-actions-artifact-v1"
    host_matches = host["os"] == policy["os"]
    if all((source["clean"], complete_phases, complete_checkpoints, complete_products,
            complete_evidence, complete_toolchain, trusted, host_matches)):
        return STATUS_PASS
    return STATUS_NO_GO


def validate_evidence_manifest(
    value: dict[str, Any], protocol: dict[str, Any], role: str,
) -> dict[str, Any]:
    exact_object(value, EVIDENCE_MANIFEST_FIELDS, "host evidence")
    if value["schema"] != EVIDENCE_SCHEMA:
        raise ReceiptError(f"host evidence schema must be {EVIDENCE_SCHEMA}")
    validate_collections(
        checkpoints=value["checkpoints"], products=value["products"],
        commands=value["commands"], evidence=value["evidence"],
        protocol=protocol, role=role, receipt=False,
    )
    return value


def validate_host_receipt(
    value: dict[str, Any], protocol: dict[str, Any], *, expected_role: str | None = None,
) -> dict[str, Any]:
    exact_object(value, HOST_RECEIPT_FIELDS, "host receipt")
    if value["schema"] != HOST_SCHEMA or value["schema_version"] != 1:
        raise ReceiptError("host receipt schema/version drifted")
    require_timestamp(value["created_at_unix"], "created_at_unix")
    source = validate_source(value["source"], "source")
    authority = validate_authority(value["authority"], "authority")
    require_hex64(value["evidence_preimages_sha256"], "evidence_preimages_sha256")
    if authority["commit"] == source["commit"] and value["attestation"]["kind"] != "local-unsigned-v1":
        raise ReceiptError("trusted receipt authority must be distinct from candidate")
    require_hex64(value["product_schema_sha256"], "product_schema_sha256")
    require_hex64(value["protocol_manifest_sha256"], "protocol_manifest_sha256")
    validate_workflow(value["workflow"], "workflow")
    validate_run(value["run"], "run")
    attestation = validate_attestation(value["attestation"], "attestation")
    role = value.get("host", {}).get("role") if isinstance(value.get("host"), dict) else None
    if role not in protocol["host_roles"] or (expected_role is not None and role != expected_role):
        raise ReceiptError("host receipt role is invalid or misplaced")
    host = validate_host(value["host"], role, "host")
    toolchains = validate_toolchains(value["toolchains"], "toolchains")
    checkpoints, products, commands, evidence = validate_collections(
        checkpoints=value["checkpoints"], products=value["products"],
        commands=value["commands"], evidence=value["evidence"],
        protocol=protocol, role=role, receipt=True,
    )
    expected_verdict = collection_verdict(
        source=source, host=host, attestation=attestation, checkpoints=checkpoints,
        products=products, commands=commands, evidence=evidence,
        toolchains=toolchains, protocol=protocol, role=role,
    )
    if value["verdict"] != expected_verdict:
        raise ReceiptError("host receipt verdict is not derived from its evidence")
    require_hex64(value["content_sha256"], "content_sha256")
    if value["content_sha256"] != content_digest(value):
        raise ReceiptError("host receipt content digest mismatch")
    return value


def validate_aggregate_receipt(value: dict[str, Any], protocol: dict[str, Any]) -> dict[str, Any]:
    exact_object(value, AGGREGATE_FIELDS, "aggregate receipt")
    if value["schema"] != AGGREGATE_SCHEMA or value["schema_version"] != 1:
        raise ReceiptError("aggregate receipt schema/version drifted")
    require_timestamp(value["created_at_unix"], "created_at_unix")
    source = validate_source(value["source"], "source")
    authority = validate_authority(value["authority"], "authority")
    if authority["commit"] == source["commit"]:
        raise ReceiptError("aggregate authority must be distinct from candidate")
    require_hex64(value["product_schema_sha256"], "product_schema_sha256")
    require_hex64(value["protocol_manifest_sha256"], "protocol_manifest_sha256")
    workflow = validate_workflow(value["workflow"], "workflow")
    run = validate_run(value["run"], "run")
    trust = protocol["trust"]
    if workflow["path"] != trust["workflow_path"] or workflow["ref"] != trust["workflow_ref"]:
        raise ReceiptError("aggregate workflow is not the trusted workflow")
    if run != {
        "provider": "github-actions",
        "repository": trust["repository"],
        "repository_id": trust["repository_id"],
        "repository_owner_id": trust["repository_owner_id"],
        "run_id": run["run_id"],
        "run_attempt": run["run_attempt"],
        "job": protocol["aggregate_job"],
        "session_nonce": run["session_nonce"],
    }:
        raise ReceiptError("aggregate run is not the trusted verifier role")

    roles = {"linux", "macos"}
    parents = exact_object(value["host_receipts"], roles, "host_receipts")
    for role in roles:
        parent = exact_object(parents[role], HOST_PARENT_FIELDS, f"host_receipts.{role}")
        require_hex64(parent["file_sha256"], f"host_receipts.{role}.file_sha256")
        require_hex64(parent["content_sha256"], f"host_receipts.{role}.content_sha256")
        require_hex64(
            parent["evidence_preimages_sha256"],
            f"host_receipts.{role}.evidence_preimages_sha256",
        )
        require_safe_component(parent["artifact_name"], f"host_receipts.{role}.artifact_name")
    if parents["linux"]["file_sha256"] == parents["macos"]["file_sha256"]:
        raise ReceiptError("aggregate host receipt file identities are replayed")
    if parents["linux"]["content_sha256"] == parents["macos"]["content_sha256"]:
        raise ReceiptError("aggregate host receipt content identities are replayed")

    hosts = exact_object(value["hosts"], roles, "hosts")
    toolchains = exact_object(value["toolchains"], roles, "toolchains")
    products = exact_object(value["products"], roles, "products")
    commands = exact_object(value["commands"], roles, "commands")
    evidence = exact_object(value["evidence"], roles, "evidence")
    complete_products = True
    complete_commands = True
    complete_evidence = True
    for role in roles:
        validate_host(hosts[role], role, f"hosts.{role}")
        validate_toolchains(toolchains[role], f"toolchains.{role}")
        if not isinstance(products[role], list) or len(products[role]) > protocol["limits"]["max_products"]:
            raise ReceiptError(f"products.{role} must be a bounded array")
        product_values = [
            validate_product(item, protocol, f"products.{role}[{index}]")
            for index, item in enumerate(products[role])
        ]
        product_ids = [item["product_id"] for item in product_values]
        if product_ids != sorted(product_ids) or len(product_ids) != len(set(product_ids)):
            raise ReceiptError(f"products.{role} is not a unique canonical product list")
        required_products = protocol["host_roles"][role]["required_products"]
        complete_products = complete_products and all(
            next(
                (item["status"] == STATUS_PASS for item in product_values
                 if item["product_id"] == product_id),
                False,
            )
            for product_id in required_products
        )

        if not isinstance(commands[role], list) or len(commands[role]) > protocol["limits"]["max_commands"]:
            raise ReceiptError(f"commands.{role} must be a bounded array")
        command_values = [
            validate_command(item, protocol, f"commands.{role}[{index}]")
            for index, item in enumerate(commands[role])
        ]
        if [item["ordinal"] for item in command_values] != list(range(len(command_values))):
            raise ReceiptError(f"commands.{role} ordinals drifted")
        allocated = protocol["host_roles"][role]["allocated_checkpoints"]
        phase_order = {name: index for index, name in enumerate(protocol["checkpoint_order"])}
        phases = [item["phase"] for item in command_values]
        if phases != sorted(phases, key=phase_order.__getitem__):
            raise ReceiptError(f"commands.{role} phases are reordered")
        complete_commands = complete_commands and all(
            any(item["phase"] == phase for item in command_values) for phase in allocated
        ) and all(
            item["exit_code"] == 0 and item["skipped_tests"] == 0 for item in command_values
        )
        validate_evidence_set(evidence[role], f"evidence.{role}")
        complete_evidence = complete_evidence and all(
            item["status"] == STATUS_PASS for item in evidence[role].values()
        )
    checkpoints = value["checkpoints"]
    if not isinstance(checkpoints, dict) or list(checkpoints) != protocol["checkpoint_order"]:
        raise ReceiptError("aggregate checkpoint order/set drifted")
    for name in protocol["checkpoint_order"]:
        validate_checkpoint(
            checkpoints[name], f"checkpoints.{name}", statuses={STATUS_PASS, STATUS_NO_GO},
        )
        assigned_roles = (
            ["linux", "macos"]
            if name == "BG-15"
            else [
                role for role in ("linux", "macos")
                if name in protocol["host_roles"][role]["allocated_checkpoints"]
            ]
        )
        expected_evidence = [parents[role]["file_sha256"] for role in assigned_roles]
        if checkpoints[name]["evidence_sha256"] != expected_evidence:
            raise ReceiptError(f"checkpoints.{name} host evidence binding drifted")
    if value["verdict"] not in {STATUS_PASS, STATUS_NO_GO}:
        raise ReceiptError("aggregate verdict is unsupported")
    expected = STATUS_PASS if (
        source["clean"]
        and complete_products
        and complete_commands
        and complete_evidence
        and all(item["status"] == STATUS_PASS for item in checkpoints.values())
    ) else STATUS_NO_GO
    if value["verdict"] != expected:
        raise ReceiptError("aggregate verdict is not derived from checkpoint verdicts")
    require_hex64(value["content_sha256"], "content_sha256")
    if value["content_sha256"] != content_digest(value):
        raise ReceiptError("aggregate receipt content digest mismatch")
    return value
