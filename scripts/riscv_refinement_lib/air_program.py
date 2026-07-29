"""Strict validation for the production-owned RISC-V AIR IR v2 program."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from . import codec
from .model import M31_MODULUS, RefinementError

AIR_IR_SCHEMA_VERSION = 2
AIR_IR_KIND = "stwo-riscv-air-constraint-program"
M31_NAME = "M31"
M31_TYPE = "m31"
LOOKUP_LIVENESS = "nonzero_numerator"
FAMILIES = frozenset(
    {
        "auipc",
        "base_alu_imm",
        "base_alu_reg",
        "branch_eq",
        "branch_lt",
        "div",
        "fence",
        "jal",
        "jalr",
        "load_store",
        "lt_imm",
        "lt_reg",
        "lui",
        "mul",
        "mulh",
        "shifts_imm",
        "shifts_reg",
    }
)
FAMILY_OPCODES = {
    "base_alu_reg": frozenset(
        {(0, "add"), (1, "sub"), (5, "xor"), (8, "or"), (9, "and")}
    ),
    "base_alu_imm": frozenset(
        {(10, "addi"), (13, "xori"), (14, "ori"), (15, "andi")}
    ),
    "shifts_reg": frozenset({(2, "sll"), (6, "srl"), (7, "sra")}),
    "shifts_imm": frozenset({(16, "slli"), (17, "srli"), (18, "srai")}),
    "lt_reg": frozenset({(3, "slt"), (4, "sltu")}),
    "lt_imm": frozenset({(11, "slti"), (12, "sltiu")}),
    "branch_eq": frozenset({(27, "beq"), (28, "bne")}),
    "branch_lt": frozenset(
        {(29, "blt"), (30, "bge"), (31, "bltu"), (32, "bgeu")}
    ),
    "lui": frozenset({(35, "lui")}),
    "auipc": frozenset({(36, "auipc")}),
    "jalr": frozenset({(34, "jalr")}),
    "jal": frozenset({(33, "jal")}),
    "load_store": frozenset(
        {
            (19, "lb"),
            (20, "lh"),
            (21, "lw"),
            (22, "lbu"),
            (23, "lhu"),
            (24, "sb"),
            (25, "sh"),
            (26, "sw"),
        }
    ),
    "mul": frozenset({(37, "mul")}),
    "mulh": frozenset({(38, "mulh"), (39, "mulhsu"), (40, "mulhu")}),
    "div": frozenset(
        {(41, "div"), (42, "divu"), (43, "rem"), (44, "remu")}
    ),
    "fence": frozenset({(45, "fence")}),
}

BUS_ARITIES = {
    "registers_state": 2,
    "memory_access": 7,
    "program_access": 5,
    "merkle": 4,
    "poseidon2": 16,
    "poseidon2_io": 32,
}
FIXED_TABLES = (
    ("bitwise", 4, 18),
    ("range_check_20", 1, 20),
    ("range_check_8_11", 2, 19),
    ("range_check_8_8_4", 3, 20),
    ("range_check_8_8", 2, 16),
    ("range_check_m31", 2, 15),
)
FIXED_ARITIES = {name: arity for name, arity, _ in FIXED_TABLES}
DOMAIN_ARITIES = BUS_ARITIES | FIXED_ARITIES
HEX_SHA256 = re.compile(r"[0-9a-f]{64}")
IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

TOP_LEVEL_KEYS = {
    "active_row",
    "columns",
    "content_digest",
    "events",
    "family",
    "field",
    "fixed_tables",
    "kind",
    "nodes",
    "opcode_selector",
    "projection",
    "schema_version",
    "source_identity",
}
UNSIGNED_TOP_LEVEL_KEYS = TOP_LEVEL_KEYS - {"content_digest", "source_identity"}

SOURCE_IDENTITY_BUILDER = "src/frontends/riscv/air/constraint_program.zig"
LUI_SOURCE_PATHS = (
    "src/core/fields/cm31.zig",
    "src/core/fields/m31.zig",
    "src/core/fields/qm31.zig",
    "src/frontends/riscv/access_clock.zig",
    "src/frontends/riscv/air/constraint_program.zig",
    "src/frontends/riscv/air/extract/model.zig",
    "src/frontends/riscv/air/extract/program.zig",
    "src/frontends/riscv/air/extract/program_json.zig",
    "src/frontends/riscv/air/extract/symbolic.zig",
    "src/frontends/riscv/air/lookups/entry.zig",
    "src/frontends/riscv/air/lookups/opcode_entries.zig",
    "src/frontends/riscv/air/lookups/tables/schema.zig",
    "src/frontends/riscv/air/program/opcode.zig",
    "src/frontends/riscv/air/semantic_eval.zig",
    "src/frontends/riscv/air/semantics/common.zig",
    "src/frontends/riscv/air/semantics/control_common.zig",
    "src/frontends/riscv/air/semantics/lui.zig",
    "src/frontends/riscv/air/semantics/mod.zig",
    "src/frontends/riscv/opcode_manifest.zig",
    "src/frontends/riscv/runner/trace.zig",
)


def _is_nat(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _reject_noninteger_json(value: Any, context: str = "$") -> None:
    if isinstance(value, bool) or isinstance(value, float):
        raise RefinementError(
            f"{context}: booleans and noninteger JSON numbers are forbidden"
        )
    if isinstance(value, list):
        for index, item in enumerate(value):
            _reject_noninteger_json(item, f"{context}[{index}]")
    elif isinstance(value, dict):
        for key, item in value.items():
            _reject_noninteger_json(item, f"{context}.{key}")


def _expect_keys(value: Any, expected: set[str], context: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        observed = sorted(value) if isinstance(value, dict) else type(value).__name__
        raise RefinementError(
            f"{context}: object keys drifted; expected {sorted(expected)}, "
            f"got {observed}"
        )
    return value


def _expect_sha256(value: Any, context: str) -> str:
    if not isinstance(value, str) or HEX_SHA256.fullmatch(value) is None:
        raise RefinementError(f"{context}: expected lowercase SHA-256")
    return value


def table_schema_digest(
    table_id: str,
    domain: str,
    arity: int,
    log_size: int,
) -> str:
    """Digest the stable per-table geometry; source identity binds its meaning."""

    return codec.sha256_bytes(
        codec.canonical_bytes(
            {
                "arity": arity,
                "domain": domain,
                "id": table_id,
                "log_size": log_size,
            }
        )
    )


def content_digest(payload: dict[str, Any]) -> str:
    unsigned = dict(payload)
    unsigned.pop("content_digest", None)
    return codec.sha256_bytes(codec.canonical_bytes(unsigned))


def source_identity(root: Path) -> dict[str, Any]:
    source_paths = LUI_SOURCE_PATHS
    if source_paths != tuple(sorted(source_paths)) or len(source_paths) != len(
        set(source_paths)
    ):
        raise RefinementError("AIR IR v2 source path closure is not sorted and unique")
    files: list[dict[str, str]] = []
    resolved_root = root.resolve()
    for relative in source_paths:
        path = root / relative
        if (
            path.is_symlink()
            or not path.is_file()
            or not path.resolve().is_relative_to(resolved_root)
        ):
            raise RefinementError(f"missing AIR IR v2 production source {relative}")
        files.append({"path": relative, "sha256": codec.sha256_file(path)})
    return {
        "builder": SOURCE_IDENTITY_BUILDER,
        "files": files,
        "source_closure_sha256": codec.sha256_bytes(codec.canonical_bytes(files)),
    }


def package_unsigned(
    payload: dict[str, Any],
    root: Path,
) -> dict[str, Any]:
    """Bind a production-emitted semantic object to its exact source closure."""

    _expect_keys(payload, UNSIGNED_TOP_LEVEL_KEYS, "unsigned AIR IR v2")
    if payload.get("family") != "lui":
        raise RefinementError("AIR IR v2 packaging currently supports only LUI")
    packaged = dict(payload)
    packaged["source_identity"] = source_identity(root)
    packaged["content_digest"] = content_digest(packaged)
    validate(packaged)
    return packaged


def verify_production_binding(
    payload: dict[str, Any],
    unsigned_payload: dict[str, Any],
    root: Path,
) -> None:
    """Require exact equality with a fresh source-bound production export."""

    expected = package_unsigned(unsigned_payload, root)
    if payload != expected:
        raise RefinementError(
            "AIR IR v2 artifact differs from fresh production serialization"
        )
    verify_source_files(payload, root)


def verify_source_files(payload: dict[str, Any], root: Path) -> None:
    """Re-hash every path named by a decoded artifact against the repository."""

    _validate_source_identity(payload)
    identity = payload["source_identity"]
    if identity["builder"] != SOURCE_IDENTITY_BUILDER:
        raise RefinementError("source_identity.builder: production builder drifted")
    actual_paths = tuple(item["path"] for item in identity["files"])
    if payload["family"] == "lui" and actual_paths != LUI_SOURCE_PATHS:
        raise RefinementError("source_identity.files: LUI source closure drifted")
    resolved_root = root.resolve()
    for item in identity["files"]:
        path = root / item["path"]
        if (
            path.is_symlink()
            or not path.is_file()
            or not path.resolve().is_relative_to(resolved_root)
            or codec.sha256_file(path) != item["sha256"]
        ):
            raise RefinementError(
                f"source_identity.files: source digest drifted for {item['path']}"
            )


def _validate_columns(payload: dict[str, Any]) -> tuple[str, ...]:
    raw_columns = payload["columns"]
    if not isinstance(raw_columns, list) or not raw_columns:
        raise RefinementError("AIR IR v2 columns must be a nonempty array")
    names: list[str] = []
    for index, raw in enumerate(raw_columns):
        column = _expect_keys(
            raw,
            {"index", "name", "role", "type", "width"},
            f"columns[{index}]",
        )
        if column["index"] != index:
            raise RefinementError(f"columns[{index}]: noncontiguous index")
        if (
            not isinstance(column["name"], str)
            or IDENTIFIER.fullmatch(column["name"]) is None
            or column["role"] not in {"input", "output", "witness"}
            or column["type"] != M31_TYPE
            or column["width"] != 1
        ):
            raise RefinementError(f"columns[{index}]: invalid typed column")
        names.append(column["name"])
    if len(set(names)) != len(names):
        raise RefinementError("AIR IR v2 contains duplicate column names")
    return tuple(names)


def _validate_nodes(
    payload: dict[str, Any],
    column_count: int,
) -> list[dict[str, Any]]:
    raw_nodes = payload["nodes"]
    if not isinstance(raw_nodes, list) or not raw_nodes:
        raise RefinementError("AIR IR v2 nodes must be a nonempty array")
    column_nodes: dict[int, int] = {}
    structural_nodes: dict[tuple[Any, ...], int] = {}
    for index, raw in enumerate(raw_nodes):
        if not isinstance(raw, dict):
            raise RefinementError(f"nodes[{index}]: expected object")
        op = raw.get("op")
        if op == "const":
            node = _expect_keys(raw, {"op", "value"}, f"nodes[{index}]")
            if not _is_nat(node["value"]) or node["value"] >= M31_MODULUS:
                raise RefinementError(f"nodes[{index}]: invalid M31 constant")
            structural_key = (op, node["value"])
        elif op == "col":
            node = _expect_keys(raw, {"column", "op"}, f"nodes[{index}]")
            column = node["column"]
            if not _is_nat(column) or column >= column_count:
                raise RefinementError(f"nodes[{index}]: invalid column reference")
            if column in column_nodes:
                raise RefinementError(
                    f"nodes[{index}]: duplicate node for column {column}"
                )
            column_nodes[column] = index
            structural_key = (op, column)
        else:
            node = _expect_keys(raw, {"args", "op"}, f"nodes[{index}]")
            args = node["args"]
            expected_arity = (
                1 if op == "neg" else 2 if op in {"add", "sub", "mul"} else None
            )
            if (
                expected_arity is None
                or not isinstance(args, list)
                or len(args) != expected_arity
                or any(not _is_nat(arg) or arg >= index for arg in args)
            ):
                raise RefinementError(
                    f"nodes[{index}]: unknown operation, arity, or forward reference"
                )
            structural_key = (op, *args)
        if structural_key in structural_nodes:
            raise RefinementError(
                f"nodes[{index}]: duplicates structurally identical node "
                f"{structural_nodes[structural_key]}"
            )
        structural_nodes[structural_key] = index
    if set(column_nodes) != set(range(column_count)):
        raise RefinementError("AIR IR v2 must contain exactly one node per column")
    return raw_nodes


def _node_ref(value: Any, node_count: int, context: str) -> int:
    if not _is_nat(value) or value >= node_count:
        raise RefinementError(f"{context}: invalid node reference")
    return value


def _static_node_values(nodes: list[dict[str, Any]]) -> list[int | None]:
    values: list[int | None] = []
    for node in nodes:
        operation = node["op"]
        if operation == "const":
            value: int | None = node["value"]
        elif operation == "col":
            value = None
        else:
            arguments = [values[index] for index in node["args"]]
            if any(argument is None for argument in arguments):
                value = None
            elif operation == "neg":
                value = (-arguments[0]) % M31_MODULUS
            elif operation == "add":
                value = (arguments[0] + arguments[1]) % M31_MODULUS
            elif operation == "sub":
                value = (arguments[0] - arguments[1]) % M31_MODULUS
            else:
                value = (arguments[0] * arguments[1]) % M31_MODULUS
        values.append(value)
    return values


def _validate_fixed_tables(payload: dict[str, Any]) -> None:
    raw_tables = payload["fixed_tables"]
    if not isinstance(raw_tables, list) or len(raw_tables) != len(FIXED_TABLES):
        raise RefinementError("AIR IR v2 must bind all six fixed tables")
    for index, (raw, expected) in enumerate(zip(raw_tables, FIXED_TABLES, strict=True)):
        table = _expect_keys(
            raw,
            {"arity", "domain", "id", "log_size", "schema_sha256"},
            f"fixed_tables[{index}]",
        )
        table_id, arity, log_size = expected
        if (
            table["id"] != table_id
            or table["domain"] != table_id
            or table["arity"] != arity
            or table["log_size"] != log_size
            or table["schema_sha256"]
            != table_schema_digest(table_id, table_id, arity, log_size)
        ):
            raise RefinementError(f"fixed_tables[{index}]: table identity drifted")


def _validate_events(
    payload: dict[str, Any],
    nodes: list[dict[str, Any]],
    static_values: list[int | None],
) -> tuple[list[dict[str, Any]], set[int]]:
    raw_events = payload["events"]
    if not isinstance(raw_events, list) or not raw_events:
        raise RefinementError("AIR IR v2 events must be a nonempty array")
    references: set[int] = set()
    lookup_events: list[dict[str, Any]] = []
    saw_lookup = False
    for index, raw in enumerate(raw_events):
        if not isinstance(raw, dict) or raw.get("ordinal") != index:
            raise RefinementError(f"events[{index}]: reordered event ordinal")
        kind = raw.get("kind")
        if kind == "constraint":
            if saw_lookup:
                raise RefinementError(
                    f"events[{index}]: direct constraint follows lookup event"
                )
            event = _expect_keys(
                raw,
                {"kind", "ordinal", "root"},
                f"events[{index}]",
            )
            references.add(_node_ref(event["root"], len(nodes), f"events[{index}].root"))
            continue
        if kind != "lookup":
            raise RefinementError(f"events[{index}]: unknown event kind")
        saw_lookup = True
        event = _expect_keys(
            raw,
            {
                "access_ordinal",
                "domain",
                "kind",
                "liveness",
                "numerator",
                "ordinal",
                "role",
                "table_id",
                "tuple",
            },
            f"events[{index}]",
        )
        domain = event["domain"]
        if domain not in DOMAIN_ARITIES:
            raise RefinementError(f"events[{index}]: unknown lookup domain")
        if event["role"] not in {"request", "consume", "emit"}:
            raise RefinementError(f"events[{index}]: unknown lookup role")
        if event["liveness"] != LOOKUP_LIVENESS:
            raise RefinementError(f"events[{index}]: unknown liveness rule")
        numerator = _node_ref(
            event["numerator"], len(nodes), f"events[{index}].numerator"
        )
        if static_values[numerator] == 0:
            raise RefinementError(f"events[{index}]: statically dead lookup")
        tuple_nodes = event["tuple"]
        if (
            not isinstance(tuple_nodes, list)
            or len(tuple_nodes) != DOMAIN_ARITIES[domain]
        ):
            raise RefinementError(f"events[{index}]: invalid lookup arity")
        references.add(numerator)
        references.update(
            _node_ref(value, len(nodes), f"events[{index}].tuple")
            for value in tuple_nodes
        )
        if domain in FIXED_ARITIES:
            if event["table_id"] != domain or event["role"] != "request":
                raise RefinementError(
                    f"events[{index}]: fixed-table identity/role drifted"
                )
        elif event["table_id"] is not None:
            raise RefinementError(f"events[{index}]: bus lookup names a fixed table")
        if domain == "program_access" and event["role"] != "request":
            raise RefinementError(
                f"events[{index}]: program lookup must have request role"
            )
        if domain == "registers_state" and event["role"] == "request":
            raise RefinementError(
                f"events[{index}]: state lookup must consume or emit"
            )
        if domain == "memory_access" and event["role"] == "request":
            raise RefinementError(
                f"events[{index}]: memory lookup must consume or emit"
            )
        access = event["access_ordinal"]
        if access is not None and (not _is_nat(access) or access == 0):
            raise RefinementError(f"events[{index}]: invalid access ordinal")
        lookup_events.append(event)
    if not saw_lookup or len(lookup_events) == len(raw_events):
        raise RefinementError(
            "AIR IR v2 must contain ordered direct constraints and lookups"
        )
    return lookup_events, references


def _validate_projection(
    payload: dict[str, Any],
    events: list[dict[str, Any]],
    node_count: int,
) -> set[int]:
    projection = _expect_keys(
        payload["projection"],
        {
            "destination_events",
            "next_pc",
            "program_event",
            "source_events",
            "state_events",
        },
        "projection",
    )
    event_groups = (
        ("program_event", [projection["program_event"]]),
        ("state_events", projection["state_events"]),
        ("source_events", projection["source_events"]),
        ("destination_events", projection["destination_events"]),
    )
    for name, values in event_groups:
        if not isinstance(values, list) or any(not _is_nat(value) for value in values):
            raise RefinementError(f"projection.{name}: invalid event array")
        if values != sorted(values) or len(values) != len(set(values)):
            raise RefinementError(
                f"projection.{name}: events are not unique and ordered"
            )
        for ordinal in values:
            if ordinal >= len(events) or events[ordinal].get("kind") != "lookup":
                raise RefinementError(
                    f"projection.{name}: does not reference a lookup event"
                )
    program_ordinal = projection["program_event"]
    if (
        events[program_ordinal]["domain"] != "program_access"
        or events[program_ordinal]["role"] != "request"
    ):
        raise RefinementError("projection.program_event: wrong lookup domain")
    expected_groups = (
        ("state_events", "registers_state"),
        ("source_events", "memory_access"),
        ("destination_events", "memory_access"),
    )
    for name, domain in expected_groups:
        ordinals = projection[name]
        if len(ordinals) % 2 != 0:
            raise RefinementError(f"projection.{name}: unpaired event array")
        for offset in range(0, len(ordinals), 2):
            if ordinals[offset + 1] != ordinals[offset] + 1:
                raise RefinementError(
                    f"projection.{name}: consume/emit pair is not adjacent"
                )
            consume = events[ordinals[offset]]
            emit = events[ordinals[offset + 1]]
            if (
                consume["domain"] != domain
                or consume["role"] != "consume"
                or emit["domain"] != domain
                or emit["role"] != "emit"
            ):
                raise RefinementError(
                    f"projection.{name}: expected ordered consume/emit pairs"
                )
            if domain == "memory_access" and (
                consume["access_ordinal"] is None
                or consume["access_ordinal"] != emit["access_ordinal"]
            ):
                raise RefinementError(
                    f"projection.{name}: access ordinal pair drifted"
                )
    all_projection_events = [
        projection["program_event"],
        *projection["state_events"],
        *projection["source_events"],
        *projection["destination_events"],
    ]
    if len(all_projection_events) != len(set(all_projection_events)):
        raise RefinementError("projection: event groups overlap")
    if len(projection["state_events"]) != 2:
        raise RefinementError("projection.state_events: expected one state pair")
    program_events = [
        event["ordinal"]
        for event in events
        if event.get("kind") == "lookup"
        and event.get("domain") == "program_access"
    ]
    if program_events != [projection["program_event"]]:
        raise RefinementError("projection.program_event: not the unique program event")
    state_events = [
        event["ordinal"]
        for event in events
        if event.get("kind") == "lookup"
        and event.get("domain") == "registers_state"
    ]
    if state_events != projection["state_events"]:
        raise RefinementError("projection.state_events: does not cover the state events")
    memory_events = [
        event["ordinal"]
        for event in events
        if event.get("kind") == "lookup"
        and event.get("domain") == "memory_access"
    ]
    projected_memory = [
        *projection["source_events"],
        *projection["destination_events"],
    ]
    if sorted(projected_memory) != memory_events:
        raise RefinementError(
            "projection source/destination events do not cover memory events"
        )
    state_emit = events[projection["state_events"][1]]
    next_pc = _node_ref(projection["next_pc"], node_count, "projection.next_pc")
    if state_emit["tuple"][0] != next_pc:
        raise RefinementError(
            "projection.next_pc: does not match the emitted state tuple"
        )
    return {
        next_pc
    }


def _validate_lui_shape(
    payload: dict[str, Any],
    lookup_events: list[dict[str, Any]],
) -> None:
    constraint_count = len(payload["events"]) - len(lookup_events)
    expected_lookups = [
        ("program_access", "request", None),
        ("registers_state", "consume", None),
        ("registers_state", "emit", None),
        ("range_check_8_8_4", "request", None),
        ("memory_access", "consume", 1),
        ("memory_access", "emit", 1),
        ("range_check_20", "request", 1),
    ]
    actual_lookups = [
        (event["domain"], event["role"], event["access_ordinal"])
        for event in lookup_events
    ]
    if constraint_count != 9 or actual_lookups != expected_lookups:
        raise RefinementError("LUI direct/lookup production event shape drifted")
    projection = payload["projection"]
    if (
        projection["source_events"] != []
        or len(projection["destination_events"]) != 2
    ):
        raise RefinementError("LUI source/destination projection drifted")


def _validate_source_identity(payload: dict[str, Any]) -> None:
    identity = _expect_keys(
        payload["source_identity"],
        {"builder", "files", "source_closure_sha256"},
        "source_identity",
    )
    if not isinstance(identity["builder"], str) or not identity["builder"]:
        raise RefinementError("source_identity.builder: expected source path")
    if identity["builder"] != SOURCE_IDENTITY_BUILDER:
        raise RefinementError("source_identity.builder: production builder drifted")
    _expect_sha256(
        identity["source_closure_sha256"],
        "source_identity.source_closure_sha256",
    )
    files = identity["files"]
    if not isinstance(files, list) or not files:
        raise RefinementError("source_identity.files: expected nonempty array")
    paths: list[str] = []
    for index, raw in enumerate(files):
        item = _expect_keys(raw, {"path", "sha256"}, f"source_identity.files[{index}]")
        path = item["path"]
        if (
            not isinstance(path, str)
            or not path
            or not path.isascii()
            or "\\" in path
            or path.startswith("/")
            or any(part in {"", ".", ".."} for part in path.split("/"))
        ):
            raise RefinementError(f"source_identity.files[{index}]: invalid path")
        _expect_sha256(item["sha256"], f"source_identity.files[{index}].sha256")
        paths.append(path)
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        raise RefinementError("source_identity.files: paths are not sorted and unique")
    if payload["family"] == "lui" and tuple(paths) != LUI_SOURCE_PATHS:
        raise RefinementError("source_identity.files: LUI source closure drifted")
    if identity["source_closure_sha256"] != codec.sha256_bytes(
        codec.canonical_bytes(files)
    ):
        raise RefinementError(
            "source_identity.source_closure_sha256: source closure drifted"
        )
    if identity["builder"] not in paths:
        raise RefinementError("source_identity.builder: builder is outside source closure")


def _reachable_nodes(nodes: list[dict[str, Any]], roots: set[int]) -> set[int]:
    reached = set(roots)
    pending = list(roots)
    while pending:
        index = pending.pop()
        for argument in nodes[index].get("args", ()):
            if argument not in reached:
                reached.add(argument)
                pending.append(argument)
    return reached


def validate(payload: dict[str, Any]) -> None:
    _reject_noninteger_json(payload)
    _expect_keys(payload, TOP_LEVEL_KEYS, "AIR IR v2")
    if (
        payload["schema_version"] != AIR_IR_SCHEMA_VERSION
        or payload["kind"] != AIR_IR_KIND
        or payload["family"] not in FAMILIES
    ):
        raise RefinementError("AIR IR v2 identity is invalid")
    field = _expect_keys(payload["field"], {"modulus", "name"}, "field")
    if field != {"name": M31_NAME, "modulus": M31_MODULUS}:
        raise RefinementError("AIR IR v2 field identity is invalid")

    columns = _validate_columns(payload)
    nodes = _validate_nodes(payload, len(columns))
    static_values = _static_node_values(nodes)
    active_row = _node_ref(payload["active_row"], len(nodes), "active_row")
    if (
        static_values[active_row] is not None
        and static_values[active_row] != 1
    ):
        raise RefinementError("active_row is statically not one")
    selector = _expect_keys(
        payload["opcode_selector"],
        {"expression", "manifest_id", "mnemonic"},
        "opcode_selector",
    )
    if (
        not _is_nat(selector["manifest_id"])
        or selector["manifest_id"] >= 46
        or not isinstance(selector["mnemonic"], str)
        or not selector["mnemonic"]
    ):
        raise RefinementError("opcode_selector identity is invalid")
    if (
        selector["manifest_id"],
        selector["mnemonic"],
    ) not in FAMILY_OPCODES[payload["family"]]:
        raise RefinementError("opcode_selector manifest/family identity drifted")
    selector_expression = _node_ref(
        selector["expression"], len(nodes), "opcode_selector.expression"
    )
    static_selector = static_values[selector_expression]
    if static_selector == 0 or (
        static_selector is not None
        and static_selector != selector["manifest_id"]
    ):
        raise RefinementError("opcode_selector expression is statically invalid")

    _validate_fixed_tables(payload)
    lookup_events, event_references = _validate_events(
        payload,
        nodes,
        static_values,
    )
    projection_references = _validate_projection(payload, payload["events"], len(nodes))
    if payload["family"] == "lui":
        _validate_lui_shape(payload, lookup_events)
    program_event = payload["events"][payload["projection"]["program_event"]]
    if program_event["tuple"][1] != selector_expression:
        raise RefinementError(
            "opcode_selector.expression is not the program tuple selector"
        )
    _validate_source_identity(payload)
    expected_digest = content_digest(payload)
    if payload["content_digest"] != expected_digest:
        raise RefinementError("AIR IR v2 content digest is invalid")

    roots = (
        event_references
        | projection_references
        | {active_row, selector_expression}
    )
    if _reachable_nodes(nodes, roots) != set(range(len(nodes))):
        raise RefinementError("AIR IR v2 contains dead/unreferenced expression nodes")

    # Access ordinals are source metadata, not adjacency inference. Every
    # declared architectural access must at least bind a consumed and emitted
    # memory tuple at the same positive subclock ordinal.
    by_access: dict[int, list[tuple[str, str]]] = {}
    first_seen_accesses: list[int] = []
    for event in lookup_events:
        access = event["access_ordinal"]
        domain = event["domain"]
        role = event["role"]
        if domain == "memory_access" and role in {"consume", "emit"}:
            if access is None:
                raise RefinementError(
                    "memory consume/emit event is missing its access ordinal"
                )
        elif access is not None and not (
            domain == "range_check_20" and role == "request"
        ):
            raise RefinementError(
                "access ordinal is only valid on memory consume/emit and "
                "their range-check-20 gap request"
            )
        if access is None:
            continue
        if access not in by_access:
            first_seen_accesses.append(access)
            by_access[access] = []
        by_access[access].append((domain, role))
    if first_seen_accesses != list(range(1, len(first_seen_accesses) + 1)):
        raise RefinementError(
            "access ordinals are not contiguous in production first-occurrence order"
        )
    expected_access_events = [
        ("memory_access", "consume"),
        ("memory_access", "emit"),
        ("range_check_20", "request"),
    ]
    for access, events in by_access.items():
        if events != expected_access_events:
            raise RefinementError(
                f"access ordinal {access}: expected ordered consume/emit/gap events"
            )


def load_canonical(path: Path) -> dict[str, Any]:
    payload = codec.load_json(path)
    validate(payload)
    try:
        encoded = path.read_bytes()
    except OSError as exc:
        raise RefinementError(f"{path}: could not read canonical AIR IR") from exc
    expected = codec.canonical_bytes(payload)
    if encoded != expected:
        raise RefinementError(
            f"{path}: AIR IR v2 is not compact canonical JSON"
        )
    return payload
