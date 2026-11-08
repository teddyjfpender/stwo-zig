#!/usr/bin/env python3
"""Generate the official, version-pinned Cairo claim registry used by the Zig port."""

from __future__ import annotations

import argparse
import ast
import dataclasses
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_RUST_ROOT = Path(
    os.environ.get(
        "STWO_CAIRO_RUST_ROOT",
        ROOT.parent / "stwo-cairo",
    )
)
DEFAULT_OUTPUT = ROOT / "src/frontends/cairo/air/official_claim_registry.zig"

PINNED_STWO_CAIRO_REVISION = "82f21252a68ec006d73e299f5bf1ce6d4db0ee78"
PINNED_STWO_REVISION = "7b211edde786775016ef3eecb837a6240d8fe792"

CLAIMS_PATH = Path("crates/cairo-air/src/claims.rs")
COMPONENTS_PATH = Path("crates/cairo-air/src/components")
MEMORY_ADDRESS_PATH = COMPONENTS_PATH / "memory_address_to_id.rs"
MEMORY_BIG_PATH = COMPONENTS_PATH / "memory_id_to_big.rs"
MEMORY_CONSTANTS_PATH = Path("crates/common/src/memory.rs")
PREPROCESSED_PATH = Path(
    "crates/common/src/preprocessed_columns/preprocessed_trace.rs"
)
CARGO_MANIFEST_PATH = Path("Cargo.toml")
CARGO_LOCK_PATH = Path("Cargo.lock")


class RegistryError(ValueError):
    pass


@dataclasses.dataclass(frozen=True)
class ClaimField:
    name: str
    field_index: int
    first_enable_slot: int
    enable_slot_count: int
    log_size_shape: str
    fixed_log_size: int | None


@dataclasses.dataclass(frozen=True)
class EnableSlot:
    name: str
    enable_slot: int
    claim_field_index: int
    field_slot_index: int
    log_size_shape: str
    fixed_log_size: int | None


@dataclasses.dataclass(frozen=True)
class SourceFile:
    path: str
    sha256: str


@dataclasses.dataclass(frozen=True)
class Registry:
    claim_fields: tuple[ClaimField, ...]
    enable_slots: tuple[EnableSlot, ...]
    source_files: tuple[SourceFile, ...]
    memory_id_to_big_slots: int
    registry_sha256: str


def _run_git(root: Path, *args: str) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), *args],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        detail = getattr(error, "stderr", "")
        raise RegistryError(f"git {' '.join(args)} failed: {detail.strip()}") from error
    return result.stdout


def _extract_braced(source: str, marker: str) -> tuple[str, int, int]:
    marker_index = source.find(marker)
    if marker_index < 0:
        raise RegistryError(f"missing Rust source marker: {marker}")
    open_index = source.find("{", marker_index + len(marker))
    if open_index < 0:
        raise RegistryError(f"missing opening brace after: {marker}")
    depth = 0
    for index in range(open_index, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[open_index + 1 : index], open_index, index
    raise RegistryError(f"unterminated Rust source block: {marker}")


def parse_claim_fields(claims_source: str) -> tuple[str, ...]:
    body, _, _ = _extract_braced(claims_source, "pub struct CairoClaim")
    fields: list[tuple[str, str]] = []
    for line in body.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        match = re.fullmatch(r"pub (\w+): (.+),", stripped)
        if match is None:
            raise RegistryError(f"unsupported CairoClaim field syntax: {stripped}")
        fields.append((match.group(1), match.group(2)))

    if not fields or fields[0] != ("public_data", "PublicData"):
        raise RegistryError("CairoClaim must begin with public_data: PublicData")
    claim_fields = fields[1:]
    if len(claim_fields) != 68:
        raise RegistryError(f"expected 68 Cairo claim fields, found {len(claim_fields)}")
    for name, encoded_type in claim_fields:
        if encoded_type != f"Option<{name}::Claim>":
            raise RegistryError(f"unexpected Cairo claim type for {name}: {encoded_type}")
    return tuple(name for name, _ in claim_fields)


def _parse_u32_constant(source: str, name: str) -> int:
    expressions = dict(
        re.findall(r"pub const (\w+): u32 = ([^;]+);", source)
    )
    active: set[str] = set()

    def resolve(constant_name: str) -> int:
        if constant_name not in expressions:
            raise RegistryError(f"missing u32 constant {constant_name}")
        if constant_name in active:
            raise RegistryError(f"cyclic u32 constant {constant_name}")
        active.add(constant_name)
        try:
            expression = ast.parse(expressions[constant_name], mode="eval").body
            return evaluate(expression)
        except (SyntaxError, ValueError, OverflowError) as error:
            raise RegistryError(
                f"unsupported u32 expression for {constant_name}: {expressions[constant_name]}"
            ) from error
        finally:
            active.remove(constant_name)

    def evaluate(node: ast.AST) -> int:
        if isinstance(node, ast.Constant) and type(node.value) is int:
            value = node.value
        elif isinstance(node, ast.Name):
            value = resolve(node.id)
        elif isinstance(node, ast.BinOp):
            left = evaluate(node.left)
            right = evaluate(node.right)
            if isinstance(node.op, ast.Add):
                value = left + right
            elif isinstance(node.op, ast.Sub):
                value = left - right
            elif isinstance(node.op, ast.Mult):
                value = left * right
            elif isinstance(node.op, ast.LShift):
                value = left << right
            elif isinstance(node.op, ast.RShift):
                value = left >> right
            else:
                raise ValueError("unsupported binary operator")
        else:
            raise ValueError("unsupported expression node")
        if not 0 <= value <= 0xFFFF_FFFF:
            raise OverflowError("u32 constant outside range")
        return value

    return resolve(name)


def parse_memory_slot_count(
    memory_address_source: str,
    memory_constants_source: str,
    preprocessed_source: str,
) -> int:
    expected_expression = re.compile(
        r"pub const MEMORY_ADDRESS_TO_ID_SPLIT: usize\s*=\s*"
        r"1 << \(LOG_MEMORY_ADDRESS_BOUND - MAX_SEQUENCE_LOG_SIZE\);"
    )
    if expected_expression.search(memory_address_source) is None:
        raise RegistryError("MEMORY_ADDRESS_TO_ID_SPLIT expression drifted")
    address_log = _parse_u32_constant(memory_constants_source, "LOG_MEMORY_ADDRESS_BOUND")
    sequence_log = _parse_u32_constant(preprocessed_source, "MAX_SEQUENCE_LOG_SIZE")
    if address_log < sequence_log:
        raise RegistryError("memory split exponent is negative")
    slot_count = 1 << (address_log - sequence_log)
    if slot_count != 16:
        raise RegistryError(f"expected 16 memory_id_to_big slots, found {slot_count}")
    return slot_count


def _parse_if_block(source: str, match: re.Match[str]) -> tuple[str, int]:
    open_index = source.find("{", match.start(), match.end())
    depth = 0
    for index in range(open_index, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[open_index + 1 : index], index
    raise RegistryError(f"unterminated flatten block for {match.group(1)}")


def parse_flatten_shapes(
    claims_source: str,
    claim_order: tuple[str, ...],
    memory_slot_count: int,
    fixed_log_sizes: dict[str, int],
) -> tuple[tuple[ClaimField, ...], tuple[EnableSlot, ...]]:
    flatten_body, _, _ = _extract_braced(
        claims_source,
        "pub fn flatten_claim(&self) -> FlatClaim",
    )
    if_match = re.compile(r"if let Some\((?:_)?c\) = self\.(\w+) \{")
    ordinary: list[tuple[int, str, str, int | None]] = []
    for match in if_match.finditer(flatten_body):
        name = match.group(1)
        block, close_index = _parse_if_block(flatten_body, match)
        true_count = block.count("component_enable_bits.push(true);")
        dynamic_count = block.count("component_log_sizes.push(c.log_size);")
        fixed_matches = re.findall(
            r"component_log_sizes\.push\((\w+)::LOG_SIZE\);",
            block,
        )
        if true_count != 1 or dynamic_count + len(fixed_matches) != 1:
            raise RegistryError(f"unsupported flatten shape for {name}")
        else_match = re.match(
            r"\s*else \{\s*component_enable_bits\.push\(false\);\s*\}",
            flatten_body[close_index + 1 :],
        )
        if else_match is None:
            raise RegistryError(f"missing fail-closed disabled slot for {name}")
        if dynamic_count:
            shape = "dynamic"
            fixed_log_size = None
        else:
            fixed_name = fixed_matches[0]
            if fixed_name != name or name not in fixed_log_sizes:
                raise RegistryError(f"unresolved fixed log size for {name}")
            shape = "fixed"
            fixed_log_size = fixed_log_sizes[name]
        ordinary.append((match.start(), name, shape, fixed_log_size))

    memory_marker = "let memory_id_to_big::Claim { big_log_sizes } ="
    memory_position = flatten_body.find(memory_marker)
    if memory_position < 0:
        raise RegistryError("missing memory_id_to_big flatten expansion")
    required_memory_fragments = (
        "self.memory_id_to_big.as_ref().unwrap()",
        "assert!(big_log_sizes.len() <= MEMORY_ADDRESS_TO_ID_SPLIT);",
        "for log_size in big_log_sizes",
        "component_log_sizes.push(*log_size);",
        "MEMORY_ADDRESS_TO_ID_SPLIT - big_log_sizes.len()",
    )
    for fragment in required_memory_fragments:
        if fragment not in flatten_body:
            raise RegistryError(f"memory_id_to_big flatten logic drifted: {fragment}")

    events: list[tuple[int, str, str, int | None]] = ordinary + [
        (memory_position, "memory_id_to_big", "special_dynamic_prefix", None)
    ]
    events.sort(key=lambda event: event[0])
    flatten_order = tuple(event[1] for event in events)
    if flatten_order != claim_order:
        raise RegistryError("CairoClaim field order and flatten_claim order differ")

    fields: list[ClaimField] = []
    slots: list[EnableSlot] = []
    for field_index, (_, name, shape, fixed_log_size) in enumerate(events):
        slot_count = memory_slot_count if name == "memory_id_to_big" else 1
        first_slot = len(slots)
        fields.append(
            ClaimField(
                name=name,
                field_index=field_index,
                first_enable_slot=first_slot,
                enable_slot_count=slot_count,
                log_size_shape=shape,
                fixed_log_size=fixed_log_size,
            )
        )
        for field_slot_index in range(slot_count):
            slot_name = (
                f"{name}[{field_slot_index}]" if slot_count > 1 else name
            )
            slots.append(
                EnableSlot(
                    name=slot_name,
                    enable_slot=len(slots),
                    claim_field_index=field_index,
                    field_slot_index=field_slot_index,
                    log_size_shape=shape,
                    fixed_log_size=fixed_log_size,
                )
            )
    if len(fields) != 68 or len(slots) != 83:
        raise RegistryError(
            f"registry cardinality mismatch: {len(fields)} fields, {len(slots)} slots"
        )
    return tuple(fields), tuple(slots)


def _git_show(root: Path, path: Path) -> str:
    return _run_git(root, "show", f"{PINNED_STWO_CAIRO_REVISION}:{path.as_posix()}")


def _read_source(root: Path, path: Path) -> str:
    source_path = root / path
    try:
        return source_path.read_text()
    except OSError as error:
        raise RegistryError(f"cannot read pinned Rust source {source_path}: {error}") from error


def _sha256_text(source: str) -> str:
    return hashlib.sha256(source.encode()).hexdigest()


def _verify_revisions(root: Path) -> None:
    head = _run_git(root, "rev-parse", "HEAD").strip()
    if head != PINNED_STWO_CAIRO_REVISION:
        raise RegistryError(
            f"expected stwo-cairo {PINNED_STWO_CAIRO_REVISION}, found {head}"
        )
    manifest = _git_show(root, CARGO_MANIFEST_PATH)
    declared_revisions = set(
        re.findall(
            r'^stwo(?:-[\w-]+)?\s*=\s*\{[^\n]*rev\s*=\s*"([0-9a-f]{8,40})"',
            manifest,
            re.MULTILINE,
        )
    )
    if not declared_revisions or any(
        not PINNED_STWO_REVISION.startswith(revision)
        for revision in declared_revisions
    ):
        raise RegistryError(
            f"unexpected Stwo revisions in pinned Cargo.toml: {declared_revisions}"
        )
    lockfile = _git_show(root, CARGO_LOCK_PATH)
    locked_revisions = set(
        re.findall(
            r"git\+https://github\.com/starkware-libs/stwo"
            r"(?:\?rev=[0-9a-f]{8,40})?#([0-9a-f]{40})",
            lockfile,
        )
    )
    if locked_revisions != {PINNED_STWO_REVISION}:
        raise RegistryError(
            f"unexpected Stwo revisions in pinned Cargo.lock: {locked_revisions}"
        )


def _verify_clean_sources(root: Path, paths: list[Path]) -> None:
    result = subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "diff",
            "--quiet",
            PINNED_STWO_CAIRO_REVISION,
            "--",
            *(path.as_posix() for path in paths),
        ],
        check=False,
    )
    if result.returncode == 1:
        raise RegistryError("claim registry Rust inputs differ from the pinned revision")
    if result.returncode != 0:
        raise RegistryError("could not validate claim registry Rust inputs")


def load_registry(root: Path) -> Registry:
    _verify_revisions(root)
    claims_source = _read_source(root, CLAIMS_PATH)
    claim_order = parse_claim_fields(claims_source)

    memory_address_source = _read_source(root, MEMORY_ADDRESS_PATH)
    memory_constants_source = _read_source(root, MEMORY_CONSTANTS_PATH)
    preprocessed_source = _read_source(root, PREPROCESSED_PATH)
    memory_big_source = _read_source(root, MEMORY_BIG_PATH)
    memory_slot_count = parse_memory_slot_count(
        memory_address_source,
        memory_constants_source,
        preprocessed_source,
    )
    if re.search(
        r"pub struct Claim \{\s*pub big_log_sizes: Vec<u32>,\s*\}",
        memory_big_source,
    ) is None:
        raise RegistryError("memory_id_to_big Claim shape drifted")

    fixed_names = set(
        re.findall(
            r"component_log_sizes\.push\((\w+)::LOG_SIZE\);",
            _extract_braced(
                claims_source,
                "pub fn flatten_claim(&self) -> FlatClaim",
            )[0],
        )
    )
    fixed_log_sizes: dict[str, int] = {}
    fixed_paths: list[Path] = []
    for name in sorted(fixed_names):
        path = COMPONENTS_PATH / f"{name}.rs"
        fixed_paths.append(path)
        fixed_log_sizes[name] = _parse_u32_constant(_read_source(root, path), "LOG_SIZE")

    source_paths = [
        CARGO_MANIFEST_PATH,
        CARGO_LOCK_PATH,
        CLAIMS_PATH,
        MEMORY_ADDRESS_PATH,
        MEMORY_BIG_PATH,
        MEMORY_CONSTANTS_PATH,
        PREPROCESSED_PATH,
        *fixed_paths,
    ]
    _verify_clean_sources(root, source_paths)
    fields, slots = parse_flatten_shapes(
        claims_source,
        claim_order,
        memory_slot_count,
        fixed_log_sizes,
    )
    source_files = tuple(
        SourceFile(path.as_posix(), _sha256_text(_read_source(root, path)))
        for path in source_paths
    )
    semantic = {
        "stwo_cairo_revision": PINNED_STWO_CAIRO_REVISION,
        "stwo_revision": PINNED_STWO_REVISION,
        "claim_fields": [dataclasses.asdict(field) for field in fields],
        "enable_slots": [dataclasses.asdict(slot) for slot in slots],
        "source_files": [dataclasses.asdict(source) for source in source_files],
    }
    digest = hashlib.sha256(
        json.dumps(semantic, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return Registry(fields, slots, source_files, memory_slot_count, digest)


def _zig_optional(value: int | None) -> str:
    return "null" if value is None else str(value)


def render_zig(registry: Registry) -> str:
    lines = [
        "//! Version-pinned Cairo claim registry.",
        "//!",
        "//! Generated by `scripts/generate_cairo_claim_registry.py`; do not edit by hand.",
        "",
        'const std = @import("std");',
        "",
        "pub const SourceRevision = struct {",
        "    stwo_cairo: []const u8,",
        "    stwo: []const u8,",
        "};",
        "",
        "pub const SourceFile = struct {",
        "    path: []const u8,",
        "    sha256: []const u8,",
        "};",
        "",
        "pub const LogSizeShape = enum {",
        "    dynamic,",
        "    fixed,",
        "    special_dynamic_prefix,",
        "};",
        "",
        "pub const ClaimField = struct {",
        "    name: []const u8,",
        "    field_index: u8,",
        "    first_enable_slot: u8,",
        "    enable_slot_count: u8,",
        "    log_size_shape: LogSizeShape,",
        "    fixed_log_size: ?u32,",
        "};",
        "",
        "pub const EnableSlot = struct {",
        "    name: []const u8,",
        "    enable_slot: u8,",
        "    claim_field_index: u8,",
        "    field_slot_index: u8,",
        "    log_size_shape: LogSizeShape,",
        "    fixed_log_size: ?u32,",
        "};",
        "",
        "pub const source_revision = SourceRevision{",
        f'    .stwo_cairo = "{PINNED_STWO_CAIRO_REVISION}",',
        f'    .stwo = "{PINNED_STWO_REVISION}",',
        "};",
        f'pub const registry_sha256 = "{registry.registry_sha256}";',
        f"pub const claim_field_count: usize = {len(registry.claim_fields)};",
        f"pub const enable_slot_count: usize = {len(registry.enable_slots)};",
        (
            "pub const memory_id_to_big_enable_slot_count: usize = "
            f"{registry.memory_id_to_big_slots};"
        ),
        "",
        "pub const claim_fields = [_]ClaimField{",
    ]
    for field in registry.claim_fields:
        lines.append(
            "    .{ "
            f'.name = "{field.name}", .field_index = {field.field_index}, '
            f".first_enable_slot = {field.first_enable_slot}, "
            f".enable_slot_count = {field.enable_slot_count}, "
            f".log_size_shape = .{field.log_size_shape}, "
            f".fixed_log_size = {_zig_optional(field.fixed_log_size)} "
            "},"
        )
    lines.extend(["};", "", "pub const enable_slots = [_]EnableSlot{"])
    for slot in registry.enable_slots:
        lines.append(
            "    .{ "
            f'.name = "{slot.name}", .enable_slot = {slot.enable_slot}, '
            f".claim_field_index = {slot.claim_field_index}, "
            f".field_slot_index = {slot.field_slot_index}, "
            f".log_size_shape = .{slot.log_size_shape}, "
            f".fixed_log_size = {_zig_optional(slot.fixed_log_size)} "
            "},"
        )
    lines.extend(["};", "", "pub const source_files = [_]SourceFile{"])
    for source in registry.source_files:
        lines.append(
            f'    .{{ .path = "{source.path}", .sha256 = "{source.sha256}" }},'
        )
    lines.extend(
        [
            "};",
            "",
            "comptime {",
            "    std.debug.assert(claim_fields.len == claim_field_count);",
            "    std.debug.assert(enable_slots.len == enable_slot_count);",
            "    var next_slot: usize = 0;",
            "    for (claim_fields, 0..) |field, field_index| {",
            "        std.debug.assert(field.field_index == field_index);",
            "        std.debug.assert(field.first_enable_slot == next_slot);",
            "        next_slot += field.enable_slot_count;",
            "    }",
            "    std.debug.assert(next_slot == enable_slot_count);",
            "    for (enable_slots, 0..) |slot, slot_index| {",
            "        std.debug.assert(slot.enable_slot == slot_index);",
            "        const field = claim_fields[slot.claim_field_index];",
            "        std.debug.assert(slot_index == field.first_enable_slot + slot.field_slot_index);",
            "        std.debug.assert(slot.field_slot_index < field.enable_slot_count);",
            "        std.debug.assert(slot.log_size_shape == field.log_size_shape);",
            "        std.debug.assert(slot.fixed_log_size == field.fixed_log_size);",
            "    }",
            "}",
            "",
            'test "claim registry cardinality and special shape" {',
            "    try std.testing.expectEqual(@as(usize, 68), claim_fields.len);",
            "    try std.testing.expectEqual(@as(usize, 83), enable_slots.len);",
            "    const memory = claim_fields[49];",
            '    try std.testing.expectEqualStrings("memory_id_to_big", memory.name);',
            "    try std.testing.expectEqual(@as(u8, 49), memory.first_enable_slot);",
            "    try std.testing.expectEqual(@as(u8, 16), memory.enable_slot_count);",
            "    try std.testing.expectEqual(LogSizeShape.special_dynamic_prefix, memory.log_size_shape);",
            "    try std.testing.expectEqual(@as(u8, 65), claim_fields[50].first_enable_slot);",
            "}",
            "",
        ]
    )
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rust-root", type=Path, default=DEFAULT_RUST_ROOT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail unless the checked-in Zig module exactly matches pinned Rust sources",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        rendered = render_zig(load_registry(args.rust_root.resolve()))
        if args.check:
            if not args.output.is_file() or args.output.read_text() != rendered:
                raise RegistryError(f"generated Cairo claim registry is stale: {args.output}")
        else:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(rendered)
    except (OSError, RegistryError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
