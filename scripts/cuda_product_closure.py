#!/usr/bin/env python3
"""Validate that copied CUDA artifacts have an explicit product disposition."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CUDA_ROOT = ROOT / "src/backends/cuda"
SOURCE = CUDA_ROOT / "vendor/upstream"
SOURCE_MANIFEST = CUDA_ROOT / "source_manifest.json"
PRODUCT_MANIFEST = CUDA_ROOT / "product_manifest.json"
NATIVE = CUDA_ROOT / "native"
NATIVE_AOT = CUDA_ROOT / "aot/native"
ABI = CUDA_ROOT / "abi"
RUNTIME_STAGES = CUDA_ROOT / "runtime/stages"
HOST_AUTHORITY = CUDA_ROOT / "vendor/host_authority"
ORDINARY_ROLES = (
    "resident_candidates",
    "quarantined_migration",
    "deferred_cairo",
    "deferred_features",
    "diagnostic_only",
)


class ProductClosureError(RuntimeError):
    pass


ZIG_EXTERN_RE = re.compile(r'pub\s+extern\s+"c"\s+fn\s+(stwo_[A-Za-z0-9_]+)\s*\(')
C_EXTERN_RE = re.compile(
    r'extern\s+"C"(?:(?!extern\s+"C").){0,320}?'
    r"\b(stwo_[A-Za-z0-9_]+)\s*\(",
    re.DOTALL,
)
RUST_EXTERN_RE = re.compile(r"\bpub\s+fn\s+(stwo_[A-Za-z0-9_]+)\s*\(")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def symbols(paths: list[Path], pattern: re.Pattern[str]) -> set[str]:
    found: set[str] = set()
    for path in paths:
        found.update(pattern.findall(path.read_text(encoding="utf-8", errors="strict")))
    return found


def closure_path(path: Path) -> str:
    for label, root in (("authority", SOURCE), ("native", NATIVE)):
        try:
            relative = path.relative_to(root)
        except ValueError:
            continue
        return f"{label}/{relative.as_posix()}"
    return str(path)


def validate_product_policy(
    product: dict[str, object],
    product_sources: list[Path],
    native_files: list[Path],
) -> None:
    closure_files = product_sources + native_files
    forbidden_tokens = product.get("forbidden_product_tokens")
    if not isinstance(forbidden_tokens, list) or not forbidden_tokens:
        raise ProductClosureError("forbidden CUDA product tokens are absent")

    token_hits: list[str] = []
    for path in closure_files:
        payload = path.read_text(encoding="utf-8", errors="strict")
        token_hits.extend(
            f"{closure_path(path)}:{token}"
            for token in forbidden_tokens
            if str(token) in payload
        )
    if token_hits:
        raise ProductClosureError(
            f"CUDA product closure contains forbidden API/token policy: "
            f"{sorted(token_hits)}"
        )

    abi = product.get("abi")
    if not isinstance(abi, dict):
        raise ProductClosureError("CUDA ABI policy is absent")
    forbidden_fragments = abi.get("forbidden_symbol_fragments")
    if not isinstance(forbidden_fragments, list) or not forbidden_fragments:
        raise ProductClosureError("forbidden CUDA ABI symbol policy is absent")
    bad_symbols = sorted(
        symbol
        for symbol in symbols(closure_files, C_EXTERN_RE)
        if any(str(fragment) in symbol for fragment in forbidden_fragments)
    )
    if bad_symbols:
        raise ProductClosureError(
            f"CUDA product closure exposes forbidden symbols: {bad_symbols}"
        )


def validate_resident_derivations(
    product: dict[str, object],
    authority: dict[str, object],
) -> int:
    derivations = product.get("resident_authority_derivations")
    if not isinstance(derivations, list) or not derivations:
        raise ProductClosureError("resident CUDA authority derivations are absent")
    names = [entry.get("name") for entry in derivations if isinstance(entry, dict)]
    if (
        len(names) != len(derivations)
        or any(not isinstance(name, str) or not name for name in names)
        or names != sorted(set(names))
    ):
        raise ProductClosureError(
            "resident CUDA authority derivations must be named, sorted, and unique"
        )

    authority_hashes = {
        str(entry.get("path")): str(entry.get("sha256"))
        for entry in authority.get("files", [])
        if isinstance(entry, dict)
    }
    seen_native: set[str] = set()
    for derivation in derivations:
        assert isinstance(derivation, dict)
        if set(derivation) != {"authority_files", "name", "native_files"}:
            raise ProductClosureError(
                f"resident CUDA derivation {derivation['name']} has a malformed schema"
            )
        for field, root, expected_hashes in (
            ("authority_files", SOURCE, authority_hashes),
            ("native_files", NATIVE, None),
        ):
            entries = derivation.get(field)
            if not isinstance(entries, list):
                raise ProductClosureError(
                    f"resident CUDA derivation {derivation['name']} lacks {field}"
                )
            paths = [
                entry.get("path") for entry in entries if isinstance(entry, dict)
            ]
            if (
                len(paths) != len(entries)
                or any(not isinstance(path, str) or not path for path in paths)
                or paths != sorted(set(paths))
            ):
                raise ProductClosureError(
                    f"resident CUDA derivation {derivation['name']} {field} "
                    "must be sorted and unique"
                )
            for entry in entries:
                assert isinstance(entry, dict)
                if set(entry) != {"path", "sha256"}:
                    raise ProductClosureError(
                        f"resident CUDA derivation {derivation['name']} "
                        f"{field} entry has a malformed schema"
                    )
                relative = str(entry["path"])
                expected = entry["sha256"]
                if not isinstance(expected, str) or SHA256_RE.fullmatch(expected) is None:
                    raise ProductClosureError(
                        f"resident CUDA derivation {derivation['name']} has an "
                        f"invalid hash for {relative}"
                    )
                path = root / relative
                if not path.is_file():
                    raise ProductClosureError(
                        f"resident CUDA derivation input is absent: {path}"
                    )
                if expected_hashes is not None and expected_hashes.get(relative) != expected:
                    raise ProductClosureError(
                        f"resident CUDA derivation authority hash is stale: {relative}"
                    )
                if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
                    raise ProductClosureError(
                        f"resident CUDA derivation content hash is stale: {relative}"
                    )
                if field == "native_files":
                    if relative in seen_native:
                        raise ProductClosureError(
                            f"resident CUDA derivation output is duplicated: {relative}"
                        )
                    seen_native.add(relative)
    return len(derivations)


def validate_abi(
    product: dict[str, object],
    ordinary: dict[str, object],
) -> dict[str, int]:
    policy = product.get("abi")
    if not isinstance(policy, dict):
        raise ProductClosureError("CUDA ABI policy is absent")
    raw_relative = policy.get("rust_authority")
    if not isinstance(raw_relative, str):
        raise ProductClosureError("CUDA ABI Rust authority is absent")
    raw_path = HOST_AUTHORITY / raw_relative
    if not raw_path.is_file():
        raise ProductClosureError(f"CUDA ABI Rust authority is absent: {raw_path}")

    abi_files = sorted(ABI.rglob("*.zig"))
    declared = symbols(abi_files, ZIG_EXTERN_RE)
    if not declared:
        raise ProductClosureError("resident CUDA ABI is empty")

    staged_modules = policy.get("staged_stage_modules")
    if (
        not isinstance(staged_modules, list)
        or staged_modules != sorted(set(staged_modules))
    ):
        raise ProductClosureError("staged CUDA stage modules must be sorted and unique")
    staged_paths = [ABI / "stages" / f"{name}.zig" for name in staged_modules]
    if any(not path.is_file() for path in staged_paths):
        raise ProductClosureError("staged CUDA ABI names an absent stage module")
    staged = symbols(staged_paths, ZIG_EXTERN_RE)
    active = declared - staged
    if not active:
        raise ProductClosureError("CUDA ABI must expose at least one active symbol")

    forbidden = policy.get("forbidden_symbol_fragments")
    if not isinstance(forbidden, list) or not forbidden:
        raise ProductClosureError("forbidden CUDA ABI symbol policy is absent")
    bad = sorted(
        symbol
        for symbol in declared
        if any(str(fragment) in symbol for fragment in forbidden)
    )
    if bad:
        raise ProductClosureError(f"resident CUDA ABI exposes legacy policy: {bad}")

    product_names = ordinary.get("product_sources")
    candidate_names = ordinary.get("resident_candidates")
    if not isinstance(product_names, list) or not isinstance(candidate_names, list):
        raise ProductClosureError("CUDA product and candidate source sets are absent")
    if product_names != sorted(set(product_names)) or not set(product_names).issubset(
        candidate_names
    ):
        raise ProductClosureError("CUDA product sources must be a sorted candidate subset")
    product_sources = [SOURCE / str(name) for name in product_names]
    candidate_sources = [SOURCE / str(name) for name in candidate_names]
    native = sorted(NATIVE.rglob("*.cpp")) + sorted(NATIVE.rglob("*.cu"))
    product_defined = symbols(product_sources + native, C_EXTERN_RE)
    candidate_defined = symbols(candidate_sources, C_EXTERN_RE)

    generated = policy.get("generated_symbols")
    zig_owned = policy.get("zig_owned_symbols")
    if (
        not isinstance(generated, list)
        or generated != sorted(set(generated))
        or not isinstance(zig_owned, list)
        or zig_owned != sorted(set(zig_owned))
    ):
        raise ProductClosureError(
            "generated and Zig-owned ABI symbols must be sorted unique arrays"
        )
    generated_symbols = {str(name) for name in generated}
    zig_owned_symbols = {str(name) for name in zig_owned}
    product_defined.update(generated_symbols)

    missing_definitions = sorted(active - product_defined)
    if missing_definitions:
        raise ProductClosureError(
            f"resident CUDA ABI has no selected implementation: {missing_definitions}"
        )

    missing_staged_definitions = sorted(staged - candidate_defined)
    if missing_staged_definitions:
        raise ProductClosureError(
            "staged CUDA ABI has no migration-candidate implementation: "
            f"{missing_staged_definitions}"
        )

    rust_symbols = symbols([raw_path], RUST_EXTERN_RE)
    missing_authority = sorted(active - rust_symbols - zig_owned_symbols - generated_symbols)
    if missing_authority:
        raise ProductClosureError(
            f"resident CUDA ABI is absent from pinned Rust declarations: {missing_authority}"
        )
    missing_staged_authority = sorted(staged - rust_symbols)
    if missing_staged_authority:
        raise ProductClosureError(
            f"staged CUDA ABI is absent from pinned Rust declarations: "
            f"{missing_staged_authority}"
        )
    stage_symbols = symbols(sorted((ABI / "stages").glob("*.zig")), ZIG_EXTERN_RE)
    wrapper_payload = "\n".join(
        path.read_text(encoding="utf-8", errors="strict")
        for path in sorted(RUNTIME_STAGES.rglob("*.zig"))
    )
    missing_wrappers = sorted(
        symbol for symbol in stage_symbols if symbol not in wrapper_payload
    )
    if missing_wrappers:
        raise ProductClosureError(
            f"resident CUDA stage ABI has no checked Zig wrapper: {missing_wrappers}"
        )
    unexpected_owned = sorted(zig_owned_symbols - product_defined)
    if unexpected_owned:
        raise ProductClosureError(
            f"Zig-owned CUDA ABI has no native definition: {unexpected_owned}"
        )
    return {
        "active_symbols": len(active),
        "staged_symbols": len(staged),
        "rust_authority_symbols": len(active & rust_symbols),
        "zig_owned_symbols": len(active & zig_owned_symbols),
        "generated_symbols": len(active & generated_symbols),
        "wrapped_stage_symbols": len(stage_symbols),
    }


def read_json(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ProductClosureError(f"cannot decode {path}: {error}") from error


def validate() -> dict[str, object]:
    authority = read_json(SOURCE_MANIFEST)
    product = read_json(PRODUCT_MANIFEST)
    if not isinstance(authority, dict) or not isinstance(product, dict):
        raise ProductClosureError("CUDA manifests must be JSON objects")
    if product.get("schema") != "stwo-zig-cuda-product-closure-v1":
        raise ProductClosureError("unsupported CUDA product-closure schema")
    if product.get("source_authority_sha256") != authority.get("closure_sha256"):
        raise ProductClosureError("product closure is not pinned to the source authority")

    expected = {
        str(entry["path"])
        for entry in authority.get("files", [])
        if str(entry["path"]).endswith((".cu", ".cpp"))
        and "generated/" not in str(entry["path"])
    }
    ordinary = product.get("ordinary")
    if not isinstance(ordinary, dict):
        raise ProductClosureError("ordinary CUDA disposition is absent")
    classified: dict[str, str] = {}
    for role in ORDINARY_ROLES:
        paths = ordinary.get(role)
        if not isinstance(paths, list) or paths != sorted(paths):
            raise ProductClosureError(f"CUDA role {role} must be a sorted array")
        for raw in paths:
            path = str(raw)
            if path in classified:
                raise ProductClosureError(
                    f"CUDA source {path} has both {classified[path]} and {role} roles"
                )
            classified[path] = role
    actual = set(classified)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise ProductClosureError(
            f"CUDA source classification mismatch: missing={missing}, extra={extra}"
        )

    generated = product.get("generated_aot")
    if not isinstance(generated, dict):
        raise ProductClosureError("generated AOT disposition is absent")
    copied_aot = read_json(SOURCE / "generated/aot_manifest.json")
    if not isinstance(copied_aot, list) or len(copied_aot) != generated.get(
        "copied_entry_count"
    ):
        raise ProductClosureError("copied AOT disposition count is stale")
    if generated.get("copied_disposition") != "cairo_reference_only":
        raise ProductClosureError("copied Cairo AOT sources cannot enter the Native product")
    native_aot = read_json(NATIVE_AOT / "aot_manifest.json")
    if not isinstance(native_aot, list) or len(native_aot) != generated.get(
        "native_entry_count"
    ):
        raise ProductClosureError("Native AOT disposition count is stale")
    native_labels = {str(entry.get("label", "")) for entry in native_aot}
    if not native_labels or any("cairo" in label for label in native_labels):
        raise ProductClosureError("Native AOT manifest contains a foreign frontend")
    cairo_eval_aot = read_json(
        NATIVE_AOT / "cairo_eval/aot_manifest.json"
    )
    if not isinstance(cairo_eval_aot, list) or len(
        cairo_eval_aot
    ) != generated.get("cairo_eval_entry_count"):
        raise ProductClosureError("Cairo eval AOT disposition count is stale")
    cairo_eval_occurrences = sum(
        len(entry.get("occurrences", []))
        for entry in cairo_eval_aot
        if isinstance(entry, dict)
    )
    if cairo_eval_occurrences != generated.get(
        "cairo_eval_occurrence_count"
    ):
        raise ProductClosureError("Cairo eval AOT placement count is stale")
    if any(
        entry.get("abi_schema") != "cairo_eval_part_v1"
        or entry.get("module_globals") != "none"
        or not str(entry.get("label", "")).startswith("cairo_eval_")
        for entry in cairo_eval_aot
        if isinstance(entry, dict)
    ):
        raise ProductClosureError("Cairo eval AOT product identity is invalid")

    product_names = ordinary.get("product_sources")
    if not isinstance(product_names, list):
        raise ProductClosureError("CUDA product source set is absent")
    product_sources = [SOURCE / str(name) for name in product_names]
    native_files = sorted(path for path in NATIVE.rglob("*") if path.is_file())
    validate_product_policy(product, product_sources, native_files)
    derivation_count = validate_resident_derivations(product, authority)

    abi = validate_abi(product, ordinary)

    digest = hashlib.sha256()
    for path in native_files:
        relative = path.relative_to(NATIVE).as_posix().encode("utf-8")
        payload = path.read_bytes()
        digest.update(len(relative).to_bytes(8, "little"))
        digest.update(relative)
        digest.update(len(payload).to_bytes(8, "little"))
        digest.update(payload)
    return {
        "classified_ordinary_sources": len(classified),
        "product_sources": len(ordinary["product_sources"]),
        "resident_candidates": len(ordinary["resident_candidates"]),
        "quarantined_or_deferred": len(classified)
        - len(ordinary["resident_candidates"]),
        "copied_aot_reference_entries": len(copied_aot),
        "native_aot_entries": len(native_aot),
        "cairo_eval_aot_entries": len(cairo_eval_aot),
        "cairo_eval_occurrences": cairo_eval_occurrences,
        "resident_authority_derivations": derivation_count,
        "native_runtime_sha256": digest.hexdigest(),
        **abi,
    }


def main() -> int:
    result = validate()
    print(
        "CUDA product closure verified: "
        f"{result['classified_ordinary_sources']} ordinary sources classified, "
        f"{result['product_sources']} authority sources admitted, "
        f"{result['resident_candidates']} resident candidates, "
        f"{result['quarantined_or_deferred']} quarantined/deferred, "
        f"{result['copied_aot_reference_entries']} copied AOT entries excluded, "
        f"{result['native_aot_entries']} Native AOT entry admitted, "
        f"{result['cairo_eval_aot_entries']} Cairo eval bodies covering "
        f"{result['cairo_eval_occurrences']} placements admitted, "
        f"{result['resident_authority_derivations']} resident derivation verified, "
        f"{result['active_symbols']} active and "
        f"{result['staged_symbols']} staged ABI symbols verified"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ProductClosureError as error:
        raise SystemExit(f"CUDA product closure rejected: {error}") from error
