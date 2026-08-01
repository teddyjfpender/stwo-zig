#!/usr/bin/env python3
"""Authenticate exact Cairo-0 CSP source fixtures and their promotion state.

This check is intentionally cheap and fail-closed.  It reconstructs every
embedded input word from the authenticated RISC-V logical payload, checks the
mandatory Cairo finalizer and public-output projection, and refuses to call a
source-only fixture runnable.  Compilation, VM adaptation, proving, and
verification are separate promotion stages and are never hidden in validation.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import re
import struct
import sys
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PROVENANCE = ROOT / "vectors/cairo/csp/fixture-provenance-v1.json"
COMPARISON_MANIFEST = "vectors/cairo/csp/comparison-manifest-v1.json"
SCHEMA = "stwo_cairo_csp_fixture_provenance_v1"
STATUSES = (
    "source_ready_compilation_pending",
    "compiled_ready_derivation_pending",
    "exact_runnable",
)
EXACT_RUNNABLE_SCHEMA_ERROR = (
    "exact_runnable requires a schema upgrade that cryptographically links "
    "the proof, verifier-accepted public statement, program, ProverInput, "
    "canonical output, secure protocol, and independent verifier authority"
)
HEX_32 = re.compile(r"[0-9a-f]{64}\Z")
HEX_20 = re.compile(r"[0-9a-f]{40}\Z")
EMBEDDED_WORD = re.compile(
    r"^    assert input\[(?P<index>[0-9]+)\] = 0x(?P<word>[0-9a-f]+);$",
    re.MULTILINE,
)


class FixtureError(ValueError):
    """A fixture source, pin, or promotion claim is invalid."""


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise FixtureError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_strict_object
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise FixtureError(f"cannot read JSON {path}: {error}") from error
    if not isinstance(value, dict):
        raise FixtureError(f"{path} must contain one JSON object")
    return value


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as error:
        raise FixtureError(f"cannot hash {path}: {error}") from error
    return digest.hexdigest()


def _object(value: Any, context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise FixtureError(f"{context} must be an object")
    return value


def _keys(value: Mapping[str, Any], expected: Sequence[str], context: str) -> None:
    actual = set(value)
    wanted = set(expected)
    if actual != wanted:
        raise FixtureError(
            f"{context} keys drifted "
            f"(missing={sorted(wanted - actual)}, extra={sorted(actual - wanted)})"
        )


def _text(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise FixtureError(f"{context} must be a nonempty string")
    return value


def _integer(value: Any, context: str, *, positive: bool = False) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise FixtureError(f"{context} must be an integer")
    if positive and value <= 0:
        raise FixtureError(f"{context} must be positive")
    return value


def _sha256(value: Any, context: str) -> str:
    value = _text(value, context)
    if HEX_32.fullmatch(value) is None:
        raise FixtureError(f"{context} must be lowercase 32-byte hex")
    return value


def _commit(value: Any, context: str) -> str:
    value = _text(value, context)
    if HEX_20.fullmatch(value) is None:
        raise FixtureError(f"{context} must be lowercase 20-byte git hex")
    return value


def _repo_path(root: Path, value: Any, context: str) -> Path:
    value = _text(value, context)
    posix = PurePosixPath(value)
    if posix.is_absolute() or "." in posix.parts or ".." in posix.parts:
        raise FixtureError(f"{context} must be a normalized repository path")
    path = (root / Path(*posix.parts)).resolve()
    try:
        path.relative_to(root.resolve())
    except ValueError as error:
        raise FixtureError(f"{context} escapes the repository") from error
    return path


def _artifact(
    root: Path, value: Any, context: str, *, gzip_program: bool = False
) -> Path:
    descriptor = _object(value, context)
    expected_keys = ["path", "bytes", "sha256"]
    if gzip_program:
        expected_keys += ["decompressed_bytes", "decompressed_sha256"]
    _keys(descriptor, expected_keys, context)
    path = _repo_path(root, descriptor.get("path"), f"{context}.path")
    expected_bytes = _integer(
        descriptor.get("bytes"), f"{context}.bytes", positive=True
    )
    try:
        actual_bytes = path.stat().st_size
    except OSError as error:
        raise FixtureError(f"cannot stat {path}: {error}") from error
    if actual_bytes != expected_bytes:
        raise FixtureError(
            f"{context} byte length mismatch: expected {expected_bytes}, got {actual_bytes}"
        )
    expected_sha = _sha256(descriptor.get("sha256"), f"{context}.sha256")
    actual_sha = sha256_file(path)
    if actual_sha != expected_sha:
        raise FixtureError(
            f"{context} digest mismatch: expected {expected_sha}, got {actual_sha}"
        )
    if gzip_program:
        try:
            decompressed = gzip.decompress(path.read_bytes())
        except (OSError, EOFError, gzip.BadGzipFile) as error:
            raise FixtureError(f"cannot decompress {path}: {error}") from error
        decompressed_bytes = _integer(
            descriptor.get("decompressed_bytes"),
            f"{context}.decompressed_bytes",
            positive=True,
        )
        if len(decompressed) != decompressed_bytes:
            raise FixtureError(f"{context} decompressed byte length drifted")
        decompressed_sha = _sha256(
            descriptor.get("decompressed_sha256"),
            f"{context}.decompressed_sha256",
        )
        if hashlib.sha256(decompressed).hexdigest() != decompressed_sha:
            raise FixtureError(f"{context} decompressed digest drifted")
    return path


def _validate_logical_input(root: Path, value: Any) -> bytes:
    logical = _object(value, "logical_input")
    _keys(
        logical,
        (
            "container_path",
            "container_sha256",
            "container_bytes",
            "container_encoding",
            "payload_offset",
            "payload_bytes",
            "payload_encoding",
            "payload_sha256",
        ),
        "logical_input",
    )
    descriptor = {
        "path": logical.get("container_path"),
        "bytes": logical.get("container_bytes"),
        "sha256": logical.get("container_sha256"),
    }
    path = _artifact(root, descriptor, "logical_input.container")
    if logical.get("container_encoding") != "u32_le_byte_length_then_message":
        raise FixtureError("logical input container encoding drifted")
    if logical.get("payload_encoding") != "raw_bytes":
        raise FixtureError("logical input payload encoding drifted")
    if logical.get("payload_offset") != 4 or logical.get("payload_bytes") != 2048:
        raise FixtureError("logical input payload extent drifted")
    encoded = path.read_bytes()
    if len(encoded) != 2052 or struct.unpack_from("<I", encoded)[0] != 2048:
        raise FixtureError("logical input length prefix drifted")
    payload = encoded[4:]
    if hashlib.sha256(payload).hexdigest() != _sha256(
        logical.get("payload_sha256"), "logical_input.payload_sha256"
    ):
        raise FixtureError("logical input payload digest drifted")
    return payload


def _validate_source_authority(root: Path, value: Any, compiler: Mapping[str, Any]) -> None:
    authority = _object(value, "source_authority")
    _keys(
        authority,
        (
            "pr171_provenance",
            "repository",
            "commit",
            "program_root",
            "base_programs",
            "cairo_common_keccak",
        ),
        "source_authority",
    )
    pr171 = _object(authority.get("pr171_provenance"), "source_authority.pr171")
    _keys(pr171, ("path", "sha256", "schema"), "source_authority.pr171")
    corpus_path = _artifact(
        root,
        {
            "path": pr171.get("path"),
            "bytes": (root / str(pr171.get("path"))).stat().st_size,
            "sha256": pr171.get("sha256"),
        },
        "source_authority.pr171",
    )
    corpus = load_json(corpus_path)
    if corpus.get("schema") != pr171.get("schema"):
        raise FixtureError("PR171 provenance schema drifted")
    upstream = _object(corpus.get("source_repository"), "PR171 source_repository")
    if (
        authority.get("repository") != upstream.get("url")
        or authority.get("commit") != upstream.get("commit")
        or authority.get("program_root") != upstream.get("program_root")
    ):
        raise FixtureError("exact fixture upstream authority drifted from PR171")
    _commit(authority.get("commit"), "source_authority.commit")
    base_programs = _object(authority.get("base_programs"), "base_programs")
    if set(base_programs) != {"sha2", "sha3"}:
        raise FixtureError("base-program inventory drifted")
    corpus_programs = _object(corpus.get("programs"), "PR171 programs")
    for name, finalizer in (("sha2", "finalize_sha256"), ("sha3", "finalize_keccak")):
        base = _object(base_programs.get(name), f"base_programs.{name}")
        _keys(
            base,
            ("source_relative", "source_sha256", "required_finalizer"),
            f"base_programs.{name}",
        )
        original = _object(corpus_programs.get(name), f"PR171 programs.{name}")
        if base.get("source_relative") != original.get("source_relative"):
            raise FixtureError(f"{name} base path drifted")
        if base.get("source_sha256") != original.get("source_sha256"):
            raise FixtureError(f"{name} base digest drifted")
        _sha256(base.get("source_sha256"), f"base_programs.{name}.source_sha256")
        if base.get("required_finalizer") != finalizer:
            raise FixtureError(f"{name} mandatory finalizer drifted")
    corpus_compiler = _object(corpus.get("compiler"), "PR171 compiler")
    for key in ("executable", "version", "profile", "arguments"):
        if compiler.get(key) != corpus_compiler.get(key):
            raise FixtureError(f"compiler {key} drifted from PR171")
    common = _object(authority.get("cairo_common_keccak"), "cairo_common_keccak")
    _keys(
        common,
        ("repository", "commit", "path", "bytes", "sha256"),
        "cairo_common_keccak",
    )
    _text(common.get("repository"), "cairo_common_keccak.repository")
    _commit(common.get("commit"), "cairo_common_keccak.commit")
    _text(common.get("path"), "cairo_common_keccak.path")
    _integer(common.get("bytes"), "cairo_common_keccak.bytes", positive=True)
    _sha256(common.get("sha256"), "cairo_common_keccak.sha256")


def _expected_words(payload: bytes, word_bits: int, byteorder: str) -> list[int]:
    width = word_bits // 8
    return [
        int.from_bytes(payload[offset : offset + width], byteorder)
        for offset in range(0, len(payload), width)
    ]


def _source_words(source: str, context: str) -> list[int]:
    matches = list(EMBEDDED_WORD.finditer(source))
    indices = [int(match.group("index")) for match in matches]
    if indices != list(range(len(matches))):
        raise FixtureError(f"{context} embedded word indices are not consecutive")
    return [int(match.group("word"), 16) for match in matches]


def _validate_source_program(
    source: str,
    payload: bytes,
    *,
    word_bits: int,
    byteorder: str,
    hash_call: str,
    finalizer: str,
    output_lines: Sequence[str],
    context: str,
) -> None:
    actual_words = _source_words(source, context)
    expected_words = _expected_words(payload, word_bits, byteorder)
    if actual_words != expected_words:
        raise FixtureError(f"{context} embedded logical input drifted")
    if "program_input" in source or "local iterations" in source:
        raise FixtureError(f"{context} reintroduced a host-input hint")
    if source.count(hash_call) != 1:
        raise FixtureError(f"{context} exact 2048-byte hash call drifted")
    calls = re.findall(rf"(?m)^    {re.escape(finalizer)}\(", source)
    if len(calls) != 1:
        raise FixtureError(f"{context} mandatory finalizer call drifted")
    for line in output_lines:
        if source.count(line) != 1:
            raise FixtureError(f"{context} public output projection drifted: {line}")


def _decimal_felts(value: Any, context: str) -> list[int]:
    if not isinstance(value, list) or not value:
        raise FixtureError(f"{context} must be a nonempty list")
    result: list[int] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item.isdecimal():
            raise FixtureError(f"{context}[{index}] must be an unsigned decimal string")
        result.append(int(item))
    return result


def _validate_fixture(
    root: Path,
    name: str,
    raw: Any,
    payload: bytes,
    comparison_rows: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    context = f"fixtures.{name}"
    fixture = _object(raw, context)
    _keys(
        fixture,
        (
            "comparison_row",
            "status",
            "base_program",
            "source",
            "arguments",
            "input_embedding",
            "required_finalizer",
            "output_projection",
            "compiled_program",
            "prover_input",
            "expected_vm_steps",
            "public_statement",
            "proof",
            "verifier_receipt",
            "promotion_blockers",
        ),
        context,
    )
    if fixture.get("comparison_row") != name:
        raise FixtureError(f"{context} comparison-row identity drifted")
    status = fixture.get("status")
    if status not in STATUSES:
        raise FixtureError(f"{context} has unsupported status {status!r}")
    source_path = _artifact(root, fixture.get("source"), f"{context}.source")
    arguments_path = _artifact(root, fixture.get("arguments"), f"{context}.arguments")
    if load_json(arguments_path) != {}:
        raise FixtureError(f"{context} exact embedded-input program must take no arguments")
    try:
        source = source_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise FixtureError(f"cannot read {source_path}: {error}") from error

    embedding = _object(fixture.get("input_embedding"), f"{context}.input_embedding")
    _keys(
        embedding,
        ("encoding", "word_bits", "word_count", "n_bytes", "host_input_hints"),
        f"{context}.input_embedding",
    )
    projection = _object(fixture.get("output_projection"), f"{context}.output_projection")
    _keys(
        projection,
        (
            "output_builtin_felts",
            "felt_decimal",
            "projection",
            "canonical_encoding",
            "canonical_hex",
        ),
        f"{context}.output_projection",
    )
    row = comparison_rows.get(name)
    if row is None:
        raise FixtureError(f"{context} has no comparison-contract row")
    expected_output = _object(row.get("expected_output"), f"comparison row {name}.output")
    if projection.get("canonical_hex") != expected_output.get("hex"):
        raise FixtureError(f"{context} canonical output drifted from comparison contract")
    if projection.get("projection") != expected_output.get("cairo_projection"):
        raise FixtureError(f"{context} output projection drifted from comparison contract")
    raw_output = bytes.fromhex(_sha256(projection.get("canonical_hex"), f"{context}.output"))
    felt_values = _decimal_felts(projection.get("felt_decimal"), f"{context}.felt_decimal")

    if name == "sha256_2048_bytes":
        if fixture.get("base_program") != "sha2" or fixture.get("required_finalizer") != "finalize_sha256":
            raise FixtureError(f"{context} constrained SHA base/finalizer drifted")
        if embedding != {
            "encoding": "512_consecutive_u32_big_endian_words",
            "word_bits": 32,
            "word_count": 512,
            "n_bytes": 2048,
            "host_input_hints": False,
        }:
            raise FixtureError(f"{context} input embedding contract drifted")
        expected_felts = list(struct.unpack(">8I", raw_output))
        output_lines = [
            f"    assert [output_ptr{'' if index == 0 else f' + {index}'}] = hash[{index}];"
            for index in range(8)
        ] + ["    let output_ptr = output_ptr + 8;"]
        _validate_source_program(
            source,
            payload,
            word_bits=32,
            byteorder="big",
            hash_call="let (hash) = sha256{sha256_ptr=sha256_ptr}(inputs, 2048);",
            finalizer="finalize_sha256",
            output_lines=output_lines,
            context=context,
        )
    elif name == "keccak256_2048_bytes":
        if fixture.get("base_program") != "sha3" or fixture.get("required_finalizer") != "finalize_keccak":
            raise FixtureError(f"{context} constrained Keccak base/finalizer drifted")
        if embedding != {
            "encoding": "256_consecutive_u64_little_endian_words",
            "word_bits": 64,
            "word_count": 256,
            "n_bytes": 2048,
            "host_input_hints": False,
        }:
            raise FixtureError(f"{context} input embedding contract drifted")
        expected_felts = [
            int.from_bytes(raw_output[:16], "little"),
            int.from_bytes(raw_output[16:], "little"),
        ]
        _validate_source_program(
            source,
            payload,
            word_bits=64,
            byteorder="little",
            hash_call=(
                "let res = cairo_keccak{keccak_ptr=hash_ptr}"
                "(inputs=inputs, n_bytes=2048);"
            ),
            finalizer="finalize_keccak",
            output_lines=(
                "    assert [output_ptr] = res.low;",
                "    assert [output_ptr + 1] = res.high;",
                "    let output_ptr = output_ptr + 2;",
            ),
            context=context,
        )
    else:
        raise FixtureError(f"unexpected exact fixture {name}")
    if felt_values != expected_felts:
        raise FixtureError(f"{context} declared output felts do not reconstruct digest")
    if projection.get("output_builtin_felts") != len(expected_felts):
        raise FixtureError(f"{context} output builtin length drifted")
    if projection.get("canonical_encoding") != "raw_32_bytes":
        raise FixtureError(f"{context} canonical output encoding drifted")

    artifacts = (
        "compiled_program",
        "prover_input",
        "public_statement",
        "proof",
        "verifier_receipt",
    )
    blockers = fixture.get("promotion_blockers")
    if not isinstance(blockers, list) or any(
        not isinstance(item, str) or not item for item in blockers
    ):
        raise FixtureError(f"{context} promotion blockers must be explicit strings")
    if status == "source_ready_compilation_pending":
        if any(fixture.get(key) is not None for key in artifacts):
            raise FixtureError(f"{context} source-ready row carries later-stage artifacts")
        if fixture.get("expected_vm_steps") is not None or len(blockers) < 2:
            raise FixtureError(f"{context} source-ready promotion state is incomplete")
    elif status == "compiled_ready_derivation_pending":
        _artifact(
            root,
            fixture.get("compiled_program"),
            f"{context}.compiled_program",
            gzip_program=True,
        )
        if any(fixture.get(key) is not None for key in artifacts[1:]):
            raise FixtureError(f"{context} compiled-ready row carries unverified artifacts")
        if fixture.get("expected_vm_steps") is not None or not blockers:
            raise FixtureError(f"{context} compiled-ready promotion state is incomplete")
    else:
        # The current official verifier verdict binds a proof digest, channel,
        # transport, and pinned revisions, but not the verifier-accepted public
        # statement.  Consequently v1 cannot prove that separately pinned
        # program, ProverInput, output, protocol, proof, and receipt files all
        # describe the same statement.  Reject every promotion until a new
        # schema supplies and validates those cryptographic cross-links.
        raise FixtureError(f"{context}: {EXACT_RUNNABLE_SCHEMA_ERROR}")
    return {
        "id": name,
        "status": status,
        "source": str(source_path.relative_to(root)),
        "embedded_words": len(_source_words(source, context)),
        "output_felts": len(expected_felts),
    }


def validate_provenance(
    provenance: Mapping[str, Any], *, root: Path = ROOT
) -> dict[str, Any]:
    root = root.resolve()
    _keys(
        provenance,
        (
            "schema",
            "note",
            "allowed_statuses",
            "logical_input",
            "source_authority",
            "compiler",
            "adapter",
            "derived_output_directory",
            "fixtures",
        ),
        "fixture provenance",
    )
    if provenance.get("schema") != SCHEMA:
        raise FixtureError(f"unsupported fixture schema {provenance.get('schema')!r}")
    _text(provenance.get("note"), "fixture provenance.note")
    if provenance.get("allowed_statuses") != list(STATUSES):
        raise FixtureError("fixture status vocabulary drifted")
    payload = _validate_logical_input(root, provenance.get("logical_input"))

    compiler = _object(provenance.get("compiler"), "compiler")
    _keys(
        compiler,
        ("executable", "version", "profile", "arguments", "distribution"),
        "compiler",
    )
    if compiler.get("executable") != "cairo-compile" or compiler.get("version") != "0.14.0.1":
        raise FixtureError("exact Cairo-0 compiler identity drifted")
    if compiler.get("profile") != "proof_mode" or compiler.get("arguments") != ["--proof_mode"]:
        raise FixtureError("exact Cairo proof-mode arguments drifted")
    distribution = _object(compiler.get("distribution"), "compiler.distribution")
    _keys(
        distribution,
        ("name", "version", "filename", "bytes", "sha256"),
        "compiler.distribution",
    )
    if distribution.get("name") != "cairo-lang" or distribution.get("version") != "0.14.0.1":
        raise FixtureError("compiler distribution identity drifted")
    _text(distribution.get("filename"), "compiler.distribution.filename")
    _integer(distribution.get("bytes"), "compiler.distribution.bytes", positive=True)
    _sha256(distribution.get("sha256"), "compiler.distribution.sha256")
    _validate_source_authority(root, provenance.get("source_authority"), compiler)

    adapter = _object(provenance.get("adapter"), "adapter")
    _keys(
        adapter,
        (
            "executable",
            "program_type",
            "layout",
            "proof_mode",
            "stwo_cairo_revision",
            "stwo_revision",
        ),
        "adapter",
    )
    expected_adapter = {
        "executable": "stwo-cairo-vm-adapter",
        "program_type": "json",
        "layout": "all_cairo_stwo",
        "proof_mode": True,
        "stwo_cairo_revision": "82f21252a68ec006d73e299f5bf1ce6d4db0ee78",
        "stwo_revision": "7b211edde786775016ef3eecb837a6240d8fe792",
    }
    if adapter != expected_adapter:
        raise FixtureError("pinned Cairo VM adapter identity drifted")
    _repo_path(
        root,
        provenance.get("derived_output_directory"),
        "derived_output_directory",
    )

    comparison = load_json(root / COMPARISON_MANIFEST)
    comparison_rows = {
        row.get("id"): row
        for row in comparison.get("rows", [])
        if isinstance(row, dict) and isinstance(row.get("id"), str)
    }
    fixtures = _object(provenance.get("fixtures"), "fixtures")
    expected_names = {"sha256_2048_bytes", "keccak256_2048_bytes"}
    if set(fixtures) != expected_names:
        raise FixtureError("exact hash fixture inventory drifted")
    rows = [
        _validate_fixture(root, name, fixtures[name], payload, comparison_rows)
        for name in sorted(fixtures)
    ]
    return {
        "schema": SCHEMA,
        "fixtures": rows,
        "source_ready": sum(
            row["status"] == "source_ready_compilation_pending" for row in rows
        ),
        "compiled_ready": sum(
            row["status"] == "compiled_ready_derivation_pending" for row in rows
        ),
        "exact_runnable": sum(row["status"] == "exact_runnable" for row in rows),
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--provenance", type=Path, default=DEFAULT_PROVENANCE)
    parser.add_argument("--json", action="store_true", help="emit the plan as JSON")
    parser.add_argument(
        "--require-runnable",
        action="store_true",
        help="fail unless at least one proof-and-verifier-backed fixture is runnable",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        plan = validate_provenance(load_json(args.provenance), root=args.root)
        if args.require_runnable and plan["exact_runnable"] == 0:
            raise FixtureError(
                "no exact_runnable Cairo CSP fixtures; source readiness is not proof readiness"
            )
    except FixtureError as error:
        print(f"cairo-csp-fixtures: {error}", file=sys.stderr)
        return 2
    if args.json:
        json.dump(plan, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    else:
        print(
            "Cairo CSP fixtures: "
            f"{plan['source_ready']} source-ready, "
            f"{plan['compiled_ready']} compiled-ready, "
            f"{plan['exact_runnable']} exact runnable"
        )
        for row in plan["fixtures"]:
            print(
                f"  {row['id']}: {row['status']} "
                f"({row['embedded_words']} words, {row['output_felts']} output felts)"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
