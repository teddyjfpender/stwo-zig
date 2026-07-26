"""Deterministic fixture inventory for the staged RISC-V benchmark matrix."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from scripts.riscv_release_oracle_lib.public_values import PINNED_ORACLE


ROOT = Path(__file__).resolve().parents[1]
TRACE_MANIFEST_REL = "vectors/riscv_elfs/trace_vectors.json"
CRYPTO_PROVENANCE_REL = "vectors/riscv_elfs/crypto/provenance.json"
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
FULL_COUNTS = {"proof": 23, "execution": 10}
SUPPORTED = "supported"
PINNED_LEGACY_LAYOUT = "d478f783055aa0d73a93768a433a3c6c31c91d1c"


class MatrixModelError(ValueError):
    pass


@dataclass(frozen=True)
class Workload:
    row_id: str
    suite: str
    row_class: str
    elf_rel: str
    elf_sha256: str
    input_rel: str | None
    input_sha256: str
    fixture: dict[str, Any]
    max_steps: int = 8_000_000


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_sha256(value: object) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise MatrixModelError(f"duplicate JSON field {key!r}")
        value[key] = item
    return value


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_bytes(), object_pairs_hook=_strict_object)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise MatrixModelError(f"{label} is not valid UTF-8 JSON: {error}") from error
    if not isinstance(value, dict):
        raise MatrixModelError(f"{label} root must be an object")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise MatrixModelError(f"{label} is not a lowercase SHA-256")
    return value


def _regular_fixture(root: Path, relative: str, expected: str, label: str) -> Path:
    raw_path = Path(relative)
    if raw_path.is_absolute():
        raise MatrixModelError(f"{label} path must be repository-relative")
    candidate = root / raw_path
    if candidate.is_symlink():
        raise MatrixModelError(f"{label} is symlinked: {relative}")
    path = candidate.resolve()
    try:
        path.relative_to(root.resolve())
    except ValueError as error:
        raise MatrixModelError(f"{label} path escapes the repository") from error
    if path.is_symlink() or not path.is_file():
        raise MatrixModelError(f"{label} is missing or non-regular: {relative}")
    actual = sha256_file(path)
    if actual != _digest(expected, f"{label} digest"):
        raise MatrixModelError(f"{label} digest mismatch: {relative}")
    return path


def _corpus_workloads(root: Path, manifest: dict[str, Any]) -> list[Workload]:
    authorities = manifest.get("authorities")
    sail = authorities.get("sail") if isinstance(authorities, dict) else None
    if not isinstance(sail, dict) or sail.get("revision") != PINNED_ORACLE:
        raise MatrixModelError("trace manifest pins a different Sail revision")
    vectors = manifest.get("vectors")
    if not isinstance(vectors, list) or not vectors:
        raise MatrixModelError("trace manifest has no vectors")
    workloads: list[Workload] = []
    names: set[str] = set()
    for index, vector in enumerate(vectors):
        if not isinstance(vector, dict):
            raise MatrixModelError(f"trace vector {index} is not an object")
        required = {
            "name", "elf", "elf_sha256", "trace_sha256", "total_steps",
            "final_pc", "executed_opcode_ids", "proof_admission",
        }
        if set(vector) != required:
            raise MatrixModelError(f"trace vector {index} fields drifted")
        name = vector["name"]
        if not isinstance(name, str) or not name or name in names:
            raise MatrixModelError(f"trace vector {index} has an invalid/duplicate name")
        names.add(name)
        elf_rel = vector["elf"]
        if not isinstance(elf_rel, str):
            raise MatrixModelError(f"{name}: ELF path is invalid")
        _regular_fixture(root, elf_rel, vector["elf_sha256"], f"{name} ELF")
        _digest(vector["trace_sha256"], f"{name} trace")
        if type(vector["total_steps"]) is not int or vector["total_steps"] <= 0:
            raise MatrixModelError(f"{name}: invalid total_steps")
        if type(vector["final_pc"]) is not int or not 0 <= vector["final_pc"] <= 0xFFFFFFFF:
            raise MatrixModelError(f"{name}: invalid final_pc")
        opcodes = vector["executed_opcode_ids"]
        if not isinstance(opcodes, list) or not opcodes or any(type(item) is not int for item in opcodes):
            raise MatrixModelError(f"{name}: invalid executed_opcode_ids")
        admission = vector["proof_admission"]
        if not isinstance(admission, dict) or not isinstance(admission.get("status"), str):
            raise MatrixModelError(f"{name}: invalid proof admission")
        status = admission["status"]
        if status != SUPPORTED:
            raise MatrixModelError(f"{name}: unknown proof admission {status!r}")
        if set(admission) != {"status"}:
            raise MatrixModelError(f"{name}: supported admission fields drifted")
        row_class = "proof"
        fixture = {
            "manifest": TRACE_MANIFEST_REL,
            "name": name,
            "elf": elf_rel,
            "elf_sha256": vector["elf_sha256"],
            "input": None,
            "input_sha256": EMPTY_SHA256,
            "trace_sha256": vector["trace_sha256"],
            "expected_total_steps": vector["total_steps"],
            "expected_final_pc": vector["final_pc"],
            "executed_opcode_ids": opcodes,
            "proof_admission": admission,
        }
        workloads.append(Workload(
            row_id=f"corpus:{name}",
            suite="corpus",
            row_class=row_class,
            elf_rel=elf_rel,
            elf_sha256=vector["elf_sha256"],
            input_rel=None,
            input_sha256=EMPTY_SHA256,
            fixture=fixture,
        ))
    return workloads


def _crypto_inputs(
    guest: str, spec: dict[str, Any], provenance: dict[str, Any],
) -> list[tuple[str, str | None]]:
    kind = spec.get("kind")
    if kind == "input_sweep":
        sizes = provenance.get("byte_input_sizes")
        if not isinstance(sizes, list) or any(type(size) is not int or size <= 0 for size in sizes):
            raise MatrixModelError("crypto byte_input_sizes are invalid")
        return [(f"{size}B", f"vectors/riscv_elfs/crypto/inputs/msg_{size}.bin") for size in sizes]
    if kind == "field_sweep":
        widths = provenance.get("poseidon_field_widths")
        if not isinstance(widths, list) or any(type(width) is not int or width <= 0 for width in widths):
            raise MatrixModelError("crypto poseidon_field_widths are invalid")
        return [(f"{width}fe", f"vectors/riscv_elfs/crypto/inputs/field_{width}.bin") for width in widths]
    if kind == "fixed":
        return [("fixed", None)]
    raise MatrixModelError(f"{guest}: unknown crypto input kind {kind!r}")


def _crypto_class(spec: dict[str, Any], label: str) -> str:
    evaluation = spec.get("eval")
    if evaluation == "provable":
        return "proof"
    if evaluation == "provable_single_block_only":
        return "proof" if label == "128B" else "execution"
    if evaluation == "execution_only":
        return "execution"
    raise MatrixModelError(f"unknown crypto evaluation {evaluation!r}")


def _crypto_workloads(root: Path, provenance: dict[str, Any]) -> list[Workload]:
    if provenance.get("schema") != "riscv_crypto_guests_v1":
        raise MatrixModelError("crypto provenance schema drifted")
    # These guest binaries still record the Stark-V checkout used to build the
    # legacy benchmark assets.  It is provenance, not the semantic authority:
    # corpus correctness is independently gated against the Sail revision above.
    if provenance.get("stark_v_commit") != PINNED_LEGACY_LAYOUT:
        raise MatrixModelError("crypto provenance pins a different legacy layout revision")
    inputs = provenance.get("input_sha256")
    guests = provenance.get("guests")
    if not isinstance(inputs, dict) or not isinstance(guests, dict) or not guests:
        raise MatrixModelError("crypto provenance has no inputs or guests")
    workloads: list[Workload] = []
    for guest in sorted(guests):
        spec = guests[guest]
        if not isinstance(spec, dict):
            raise MatrixModelError(f"{guest}: guest specification is not an object")
        elf_rel = spec.get("elf")
        elf_digest = spec.get("elf_sha256")
        if not isinstance(elf_rel, str):
            raise MatrixModelError(f"{guest}: ELF path is invalid")
        _regular_fixture(root, elf_rel, elf_digest, f"{guest} ELF")
        if spec.get("metal_backend") != "gated_riscv_adapter_is_cpu_only":
            raise MatrixModelError(f"{guest}: Metal gate identity drifted")
        for label, input_rel in _crypto_inputs(guest, spec, provenance):
            if input_rel is None:
                input_digest = EMPTY_SHA256
            else:
                input_digest = inputs.get(Path(input_rel).name)
                _regular_fixture(root, input_rel, input_digest, f"{guest} {label} input")
            row_class = _crypto_class(spec, label)
            fixture = {
                "manifest": CRYPTO_PROVENANCE_REL,
                "name": guest,
                "case": label,
                "elf": elf_rel,
                "elf_sha256": elf_digest,
                "input": input_rel,
                "input_sha256": input_digest,
                "guest_spec_sha256": canonical_sha256(spec),
                "guest_source": spec.get("source"),
                "guest_evaluation": spec.get("eval"),
                "guest_kind": spec.get("kind"),
            }
            workloads.append(Workload(
                row_id=f"crypto:{guest}:{label}",
                suite="crypto",
                row_class=row_class,
                elf_rel=elf_rel,
                elf_sha256=elf_digest,
                input_rel=input_rel,
                input_sha256=input_digest,
                fixture=fixture,
            ))
    return workloads


def load_workloads(root: Path = ROOT) -> tuple[list[Workload], dict[str, Any]]:
    trace_path = root / TRACE_MANIFEST_REL
    crypto_path = root / CRYPTO_PROVENANCE_REL
    trace = load_json(trace_path, "trace-vector manifest")
    crypto = load_json(crypto_path, "crypto provenance")
    workloads = [*_corpus_workloads(root, trace), *_crypto_workloads(root, crypto)]
    ids = [workload.row_id for workload in workloads]
    if len(ids) != len(set(ids)):
        raise MatrixModelError("matrix row IDs are not unique")
    counts = {name: sum(item.row_class == name for item in workloads) for name in FULL_COUNTS}
    if counts != FULL_COUNTS or len(workloads) != sum(FULL_COUNTS.values()):
        raise MatrixModelError(f"full matrix shape drifted: {counts}")
    identities = {
        "trace_manifest": {
            "path": TRACE_MANIFEST_REL,
            "sha256": sha256_file(trace_path),
        },
        "crypto_provenance": {
            "path": CRYPTO_PROVENANCE_REL,
            "sha256": sha256_file(crypto_path),
        },
        "row_set_sha256": canonical_sha256(ids),
    }
    return workloads, identities
