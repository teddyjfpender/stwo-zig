"""Canonical RISC-V witness and ordered-access boundary comparisons."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

try:
    from riscv_trace_vectors_lib import admission as admission_policy
except ModuleNotFoundError:  # Imported as scripts.riscv_release_oracle_lib in tests.
    from scripts.riscv_trace_vectors_lib import admission as admission_policy

try:
    from riscv_release_oracle_lib import superseded_air
except ModuleNotFoundError:  # Imported as scripts.riscv_release_oracle_lib in tests.
    from scripts.riscv_release_oracle_lib import superseded_air


WITNESS_ROW_LINEAGE = "family set and per-family column count and column names"


def load_trace_vectors(root: Path, pinned: str, receipt: dict) -> dict:
    """Load and content-verify the corpus manifest, binding it to both authorities.

    ``pinned`` is the Sail semantic authority. The manifest also carries the
    legacy Stark-V layout revision, which must declare itself non-authoritative
    for semantics: Stark-V is a layout-lineage reference, not an ISA or AIR
    oracle. ``scripts/check_upstream_pins.py`` owns the exact legacy revision, so
    this check requires the declaration rather than duplicating the commit here.
    """
    manifest_path = root / "vectors" / "riscv_elfs" / "trace_vectors.json"
    manifest_bytes = manifest_path.read_bytes()
    vectors = json.loads(manifest_bytes)
    if not isinstance(vectors, dict):
        raise SystemExit("trace vector manifest root is not an object")
    authorities = vectors.get("authorities")
    sail = authorities.get("sail") if isinstance(authorities, dict) else None
    if not isinstance(sail, dict) or sail.get("revision") != pinned:
        raise SystemExit("trace vectors pinned to a different Sail oracle commit")
    legacy = vectors.get("legacy_protocol_layout")
    if not isinstance(legacy, dict) or not isinstance(legacy.get("revision"), str):
        raise SystemExit("trace vectors declare no legacy protocol-layout revision")
    if legacy.get("semantic_authority") is not False:
        raise SystemExit(
            "trace vectors must declare the legacy Stark-V layout non-authoritative"
        )

    digest = hashlib.sha256()
    digest.update(manifest_bytes)
    observed_names: set[str] = set()
    for group in ("vectors", "negative_vectors"):
        entries = vectors.get(group)
        if not isinstance(entries, list):
            raise SystemExit(f"trace vector manifest has no {group} list")
        if group == "vectors" and not entries:
            raise SystemExit("trace vector manifest has no positive release vectors")
        for vector in entries:
            if not isinstance(vector, dict):
                raise SystemExit(f"trace vector manifest has a non-object {group} entry")
            name = vector.get("name")
            elf_path = vector.get("elf")
            expected_digest = vector.get("elf_sha256")
            if not isinstance(name, str) or not name or name in observed_names:
                raise SystemExit(f"trace vector manifest has invalid or duplicate name: {name!r}")
            observed_names.add(name)
            if not isinstance(elf_path, str) or not elf_path:
                raise SystemExit(f"trace vector {name} has no ELF path")
            if not isinstance(expected_digest, str):
                raise SystemExit(f"trace vector {name} has no ELF digest")
            if group == "negative_vectors" and vector.get("expected") != \
                    "diagnostic_only_not_release_eligible":
                raise SystemExit(
                    f"negative ELF is not diagnostic-only: {name}"
                )
            elf = (root / elf_path).resolve()
            if not elf.is_relative_to(root.resolve()):
                raise SystemExit(f"trace vector ELF escapes the repository: {name}")
            elf_bytes = elf.read_bytes()
            actual = hashlib.sha256(elf_bytes).hexdigest()
            if actual != expected_digest:
                raise SystemExit(f"ELF digest mismatch for {name}: {actual}")
            digest.update(group.encode())
            digest.update(b"\0")
            digest.update(name.encode())
            digest.update(b"\0")
            digest.update(elf_bytes)

    positive_vectors = vectors["vectors"]
    positive_names = [vector["name"] for vector in positive_vectors]
    try:
        expected_admission = admission_policy.for_programs(positive_names)
    except (TypeError, ValueError) as error:
        raise SystemExit(f"invalid trace-vector proof-admission policy: {error}") from error
    admission_errors = admission_policy.errors(positive_vectors, expected_admission)
    if admission_errors:
        raise SystemExit(
            "invalid trace-vector proof-admission policy: " + "; ".join(admission_errors)
        )
    receipt["corpus_digest_sha256"] = digest.hexdigest()
    return vectors


def _run(command: list[str], cwd: Path | None = None) -> str:
    return subprocess.run(
        command,
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    ).stdout


def _first_line_difference(rust: str, zig: str) -> dict[str, object] | None:
    rust_lines = rust.splitlines()
    zig_lines = zig.splitlines()
    for index in range(max(len(rust_lines), len(zig_lines))):
        rust_line = rust_lines[index] if index < len(rust_lines) else None
        zig_line = zig_lines[index] if index < len(zig_lines) else None
        if rust_line != zig_line:
            return {"line": index + 1, "rust": rust_line, "zig": zig_line}
    return None


def _witness_layout(output: str) -> bytes:
    layout = []
    lines = output.splitlines()
    for index, line in enumerate(lines):
        if not line.startswith("family="):
            continue
        fields = dict(part.split("=", 1) for part in line.split())
        if index + 1 >= len(lines) or not lines[index + 1].startswith("names="):
            raise SystemExit(f"malformed witness layout after {fields['family']}")
        layout.append(
            f"family={fields['family']} columns={fields['columns']}\n{lines[index + 1]}\n"
        )
    if not layout:
        raise SystemExit("witness dump contains no family layouts")
    return "".join(layout).encode()


def _compare_canonical_dump(
    oracle_exe: Path,
    receipt: dict,
    root: Path,
    pinned: str,
    *,
    boundary: str,
    rust_flag: str,
    zig_flag: str,
) -> None:
    zig_exe = root / "zig-out" / "bin" / "riscv-trace-dump"
    vectors = load_trace_vectors(root, pinned, receipt)
    demoted = boundary == "per_family_witness_rows"
    cases = []
    layouts: set[str] = set()
    declared: set[str] = set()
    all_ok = True
    lineage_agree = True
    for vector in vectors["vectors"]:
        elf = root / vector["elf"]
        rust = _run([str(oracle_exe), rust_flag, "--elf", str(elf)])
        zig = _run([str(zig_exe), zig_flag, str(elf)], cwd=root)
        agree = rust == zig
        all_ok = all_ok and agree
        case = {
            "name": vector["name"],
            "elf_sha256": vector["elf_sha256"],
            "agree": agree,
            "rust_sha256": hashlib.sha256(rust.encode()).hexdigest(),
            "zig_sha256": hashlib.sha256(zig.encode()).hexdigest(),
            "bytes": len(zig.encode()),
            "records": sum(1 for line in zig.splitlines() if line.startswith("row="))
            if demoted
            else len(zig.splitlines()),
        }
        if demoted:
            # The layout digest is Zig-side identity, not a parity verdict, so it
            # is recorded whether or not the demoted row comparison agrees.
            layouts.add(hashlib.sha256(_witness_layout(zig)).hexdigest())
            try:
                paths, lineage_ok = superseded_air.witness_row_divergence(rust, zig)
            except ValueError as error:
                raise SystemExit(
                    f"witness-row dump for {vector['name']} is malformed: {error}"
                ) from error
            lineage_agree = lineage_agree and lineage_ok
            if not agree:
                case["divergence_paths"] = paths
                declared.update(paths)
        if not agree:
            case["first_disagreement"] = _first_line_difference(rust, zig)
        cases.append(case)

    layout_ok = not demoted or len(layouts) == 1
    if demoted and layout_ok:
        receipt["witness_layout_digest_sha256"] = next(iter(layouts))
    result = {
        "comparison": "byte-for-byte canonical serialization of production buffers",
        "corpus": cases,
    }
    if demoted and not all_ok and layout_ok:
        result.update(superseded_air.declaration(
            declared, {"agree": lineage_agree, "comparison": WITNESS_ROW_LINEAGE}
        ))
    else:
        result["status"] = "pass" if all_ok and layout_ok else "fail"
    if demoted:
        result["layout_digests"] = sorted(layouts)
    receipt["boundaries"][boundary] = result


def compare_per_family_witness_rows(
    oracle_exe: Path,
    receipt: dict,
    root: Path,
    pinned: str,
) -> None:
    _compare_canonical_dump(
        oracle_exe,
        receipt,
        root,
        pinned,
        boundary="per_family_witness_rows",
        rust_flag="--witness-rows",
        zig_flag="--witness-rows",
    )


def compare_ordered_accesses(
    oracle_exe: Path,
    receipt: dict,
    root: Path,
    pinned: str,
) -> None:
    _compare_canonical_dump(
        oracle_exe,
        receipt,
        root,
        pinned,
        boundary="ordered_accesses",
        rust_flag="--ordered-accesses",
        zig_flag="--ordered-accesses",
    )
