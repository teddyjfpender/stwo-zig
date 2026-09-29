"""Pin, provenance and fixture validation for the circuit recursion lane.

The lane's Rust oracle (`tools/stwo-circuit-oracle-rs`) depends on StarkWare's
`proving` repository by git URL and revision. Its checkpoints live under
`vectors/circuit/`, authenticated by `vectors/circuit/provenance.json`, which
binds every fixture to its bytes, SHA-256, generating command, and the digest of
the oracle source that produced it. Editing the oracle without regenerating the
fixtures, or editing a fixture by hand, is therefore rejected.
"""

from __future__ import annotations

import hashlib
import json
import struct
import tomllib
from pathlib import Path


ORACLE = "tools/stwo-circuit-oracle-rs"
MANIFEST = f"{ORACLE}/Cargo.toml"
LOCK = f"{ORACLE}/Cargo.lock"
TOOLCHAIN = f"{ORACLE}/rust-toolchain.toml"
AUTHORITY_SOURCE = f"{ORACLE}/src/checkpoint.rs"
VECTORS = "vectors/circuit"
README = f"{VECTORS}/README.md"
PROVENANCE = f"{VECTORS}/provenance.json"
PROVENANCE_SCHEMA = "stwo-circuit-oracle-provenance-v1"
CHECKPOINT_SCHEMA = "stwo-circuit-oracle-checkpoint-v1"
METADATA_TABLE = "circuit-recursion-oracle"
PROVING_ROOT_PLACEHOLDER = "<proving checkout at the pinned revision>"

# (fixture, rung, oracle subcommand, reads upstream data)
ORACLE_ARTIFACTS = (
    (f"{VECTORS}/r0/primitives.json", "r0", "primitives", False),
    (f"{VECTORS}/r2/gadgets.json", "r1-r2", "gadgets", False),
    (f"{VECTORS}/r3/components.json", "r3", "components", True),
    (f"{VECTORS}/official/compiled_air_constraints_v1.bin", "r3", "project-air", True),
)
PROJECTION = ORACLE_ARTIFACTS[3][0]
COMPONENTS = ORACLE_ARTIFACTS[2][0]
# (fixture, path in the proving checkout) for files copied verbatim.
UPSTREAM_COPIES = (
    (
        f"{VECTORS}/official/compiled_casm_air.sample_evaluations.json",
        "outputs/compiled_casm_air/sample_evaluations.json",
    ),
    (
        f"{VECTORS}/official/compiled_circuit_air.sample_evaluations.json",
        "outputs/compiled_circuit_air/sample_evaluations.json",
    ),
    (
        f"{VECTORS}/official/registries/leaf_prover_canonical_small.json",
        "crates/leaf_prover/tests/data/circuit_registry_canonical_small.json",
    ),
    (
        f"{VECTORS}/official/registries/recursive_tree_test.json",
        "crates/stwo_run_and_prove_recursive_tree/test_data/circuit_registry.json",
    ),
    # Wire-format goldens (M3): circuit proofs, leaf and tree outputs.
    (
        f"{VECTORS}/official/registries/privacy_large_proofs.json",
        "crates/privacy_circuit_verify/large_proofs_circuit_registry.json",
    ),
    (
        f"{VECTORS}/official/circuit_multiverifier/proof.bin",
        "test_data/circuit_multiverifier/proof.bin",
    ),
    (
        f"{VECTORS}/official/circuit_multiverifier/proof_cairo.bin",
        "test_data/circuit_multiverifier/proof_cairo.bin",
    ),
    (
        f"{VECTORS}/official/circuit_multiverifier/backward_compatibility_cairo_proof.bin",
        "test_data/circuit_multiverifier/backward_compatibility_cairo_proof.bin",
    ),
    (
        f"{VECTORS}/official/leaf_prover/expected_output.json",
        "crates/leaf_prover/tests/data/expected_output.json",
    ),
    (
        f"{VECTORS}/official/recursive_tree/four_leaves/leaf.json",
        "crates/stwo_run_and_prove_recursive_tree/test_data/goldens/four_leaves/leaf.json",
    ),
    (
        f"{VECTORS}/official/recursive_tree/four_leaves/root.proof",
        "crates/stwo_run_and_prove_recursive_tree/test_data/goldens/four_leaves/root.proof",
    ),
    (
        f"{VECTORS}/official/recursive_tree/four_leaves/root_outputs.json",
        "crates/stwo_run_and_prove_recursive_tree/test_data/goldens/four_leaves/root_outputs.json",
    ),
    (
        f"{VECTORS}/official/recursive_tree/four_leaves/root_packed.json",
        "crates/stwo_run_and_prove_recursive_tree/test_data/goldens/four_leaves/root_packed.json",
    ),
)
MANAGED = tuple(path for path, *_ in ORACLE_ARTIFACTS) + tuple(
    path for path, _ in UPSTREAM_COPIES
)

PROJECTION_MAGIC = b"STWOCAIR"
PROJECTION_VERSION = 1
INPUTS_DOMAIN = b"STWO_CIRCUIT_ORACLE_INPUTS_V1\0"


def lock_source(repository: str, revision: str) -> str:
    return f"git+{repository}?rev={revision}#{revision}"


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def oracle_sources(root: Path) -> list[str]:
    """The files that determine the oracle binary, as sorted repository paths."""
    oracle = root / ORACLE
    files = [oracle / "Cargo.toml", oracle / "Cargo.lock", oracle / "rust-toolchain.toml"]
    files.extend(sorted((oracle / "src").rglob("*.rs")))
    return sorted(path.relative_to(root).as_posix() for path in files)


def oracle_source_sha256(root: Path) -> str:
    """SHA-256 over `path NUL sha256 LF` lines of every oracle source, in path order."""
    lines = "".join(
        f"{path}\0{sha256_file(root / path)}\n" for path in oracle_sources(root)
    )
    return hashlib.sha256(lines.encode("utf-8")).hexdigest()


def inputs_aggregate(records: list[dict]) -> str:
    """The oracle's aggregate digest of the upstream inputs it read (`src/upstream.rs`)."""
    digest = hashlib.sha256(INPUTS_DOMAIN)
    for record in sorted(records, key=lambda item: item["path"]):
        digest.update(record["path"].encode("utf-8"))
        digest.update(b"\0")
        digest.update(struct.pack("<Q", record["bytes"]))
        digest.update(bytes.fromhex(record["sha256"]))
    return digest.hexdigest()


class ProjectionError(ValueError):
    """The projection does not follow the documented v1 grammar."""


class _Reader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.position = 0
        self.strings: list[str] = []

    def take(self, size: int) -> bytes:
        end = self.position + size
        if end > len(self.data):
            raise ProjectionError(f"truncated at byte {self.position}")
        chunk = self.data[self.position:end]
        self.position = end
        return chunk

    def u8(self) -> int:
        return self.take(1)[0]

    def u32(self) -> int:
        return struct.unpack("<I", self.take(4))[0]

    def string(self) -> str:
        index = self.u32()
        if index >= len(self.strings):
            raise ProjectionError(f"string index {index} out of range")
        return self.strings[index]

    def many(self, item):
        return [item() for _ in range(self.u32())]

    def optional(self, item):
        flag = self.u8()
        if flag not in (0, 1):
            raise ProjectionError(f"invalid option flag {flag}")
        return item() if flag else None

    def use_or_yield(self) -> str:
        value = self.u8()
        if value not in (0, 1):
            raise ProjectionError(f"invalid use_or_yield {value}")
        return "Use" if value == 0 else "Yield"

    def expr(self) -> None:
        tag = self.u8()
        if tag == 0:
            if self.u32() >= 2**31 - 1:
                raise ProjectionError("non-canonical M31 constant")
        elif tag in (1, 2, 7, 8):
            self.string()
        elif tag == 3:
            if self.u8() not in (0, 1, 2):
                raise ProjectionError("invalid binary operator")
            self.expr()
            self.expr()
        elif tag == 4:
            if self.u8() != 1:
                raise ProjectionError("invalid unary operator")
            self.expr()
        elif tag == 5:
            self.string()
            self.many(self.expr)
        elif tag == 6:
            self.many(self.expr)
        elif tag != 9:
            raise ProjectionError(f"invalid expression tag {tag}")

    def step(self) -> None:
        tag = self.u8()
        if tag == 0:
            self.expr()
        elif tag == 1:
            self.many(self.string)
            self.expr()
        elif tag == 2:
            self.string()
            self.use_or_yield()
            self.many(self.expr)
            self.expr()
        else:
            raise ProjectionError(f"invalid step tag {tag}")

    def record(self) -> str:
        name = self.string()
        self.string()
        self.optional(self.u32)
        for _ in range(2):
            self.many(self.string)
        self.many(lambda: (self.string(), self.use_or_yield()))
        for _ in range(4):
            self.many(self.string)
        self.many(self.step)
        self.optional(self.expr)
        return name


def parse_projection(data: bytes) -> dict:
    """Decodes a v1 projection, verifying every record digest; returns its header summary."""
    reader = _Reader(data)
    if reader.take(8) != PROJECTION_MAGIC:
        raise ProjectionError("bad magic")
    if reader.u32() != PROJECTION_VERSION:
        raise ProjectionError("unsupported version")
    for _ in range(reader.u32()):
        reader.strings.append(reader.take(reader.u32()).decode("utf-8"))
    summary = {
        "revision": reader.string(),
        "inputs_sha256": reader.string(),
        "constants": dict(reader.many(lambda: (reader.string(), reader.u32()))),
        "sources": {},
    }
    for _ in range(reader.u32()):
        label = reader.string()
        slots = reader.many(reader.string)
        hand_written = reader.many(reader.string)
        functions = []
        for _ in range(reader.u32()):
            length = reader.u32()
            digest = reader.take(32)
            start = reader.position
            record = reader.take(length)
            if hashlib.sha256(record).digest() != digest:
                raise ProjectionError(f"{label}: record at byte {start} has a bad digest")
            reader.position = start
            functions.append(reader.record())
            if reader.position != start + length:
                raise ProjectionError(f"{label}: record {functions[-1]} length mismatch")
        summary["sources"][label] = {
            "slots": slots,
            "hand_written": hand_written,
            "functions": functions,
        }
    if reader.position != len(data):
        raise ProjectionError("trailing bytes")
    return summary


def _load_toml(root: Path, relative: str) -> tuple[dict | None, list[str]]:
    try:
        with (root / relative).open("rb") as handle:
            return tomllib.load(handle), []
    except (OSError, tomllib.TOMLDecodeError) as error:
        return None, [f"{relative}: unable to parse: {error}"]


def _check_manifest(root: Path, repository: str, revision: str, toolchain: str) -> list[str]:
    manifest, errors = _load_toml(root, MANIFEST)
    if manifest is None:
        return errors
    metadata = manifest.get("package", {}).get("metadata", {}).get(METADATA_TABLE, {})
    expected = {
        "checkpoint-schema": CHECKPOINT_SCHEMA,
        "proving-repository": repository,
        "proving-revision": revision,
        "rust-toolchain": toolchain,
    }
    errors = [
        f"{MANIFEST}: metadata {key!r} is {metadata.get(key)!r}, expected {value!r}"
        for key, value in expected.items()
        if metadata.get(key) != value
    ]
    pinned = 0
    for name, value in manifest.get("dependencies", {}).items():
        if isinstance(value, dict) and "path" in value:
            errors.append(f"{MANIFEST}: path dependency {name!r} is forbidden")
        if isinstance(value, dict) and "git" in value:
            pinned += 1
            if value.get("git") != repository or value.get("rev") != revision:
                errors.append(
                    f"{MANIFEST}: dependency {name!r} is {value.get('git')!r}@"
                    f"{value.get('rev')!r}, expected {repository!r}@{revision!r}"
                )
    if pinned == 0:
        errors.append(f"{MANIFEST}: no dependency on {repository}")
    for key in ("patch", "replace"):
        if key in manifest:
            errors.append(f"{MANIFEST}: [{key}] is forbidden")
    return errors


def _check_lock_and_toolchain(root: Path, repository: str, revision: str, toolchain: str) -> list[str]:
    lock, errors = _load_toml(root, LOCK)
    if lock is not None:
        sources = {
            package["source"]
            for package in lock.get("package", [])
            if isinstance(package.get("source"), str)
            and package["source"].startswith("git+")
        }
        if sources != {lock_source(repository, revision)}:
            errors.append(
                f"{LOCK}: git sources are {sorted(sources)!r}, expected only "
                f"{lock_source(repository, revision)!r}"
            )
    config, toolchain_errors = _load_toml(root, TOOLCHAIN)
    errors.extend(toolchain_errors)
    if config is not None and config.get("toolchain", {}).get("channel") != toolchain:
        errors.append(f"{TOOLCHAIN}: channel is not {toolchain!r}")
    try:
        source = (root / AUTHORITY_SOURCE).read_text(encoding="utf-8")
    except OSError as error:
        return errors + [f"{AUTHORITY_SOURCE}: unable to read: {error}"]
    for constant, value in (("PROVING_REPOSITORY", repository), ("PROVING_REVISION", revision)):
        line = f'pub const {constant}: &str = "{value}";'
        if source.count(f"pub const {constant}:") != 1 or line not in source:
            errors.append(f"{AUTHORITY_SOURCE}: {constant} is not {value!r}")
    return errors


def _check_checkpoint(root: Path, path: str, rung: str, subcommand: str, revision: str) -> list[str]:
    try:
        document = json.loads((root / path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return [f"{path}: unable to parse checkpoint: {error}"]
    expected = {
        "schema": CHECKPOINT_SCHEMA,
        "rung": rung,
        "subcommand": subcommand,
    }
    errors = [
        f"{path}: {key} is {document.get(key)!r}, expected {value!r}"
        for key, value in expected.items()
        if document.get(key) != value
    ]
    if document.get("authority", {}).get("revision") != revision:
        errors.append(f"{path}: authority revision is not {revision}")
    return errors


def _check_projection(root: Path, revision: str) -> list[str]:
    try:
        summary = parse_projection((root / PROJECTION).read_bytes())
        components = json.loads((root / COMPONENTS).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ProjectionError, UnicodeDecodeError) as error:
        return [f"{PROJECTION}: {error}"]
    errors = []
    if summary["revision"] != revision:
        errors.append(f"{PROJECTION}: revision is {summary['revision']!r}, expected {revision!r}")
    if summary["inputs_sha256"] != inputs_aggregate(components.get("inputs", [])):
        errors.append(f"{PROJECTION}: upstream inputs differ from {COMPONENTS}")
    body = components.get("body", {})
    slots = {
        "cairo": body.get("cairo_slots"),
        "circuit": body.get("circuit_components"),
    }
    for label, expected_slots in slots.items():
        source = summary["sources"].get(label)
        if source is None or source["slots"] != expected_slots:
            errors.append(f"{PROJECTION}: {label} slots differ from {COMPONENTS}")
    return errors


def _check_provenance(root: Path, repository: str, revision: str, toolchain: str) -> list[str]:
    try:
        provenance = json.loads((root / PROVENANCE).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return [f"{PROVENANCE}: unable to parse: {error}"]
    errors = []
    if provenance.get("schema") != PROVENANCE_SCHEMA:
        errors.append(f"{PROVENANCE}: schema is not {PROVENANCE_SCHEMA}")
    if provenance.get("upstream") != {"repository": repository, "revision": revision}:
        errors.append(f"{PROVENANCE}: upstream is not {repository}@{revision}")
    oracle = provenance.get("oracle", {})
    if oracle.get("toolchain") != toolchain or oracle.get("manifest") != MANIFEST:
        errors.append(f"{PROVENANCE}: oracle manifest or toolchain drifted")
    if oracle.get("source_sha256") != oracle_source_sha256(root):
        errors.append(
            f"{PROVENANCE}: oracle source digest drifted; regenerate with "
            "scripts/generate_circuit_oracle_vectors.py"
        )
    artifacts = provenance.get("artifacts", [])
    by_path = {artifact.get("path"): artifact for artifact in artifacts}
    if len(by_path) != len(artifacts) or set(by_path) != set(MANAGED):
        errors.append(f"{PROVENANCE}: artifact set is not exactly {sorted(MANAGED)}")
    for path, artifact in by_path.items():
        if path not in MANAGED:
            continue
        try:
            data = (root / path).read_bytes()
        except OSError as error:
            errors.append(f"{path}: unable to read fixture: {error}")
            continue
        if artifact.get("bytes") != len(data) or artifact.get("sha256") != hashlib.sha256(data).hexdigest():
            errors.append(f"{path}: fixture bytes differ from {PROVENANCE}")
    for path, rung, subcommand, reads_upstream in ORACLE_ARTIFACTS:
        command = ["stwo-circuit-oracle", subcommand]
        if reads_upstream:
            command += ["--proving-root", PROVING_ROOT_PLACEHOLDER]
        artifact = by_path.get(path, {})
        if artifact.get("command") != command + ["--output", path]:
            errors.append(f"{path}: provenance command is not {command}")
        if path.endswith(".json"):
            errors.extend(_check_checkpoint(root, path, rung, subcommand, revision))
    for path, upstream_path in UPSTREAM_COPIES:
        if by_path.get(path, {}).get("upstream_path") != upstream_path:
            errors.append(f"{path}: provenance upstream path is not {upstream_path}")
    present = {
        path.relative_to(root).as_posix()
        for path in (root / VECTORS).rglob("*")
        if path.is_file()
    }
    for unlisted in sorted(present - set(MANAGED) - {README, PROVENANCE}):
        errors.append(f"{unlisted}: fixture is not listed in {PROVENANCE}")
    return errors


def _check_upstream_copies(root: Path) -> list[str]:
    """Copies of files the oracle read must equal the bytes it recorded reading."""
    try:
        components = json.loads((root / COMPONENTS).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return [f"{COMPONENTS}: unable to parse: {error}"]
    recorded = {record["path"]: record["sha256"] for record in components.get("inputs", [])}
    errors = []
    for path, upstream_path in UPSTREAM_COPIES:
        if upstream_path in recorded and (root / path).is_file():
            if sha256_file(root / path) != recorded[upstream_path]:
                errors.append(f"{path}: differs from the {upstream_path} the oracle read")
    return errors


def check(root: Path, *, repository: str, revision: str, toolchain: str) -> list[str]:
    errors = _check_manifest(root, repository, revision, toolchain)
    errors.extend(_check_lock_and_toolchain(root, repository, revision, toolchain))
    errors.extend(_check_provenance(root, repository, revision, toolchain))
    errors.extend(_check_projection(root, revision))
    errors.extend(_check_upstream_copies(root))
    return errors
