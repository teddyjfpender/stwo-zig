"""Authenticated, isolated Stwo-Cairo witness artifact generation."""

from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

import fcntl

OFFICIAL_REVISION = "82f21252a68ec006d73e299f5bf1ce6d4db0ee78"
OFFICIAL_TREE = "2b06286971d87c6d3e834de622d3777f1ff9f41f"
OFFICIAL_WITNESS_MOD_SHA256 = (
    "e0113af8099143ea2770312bff24bc1e2fa5329933b272bac0fdae815b0de448"
)
EXPECTED_BUNDLE_SHA256 = (
    "d119a31ecf07c0e4d97ad5884384d99150517ffddfb4515ebbe5c626ce28094f"
)
EXPECTED_BUNDLE_BYTES = 2_486_826
EXPECTED_PROGRAM_COUNT = 63

COMPONENTS = (
    "add_ap_opcode",
    "add_mod_builtin",
    "add_opcode",
    "add_opcode_small",
    "assert_eq_opcode",
    "assert_eq_opcode_double_deref",
    "assert_eq_opcode_imm",
    "bitwise_builtin",
    "blake_g",
    "blake_round",
    "blake_round_sigma",
    "call_opcode_abs",
    "call_opcode_rel_imm",
    "cube_252",
    "ec_op_builtin",
    "generic_opcode",
    "jnz_opcode_non_taken",
    "jnz_opcode_taken",
    "jump_opcode_abs",
    "jump_opcode_double_deref",
    "jump_opcode_rel",
    "jump_opcode_rel_imm",
    "mul_mod_builtin",
    "mul_opcode",
    "mul_opcode_small",
    "partial_ec_mul_generic",
    "partial_ec_mul_window_bits_18",
    "partial_ec_mul_window_bits_9",
    "pedersen_aggregator_window_bits_18",
    "pedersen_aggregator_window_bits_9",
    "pedersen_builtin",
    "pedersen_builtin_narrow_windows",
    "pedersen_points_table_window_bits_18",
    "pedersen_points_table_window_bits_9",
    "poseidon_3_partial_rounds_chain",
    "poseidon_aggregator",
    "poseidon_builtin",
    "poseidon_full_round_chain",
    "poseidon_round_keys",
    "qm_31_add_mul_opcode",
    "range_check_252_width_27",
    "range_check_11",
    "range_check_12",
    "range_check_18",
    "range_check_20",
    "range_check_3_3_3_3_3",
    "range_check_3_6_6_3",
    "range_check_4_3",
    "range_check_4_4",
    "range_check_4_4_4_4",
    "range_check_6",
    "range_check_7_2_5",
    "range_check_8",
    "range_check_9_9",
    "range_check96_builtin",
    "range_check_builtin",
    "ret_opcode",
    "triple_xor_32",
    "verify_bitwise_xor_4",
    "verify_bitwise_xor_7",
    "verify_bitwise_xor_8",
    "verify_bitwise_xor_9",
    "verify_instruction",
)

ROOT = Path(__file__).resolve().parent
REWRITER = ROOT / "rewriter"
SUPPORT = ROOT / "support"


@dataclass(frozen=True)
class SourceIdentity:
    revision: str
    tree: str
    commit_timestamp: int


@dataclass(frozen=True)
class CompilerReceipt:
    schema: str
    official_source: SourceIdentity
    orchestrator_sha256: str
    rewriter_closure_sha256: str
    support_closure_sha256: str
    emitted_components: tuple[str, ...]
    program_count: int
    instruction_count: int
    artifact_bytes: int
    artifact_sha256: str

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, sort_keys=True) + "\n"


def _run(
    args: Iterable[os.PathLike[str] | str],
    *,
    cwd: Path,
    env: dict[str, str] | None = None,
    capture: bool = False,
) -> str:
    command = [os.fspath(arg) for arg in args]
    result = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        check=True,
        text=True,
        stdout=subprocess.PIPE if capture else None,
    )
    return result.stdout if capture else ""


def authenticate_source(source: Path) -> SourceIdentity:
    if not source.is_dir():
        raise ValueError(f"official source is not a directory: {source}")

    revision = _run(["git", "rev-parse", "HEAD"], cwd=source, capture=True).strip()
    tree = _run(["git", "rev-parse", "HEAD^{tree}"], cwd=source, capture=True).strip()
    dirty = _run(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=source,
        capture=True,
    )
    if dirty:
        raise ValueError("official source checkout is dirty")
    if revision != OFFICIAL_REVISION:
        raise ValueError(
            f"official source revision {revision} != pinned {OFFICIAL_REVISION}"
        )
    if tree != OFFICIAL_TREE:
        raise ValueError(f"official source tree {tree} != pinned {OFFICIAL_TREE}")
    timestamp_text = _run(
        ["git", "show", "-s", "--format=%ct", "HEAD"],
        cwd=source,
        capture=True,
    ).strip()
    try:
        commit_timestamp = int(timestamp_text)
    except ValueError as error:
        raise ValueError(f"invalid official commit timestamp: {timestamp_text!r}") from error
    return SourceIdentity(
        revision=revision,
        tree=tree,
        commit_timestamp=commit_timestamp,
    )


def closure_sha256(root: Path) -> str:
    digest = hashlib.sha256()
    files = sorted(
        path
        for path in root.rglob("*")
        if path.is_file()
        and not {"target", "__pycache__", ".git"}.intersection(
            path.relative_to(root).parts
        )
        and path.suffix != ".pyc"
    )
    for path in files:
        relative = path.relative_to(root).as_posix().encode("utf-8")
        data = path.read_bytes()
        digest.update(len(relative).to_bytes(4, "little"))
        digest.update(relative)
        digest.update(len(data).to_bytes(8, "little"))
        digest.update(data)
    return digest.hexdigest()


def files_sha256(root: Path, paths: Iterable[Path]) -> str:
    digest = hashlib.sha256()
    for path in sorted(paths):
        relative = path.relative_to(root).as_posix().encode("utf-8")
        data = path.read_bytes()
        digest.update(len(relative).to_bytes(4, "little"))
        digest.update(relative)
        digest.update(len(data).to_bytes(8, "little"))
        digest.update(data)
    return digest.hexdigest()


@contextmanager
def _compiler_lock() -> Iterable[None]:
    lock_path = ROOT / "target" / "compiler.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+b") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        yield


def _build_identity() -> str:
    digest = hashlib.sha256()
    digest.update(OFFICIAL_TREE.encode("ascii"))
    digest.update(Path(__file__).read_bytes())
    digest.update(closure_sha256(REWRITER).encode("ascii"))
    digest.update(closure_sha256(SUPPORT).encode("ascii"))
    return digest.hexdigest()


def _build_identity_timestamp() -> int:
    digest = bytes.fromhex(_build_identity())
    # Keep the synthetic time in a range accepted by common filesystems. Its only
    # purpose is Cargo invalidation: equal closures get equal mtimes.
    return 1_600_000_000 + int.from_bytes(digest[:4], "little") % 300_000_000


def _normalize_mtimes(root: Path, timestamp: int) -> None:
    paths = list(root.rglob("*"))
    for path in (candidate for candidate in paths if not candidate.is_dir()):
        os.utime(path, (timestamp, timestamp), follow_symlinks=False)
    directories = sorted(
        (candidate for candidate in paths if candidate.is_dir()),
        key=lambda candidate: len(candidate.parts),
        reverse=True,
    )
    for path in directories:
        os.utime(path, (timestamp, timestamp), follow_symlinks=False)
    os.utime(root, (timestamp, timestamp), follow_symlinks=False)


def _extract_authenticated_source(source: Path, destination: Path) -> None:
    archive = subprocess.run(
        ["git", "archive", "--format=tar", OFFICIAL_REVISION],
        cwd=source,
        check=True,
        stdout=subprocess.PIPE,
    ).stdout
    destination.mkdir()
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as source_tar:
        source_tar.extractall(destination, filter="data")


def _build_rewriter() -> Path:
    _run(
        [
            "cargo",
            "build",
            "--release",
            "--locked",
            "--manifest-path",
            REWRITER / "Cargo.toml",
        ],
        cwd=ROOT,
    )
    binary = REWRITER / "target" / "release" / "cairo-witness-rewriter"
    if not binary.is_file():
        raise RuntimeError(f"rewriter build did not produce {binary}")
    return binary


def _rewrite_components(staged: Path, emitted: Path) -> tuple[str, ...]:
    components_root = staged / "crates/prover/src/witness/components"
    binary = _build_rewriter()
    _run(
        [binary, "--emit-dir", emitted, components_root],
        cwd=ROOT,
    )
    actual = tuple(sorted(path.stem for path in emitted.glob("*.rs")))
    expected = tuple(sorted(COMPONENTS))
    if actual != expected:
        raise RuntimeError(
            f"rewriter emitted {actual!r}; expected exact component set {expected!r}"
        )
    for component in actual:
        shutil.copy2(emitted / f"{component}.rs", components_root / f"{component}.rs")
    return actual


def patch_module_registry(path: Path) -> None:
    original = path.read_bytes()
    actual_hash = hashlib.sha256(original).hexdigest()
    if actual_hash != OFFICIAL_WITNESS_MOD_SHA256:
        raise RuntimeError(
            f"official witness module hash {actual_hash} != "
            f"{OFFICIAL_WITNESS_MOD_SHA256}"
        )
    text = original.decode("utf-8")
    text = text.replace(
        "pub mod fast_deduction;\n",
        "pub mod fast_deduction;\nmod jit_flat_macros;\n",
        1,
    )
    text = text.replace(
        "pub mod range_checks;\npub mod utils;\n",
        "pub mod range_checks;\npub mod recording_export;\n"
        "pub mod utils;\npub mod witness_eval;\n",
        1,
    )
    path.write_text(text)


def _install_support(staged: Path) -> None:
    for source_path in sorted(path for path in SUPPORT.rglob("*") if path.is_file()):
        relative = source_path.relative_to(SUPPORT)
        destination = staged / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_path, destination)
    patch_module_registry(staged / "crates/prover/src/witness/mod.rs")


def _compile_bundle(staged: Path, artifact: Path) -> None:
    env = os.environ.copy()
    cargo_target = ROOT / "target" / "official-source"
    env["CARGO_TARGET_DIR"] = os.fspath(cargo_target)
    env["RUST_MIN_STACK"] = "67108864"
    identity = _build_identity()
    identity_path = cargo_target / "stwo-cairo-compiler-identity"
    cached_identity = (
        identity_path.read_text(encoding="ascii").strip()
        if identity_path.is_file()
        else None
    )
    if cached_identity != identity:
        _run(
            [
                "cargo",
                "clean",
                "--target-dir",
                cargo_target,
                "-p",
                "stwo-cairo-prover",
                "-p",
                "stwo-cairo-common",
                "-p",
                "cairo-air",
                "-p",
                "stwo-cairo-adapter",
                "-p",
                "stwo-cairo-serialize",
            ],
            cwd=staged,
            env=env,
        )
        # Cargo's fast freshness path is mtime-based. The content-derived
        # normalized timestamp can move backward across compiler identities, so
        # advance one installed support source only when the identity changes.
        # This forces the local prover crate to rebuild once without sacrificing
        # the identical-closure warm path.
        os.utime(
            staged / "crates/prover/src/witness/recording_export.rs",
            None,
        )
    _run(
        [
            "cargo",
            "--config",
            "profile.release.package.stwo-cairo-prover.opt-level=0",
            "run",
            "--release",
            "--locked",
            "-p",
            "stwo-cairo-prover",
            "--bin",
            "witness_export",
            "--",
            artifact,
        ],
        cwd=staged,
        env=env,
    )
    identity_path.write_text(identity + "\n", encoding="ascii")


def inspect_bundle(data: bytes) -> tuple[int, int]:
    if len(data) != EXPECTED_BUNDLE_BYTES:
        raise RuntimeError(
            f"bundle has {len(data)} bytes; expected {EXPECTED_BUNDLE_BYTES}"
        )
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED_BUNDLE_SHA256:
        raise RuntimeError(
            f"bundle SHA-256 {digest} != expected {EXPECTED_BUNDLE_SHA256}"
        )
    if data[:8] != b"STWZWIT\0":
        raise RuntimeError("bundle magic mismatch")
    version = int.from_bytes(data[8:12], "little")
    count = int.from_bytes(data[12:16], "little")
    if version != 1 or count != EXPECTED_PROGRAM_COUNT:
        raise RuntimeError(f"bundle header version={version}, programs={count}")

    offset = 16
    instructions = 0
    for _ in range(count):
        label_len = int.from_bytes(data[offset : offset + 2], "little")
        padding = int.from_bytes(data[offset + 2 : offset + 4], "little")
        instruction_count = int.from_bytes(data[offset + 28 : offset + 32], "little")
        if padding != 0:
            raise RuntimeError("bundle entry padding is nonzero")
        offset += 40 + label_len + instruction_count * 16
        instructions += instruction_count
    if offset != len(data):
        raise RuntimeError(f"bundle parser ended at {offset}, size is {len(data)}")
    return count, instructions


def publish_new(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise FileExistsError(f"refusing to replace existing output: {path}")
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            prefix=f".{path.name}.",
            dir=path.parent,
            delete=False,
        ) as output:
            temporary = Path(output.name)
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, 0o644)
        os.link(temporary, path)
        temporary.unlink()
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def generate_bundle(
    *,
    source: Path,
    output: Path,
    receipt_path: Path | None = None,
) -> CompilerReceipt:
    identity = authenticate_source(source)
    if output.exists():
        raise FileExistsError(f"refusing to replace existing output: {output}")
    if receipt_path is not None and receipt_path.exists():
        raise FileExistsError(f"refusing to replace existing receipt: {receipt_path}")
    if receipt_path == output:
        raise ValueError("bundle and receipt paths must be different")

    cache = ROOT / "target"
    staged = cache / "official-source-overlay"
    staged_next = cache / "official-source-overlay.next"
    emitted = cache / "emitted.next"
    artifact = cache / "witness_programs_v1.next.bin"
    with _compiler_lock():
        shutil.rmtree(staged_next, ignore_errors=True)
        shutil.rmtree(emitted, ignore_errors=True)
        emitted.mkdir(parents=True)
        artifact.unlink(missing_ok=True)
        try:
            _extract_authenticated_source(source, staged_next)
            components = _rewrite_components(staged_next, emitted)
            _install_support(staged_next)
            _normalize_mtimes(staged_next, _build_identity_timestamp())
            shutil.rmtree(staged, ignore_errors=True)
            os.replace(staged_next, staged)
            _compile_bundle(staged, artifact)
            data = artifact.read_bytes()
        finally:
            shutil.rmtree(staged_next, ignore_errors=True)
            shutil.rmtree(emitted, ignore_errors=True)
            artifact.unlink(missing_ok=True)

    program_count, instruction_count = inspect_bundle(data)
    receipt = CompilerReceipt(
        schema="stwo_zig_cairo_witness_compiler_receipt_v1",
        official_source=identity,
        orchestrator_sha256=files_sha256(
            ROOT,
            (ROOT / "generate.py", ROOT / "orchestrator.py"),
        ),
        rewriter_closure_sha256=closure_sha256(REWRITER),
        support_closure_sha256=closure_sha256(SUPPORT),
        emitted_components=components,
        program_count=program_count,
        instruction_count=instruction_count,
        artifact_bytes=len(data),
        artifact_sha256=hashlib.sha256(data).hexdigest(),
    )
    publish_new(output, data)
    if receipt_path is not None:
        publish_new(receipt_path, receipt.to_json().encode("utf-8"))
    return receipt
