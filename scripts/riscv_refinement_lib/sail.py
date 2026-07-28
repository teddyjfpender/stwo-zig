"""Bind the normalized pilot capsule to pinned Sail theorem-backend output."""

from __future__ import annotations

import copy
import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from . import codec
from .model import (
    SAIL_REPOSITORY,
    SAIL_REVISION,
    SAIL_VERSION,
    RefinementError,
)

GENERATED_DEFINITION_HASHES = {
    "execute_UTYPE": "f746995b8c903140529bb742379c295bee8d95a02de2d730990dc77fe1cacf1c",
    "execute_ITYPE": "1d014d14c56ab01dc511fc36c8c6ee4dea56a63708257b8a5df451e7c6f6b17d",
}
SOURCE_SLICE_HASHES = {
    "UTYPE": "a994f93a7ea421755ae439539d20b62fac52ab9c6517f18e9159d37b9481432d",
    "ITYPE": "d543047dde089e1175bce44a64d745d68e1c8cc37f61f442f86feea0fd0ffaa6",
}
PROFILE_PATH = Path("conformance/riscv/rv32im-sail-profile.json")
OVERRIDE_PATHS = (
    Path("conformance/riscv/sail-rv32im-override.json"),
    Path("conformance/riscv/sail-rv32im-tagged-options.json"),
)
PATCH_PATH = Path("conformance/riscv/sail-rvfi-zkvm-entry.patch")
PATCHED_SOURCE = Path("c_emulator/rvfi_dii.cpp")
MODEL_ENTRY = Path("model/riscv.sail_project")
SOURCE_FILE = Path("model/extensions/I/base_insts.sail")
BASE_CONFIGURATION = Path("build/config/rv32d_v256_e32.json")
EXACT_CONFIGURATION = Path("build/riscv-refinement/rv32im-zkvm-v1.json")
GENERATED_FILE = Path(
    "build/riscv-refinement/Lean_RV32IM/LeanRV32IM/InstsEnd.lean"
)
SIMULATOR = Path("build/c_emulator/sail_riscv_sim")


@dataclass(frozen=True)
class SailEvidence:
    source_root: Path
    compiler: Path
    compiler_sha256: str
    simulator_sha256: str
    generated_file: Path
    generated_file_sha256: str
    source_file_sha256: str
    model_entry_sha256: str
    base_configuration_sha256: str
    exact_configuration: bytes
    exact_configuration_sha256: str
    profile_file_sha256: dict[str, str]
    checkout_state: str
    definition_hashes: dict[str, str]
    source_slice_hashes: dict[str, str]


def _run(
    argv: list[str],
    cwd: Path | None = None,
    timeout: int = 120,
) -> str:
    try:
        completed = subprocess.run(
            argv,
            cwd=cwd,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        detail = ""
        if isinstance(exc, subprocess.CalledProcessError):
            detail = (exc.stderr or exc.stdout or "").strip()
            if len(detail) > 4000:
                detail = "... " + detail[-4000:]
        raise RefinementError(
            f"command failed: {' '.join(argv)}" + (f": {detail}" if detail else "")
        ) from exc
    return completed.stdout.strip()


def _run_bytes(argv: list[str], cwd: Path | None = None) -> bytes:
    try:
        return subprocess.run(
            argv,
            cwd=cwd,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=120,
        ).stdout
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise RefinementError(f"command failed: {' '.join(argv)}") from exc


def _git_revision(root: Path) -> str:
    return _run(["git", "-C", str(root), "rev-parse", "HEAD"])


def _compiler_version(compiler: Path) -> str:
    output = _run([str(compiler), "--version"])
    match = re.search(r"\b(\d+\.\d+\.\d+)\b", output)
    if match is None:
        raise RefinementError(f"could not parse Sail version from {output!r}")
    return match.group(1)


def _profile(repository_root: Path) -> dict[str, object]:
    profile_path = repository_root / PROFILE_PATH
    profile = codec.load_json(profile_path)
    try:
        authority = profile["authorities"]["sail"]
        transport = profile["rvfi_transport"]
        configured_overrides = tuple(
            Path(path) for path in authority["configuration_overrides_in_order"]
        )
        if (
            profile["schema"] != "stwo-riscv-formal-profile-v1"
            or profile["name"] != "rv32im-zkvm-v1"
            or authority["repository"] != SAIL_REPOSITORY
            or authority["revision"] != SAIL_REVISION
            or authority["compiler"] != SAIL_VERSION
            or authority["base_configuration"] != "rv32"
            or authority["validated_isa_string"] != "rv32im"
            or configured_overrides != OVERRIDE_PATHS
            or Path(transport["patch"]["path"]) != PATCH_PATH
        ):
            raise RefinementError("normative RV32IM Sail profile drifted")
    except (KeyError, TypeError) as exc:
        raise RefinementError("normative RV32IM Sail profile is malformed") from exc
    patch_path = repository_root / PATCH_PATH
    if codec.sha256_file(patch_path) != transport["patch"]["sha256"]:
        raise RefinementError("normative Sail transport patch digest drifted")
    return profile


def _strip_line_comments(text: str) -> str:
    result: list[str] = []
    quoted = False
    escaped = False
    index = 0
    while index < len(text):
        character = text[index]
        if quoted:
            result.append(character)
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                quoted = False
            index += 1
            continue
        if character == '"':
            quoted = True
            result.append(character)
            index += 1
            continue
        if character == "/" and index + 1 < len(text) and text[index + 1] == "/":
            index += 2
            while index < len(text) and text[index] not in "\r\n":
                index += 1
            continue
        result.append(character)
        index += 1
    if quoted:
        raise RefinementError("Sail base configuration has an unterminated string")
    return "".join(result)


def _relaxed_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(_strip_line_comments(path.read_text(encoding="utf-8")))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RefinementError(f"{path}: invalid Sail configuration") from exc
    if not isinstance(value, dict):
        raise RefinementError(f"{path}: Sail configuration must be an object")
    return value


def _merge_configuration(
    base: dict[str, object],
    override: dict[str, object],
) -> dict[str, object]:
    result = copy.deepcopy(base)
    for key, value in override.items():
        current = result.get(key)
        if isinstance(current, dict) and isinstance(value, dict):
            result[key] = _merge_configuration(current, value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def exact_configuration(repository_root: Path, source_root: Path) -> bytes:
    base_path = source_root / BASE_CONFIGURATION
    if not base_path.is_file():
        raise RefinementError(
            f"{base_path}: generated Sail base configuration is absent; "
            "prepare the pinned formal tools first"
        )
    merged = _relaxed_json(base_path)
    for relative in OVERRIDE_PATHS:
        merged = _merge_configuration(
            merged,
            codec.load_json(repository_root / relative),
        )
    try:
        if (
            merged["base"]["xlen"] != 32
            or merged["extensions"]["M"]["supported"] is not True
            or any(
                merged["extensions"][extension]["supported"] is not False
                for extension in ("A", "F", "D")
            )
            or merged["extensions"]["V"]["support_level"] != "Disabled"
        ):
            raise RefinementError("merged Sail configuration is not RV32IM")
    except (KeyError, TypeError) as exc:
        raise RefinementError("merged Sail configuration is malformed") from exc
    return codec.pretty_bytes(merged)


def _checkout_state(
    repository_root: Path,
    source_root: Path,
    profile: dict[str, object],
) -> str:
    status = _run(
        [
            "git",
            "-C",
            str(source_root),
            "status",
            "--porcelain",
            "--untracked-files=no",
        ]
    )
    if not status:
        return "clean"
    expected = f"M {PATCHED_SOURCE.as_posix()}"
    if status != expected:
        raise RefinementError(
            f"pinned sail-riscv checkout has unexpected changes: {status!r}"
        )
    upstream = _run_bytes(
        [
            "git",
            "-C",
            str(source_root),
            "show",
            f"HEAD:{PATCHED_SOURCE.as_posix()}",
        ]
    )
    old = b"  return 0x80000000;"
    new = b"  return 0x00010000;"
    if upstream.count(old) != 1 or new in upstream:
        raise RefinementError("pinned Sail RVFI source shape drifted")
    if (source_root / PATCHED_SOURCE).read_bytes() != upstream.replace(old, new):
        raise RefinementError("Sail checkout contains more than the pinned RVFI patch")
    patch = profile["rvfi_transport"]["patch"]
    if codec.sha256_file(repository_root / PATCH_PATH) != patch["sha256"]:
        raise RefinementError("Sail RVFI patch identity drifted")
    return "rvfi-transport-patch-only"


def _extract_definition(text: str, name: str) -> str:
    marker = f"def {name} "
    try:
        start = text.index(marker)
    except ValueError as exc:
        raise RefinementError(f"generated Sail output has no {name}") from exc
    next_definition = re.search(r"\ndef [A-Za-z0-9_]+ ", text[start + 1 :])
    end = (
        start + 1 + next_definition.start()
        if next_definition is not None
        else len(text)
    )
    return text[start:end].rstrip() + "\n"


def _extract_source_slices(text: str) -> dict[str, str]:
    markers = {
        "UTYPE": (
            "union clause instruction = UTYPE",
            "// *****************************************************************\n\n// Jump",
        ),
        "ITYPE": (
            "union clause instruction = ITYPE",
            "// *****************************************************************\nunion clause instruction = SHIFTIOP",
        ),
    }
    result: dict[str, str] = {}
    for name, (start_marker, end_marker) in markers.items():
        try:
            start = text.index(start_marker)
            end = text.index(end_marker, start)
        except ValueError as exc:
            raise RefinementError(f"pinned Sail source has no complete {name} slice") from exc
        result[name] = text[start:end].rstrip() + "\n"
    return result


def _validate_semantic_shapes(definitions: dict[str, str]) -> None:
    utype = definitions["execute_UTYPE"]
    itype = definitions["execute_ITYPE"]
    required_utype = (
        "sign_extend (m := 32) (imm +++ 0x000#12)",
        "| .LUI => (pure off)",
        "(wX_bits rd",
        "(pure RETIRE_SUCCESS)",
    )
    required_itype = (
        "sign_extend (m := 32) imm",
        "| .ADDI => (pure ((← (rX_bits rs1)) + immext))",
        "(wX_bits rd",
        "(pure RETIRE_SUCCESS)",
    )
    for phrase in required_utype:
        if phrase not in utype:
            raise RefinementError(f"generated execute_UTYPE lost {phrase!r}")
    for phrase in required_itype:
        if phrase not in itype:
            raise RefinementError(f"generated execute_ITYPE lost {phrase!r}")


def discover_source(explicit: Path | None, repository_root: Path) -> Path:
    candidates: list[Path] = []
    if explicit is not None:
        candidates.append(explicit)
    configured = os.environ.get("STWO_SAIL_RISCV_DIR")
    if configured:
        candidates.append(Path(configured))
    candidates.extend(
        [
            repository_root / "zig-out" / "riscv-refinement" / "sail-riscv",
            Path("/tmp/stwo-riscv-formal/source/sail-riscv"),
        ]
    )
    for candidate in candidates:
        if (candidate / ".git").exists() and (candidate / "model").is_dir():
            return candidate.resolve()
    raise RefinementError(
        "pinned sail-riscv checkout not found; pass --sail-riscv-dir or set "
        "STWO_SAIL_RISCV_DIR"
    )


def discover_compiler(explicit: Path | None) -> Path:
    if explicit is not None:
        candidate = explicit
    elif os.environ.get("SAIL"):
        candidate = Path(os.environ["SAIL"])
    else:
        found = shutil.which("sail")
        if found is None:
            fallback = Path.home() / ".opam" / "default" / "bin" / "sail"
            candidate = fallback
        else:
            candidate = Path(found)
    if not candidate.is_file():
        raise RefinementError("Sail compiler not found; pass --sail-bin")
    return candidate.resolve()


def _generated_file(source_root: Path, explicit: Path | None) -> Path:
    expected = (source_root / GENERATED_FILE).resolve()
    candidate = explicit.resolve() if explicit is not None else expected
    if candidate != expected:
        raise RefinementError(
            f"generated Sail file must be the exact RV32IM output {expected}"
        )
    if not candidate.is_file():
        raise RefinementError(
            "generated RV32IM Lean model is absent; run "
            "scripts/riscv_refinement.py prepare-sail"
        )
    return candidate


def _validate_exact_configuration(
    source_root: Path,
    configuration_path: Path,
) -> tuple[Path, str]:
    simulator = source_root / SIMULATOR
    if not simulator.is_file():
        raise RefinementError(
            f"{simulator}: pinned Sail simulator is absent; prepare the formal "
            "tools first"
        )
    _run(
        [
            str(simulator),
            "--config",
            str(configuration_path),
            "--validate-config",
        ]
    )
    isa = _run(
        [
            str(simulator),
            "--config",
            str(configuration_path),
            "--print-isa-string",
        ]
    )
    if isa.splitlines()[-1] != "rv32im":
        raise RefinementError(
            f"exact Sail configuration reports {isa!r}, expected rv32im"
        )
    resolved = simulator.resolve()
    return resolved, codec.sha256_file(resolved)


def prepare_exact_backend(
    repository_root: Path,
    source_root: Path | None,
    compiler: Path | None,
    force: bool,
) -> SailEvidence:
    root = discover_source(source_root, repository_root)
    profile = _profile(repository_root)
    revision = _git_revision(root)
    if revision != SAIL_REVISION:
        raise RefinementError(
            f"sail-riscv revision {revision} does not match pin {SAIL_REVISION}"
        )
    _checkout_state(repository_root, root, profile)
    sail_bin = discover_compiler(compiler)
    version = _compiler_version(sail_bin)
    if version != SAIL_VERSION:
        raise RefinementError(
            f"Sail compiler {version} does not match required {SAIL_VERSION}"
        )

    configuration = exact_configuration(repository_root, root)
    configuration_path = root / EXACT_CONFIGURATION
    changed = (
        not configuration_path.is_file()
        or configuration_path.read_bytes() != configuration
    )
    codec.atomic_write(configuration_path, configuration)
    _validate_exact_configuration(root, configuration_path)

    generated = root / GENERATED_FILE
    if force or changed or not generated.is_file():
        generated.parent.parent.parent.mkdir(parents=True, exist_ok=True)
        output_root = root / "build" / "riscv-refinement"
        memo_root = output_root / "sail_smt_cache"
        output_root.mkdir(parents=True, exist_ok=True)
        if memo_root.is_dir():
            if any(memo_root.iterdir()):
                raise RefinementError(
                    f"{memo_root}: Sail memo path must be a file, not a "
                    "nonempty directory"
                )
            memo_root.rmdir()
        _run(
            [
                str(sail_bin),
                "--strict-var",
                "--strict-bitvector",
                "--strict-exponentials",
                "--require-version",
                SAIL_VERSION,
                "--memo-z3-path",
                str(memo_root),
                "--config",
                str(configuration_path),
                "--lean",
                "--memo-z3",
                "--lean-output-dir",
                str(output_root),
                "--lean-force-output",
                "--lean-non-beq-type",
                "instruction",
                "--lean-non-beq-type",
                "ExecutionResult",
                "--lean-non-beq-type",
                "Step",
                "--lean-noncomputable",
                "--lean-noncomputable-function",
                "encdec_forwards",
                "--lean-noncomputable-function",
                "encdec_backwards",
                "--lean-noncomputable-function",
                "encdec_forwards_matches",
                "--lean-noncomputable-function",
                "encdec_backwards_matches",
                "--lean-noncomputable-function",
                "encdec_compressed_forwards",
                "--lean-noncomputable-function",
                "encdec_compressed_backwards",
                "--lean-noncomputable-function",
                "encdec_compressed_forwards_matches",
                "--lean-noncomputable-function",
                "encdec_compressed_backwards_matches",
                "--lean-import-file",
                "../handwritten_support/RiscvExtras.lean",
                "-o",
                "Lean_RV32IM",
                "--all-modules",
                MODEL_ENTRY.name,
            ],
            cwd=root / "model",
            timeout=1800,
        )
    return collect_evidence(
        repository_root,
        root,
        sail_bin,
        generated,
    )


def collect_evidence(
    repository_root: Path,
    source_root: Path | None,
    compiler: Path | None,
    generated_file: Path | None,
) -> SailEvidence:
    root = discover_source(source_root, repository_root)
    profile = _profile(repository_root)
    revision = _git_revision(root)
    if revision != SAIL_REVISION:
        raise RefinementError(
            f"sail-riscv revision {revision} does not match pin {SAIL_REVISION}"
        )
    sail_bin = discover_compiler(compiler)
    version = _compiler_version(sail_bin)
    if version != SAIL_VERSION:
        raise RefinementError(
            f"Sail compiler {version} does not match required {SAIL_VERSION}"
        )
    checkout_state = _checkout_state(repository_root, root, profile)
    configuration = exact_configuration(repository_root, root)
    configuration_path = root / EXACT_CONFIGURATION
    if (
        not configuration_path.is_file()
        or configuration_path.read_bytes() != configuration
    ):
        raise RefinementError(
            "exact RV32IM Sail configuration is absent or stale; run "
            "scripts/riscv_refinement.py prepare-sail"
        )
    simulator, simulator_sha256 = _validate_exact_configuration(
        root,
        configuration_path,
    )
    generated = _generated_file(root, generated_file)
    source = root / SOURCE_FILE
    generated_text = generated.read_text(encoding="utf-8")
    source_text = source.read_text(encoding="utf-8")
    definitions = {
        name: _extract_definition(generated_text, name)
        for name in GENERATED_DEFINITION_HASHES
    }
    definition_hashes = {
        name: codec.sha256_bytes(block.encode("utf-8"))
        for name, block in definitions.items()
    }
    if definition_hashes != GENERATED_DEFINITION_HASHES:
        raise RefinementError(
            "pinned Sail theorem-backend definitions drifted; review before "
            "updating the normalized capsule"
        )
    slices = _extract_source_slices(source_text)
    slice_hashes = {
        name: codec.sha256_bytes(block.encode("utf-8"))
        for name, block in slices.items()
    }
    if slice_hashes != SOURCE_SLICE_HASHES:
        raise RefinementError(
            "pinned Sail source slices drifted; review before updating the bridge"
        )
    _validate_semantic_shapes(definitions)
    profile_files = (PROFILE_PATH, *OVERRIDE_PATHS, PATCH_PATH)
    return SailEvidence(
        source_root=root,
        compiler=sail_bin,
        compiler_sha256=codec.sha256_file(sail_bin),
        simulator_sha256=simulator_sha256,
        generated_file=generated,
        generated_file_sha256=codec.sha256_file(generated),
        source_file_sha256=codec.sha256_file(source),
        model_entry_sha256=codec.sha256_file(root / MODEL_ENTRY),
        base_configuration_sha256=codec.sha256_file(root / BASE_CONFIGURATION),
        exact_configuration=configuration,
        exact_configuration_sha256=codec.sha256_bytes(configuration),
        profile_file_sha256={
            relative.as_posix(): codec.sha256_file(repository_root / relative)
            for relative in profile_files
        },
        checkout_state=checkout_state,
        definition_hashes=definition_hashes,
        source_slice_hashes=slice_hashes,
    )


def provenance(evidence: SailEvidence) -> dict[str, object]:
    return {
        "repository": SAIL_REPOSITORY,
        "revision": SAIL_REVISION,
        "checkout_state": evidence.checkout_state,
        "compiler_version": SAIL_VERSION,
        "compiler_sha256": evidence.compiler_sha256,
        "simulator_sha256": evidence.simulator_sha256,
        "architectural_profile": "rv32im-zkvm-v1",
        "profile_file_sha256": evidence.profile_file_sha256,
        "model_entry": MODEL_ENTRY.as_posix(),
        "model_entry_sha256": evidence.model_entry_sha256,
        "base_configuration": BASE_CONFIGURATION.as_posix(),
        "base_configuration_sha256": evidence.base_configuration_sha256,
        "exact_configuration": EXACT_CONFIGURATION.as_posix(),
        "exact_configuration_sha256": evidence.exact_configuration_sha256,
        "validated_isa_string": "rv32im",
        "source_file": SOURCE_FILE.as_posix(),
        "source_file_sha256": evidence.source_file_sha256,
        "generated_backend_file": GENERATED_FILE.as_posix(),
        "generated_backend_file_sha256": evidence.generated_file_sha256,
        "generated_definition_sha256": evidence.definition_hashes,
        "source_slice_sha256": evidence.source_slice_hashes,
        "normalization": "reviewed exact-hash LUI and ADDI expression capsule",
        "generated_monad_normalization_theorem": False,
    }
