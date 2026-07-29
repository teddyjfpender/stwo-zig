"""Kernel-check the pilot bridge against the exact generated Sail project."""

from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any

from . import codec
from .model import LEAN_TOOLCHAIN, Paths, RefinementError

SCHEMA_VERSION = "stwo-generated-sail-monad-bridge-v1"
BRIDGE_SOURCE = Path(
    "formal/riscv-refinement/generated-sail-bridge/Pilot.lean"
)
SUPPORT_PATCH = Path("conformance/riscv/sail-lean-riscv-extras.patch")
COMMITTED_RECEIPT = Path(
    "generated/sail/generated-monad-bridge-receipt-v1.json"
)
LEAN_SAIL_REVISION = "79b4d08505af29d88b3918f32d29840fae1fa191"
SUPPORT_PATCH_SHA256 = (
    "ceb85e86b94a9f254502373f821198f9dfd3019105b77dc7987818b2a4388070"
)
PATCHED_SUPPORT_SHA256 = (
    "7d774a62134bd79b6a0bebd85ce2f215a2a3ce3552e74d4e3c9ac4c9ed24e95c"
)
GENERATED_MODULE_SHA256 = {
    "LeanRV32IM/Callbacks.lean":
        "08dbceb93ab1e5711e51f28127c6999b9d15331a13ac6317a4a096bc22d6e194",
    "LeanRV32IM/Defs.lean":
        "48049c73d2445dc9e84526b797ea31217082a54239d7a9f59e680dd303170b09",
    "LeanRV32IM/InstsBegin.lean":
        "e7dfdc19a7be526cffdd27e4eb63289a5b8640135f30164a98fd56a127e8d7d8",
    "LeanRV32IM/InstsEnd.lean":
        "074d61135954f165c3490630aec286f28638ba99f1c64c92056bd3c29c05c21a",
    "LeanRV32IM/PcAccess.lean":
        "5664b05b4d12ec41a9928adaf5767ebfe34b8e4bd103ed2d64764294812c727d",
    "LeanRV32IM/Regs.lean":
        "0ef72eb67e9628999a3e738394cbdd7915381006cb807ab16121fe0695230af5",
    "LeanRV32IM/RiscvExtras.lean": PATCHED_SUPPORT_SHA256,
}
THEOREMS = (
    "LeanRV32IM.Functions.execute_LUI_normalizes_write",
    "LeanRV32IM.Functions.execute_ADDI_normalizes_write",
    "LeanRV32IM.Functions.complete_LUI_normalizes",
    "LeanRV32IM.Functions.complete_ADDI_normalizes",
)
APPROVED_AXIOMS = frozenset(
    {
        "propext",
        "Classical.choice",
        "Quot.sound",
    }
)
CLAIM_BOUNDARY = {
    "generated_execute_clause_monad_normalization": True,
    "sequential_next_pc_and_tick_fragment": True,
    "fetch_interrupt_trap_and_step_loop_framing": False,
}
_UNPATCHED_OPEN = b"open LeanRV32IM.Defs\n\n"
_AXIOM_LINE = re.compile(
    r"^'([^']+)' depends on axioms: \[([^\]]*)\]$",
    re.MULTILINE,
)
_PROOF_ESCAPES = re.compile(
    r"\b(?:sorry|admit|axiom|native_decide)\b"
)


def _run(
    argv: list[str],
    cwd: Path,
    *,
    env: dict[str, str] | None = None,
    timeout: int = 1800,
) -> str:
    try:
        completed = subprocess.run(
            argv,
            cwd=cwd,
            env=env,
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
            if len(detail) > 8000:
                detail = "... " + detail[-8000:]
        raise RefinementError(
            "generated Sail Lean bridge command failed: "
            + " ".join(argv)
            + (f": {detail}" if detail else "")
        ) from exc
    return completed.stdout.strip()


def _project(generated_file: Path) -> Path:
    generated = generated_file.resolve()
    project = generated.parent.parent
    if (
        generated.name != "InstsEnd.lean"
        or generated.parent.name != "LeanRV32IM"
        or not (project / "lakefile.toml").is_file()
        or not (project / "lean-toolchain").is_file()
    ):
        raise RefinementError(
            "generated Sail backend is not inside a Lean_RV32IM project"
        )
    return project


def _patch_support(paths: Paths, project: Path) -> None:
    patch = paths.root / SUPPORT_PATCH
    if (
        patch.is_symlink()
        or not patch.is_file()
        or codec.sha256_file(patch) != SUPPORT_PATCH_SHA256
    ):
        raise RefinementError(
            "generated Sail Lean support patch identity drifted"
        )
    support = project / "LeanRV32IM" / "RiscvExtras.lean"
    if support.is_symlink() or not support.is_file():
        raise RefinementError(
            "generated Sail project has no regular RiscvExtras.lean"
        )
    data = support.read_bytes()
    if _UNPATCHED_OPEN in data:
        if data.count(_UNPATCHED_OPEN) != 1:
            raise RefinementError(
                "generated RiscvExtras namespace patch anchor is ambiguous"
            )
        codec.atomic_write(support, data.replace(_UNPATCHED_OPEN, b""))
    if codec.sha256_file(support) != PATCHED_SUPPORT_SHA256:
        raise RefinementError(
            "generated RiscvExtras differs beyond the pinned namespace fix"
        )


def _lean_sail_revision(project: Path) -> str:
    manifest = project / "lake-manifest.json"
    if not manifest.is_file():
        _run(["lake", "update"], project, timeout=600)
    try:
        payload = json.loads(manifest.read_text(encoding="utf-8"))
        packages = payload["packages"]
        matches = [
            package
            for package in packages
            if package.get("name") == "Sail"
        ]
        revision = matches[0]["rev"]
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError, IndexError) as exc:
        raise RefinementError(
            "generated Sail project dependency manifest is malformed"
        ) from exc
    if len(matches) != 1 or revision != LEAN_SAIL_REVISION:
        raise RefinementError(
            "generated Sail project resolved an unpinned lean-sail revision"
        )
    return revision


def _source_closure(project: Path) -> tuple[int, str]:
    sources = sorted((project / "LeanRV32IM").glob("*.lean"))
    if not sources:
        raise RefinementError("generated Sail Lean source closure is empty")
    mapping = {
        source.relative_to(project).as_posix(): codec.sha256_file(source)
        for source in sources
        if not source.is_symlink() and source.is_file()
    }
    if len(mapping) != len(sources):
        raise RefinementError(
            "generated Sail Lean source closure contains a non-regular file"
        )
    for relative, expected in GENERATED_MODULE_SHA256.items():
        if mapping.get(relative) != expected:
            raise RefinementError(
                f"generated Sail bridge input drifted: {relative}"
            )
    return len(mapping), codec.sha256_bytes(codec.canonical_bytes(mapping))


def _proof_axioms(output: str) -> dict[str, list[str]]:
    found: dict[str, list[str]] = {}
    for theorem, raw_axioms in _AXIOM_LINE.findall(output):
        axioms = [
            axiom.strip()
            for axiom in raw_axioms.split(",")
            if axiom.strip()
        ]
        if theorem in found:
            raise RefinementError(
                f"generated Sail bridge repeated axiom output for {theorem}"
            )
        found[theorem] = sorted(axioms)
    if set(found) != set(THEOREMS):
        raise RefinementError(
            "generated Sail bridge axiom inventory is incomplete: "
            f"found={sorted(found)}, expected={sorted(THEOREMS)}"
        )
    unexpected = {
        axiom
        for axioms in found.values()
        for axiom in axioms
        if axiom not in APPROVED_AXIOMS
    }
    if unexpected:
        raise RefinementError(
            "generated Sail bridge uses unapproved axioms: "
            + ", ".join(sorted(unexpected))
        )
    return {theorem: found[theorem] for theorem in THEOREMS}


def _static_identity(
    paths: Paths,
    generated_backend_sha256: str,
) -> dict[str, Any]:
    bridge = paths.root / BRIDGE_SOURCE
    if bridge.is_symlink() or not bridge.is_file():
        raise RefinementError("generated Sail monad bridge source is absent")
    try:
        bridge_text = bridge.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise RefinementError(
            "generated Sail monad bridge source is unreadable"
        ) from exc
    stripped_comments = re.sub(r"/-!.*?-/", "", bridge_text, flags=re.DOTALL)
    if _PROOF_ESCAPES.search(stripped_comments):
        raise RefinementError(
            "generated Sail monad bridge contains a forbidden proof escape"
        )
    capsule = paths.formal / "RiscvRefinement/Sail/Generated/Pilot.lean"
    if capsule.is_symlink() or not capsule.is_file():
        raise RefinementError(
            "normalized generated Sail pilot capsule is absent"
        )
    return {
        "generated_backend_sha256": generated_backend_sha256,
        "bridge_source": BRIDGE_SOURCE.as_posix(),
        "bridge_source_sha256": codec.sha256_file(bridge),
        "normalized_capsule":
            "RiscvRefinement/Sail/Generated/Pilot.lean",
        "normalized_capsule_sha256": codec.sha256_file(capsule),
        "support_patch": SUPPORT_PATCH.as_posix(),
        "support_patch_sha256": codec.sha256_file(
            paths.root / SUPPORT_PATCH
        ),
        "lean_toolchain": LEAN_TOOLCHAIN,
        "lean_sail_revision": LEAN_SAIL_REVISION,
        "generated_module_sha256": dict(GENERATED_MODULE_SHA256),
        "theorems": list(THEOREMS),
        "claim_boundary": dict(CLAIM_BOUNDARY),
    }


def verify(
    paths: Paths,
    generated_file: Path,
    generated_backend_sha256: str,
) -> dict[str, Any]:
    """Build the exact generated project and kernel-check the cross bridge."""
    project = _project(generated_file)
    if codec.sha256_file(generated_file) != generated_backend_sha256:
        raise RefinementError(
            "generated Sail bridge backend digest does not match its evidence"
        )
    _patch_support(paths, project)
    revision = _lean_sail_revision(project)
    toolchain = (
        project / "lean-toolchain"
    ).read_text(encoding="utf-8").strip()
    if toolchain != LEAN_TOOLCHAIN:
        raise RefinementError(
            "generated Sail project Lean toolchain does not match the proof "
            "project"
        )
    source_count, source_digest = _source_closure(project)
    _run(["lake", "build", "LeanRV32IM"], project)
    _run(
        ["lake", "build", "RiscvRefinement.Sail.Generated.Pilot"],
        paths.formal,
        timeout=600,
    )
    environment = dict(os.environ)
    formal_lean_path = paths.formal / ".lake" / "build" / "lib" / "lean"
    inherited = environment.get("LEAN_PATH")
    environment["LEAN_PATH"] = (
        str(formal_lean_path)
        if not inherited
        else f"{formal_lean_path}{os.pathsep}{inherited}"
    )
    output = _run(
        [
            "lake",
            "env",
            "lean",
            "--tstack=400000",
            str(paths.root / BRIDGE_SOURCE),
        ],
        project,
        env=environment,
        timeout=600,
    )
    receipt: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "kind": "stwo-generated-sail-monad-bridge",
        "evidence_source": "exact-pinned-generated-backend",
        **_static_identity(paths, generated_backend_sha256),
        "lean_sail_revision": revision,
        "generated_source_count": source_count,
        "generated_source_closure_sha256": source_digest,
        "theorem_axioms": _proof_axioms(output),
    }
    receipt["canonical_digest"] = codec.content_digest(receipt)
    return receipt


def validate_carried(
    paths: Paths,
    receipt: dict[str, Any],
    generated_backend_sha256: str,
) -> dict[str, Any]:
    """Validate the committed proof receipt without pretending to rebuild it."""
    if (
        receipt.get("schema_version") != SCHEMA_VERSION
        or receipt.get("kind") != "stwo-generated-sail-monad-bridge"
        or receipt.get("evidence_source")
        != "exact-pinned-generated-backend"
        or receipt.get("canonical_digest") != codec.content_digest(receipt)
    ):
        raise RefinementError(
            "committed generated Sail monad bridge receipt identity is invalid"
        )
    static = _static_identity(paths, generated_backend_sha256)
    for key, expected in static.items():
        actual = receipt.get(key)
        if key == "theorems":
            if actual != expected:
                raise RefinementError(
                    "committed generated Sail bridge theorem list drifted"
                )
        elif actual != expected:
            raise RefinementError(
                f"committed generated Sail bridge field {key} drifted"
            )
    if (
        not isinstance(receipt.get("generated_source_count"), int)
        or receipt["generated_source_count"] <= 0
        or re.fullmatch(
            r"[0-9a-f]{64}",
            str(receipt.get("generated_source_closure_sha256")),
        )
        is None
        or receipt.get("theorem_axioms")
        != {theorem: sorted(APPROVED_AXIOMS) for theorem in THEOREMS}
    ):
        raise RefinementError(
            "committed generated Sail bridge proof inventory is invalid"
        )
    return receipt
