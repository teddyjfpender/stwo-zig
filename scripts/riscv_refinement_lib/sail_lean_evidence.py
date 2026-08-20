"""Generated Sail definition and kernel-axiom evidence parsing."""

from __future__ import annotations

import re
from pathlib import Path

from . import codec
from .model import RefinementError


def source_closure(project: Path) -> tuple[int, str]:
    from .sail_lean_bridge import GENERATED_MODULE_SHA256

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
            raise RefinementError(f"generated Sail bridge input drifted: {relative}")
    return len(mapping), codec.sha256_bytes(codec.canonical_bytes(mapping))


def extract_definition(text: str, name: str) -> str:
    marker = f"def {name} "
    try:
        start = text.index(marker)
    except ValueError as exc:
        raise RefinementError(
            f"generated Sail output has no {name}"
        ) from exc
    next_definition = re.search(
        r"\ndef [A-Za-z0-9_]+ ",
        text[start + 1 :],
    )
    end = (
        start + 1 + next_definition.start()
        if next_definition is not None
        else len(text)
    )
    return text[start:end].rstrip() + "\n"


def validate_selector_source_digests(generated_file: Path) -> None:
    from .sail_lean_bridge import GENERATED_EXECUTE_DEFINITION_SHA256

    try:
        generated_text = generated_file.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise RefinementError(
            "generated Sail execute definitions are unreadable"
        ) from exc
    actual = {
        name: codec.sha256_bytes(
            extract_definition(generated_text, name).encode("utf-8")
        )
        for name in GENERATED_EXECUTE_DEFINITION_SHA256
    }
    if actual != GENERATED_EXECUTE_DEFINITION_SHA256:
        changed = sorted(
            name
            for name, digest in actual.items()
            if GENERATED_EXECUTE_DEFINITION_SHA256.get(name) != digest
        )
        raise RefinementError(
            "generated Sail publication execute definitions drifted: "
            + ", ".join(changed)
        )


def proof_axioms(output: str) -> dict[str, list[str]]:
    from .sail_lean_bridge import (
        APPROVED_AXIOMS,
        EXPECTED_THEOREM_AXIOMS,
        THEOREMS,
        _AXIOM_LINE,
    )

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
    ordered = {theorem: found[theorem] for theorem in THEOREMS}
    if ordered != EXPECTED_THEOREM_AXIOMS:
        raise RefinementError(
            "generated Sail bridge axiom inventory drifted from the exact "
            "per-theorem contract"
        )
    return ordered
