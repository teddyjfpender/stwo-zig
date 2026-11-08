"""Validated inputs for a focused product closure check."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class NamedImport:
    name: str
    source: str


@dataclass(frozen=True)
class Manifest:
    product: str
    entry_roots: tuple[str, ...]
    named_imports: tuple[NamedImport, ...]
    generated_imports: frozenset[str]
    allowed_files: frozenset[str]
    allowed_prefixes: tuple[str, ...]

    def canonical(self) -> dict[str, object]:
        return {
            "product": self.product,
            "entry_roots": sorted(self.entry_roots),
            "named_imports": {
                item.name: item.source
                for item in sorted(self.named_imports, key=lambda item: item.name)
            },
            "generated_imports": sorted(self.generated_imports),
            "allowed_files": sorted(self.allowed_files),
            "allowed_prefixes": sorted(self.allowed_prefixes),
        }

    def digest(self) -> str:
        payload = json.dumps(
            self.canonical(), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    def validate(self, repository: Path) -> list[str]:
        errors: list[str] = []
        if not self.product:
            errors.append("product identity is empty")
        if not self.entry_roots:
            errors.append("source manifest has no entry roots")
        if not self.allowed_files and not self.allowed_prefixes:
            errors.append("source manifest has no allowed source owners")

        names: set[str] = set()
        for item in self.named_imports:
            if not item.name:
                errors.append("named import has an empty name")
            elif item.name in names:
                errors.append(f"duplicate named import {item.name!r}")
            names.add(item.name)
        overlap = names.intersection(self.generated_imports)
        for name in sorted(overlap):
            errors.append(f"import {name!r} is both named and generated")

        declared = list(self.entry_roots)
        declared.extend(item.source for item in self.named_imports)
        declared.extend(self.allowed_files)
        declared.extend(self.allowed_prefixes)
        for raw in declared:
            errors.extend(validate_repository_path(repository, raw))
        return errors


def validate_repository_path(repository: Path, raw: str) -> list[str]:
    if not raw:
        return ["source manifest contains an empty path"]
    candidate = Path(raw)
    if candidate.is_absolute():
        return [f"source manifest path must be repository-relative: {raw}"]
    resolved = (repository / candidate).resolve()
    try:
        resolved.relative_to(repository.resolve())
    except ValueError:
        return [f"source manifest path escapes repository: {raw}"]
    if not resolved.exists():
        return [f"source manifest path does not exist: {raw}"]
    return []


def parse_named_import(raw: str) -> NamedImport:
    name, separator, source = raw.partition("=")
    if not separator or not name or not source:
        raise ValueError(f"named import must be NAME=PATH, got {raw!r}")
    return NamedImport(name=name, source=source)
