"""Self-contained literal Zig import closure used for H-010 provenance."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path


class ClosureError(ValueError):
    """A declared source root or literal import cannot be resolved."""


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
            "allowed_prefixes": sorted(self.allowed_prefixes),
        }

    def digest(self) -> str:
        encoded = json.dumps(
            self.canonical(), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def validate(self, repository: Path) -> None:
        if not self.product or not self.entry_roots or not self.allowed_prefixes:
            raise ClosureError("source-closure manifest has an empty required field")
        names = [item.name for item in self.named_imports]
        if any(not name for name in names) or len(names) != len(set(names)):
            raise ClosureError("source-closure manifest has invalid named imports")
        if set(names).intersection(self.generated_imports):
            raise ClosureError("source import is both named and generated")
        for raw in (
            *self.entry_roots,
            *(item.source for item in self.named_imports),
            *self.allowed_prefixes,
        ):
            _repository_path(repository, raw, require_file=False)


@dataclass(frozen=True)
class SourceGraph:
    repository: Path
    sources: frozenset[Path]

    def relative_sources(self) -> tuple[str, ...]:
        return tuple(
            sorted(str(path.relative_to(self.repository)) for path in self.sources)
        )

    def source_digest(self) -> str:
        digest = hashlib.sha256()
        for relative in self.relative_sources():
            content = (self.repository / relative).read_bytes()
            digest.update(relative.encode("utf-8"))
            digest.update(b"\0")
            digest.update(hashlib.sha256(content).digest())
        return digest.hexdigest()


def inspect_sources(repository: Path, manifest: Manifest) -> SourceGraph:
    repository = repository.resolve()
    manifest.validate(repository)
    named = {
        item.name: _repository_path(repository, item.source)
        for item in manifest.named_imports
    }
    pending = [_repository_path(repository, raw) for raw in manifest.entry_roots]
    sources: set[Path] = set()
    while pending:
        source = pending.pop()
        if source in sources:
            continue
        sources.add(source)
        for imported in literal_imports(source.read_text(encoding="utf-8")):
            if imported in manifest.generated_imports:
                continue
            if imported in named:
                target = named[imported]
            elif imported.endswith(".zig"):
                target = (source.parent / imported).resolve()
                try:
                    target.relative_to(repository)
                except ValueError as error:
                    raise ClosureError(
                        f"{source.relative_to(repository)}: import escapes repository"
                    ) from error
                if not target.is_file():
                    raise ClosureError(
                        f"{source.relative_to(repository)}: unresolved import {imported!r}"
                    )
            else:
                raise ClosureError(
                    f"{source.relative_to(repository)}: undeclared named import {imported!r}"
                )
            if target not in sources:
                pending.append(target)
    graph = SourceGraph(repository, frozenset(sources))
    for relative in graph.relative_sources():
        if not any(
            relative == prefix.rstrip("/")
            or relative.startswith(prefix.rstrip("/") + "/")
            for prefix in manifest.allowed_prefixes
        ):
            raise ClosureError(f"source outside H-010 closure owners: {relative}")
    return graph


def _repository_path(
    repository: Path,
    raw: str,
    *,
    require_file: bool = True,
) -> Path:
    if not raw or Path(raw).is_absolute():
        raise ClosureError(f"invalid repository-relative source path: {raw!r}")
    resolved = (repository / raw).resolve()
    try:
        resolved.relative_to(repository)
    except ValueError as error:
        raise ClosureError(f"source path escapes repository: {raw}") from error
    if require_file and not resolved.is_file():
        raise ClosureError(f"missing source file: {raw}")
    if not require_file and not resolved.exists():
        raise ClosureError(f"missing source owner: {raw}")
    return resolved


def literal_imports(source: str) -> tuple[str, ...]:
    imports: list[str] = []
    index = 0
    while index < len(source):
        following = source[index + 1] if index + 1 < len(source) else ""
        if source[index] == "/" and following == "/":
            index = _skip_line(source, index)
        elif source[index] == "\\" and following == "\\":
            index = _skip_line(source, index)
        elif source[index] in {'"', "'"}:
            index = _skip_quoted(source, index, source[index])
        elif source.startswith("@import", index):
            imported, index = _parse_import(source, index)
            imports.append(imported)
        else:
            index += 1
    return tuple(imports)


def _parse_import(source: str, start: int) -> tuple[str, int]:
    index = _skip_space(source, start + len("@import"))
    if index >= len(source) or source[index] != "(":
        raise ClosureError("unsupported non-literal @import expression")
    index = _skip_space(source, index + 1)
    if index >= len(source) or source[index] != '"':
        raise ClosureError("unsupported non-literal @import expression")
    end = index + 1
    while end < len(source) and source[end] != '"':
        if source[end] in {"\\", "\n", "\r"}:
            raise ClosureError("escaped or multiline Zig import is unsupported")
        end += 1
    if end >= len(source):
        raise ClosureError("unterminated Zig import path")
    imported = source[index + 1 : end]
    index = _skip_space(source, end + 1)
    if index >= len(source) or source[index] != ")":
        raise ClosureError("unsupported non-literal @import expression")
    return imported, index + 1


def _skip_space(source: str, index: int) -> int:
    while index < len(source) and source[index].isspace():
        index += 1
    return index


def _skip_line(source: str, index: int) -> int:
    newline = source.find("\n", index)
    return len(source) if newline < 0 else newline + 1


def _skip_quoted(source: str, index: int, quote: str) -> int:
    index += 1
    while index < len(source):
        if source[index] == "\\":
            index += 2
        elif source[index] == quote:
            return index + 1
        else:
            index += 1
    raise ClosureError("unterminated Zig string or character literal")
