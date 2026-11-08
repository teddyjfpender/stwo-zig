"""Resolve and validate a focused Zig product's transitive source graph."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from .model import Manifest


class ClosureError(ValueError):
    pass


@dataclass(frozen=True)
class SourceGraph:
    repository: Path
    sources: frozenset[Path]
    edges: dict[Path, frozenset[Path]]
    named_edges: frozenset[tuple[Path, Path]]

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
    errors = manifest.validate(repository)
    if errors:
        raise ClosureError("\n".join(errors))

    named = {
        item.name: source_path(repository, item.source) for item in manifest.named_imports
    }
    pending = [source_path(repository, raw) for raw in manifest.entry_roots]
    sources: set[Path] = set()
    edges: dict[Path, frozenset[Path]] = {}
    named_edges: set[tuple[Path, Path]] = set()
    while pending:
        source = pending.pop()
        if source in sources:
            continue
        require_file(repository, source)
        sources.add(source)
        targets, source_named_edges = resolve_imports(
            repository, source, named, manifest.generated_imports
        )
        edges[source] = frozenset(targets)
        named_edges.update((source, target) for target in source_named_edges)
        pending.extend(target for target in targets if target not in sources)

    graph = SourceGraph(repository, frozenset(sources), edges, frozenset(named_edges))
    cycle = find_named_cycle(graph)
    if cycle:
        rendered = " -> ".join(str(path.relative_to(repository)) for path in cycle)
        raise ClosureError(f"source import cycle: {rendered}")
    violations = [
        relative
        for relative in graph.relative_sources()
        if not is_allowed(relative, manifest)
    ]
    if violations:
        raise ClosureError(
            "\n".join(f"source outside product manifest: {path}" for path in violations)
        )
    return graph


def resolve_imports(
    repository: Path,
    source: Path,
    named: dict[str, Path],
    generated: frozenset[str],
) -> tuple[set[Path], set[Path]]:
    targets: set[Path] = set()
    named_targets: set[Path] = set()
    try:
        imports = literal_imports(source.read_text(encoding="utf-8"))
    except ClosureError as error:
        relative = source.relative_to(repository)
        raise ClosureError(f"{relative}: {error}") from error
    for imported in imports:
        if imported in generated:
            continue
        if imported in named:
            target = named[imported]
            targets.add(target)
            named_targets.add(target)
            continue
        if not imported.endswith(".zig"):
            relative = source.relative_to(repository)
            raise ClosureError(f"{relative}: undeclared named import {imported!r}")
        target = (source.parent / imported).resolve()
        try:
            target.relative_to(repository)
        except ValueError as error:
            relative = source.relative_to(repository)
            raise ClosureError(f"{relative}: import escapes repository: {imported}") from error
        require_file(repository, target, source, imported)
        targets.add(target)
    return targets, named_targets


def literal_imports(source: str) -> tuple[str, ...]:
    imports: list[str] = []
    index = 0
    while index < len(source):
        char = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if char == "/" and following == "/":
            index = skip_line(source, index)
            continue
        if char == "\\" and following == "\\":
            index = skip_line(source, index)
            continue
        if char in {'"', "'"}:
            index = skip_quoted(source, index, char)
            continue
        if source.startswith("@import", index):
            imported, index = parse_import(source, index)
            imports.append(imported)
            continue
        index += 1
    return tuple(imports)


def parse_import(source: str, start: int) -> tuple[str, int]:
    index = start + len("@import")
    index = skip_space(source, index)
    if index >= len(source) or source[index] != "(":
        raise ClosureError("unsupported non-literal @import expression")
    index = skip_space(source, index + 1)
    if index >= len(source) or source[index] != '"':
        raise ClosureError("unsupported non-literal @import expression")
    end = index + 1
    while end < len(source) and source[end] != '"':
        if source[end] in {"\\", "\n", "\r"}:
            raise ClosureError("escaped or multiline Zig import paths are unsupported")
        end += 1
    if end >= len(source):
        raise ClosureError("unterminated Zig import path")
    imported = source[index + 1 : end]
    index = skip_space(source, end + 1)
    if index < len(source) and source[index] == ",":
        index = skip_space(source, index + 1)
    if index >= len(source) or source[index] != ")":
        raise ClosureError("unsupported non-literal @import expression")
    return imported, index + 1


def skip_space(source: str, index: int) -> int:
    while index < len(source) and source[index].isspace():
        index += 1
    return index


def skip_line(source: str, index: int) -> int:
    newline = source.find("\n", index)
    return len(source) if newline < 0 else newline + 1


def skip_quoted(source: str, index: int, quote: str) -> int:
    index += 1
    while index < len(source):
        if source[index] == "\\":
            index += 2
        elif source[index] == quote:
            return index + 1
        else:
            index += 1
    raise ClosureError("unterminated Zig string or character literal")


def find_named_cycle(graph: SourceGraph) -> tuple[Path, ...] | None:
    visited: set[Path] = set()
    active: list[Path] = []
    active_set: set[Path] = set()

    def visit(source: Path) -> tuple[Path, ...] | None:
        if source in active_set:
            start = active.index(source)
            cycle = tuple(active[start:] + [source])
            if any(
                (cycle[index], cycle[index + 1]) in graph.named_edges
                for index in range(len(cycle) - 1)
            ):
                return cycle
            return None
        if source in visited:
            return None
        active.append(source)
        active_set.add(source)
        for target in sorted(graph.edges.get(source, ())):
            cycle = visit(target)
            if cycle:
                return cycle
        active.pop()
        active_set.remove(source)
        visited.add(source)
        return None

    for source in sorted(graph.sources):
        cycle = visit(source)
        if cycle:
            return cycle
    return None


def is_allowed(relative: str, manifest: Manifest) -> bool:
    if relative in manifest.entry_roots or relative in manifest.allowed_files:
        return True
    if any(relative == item.source for item in manifest.named_imports):
        return True
    return any(
        relative == prefix.rstrip("/") or relative.startswith(prefix.rstrip("/") + "/")
        for prefix in manifest.allowed_prefixes
    )


def source_path(repository: Path, raw: str) -> Path:
    path = (repository / raw).resolve()
    try:
        path.relative_to(repository)
    except ValueError as error:
        raise ClosureError(f"source path escapes repository: {raw}") from error
    require_file(repository, path)
    return path


def require_file(
    repository: Path,
    path: Path,
    source: Path | None = None,
    imported: str | None = None,
) -> None:
    if path.is_file():
        return
    if source is None:
        raise ClosureError(f"missing source root: {path.relative_to(repository)}")
    raise ClosureError(
        f"{source.relative_to(repository)}: unresolved import {imported!r}"
    )
