"""Filesystem and directed-graph primitives for conformance scanners."""

from __future__ import annotations

from pathlib import Path

from . import policy


EXCLUDED_DIRECTORY_NAMES = frozenset({
    ".cache",
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".zig-cache",
    "__pycache__",
    "generated",
    "target",
    "vendor",
    "zig-out",
})


def iter_tree_sources(root: Path, suffixes: frozenset[str]) -> list[Path]:
    if not root.is_dir():
        return []
    return sorted(
        path
        for path in root.rglob("*")
        if path.is_file()
        and path.suffix in suffixes
        and not EXCLUDED_DIRECTORY_NAMES.intersection(path.relative_to(root).parts[:-1])
    )


def contained_path(path: Path, root: Path) -> Path | None:
    try:
        return path.resolve().relative_to(root.resolve())
    except ValueError:
        return None


def is_deferred(relative: Path | str) -> bool:
    display = Path(relative).as_posix() if isinstance(relative, Path) else relative
    return any(display.startswith(prefix) for prefix in policy.DEFERRED_PREFIXES)


def cycle_nodes(edges: dict[str, set[str]]) -> set[str]:
    """Return graph nodes participating in a directed cycle."""
    visiting: list[str] = []
    active: set[str] = set()
    complete: set[str] = set()
    cyclic: set[str] = set()

    def visit(node: str) -> None:
        if node in complete:
            return
        if node in active:
            cyclic.update(visiting[visiting.index(node):])
            return
        active.add(node)
        visiting.append(node)
        for target in sorted(edges.get(node, set())):
            visit(target)
        visiting.pop()
        active.remove(node)
        complete.add(node)

    for node in sorted(edges):
        visit(node)
    return cyclic
