"""Resolve static ``build.zig`` and ``build_support`` graph edges.

Only literal ``@import("...zig")`` and ``b.path("...")`` expressions are
resolved, and only outside comments: prose describing an import declares no
build edge. Formatted/generated paths are validated by Zig's build graph and its
focused tests rather than guessed here.
"""

from __future__ import annotations

import re
from pathlib import Path

from . import comments
from .common import contained_path, cycle_nodes, is_deferred, iter_tree_sources
from .model import Finding


IMPORT_RE = re.compile(r'@import\("([^"\n]+)"\)')
BUILD_PATH_RE = re.compile(r'\bb\.path\("([^"\n]+)"\)')


def build_sources(repo: Path) -> list[Path]:
    sources = []
    if (repo / "build.zig").is_file():
        sources.append(repo / "build.zig")
    sources.extend(iter_tree_sources(repo / "build_support", frozenset({".zig"})))
    return sources


def scan(repo: Path) -> list[Finding]:
    findings: list[Finding] = []
    graph: dict[str, set[str]] = {}
    for source in build_sources(repo):
        display = source.relative_to(repo)
        text = comments.strip_zig(source.read_text(encoding="utf-8"))
        node = display.as_posix()
        graph.setdefault(node, set())
        for imported in IMPORT_RE.findall(text):
            if imported == "std" or not imported.endswith(".zig"):
                continue
            target = (source.parent / imported).resolve()
            target_relative = contained_path(target, repo)
            allowed = target_relative is not None and target_relative.parts[0] == "build_support"
            if not target.is_file() or not allowed:
                rendered = target_relative.as_posix() if target_relative is not None else imported
                findings.append(Finding(
                    f"build-dependency:{node}->{rendered}",
                    f"{display}: build graph imports must resolve below build_support ({imported})",
                ))
                continue
            target_node = target_relative.as_posix()
            graph[node].add(target_node)
            graph.setdefault(target_node, set())

        for referenced in BUILD_PATH_RE.findall(text):
            target = (repo / referenced).resolve()
            target_relative = contained_path(target, repo)
            if target_relative is None or is_deferred(target_relative):
                continue
            if not target.exists():
                findings.append(Finding(
                    f"build-path:{node}->{referenced}",
                    f"{display}: static build path does not exist ({referenced})",
                ))
    for node in sorted(cycle_nodes(graph)):
        findings.append(Finding(
            f"build-cycle:{node}",
            f"{node}: build-support imports participate in a dependency cycle",
        ))
    return findings
