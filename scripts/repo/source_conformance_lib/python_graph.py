"""Resolve maintained Python's static repository-local import graph.

The scanner uses Python's AST and covers ``import`` and ``from ... import ...``
statements whose target is another maintained module below ``scripts/``. It does
not infer ``importlib``, computed module names, or ``sys.path`` mutation. Those
runtime mechanisms remain integration-test concerns.
"""

from __future__ import annotations

import ast
from pathlib import Path

from . import policy
from .common import is_deferred, iter_tree_sources
from .model import Finding


def module_index(repo: Path) -> dict[str, Path]:
    scripts_root = repo / "scripts"
    modules: dict[str, Path] = {}
    for source in iter_tree_sources(scripts_root, frozenset({".py"})):
        relative = source.relative_to(scripts_root).with_suffix("")
        parts = relative.parts[:-1] if relative.name == "__init__" else relative.parts
        module = ".".join(parts)
        if module:
            modules[module] = source
            modules[f"scripts.{module}"] = source
    return modules


def resolve_imports(
    source: Path,
    tree: ast.AST,
    scripts_root: Path,
    modules: dict[str, Path],
) -> set[Path]:
    relative = source.relative_to(scripts_root).with_suffix("")
    package_parts = list(relative.parts[:-1])
    targets: set[Path] = set()

    def add_module(name: str) -> None:
        candidate = name
        while candidate:
            target = modules.get(candidate)
            if target is not None:
                targets.add(target)
                return
            candidate = candidate.rpartition(".")[0]

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                add_module(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                keep = len(package_parts) - (node.level - 1)
                base = package_parts[:max(keep, 0)]
                if node.module:
                    base.extend(node.module.split("."))
                module = ".".join(base)
            else:
                module = node.module or ""
            add_module(module)
            for alias in node.names:
                add_module(".".join(part for part in (module, alias.name) if part))
    return targets


def layer(relative: Path) -> tuple[str, str | None]:
    if relative.parts[0] == "tests":
        return "test", None
    if len(relative.parts) > 1 and (
        relative.parts[0].endswith("_lib") or relative.parts[0] == "product_closure"
    ):
        return "library", relative.parts[0]
    return "boundary", None


def scan(repo: Path) -> list[Finding]:
    scripts_root = repo / "scripts"
    modules = module_index(repo)
    findings: list[Finding] = []
    for source in iter_tree_sources(scripts_root, frozenset({".py"})):
        display = source.relative_to(repo)
        if is_deferred(display):
            continue
        try:
            tree = ast.parse(source.read_text(encoding="utf-8"), filename=display.as_posix())
        except SyntaxError as error:
            findings.append(Finding(
                f"python-syntax:{display.as_posix()}",
                f"{display}: Python source cannot be parsed for dependency conformance ({error.msg})",
            ))
            continue
        source_layer, source_package = layer(source.relative_to(scripts_root))
        for target in resolve_imports(source, tree, scripts_root, modules):
            target_display = target.relative_to(repo)
            if is_deferred(target_display):
                findings.append(Finding(
                    f"python-dependency:{display.as_posix()}->{target_display.as_posix()}",
                    f"{display}: active Python tooling must not import deferred tooling ({target_display})",
                ))
                continue
            _, target_package = layer(target.relative_to(scripts_root))
            allowed_packages = {
                source_package,
                *policy.PYTHON_FOUNDATION_LIBRARIES,
                *policy.PYTHON_LIBRARY_DEPENDENCIES.get(source_package, frozenset()),
            }
            if (
                source_layer == "library"
                and target_package not in allowed_packages
            ):
                findings.append(Finding(
                    f"python-dependency:{display.as_posix()}->{target_display.as_posix()}",
                    f"{display}: library package must not depend outside {source_package} ({target_display})",
                ))
    return findings
