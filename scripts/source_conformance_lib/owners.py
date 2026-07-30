"""Mechanically enforce thin active build, command, test, and evidence roots.

The rules apply to named architectural roots, not every implementation module.
Python functions are measured from the AST; Zig and Rust declarations are matched
against comment-blanked text, and Zig ``main`` bodies use a conservative brace
scan and therefore cover ordinary entry points, not generated syntax.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from . import comments, policy
from .common import is_deferred, iter_tree_sources
from .model import Finding, headroom


def zig_main_lines(text: str) -> int | None:
    match = re.search(r"\bpub\s+fn\s+main\s*\([^)]*\)[^{]*\{", text)
    if match is None:
        return None
    depth = 0
    for index in range(match.end() - 1, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                start_line = text.count("\n", 0, match.start()) + 1
                end_line = text.count("\n", 0, index) + 1
                return end_line - start_line + 1
    return None


def is_zig_root(relative: Path, text: str) -> bool:
    display = (Path("src") / relative).as_posix()
    if is_deferred(display):
        return False
    return (
        relative in {Path("stwo.zig"), Path("stwo_deep.zig"), Path("tests.zig")}
        or (relative.parts[0] == "tools" and relative.name == "main.zig")
        or relative == Path("tools/metal_core_aot/probe.zig")
        or relative.parts[:2] == ("tools", "native_proof_bench")
        or (relative.parts[0] == "tests" and relative.name in {"mod.zig", "backend_test.zig"})
        or (
            relative.parts[0] == "bench"
            and "pub fn main" in text
            and (len(relative.parts) == 2 or relative.parts[1] == "metal")
        )
    )


def scan_zig(relative: Path, text: str) -> list[Finding]:
    code = comments.strip_zig(text)
    if not is_zig_root(relative, code):
        return []
    repo_path = Path("src") / relative
    line_count = len(text.splitlines())
    findings: list[Finding] = []
    if line_count > policy.ZIG_OWNER_CEILING:
        findings.append(Finding(
            f"thin-owner:{relative.as_posix()}",
            f"{relative}: active Zig command/test owner exceeds the {policy.ZIG_OWNER_CEILING}-line ceiling",
            line_count,
        ))
    else:
        findings.extend(headroom(
            f"thin-owner:{relative.as_posix()}",
            relative,
            line_count,
            policy.ZIG_OWNER_CEILING,
            "active Zig command/test owner ceiling",
            repo_path,
        ))
    main_lines = zig_main_lines(code)
    if main_lines is None:
        return findings
    if main_lines > policy.ZIG_ENTRYPOINT_CEILING:
        findings.append(Finding(
            f"thin-owner:{relative.as_posix()}",
            f"{relative}: Zig entry point is {main_lines} lines; active command roots are capped at {policy.ZIG_ENTRYPOINT_CEILING}",
            main_lines,
        ))
    else:
        findings.extend(headroom(
            f"thin-owner:{relative.as_posix()}",
            relative,
            main_lines,
            policy.ZIG_ENTRYPOINT_CEILING,
            "Zig entry-point ceiling",
            repo_path,
        ))
    return findings


def scan_build(repo: Path) -> list[Finding]:
    findings: list[Finding] = []
    root = repo / "build.zig"
    if root.is_file():
        line_count = len(root.read_text(encoding="utf-8").splitlines())
        if line_count > policy.BUILD_ROOT_CEILING:
            findings.append(Finding(
                "thin-owner:build.zig",
                f"build.zig: public build graph exceeds the {policy.BUILD_ROOT_CEILING}-line owner ceiling",
                line_count,
            ))
        else:
            findings.extend(headroom(
                "thin-owner:build.zig",
                "build.zig",
                line_count,
                policy.BUILD_ROOT_CEILING,
                "public build graph owner ceiling",
            ))
    for source in iter_tree_sources(repo / "build_support", frozenset({".zig", ".py"})):
        line_count = len(source.read_text(encoding="utf-8").splitlines())
        display = source.relative_to(repo)
        if line_count > policy.BUILD_SUPPORT_CEILING:
            findings.append(Finding(
                f"thin-owner:{display.as_posix()}",
                f"{display}: build-support owner exceeds the {policy.BUILD_SUPPORT_CEILING}-line ceiling",
                line_count,
            ))
        else:
            findings.extend(headroom(
                f"thin-owner:{display.as_posix()}",
                display,
                line_count,
                policy.BUILD_SUPPORT_CEILING,
                "build-support owner ceiling",
            ))
    return findings


def scan_python_roots(repo: Path) -> list[Finding]:
    findings: list[Finding] = []
    for relative in policy.ACTIVE_FORMAL_EVIDENCE_ROOTS:
        source = repo / relative
        if not source.is_file():
            continue
        text = source.read_text(encoding="utf-8")
        line_count = len(text.splitlines())
        if line_count > policy.PYTHON_ROOT_CEILING:
            findings.append(Finding(
                f"thin-owner:{relative}",
                f"{relative}: active evidence root exceeds the {policy.PYTHON_ROOT_CEILING}-line owner ceiling",
                line_count,
            ))
        else:
            findings.extend(headroom(
                f"thin-owner:{relative}",
                relative,
                line_count,
                policy.PYTHON_ROOT_CEILING,
                "active evidence root owner ceiling",
            ))
        try:
            tree = ast.parse(text, filename=relative)
        except SyntaxError:
            continue
        mains = [
            node for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "main"
        ]
        delegated_mains = [
            alias
            for node in tree.body
            if isinstance(node, ast.ImportFrom)
            and node.module is not None
            and (
                node.module.endswith("_lib")
                or node.module.endswith("_lib.controller")
            )
            for alias in node.names
            if alias.name == "main" and alias.asname in {None, "main"}
        ]
        if len(mains) + len(delegated_mains) != 1:
            findings.append(Finding(
                f"thin-owner:{relative}",
                f"{relative}: active evidence root must define or delegate one main entry point",
            ))
            continue
        if not mains:
            continue
        main_lines = (mains[0].end_lineno or mains[0].lineno) - mains[0].lineno + 1
        if main_lines > policy.PYTHON_ENTRYPOINT_CEILING:
            findings.append(Finding(
                f"thin-owner:{relative}",
                f"{relative}: main exceeds the {policy.PYTHON_ENTRYPOINT_CEILING}-line entrypoint ceiling",
                main_lines,
            ))
        else:
            findings.extend(headroom(
                f"thin-owner:{relative}",
                relative,
                main_lines,
                policy.PYTHON_ENTRYPOINT_CEILING,
                "entrypoint ceiling",
            ))
    return findings


def scan_python_controllers(repo: Path) -> list[Finding]:
    """Cap every active deep evidence controller without pretending it is an entry point."""
    findings: list[Finding] = []
    scripts_root = repo / "scripts"
    for source in sorted(scripts_root.glob("*_lib/controller.py")):
        display = source.relative_to(repo)
        if is_deferred(display):
            continue
        line_count = len(source.read_text(encoding="utf-8").splitlines())
        if line_count > policy.PYTHON_CONTROLLER_CEILING:
            findings.append(Finding(
                f"deep-controller:{display.as_posix()}",
                f"{display}: cohesive evidence controller exceeds the "
                f"{policy.PYTHON_CONTROLLER_CEILING}-line soft ceiling",
                line_count,
            ))
        else:
            findings.extend(headroom(
                f"deep-controller:{display.as_posix()}",
                display,
                line_count,
                policy.PYTHON_CONTROLLER_CEILING,
                "evidence controller soft ceiling",
            ))
        root_name = policy.PYTHON_CONTROLLER_ROOTS.get(
            source.parent.name,
            f"{source.parent.name.removesuffix('_lib')}.py",
        )
        root = scripts_root / root_name
        if not root.is_file():
            findings.append(Finding(
                f"deep-controller:{display.as_posix()}",
                f"{display}: evidence controller has no stable executable facade ({root.name})",
            ))
    return findings


def scan_rust(repo: Path) -> list[Finding]:
    findings: list[Finding] = []
    for crate_name in sorted(policy.ACTIVE_NATIVE_RUST_CRATES):
        root = repo / "tools" / crate_name / "src/main.rs"
        if not root.is_file():
            continue
        text = root.read_text(encoding="utf-8")
        line_count = len(text.splitlines())
        has_module = re.search(
            r"^\s*(?:pub\s+)?mod\s+\w+\s*;",
            comments.strip_c(text),
            re.MULTILINE,
        )
        display = root.relative_to(repo)
        if line_count > policy.RUST_ENTRYPOINT_CEILING or has_module is None:
            findings.append(Finding(
                f"thin-owner:{display.as_posix()}",
                f"{display}: Native Rust root must delegate to modules and stay at or below {policy.RUST_ENTRYPOINT_CEILING} lines",
                line_count,
            ))
        else:
            findings.extend(headroom(
                f"thin-owner:{display.as_posix()}",
                display,
                line_count,
                policy.RUST_ENTRYPOINT_CEILING,
                "Native Rust root ceiling",
            ))
    return findings


def scan(repo: Path) -> list[Finding]:
    return scan_build(repo) + scan_python_roots(repo) + scan_python_controllers(repo) + scan_rust(repo)
