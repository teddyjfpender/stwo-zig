"""Measured package complexity ceilings; ownership comes from workspace contracts.

Counters concern tracked source, not runtime cost. No update/ratchet operation is
provided: raising a ceiling is a reviewed contract transaction.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

from scripts.repo.check_source_conformance import is_generated
from scripts.repo.source_conformance_lib.rv64_flags import LIVE, SUFFIXES

COUNTERS = ("code_files", "code_lines", "generated_code_files", "generated_code_lines",
            "script_files", "api_entries", "dependencies", "rv64_registry_flags", "versioned_files")


def empty() -> dict[str, int]:
    return dict.fromkeys(COUNTERS, 0)


def owner_for(repository: Path, path: str, contracts):
    # Match the workspace's longest-prefix/nested-package exclusion authority.
    from scripts.repo.check_package_workspace import owned_by
    source = repository / path
    for contract in sorted(contracts, key=lambda c: len(c.directory.parts), reverse=True):
        if source.is_relative_to(contract.directory) and owned_by(contract, source):
            return contract.package
    return None


def measure(repository: Path, contracts, paths=None) -> dict:
    repository = repository.resolve()
    if paths is None:
        raw = subprocess.check_output(["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=repository)
        paths = raw.decode().split("\0")
    rows = {c.package: empty() for c in contracts}
    unowned = empty()
    for path in sorted(set(paths) - {""}):
        source = repository / path
        if not source.is_file():
            continue
        if source.is_symlink():
            raise ValueError(f"package budget refuses tracked symlink: {path}")
        row = rows.get(owner_for(repository, path, contracts), unowned)
        row["versioned_files"] += 1
        if source.suffix in {".py", ".sh"}:
            row["script_files"] += 1
        if source.suffix in SUFFIXES:
            text = source.read_text(encoding="utf-8")
            generated = is_generated(text)
            prefix = "generated_code_" if generated else "code_"
            row[prefix + "files"] += 1
            row[prefix + "lines"] += len(text.splitlines())
    for contract in contracts:
        rows[contract.package]["api_entries"] = len(contract.api_surface)
        rows[contract.package]["dependencies"] = len(contract.dependencies)
    registry = repository / "conformance/rv64-flags.json"
    if registry.is_file():
        for flag in json.loads(registry.read_text())["flags"].values():
            if flag["status"] in LIVE:
                row = rows.get(owner_for(repository, flag["owner"], contracts), unowned)
                row["rv64_registry_flags"] += 1
    return {"packages": rows, "unowned": unowned}


def check(repository: Path, contracts) -> list[str]:
    try:
        measured = measure(repository, contracts)["packages"]
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        return [f"package budgets: census failed: {error}"]
    failures = []
    for contract in contracts:
        ceiling = contract.budget
        if ceiling is None:
            failures.append(f"{contract.package}: contract missing measured budget")
            continue
        for name in COUNTERS:
            actual = measured[contract.package][name]
            if actual > ceiling[name]:
                failures.append(f"{contract.package}: {name} {actual} exceeds budget {ceiling[name]}")
    try:
        failures.extend(review_errors(repository, contracts, baseline(repository)))
        failures.extend(hot_path_errors(repository, contracts))
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        failures.append(f"package budgets: review baseline unavailable: {error}")
    return failures


def report(repository: Path, contracts) -> dict:
    def git(*args):
        return subprocess.check_output(["git", *args], cwd=repository)
    new_files = git("ls-files", "--others", "--exclude-standard", "-z").decode().split("\0")
    new_hashes = {path: hashlib.sha256((repository / path).read_bytes()).hexdigest()
                  for path in new_files if path and (repository / path).is_file()}
    return {"schema": "package-complexity-census/v1",
            "new_file_sha256": new_hashes,
            "source_commit": git("rev-parse", "HEAD").decode().strip(),
            "index_tree": git("write-tree").decode().strip(),
            "tracked_worktree_diff_sha256": hashlib.sha256(git("diff", "HEAD", "--binary")).hexdigest(),
            "measurement": measure(repository, contracts),
            "scope": "Tracked and nonignored new files plus declared API/dependencies/live flag ownership; no runtime bound."}


def review_errors(repository: Path, contracts, base: str) -> list[str]:
    """Require an exact reviewed transaction for every increase from base."""
    changes = json.loads((repository / "conformance/rv64-productionisation-budget.json").read_text()).get("package_budget_changes", [])
    failures = []
    for contract in contracts:
        relative = (contract.directory / "package.contract.json").relative_to(repository).as_posix()
        previous = subprocess.run(["git", "show", f"{base}:{relative}"], cwd=repository,
                                  capture_output=True, text=True)
        if previous.returncode:
            continue  # A genuinely new package has no previous ceiling.
        before = json.loads(previous.stdout).get("budget")
        after = contract.budget
        if before is None or after is None or not any(after[k] > before[k] for k in COUNTERS):
            continue
        approved = any(isinstance(row, dict) and set(row) == {"package", "base_commit", "before", "after", "decision"}
                       and row["package"] == contract.package and row["base_commit"] == base
                       and row["before"] == before and row["after"] == after
                       and isinstance(row["decision"], str)
                       and row["decision"].startswith("https://github.com/teddyjfpender/stwo-zig/issues/")
                       and "#issuecomment-" in row["decision"] for row in changes)
        if not approved:
            failures.append(f"{contract.package}: budget increase requires exact reviewed CB-2 transaction from {base}")
    return failures


def baseline(repository: Path) -> str:
    """Compare feature branches to trunk; trunk merges to their first parent."""
    import os
    requested = "origin/" + os.environ["GITHUB_BASE_REF"] if os.environ.get("GITHUB_BASE_REF") else "origin/main"
    trunk = subprocess.check_output(["git", "rev-parse", requested], cwd=repository).decode().strip()
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repository).decode().strip()
    target = "HEAD^" if head == trunk else requested
    return subprocess.check_output(["git", "rev-parse", target], cwd=repository).decode().strip()


def branch_count(text: str, function: str) -> int:
    """Conservative branch-token proxy on one unambiguous function body."""
    import re
    from scripts.repo.source_conformance_lib.comments import strip_zig
    clean = strip_zig(text)
    clean = re.sub(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|\\\\[^\n]*', ' ', clean)
    matches = list(re.finditer(r'\bfn\s+' + re.escape(function) + r'\s*\([^{}]*?\)[^{}]*\{', clean))
    if len(matches) != 1:
        raise ValueError(f"hot function {function} must resolve exactly once")
    start = matches[0].end()
    depth = 1
    end = start
    while end < len(clean) and depth:
        depth += (clean[end] == '{') - (clean[end] == '}')
        end += 1
    if depth:
        raise ValueError(f"unterminated hot function {function}")
    return len(re.findall(r'\b(?:if|while|for|catch|orelse)\b|=>', clean[start:end-1]))


def hot_path_errors(repository: Path, contracts) -> list[str]:
    policy = json.loads((repository / "conformance/rv64-productionisation-budget.json").read_text())
    failures = []
    seen = set()
    for row in policy.get("hot_path_budgets", []):
        if (not isinstance(row, dict) or set(row) != {"package", "source", "function", "max_branches", "decision"}
                or any(not isinstance(row.get(key), str) or not row[key] for key in ("package", "source", "function", "decision"))
                or type(row.get("max_branches")) is not int or not 0 <= row["max_branches"] <= 15):
            failures.append("invalid hot-path complexity budget")
            continue
        source = repository / row["source"]
        identity = (row["source"], row["function"])
        if (identity in seen or not source.is_file() or not source.resolve().is_relative_to(repository)
                or owner_for(repository, row["source"], contracts) != row["package"]):
            failures.append(f"invalid or duplicate hot-path owner: {identity}")
            continue
        seen.add(identity)
        try:
            count = branch_count(source.read_text(), row["function"])
            if count > row["max_branches"]:
                failures.append(f"{identity}: {count} branch tokens exceed {row['max_branches']}")
        except ValueError as error:
            failures.append(str(error))
    return failures
