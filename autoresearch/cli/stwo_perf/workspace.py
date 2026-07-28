"""Workspaces: clone, setup, sync, and reset via git worktrees.

`sync`/`reset` restore only manifest editable paths while keeping everything
else at the default-branch tip, and both refuse a dirty worktree without
--force — the reference workflow's central safety rule.
"""

from __future__ import annotations

import platform
import subprocess
from pathlib import Path

from .manifest import Manifest, ManifestError


class WorkspaceError(RuntimeError):
    pass


def _git(cwd: Path, *args: str, check: bool = True) -> str:
    proc = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True)
    if check and proc.returncode != 0:
        raise WorkspaceError(f"git {' '.join(args)} failed: {proc.stderr.strip()}")
    return proc.stdout.strip()


def _git_rc(cwd: Path, *args: str) -> tuple[int, str]:
    proc = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True)
    return proc.returncode, proc.stderr.strip()


def is_dirty(root: Path) -> bool:
    return _git(root, "status", "--porcelain") != ""


def clone(repo_root: Path, dest: Path, ref: str = "HEAD") -> Path:
    """Create a searcher workspace as a linked worktree at `dest`."""
    dest = dest.resolve()
    if dest.exists() and any(dest.iterdir()):
        raise WorkspaceError(f"destination {dest} exists and is not empty")
    _git(repo_root, "worktree", "add", str(dest), ref)
    return dest


def setup(root: Path, manifest: Manifest, board: str | None = None) -> list[str]:
    """Verify toolchain and build the selected board's bench target.

    With no board, preserve the interactive setup behavior and build every
    enabled group. Fork qualification supplies its dispatched board so a
    Linux runner never tries to build unrelated host-specific backends.
    Disabled groups are announced loudly (never silently dropped); returns
    the group ids that were built.
    """
    zig = subprocess.run(["zig", "version"], capture_output=True, text=True)
    if zig.returncode != 0:
        raise WorkspaceError("zig not found on PATH")
    groups = manifest.groups()
    if board is not None:
        try:
            group = manifest.group_for_board(board)
        except ManifestError as exc:
            raise WorkspaceError(str(exc)) from exc
        if not group.enabled:
            raise WorkspaceError(
                f"workload group {group.group_id} for board {board} is disabled: "
                f"{group.disabled_reason or 'no reason recorded'}"
            )
        groups = [group]
    built: list[str] = []
    for group in groups:
        if not group.enabled:
            print(f"skipped group {group.group_id}: "
                  f"{group.disabled_reason or 'no reason recorded'}")
            continue
        if board is None and group.board == "core_metal" and platform.system() != "Darwin":
            print(
                f"skipped group {group.group_id}: core_metal requires a Darwin "
                "host with the Apple Metal SDK"
            )
            continue
        proc = subprocess.run(
            group.build_step.split(), cwd=root, capture_output=True, text=True
        )
        if proc.returncode != 0:
            raise WorkspaceError(
                f"build step for group {group.group_id} failed:\n"
                f"{proc.stderr.strip()[-800:]}"
            )
        built.append(group.group_id)
    if not built:
        raise WorkspaceError("no enabled workload groups to build")
    return built


def default_branch_tip(root: Path) -> str:
    for ref in ("origin/main", "main"):
        sha = _git(root, "rev-parse", "--verify", "--quiet", ref, check=False)
        if sha:
            return sha
    raise WorkspaceError("cannot resolve the default branch (main)")


def restore_editable_from(root: Path, manifest: Manifest, source_commit: str,
                          force: bool = False) -> list[str]:
    """Move to the default-branch tip, then restore editable paths from
    `source_commit`. Harness and locked files always track the tip.

    True restore semantics: files under an editable pathspec that exist at the
    tip but not in the source commit are removed first — a plain pathspec
    checkout would otherwise leave a tip/source hybrid.
    """
    if is_dirty(root) and not force:
        raise WorkspaceError("worktree is dirty; commit, stash, or pass --force")
    tip = default_branch_tip(root)
    _git(root, "checkout", "--detach", tip)
    restored, missing = [], []
    for entry in manifest.editable:
        glob = entry["glob"]
        pathspec = glob[:-3] if glob.endswith("/**") else glob
        in_source = _git(root, "ls-tree", "-r", "--name-only",
                         source_commit, "--", pathspec, check=False)
        if not in_source:
            missing.append(pathspec)  # path absent in source; keep tip state
            continue
        _git_rc(root, "rm", "-rq", "--ignore-unmatch", "--", pathspec)
        rc, err = _git_rc(root, "checkout", source_commit, "--", pathspec)
        if rc != 0:
            raise WorkspaceError(f"restore of {pathspec} from {source_commit} failed: {err}")
        restored.append(pathspec)
    if missing:
        restored.append(f"(absent in source, kept at tip: {', '.join(missing)})")
    return restored


def sync(root: Path, manifest: Manifest, promoted_commit: str | None,
         force: bool = False) -> list[str]:
    """Fast-forward to the frontier: tip harness + latest promoted editable set."""
    source = promoted_commit or default_branch_tip(root)
    return restore_editable_from(root, manifest, source, force=force)
