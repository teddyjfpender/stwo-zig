"""Immutable workspace snapshotting for native CSP A/B evidence."""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
import subprocess
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence

from scripts.riscv_csp_ab_benchmark_lib import contract


SOURCE_DIGEST_SCHEMA = b"stwo-native-ab-source-content-v1\0"
PAYLOAD_DIGEST_SCHEMA = b"stwo-native-ab-untracked-payload-v1\0"
SNAPSHOT_AUTHOR_DATE = "2000-01-01T00:00:00+00:00"
SNAPSHOT_MESSAGE_PREFIX = "benchmark: ephemeral typed-air source snapshot"
RECURSIVE_PATHS = (
    "src/frontends/riscv/recursion",
    "src/tools/riscv/recursive_csp_producer",
    "src/integrations/riscv_cpu/recursive_fri_outer.zig",
)
IGNORED_INPUT_SCOPES = (
    "build.zig",
    "build.zig.zon",
    "build_support",
    "src",
    "scripts",
    "tests",
    "third_party",
    "tools",
    "vectors/riscv_csp",
    "vectors/riscv_elfs",
    "vectors/riscv_guests",
)


def _run(
    argv: Sequence[os.PathLike[str] | str],
    *,
    cwd: Path,
    env: Mapping[str, str] | None = None,
    input_bytes: bytes | None = None,
    timeout: int = 120,
    check: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    command = [os.fspath(value) for value in argv]
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            env=None if env is None else dict(env),
            input=input_bytes,
            capture_output=True,
            check=False,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise contract.ABError(f"cannot run {command[0]}: {error}") from error
    if check and completed.returncode != 0:
        stderr = completed.stderr.decode("utf-8", "replace")[-4000:]
        stdout = completed.stdout.decode("utf-8", "replace")[-4000:]
        raise contract.ABError(
            f"command exited {completed.returncode}: {' '.join(command)}\n"
            f"{stderr or stdout}"
        )
    return completed


def _git_raw(root: Path, *arguments: str, timeout: int = 120) -> bytes:
    return _run(["git", *arguments], cwd=root, timeout=timeout).stdout


def _git_text(root: Path, *arguments: str, timeout: int = 120) -> str:
    return _git_raw(root, *arguments, timeout=timeout).decode("utf-8").strip()


def repository_root(path: Path) -> Path:
    try:
        root = path.resolve(strict=True)
    except OSError as error:
        raise contract.ABError(f"repository does not exist: {path}") from error
    top = _git_text(root, "rev-parse", "--show-toplevel", timeout=30)
    if Path(top).resolve() != root:
        raise contract.ABError(f"path must be the repository root: {root}")
    if _git_text(root, "rev-parse", "--is-inside-work-tree") != "true":
        raise contract.ABError(f"path is not a Git worktree: {root}")
    return root


def _nul_paths(raw: bytes, label: str) -> list[str]:
    if raw and not raw.endswith(b"\0"):
        raise contract.ABError(f"{label} is not NUL terminated")
    result: list[str] = []
    for item in raw.split(b"\0")[:-1]:
        value = os.fsdecode(item)
        pure = PurePosixPath(value)
        if not value or pure.is_absolute() or ".." in pure.parts or "." in pure.parts:
            raise contract.ABError(f"{label} contains an unsafe path")
        result.append(value)
    if len(result) != len(set(result)):
        raise contract.ABError(f"{label} contains duplicate paths")
    return result


def tracked_and_untracked_paths(root: Path) -> list[str]:
    raw = _git_raw(
        root,
        "ls-files",
        "-z",
        "--cached",
        "--others",
        "--exclude-standard",
    )
    return sorted(_nul_paths(raw, "source inventory"), key=os.fsencode)


def untracked_paths(root: Path) -> list[str]:
    raw = _git_raw(root, "ls-files", "-z", "--others", "--exclude-standard")
    return sorted(_nul_paths(raw, "untracked inventory"), key=os.fsencode)


def _hash_one(root: Path, relative: str) -> tuple[bytes, int]:
    path = root / relative
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        # A deleted tracked path is not part of the resulting source tree.
        return b"", 0
    path_bytes = os.fsencode(relative)
    prefix = len(path_bytes).to_bytes(8, "big") + path_bytes
    if stat.S_ISREG(metadata.st_mode):
        digest = hashlib.sha256()
        size = 0
        try:
            with path.open("rb") as source:
                for block in iter(lambda: source.read(1024 * 1024), b""):
                    digest.update(block)
                    size += len(block)
        except OSError as error:
            raise contract.ABError(f"cannot hash source entry {relative}: {error}") from error
        executable = b"x" if metadata.st_mode & 0o111 else b"-"
        return prefix + b"f" + executable + size.to_bytes(8, "big") + digest.digest(), size
    if stat.S_ISLNK(metadata.st_mode):
        try:
            target = os.fsencode(os.readlink(path))
        except OSError as error:
            raise contract.ABError(f"cannot read source symlink {relative}: {error}") from error
        return prefix + b"l" + len(target).to_bytes(8, "big") + target, len(target)
    if stat.S_ISDIR(metadata.st_mode):
        raise contract.ABError(
            f"source inventory contains directory {relative}; submodules are unsupported"
        )
    raise contract.ABError(f"source inventory contains special file {relative}")


def digest_paths(
    root: Path,
    paths: Sequence[str],
    *,
    schema: bytes,
) -> dict[str, Any]:
    digest = hashlib.sha256(schema)
    count = 0
    total_bytes = 0
    for relative in sorted(paths, key=os.fsencode):
        record, byte_count = _hash_one(root, relative)
        if not record:
            continue
        digest.update(len(record).to_bytes(8, "big"))
        digest.update(record)
        count += 1
        total_bytes += byte_count
    return {
        "sha256": digest.hexdigest(),
        "file_count": count,
        "payload_bytes": total_bytes,
    }


def source_content(root: Path) -> dict[str, Any]:
    return digest_paths(
        root,
        tracked_and_untracked_paths(root),
        schema=SOURCE_DIGEST_SCHEMA,
    )


def worktree_status(root: Path) -> dict[str, Any]:
    raw = _git_raw(
        root,
        "status",
        "--porcelain=v2",
        "-z",
        "--untracked-files=all",
    )
    counts = {
        "ordinary": 0,
        "rename_or_copy": 0,
        "unmerged": 0,
        "untracked": 0,
    }
    for item in raw.split(b"\0"):
        if item.startswith(b"1 "):
            counts["ordinary"] += 1
        elif item.startswith(b"2 "):
            counts["rename_or_copy"] += 1
        elif item.startswith(b"u "):
            counts["unmerged"] += 1
        elif item.startswith(b"? "):
            counts["untracked"] += 1
    if counts["unmerged"]:
        raise contract.ABError("active source has unmerged index entries")
    return {
        "dirty": bool(raw),
        "status_sha256": contract.sha256_bytes(raw),
        "entry_count": sum(counts.values()),
        "category_counts": counts,
    }


def _safe_ignored_output(relative: str) -> bool:
    parts = PurePosixPath(relative).parts
    if any(
        part in {".zig-cache", "zig-out", "target", "__pycache__", ".lake"}
        or part.startswith("target-")
        for part in parts
    ):
        return True
    name = parts[-1]
    return (
        name == ".DS_Store"
        or name.endswith((".pyc", ".pyo", ".metallib.binarchive", ".nsys-rep", ".ncu-rep"))
    )


def assert_no_ignored_source_inputs(root: Path) -> None:
    raw = _git_raw(
        root,
        "ls-files",
        "-z",
        "--others",
        "--ignored",
        "--exclude-standard",
        "--",
        *IGNORED_INPUT_SCOPES,
        timeout=300,
    )
    ignored = _nul_paths(raw, "ignored source inventory")
    unsafe = [path for path in ignored if not _safe_ignored_output(path)]
    if unsafe:
        preview = ", ".join(unsafe[:8])
        suffix = "" if len(unsafe) <= 8 else f" (+{len(unsafe) - 8} more)"
        raise contract.ABError(
            "ignored files may influence the benchmark but cannot enter the "
            f"snapshot: {preview}{suffix}"
        )


def _assert_no_gitlinks(root: Path, commit: str) -> None:
    raw = _git_text(root, "ls-tree", "-r", commit)
    if any(line.startswith("160000 ") for line in raw.splitlines()):
        raise contract.ABError("benchmark snapshots do not admit Git submodules")


def _copy_untracked(active: Path, clone: Path, paths: Sequence[str]) -> None:
    for relative in paths:
        source = active / relative
        destination = clone / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        try:
            metadata = source.lstat()
            if stat.S_ISREG(metadata.st_mode):
                shutil.copy2(source, destination, follow_symlinks=False)
            elif stat.S_ISLNK(metadata.st_mode):
                os.symlink(os.readlink(source), destination)
            else:
                raise contract.ABError(
                    f"untracked payload contains unsupported entry {relative}"
                )
        except OSError as error:
            raise contract.ABError(f"cannot copy untracked entry {relative}: {error}") from error


def clone_at(source: Path, destination: Path, commit: str) -> None:
    if destination.exists():
        raise contract.ABError(f"snapshot destination already exists: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    _run(
        [
            "git",
            "clone",
            "--quiet",
            "--no-hardlinks",
            "--no-checkout",
            source,
            destination,
        ],
        cwd=source,
        timeout=600,
    )
    _run(["git", "checkout", "--quiet", "--detach", commit], cwd=destination)
    if _git_text(destination, "rev-parse", "HEAD") != commit:
        raise contract.ABError("isolated clone checked out the wrong commit")
    if worktree_status(destination)["dirty"]:
        raise contract.ABError("isolated clone was not clean after checkout")


def materialize_ephemeral_current(active_path: Path, destination: Path) -> dict[str, Any]:
    active = repository_root(active_path)
    base_head = _git_text(active, "rev-parse", "HEAD")
    if not contract.HEX_40.fullmatch(base_head):
        raise contract.ABError("active repository HEAD is not SHA-1 shaped")
    _assert_no_gitlinks(active, base_head)
    assert_no_ignored_source_inputs(active)

    before_status = worktree_status(active)
    before_content = source_content(active)
    before_untracked = untracked_paths(active)
    before_payload = digest_paths(
        active,
        before_untracked,
        schema=PAYLOAD_DIGEST_SCHEMA,
    )
    patch = _git_raw(
        active,
        "diff",
        "--binary",
        "--full-index",
        "--no-ext-diff",
        "HEAD",
        "--",
        timeout=600,
    )

    clone_at(active, destination, base_head)
    if patch:
        _run(
            ["git", "apply", "--binary", "--whitespace=nowarn", "-"],
            cwd=destination,
            input_bytes=patch,
            timeout=600,
        )
    _copy_untracked(active, destination, before_untracked)

    clone_content = source_content(destination)
    after_content = source_content(active)
    after_status = worktree_status(active)
    after_untracked = untracked_paths(active)
    after_payload = digest_paths(
        active,
        after_untracked,
        schema=PAYLOAD_DIGEST_SCHEMA,
    )
    after_patch = _git_raw(
        active,
        "diff",
        "--binary",
        "--full-index",
        "--no-ext-diff",
        "HEAD",
        "--",
        timeout=600,
    )
    if (
        before_content != clone_content
        or before_content != after_content
        or before_status != after_status
        or before_untracked != after_untracked
        or before_payload != after_payload
        or patch != after_patch
    ):
        raise contract.ABError(
            "active source changed while the isolated snapshot was being captured"
        )

    _run(["git", "add", "-A", "--"], cwd=destination, timeout=600)
    tree_oid = _git_text(destination, "write-tree")
    message = f"{SNAPSHOT_MESSAGE_PREFIX}\n\nsource-sha256: {before_content['sha256']}\n"
    commit_env = os.environ.copy()
    commit_env.update(
        {
            "GIT_AUTHOR_NAME": "stwo benchmark snapshot",
            "GIT_AUTHOR_EMAIL": "benchmark-snapshot@invalid",
            "GIT_AUTHOR_DATE": SNAPSHOT_AUTHOR_DATE,
            "GIT_COMMITTER_NAME": "stwo benchmark snapshot",
            "GIT_COMMITTER_EMAIL": "benchmark-snapshot@invalid",
            "GIT_COMMITTER_DATE": SNAPSHOT_AUTHOR_DATE,
        }
    )
    temporary_commit = _run(
        ["git", "commit-tree", tree_oid, "-p", base_head],
        cwd=destination,
        env=commit_env,
        input_bytes=message.encode("utf-8"),
    ).stdout.decode("ascii").strip()
    _run(
        ["git", "update-ref", "HEAD", temporary_commit, base_head],
        cwd=destination,
    )
    if worktree_status(destination)["dirty"]:
        raise contract.ABError("ephemeral benchmark commit did not leave a clean clone")
    committed_content = source_content(destination)
    if committed_content != before_content:
        raise contract.ABError("ephemeral commit does not reproduce active source content")
    listing = _git_raw(destination, "ls-tree", "-r", "-z", temporary_commit)
    return {
        "active_worktree_dirty": before_status["dirty"],
        "base_head": base_head,
        "source_content_sha256": before_content["sha256"],
        "source_file_count": before_content["file_count"],
        "source_payload_bytes": before_content["payload_bytes"],
        "status_sha256": before_status["status_sha256"],
        "status_entry_count": before_status["entry_count"],
        "status_category_counts": before_status["category_counts"],
        "tracked_patch_sha256": contract.sha256_bytes(patch),
        "tracked_patch_bytes": len(patch),
        "untracked_payload_sha256": before_payload["sha256"],
        "untracked_file_count": before_payload["file_count"],
        "untracked_payload_bytes": before_payload["payload_bytes"],
        "ignored_source_input_count": 0,
        "temporary_tree_git_oid": tree_oid,
        "temporary_tree_listing_sha256": contract.sha256_bytes(listing),
        "temporary_commit": temporary_commit,
        "capture_protocol": (
            "binary_HEAD_diff_plus_git_ls_files_others_exclude_standard_v1"
        ),
    }
