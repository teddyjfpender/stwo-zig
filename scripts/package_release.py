#!/usr/bin/env python3
"""Build deterministic, dependency-closed Zig source package archives."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import subprocess
import tarfile
import tempfile
from pathlib import Path
from typing import Any, Iterable, Sequence

try:
    from scripts import check_package_workspace
except ModuleNotFoundError:
    import check_package_workspace  # type: ignore[no-redef]


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "conformance/package-release-v1.json"
POLICY_SCHEMA = "stwo-zig-package-release-policy-v1"
MANIFEST_SCHEMA = "stwo-zig-source-package-v1"
INDEX_SCHEMA = "stwo-zig-package-release-index-v1"
FORBIDDEN_PUBLISHED_PREFIXES = (
    "autoresearch/",
    "formal/",
    "tools/",
    "vectors/",
)
FORBIDDEN_PUBLISHED_SUFFIXES = (".rs",)


class ReleaseError(RuntimeError):
    pass


def _run(repository: Path, *command: str) -> bytes:
    completed = subprocess.run(
        list(command),
        cwd=repository,
        check=False,
        capture_output=True,
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode(errors="replace").strip()
        raise ReleaseError(f"command failed ({' '.join(command)}): {detail}")
    return completed.stdout


def load_contracts(repository: Path) -> dict[str, check_package_workspace.Contract]:
    contracts = [
        check_package_workspace.load_contract(path)
        for path in sorted(repository.glob("src/**/package.contract.json"))
    ]
    result = {contract.package: contract for contract in contracts}
    if not result or len(result) != len(contracts):
        raise ReleaseError("package contracts are missing or have duplicate names")
    return result


def load_policy(
    repository: Path,
    contracts: dict[str, check_package_workspace.Contract],
) -> dict[str, dict[str, str]]:
    try:
        payload: Any = json.loads(
            (repository / POLICY_PATH.relative_to(ROOT)).read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError) as error:
        raise ReleaseError(f"cannot load package release policy: {error}") from error
    if not isinstance(payload, dict) or set(payload) != {
        "schema",
        "archive_format",
        "packages",
    }:
        raise ReleaseError("package release policy has unexpected fields")
    if payload["schema"] != POLICY_SCHEMA or payload["archive_format"] != "tar":
        raise ReleaseError("package release policy schema or archive format drifted")
    packages = payload["packages"]
    if not isinstance(packages, dict) or set(packages) != set(contracts):
        raise ReleaseError("package release policy must classify every package exactly once")
    result: dict[str, dict[str, str]] = {}
    for name, raw in packages.items():
        if not isinstance(raw, dict) or set(raw) != {"status", "reason"}:
            raise ReleaseError(f"release policy entry is malformed: {name}")
        status = raw["status"]
        reason = raw["reason"]
        if status not in {"published", "deferred", "internal"}:
            raise ReleaseError(f"release policy status is invalid: {name}")
        if not isinstance(reason, str) or not reason.strip():
            raise ReleaseError(f"release policy reason is empty: {name}")
        result[name] = {"status": status, "reason": reason}
    for name in contracts:
        if result[name]["status"] != "published":
            continue
        unavailable = sorted(
            dependency
            for dependency in dependency_closure(name, contracts)
            if result[dependency]["status"] == "deferred"
        )
        if unavailable:
            raise ReleaseError(
                f"published package {name} depends on unpublished packages {unavailable}"
            )
    return result


def dependency_closure(
    package: str,
    contracts: dict[str, check_package_workspace.Contract],
) -> tuple[str, ...]:
    reached: set[str] = set()

    def visit(name: str) -> None:
        if name in reached:
            return
        for dependency in sorted(contracts[name].dependencies):
            visit(dependency)
        reached.add(name)

    visit(package)
    return tuple(sorted(reached))


def tracked_files(repository: Path) -> tuple[Path, ...]:
    entries = _run(repository, "git", "ls-files", "-z").split(b"\0")
    return tuple(
        Path(entry.decode())
        for entry in entries
        if entry
    )


def package_files(
    repository: Path,
    closure: Iterable[str],
    contracts: dict[str, check_package_workspace.Contract],
    tracked: Iterable[Path],
) -> tuple[Path, ...]:
    roots = tuple(
        contract.directory.relative_to(repository)
        for contract in (contracts[name] for name in closure)
    )
    selected = {
        path
        for path in tracked
        if path == Path("LICENSE")
        or any(path == root or root in path.parents for root in roots)
    }
    symlinks = [path for path in selected if (repository / path).is_symlink()]
    if symlinks:
        raise ReleaseError(f"published package files cannot be symlinks: {symlinks[:3]}")
    missing = [path for path in selected if not (repository / path).is_file()]
    if missing:
        raise ReleaseError(f"tracked package files are missing: {missing[:3]}")
    return tuple(sorted(selected, key=lambda path: path.as_posix()))


def validate_published_payload(paths: Iterable[Path]) -> None:
    violations = []
    for path in paths:
        text = path.as_posix()
        if text.startswith(FORBIDDEN_PUBLISHED_PREFIXES) or text.endswith(
            FORBIDDEN_PUBLISHED_SUFFIXES
        ):
            violations.append(text)
    if violations:
        raise ReleaseError(
            "published Zig package closure contains non-distribution tooling: "
            + ", ".join(violations[:5])
        )


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def source_identity(repository: Path) -> dict[str, Any]:
    commit = _run(repository, "git", "rev-parse", "HEAD").decode().strip()
    tree = _run(repository, "git", "rev-parse", "HEAD^{tree}").decode().strip()
    dirty = bool(_run(repository, "git", "status", "--porcelain", "--untracked-files=all"))
    return {"commit": commit, "tree": tree, "dirty": dirty}


def _tar_entry(name: str, payload: bytes, mode: int) -> tuple[tarfile.TarInfo, bytes]:
    entry = tarfile.TarInfo(name)
    entry.size = len(payload)
    entry.mode = mode
    entry.mtime = 0
    entry.uid = 0
    entry.gid = 0
    entry.uname = ""
    entry.gname = ""
    return entry, payload


def build_archive(
    repository: Path,
    output: Path,
    package: str,
    contracts: dict[str, check_package_workspace.Contract],
    policy: dict[str, dict[str, str]],
    identity: dict[str, Any],
    tracked: tuple[Path, ...],
) -> dict[str, Any]:
    contract = contracts[package]
    closure = dependency_closure(package, contracts)
    paths = package_files(repository, closure, contracts, tracked)
    validate_published_payload(paths)
    prefix = f"{package}-{contract.version}"
    payload_records = []
    payloads: list[tuple[str, bytes, int]] = []
    for path in paths:
        payload = (repository / path).read_bytes()
        mode = 0o755 if os.stat(repository / path).st_mode & 0o111 else 0o644
        payloads.append((path.as_posix(), payload, mode))
        payload_records.append(
            {
                "path": path.as_posix(),
                "bytes": len(payload),
                "mode": f"{mode:04o}",
                "sha256": sha256_bytes(payload),
            }
        )
    manifest = {
        "schema": MANIFEST_SCHEMA,
        "package": package,
        "version": contract.version,
        "archive_prefix": prefix,
        "root_build_file": (
            contract.directory.relative_to(repository) / "build.zig"
        ).as_posix(),
        "source": identity,
        "dependency_closure": list(closure),
        "distribution_policy": policy[package],
        "payload": payload_records,
    }
    manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    output.mkdir(parents=True, exist_ok=True)
    archive = output / f"{prefix}.tar"
    with tempfile.NamedTemporaryFile(dir=output, delete=False) as temporary:
        temporary_path = Path(temporary.name)
    try:
        with tarfile.open(temporary_path, mode="w", format=tarfile.GNU_FORMAT) as bundle:
            for name, payload, mode in payloads:
                entry, content = _tar_entry(f"{prefix}/{name}", payload, mode)
                bundle.addfile(entry, io.BytesIO(content))
            entry, content = _tar_entry(
                f"{prefix}/PACKAGE-RELEASE.json",
                manifest_bytes,
                0o644,
            )
            bundle.addfile(entry, io.BytesIO(content))
        os.replace(temporary_path, archive)
    finally:
        temporary_path.unlink(missing_ok=True)
    archive_bytes = archive.read_bytes()
    return {
        "package": package,
        "version": contract.version,
        "archive": archive.name,
        "bytes": len(archive_bytes),
        "sha256": sha256_bytes(archive_bytes),
        "dependency_closure": list(closure),
    }


def atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as temporary:
        temporary.write(payload)
        temporary_path = Path(temporary.name)
    os.replace(temporary_path, path)


def build_release(
    repository: Path,
    output: Path,
    requested: Sequence[str],
    allow_dirty: bool,
) -> dict[str, Any]:
    failures = check_package_workspace.check_repository(repository)
    if failures:
        raise ReleaseError("package workspace is invalid:\n" + "\n".join(failures))
    contracts = load_contracts(repository)
    policy = load_policy(repository, contracts)
    published = sorted(
        name for name, entry in policy.items() if entry["status"] == "published"
    )
    packages = list(requested) if requested else published
    unknown = sorted(set(packages) - set(contracts))
    unpublished = sorted(
        name for name in packages if name in policy and policy[name]["status"] != "published"
    )
    if unknown:
        raise ReleaseError(f"unknown packages requested: {unknown}")
    if unpublished:
        raise ReleaseError(f"packages are not publishable: {unpublished}")
    if len(packages) != len(set(packages)):
        raise ReleaseError("package selection contains duplicates")
    identity = source_identity(repository)
    if identity["dirty"] and not allow_dirty:
        raise ReleaseError("source tree is dirty; commit it or pass --allow-dirty")
    tracked = tracked_files(repository)
    archives = [
        build_archive(
            repository,
            output,
            package,
            contracts,
            policy,
            identity,
            tracked,
        )
        for package in sorted(packages)
    ]
    index = {
        "schema": INDEX_SCHEMA,
        "source": identity,
        "archives": archives,
    }
    atomic_write(
        output / "index.json",
        (json.dumps(index, indent=2, sort_keys=True) + "\n").encode(),
    )
    sums = "".join(f"{entry['sha256']}  {entry['archive']}\n" for entry in archives)
    atomic_write(output / "SHA256SUMS", sums.encode())
    return index


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build deterministic, dependency-closed Zig package archives"
    )
    parser.add_argument("--repo", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path, default=ROOT / "zig-out/packages")
    parser.add_argument("--package", action="append", default=[])
    parser.add_argument("--allow-dirty", action="store_true")
    arguments = parser.parse_args(argv)
    try:
        index = build_release(
            arguments.repo.resolve(),
            arguments.output.resolve(),
            arguments.package,
            arguments.allow_dirty,
        )
    except ReleaseError as error:
        parser.error(str(error))
    print(
        "package release: PASS "
        f"({len(index['archives'])} archives, {arguments.output.resolve()})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
