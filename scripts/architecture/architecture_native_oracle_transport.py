#!/usr/bin/env python3
"""Pack and extract exact mode-preserving Native oracle tar transports."""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import stat
import sys
import tarfile
import tempfile
from pathlib import Path


MEMBERS = {"manifest.json": 0o644, "stwo-interop-rs": 0o555}
MAX_MEMBER_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE_BYTES = 512 * 1024 * 1024


class TransportError(ValueError):
    pass


def _regular(path: Path, mode: int) -> None:
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or path.is_symlink()
        or metadata.st_size <= 0
        or metadata.st_size > MAX_MEMBER_BYTES
        or stat.S_IMODE(metadata.st_mode) != mode
    ):
        raise TransportError(f"Native oracle transport member is unsafe: {path.name}")


def pack(bundle: Path, output: Path) -> str:
    bundle = bundle.resolve(strict=True)
    if {path.name for path in bundle.iterdir()} != set(MEMBERS):
        raise TransportError("Native oracle bundle path set drifted")
    if output.exists():
        raise TransportError("refusing to replace Native oracle transport")
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{output.name}.", dir=output.parent)
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        with tarfile.open(temporary, "w", format=tarfile.USTAR_FORMAT) as archive:
            for name, mode in MEMBERS.items():
                source = bundle / name
                _regular(source, mode)
                info = archive.gettarinfo(str(source), arcname=name)
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""
                info.mtime = 0
                info.mode = mode
                with source.open("rb") as stream:
                    archive.addfile(info, stream)
        temporary.replace(output)
    finally:
        temporary.unlink(missing_ok=True)
    return hashlib.sha256(output.read_bytes()).hexdigest()


def extract(archive_path: Path, output: Path) -> str:
    if archive_path.stat().st_size <= 0 or archive_path.stat().st_size > MAX_ARCHIVE_BYTES:
        raise TransportError("Native oracle transport size is invalid")
    if output.exists():
        raise TransportError("refusing to replace extracted Native oracle bundle")
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=output.parent))
    try:
        with tarfile.open(archive_path, "r:") as archive:
            members = archive.getmembers()
            names = [member.name for member in members]
            if names != list(MEMBERS) or len(names) != len(set(names)):
                raise TransportError("Native oracle transport member schema drifted")
            for member in members:
                if (
                    not member.isfile()
                    or member.issym()
                    or member.islnk()
                    or member.size <= 0
                    or member.size > MAX_MEMBER_BYTES
                    or member.uid != 0
                    or member.gid != 0
                    or member.uname != ""
                    or member.gname != ""
                    or member.mtime != 0
                    or member.mode != MEMBERS[member.name]
                ):
                    raise TransportError("Native oracle transport metadata drifted")
                stream = archive.extractfile(member)
                if stream is None:
                    raise TransportError("Native oracle transport member has no payload")
                target = staging / member.name
                with target.open("xb") as destination:
                    shutil.copyfileobj(stream, destination, length=1024 * 1024)
                target.chmod(MEMBERS[member.name])
        staging.replace(output)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return hashlib.sha256(archive_path.read_bytes()).hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    phases = parser.add_subparsers(dest="phase", required=True)
    create = phases.add_parser("pack")
    create.add_argument("--bundle", type=Path, required=True)
    create.add_argument("--output", type=Path, required=True)
    unpack = phases.add_parser("extract")
    unpack.add_argument("--archive", type=Path, required=True)
    unpack.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        digest = pack(args.bundle, args.output) if args.phase == "pack" else extract(
            args.archive, args.output,
        )
    except (OSError, tarfile.TarError, TransportError) as error:
        print(f"architecture Native oracle transport: FAIL: {error}", file=sys.stderr)
        return 2
    print(f"architecture Native oracle transport: PASS sha256:{digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
