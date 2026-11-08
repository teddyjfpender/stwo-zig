"""Bounded content-addressed host preimages and independent recomputation."""

from __future__ import annotations

import json
import os
import re
import stat
import tempfile
import zipfile
from pathlib import Path
from typing import Any

from scripts.architecture_host_gate_lib import capture, products, validators
from scripts.build_architecture_receipt_lib.codec import canonical_bytes
from scripts.build_architecture_receipt_lib.model import ReceiptError


MAX_FILES = 512
MAX_FILE_BYTES = 128 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024
HEX64 = re.compile(r"^[0-9a-f]{64}$")
INDEX_FIELDS = {
    "schema", "role", "candidate", "tree", "plan_sha256", "details",
    "host_evidence", "files",
    "path_map",
}
FILE_FIELDS = {"sha256", "size", "executable"}
DETAIL_FIELDS = {
    "record", "stdout_path", "stderr_path", "inputs", "outputs", "failures",
}


def _strict_object(raw: bytes) -> dict[str, Any]:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ReceiptError(f"duplicate architecture preimage JSON field: {key}")
            result[key] = value
        return result

    value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique)
    if not isinstance(value, dict):
        raise ReceiptError("architecture preimage index is not an object")
    return value


def _logical(root: Path, path: Path, digest: str) -> str:
    resolved = path.resolve()
    if resolved.is_relative_to(root.resolve()):
        return resolved.relative_to(root.resolve()).as_posix()
    return f"external/{digest}/{resolved.name}"


def create(
    path: Path, *, root: Path, role: str, candidate: str, tree: str,
    plan_sha256: str, details: dict[str, dict[str, Any]],
    manifest: dict[str, Any], captured_paths: set[Path],
) -> None:
    files: dict[str, dict[str, Any]] = {}
    sources: dict[str, Path] = {}
    path_map: dict[str, str] = {}
    total = 0
    expanded = set(captured_paths)
    for candidate_path in list(captured_paths):
        if candidate_path.is_dir():
            expanded.update(item for item in candidate_path.rglob("*") if item.is_file())
    for source in sorted(expanded):
        if not source.exists() or not source.is_file() or source.is_symlink():
            continue
        size = source.stat().st_size
        if size > MAX_FILE_BYTES:
            raise ReceiptError(f"architecture preimage exceeds per-file bound: {source}")
        total += size
        if total > MAX_TOTAL_BYTES or len(files) >= MAX_FILES:
            raise ReceiptError("architecture preimage bundle exceeds protocol bounds")
        digest = capture.sha256_file(source)
        logical = _logical(root, source, digest)
        files[logical] = {
            "sha256": digest,
            "size": size,
            "executable": bool(source.stat().st_mode & 0o111),
        }
        sources[logical] = source
        path_map[str(source.resolve())] = logical
        if source.resolve().is_relative_to(root.resolve()):
            path_map[source.resolve().relative_to(root.resolve()).as_posix()] = logical
    index = {
        "schema": "build-architecture-evidence-preimages-v1",
        "role": role,
        "candidate": candidate,
        "tree": tree,
        "plan_sha256": plan_sha256,
        "details": details,
        "host_evidence": manifest,
        "files": files,
        "path_map": path_map,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_STORED) as archive:
            archive.writestr("index.json", canonical_bytes(index))
            emitted: set[str] = set()
            for logical, metadata in files.items():
                digest = metadata["sha256"]
                if digest in emitted:
                    continue
                archive.write(sources[logical], f"files/{digest}")
                emitted.add(digest)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _extract(path: Path, destination: Path) -> dict[str, Any]:
    if path.stat().st_size > MAX_TOTAL_BYTES * 2:
        raise ReceiptError("architecture preimage archive exceeds compressed size bound")
    with zipfile.ZipFile(path) as archive:
        members = archive.infolist()
        if not members or len(members) > MAX_FILES + 1:
            raise ReceiptError("architecture preimage archive member count is invalid")
        names = [member.filename for member in members]
        if len(names) != len(set(names)):
            raise ReceiptError("architecture preimage archive contains duplicate members")
        if members[0].filename != "index.json":
            raise ReceiptError("architecture preimage archive lacks canonical index")
        total = sum(member.file_size for member in members)
        if total > MAX_TOTAL_BYTES:
            raise ReceiptError("architecture preimage archive exceeds expanded size bound")
        for member in members:
            pure = Path(member.filename)
            if pure.is_absolute() or ".." in pure.parts or member.is_dir():
                raise ReceiptError("architecture preimage archive contains unsafe member")
        index = _strict_object(archive.read("index.json"))
        if set(index) != INDEX_FIELDS or index.get("schema") != "build-architecture-evidence-preimages-v1":
            raise ReceiptError("architecture preimage index schema drifted")
        files = index.get("files")
        path_map = index.get("path_map")
        if not isinstance(files, dict) or len(files) > MAX_FILES:
            raise ReceiptError("architecture preimage file index is invalid")
        if (
            not isinstance(path_map, dict)
            or not all(
                isinstance(original, str) and isinstance(logical, str) and logical in files
                for original, logical in path_map.items()
            )
        ):
            raise ReceiptError("architecture preimage path map is malformed")
        expected_members = {"index.json"} | {
            f"files/{metadata.get('sha256')}" for metadata in files.values()
            if isinstance(metadata, dict)
        }
        if {member.filename for member in members} != expected_members:
            raise ReceiptError("architecture preimage archive members differ from index")
        for logical, metadata in files.items():
            if not isinstance(logical, str) or not isinstance(metadata, dict):
                raise ReceiptError("architecture preimage file record is malformed")
            if (
                set(metadata) != FILE_FIELDS
                or not isinstance(metadata["sha256"], str)
                or HEX64.fullmatch(metadata["sha256"]) is None
                or not isinstance(metadata["size"], int)
                or isinstance(metadata["size"], bool)
                or metadata["size"] < 0
                or metadata["size"] > MAX_FILE_BYTES
                or not isinstance(metadata["executable"], bool)
            ):
                raise ReceiptError("architecture preimage file metadata is malformed")
            target = (destination / logical).resolve()
            if not target.is_relative_to(destination.resolve()):
                raise ReceiptError("architecture preimage logical path escapes reconstruction root")
            payload = archive.read(f"files/{metadata['sha256']}")
            if len(payload) != metadata.get("size") or capture.sha256_bytes(payload) != metadata["sha256"]:
                raise ReceiptError("architecture preimage content digest mismatch")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload)
            if metadata.get("executable") is True:
                target.chmod(target.stat().st_mode | stat.S_IXUSR)
    return index


def verify(
    path: Path, *, plan_value: dict[str, Any], protocol: dict[str, Any],
    role: str, candidate: str, tree: str, plan_sha256: str,
    reinspect_link_binaries: bool = True,
) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="stwo-architecture-preimages-") as raw:
        reconstructed = Path(raw)
        index = _extract(path, reconstructed)
        if (
            index.get("role") != role
            or index.get("candidate") != candidate
            or index.get("tree") != tree
            or index.get("plan_sha256") != plan_sha256
        ):
            raise ReceiptError("architecture preimage identity differs from protected verification")
        details = index.get("details")
        manifest = index.get("host_evidence")
        if not isinstance(details, dict) or not isinstance(manifest, dict):
            raise ReceiptError("architecture preimage derivation inputs are malformed")
        role_plan = plan_value["roles"][role]
        expected_ids = [item["id"] for item in role_plan["commands"]]
        if list(details) != expected_ids:
            raise ReceiptError("architecture preimage command coverage differs from authority plan")
        command_outputs: dict[str, Path] = {}
        for ordinal, raw_command in enumerate(role_plan["commands"]):
            command_id = raw_command["id"]
            detail = details[command_id]
            if not isinstance(detail, dict) or set(detail) != DETAIL_FIELDS:
                raise ReceiptError("architecture command preimage fields drifted")
            record = detail["record"]
            if manifest["commands"][ordinal] != record:
                raise ReceiptError("architecture preimage command record differs from receipt")
            try:
                stdout = reconstructed / index["path_map"][detail["stdout_path"]]
                stderr = reconstructed / index["path_map"][detail["stderr_path"]]
            except KeyError as error:
                raise ReceiptError("architecture command log lacks an exact logical path") from error
            if capture.sha256_file(stdout) != record["stdout_sha256"]:
                raise ReceiptError("architecture command stdout digest differs from record")
            if capture.sha256_file(stderr) != record["stderr_sha256"]:
                raise ReceiptError("architecture command stderr digest differs from record")
            command_outputs[command_id] = stdout
            validators.validate_stdout(command_id, stdout, host_role=role)
            try:
                outputs = [reconstructed / index["path_map"][relative] for relative in detail["outputs"]]
                inputs = [
                    reconstructed / index["path_map"][original]
                    for original in detail["inputs"]
                ]
            except KeyError as error:
                raise ReceiptError(
                    f"architecture preimage lacks exact logical path: {error.args[0]}"
                ) from error
            if outputs:
                validators.validate_outputs(
                    command_id, outputs, inputs, root=reconstructed, candidate=candidate,
                    host_role=role,
                    reinspect_link_binaries=reinspect_link_binaries,
                )
        product_records = [
            products.collect(
                spec, root=reconstructed, command_outputs=command_outputs,
                candidate=candidate, tree=tree,
            )
            for spec in role_plan["products"]
        ]
        if product_records != manifest["products"]:
            raise ReceiptError("architecture product records differ from protected recomputation")
        from scripts.architecture_host_gate_lib.controller import _checkpoints, _evidence

        checkpoints = _checkpoints(
            role=role, protocol=protocol, role_plan=role_plan,
            details=details, product_records=product_records,
            plan_sha256=plan_sha256, source_clean=True,
        )
        evidence = _evidence(
            role=role, protocol=protocol, architecture_plan=plan_value,
            checkpoints=checkpoints, details=details,
        )
        if checkpoints != manifest["checkpoints"] or evidence != manifest["evidence"]:
            raise ReceiptError("architecture checkpoint/evidence derivation differs from recomputation")
        return index
