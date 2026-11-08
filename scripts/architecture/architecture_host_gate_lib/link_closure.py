#!/usr/bin/env python3
"""Inspect exact architecture binaries against focused linkage policy."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

from scripts.product_closure.linkage import (
    DynamicLinkage,
    LinkageError,
    check_dynamic,
    check_static_elf,
    inspect_dynamic,
    inspect_elf,
    sha256_file,
)


POLICY = {
    "stwo-native-cpu": {"required": (), "forbidden": ("Metal", "Foundation", "libobjc", "cuda")},
    "stwo-riscv-cpu": {"required": (), "forbidden": ("Metal", "Foundation", "libobjc", "cuda")},
    "stwo-native-metal": {"required": ("Metal", "Foundation", "libobjc"), "forbidden": ("cuda",)},
    "stwo-zig": {"required": (), "forbidden": ("Metal", "Foundation", "libobjc", "cuda")},
}
RECEIPT_FIELDS = {
    "schema", "status", "product_id", "binary", "static_binary",
    "required", "forbidden", "failures",
}


def host_policy(product: str, host_role: str) -> dict[str, tuple[str, ...]]:
    if product == "stwo-zig" and host_role == "macos":
        return {
            "required": ("Metal", "Foundation", "libobjc"),
            "forbidden": ("cuda",),
        }
    return POLICY[product]


def write(path: Path, value: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(value, output, indent=2, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def inspect(
    product: str, binary: Path, static_binary: Path | None,
    host_role: str | None = None,
) -> dict[str, object]:
    role = host_role or ("macos" if sys.platform == "darwin" else "linux")
    policy = host_policy(product, role)
    dynamic = inspect_dynamic(binary)
    failures = check_dynamic(dynamic, policy["required"], policy["forbidden"])
    static = None
    if static_binary is not None:
        identity = inspect_elf(static_binary)
        failures.extend(check_static_elf(identity, "x86_64", 64))
        static = {
            "path": str(static_binary),
            "sha256": sha256_file(static_binary),
            "bits": identity.bits,
            "machine": identity.machine,
            "has_interpreter": identity.has_interpreter,
        }
    return {
        "schema": "build-architecture-link-closure-v1",
        "status": "PASS" if not failures else "NO-GO",
        "product_id": product,
        "binary": {
            "path": str(binary),
            "sha256": sha256_file(binary),
            "inspector": dynamic.inspector,
            "output": dynamic.output.splitlines(),
        },
        "static_binary": static,
        "required": list(policy["required"]),
        "forbidden": list(policy["forbidden"]),
        "failures": failures,
    }


def validate_receipt(
    path: Path, *, product: str, binary: Path, static_binary: Path | None,
    host_role: str | None = None,
    logical_binary: Path | None = None, logical_static_binary: Path | None = None,
    reinspect_binary: bool = True,
) -> dict[str, object]:
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise LinkageError(f"duplicate link-closure receipt field: {key}")
            value[key] = item
        return value

    value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique)
    if not isinstance(value, dict) or set(value) != RECEIPT_FIELDS:
        raise LinkageError("link-closure receipt fields drifted")
    role = host_role or ("macos" if sys.platform == "darwin" else "linux")
    actual_role = "macos" if sys.platform == "darwin" else "linux"
    if reinspect_binary and role != actual_role:
        raise LinkageError("fresh linkage recomputation must run on the product host role")
    policy = host_policy(product, role)
    recorded_binary = logical_binary or binary
    if (
        value["schema"] != "build-architecture-link-closure-v1"
        or value["status"] != "PASS"
        or value["product_id"] != product
        or value["required"] != list(policy["required"])
        or value["forbidden"] != list(policy["forbidden"])
        or value["failures"] != []
    ):
        raise LinkageError("link-closure receipt policy or result drifted")
    dynamic = value["binary"]
    if not isinstance(dynamic, dict) or set(dynamic) != {
        "path", "sha256", "inspector", "output",
    }:
        raise LinkageError("link-closure dynamic identity drifted")
    if (
        dynamic["path"] != str(recorded_binary)
        or dynamic["sha256"] != sha256_file(binary)
        or dynamic["inspector"] not in {"otool", "readelf", "ldd"}
        or not isinstance(dynamic["output"], list)
        or not all(isinstance(item, str) for item in dynamic["output"])
    ):
        raise LinkageError("link-closure dynamic artifact binding drifted")
    expected_inspectors = {"otool"} if role == "macos" else {"readelf", "ldd"}
    if dynamic["inspector"] not in expected_inspectors:
        raise LinkageError("link-closure inspector is inconsistent with the host")
    failures = check_dynamic(
        DynamicLinkage(dynamic["inspector"], "\n".join(dynamic["output"])),
        policy["required"], policy["forbidden"],
    )
    if failures:
        raise LinkageError("link-closure raw dependency preimage violates policy")
    expected_static = None
    if static_binary is not None:
        expected_static = {
            "path": str(logical_static_binary or static_binary),
            "sha256": sha256_file(static_binary),
            "bits": 64,
            "machine": "x86_64",
            "has_interpreter": False,
        }
    if value["static_binary"] != expected_static:
        raise LinkageError("link-closure static artifact binding drifted")
    if reinspect_binary:
        fresh = inspect(product, binary, static_binary, role)
        fresh["binary"]["path"] = str(recorded_binary)
        if fresh["static_binary"] is not None:
            fresh["static_binary"]["path"] = str(logical_static_binary or static_binary)
        if fresh != value:
            raise LinkageError("link-closure receipt differs from fresh binary inspection")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--product", choices=tuple(POLICY), required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--static-binary", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = inspect(args.product, args.binary, args.static_binary)
        write(args.output, report)
    except (LinkageError, OSError, ValueError) as error:
        print(f"architecture link closure: FAIL: {error}")
        return 2
    if report["status"] != "PASS":
        print("\n".join(report["failures"]))
        return 1
    print(f"architecture link closure: PASS ({args.product})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
