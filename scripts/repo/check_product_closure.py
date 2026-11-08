#!/usr/bin/env python3
"""Check one descriptor-supplied focused product and emit a bound receipt."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.product_closure.graph import ClosureError, inspect_sources
from scripts.product_closure.linkage import (
    LinkageError,
    check_dynamic,
    check_static_elf,
    inspect_dynamic,
    inspect_elf,
    sha256_file,
)
from scripts.product_closure.model import Manifest, parse_named_import


DEFAULT_GENERATED = ("build_identity", "builtin", "product_identity", "std")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument("--repo", type=Path, default=ROOT)
    result.add_argument("--product", required=True)
    result.add_argument("--entry-root", action="append", default=[])
    result.add_argument("--named-import", action="append", default=[])
    result.add_argument("--generated-import", action="append", default=[])
    result.add_argument("--allow-file", action="append", default=[])
    result.add_argument("--allow-prefix", action="append", default=[])
    result.add_argument("--binary", type=Path)
    result.add_argument("--require-link", action="append", default=[])
    result.add_argument("--forbid-link", action="append", default=[])
    result.add_argument("--static-binary", type=Path)
    result.add_argument("--static-machine", default="x86_64")
    result.add_argument("--static-bits", type=int, choices=(32, 64), default=64)
    result.add_argument("--receipt", type=Path)
    return result


def run(args: argparse.Namespace) -> tuple[list[str], dict[str, object]]:
    repository = args.repo.resolve()
    errors: list[str] = []
    if (args.require_link or args.forbid_link) and args.binary is None:
        return ["dynamic linkage policy requires --binary"], {}
    try:
        named = tuple(parse_named_import(raw) for raw in args.named_import)
    except ValueError as error:
        return [str(error)], {}
    manifest = Manifest(
        product=args.product,
        entry_roots=tuple(args.entry_root),
        named_imports=named,
        generated_imports=frozenset((*DEFAULT_GENERATED, *args.generated_import)),
        allowed_files=frozenset(args.allow_file),
        allowed_prefixes=tuple(args.allow_prefix),
    )
    try:
        graph = inspect_sources(repository, manifest)
    except ClosureError as error:
        return str(error).splitlines(), {}

    receipt: dict[str, object] = {
        "schema": "stwo-zig-product-closure-v1",
        "product": args.product,
        "manifest": manifest.canonical(),
        "manifest_sha256": manifest.digest(),
        "source": {
            "entry_roots": list(manifest.entry_roots),
            "named_imports": {
                item.name: item.source for item in sorted(named, key=lambda item: item.name)
            },
            "generated_imports": sorted(manifest.generated_imports),
            "source_count": len(graph.sources),
            "content_sha256": graph.source_digest(),
            "sources": list(graph.relative_sources()),
        },
    }
    if args.binary:
        try:
            linkage = inspect_dynamic(args.binary)
        except (LinkageError, OSError) as error:
            errors.append(str(error))
        else:
            errors.extend(
                check_dynamic(linkage, tuple(args.require_link), tuple(args.forbid_link))
            )
            receipt["binary"] = {
                "sha256": sha256_file(args.binary),
                "dynamic_inspector": linkage.inspector,
                "dynamic_output": linkage.output.splitlines(),
            }
    if args.static_binary:
        try:
            identity = inspect_elf(args.static_binary)
        except (LinkageError, OSError) as error:
            errors.append(str(error))
        else:
            errors.extend(check_static_elf(identity, args.static_machine, args.static_bits))
            receipt["static_binary"] = {
                "sha256": sha256_file(args.static_binary),
                "bits": identity.bits,
                "machine": identity.machine,
                "has_interpreter": identity.has_interpreter,
            }
    return errors, receipt


def write_receipt(path: Path, receipt: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(receipt, indent=2, sort_keys=True) + "\n"
    descriptor, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main() -> int:
    args = parser().parse_args()
    errors, receipt = run(args)
    if errors:
        print("\n".join(errors))
        return 1
    if args.receipt:
        write_receipt(args.receipt, receipt)
    source = receipt["source"]
    assert isinstance(source, dict)
    print(
        f"{args.product} closure: PASS "
        f"({source['source_count']} transitive Zig sources, {source['content_sha256']})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
