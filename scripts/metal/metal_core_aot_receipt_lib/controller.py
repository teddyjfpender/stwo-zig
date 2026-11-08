"""Two-phase Native Metal AOT acceptance orchestration."""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path
from typing import Any

from .artifacts import (
    checksum_path,
    executable_identity,
    load_bundle,
    read_receipt,
    recorded_bundle_identity,
    require_reproducible,
    write_receipt,
)
from .environment import (
    ci_identity,
    exact_commit,
    host_identity,
    require_hosted_ci_identity,
    run,
)
from .model import (
    ANCHOR,
    BUILD_CHECKS,
    BUILD_SCHEMA,
    BUNDLE_NAMES,
    DEVICE_CHECKS,
    DEVICE_SCHEMA,
    ReceiptError,
)


def require_recorded_bundle(recorded: Any, actual: dict[str, Any], name: str) -> None:
    if recorded != recorded_bundle_identity(actual, name):
        raise ReceiptError(f"hosted receipt bundle identity mismatch: {name}")


def require_build_receipt(receipt: dict[str, Any], commit: str) -> dict[str, Any]:
    if receipt.get("phase") != "hosted_build":
        raise ReceiptError("hosted build receipt phase mismatch")
    if receipt.get("repository_commit") != commit:
        raise ReceiptError("hosted build receipt commit mismatch")
    if receipt.get("build_mode") != "ReleaseSafe":
        raise ReceiptError("hosted build receipt mode mismatch")
    if receipt.get("checks") != BUILD_CHECKS:
        raise ReceiptError("hosted build receipt checks mismatch")
    require_hosted_ci_identity(receipt.get("ci"))
    bundles = receipt.get("bundles")
    if not isinstance(bundles, dict) or set(bundles) != set(BUNDLE_NAMES):
        raise ReceiptError("hosted build receipt bundle set mismatch")
    return bundles


def require_receipt_outside_bundles(receipt_out: Path, bundles: tuple[Path, ...]) -> None:
    for bundle in bundles:
        if receipt_out == bundle or receipt_out.is_relative_to(bundle):
            raise ReceiptError("receipt output must not mutate an admitted bundle")


def _build_twice(builder: Path, output_dir: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Run two independent AOT builds into fresh bundles; returns (commands, bundles)."""
    if output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True)
    compiler_workspace = output_dir / ".canonical-compiler-workspace"

    commands: list[dict[str, Any]] = []
    bundles: list[dict[str, Any]] = []
    for bundle in (output_dir / name for name in BUNDLE_NAMES):
        if compiler_workspace.exists():
            shutil.rmtree(compiler_workspace)
        commands.append(
            run([str(builder), "build", "--output-dir", str(compiler_workspace)])
        )
        shutil.copytree(compiler_workspace, bundle, copy_function=shutil.copyfile)
        bundles.append(load_bundle(bundle))
    shutil.rmtree(compiler_workspace)
    return commands, bundles


def reproduce_build(args: argparse.Namespace) -> None:
    """PR-lane verification: the AOT builds are byte-identical, asserted
    without hosted-provenance identity and without writing any receipt —
    the provenance-bound receipt stays exclusive to the metal-acceptance job."""
    output_dir = args.output_dir.resolve()
    builder = args.builder.resolve(strict=True)
    if builder == output_dir or builder.is_relative_to(output_dir):
        raise ReceiptError("builder must be outside the replaceable output directory")
    _, bundles = _build_twice(builder, output_dir)
    require_reproducible(bundles[0], bundles[1])


def capture_build(args: argparse.Namespace) -> str:
    output_dir = args.output_dir.resolve()
    builder = args.builder.resolve(strict=True)
    if builder == output_dir or builder.is_relative_to(output_dir):
        raise ReceiptError("builder must be outside the replaceable output directory")
    receipt_out = args.receipt_out.resolve()
    if receipt_out.parent != output_dir:
        raise ReceiptError("hosted build receipt must be inside the artifact root")
    bundle_paths = tuple(output_dir / name for name in BUNDLE_NAMES)
    require_receipt_outside_bundles(receipt_out, bundle_paths)
    commands, bundles = _build_twice(builder, output_dir)
    require_reproducible(bundles[0], bundles[1])

    ci = ci_identity()
    require_hosted_ci_identity(ci)
    receipt = {
        "schema": BUILD_SCHEMA,
        "phase": "hosted_build",
        "repository_commit": exact_commit(args.commit),
        "build_mode": "ReleaseSafe",
        "checks": BUILD_CHECKS,
        "executables": {"builder": executable_identity(builder)},
        "commands": commands,
        "bundles": {
            name: recorded_bundle_identity(bundle, name)
            for name, bundle in zip(BUNDLE_NAMES, bundles, strict=True)
        },
        "host": host_identity(include_metal_device=False),
        "ci": ci,
    }
    return write_receipt(receipt_out, receipt)


def admit_build(args: argparse.Namespace) -> str:
    commit = exact_commit(args.commit)
    receipt_path = args.build_receipt.resolve(strict=True)
    receipt_out = args.receipt_out.resolve()
    if receipt_out == receipt_path or receipt_out == checksum_path(receipt_path):
        raise ReceiptError("device receipt must not replace its hosted parent")
    bundle_paths = (args.bundle_a.resolve(strict=True), args.bundle_b.resolve(strict=True))
    if bundle_paths[0] == bundle_paths[1]:
        raise ReceiptError("device admission requires two distinct hosted build directories")
    expected_paths = tuple(
        (receipt_path.parent / name).resolve(strict=True) for name in BUNDLE_NAMES
    )
    if bundle_paths != expected_paths:
        raise ReceiptError("hosted bundle paths do not match the canonical receipt layout")
    require_receipt_outside_bundles(receipt_out, bundle_paths)
    probe = args.probe.resolve(strict=True)

    hosted, hosted_sha256 = read_receipt(receipt_path, BUILD_SCHEMA)
    recorded_bundles = require_build_receipt(hosted, commit)
    bundles = (load_bundle(bundle_paths[0]), load_bundle(bundle_paths[1]))
    require_recorded_bundle(recorded_bundles["build-a"], bundles[0], "build-a")
    require_recorded_bundle(recorded_bundles["build-b"], bundles[1], "build-b")
    require_reproducible(bundles[0], bundles[1])

    commands = []
    for bundle in bundle_paths:
        commands.append(
            run(
                [
                    str(probe),
                    "--bundle-dir",
                    str(bundle),
                    "--trust-anchor",
                    str(bundle / ANCHOR),
                ]
            )
        )

    receipt = {
        "schema": DEVICE_SCHEMA,
        "phase": "local_device_admission",
        "repository_commit": commit,
        "build_mode": "ReleaseSafe",
        "parent": {
            "schema": BUILD_SCHEMA,
            "receipt_sha256": hosted_sha256,
            "repository_commit": hosted["repository_commit"],
        },
        "checks": DEVICE_CHECKS,
        "executables": {"probe": executable_identity(probe)},
        "commands": commands,
        "bundles": {
            name: recorded_bundle_identity(bundle, name)
            for name, bundle in zip(BUNDLE_NAMES, bundles, strict=True)
        },
        "host": host_identity(include_metal_device=True),
        "ci": ci_identity(),
    }
    return write_receipt(receipt_out, receipt)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    phases = parser.add_subparsers(dest="phase", required=True)

    build = phases.add_parser("build", help="capture two reproducible AOT builds")
    build.add_argument("--builder", type=Path, required=True)
    build.add_argument("--output-dir", type=Path, required=True)
    build.add_argument("--receipt-out", type=Path, required=True)
    build.add_argument("--commit", default=None)

    reproduce = phases.add_parser(
        "reproduce",
        help="verify the two AOT builds are byte-identical without hosted "
             "provenance (PR lanes; writes no receipt)",
    )
    reproduce.add_argument("--builder", type=Path, required=True)
    reproduce.add_argument("--output-dir", type=Path, required=True)

    admit = phases.add_parser("admit", help="admit a hosted build receipt on a Metal device")
    admit.add_argument("--build-receipt", type=Path, required=True)
    admit.add_argument("--bundle-a", type=Path, required=True)
    admit.add_argument("--bundle-b", type=Path, required=True)
    admit.add_argument("--probe", type=Path, required=True)
    admit.add_argument("--receipt-out", type=Path, required=True)
    admit.add_argument("--commit", default=None)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.phase == "build":
        digest = capture_build(args)
        print(f"Native Metal core hosted build receipt: {digest}")
    elif args.phase == "reproduce":
        reproduce_build(args)
        print("Native Metal core AOT builds are byte-identical (no receipt written)")
    else:
        digest = admit_build(args)
        print(f"Native Metal core device acceptance receipt: {digest}")
    return 0
