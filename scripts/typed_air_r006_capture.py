#!/usr/bin/env python3
"""Plan, capture, and independently validate R-006 profiled worker sweeps."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
REPOSITORY = SCRIPT_DIR.parent
if str(REPOSITORY) not in sys.path:
    sys.path.insert(0, str(REPOSITORY))

from scripts.typed_air_r006_capture_lib import (  # noqa: E402
    CaptureError,
    CaptureSettings,
    PAIR_ATTEMPTS,
    PairCaptureSettings,
    PairPlanSettings,
    PlanSettings,
    SmokeSettings,
    build_plan,
    build_pair_plan,
    capture,
    capture_pair,
    evaluate_pair_scaling,
    evaluate_pair_prefix_scaling,
    host_preflight,
    install_candidate,
    installed_v4_smoke,
    load_plan,
    load_pair_plan,
    materialize_snapshot,
    validate_bundle,
    validate_host_preflight,
    validate_pair_bundle,
    validate_pair_prefix,
    validate_pair_prefix_reduction,
    validate_pair_reduction,
    validate_snapshot_receipt,
    write_plan_new,
    write_pair_plan_new,
)
from scripts.typed_air_r006_capture_lib.codec import (  # noqa: E402
    canonical_bytes,
    decode_strict,
    sha256_bytes,
    write_new,
)
from scripts.typed_air_r006_capture_lib.contract import (  # noqa: E402
    WorkloadPaths,
    materialized_poseidon_input,
)
from scripts.typed_air_r006_capture_lib.model import (  # noqa: E402
    GENERATED_WORKLOADS,
    GENERATED_WORKLOAD_PARAMETERS,
    LANES,
    PLAN_ATTEMPTS,
    WORKLOAD_IDS,
)


def _binding(value: str) -> tuple[str, Path]:
    name, separator, path = value.partition("=")
    if not separator or name not in WORKLOAD_IDS or not path:
        raise argparse.ArgumentTypeError("binding must be one admitted WORKLOAD=PATH")
    return name, Path(path)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=REPOSITORY)
    commands = parser.add_subparsers(dest="command", required=True)

    materialize = commands.add_parser(
        "materialize-inputs",
        help="create the two frozen per-workload generated input files",
    )
    materialize.add_argument("--output-dir", type=Path, required=True)

    snapshot = commands.add_parser(
        "snapshot",
        help="materialize a content-bound diagnostic source snapshot outside the checkout",
    )
    snapshot.add_argument("--destination", type=Path, required=True)
    snapshot.add_argument("--receipt", type=Path, required=True)

    validate_snapshot = commands.add_parser(
        "validate-snapshot",
        help="replay a diagnostic snapshot receipt against its clean isolated source",
    )
    validate_snapshot.add_argument("receipt", type=Path)

    preflight = commands.add_parser(
        "host-preflight",
        help="seal AC-power, low-power, quiet-host, thermal, and Metal evidence",
    )
    preflight.add_argument("--output", type=Path, required=True)

    validate_preflight = commands.add_parser(
        "validate-host-preflight",
        help="independently replay a canonical R-006 host-preflight receipt",
    )
    validate_preflight.add_argument("receipt", type=Path)
    validate_preflight.add_argument(
        "--require-admitted",
        action="store_true",
        help="reject a valid receipt when its evidence does not admit capture",
    )

    install = commands.add_parser(
        "install-candidate",
        help="build CPU and Metal ReleaseFast candidates from an isolated snapshot",
    )
    install.add_argument("--snapshot", type=Path, required=True)
    install.add_argument("--prefix", type=Path, required=True)
    install.add_argument("--receipt", type=Path, required=True)
    install.add_argument(
        "--execute-releasefast-build",
        action="store_true",
        required=True,
    )

    smoke = commands.add_parser(
        "smoke-installed-v4",
        help="run and independently verify one exact-work V4 proof from an installed binary",
    )
    smoke.add_argument("--snapshot", type=Path, required=True)
    smoke.add_argument("--lane", choices=sorted(LANES), required=True)
    smoke.add_argument("--executable", type=Path, required=True)
    smoke.add_argument("--install-receipt", type=Path, required=True)
    smoke.add_argument("--elf", type=Path, required=True)
    smoke.add_argument("--input", type=Path)
    smoke.add_argument(
        "--generated-workload",
        choices=sorted(GENERATED_WORKLOADS),
        help="explicitly select one frozen generated Poseidon2 workload",
    )
    smoke.add_argument("--bundle", type=Path, required=True)
    smoke.add_argument("--session-id", required=True)
    smoke.add_argument("--timeout-seconds", type=float, default=86_400.0)
    smoke.add_argument(
        "--execute-installed-v4-smoke",
        action="store_true",
        required=True,
    )

    plan = commands.add_parser("plan", help="publish one immutable R-006 plan")
    plan.add_argument("--output", type=Path, required=True)
    plan.add_argument("--session-id", required=True)
    plan.add_argument("--lane", choices=sorted(LANES), required=True)
    plan.add_argument("--power-state", required=True)
    plan.add_argument("--executable", type=Path)
    plan.add_argument("--elf", type=_binding, action="append", default=[])
    plan.add_argument("--input", type=_binding, action="append", default=[])
    plan.add_argument("--toolchain")
    plan.add_argument("--target", default="native")
    plan.add_argument("--cpu-features", default="native")

    pair_plan = commands.add_parser(
        "plan-pair",
        help="publish one immutable CPU/Metal fixed-interleaving R-006 plan",
    )
    pair_plan.add_argument("--output", type=Path, required=True)
    pair_plan.add_argument("--session-id", required=True)
    pair_plan.add_argument("--power-state", required=True)
    pair_plan.add_argument("--cpu-executable", type=Path)
    pair_plan.add_argument("--metal-executable", type=Path)
    pair_plan.add_argument("--elf", type=_binding, action="append", default=[])
    pair_plan.add_argument("--input", type=_binding, action="append", default=[])
    pair_plan.add_argument("--toolchain")
    pair_plan.add_argument("--target", default="native")
    pair_plan.add_argument("--cpu-features", default="native")

    validate_pair_plan = commands.add_parser(
        "validate-pair-plan",
        help="replay an immutable paired CPU/Metal R-006 plan",
    )
    validate_pair_plan.add_argument("plan", type=Path)

    execute_pair = commands.add_parser(
        "capture-pair",
        help="execute or resume the fixed CPU/Metal R-006 schedule",
    )
    execute_pair.add_argument("plan", type=Path)
    execute_pair.add_argument("--bundle", type=Path, required=True)
    execute_pair.add_argument("--timeout-seconds", type=float, default=86_400.0)
    execute_pair.add_argument("--max-new-attempts", type=int)
    execute_pair.add_argument(
        "--authorize-interrupted-attempt-retry",
        action="store_true",
        help=(
            "explicitly attest that no child remains and authorize one retry of "
            "the exact pending intent; the recovery is retained in final evidence"
        ),
    )
    execute_pair.add_argument(
        f"--execute-frozen-{PAIR_ATTEMPTS}-attempt-schedule",
        action="store_true",
        required=True,
    )

    validate_pair_raw = commands.add_parser(
        "validate-pair-bundle",
        help="authenticate both lane bundles and the pair journal",
    )
    validate_pair_raw.add_argument("bundle", type=Path)

    reduce_pair = commands.add_parser(
        "reduce-pair-bundle",
        help="recompute and publish the paired worker-scaling receipt",
    )
    reduce_pair.add_argument("bundle", type=Path)
    reduce_pair.add_argument("--output", type=Path, required=True)

    validate_reduction = commands.add_parser(
        "validate-pair-reduction",
        help="recompute a scaling receipt from its complete raw pair bundle",
    )
    validate_reduction.add_argument("bundle", type=Path)
    validate_reduction.add_argument("receipt", type=Path)

    validate_prefix = commands.add_parser(
        "validate-pair-prefix",
        help="authenticate every retained attempt and select complete comparison blocks",
    )
    validate_prefix.add_argument("bundle", type=Path)

    reduce_prefix = commands.add_parser(
        "reduce-pair-prefix",
        help="publish an append-compatible scaling receipt from complete blocks",
    )
    reduce_prefix.add_argument("bundle", type=Path)
    reduce_prefix.add_argument("--output", type=Path, required=True)
    reduce_prefix.add_argument(
        "--accept-partial-frozen-matrix",
        action="store_true",
        required=True,
        help="acknowledge that the receipt is resumable, partial, and non-promotional",
    )

    validate_prefix_reduction = commands.add_parser(
        "validate-pair-prefix-reduction",
        help="recompute a complete-block prefix receipt from its bound append-only prefix",
    )
    validate_prefix_reduction.add_argument("bundle", type=Path)
    validate_prefix_reduction.add_argument("receipt", type=Path)

    validate = commands.add_parser("validate-plan", help="replay an immutable plan")
    validate.add_argument("plan", type=Path)

    execute = commands.add_parser(
        "capture", help="execute the complete serial fresh-process R-006 schedule"
    )
    execute.add_argument("plan", type=Path)
    execute.add_argument("--bundle", type=Path, required=True)
    execute.add_argument("--timeout-seconds", type=float, default=86_400.0)
    execute.add_argument(
        f"--execute-frozen-{PLAN_ATTEMPTS}-attempt-schedule",
        action="store_true",
        required=True,
    )

    validate_raw = commands.add_parser(
        "validate-bundle", help="authenticate all raw files and recompute projections"
    )
    validate_raw.add_argument("bundle", type=Path)
    return parser


def _zig_toolchain(repository: Path) -> str:
    try:
        result = subprocess.run(
            ("zig", "version"),
            cwd=repository,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CaptureError("cannot resolve the Zig toolchain identity") from error
    if result.returncode != 0 or result.stderr:
        raise CaptureError("zig version failed while planning R-006")
    version = result.stdout.decode("ascii", errors="strict").strip()
    if not version:
        raise CaptureError("zig version returned no identity")
    return f"zig:{version}"


def _defaults(repository: Path) -> dict[str, WorkloadPaths]:
    guest = repository / "vectors/riscv_guests/poseidon2_m31_permute_v1"
    binary = Path("riscv32im-unknown-none-elf/release/poseidon2_m31_permute_v1")
    return {
        "multi_shard_addi": WorkloadPaths(
            repository / "vectors/riscv_elfs/multi_shard_addi.elf", None
        ),
        "memcpy_loop": WorkloadPaths(
            repository / "vectors/riscv_elfs/memcpy_loop.elf", None
        ),
        "balanced_core_and_poseidon2": WorkloadPaths(
            guest / "target-balanced-precompile" / binary, None
        ),
        "poseidon2_dominant": WorkloadPaths(
            guest / "target-precompile" / binary, None
        ),
    }


def _overrides(
    repository: Path,
    elf_values: list[tuple[str, Path]],
    input_values: list[tuple[str, Path]],
) -> dict[str, WorkloadPaths]:
    result = _defaults(repository)
    seen_elf: set[str] = set()
    for name, path in elf_values:
        if name in seen_elf:
            raise CaptureError(f"duplicate workload ELF override: {name}")
        seen_elf.add(name)
        current = result[name]
        result[name] = WorkloadPaths(
            path if path.is_absolute() else repository / path,
            current.input,
        )
    seen_input: set[str] = set()
    for name, path in input_values:
        if name in seen_input:
            raise CaptureError(f"duplicate workload input override: {name}")
        if name not in GENERATED_WORKLOADS:
            raise CaptureError(f"fixed workload does not accept input: {name}")
        seen_input.add(name)
        current = result[name]
        result[name] = WorkloadPaths(
            current.elf,
            path if path.is_absolute() else repository / path,
        )
    return result


def _summary(plan: dict[str, object], status: str) -> dict[str, object]:
    return {
        "schema": "stwo.typed-air.r006-plan-command.v1",
        "status": status,
        "session_id": plan["session_id"],
        "plan_sha256": plan["content_sha256"],
        "lane": plan["lane"],
        "attempts": len(plan["attempts"]),
    }


def _inside(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
    except ValueError:
        return False
    return True


def _external(path: Path, repository: Path, label: str) -> None:
    if _inside(path, repository):
        raise CaptureError(f"{label} must be outside the active repository")


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    repository = args.repository.resolve()
    exit_code = 0
    try:
        if args.command == "materialize-inputs":
            outputs = []
            for workload in GENERATED_WORKLOADS:
                parameters = GENERATED_WORKLOAD_PARAMETERS[workload]
                raw = materialized_poseidon_input(parameters["calls"])
                path = args.output_dir.resolve() / f"{workload}.input.bin"
                write_new(path, raw)
                outputs.append(
                    {
                        "workload": workload,
                        "generator": dict(GENERATED_WORKLOADS[workload]),
                        "parameters": dict(parameters),
                        "input": {
                            "path": str(path),
                            "bytes": len(raw),
                            "sha256": sha256_bytes(raw),
                        },
                    }
                )
            result: dict[str, object] = {
                "schema": "stwo.typed-air.r006-materialized-inputs.v2",
                "schema_version": 2,
                "outputs": outputs,
            }
        elif args.command == "snapshot":
            result = materialize_snapshot(
                repository,
                args.destination,
                args.receipt,
            )
        elif args.command == "validate-snapshot":
            result = validate_snapshot_receipt(args.receipt)
        elif args.command == "host-preflight":
            _external(args.output, repository, "host-preflight receipt")
            result = host_preflight()
            write_new(args.output, canonical_bytes(result))
            exit_code = 0 if result["admissible"] else 2
        elif args.command == "validate-host-preflight":
            raw = args.receipt.read_bytes()
            value = decode_strict(raw)
            if raw != canonical_bytes(value):
                raise CaptureError("R-006 host-preflight receipt is not canonical JSON")
            preflight = validate_host_preflight(
                value,
                require_admitted=args.require_admitted,
            )
            result = {
                "schema": "stwo.typed-air.r006-host-preflight-validation.v1",
                "status": (
                    "VALID_ADMITTED_HOST"
                    if preflight["admissible"]
                    else "VALID_REJECTED_HOST"
                ),
                "admissible": preflight["admissible"],
                "content_sha256": preflight["content_sha256"],
            }
        elif args.command == "install-candidate":
            _external(args.prefix, repository, "diagnostic install prefix")
            _external(args.receipt, repository, "diagnostic install receipt")
            result = install_candidate(
                args.snapshot,
                args.prefix,
                args.receipt,
                execute_releasefast_build=args.execute_releasefast_build,
            )
        elif args.command == "smoke-installed-v4":
            _external(args.bundle, repository, "installed V4 smoke bundle")
            result = installed_v4_smoke(
                SmokeSettings(
                    repository=args.snapshot,
                    lane=args.lane,
                    executable=args.executable,
                    install_receipt=args.install_receipt,
                    elf=args.elf,
                    input_path=args.input,
                    bundle=args.bundle,
                    session_id=args.session_id,
                    execute_installed_v4_smoke=args.execute_installed_v4_smoke,
                    timeout_seconds=args.timeout_seconds,
                    generated_workload_id=args.generated_workload,
                )
            )
        elif args.command == "plan":
            lane = LANES[args.lane]
            executable = args.executable or repository / "zig-out/bin" / lane["executable"]
            plan = build_plan(
                PlanSettings(
                    repository=repository,
                    session_id=args.session_id,
                    lane=args.lane,
                    power_state=args.power_state,
                    executable=executable,
                    workloads=_overrides(repository, args.elf, args.input),
                    toolchain=args.toolchain or _zig_toolchain(repository),
                    target=args.target,
                    cpu_features=args.cpu_features,
                )
            )
            write_plan_new(args.output, plan)
            result = _summary(plan, "created")
        elif args.command == "plan-pair":
            _external(args.output, repository, "paired capture plan")
            cpu_executable = (
                args.cpu_executable
                or repository / "zig-out/bin" / LANES["cpu-native"]["executable"]
            )
            metal_executable = (
                args.metal_executable
                or repository / "zig-out/bin" / LANES["metal-hybrid"]["executable"]
            )
            pair = build_pair_plan(
                PairPlanSettings(
                    repository=repository,
                    session_id=args.session_id,
                    power_state=args.power_state,
                    cpu_executable=cpu_executable,
                    metal_executable=metal_executable,
                    workloads=_overrides(repository, args.elf, args.input),
                    toolchain=args.toolchain or _zig_toolchain(repository),
                    target=args.target,
                    cpu_features=args.cpu_features,
                )
            )
            write_pair_plan_new(args.output, pair)
            result = {
                "schema": "stwo.typed-air.r006-pair-plan-command.v1",
                "status": "created",
                "session_id": pair["session_id"],
                "plan_sha256": pair["content_sha256"],
                "lanes": list(pair["lanes"]),
                "attempts": len(pair["interleaving"]),
            }
        elif args.command == "validate-plan":
            plan = load_plan(args.plan, repository=repository)
            result = _summary(plan, "valid")
        elif args.command == "validate-pair-plan":
            pair = load_pair_plan(
                args.plan,
                repository=repository,
                verify_local=True,
            )
            result = {
                "schema": "stwo.typed-air.r006-pair-plan-command.v1",
                "status": "valid",
                "session_id": pair["session_id"],
                "plan_sha256": pair["content_sha256"],
                "lanes": list(pair["lanes"]),
                "attempts": len(pair["interleaving"]),
            }
        elif args.command == "capture":
            result = capture(
                CaptureSettings(
                    repository=repository,
                    plan_path=args.plan,
                    bundle_path=args.bundle,
                    timeout_seconds=args.timeout_seconds,
                )
            )
        elif args.command == "capture-pair":
            _external(args.bundle, repository, "paired capture bundle")
            result = capture_pair(
                PairCaptureSettings(
                    repository=repository,
                    plan_path=args.plan,
                    bundle_path=args.bundle,
                    execute_frozen_2080_attempt_schedule=getattr(
                        args,
                        f"execute_frozen_{PAIR_ATTEMPTS}_attempt_schedule",
                    ),
                    timeout_seconds=args.timeout_seconds,
                    max_new_attempts=args.max_new_attempts,
                    authorize_interrupted_attempt_retry=(
                        args.authorize_interrupted_attempt_retry
                    ),
                    recovery_controller_commit=(
                        subprocess.run(
                            ("git", "rev-parse", "HEAD"),
                            cwd=REPOSITORY,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            check=True,
                            text=True,
                        ).stdout.strip()
                        if args.authorize_interrupted_attempt_retry
                        else None
                    ),
                )
            )
        elif args.command == "validate-pair-bundle":
            result = validate_pair_bundle(repository, args.bundle)
        elif args.command == "reduce-pair-bundle":
            _external(args.output, repository, "paired scaling receipt")
            result = evaluate_pair_scaling(repository, args.bundle)
            write_new(args.output, canonical_bytes(result))
        elif args.command == "validate-pair-reduction":
            result = validate_pair_reduction(
                repository,
                args.bundle,
                args.receipt,
            )
        elif args.command == "validate-pair-prefix":
            result = validate_pair_prefix(repository, args.bundle)
        elif args.command == "reduce-pair-prefix":
            if not args.accept_partial_frozen_matrix:
                raise CaptureError("prefix reduction requires explicit partial-matrix acceptance")
            _external(args.output, repository, "paired prefix scaling receipt")
            result = evaluate_pair_prefix_scaling(repository, args.bundle)
            write_new(args.output, canonical_bytes(result))
        elif args.command == "validate-pair-prefix-reduction":
            result = validate_pair_prefix_reduction(
                repository,
                args.bundle,
                args.receipt,
            )
        else:
            result = validate_bundle(repository, args.bundle)
    except (CaptureError, OSError, UnicodeError, ValueError) as error:
        print(f"R-006 capture: FAIL: {error}", file=sys.stderr)
        return 1
    sys.stdout.buffer.write(canonical_bytes(result))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
