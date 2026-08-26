#!/usr/bin/env python3
"""Plan, execute, and independently validate the C-013 CPU capture."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
REPOSITORY = SCRIPT_DIR.parent
if str(REPOSITORY) not in sys.path:
    sys.path.insert(0, str(REPOSITORY))

from scripts.typed_air_c013_capture_lib import (  # noqa: E402
    CaptureError,
    PlanSettings,
    build_plan,
    load_and_validate_plan,
    write_plan_new,
)
from scripts.typed_air_c013_capture_lib.plan import (  # noqa: E402
    ARTIFACT_IDS,
    default_artifacts,
)
from scripts.typed_air_c013_capture_lib.runner import (  # noqa: E402
    CaptureSettings,
    capture,
)
from scripts.typed_air_c013_capture_lib.bundle import validate_bundle  # noqa: E402


def _artifact(value: str) -> tuple[str, Path]:
    name, separator, path = value.partition("=")
    if not separator or name not in ARTIFACT_IDS or not path:
        raise argparse.ArgumentTypeError(
            "artifact override must be one admitted ID=PATH pair"
        )
    return name, Path(path)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repository",
        type=Path,
        default=REPOSITORY,
        help="clean stwo-zig repository snapshot",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    plan = commands.add_parser("plan", help="publish one create-only plan")
    plan.add_argument("--output", type=Path, required=True)
    plan.add_argument("--session-id", required=True)
    plan.add_argument("--power-state", required=True)
    plan.add_argument(
        "--artifact",
        action="append",
        type=_artifact,
        default=[],
        metavar="ID=PATH",
        help="override one default child/tool/ELF path",
    )
    validate = commands.add_parser("validate-plan", help="replay a saved plan")
    validate.add_argument("plan", type=Path)
    validate_bundle_command = commands.add_parser(
        "validate-bundle",
        help="authenticate a finalized bundle and recompute its CPU reduction",
    )
    validate_bundle_command.add_argument("bundle", type=Path)
    execute = commands.add_parser(
        "capture",
        help="execute all 1,520 serial fresh children from a valid plan",
    )
    execute.add_argument("plan", type=Path)
    execute.add_argument("--bundle", type=Path, required=True)
    execute.add_argument("--timeout-seconds", type=float, default=86_400.0)
    execute.add_argument(
        "--execute-frozen-1520-attempt-schedule",
        action="store_true",
        required=True,
        help="explicit acknowledgement of the complete non-retrying schedule",
    )
    return parser


def _summary(plan: dict[str, object], status: str) -> bytes:
    attempts = plan["attempts"]
    assert isinstance(attempts, list)
    return (
        json.dumps(
            {
                "schema": "stwo.typed-air.c013-capture-plan-command.v1",
                "status": status,
                "session_id": plan["session_id"],
                "plan_sha256": plan["content_sha256"],
                "schedule_sha256": plan["schedule"]["sha256"],
                "attempts": len(attempts),
                "lane": plan["lane"],
                "security": plan["security"],
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        + b"\n"
    )


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    repository = args.repository.resolve()
    try:
        if args.command == "plan":
            artifacts = default_artifacts(repository)
            seen: set[str] = set()
            for name, path in args.artifact:
                if name in seen:
                    raise CaptureError(f"duplicate artifact override: {name}")
                seen.add(name)
                artifacts[name] = path if path.is_absolute() else repository / path
            plan = build_plan(
                PlanSettings(
                    repository=repository,
                    session_id=args.session_id,
                    power_state=args.power_state,
                    artifacts=artifacts,
                )
            )
            write_plan_new(args.output, plan)
            output = _summary(plan, "created")
        elif args.command == "validate-plan":
            plan = load_and_validate_plan(args.plan, repository=repository)
            output = _summary(plan, "valid")
        elif args.command == "capture":
            result = capture(
                CaptureSettings(
                    repository=repository,
                    plan_path=args.plan,
                    bundle_path=args.bundle,
                    timeout_seconds=args.timeout_seconds,
                )
            )
            output = (
                json.dumps(result, sort_keys=True, separators=(",", ":")).encode(
                    "ascii"
                )
                + b"\n"
            )
        else:
            result = validate_bundle(repository, args.bundle)
            output = (
                json.dumps(
                    asdict(result),
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("ascii")
                + b"\n"
            )
    except (CaptureError, OSError, ValueError) as error:
        print(f"C-013 capture plan: FAIL: {error}", file=sys.stderr)
        return 1
    sys.stdout.buffer.write(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
