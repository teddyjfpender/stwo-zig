#!/usr/bin/env python3
"""Create-only, resumable controller for Ethereum optimization observations.

The controller does not execute an arbitrary benchmark child.  A typed result
adapter produces an observation; this runner journals, reopens, validates, and
commits it.  A crash after intent therefore creates a new retained attempt
without discarding any earlier fixture or round.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import os
import sys
from typing import Any


BENCHMARK_DIR = Path(__file__).resolve().parent
REPOSITORY = Path(__file__).resolve().parents[2]
for search_path in (str(REPOSITORY), str(BENCHMARK_DIR)):
    if search_path not in sys.path:
        sys.path.insert(0, search_path)

import ethereum_block_optimization_protocol as optimization  # noqa: E402
from scripts import ethereum_block_proof_protocol as protocol  # noqa: E402
from scripts import ethereum_block_proof_store as store  # noqa: E402


RUN_SCHEMA = "stwo.ethereum.optimization-run.v1"
ATTEMPT_RECORD_SCHEMA = "stwo.ethereum.optimization-task-attempt-record.v1"
SELECTED_SCHEMA = "stwo.ethereum.optimization-task-selection.v1"
PHASES = ("intent", "indeterminate", "prepared", "committed")


class OptimizationRunnerError(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise OptimizationRunnerError(message)


def _read_json(path: Path, where: str) -> dict[str, Any]:
    raw = store.read_regular(path, where, maximum=store.MAX_JSON_BYTES)
    value = store.decode_strict(raw)
    _require(type(value) is dict and raw == protocol.canonical_bytes(value),
             f"{where} is not canonical JSON")
    return value


def _identity(path: Path, where: str) -> dict[str, Any]:
    path = path.absolute()
    return {"path": str(path), **store.file_identity(path, where)}


def _publish(path: Path, value: dict[str, Any], staging: Path) -> None:
    store.publish_new_or_identical(
        path, protocol.canonical_bytes(value), staging_directory=staging,
    )


def initialize(plan_path: Path, run_root: Path, staging: Path) -> dict[str, Any]:
    plan_path = plan_path.absolute()
    plan = _read_json(plan_path, "optimization plan")
    optimization.validate_plan(plan)
    run_root = run_root.absolute()
    staging = staging.absolute()
    store.require_directory(run_root.parent, "optimization run parent")
    store.require_directory(run_root, "optimization run root", create=True)
    store.require_directory(staging, "optimization staging directory", create=True)
    tasks = run_root / "tasks"
    store.require_directory(tasks, "optimization tasks root", create=True)
    authority = protocol.seal({
        "schema": RUN_SCHEMA,
        "plan": _identity(plan_path, "optimization plan"),
        "plan_sha256": plan["content_sha256"],
        "staging_directory": str(staging),
        "task_count": len(plan["tasks"]),
    })
    _publish(run_root / "run.json", authority, staging)
    return authority


def _load_run(run_root: Path) -> tuple[dict[str, Any], dict[str, Any], Path]:
    run_root = run_root.absolute()
    store.require_directory(run_root, "optimization run root")
    run = _read_json(run_root / "run.json", "optimization run authority")
    _require(set(run) == {
        "schema", "plan", "plan_sha256", "staging_directory", "task_count",
        "content_sha256",
    } and run["schema"] == RUN_SCHEMA
             and run["content_sha256"] == protocol.content_sha256(run),
             "optimization run authority differs")
    plan_identity = run["plan"]
    _require(type(plan_identity) is dict and set(plan_identity) == {
        "path", "bytes", "sha256",
    }, "optimization run plan identity differs")
    store.validate_file_identity(Path(plan_identity["path"]), {
        "bytes": plan_identity["bytes"], "sha256": plan_identity["sha256"],
    }, "optimization run plan")
    plan = _read_json(Path(plan_identity["path"]), "optimization run plan")
    optimization.validate_plan(plan)
    _require(run["plan_sha256"] == plan["content_sha256"]
             and run["task_count"] == len(plan["tasks"]),
             "optimization run plan binding differs")
    staging = Path(run["staging_directory"])
    _require(staging.is_absolute(), "optimization staging path differs")
    store.require_directory(staging, "optimization staging directory")
    store.require_directory(run_root / "tasks", "optimization tasks root")
    return run, plan, staging


def _task_root(run_root: Path, task: dict[str, Any], *, create: bool) -> Path:
    root = run_root / "tasks" / task["task_id"]
    store.require_directory(root, "optimization task root", create=create)
    return root


def _attempt_directories(task_root: Path) -> list[Path]:
    try:
        entries = sorted(
            (entry for entry in task_root.iterdir()
             if entry.name.startswith("attempt-") and entry.name[8:].isdigit()),
            key=lambda item: int(item.name[8:]),
        )
    except OSError as error:
        raise OptimizationRunnerError("cannot inventory optimization attempts") from error
    _require([entry.name for entry in entries]
             == [f"attempt-{index:03d}" for index in range(len(entries))],
             "optimization attempt sequence differs")
    for entry in entries:
        store.require_directory(entry, "optimization attempt directory")
    return entries


def _record(
    task: dict[str, Any], plan_sha256: str, attempt_index: int, phase: str,
    observation: dict[str, Any] | None,
) -> dict[str, Any]:
    _require(phase in PHASES, "optimization attempt phase differs")
    observation_identity = None
    observation_sha256 = None
    if observation is not None:
        observation_identity = observation["identity"]
        observation_sha256 = observation["content_sha256"]
    return protocol.seal({
        "schema": ATTEMPT_RECORD_SCHEMA,
        "task_id": task["task_id"],
        "plan_sha256": plan_sha256,
        "attempt_index": attempt_index,
        "phase": phase,
        "observation_identity": observation_identity,
        "observation_sha256": observation_sha256,
    })


def _read_record(
    path: Path, task: dict[str, Any], plan_sha256: str, index: int, phase: str,
) -> dict[str, Any]:
    value = _read_json(path, f"optimization {phase} record")
    _require(value.get("content_sha256") == protocol.content_sha256(value)
             and value.get("schema") == ATTEMPT_RECORD_SCHEMA
             and value.get("task_id") == task["task_id"]
             and value.get("plan_sha256") == plan_sha256
             and value.get("attempt_index") == index
             and value.get("phase") == phase,
             f"optimization {phase} record differs")
    return value


def _attempt_state(
    attempt: Path, task: dict[str, Any], plan_sha256: str, index: int,
) -> str:
    present = {phase: os.path.lexists(attempt / f"{phase}.json") for phase in PHASES}
    _require(present["intent"], "optimization attempt lacks intent")
    _read_record(attempt / "intent.json", task, plan_sha256, index, "intent")
    if present["indeterminate"]:
        _require(not present["prepared"] and not present["committed"],
                 "indeterminate optimization attempt carries evidence")
        _read_record(attempt / "indeterminate.json", task, plan_sha256, index,
                     "indeterminate")
        return "indeterminate"
    if present["prepared"]:
        prepared = _read_record(attempt / "prepared.json", task, plan_sha256, index,
                                "prepared")
        _require(prepared["observation_identity"] is not None,
                 "prepared optimization attempt lacks observation")
        if present["committed"]:
            committed = _read_record(attempt / "committed.json", task, plan_sha256,
                                     index, "committed")
            _require(committed["observation_identity"] == prepared["observation_identity"]
                     and committed["observation_sha256"]
                     == prepared["observation_sha256"],
                     "committed optimization observation differs")
            return "committed"
        return "prepared"
    _require(not present["committed"], "optimization commit lacks preparation")
    return "intent"


def _selected(
    task_root: Path, task: dict[str, Any], plan: dict[str, Any],
) -> dict[str, Any] | None:
    path = task_root / "selected.json"
    if not os.path.lexists(path):
        return None
    value = _read_json(path, "optimization task selection")
    _require(set(value) == {
        "schema", "task_id", "plan_sha256", "attempt_index",
        "observation_identity", "observation_sha256", "content_sha256",
    } and value["schema"] == SELECTED_SCHEMA
             and value["task_id"] == task["task_id"]
             and value["plan_sha256"] == plan["content_sha256"]
             and value["content_sha256"] == protocol.content_sha256(value),
             "optimization task selection differs")
    attempts = _attempt_directories(task_root)
    index = value["attempt_index"]
    _require(type(index) is int and 0 <= index < len(attempts)
             and _attempt_state(attempts[index], task, plan["content_sha256"], index)
             == "committed",
             "optimization selected attempt differs")
    committed = _read_record(
        attempts[index] / "committed.json", task, plan["content_sha256"], index,
        "committed",
    )
    _require(value["observation_identity"] == committed["observation_identity"]
             and value["observation_sha256"] == committed["observation_sha256"],
             "optimization selection observation differs")
    return value


def begin_next(run_root: Path) -> dict[str, Any] | None:
    _, plan, staging = _load_run(run_root)
    run_root = run_root.absolute()
    for task in plan["tasks"]:
        task_root = _task_root(run_root, task, create=True)
        if _selected(task_root, task, plan) is not None:
            continue
        attempts = _attempt_directories(task_root)
        if attempts:
            last = attempts[-1]
            state = _attempt_state(
                last, task, plan["content_sha256"], len(attempts) - 1,
            )
            if state == "prepared":
                raise OptimizationRunnerError("prepared observation requires commit recovery")
            if state == "intent":
                sealed = _record(
                    task, plan["content_sha256"], len(attempts) - 1,
                    "indeterminate", None,
                )
                _publish(last / "indeterminate.json", sealed, staging)
            elif state == "committed":
                raise OptimizationRunnerError("committed attempt lacks task selection")
        index = len(attempts)
        attempt = task_root / f"attempt-{index:03d}"
        store.require_directory(attempt, "new optimization attempt", create=True)
        intent = _record(task, plan["content_sha256"], index, "intent", None)
        _publish(attempt / "intent.json", intent, staging)
        return {"task": task, "attempt_index": index, "intent": intent}
    return None


def admit(run_root: Path, observation_path: Path) -> dict[str, Any]:
    _, plan, staging = _load_run(run_root)
    run_root = run_root.absolute()
    observation_path = observation_path.absolute()
    observation = _read_json(observation_path, "optimization observation")
    task_id = observation.get("task", {}).get("task_id")
    task = next((item for item in plan["tasks"] if item["task_id"] == task_id), None)
    _require(task is not None, "optimization observation task is unknown")
    optimization.validate_observation(observation, plan, task)
    task_root = _task_root(run_root, task, create=False)
    _require(_selected(task_root, task, plan) is None,
             "optimization task is already selected")
    attempts = _attempt_directories(task_root)
    _require(attempts, "optimization task lacks a launched intent")
    index = len(attempts) - 1
    attempt = attempts[index]
    _require(_attempt_state(attempt, task, plan["content_sha256"], index) == "intent",
             "optimization current attempt is not admissible")
    custody = {
        "identity": _identity(observation_path, "optimization observation"),
        "content_sha256": observation["content_sha256"],
    }
    prepared = _record(task, plan["content_sha256"], index, "prepared", custody)
    _publish(attempt / "prepared.json", prepared, staging)
    committed = _record(task, plan["content_sha256"], index, "committed", custody)
    _publish(attempt / "committed.json", committed, staging)
    selection = protocol.seal({
        "schema": SELECTED_SCHEMA,
        "task_id": task["task_id"],
        "plan_sha256": plan["content_sha256"],
        "attempt_index": index,
        "observation_identity": custody["identity"],
        "observation_sha256": custody["content_sha256"],
    })
    _publish(task_root / "selected.json", selection, staging)
    return selection


def _committed_observations(
    run_root: Path, plan: dict[str, Any], *, require_complete: bool,
) -> list[dict[str, Any]]:
    observations = []
    missing = []
    for task in plan["tasks"]:
        candidate_root = run_root / "tasks" / task["task_id"]
        if not os.path.lexists(candidate_root):
            missing.append(task["task_id"])
            continue
        task_root = _task_root(run_root, task, create=False)
        selected = _selected(task_root, task, plan)
        if selected is None:
            missing.append(task["task_id"])
            continue
        identity = selected["observation_identity"]
        store.validate_file_identity(Path(identity["path"]), {
            "bytes": identity["bytes"], "sha256": identity["sha256"],
        }, "selected optimization observation")
        observation = _read_json(
            Path(identity["path"]), "selected optimization observation",
        )
        optimization.validate_observation(observation, plan, task)
        _require(observation["content_sha256"] == selected["observation_sha256"],
                 "selected optimization observation content differs")
        observations.append(observation)
    _require(not require_complete or not missing,
             "optimization run has uncommitted tasks")
    return observations


def status(run_root: Path) -> dict[str, Any]:
    _, plan, _ = _load_run(run_root)
    run_root = run_root.absolute()
    committed = _committed_observations(run_root, plan, require_complete=False)
    return {
        "schema": "stwo.ethereum.optimization-run-status.v1",
        "task_count": len(plan["tasks"]),
        "committed_task_count": len(committed),
        "complete": len(committed) == len(plan["tasks"]),
        "promotion_possible": plan["trial_class"] == "promotion",
    }


def finalize(run_root: Path, output: Path) -> dict[str, Any]:
    _, plan, staging = _load_run(run_root)
    observations = _committed_observations(
        run_root.absolute(), plan, require_complete=True,
    )
    result = optimization.summarize(plan, observations)
    optimization.validate_result(result, plan)
    _publish(output.absolute(), result, staging)
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    initialize_command = commands.add_parser("initialize")
    initialize_command.add_argument("--plan", type=Path, required=True)
    initialize_command.add_argument("--run-root", type=Path, required=True)
    initialize_command.add_argument("--staging-directory", type=Path, required=True)
    for name in ("begin-next", "status"):
        command = commands.add_parser(name)
        command.add_argument("--run-root", type=Path, required=True)
    admit_command = commands.add_parser("admit")
    admit_command.add_argument("--run-root", type=Path, required=True)
    admit_command.add_argument("--observation", type=Path, required=True)
    finalize_command = commands.add_parser("finalize")
    finalize_command.add_argument("--run-root", type=Path, required=True)
    finalize_command.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "initialize":
            result = initialize(
                arguments.plan, arguments.run_root, arguments.staging_directory,
            )
        elif arguments.command == "begin-next":
            result = begin_next(arguments.run_root)
        elif arguments.command == "admit":
            result = admit(arguments.run_root, arguments.observation)
        elif arguments.command == "status":
            result = status(arguments.run_root)
        else:
            result = finalize(arguments.run_root, arguments.output)
        print(protocol.canonical_bytes(result).decode("ascii"), end="")
        return 0
    except (
        OptimizationRunnerError, optimization.OptimizationProtocolError,
        protocol.ProofProtocolError,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
