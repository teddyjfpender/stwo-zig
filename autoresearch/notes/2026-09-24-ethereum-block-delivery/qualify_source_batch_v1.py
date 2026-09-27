"""Retain an immutable, focused CPU source qualification attempt.

Only use roots containing nonproving fixtures and retained production bodies.
This runner does not authorize guest, STARK, segment, benchmark or device runs.
Semantic mode analyzes bodies without emitting or running a test binary.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
GATES = HERE / "cpu-performance-gates-v1"
sys.path.insert(0, str(ROOT / "scripts"))
from zig_serial_build import build_lock
from zig_protocol_lib.command import protocol_package_modules


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def local_sources(command: list[str], runner: str | None) -> list[dict[str, str]]:
    modules = {}
    for argument in command:
        if argument.startswith("-M") and "=" in argument:
            name, path = argument[2:].split("=", 1)
            modules[name] = (ROOT / path).resolve()
    pending = list(modules.values())
    # Pin the authoritative dependency graph as well as its source bodies.
    pending.extend(package.contract for package in protocol_package_modules()
                   if package.name in modules)
    if runner:
        pending.append((ROOT / runner).resolve())
    pending.extend((Path(__file__).resolve(), HERE / "test_sha_memory_proof.py",
                    ROOT / "scripts/zig_serial_build.py"))
    pending.extend((ROOT / "scripts/zig_protocol_lib").glob("*.py"))
    found: set[Path] = set()
    while pending:
        path = pending.pop()
        if path in found or not path.is_file() or not path.is_relative_to(ROOT):
            continue
        found.add(path)
        if path.suffix != ".zig":
            continue
        for target in re.findall(r'@(?:import|embedFile)\("([^"\n]+)"\)', path.read_text()):
            if target in modules:
                pending.append(modules[target])
            elif target not in ("std", "builtin"):
                pending.append((path.parent / target).resolve())
    return [{"path": str(path.relative_to(ROOT)), "sha256": digest(path)}
            for path in sorted(found)]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--name", required=True, help="new immutable attempt name including version")
    parser.add_argument("--root", required=True)
    parser.add_argument("--filter", action="append", required=True)
    parser.add_argument("--runner")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--semantic", action="store_true")
    mode.add_argument("--object", action="store_true", help="emit retained production bodies to an object without linking or running")
    parser.add_argument("--package", action="append", default=[])
    parser.add_argument("--optimize", choices=("Debug", "ReleaseSafe", "ReleaseFast"), default="ReleaseFast")
    options = parser.parse_args()
    if options.object and options.runner:
        parser.error("retained-body objects do not use a test runner")
    if not re.fullmatch(r"[a-z0-9-]+", options.name):
        parser.error("attempt names must be plain lower-case letters, digits and hyphens")
    source_path = GATES / f"{options.name}-source.json"
    result_path = GATES / f"{options.name}-result.json"
    log_path = GATES / f"{options.name}.log"
    if any(path.exists() for path in (source_path, result_path, log_path)):
        parser.error("attempt exists; preserve evidence and choose a new version")
    spec = importlib.util.spec_from_file_location("focused_source_command", HERE / "test_sha_memory_proof.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    inputs = ["--root", options.root, "--optimize", options.optimize]
    if options.runner:
        inputs += ["--test-runner", options.runner]
    for package in options.package:
        inputs += ["--package", package]
    command = module.command(inputs + options.filter)
    if options.object:
        command[1] = "build-obj"
        stripped = []
        arguments = iter(command)
        for argument in arguments:
            if argument == "--test-filter":
                next(arguments)
            else:
                stripped.append(argument)
        command = stripped
    binary = Path("/tmp") / (f"block-v5-{options.name}" + (".o" if options.object else ""))
    command.append("-fno-emit-bin" if options.semantic else f"-femit-bin={binary}")
    with build_lock(label=options.name):
        # Pin after acquiring the shared compiler lane, immediately before use.
        sources = local_sources(command, options.runner)
        snapshot = {"sources": sources, "command": command,
                    "scope": "retained production object; never executed" if options.object else "nonproving fixtures and retained bodies; zero-test focused runs rejected",
                    "compiler_sha256": digest(Path(command[0]))}
        with source_path.open("x") as output:
            json.dump(snapshot, output, indent=2)
            output.write("\n")
        print(f"Starting {options.name}: {len(sources)} source pins", flush=True)
        started = time.monotonic()
        with log_path.open("x") as output:
            completed = subprocess.run(command, cwd=ROOT, stdout=output, stderr=subprocess.STDOUT)
        elapsed = time.monotonic() - started
        changed = [entry["path"] for entry in sources
                   if not (ROOT / entry["path"]).is_file() or digest(ROOT / entry["path"]) != entry["sha256"]]
        if digest(Path(command[0])) != snapshot["compiler_sha256"]:
            changed.append(command[0])
    output = log_path.read_text()
    discoveries = [int(value) for value in re.findall(r"^\d+/(\d+) ", output, re.MULTILINE)]
    count = max(discoveries, default=0)
    emitted_object = options.object and binary.is_file() and binary.stat().st_size > 0
    qualified = completed.returncode == 0 and not changed and (options.semantic or emitted_object or count > 0)
    record = {"source_candidate": source_path.name, "exit_code": completed.returncode,
              "elapsed_seconds": elapsed, "changed_source_pins": changed,
              "qualified": qualified, "semantic_only": options.semantic,
              "object_only": options.object,
              "tests_run": count > 0, "discovered_tests": count,
              "test_summary": re.findall(r"^(?:All \d+ tests passed\.|\d+ passed;.*)$", output, re.MULTILINE),
              "log": str(log_path.relative_to(ROOT)), "segments_run": False,
              "stark_proving_run": False, "device_run": False,
              "binary": None if options.semantic or not binary.exists() else
                  {"path": str(binary), "bytes": binary.stat().st_size, "sha256": digest(binary)}}
    with result_path.open("x") as result:
        json.dump(record, result, indent=2)
        result.write("\n")
    print(json.dumps(record), flush=True)
    print(output[-12000:], flush=True)
    return completed.returncode or int(not qualified)


if __name__ == "__main__":
    raise SystemExit(main())
