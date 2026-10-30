#!/usr/bin/env python3
"""Plan exact block coverage and publish inputs from one bounded execution.

The census and checkpoint manifests are scheduling evidence, never proof
receipts. Originals, window roots, upper folds and final verification remain
separate obligations. Odd tree frontiers are carried, never duplicated.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import struct

from v7_real_window_corpus import PINS


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def load_census(directory: Path):
    summary_bytes = (directory / "summary.json").read_bytes()
    records_bytes = (directory / "segments.jsonl").read_bytes()
    summary = json.loads(summary_bytes)
    records = [json.loads(line) for line in records_bytes.splitlines() if line]
    if summary["elf_sha256"] != PINS["guest.elf"][0] or summary["input_sha256"] != PINS["input.bin"][0] or summary["output_sha256"] != PINS["expected-output.bin"][0]:
        raise ValueError("retained execution source mismatch")
    first = 1
    previous_pc = None
    totals = {key: 0 for key in ("cycles", "core_rows", "keccak_calls", "recovery_calls", "sha_calls")}
    for index, row in enumerate(records):
        counts = row["counts"]
        if row["index"] != index or row["first_cycle"] != first or (previous_pc is not None and row["entry_pc"] != previous_pc):
            raise ValueError("census coverage/CPU discontinuity")
        if any(type(counts[key]) is not int or counts[key] < 0 for key in totals) or counts["cycles"] == 0:
            raise ValueError("invalid census counters")
        if counts["core_rows"] + sum(counts[key] for key in ("keccak_calls", "recovery_calls", "sha_calls")) != counts["cycles"]:
            raise ValueError("unaccounted retirement")
        if row["terminal"] != ("halt_flag" if index == len(records) - 1 else None):
            raise ValueError("missing or premature terminal")
        first += counts["cycles"]
        previous_pc = row["exit_pc"]
        for key in totals:
            totals[key] += counts[key]
    if len(records) != summary["segments"] or any(totals[key] != summary["counts"][key] for key in totals) or totals["cycles"] != summary["expected_cycles"]:
        raise ValueError("census aggregate mismatch")
    return summary, records, {"summary_sha256": digest(summary_bytes), "segments_sha256": digest(records_bytes)}


def make_plan(directory: Path, native_cycles: int, mixed_cycles: int, caller_calls: int):
    if not 0 < native_cycles <= 1 << 24 or not 0 < mixed_cycles <= 1 << 24 or caller_calls <= 0:
        raise ValueError("invalid independent component bounds")
    summary, records, evidence = load_census(directory)
    windows = []
    for row in records:
        calls = sum(row["counts"][key] for key in ("keccak_calls", "recovery_calls", "sha_calls"))
        kind = "mixed" if calls else "native"
        cap = mixed_cycles if calls else native_cycles
        if row["counts"]["cycles"] > cap or calls > caller_calls:
            raise ValueError("census resolution exceeds component bounds; collect a finer census instead of guessing call positions")
        current = windows[-1] if windows else None
        if current is None or current["kind"] != kind or current["cycles"] + row["counts"]["cycles"] > cap or current["caller_calls"] + calls > caller_calls:
            current = dict(index=len(windows), kind=kind, skip_cycles=row["first_cycle"] - 1, cycles=0, caller_calls=0, counts={key: 0 for key in ("core_rows", "keccak_calls", "recovery_calls", "sha_calls")}, census_first=row["index"], census_count=0)
            windows.append(current)
        current["cycles"] += row["counts"]["cycles"]
        current["caller_calls"] += calls
        current["census_count"] += 1
        for key in current["counts"]:
            current["counts"][key] += row["counts"][key]
    total = summary["expected_cycles"]
    for window in windows:
        window["initial"] = window["skip_cycles"] == 0
        window["terminal"] = window["skip_cycles"] + window["cycles"] == total
        window["id"] = "window-" + digest(canonical(window))[:24]
    # Each node's ordered children partition its exact range. The odd child is
    # carried as the SAME node, so neither proof count nor work is rounded up.
    frontier = [dict(id=w["id"], skip_cycles=w["skip_cycles"], cycles=w["cycles"]) for w in windows]
    folds = []
    level = 0
    while len(frontier) > 1:
        following = []
        for index in range(0, len(frontier), 2):
            if index + 1 == len(frontier):
                following.append(frontier[index])
                continue
            left, right = frontier[index:index + 2]
            if left["skip_cycles"] + left["cycles"] != right["skip_cycles"]:
                raise ValueError("noncontiguous reduction")
            node = dict(level=level, children=[left["id"], right["id"]], skip_cycles=left["skip_cycles"], cycles=left["cycles"] + right["cycles"])
            node["id"] = "fold-" + digest(canonical(node))[:24]
            folds.append(node)
            following.append(node)
        frontier = following
        level += 1
    if not frontier or frontier[0]["skip_cycles"] != 0 or frontier[0]["cycles"] != total or len(folds) != len(windows) - 1:
        raise ValueError("incomplete block reduction")
    return dict(schema="stwo-b8-full-block-schedule-v1", proof_verified=False, scope="execution and proof scheduling only; no verified block result", elf_sha256=summary["elf_sha256"], input_sha256=summary["input_sha256"], output_sha256=summary["output_sha256"], total_cycles=total, security=dict(queries=70, pow_bits=26), evidence=evidence, independent_bounds=dict(native_cycles=native_cycles, mixed_cycles=mixed_cycles, caller_calls=caller_calls), windows=windows, folds=folds, root_id=frontier[0]["id"])


def validate_plan(plan: dict):
    if plan['schema'] != 'stwo-b8-full-block-schedule-v1' or plan['proof_verified'] is not False or plan['security'] != dict(queries=70, pow_bits=26):
        raise ValueError('invalid campaign statement')
    windows, folds = plan['windows'], plan['folds']
    if not 1 <= len(windows) <= 4096 or len(folds) != len(windows) - 1:
        raise ValueError('invalid campaign roster')
    nodes, uses = {}, {}
    cursor = 0
    for index, window in enumerate(windows):
        if window['index'] != index or window['skip_cycles'] != cursor or type(window['cycles']) is not int or not 0 < window['cycles'] <= 1 << 24:
            raise ValueError('invalid campaign coverage')
        cursor += window['cycles']
        if window['initial'] != (index == 0) or window['terminal'] != (index == len(windows) - 1):
            raise ValueError('invalid campaign boundaries')
        body = {key: value for key, value in window.items() if key != 'id'}
        if window['id'] != 'window-' + digest(canonical(body))[:24] or not re.fullmatch(r'window-[0-9a-f]{24}', window['id']):
            raise ValueError('invalid window identity')
        if window['kind'] not in ('native', 'mixed') or window['counts']['core_rows'] + window['caller_calls'] != window['cycles'] or sum(window['counts'][key] for key in ('keccak_calls', 'recovery_calls', 'sha_calls')) != window['caller_calls'] or (window['kind'] == 'mixed') != (window['caller_calls'] > 0):
            raise ValueError('invalid campaign retirement census')
        nodes[window['id']] = window
        uses[window['id']] = 0
    if cursor != plan['total_cycles']:
        raise ValueError('campaign omits execution')
    for fold in folds:
        body = {key: value for key, value in fold.items() if key != 'id'}
        if fold['id'] != 'fold-' + digest(canonical(body))[:24] or fold['id'] in nodes or len(fold['children']) != 2:
            raise ValueError('invalid fold identity')
        if any(child not in nodes for child in fold['children']):
            raise ValueError('unknown or cyclic fold child')
        left, right = (nodes[child] for child in fold['children'])
        if left['skip_cycles'] != fold['skip_cycles'] or left['skip_cycles'] + left['cycles'] != right['skip_cycles'] or left['cycles'] + right['cycles'] != fold['cycles']:
            raise ValueError('invalid fold coverage')
        for child in fold['children']:
            uses[child] += 1
        nodes[fold['id']] = fold
        uses[fold['id']] = 0
    root = nodes.get(plan['root_id'])
    if root is None or root['skip_cycles'] != 0 or root['cycles'] != plan['total_cycles'] or any(count != (0 if node == plan['root_id'] else 1) for node, count in uses.items()):
        raise ValueError('invalid campaign root or reused child')


def snapshot_identity(raw: bytes) -> str:
    if len(raw) < 148 or raw[:8] != b"B7WIN001":
        raise ValueError("invalid checkpoint transport")
    words, = struct.unpack_from("<Q", raw, 140)
    if words > 8_000_000 or len(raw) != 148 + words * 8:
        raise ValueError("invalid checkpoint size")
    scalars = struct.unpack_from("<33I", raw, 8)
    if scalars[1] != 0:
        raise ValueError("invalid x0 checkpoint")
    h = hashlib.sha256(b"stwo-v7-real-window-state-v1")
    for scalar in (*scalars, words):
        h.update(struct.pack("<Q", scalar))
    previous = -1
    for address, value in struct.iter_unpack("<II", memoryview(raw)[148:]):
        if address & 3 or address <= previous:
            raise ValueError("invalid checkpoint word ordering")
        previous = address
        h.update(struct.pack("<QQ", address, value))
    return h.hexdigest()


def publish_capsules(plan: dict, census: Path, destination: Path):
    """Validate one-pass checkpoint bytes and emit existing producer inputs."""
    validate_plan(plan)
    summary, records, _ = load_census(census)
    if any(summary[key] != plan[key] for key in ("elf_sha256", "input_sha256", "output_sha256")) or summary["expected_cycles"] != plan["total_cycles"]:
        raise ValueError("checkpoint execution differs from plan")
    snapshots = {}
    for line in (census / "checkpoints/snapshots.jsonl").read_text().splitlines():
        item = json.loads(line)
        cycle = item["completed_cycles"]
        if type(cycle) is not int or cycle in snapshots or item["file"] != f"state-{cycle}.b7win":
            raise ValueError("duplicate or unsafe checkpoint")
        path = census / "checkpoints" / item["file"]
        raw = path.read_bytes()
        if len(raw) != item["bytes"] or digest(raw) != item["transport_sha256"] or snapshot_identity(raw) != item["snapshot_id"]:
            raise ValueError("checkpoint authentication mismatch")
        snapshots[cycle] = item
    expected = {0, *(w["skip_cycles"] + w["cycles"] for w in plan["windows"])}
    if set(snapshots) != expected:
        raise ValueError("incomplete or extra checkpoint coverage")
    if destination.exists():
        raise ValueError("preserving existing campaign capsules")
    destination.mkdir(parents=True)
    for window in plan["windows"]:
        start, end = window["skip_cycles"], window["skip_cycles"] + window["cycles"]
        actual = [r for r in records if start < r["first_cycle"] <= end]
        if not actual or actual[0]["first_cycle"] != start + 1 or actual[-1]["first_cycle"] + actual[-1]["counts"]["cycles"] != end + 1:
            raise ValueError("one-pass census does not partition planned window")
        for key, count in window["counts"].items():
            if sum(row["counts"][key] for row in actual) != count:
                raise ValueError("one-pass caller/native inventory changed")
        path = destination / window["id"]
        path.mkdir()
        for name, cycle in (("incoming.b7win", start), ("outgoing.b7win", end)):
            source = (census / "checkpoints" / snapshots[cycle]["file"]).resolve()
            os.symlink(os.path.relpath(source, path.resolve()), path / name)
        capsule = dict(schema="stwo-b8-one-pass-captured-window-input-v1", proof_verified=False, elf_sha256=plan["elf_sha256"], input_sha256=plan["input_sha256"], incoming_sha256=snapshots[start]["snapshot_id"], outgoing_sha256=snapshots[end]["snapshot_id"], window=dict(skip_cycles=start, cycles=window["cycles"]), stats=dict(cycles=window["cycles"], **window["counts"]), initial=window["initial"], terminal=window["terminal"])
        (path / "capture.json").write_text(json.dumps(capsule, indent=2) + "\n")
    (destination / "plan.json").write_text(json.dumps(plan, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    plan_parser = sub.add_parser("plan")
    plan_parser.add_argument("--census", type=Path, required=True)
    plan_parser.add_argument("--output", type=Path, required=True)
    plan_parser.add_argument("--native-cycles", type=int, default=1 << 23)
    plan_parser.add_argument("--mixed-cycles", type=int, default=1 << 20)
    plan_parser.add_argument("--caller-calls", type=int, default=4096)
    publish = sub.add_parser("publish-capsules")
    publish.add_argument("--plan", type=Path, required=True)
    publish.add_argument("--census", type=Path, required=True)
    publish.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "plan":
        if args.output.exists():
            parser.error("output already exists")
        plan = make_plan(args.census, args.native_cycles, args.mixed_cycles, args.caller_calls)
        validate_plan(plan)
        args.output.mkdir(parents=True)
        (args.output / "plan.json").write_text(json.dumps(plan, indent=2) + "\n")
        (args.output / "checkpoint-plan.json").write_text(json.dumps(dict(boundaries=[0] + [w["skip_cycles"] + w["cycles"] for w in plan["windows"]]), indent=2) + "\n")
        print(json.dumps(dict(windows=len(plan["windows"]), folds=len(plan["folds"]), total_cycles=plan["total_cycles"], proof_verified=False)))
    else:
        publish_capsules(json.loads(args.plan.read_text()), args.census, args.output)


if __name__ == "__main__":
    main()
