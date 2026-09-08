#!/usr/bin/env python3
"""Summarize one ordinary-route composition timing log without double counting."""
import argparse
import json
from pathlib import Path
import re


def summarize(text):
    records = {}
    for kind, body in re.findall(r"metal composition (\w+): ([^\n]+)", text):
        records.setdefault(kind, []).append(dict(re.findall(r"(\w+)=(\S+)", body)))
    walls = records.get("wall", [])
    if len(walls) != 1 or walls[0].get("completed") != "true":
        raise ValueError("expected exactly one completed composition; retain failed/partial logs separately")
    wall = walls[0]
    total = int(wall["wall_ns"])
    if total <= 0:
        raise ValueError("nonpositive composition duration")
    phases = records.get("phase", [])
    names = [p["phase"] for p in phases]
    if not phases or len(names) != len(set(names)):
        raise ValueError("missing or duplicate phase accounting")
    durations = [int(p["wall_ns"]) for p in phases]
    if min(durations) < 0 or sum(durations) != total or int(wall["phase_sum_ns"]) != total:
        raise ValueError("phase sum does not equal composition wall time")
    cursor = 0
    for phase, duration in zip(phases, durations):
        if int(phase["start_ns"]) != cursor or int(phase["end_ns"]) != cursor + duration:
            raise ValueError("phase intervals overlap or leave a gap")
        cursor += duration
    hosts = records.get("host", [])
    indices = [h["component_index"] for h in hosts]
    if len(indices) != len(set(indices)):
        raise ValueError("duplicate host component")
    spans = []
    for host in hosts:
        start, end, duration = (int(host[k]) for k in ("start_ns", "end_ns", "wall_ns"))
        if not 0 <= start <= end <= total or end - start != duration or host.get("failed") != "false":
            raise ValueError("invalid or failed host span")
        spans.append((start, end))
    # The union measures time during which any host component was executing.
    # It overlaps caller phases and GPU work and must not be added to either.
    covered, right = 0, 0
    for start, end in sorted(spans):
        covered += max(0, end - max(start, right))
        right = max(right, end)
    return {
        "composition_seconds": total / 1e9,
        "scheduler": wall["scheduler"],
        "wall_accounting_exact": True,
        "phases": sorted([
            {"phase": p["phase"], "seconds": d / 1e9, "wall_share": d / total}
            for p, d in zip(phases, durations)
        ], key=lambda p: p["seconds"], reverse=True),
        "host_components": sorted(hosts, key=lambda h: int(h["wall_ns"]), reverse=True),
        "host_span_union_seconds": covered / 1e9,
        "host_spans_overlap_caller_phases": True,
        "process_resource_samples": records.get("resource", []),
        "gpu_device_ms": [{"kind": d["family"], "milliseconds": float(d["gpu_ms"])}
                          for d in records.get("device", [])],
        "note": "Device times and host spans overlap caller phases. Process memory samples are not per-component allocation ownership.",
    }


def self_test():
    text = """metal composition phase: phase=host_launch_or_inline start_ns=0 end_ns=60 wall_ns=60
metal composition phase: phase=cleanup start_ns=60 end_ns=100 wall_ns=40
metal composition host: component_index=0 start_ns=10 end_ns=50 wall_ns=40 failed=false
metal composition host: component_index=1 start_ns=30 end_ns=70 wall_ns=40 failed=false
metal composition wall: completed=true scheduler=pool wall_ns=100 phase_sum_ns=100
"""
    assert summarize(text)["host_span_union_seconds"] == 60 / 1e9
    for bad in [text.replace("phase_sum_ns=100", "phase_sum_ns=101"),
                text.replace("completed=true", "completed=false"),
                text.replace("start_ns=60", "start_ns=59"),
                text.replace("end_ns=70", "end_ns=101"), text + text]:
        try:
            summarize(bad)
        except ValueError:
            continue
        raise AssertionError("accepted incomplete or inconsistent timing")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path, nargs="?")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
    elif args.log:
        print(json.dumps(summarize(args.log.read_text()), indent=2))
    else:
        parser.error("provide a log or --self-test")
