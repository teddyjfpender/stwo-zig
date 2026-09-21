"""Persistent per-run evidence and full-proof negative-fixture validation."""
from __future__ import annotations

import json
import tempfile
from dataclasses import replace
from pathlib import Path

from .contract import BenchmarkError, Case, NegativeCase


class EvidenceRun:
    """Keep completed rows and raw artifacts even if a later case fails."""

    def __init__(self, report: Path):
        report.parent.mkdir(parents=True, exist_ok=True)
        self.directory = Path(tempfile.mkdtemp(prefix=f"{report.stem}.evidence-", dir=report.parent))
        self.rows: list[dict] = []
        self._write("running")

    def _write(self, status: str, **details) -> None:
        path = self.directory / "progress.json"
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps({"status": status, "results": self.rows, **details}, indent=2) + "\n")
        temporary.replace(path)

    def __enter__(self):
        return self

    def __exit__(self, kind, error, traceback):
        if error is not None:
            self._write("failed", error=str(error))
        else:
            self._write("proofs_verified_report_pending")
        return False

    def record(self, kind: str, row: dict) -> None:
        self.rows.append({"kind": kind, "result": row})
        self._write("running")

    def finish(self, report: Path) -> None:
        self._write("complete", report=str(report))


def prove_negative_case(case: NegativeCase, cases: list[Case], cli: Path, trace_cli: Path,
                        *, benchmark, work_dir: Path, **options) -> tuple[dict, str]:
    matches = [positive for positive in cases
               if positive.target == case.target and positive.guest_path == case.guest_path]
    if len(matches) != 1:
        raise BenchmarkError(f"negative fixture {case.name}: ambiguous guest workload")
    workload = replace(matches[0], input_path=case.input_path, input_sha256=case.input_sha256,
                       expected_digest=case.expected_digest, expected_cycles=case.expected_cycles)
    directory = work_dir / case.name
    directory.mkdir()
    row, commit = benchmark(workload, cli, trace_cli, warmups=0, samples=1,
                            work_dir=directory, **options)
    return {
        "name": case.name, "target": case.target, "status": "rejected_as_expected",
        "execution_mode": row.get("execution_mode", "software"),
        "proof_status": row["evidence"]["status"], "input_sha256": case.input_sha256,
        "output_digest": row["evidence"]["output_digest"], "cycles": row["cycles"],
        "public_values_sha256": row["evidence"]["public_values_sha256"],
        "evidence": row["evidence"],
        "timing_scope": "validation only; excluded from performance measurements",
    }, commit
