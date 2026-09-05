#!/usr/bin/env python3
"""Test-only real-subprocess fixture for recursive-pipeline-worker-v1."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys
import tempfile

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts import recursive_pipeline_mock as mock
from scripts import recursive_pipeline_protocol as protocol
from scripts import recursive_pipeline_store as store_mod
from scripts import recursive_pipeline_worker_acceptance as acceptance
from scripts.tests.test_recursive_pipeline_campaign import fixture_inventory


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--worker", required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(
        prefix="stwo-recursive-worker-v1-",
        dir=os.environ.get("TMPDIR"),
    ) as raw:
        root = Path(raw)
        workspace_path = root / "workspace"
        workspace = store_mod.Workspace(workspace_path, create=True)
        inventory = fixture_inventory(workspace)
        inventory_path = root / "inventory.json"
        inventory_path.write_bytes(protocol.canonical_bytes(inventory))
        authorities = protocol.seal({
            "schema": "stwo.recursive-pipeline-execution-authority-set.v1",
            "authorities": mock.execution_authorities(),
        })
        authorities_path = root / "execution-authorities.json"
        authorities_path.write_bytes(protocol.canonical_bytes(authorities))
        command = [
            "--workspace", str(workspace_path),
            "--inventory", str(inventory_path),
            "--execution-authorities", str(authorities_path),
            "--worker", args.worker,
            "--worker-arg=--store-root",
            f"--worker-arg={workspace_path}",
            "--worker-arg=--adapter",
            "--worker-arg=mock",
            "--worker-cwd", str(REPO_ROOT),
            "--through", "leaf/000",
        ]
        if acceptance.main(command) != 0:
            emit_worker_diagnostics(workspace_path)
            return 1
        selected = workspace.read_run_ref("worker-acceptance", "leaf/000")
        manifest_ref = protocol.validate_blob_ref(
            selected["stage_manifest"], "Zig worker stage manifest",
        )
        protocol.require(
            manifest_ref["kind"] == 4 and manifest_ref["schema_version"] == 1,
            "Zig worker did not publish canonical StageManifestV1",
        )
        # A new worker process must cold-open CAS custody; no live lease crosses
        # this process boundary. The second run therefore exercises resume.
        if acceptance.main(command) != 0:
            emit_worker_diagnostics(workspace_path)
            return 1
    return 0


def emit_worker_diagnostics(workspace_path: Path) -> None:
    """Expose only the worker's bounded failure log before temp cleanup."""
    for path in sorted((workspace_path / "worker-logs").glob("*.stderr.log")):
        raw = path.read_bytes()
        if raw:
            sys.stderr.buffer.write(raw[-4096:])


if __name__ == "__main__":
    raise SystemExit(main())
