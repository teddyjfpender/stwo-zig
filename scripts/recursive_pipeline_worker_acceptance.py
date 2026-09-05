#!/usr/bin/env python3
"""Cross-process acceptance harness for recursive-pipeline-worker-v1.

The worker executable is injected; this harness contains no AIR dispatch and
cannot fall back to the Python mock.  It is intentionally usable before every
real adapter exists by selecting a bounded `--through` node.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

from scripts import ethereum_block_proof_store as durable
from scripts import recursive_pipeline_campaign as campaign
from scripts import recursive_pipeline_cli as pipeline_cli
from scripts import recursive_pipeline_protocol as protocol
from scripts import recursive_pipeline_registry as registry_mod
from scripts import recursive_pipeline_runner as runner_mod
from scripts import recursive_pipeline_store as store_mod


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(prog="recursive-pipeline-worker-acceptance")
    value.add_argument("--workspace", type=Path, required=True)
    value.add_argument("--inventory", type=Path, required=True)
    value.add_argument("--execution-authorities", type=Path, required=True)
    value.add_argument("--worker", required=True)
    value.add_argument("--worker-arg", action="append", default=[])
    value.add_argument("--worker-cwd", type=Path, default=Path.cwd())
    value.add_argument("--run-id", default="worker-acceptance")
    value.add_argument("--through")
    value.add_argument("--cpu-tokens", type=int, default=1)
    value.add_argument("--rss-tokens", type=int, default=1)
    value.add_argument("--validator-version", type=int, default=1)
    return value


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    registry = registry_mod.StageRegistry()
    try:
        workspace = store_mod.Workspace(args.workspace)
        raw = durable.read_regular(
            args.inventory, "acceptance campaign inventory",
            maximum=durable.MAX_JSON_BYTES,
        )
        inventory = protocol.parse_canonical(
            raw, campaign.validate_inventory, "acceptance campaign inventory",
        )
        for index, ref in enumerate(campaign.referenced_blobs(inventory)):
            workspace.stat_blob(ref, f"acceptance campaign input {index}")
        manifest, authority = campaign.plan(inventory)
        workspace.publish_campaign_document(inventory)
        workspace.publish_campaign_document(authority)
        workspace.publish_manifest(manifest)
        authorities = pipeline_cli._read_execution_authorities(
            args.execution_authorities,
        )
        adapters = {node["adapter"] for node in manifest["nodes"]}
        protocol.require(len(adapters) == 1,
                         "acceptance campaign adapter set differs")
        adapter = registry_mod.ZigWorkerAdapter(
            [args.worker, *args.worker_arg], cwd=args.worker_cwd,
            validator_version=args.validator_version,
            object_root=workspace.sha_objects,
        )
        registry.register(next(iter(adapters)), adapter)
        runner = runner_mod.Runner(
            workspace, manifest, args.run_id, registry, authorities,
            cpu_tokens=args.cpu_tokens, rss_tokens=args.rss_tokens,
        )
        summary = runner.run(through=args.through)
        sys.stdout.buffer.write(protocol.canonical_bytes({
            "schema": "stwo.recursive-pipeline-worker-acceptance-result.v1",
            "campaign_authority_sha256": authority["content_sha256"],
            "manifest_sha256": manifest["content_sha256"],
            "run_id": args.run_id,
            "through": args.through,
            "committed": summary.committed,
            "executed": summary.executed,
            "cache_hits": summary.cache_hits,
            "goal_output": summary.goal_output,
        }))
        return 0
    except (OSError, protocol.PipelineError) as error:
        print(f"recursive-pipeline-worker-acceptance: {error}", file=sys.stderr)
        return 2
    finally:
        registry.close()


if __name__ == "__main__":
    raise SystemExit(main())
