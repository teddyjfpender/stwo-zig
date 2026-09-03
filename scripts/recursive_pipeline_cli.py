#!/usr/bin/env python3
"""CLI for resumable recursive proof campaigns.

Production stages are opaque to this process: every semantic operation crosses
the versioned recursive-pipeline-worker-v1 protocol.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys
from typing import Any

from scripts import ethereum_block_proof_store as durable
from scripts import ethereum_block_proof_protocol as proof_protocol
from scripts import recursive_pipeline_mock as mock
from scripts import recursive_pipeline_campaign as campaign
from scripts import recursive_pipeline_protocol as protocol
from scripts import recursive_pipeline_registry as registry_mod
from scripts import recursive_pipeline_runner as runner_mod
from scripts import recursive_pipeline_store as store_mod
from scripts import recursive_pipeline_zig_stage101_frontier as zig_frontier


EXECUTION_AUTHORITY_SCHEMA = "stwo.recursive-pipeline-execution-authority-set.v1"


def _emit(value: Any) -> None:
    sys.stdout.buffer.write(protocol.canonical_bytes(value))


def _read_manifest(
    workspace: store_mod.Workspace, selector: str, *, publish: bool = True,
) -> dict[str, Any]:
    if protocol.SHA256.fullmatch(selector):
        return workspace.read_manifest(selector)
    path = Path(selector)
    raw = durable.read_regular(path, "pipeline manifest", maximum=durable.MAX_JSON_BYTES)
    manifest = protocol.parse_canonical(
        raw, protocol.validate_pipeline_manifest, "pipeline manifest",
    )
    if publish:
        workspace.publish_manifest(manifest)
    return manifest


def _read_campaign_inventory(
    workspace: store_mod.Workspace, selector: str, *, publish: bool,
) -> dict[str, Any]:
    if protocol.SHA256.fullmatch(selector):
        return workspace.read_campaign_document(
            selector, campaign.validate_inventory,
        )
    raw = durable.read_regular(
        Path(selector), "production campaign inventory",
        maximum=durable.MAX_JSON_BYTES,
    )
    inventory = protocol.parse_canonical(
        raw, campaign.validate_inventory, "production campaign inventory",
    )
    if publish:
        workspace.publish_campaign_document(inventory)
    return inventory


def _read_execution_authorities(path: Path) -> dict[str, str]:
    raw = durable.read_regular(path, "pipeline execution authorities",
                               maximum=durable.MAX_JSON_BYTES)
    envelope = protocol.parse_canonical(
        raw, lambda value: protocol.validate_seal(value, "execution authorities"),
        "execution authorities",
    )
    protocol.exact(envelope, {
        "schema", "authorities", "content_sha256",
    }, "execution authorities")
    protocol.require(envelope["schema"] == EXECUTION_AUTHORITY_SCHEMA,
                     "execution authority schema differs")
    authorities = protocol.exact(
        envelope["authorities"], protocol.EXECUTION_AUTHORITY_FIELDS,
        "execution authority fields",
    )
    for field in protocol.EXECUTION_AUTHORITY_FIELDS:
        protocol.nonzero_digest(authorities[field], f"execution authority {field}")
    return authorities


def _registry(
    args: argparse.Namespace, workspace: store_mod.Workspace,
    manifest: dict[str, Any],
) -> tuple[registry_mod.StageRegistry, dict[str, str]]:
    names = {node["adapter"] for node in manifest["nodes"]}
    if args.mock:
        protocol.require(manifest["test_only"],
                         "mock backend requires a test-only manifest")
        protocol.require(names == {mock.MOCK_ADAPTER},
                         "mock manifest adapter differs")
        authorities = mock.execution_authorities(
            resource_policy=args.mock_resource_policy,
        )
        registry = registry_mod.StageRegistry(allow_mock=True)
        registry.register(mock.MOCK_ADAPTER, registry_mod.MockStageAdapter(
            authorities, validator_version=args.validator_version,
        ))
        return registry, authorities
    protocol.require(not manifest["test_only"],
                     "test-only manifest requires explicit --mock")
    protocol.require(len(names) == 1 and args.worker is not None,
                     "production pipeline requires one generic Zig worker")
    protocol.require(args.execution_authorities is not None,
                     "production execution authorities are absent")
    authorities = _read_execution_authorities(args.execution_authorities)
    registry = registry_mod.StageRegistry()
    registry.register(next(iter(names)), registry_mod.ZigWorkerAdapter(
        [args.worker, *args.worker_arg], cwd=args.worker_cwd,
        validator_version=args.validator_version,
        object_root=workspace.sha_objects,
    ))
    return registry, authorities


def _promotions(values: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for value in values:
        node_id, separator, identity = value.partition("=")
        protocol.require(bool(separator) and node_id not in result,
                         "pipeline promotion syntax differs")
        protocol.digest(identity, "pipeline promotion candidate")
        result[node_id] = identity
    return result


def _summary(value: runner_mod.RunSummary) -> dict[str, Any]:
    return {
        "committed": value.committed,
        "cache_hits": value.cache_hits,
        "recovered": value.recovered,
        "executed": value.executed,
        "reprofiled": value.reprofiled,
        "max_live_leases": value.max_live_leases,
        "peak_cpu_tokens": value.peak_cpu_tokens,
        "peak_rss_tokens": value.peak_rss_tokens,
        "max_parallel_tasks": value.max_parallel_tasks,
        "goal_output": value.goal_output,
        "goal_cache_record_sha256": value.goal_cache_record_sha256,
    }


def command_plan(args: argparse.Namespace) -> None:
    workspace = store_mod.Workspace(args.workspace, create=True)
    mock_real_leaves = args.mock_real_leaves
    if mock_real_leaves is not None:
        manifest = mock.build_manifest(
            workspace,
            mutate_leaf=args.mutate_leaf,
            real_leaf_count=mock_real_leaves,
        )
        authority = None
    elif args.campaign_inventory is not None:
        protocol.require(args.mutate_leaf is None,
                         "campaign plan does not accept mock mutation")
        inventory = _read_campaign_inventory(
            workspace, args.campaign_inventory, publish=True,
        )
        manifest, authority = campaign.plan(inventory)
        workspace.publish_campaign_document(authority)
    else:
        protocol.require(args.manifest_file is not None,
                         "plan requires a manifest, campaign inventory, or mock")
        manifest = _read_manifest(workspace, str(args.manifest_file))
        authority = None
    path = workspace.publish_manifest(manifest)
    _emit({
        "manifest_sha256": manifest["content_sha256"],
        "manifest_path": str(path),
        "node_count": len(manifest["nodes"]),
        "goal": manifest["goal"],
        "test_only": manifest["test_only"],
        "campaign_authority_sha256": (
            authority["content_sha256"] if authority is not None else None
        ),
    })


def command_import(args: argparse.Namespace) -> None:
    workspace = store_mod.Workspace(args.workspace, create=True)
    inventory = _read_campaign_inventory(
        workspace, str(args.inventory), publish=False,
    )
    references = campaign.referenced_blobs(inventory)
    shape = campaign.derive_shape(len(inventory["real_leaves"]))
    for index, ref in enumerate(references):
        workspace.stat_blob(ref, f"campaign input object {index}")
    path = workspace.publish_campaign_document(inventory)
    _emit({
        "inventory_sha256": inventory["content_sha256"],
        "inventory_path": str(path),
        "real_leaf_count": shape.real_leaf_count,
        "empty_leaf_count": shape.empty_leaf_count,
        "fold_count": shape.fold_count,
        "referenced_blob_count": len(references),
    })


def command_stage101_frontier(args: argparse.Namespace) -> None:
    description = zig_frontier.run_cold_describe(
        args.cold_describe_worker,
        args.campaign_import_receipt,
        args.artifact_store_root,
        timeout_seconds=args.timeout_seconds,
    )
    _emit(zig_frontier.controller_view(description))


def command_run(args: argparse.Namespace, *, resume: bool) -> None:
    workspace = store_mod.Workspace(args.workspace)
    manifest = _read_manifest(workspace, args.manifest, publish=not resume)
    if resume:
        durable.require_directory(workspace.runs / args.run_id,
                                  "pipeline run to resume")
    registry, authorities = _registry(args, workspace, manifest)
    try:
        runner = runner_mod.Runner(
            workspace, manifest, args.run_id, registry, authorities,
            cpu_tokens=args.cpu_tokens, rss_tokens=args.rss_tokens,
            lease_frontier_limit=args.lease_frontier_limit,
            prepare_run=not resume,
        )
        result = runner.run(
            through=args.through, reprofile=args.reprofile,
            promote=_promotions(args.promote),
        )
        _emit(_summary(result))
    finally:
        registry.close()


def command_verify(args: argparse.Namespace) -> None:
    workspace = store_mod.Workspace(args.workspace)
    manifest = _read_manifest(workspace, args.manifest, publish=False)
    registry, authorities = _registry(args, workspace, manifest)
    try:
        runner = runner_mod.Runner(
            workspace, manifest, args.run_id, registry, authorities,
            cpu_tokens=args.cpu_tokens, rss_tokens=args.rss_tokens,
            lease_frontier_limit=args.lease_frontier_limit,
            prepare_run=False,
        )
        _emit(_summary(runner.verify(mode=args.mode)))
    finally:
        registry.close()


def command_status(args: argparse.Namespace) -> None:
    workspace = store_mod.Workspace(args.workspace, read_only=True)
    manifest = _read_manifest(workspace, args.manifest, publish=False)
    runner = runner_mod.Runner(
        workspace, manifest, args.run_id, registry_mod.StageRegistry(),
        mock.execution_authorities(), cpu_tokens=1, rss_tokens=1,
        prepare_run=False,
    )
    _emit(runner.status())


def command_publish_root(args: argparse.Namespace) -> None:
    protocol.require(not os.path.lexists(args.result),
                     "root publication result already exists")
    workspace = store_mod.Workspace(args.workspace)
    manifest = _read_manifest(workspace, args.manifest, publish=False)
    registry, authorities = _registry(args, workspace, manifest)
    try:
        runner = runner_mod.Runner(
            workspace, manifest, args.run_id, registry, authorities,
            cpu_tokens=args.cpu_tokens, rss_tokens=args.rss_tokens,
            lease_frontier_limit=args.lease_frontier_limit,
            prepare_run=False,
        )
        summary = runner.verify(mode="root")
        result = protocol.seal({
            "schema": "stwo.recursive-pipeline-root-publication.v1",
            "status": "cold_verified",
            "manifest_sha256": manifest["content_sha256"],
            "run_id": args.run_id,
            "goal_node_id": manifest["goal"],
            "goal_output": summary.goal_output,
            "validation_cache_record_sha256": summary.goal_cache_record_sha256,
        })
        durable.require_directory(args.result.parent,
                                  "root publication parent")
        durable.publish_new_or_identical(
            args.result, protocol.canonical_bytes(result),
            staging_directory=workspace.staging,
        )
        _emit(result)
    finally:
        registry.close()


def command_explain(args: argparse.Namespace) -> None:
    workspace = store_mod.Workspace(args.workspace, read_only=True)
    manifest = _read_manifest(workspace, args.manifest, publish=False)
    _emit(runner_mod.explain_run_difference(
        workspace, args.left_run, args.right_run, manifest,
    ))


def _backend_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--mock", action="store_true")
    parser.add_argument("--mock-resource-policy", default="mock-resource-v1")
    parser.add_argument("--worker")
    parser.add_argument("--worker-arg", action="append", default=[])
    parser.add_argument("--worker-cwd", type=Path, default=Path.cwd())
    parser.add_argument("--execution-authorities", type=Path)
    parser.add_argument("--validator-version", type=int, default=1)
    parser.add_argument("--cpu-tokens", type=int, default=os.cpu_count() or 1)
    parser.add_argument("--rss-tokens", type=int, default=1)
    parser.add_argument("--lease-frontier-limit", type=int, default=64)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="recursive-pipeline")
    sub = result.add_subparsers(dest="command", required=True)

    plan = sub.add_parser("plan")
    plan.add_argument("--workspace", type=Path, required=True)
    source = plan.add_mutually_exclusive_group(required=True)
    source.add_argument(
        "--mock-real-leaves", type=int, metavar="COUNT",
        help="build an inventory-shaped mock campaign for COUNT real leaves",
    )
    source.add_argument(
        "--mock-210", action="store_const", const=mock.REAL_LEAF_COUNT,
        dest="mock_real_leaves", help=argparse.SUPPRESS,
    )
    source.add_argument("--manifest-file", type=Path)
    source.add_argument("--campaign-inventory")
    plan.add_argument("--mutate-leaf", type=int)

    import_command = sub.add_parser("import")
    import_command.add_argument("--workspace", type=Path, required=True)
    import_command.add_argument("--inventory", type=Path, required=True)

    stage101_frontier = sub.add_parser("stage101-frontier")
    stage101_frontier.add_argument(
        "--cold-describe-worker", type=Path, required=True,
    )
    stage101_frontier.add_argument(
        "--campaign-import-receipt", type=Path, required=True,
    )
    stage101_frontier.add_argument(
        "--artifact-store-root", type=Path, required=True,
    )
    stage101_frontier.add_argument(
        "--timeout-seconds", type=float, default=3600.0,
    )

    for name in ("run", "resume"):
        command = sub.add_parser(name)
        command.add_argument("--workspace", type=Path, required=True)
        command.add_argument("--manifest", required=True)
        command.add_argument("--run-id", required=True)
        command.add_argument("--through")
        command.add_argument("--reprofile", action="append", default=[])
        command.add_argument("--promote", action="append", default=[])
        _backend_options(command)

    verify = sub.add_parser("verify")
    verify.add_argument("--workspace", type=Path, required=True)
    verify.add_argument("--manifest", required=True)
    verify.add_argument("--run-id", required=True)
    verify.add_argument("--mode", choices=("root", "deep"), default="deep")
    _backend_options(verify)

    status = sub.add_parser("status")
    status.add_argument("--workspace", type=Path, required=True)
    status.add_argument("--manifest", required=True)
    status.add_argument("--run-id", required=True)

    publish = sub.add_parser("publish-root")
    publish.add_argument("--workspace", type=Path, required=True)
    publish.add_argument("--manifest", required=True)
    publish.add_argument("--run-id", required=True)
    publish.add_argument("--result", type=Path, required=True)
    _backend_options(publish)

    explain = sub.add_parser("explain-cache")
    explain.add_argument("--workspace", type=Path, required=True)
    explain.add_argument("--manifest", required=True)
    explain.add_argument("--left-run", required=True)
    explain.add_argument("--right-run", required=True)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "plan":
            command_plan(args)
        elif args.command == "import":
            command_import(args)
        elif args.command == "stage101-frontier":
            command_stage101_frontier(args)
        elif args.command == "run":
            command_run(args, resume=False)
        elif args.command == "resume":
            command_run(args, resume=True)
        elif args.command == "verify":
            command_verify(args)
        elif args.command == "status":
            command_status(args)
        elif args.command == "publish-root":
            command_publish_root(args)
        elif args.command == "explain-cache":
            command_explain(args)
        else:
            raise AssertionError(args.command)
        return 0
    except (OSError, protocol.PipelineError,
            proof_protocol.ProofProtocolError) as error:
        print(f"recursive-pipeline: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
