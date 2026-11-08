"""Thin command-line orchestration for the BG-15 evidence protocol."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from .model import (
    DEFAULT_OUTPUT_ROOT,
    DEFAULT_PRODUCT_SCHEMA,
    DEFAULT_PROTOCOL,
    DEFAULT_WORKFLOW,
    ROOT,
    STATUS_PASS,
    ReceiptError,
)
from .producer import default_run_id, default_session_nonce, detected_role, produce
from .protocol import load_protocol
from .receipt import validate_host_receipt
from .codec import strict_json
from .verifier import verify


def _shared_paths(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--authority-root", type=Path, default=ROOT)
    parser.add_argument("--protocol", type=Path, default=DEFAULT_PROTOCOL)
    parser.add_argument("--product-schema", type=Path, default=DEFAULT_PRODUCT_SCHEMA)
    parser.add_argument("--workflow-definition", type=Path, default=DEFAULT_WORKFLOW)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    phases = parser.add_subparsers(dest="phase", required=True)

    producer = phases.add_parser("produce", help="produce one host-local receipt")
    _shared_paths(producer)
    producer.add_argument("--host-role", choices=("auto", "linux", "macos"), default="auto")
    producer.add_argument("--candidate", default=None)
    producer.add_argument("--run-id", default=None)
    producer.add_argument("--run-attempt", default=None)
    producer.add_argument("--session-nonce", default=None)
    producer.add_argument(
        "--attestation",
        choices=("local-unsigned", "github-actions-artifact"),
        default="local-unsigned",
    )
    producer.add_argument("--evidence-manifest", type=Path, default=None)
    producer.add_argument("--evidence-preimages", type=Path, default=None)
    producer.add_argument("--authority-commit", default=None)
    producer.add_argument("--authority-tree", default=None)
    producer.add_argument("--authority-plan-sha256", default=None)

    verifier = phases.add_parser("verify", help="run the trusted cross-host verifier")
    _shared_paths(verifier)
    verifier.add_argument("--linux-receipt", type=Path, required=True)
    verifier.add_argument("--macos-receipt", type=Path, required=True)
    verifier.add_argument("--candidate", required=True)
    verifier.add_argument("--session-nonce", default=None)
    verifier.add_argument("--linux-preimages", type=Path, required=True)
    verifier.add_argument("--macos-preimages", type=Path, required=True)

    inspect = phases.add_parser("inspect", help="validate one diagnostic host receipt")
    inspect.add_argument("--protocol", type=Path, default=DEFAULT_PROTOCOL)
    inspect.add_argument("--receipt", type=Path, required=True)
    return parser.parse_args(argv)


def _producer(args: argparse.Namespace) -> int:
    role = detected_role() if args.host_role == "auto" else args.host_role
    run_id = args.run_id or os.environ.get("GITHUB_RUN_ID") or default_run_id()
    run_attempt = args.run_attempt or os.environ.get("GITHUB_RUN_ATTEMPT") or "1"
    nonce = args.session_nonce or os.environ.get("STWO_ARCHITECTURE_SESSION_NONCE")
    if nonce is None:
        if args.attestation != "local-unsigned":
            raise ReceiptError("trusted production requires an issued session nonce")
        nonce = default_session_nonce()
    output, receipt, digest = produce(
        root=args.root.resolve(),
        authority_root=args.authority_root.resolve(),
        protocol_path=args.protocol,
        product_schema_path=args.product_schema,
        workflow_path=args.workflow_definition,
        evidence_path=args.evidence_manifest,
        output_root=args.output_root,
        role=role,
        candidate=args.candidate,
        run_id=run_id,
        run_attempt=run_attempt,
        session_nonce=nonce,
        attestation_mode=args.attestation,
        authority_commit=args.authority_commit,
        authority_tree=args.authority_tree,
        authority_plan_sha256=args.authority_plan_sha256,
        evidence_preimages_path=args.evidence_preimages,
    )
    print(
        f"architecture host receipt: {receipt['verdict']} "
        f"{receipt['host']['role']} {digest} {output}"
    )
    return 0 if receipt["verdict"] == STATUS_PASS else 1


def _verifier(args: argparse.Namespace) -> int:
    nonce = args.session_nonce or os.environ.get("STWO_ARCHITECTURE_SESSION_NONCE")
    if nonce is None:
        raise ReceiptError("aggregate verification requires the issued session nonce")
    output, receipt, digest = verify(
        root=args.root.resolve(),
        authority_root=args.authority_root.resolve(),
        protocol_path=args.protocol,
        product_schema_path=args.product_schema,
        workflow_path=args.workflow_definition,
        linux_receipt_path=args.linux_receipt,
        macos_receipt_path=args.macos_receipt,
        output_root=args.output_root,
        candidate=args.candidate,
        session_nonce=nonce,
        linux_preimages_path=args.linux_preimages,
        macos_preimages_path=args.macos_preimages,
    )
    print(f"architecture aggregate receipt: {receipt['verdict']} {digest} {output}")
    return 0 if receipt["verdict"] == STATUS_PASS else 1


def _inspect(args: argparse.Namespace) -> int:
    protocol, _ = load_protocol(args.protocol)
    receipt = strict_json(args.receipt, protocol["limits"]["max_json_bytes"])
    validate_host_receipt(receipt, protocol)
    print(
        f"architecture host receipt: structurally valid {receipt['verdict']} "
        f"{receipt['host']['role']}"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.phase == "produce":
            return _producer(args)
        if args.phase == "verify":
            return _verifier(args)
        return _inspect(args)
    except (OSError, ReceiptError) as error:
        print(f"architecture receipt: FAIL: {error}", file=sys.stderr)
        return 2
