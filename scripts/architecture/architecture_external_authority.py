#!/usr/bin/env python3
"""Execute and aggregate architecture gates from an authenticated authority checkout."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Mapping


AUTHORITY_ROOT = Path(__file__).resolve().parents[1]
if str(AUTHORITY_ROOT) not in sys.path:
    sys.path.insert(0, str(AUTHORITY_ROOT))

from scripts.architecture_host_gate_lib import controller as host_controller  # noqa: E402
from scripts.architecture_host_gate_lib import plan as host_plan  # noqa: E402
from scripts.architecture_host_gate_lib import preimages  # noqa: E402
from scripts import architecture_native_oracle  # noqa: E402
from scripts.build_architecture_receipt_lib.codec import sha256_file, strict_json  # noqa: E402
from scripts.build_architecture_receipt_lib.model import ReceiptError, require_hex40  # noqa: E402
from scripts.build_architecture_receipt_lib.producer import produce  # noqa: E402
from scripts.build_architecture_receipt_lib.protocol import load_protocol  # noqa: E402
from scripts.build_architecture_receipt_lib.verifier import verify as verify_receipts  # noqa: E402


CONTRACT = AUTHORITY_ROOT / "conformance/build-architecture-external-verifier-v1.json"
PROTOCOL = AUTHORITY_ROOT / "conformance/build-architecture-receipt-protocol-v1.json"
PLAN = AUTHORITY_ROOT / "conformance/build-architecture-ci-plan-v1.json"
AUTHORITY_STATE = AUTHORITY_ROOT / "conformance/build-architecture-authority-state-v1.json"
AUTHORITY_WORKFLOW = AUTHORITY_ROOT / ".github/workflows/architecture-authority.yml"
PRODUCT_SCHEMA = Path("build_support/graph/product.zig")


def _git(root: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ("git", *arguments), cwd=root, check=False, capture_output=True, text=True,
    )
    if completed.returncode != 0:
        raise ReceiptError(f"git {' '.join(arguments)} failed: {completed.stderr.strip()}")
    return completed.stdout.strip()


def _git_bytes(root: Path, *arguments: str) -> bytes:
    completed = subprocess.run(
        ("git", *arguments), cwd=root, check=False, capture_output=True,
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise ReceiptError(f"git {' '.join(arguments)} failed: {detail}")
    return completed.stdout


def _required(environment: Mapping[str, str], name: str) -> str:
    value = environment.get(name, "")
    if not value:
        raise ReceiptError(f"architecture authority environment is missing {name}")
    return value


def _require_authority_modules() -> None:
    for name, module in sys.modules.items():
        origin_raw = getattr(module, "__file__", None)
        if not name.startswith("scripts.") or origin_raw is None:
            continue
        origin = Path(origin_raw).resolve()
        if not origin.is_relative_to(AUTHORITY_ROOT):
            raise ReceiptError(f"authority module was shadowed outside checkout: {origin}")


def load_contract() -> dict[str, Any]:
    protocol, _ = load_protocol(PROTOCOL)
    contract = strict_json(CONTRACT, 1024 * 1024)
    if contract.get("schema") != "build-architecture-external-verifier-v1":
        raise ReceiptError("external architecture verifier contract schema drifted")
    if sha256_file(CONTRACT) != protocol["trust"]["external_verifier_contract_sha256"]:
        raise ReceiptError("external architecture verifier contract digest drifted")
    expected = {
        "path": protocol["trust"]["workflow_path"],
        "ref": protocol["trust"]["workflow_ref"],
        "aggregate_job": protocol["aggregate_job"],
        "host_jobs": {
            role: policy["producer_job"]
            for role, policy in protocol["host_roles"].items()
        },
    }
    if contract.get("authority_workflow") != expected:
        raise ReceiptError("external verifier workflow identity differs from receipt protocol")
    if contract.get("candidate_workflow") != {
        "path": ".github/workflows/ci.yml", "role": "diagnostic-only",
    }:
        raise ReceiptError("candidate workflow is not explicitly diagnostic-only")
    return contract


def authenticate(
    *, candidate_root: Path, candidate: str, expected_job: str,
    environment: Mapping[str, str] | None = None,
) -> dict[str, str]:
    _require_authority_modules()
    contract = load_contract()
    protocol, _ = load_protocol(PROTOCOL)
    env = os.environ if environment is None else environment
    require_hex40(candidate, "candidate")
    authority = require_hex40(
        _required(env, "ARCHITECTURE_AUTHORITY_SHA"), "ARCHITECTURE_AUTHORITY_SHA",
    )
    if authority == candidate:
        raise ReceiptError("protected architecture authority equals candidate")
    expected = {
        "GITHUB_ACTIONS": "true",
        "GITHUB_REPOSITORY": protocol["trust"]["repository"],
        "GITHUB_REPOSITORY_ID": str(protocol["trust"]["repository_id"]),
        "GITHUB_REPOSITORY_OWNER_ID": str(protocol["trust"]["repository_owner_id"]),
        "GITHUB_WORKFLOW_REF": protocol["trust"]["workflow_ref"],
        "GITHUB_WORKFLOW_SHA": authority,
        "GITHUB_JOB": expected_job,
        "STWO_ARCHITECTURE_DISPATCH_ACTOR_ID": str(
            protocol["trust"]["repository_owner_id"]
        ),
    }
    for name, value in expected.items():
        if _required(env, name) != value:
            raise ReceiptError(f"architecture authority environment mismatch: {name}")
    if _git(AUTHORITY_ROOT, "rev-parse", "HEAD") != authority:
        raise ReceiptError("authority checkout HEAD differs from protected authority SHA")
    if _git(AUTHORITY_ROOT, "status", "--porcelain=v1", "--untracked-files=all"):
        raise ReceiptError("authority checkout is dirty")
    committed_workflow = _git_bytes(
        AUTHORITY_ROOT, "show", f"{authority}:.github/workflows/architecture-authority.yml",
    )
    if committed_workflow != AUTHORITY_WORKFLOW.read_bytes():
        raise ReceiptError("authority workflow bytes differ from authenticated commit")
    candidate_root = candidate_root.resolve()
    if _git(candidate_root, "rev-parse", "HEAD") != candidate:
        raise ReceiptError("candidate checkout HEAD differs from requested candidate")
    if _git(candidate_root, "status", "--porcelain=v1", "--untracked-files=all"):
        raise ReceiptError("candidate checkout is dirty before authority execution")
    candidate_tree = _git(candidate_root, "rev-parse", "HEAD^{tree}")
    return {
        "candidate": candidate,
        "candidate_tree": candidate_tree,
        "authority_commit": authority,
        "authority_tree": _git(AUTHORITY_ROOT, "rev-parse", "HEAD^{tree}"),
        "authority_plan_sha256": sha256_file(PLAN),
        "workflow_path": contract["authority_workflow"]["path"],
    }


def run_host(
    *, role: str, candidate_root: Path, candidate: str, output_dir: Path,
    receipt_root: Path, session_nonce: str, native_oracle_bundle: Path,
    native_oracle_trust: Path,
    environment: Mapping[str, str] | None = None,
) -> tuple[Path, dict[str, Any]]:
    env = os.environ if environment is None else environment
    protocol, _ = load_protocol(PROTOCOL)
    job = protocol["host_roles"][role]["producer_job"]
    identity = authenticate(
        candidate_root=candidate_root, candidate=candidate,
        expected_job=job, environment=env,
    )
    actual_role = "macos" if sys.platform == "darwin" else "linux"
    if role != actual_role:
        raise ReceiptError("authority host execution is not on its allocated operating system")
    evidence_path, manifest = host_controller.execute(
        root=candidate_root, authority_root=AUTHORITY_ROOT,
        role=role, plan_path=PLAN, protocol_path=PROTOCOL,
        output_dir=output_dir, candidate=candidate, timeout=3600.0,
        run_id=_required(env, "GITHUB_RUN_ID"),
        run_attempt=_required(env, "GITHUB_RUN_ATTEMPT"),
        repository=_required(env, "GITHUB_REPOSITORY"),
        repository_id=_required(env, "GITHUB_REPOSITORY_ID"),
        workflow_sha=identity["authority_commit"],
        native_oracle_bundle=native_oracle_bundle,
        native_oracle_trust=native_oracle_trust,
    )
    post_identity = authenticate(
        candidate_root=candidate_root, candidate=candidate,
        expected_job=job, environment=env,
    )
    if post_identity != identity:
        raise ReceiptError("architecture identity changed during candidate execution")
    native_producer = strict_json(native_oracle_trust, 1024 * 1024)
    architecture_native_oracle.verify(
        native_oracle_bundle,
        candidate_root,
        role,
        expected_producer=native_producer,
        authority_root=AUTHORITY_ROOT,
        protected=True,
    )
    preimages_path = output_dir / f"{role}-{_required(env, 'GITHUB_RUN_ID')}-preimages.zip"
    preimages.verify(
        preimages_path,
        plan_value=host_plan.load(PLAN, protocol),
        protocol=protocol,
        role=role,
        candidate=candidate,
        tree=identity["candidate_tree"],
        plan_sha256=identity["authority_plan_sha256"],
        reinspect_link_binaries=True,
    )
    receipt_path, receipt, _ = produce(
        root=candidate_root.resolve(), authority_root=AUTHORITY_ROOT,
        protocol_path=PROTOCOL,
        product_schema_path=candidate_root.resolve() / PRODUCT_SCHEMA,
        workflow_path=AUTHORITY_WORKFLOW, evidence_path=evidence_path,
        output_root=receipt_root, role=role, candidate=candidate,
        run_id=_required(env, "GITHUB_RUN_ID"),
        run_attempt=_required(env, "GITHUB_RUN_ATTEMPT"),
        session_nonce=session_nonce, attestation_mode="github-actions-artifact",
        authority_commit=identity["authority_commit"],
        authority_tree=identity["authority_tree"],
        authority_plan_sha256=identity["authority_plan_sha256"],
        evidence_preimages_path=preimages_path,
    )
    if receipt["verdict"] != "PASS" or any(
        item["status"] != "PASS" for item in manifest["checkpoints"].values()
    ):
        raise ReceiptError(f"{role} authority execution did not pass every checkpoint")
    return receipt_path, receipt


def _authority_enabled() -> None:
    state = strict_json(AUTHORITY_STATE, 64 * 1024)
    if set(state) != {
        "schema", "bg15_release_authority_enabled", "reason", "required_controls",
    } or state.get("schema") != "build-architecture-authority-state-v1":
        raise ReceiptError("architecture authority activation state schema drifted")
    if state.get("bg15_release_authority_enabled") is not True:
        raise ReceiptError(
            "BG-15 release authority is unavailable until protected external controls are installed"
        )


def aggregate(
    *, candidate_root: Path, candidate: str, session_nonce: str,
    linux_receipt: Path, macos_receipt: Path,
    linux_preimages: Path, macos_preimages: Path, output_root: Path,
    environment: Mapping[str, str] | None = None,
) -> tuple[Path, dict[str, Any], str]:
    env = os.environ if environment is None else environment
    protocol, _ = load_protocol(PROTOCOL)
    identity = authenticate(
        candidate_root=candidate_root, candidate=candidate,
        expected_job=protocol["aggregate_job"], environment=env,
    )
    _authority_enabled()
    trusted_environment = dict(env)
    trusted_environment.update({
        "STWO_ARCHITECTURE_AUTHORITY_COMMIT": identity["authority_commit"],
        "STWO_ARCHITECTURE_AUTHORITY_TREE": identity["authority_tree"],
        "STWO_ARCHITECTURE_AUTHORITY_PLAN_SHA256": identity["authority_plan_sha256"],
    })
    plan_value = host_plan.load(PLAN, protocol)
    for role, bundle in (
        ("linux", linux_preimages),
        ("macos", macos_preimages),
    ):
        preimages.verify(
            bundle,
            plan_value=plan_value,
            protocol=protocol,
            role=role,
            candidate=candidate,
            tree=identity["candidate_tree"],
            plan_sha256=identity["authority_plan_sha256"],
            # The Linux verifier cannot execute platform-specific binary
            # inspection for the macOS receipt. Each host already performs
            # that inspection before publishing its authenticated receipt.
            reinspect_link_binaries=False,
        )
    return verify_receipts(
        root=candidate_root.resolve(), authority_root=AUTHORITY_ROOT,
        protocol_path=PROTOCOL,
        product_schema_path=candidate_root.resolve() / PRODUCT_SCHEMA,
        workflow_path=AUTHORITY_WORKFLOW,
        linux_receipt_path=linux_receipt, macos_receipt_path=macos_receipt,
        linux_preimages_path=linux_preimages, macos_preimages_path=macos_preimages,
        output_root=output_root, candidate=candidate, session_nonce=session_nonce,
        environment=trusted_environment,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    phases = parser.add_subparsers(dest="phase", required=True)
    check = phases.add_parser("validate-contract")
    check.add_argument("--candidate-root", type=Path, required=True)
    check.add_argument("--candidate", required=True)
    check.add_argument("--expected-job", required=True)
    host = phases.add_parser("run-host")
    host.add_argument("--role", choices=("linux", "macos"), required=True)
    host.add_argument("--candidate-root", type=Path, required=True)
    host.add_argument("--candidate", required=True)
    host.add_argument("--output-dir", type=Path, required=True)
    host.add_argument("--receipt-root", type=Path, required=True)
    host.add_argument("--session-nonce", required=True)
    host.add_argument("--native-oracle-bundle", type=Path, required=True)
    host.add_argument("--native-oracle-trust", type=Path, required=True)
    verify = phases.add_parser("verify")
    verify.add_argument("--candidate-root", type=Path, required=True)
    verify.add_argument("--candidate", required=True)
    verify.add_argument("--session-nonce", required=True)
    verify.add_argument("--linux-receipt", type=Path, required=True)
    verify.add_argument("--macos-receipt", type=Path, required=True)
    verify.add_argument("--linux-preimages", type=Path, required=True)
    verify.add_argument("--macos-preimages", type=Path, required=True)
    verify.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.phase == "validate-contract":
            authenticate(
                candidate_root=args.candidate_root, candidate=args.candidate,
                expected_job=args.expected_job,
            )
            print("architecture authority contract: authenticated")
            return 0
        if args.phase == "run-host":
            receipt_path, _ = run_host(
                role=args.role, candidate_root=args.candidate_root,
                candidate=args.candidate, output_dir=args.output_dir,
                receipt_root=args.receipt_root, session_nonce=args.session_nonce,
                native_oracle_bundle=args.native_oracle_bundle,
                native_oracle_trust=args.native_oracle_trust,
            )
            print(f"architecture authority host: PASS {receipt_path}")
            return 0
        output, receipt, digest = aggregate(
            candidate_root=args.candidate_root, candidate=args.candidate,
            session_nonce=args.session_nonce, linux_receipt=args.linux_receipt,
            macos_receipt=args.macos_receipt,
            linux_preimages=args.linux_preimages,
            macos_preimages=args.macos_preimages, output_root=args.output_root,
        )
    except (OSError, ValueError, ReceiptError) as error:
        print(f"architecture authority: NO-GO: {error}", file=sys.stderr)
        return 2
    print(f"architecture authority: {receipt['verdict']} {digest} {output}")
    return 0 if receipt["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
