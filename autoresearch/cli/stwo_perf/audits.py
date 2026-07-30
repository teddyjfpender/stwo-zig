"""Deterministic Metrics-v2 audit planning, execution, and ledger ingestion.

Planning is pure over the manifest, current epoch, ledger, and candidate HEAD.
Execution is deliberately narrower than the public benchmark command: it can
only run a judged, full-guard, oracle-backed, audit-power paired comparison.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Callable

from . import ledger, metrics, promotion, runner, signing
from .manifest import Manifest, load as load_manifest

PLAN_SCHEMA = "metrics-v2-audit-plan-v1"
UNSIGNED_SCHEMA = "metrics-v2-audit-unsigned-v1"
SIGNED_SCHEMA = "metrics-v2-audit-evidence-v1"
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")


class AuditError(RuntimeError):
    pass


def _canonical_digest(value: object) -> str:
    payload = json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("ascii")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _file_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _git(repo: Path, *args: str) -> str:
    process = subprocess.run(
        ["git", *args], cwd=repo, capture_output=True, text=True,
    )
    if process.returncode:
        raise AuditError(f"git {' '.join(args)} failed: {process.stderr.strip()}")
    return process.stdout.strip()


def source_binding(repo: Path) -> dict:
    paths = {
        "manifest": repo / "autoresearch" / "MANIFEST.json",
        "ledger": ledger.ledger_path(repo),
        "epochs": ledger.epochs_path(repo),
    }
    return {
        "candidate_commit": _git(repo, "rev-parse", "HEAD"),
        **{f"{name}_sha256": _file_digest(path) for name, path in paths.items()},
    }


def _class_rows(
    rows: list[ledger.Row], epoch: int, board: str, workload_class: str,
) -> list[ledger.Row]:
    return [
        row for row in ledger.resolve_corrections(rows)
        if row.epoch == epoch
        and row.board == board
        and row.workload_class == workload_class
    ]


def _item(
    manifest: Manifest,
    rows: list[ledger.Row],
    epoch: int,
    board: str,
    workload_class: str,
    candidate_commit: str,
    ledger_sha256: str,
    commit_resolver: Callable[[str], str],
) -> dict | None:
    # TRACKS §7: the board's era, when it declares one, owns its audit anchor;
    # the global epoch's anchor stays the fallback.
    epoch_spec = ledger.epoch_for_board(manifest.root, epoch, board)
    policy = metrics.policy_from_epoch(epoch_spec)
    due = metrics.due_state(
        rows, epoch, board, workload_class, policy=policy,
    )
    if not due.direct_audit_due and not due.span_due:
        return None
    class_rows = _class_rows(rows, epoch, board, workload_class)
    group = manifest.group_for_board(board)
    gate_policy = manifest.gates_for_workload(group.group_id, workload_class)
    blocked = None
    retirement = group.retirement or None
    if retirement is not None and group.enabled:
        # TRACKS §6 retire-and-complete: a retired board refuses new promotions
        # but still owes the closing audit that stamps its last audited score.
        # Auditing is not promoting, so promotion ineligibility cannot block it
        # — once the closing audit is recorded, nothing further is due.
        if retirement.get("closing_audit") is not None:
            blocked = "retired board has already recorded its closing audit"
    elif not group.enabled or not group.promotion_eligible:
        blocked = "workload group is not enabled and promotion eligible"
    if blocked is None and gate_policy.get("require_rust_oracle") is not True:
        blocked = "workload gate policy does not require the pinned oracle"

    if due.direct_audit_due:
        kind = "direct_audit"
        predecessor = due.audited_through or policy.audit_anchor_commit
        covers: tuple[str, ...] = ()
        replaces = due.direct_audit_replaces
    else:
        kind = "span_audit"
        pending = {
            row.observation_id: row
            for row in class_rows
            if row.evidence_kind == "promotion"
            and row.observation_id in set(due.span_covers)
        }
        ordered = [pending[observation] for observation in due.span_covers]
        first_index = class_rows.index(ordered[0])
        tail_promotions = [
            row for row in class_rows[first_index:]
            if row.evidence_kind == "promotion"
        ]
        if tuple(row.observation_id for row in tail_promotions) != due.span_covers:
            blocked = "span constituents are not the contiguous promotion tail"
        first_commit = commit_resolver(ordered[0].commit)
        predecessor = commit_resolver(f"{first_commit}^1")
        covers = due.span_covers
        replaces = ()
    predecessor = commit_resolver(predecessor)
    if not _COMMIT_RE.fullmatch(predecessor):
        blocked = "audit predecessor is not a canonical 40-hex commit"
    if not _COMMIT_RE.fullmatch(candidate_commit):
        raise AuditError("candidate HEAD is not a canonical 40-hex commit")
    payload = {
        "epoch": epoch,
        "board": board,
        "workload_class": workload_class,
        "evidence_kind": kind,
        "predecessor_commit": predecessor,
        "candidate_commit": candidate_commit,
        "authority_ledger_sha256": ledger_sha256,
        "covers": list(covers),
        "credit_replaces": list(replaces),
        "span_reasons": list(due.span_reasons) if kind == "span_audit" else [],
        "runnable": blocked is None,
        "blocked_reason": blocked,
        "execution_contract": {
            "judged": True,
            "guards_mode": "all",
            "oracle_required": True,
            "audit_power": "required_bounded_boost",
            "scope": "s5",
            "dimension": "time",
        },
    }
    return {"item_id": _canonical_digest(payload), **payload}


def build_plan(
    manifest: Manifest,
    rows: list[ledger.Row],
    *,
    epoch: int,
    candidate_commit: str,
    source: dict,
    board: str | None = None,
    workload_class: str | None = None,
    commit_resolver: Callable[[str], str] | None = None,
) -> dict:
    """Enumerate all due cells in stable manifest board/class order."""
    items = []
    resolver = commit_resolver or (lambda value: value)
    for group in manifest.groups():
        if board is not None and group.board != board:
            continue
        for name in manifest.class_names(
            board=group.board, scored_only=True, include_disabled=True,
        ):
            if workload_class is not None and name != workload_class:
                continue
            item = _item(
                manifest,
                rows,
                epoch,
                group.board,
                name,
                candidate_commit,
                str(source["ledger_sha256"]),
                resolver,
            )
            if item is not None:
                items.append(item)
    body = {
        "schema": PLAN_SCHEMA,
        "source": source,
        "epoch": epoch,
        "items": items,
    }
    return {**body, "plan_sha256": _canonical_digest(body)}


def plan_repository(
    repo: Path, *, board: str | None = None, workload_class: str | None = None,
) -> dict:
    dirty = _git(
        repo,
        "status",
        "--porcelain",
        "--",
        "autoresearch",
        ".github/workflows/audit.yml",
    )
    if dirty:
        raise AuditError("audit planning inputs are dirty")
    manifest = load_manifest(repo)
    if board is not None:
        manifest.group_for_board(board)
    if workload_class is not None:
        manifest.workload_class(workload_class)
    epoch = int(ledger.current_epoch(repo)["epoch"])
    source = source_binding(repo)
    return build_plan(
        manifest,
        ledger.load(repo),
        epoch=epoch,
        candidate_commit=source["candidate_commit"],
        source=source,
        board=board,
        workload_class=workload_class,
        commit_resolver=lambda value: _git(
            repo, "rev-parse", "--verify", f"{value}^{{commit}}"
        ),
    )


def validate_plan(repo: Path, plan: dict) -> None:
    if plan.get("schema") != PLAN_SCHEMA:
        raise AuditError("unsupported audit plan schema")
    body = {key: value for key, value in plan.items() if key != "plan_sha256"}
    if plan.get("plan_sha256") != _canonical_digest(body):
        raise AuditError("audit plan digest does not match")
    if plan.get("source") != source_binding(repo):
        raise AuditError("audit plan is stale relative to HEAD/manifest/ledger/epoch")
    manifest = load_manifest(repo)
    canonical = build_plan(
        manifest,
        ledger.load(repo),
        epoch=int(ledger.current_epoch(repo)["epoch"]),
        candidate_commit=plan["source"]["candidate_commit"],
        source=plan["source"],
        commit_resolver=lambda value: _git(
            repo, "rev-parse", "--verify", f"{value}^{{commit}}"
        ),
    )
    canonical_items = {item["item_id"]: item for item in canonical["items"]}
    for item in plan.get("items", []):
        payload = {key: value for key, value in item.items() if key != "item_id"}
        if item.get("item_id") != _canonical_digest(payload):
            raise AuditError("audit item digest does not match")
        contract = item.get("execution_contract")
        expected = {
            "judged": True,
            "guards_mode": "all",
            "oracle_required": True,
            "audit_power": "required_bounded_boost",
            "scope": "s5",
            "dimension": "time",
        }
        if contract != expected:
            raise AuditError("audit execution contract is not fail closed")
        if canonical_items.get(item["item_id"]) != item:
            raise AuditError("audit item is not currently due under ledger authority")
        for commit in (item["predecessor_commit"], item["candidate_commit"]):
            _git(repo, "cat-file", "-e", f"{commit}^{{commit}}")
        ancestry = subprocess.run(
            [
                "git", "merge-base", "--is-ancestor",
                item["predecessor_commit"], item["candidate_commit"],
            ],
            cwd=repo,
            capture_output=True,
            text=True,
        )
        if ancestry.returncode != 0:
            raise AuditError("audit predecessor is not an ancestor of candidate HEAD")


def _execute_item(repo: Path, manifest: Manifest, item: dict, out_dir: Path) -> dict:
    if item.get("runnable") is not True:
        raise AuditError(f"due audit is blocked: {item.get('blocked_reason')}")
    predecessor = item["predecessor_commit"]
    _git(repo, "cat-file", "-e", f"{predecessor}^{{commit}}")
    with tempfile.TemporaryDirectory(prefix="stwo-perf-audit-") as raw:
        pred = Path(raw) / "predecessor"
        _git(repo, "worktree", "add", "--detach", str(pred), predecessor)
        try:
            verdict = runner.evaluate(
                repo,
                pred,
                manifest,
                item["workload_class"],
                "time",
                "s5",
                judged=True,
                out_dir=out_dir / item["item_id"].split(":", 1)[1][:16],
                board=item["board"],
                holdout_seed=int(item["item_id"][-8:], 16),
                guards_mode="all",
                audit_mode=True,
                require_quiet_host=True,
            )
        finally:
            _git(repo, "worktree", "remove", "--force", str(pred))
    verdict["repo_commit"] = item["candidate_commit"]
    verdict["predecessor_commit"] = predecessor
    gates_passed = bool(verdict.get("gates")) and all(
        gate.get("pass") is True for gate in verdict["gates"].values()
    )
    replacements = (
        item["credit_replaces"]
        if item["evidence_kind"] == "direct_audit" and gates_passed else []
    )
    verdict["ledger_evidence"] = {
        "evidence_kind": item["evidence_kind"],
        "covers": item["covers"],
        "credit_replaces": replacements,
        "supersedes": "",
    }
    verdict["audit_binding"] = {
        "plan_sha256": item["item_id"],
        "candidate_commit": item["candidate_commit"],
        "predecessor_commit": predecessor,
        "guards_mode": "all",
        "oracle_required": True,
        "audit_power": "required_bounded_boost",
    }
    return verdict


def _blocked_item_report(item: dict) -> dict:
    return {
        "item_id": item["item_id"],
        "board": item["board"],
        "workload_class": item["workload_class"],
        "evidence_kind": item["evidence_kind"],
        "blocked_reason": item["blocked_reason"],
    }


def execute_plan(repo: Path, plan: dict, out_dir: Path, max_items: int = 1) -> dict:
    validate_plan(repo, plan)
    if max_items < 1:
        raise AuditError("max_items must be positive")
    selected = []
    blocked = []
    for item in plan["items"]:
        if len(selected) == max_items:
            break
        if item["runnable"]:
            selected.append(item)
        else:
            blocked.append(_blocked_item_report(item))
    manifest = load_manifest(repo)
    lock = runner.acquire_judge_lock(repo)
    try:
        verdicts = [_execute_item(repo, manifest, item, out_dir) for item in selected]
    finally:
        lock.unlink(missing_ok=True)
    return {
        "schema": UNSIGNED_SCHEMA,
        "plan": plan,
        "executed_item_ids": [item["item_id"] for item in selected],
        "blocked_items": blocked,
        "verdicts": verdicts,
    }


def _validate_unsigned_verdict(repo: Path, item: dict, verdict: dict) -> None:
    binding = verdict.get("audit_binding", {})
    objective = verdict.get("declared_objective", {})
    environment = verdict.get("environment", {})
    if (
        not isinstance(binding, dict)
        or not isinstance(objective, dict)
        or not isinstance(environment, dict)
        or verdict.get("kind") != "judged"
        or verdict.get("audit_mode") is not True
        or environment.get("judge_lock_held") is not True
        or verdict.get("repo_commit") != item["candidate_commit"]
        or verdict.get("predecessor_commit") != item["predecessor_commit"]
        or objective.get("board") != item["board"]
        or objective.get("workload_class") != item["workload_class"]
        or objective.get("dimension") != "time"
    ):
        raise AuditError("unsigned verdict identity does not match its audit item")
    if (
        binding.get("plan_sha256") != item["item_id"]
        or binding.get("guards_mode") != "all"
        or binding.get("oracle_required") is not True
        or binding.get("audit_power") != "required_bounded_boost"
    ):
        raise AuditError("unsigned audit verdict weakened its execution contract")
    manifest = load_manifest(repo)
    expected_guards = set(runner.guard_registry(manifest).get("workloads", {}))
    guards = verdict.get("guards")
    if not isinstance(guards, dict) or set(guards) != expected_guards:
        raise AuditError("unsigned audit verdict does not contain the full guard portfolio")
    workloads = manifest.workloads(
        item["workload_class"], board=item["board"],
    )
    oracles = verdict.get("rust_oracle")
    if (
        not isinstance(oracles, list)
        or len(oracles) != len(workloads)
        or not all(
            isinstance(result, dict) and result.get("verified") is True
            for result in oracles
        )
    ):
        raise AuditError("unsigned audit verdict lacks complete oracle parity")
    health = verdict.get("search_health", {})
    decision = health.get("decision", {}) if isinstance(health, dict) else {}
    target = decision.get("target_rounds") if isinstance(decision, dict) else None
    configured = (
        decision.get("configured_rounds") if isinstance(decision, dict) else None
    )
    if (
        not isinstance(decision, dict)
        or type(target) is not int
        or type(configured) is not int
        or target <= configured
    ):
        raise AuditError("unsigned audit verdict did not use boosted measurement power")
    gates = verdict.get("gates")
    gates_passed = isinstance(gates, dict) and bool(gates) and all(
        isinstance(gate, dict) and gate.get("pass") is True
        for gate in gates.values()
    )
    expected_replacements = (
        item["credit_replaces"]
        if item["evidence_kind"] == "direct_audit" and gates_passed else []
    )
    if verdict.get("ledger_evidence") != {
        "evidence_kind": item["evidence_kind"],
        "covers": item["covers"],
        "credit_replaces": expected_replacements,
        "supersedes": "",
    }:
        raise AuditError("unsigned verdict changed its append-only audit evidence")


def finalize(repo: Path, unsigned: dict) -> dict:
    """Sign verdicts and materialize exact append-ready schema-v3 rows."""
    if unsigned.get("schema") != UNSIGNED_SCHEMA:
        raise AuditError("unsupported unsigned audit bundle")
    plan = unsigned.get("plan", {})
    validate_plan(repo, plan)
    by_id = {item["item_id"]: item for item in plan.get("items", [])}
    epoch = int(plan.get("epoch", 0))
    executed = unsigned.get("executed_item_ids")
    blocked = unsigned.get("blocked_items", [])
    verdicts = unsigned.get("verdicts")
    if (
        not isinstance(executed, list)
        or not isinstance(blocked, list)
        or not isinstance(verdicts, list)
        or len(executed) != len(set(executed))
        or len(executed) != len(verdicts)
        or any(not isinstance(verdict, dict) for verdict in verdicts)
    ):
        raise AuditError("unsigned bundle execution list is malformed")
    canonical_blocked = {
        item["item_id"]: _blocked_item_report(item)
        for item in plan.get("items", []) if not item["runnable"]
    }
    if (
        any(
            not isinstance(report, dict)
            or canonical_blocked.get(report.get("item_id")) != report
            for report in blocked
        )
        or len(blocked) != len({report["item_id"] for report in blocked})
    ):
        raise AuditError("unsigned bundle blocked-item report is malformed")
    evidence = []
    for item_id, verdict in zip(executed, verdicts):
        binding = verdict.get("audit_binding", {})
        item = by_id.get(item_id)
        if item is None or binding.get("plan_sha256") != item_id:
            raise AuditError("unsigned verdict is not bound to a judged audit item")
        _validate_unsigned_verdict(repo, item, verdict)
        signed = signing.sign(verdict)
        outcome, gates_cell = promotion.decide_outcome(signed, predecessor_fresh=True)
        submission_id = (
            f"audit-e{epoch}-{item['evidence_kind'].replace('_audit', '')}-"
            f"{item['board']}-{item['workload_class']}-"
            f"{item['item_id'][-12:]}"
        )
        row = promotion.row_from_verdict(
            submission_id,
            signed,
            epoch,
            outcome,
            gates_cell,
            verdict_kind="judged",
            commit=item["candidate_commit"],
        )
        evidence.append({
            "item_id": item["item_id"],
            "signed_verdict": signed,
            "ledger_row": row,
            "ledger_tsv": ledger.serialize_row(row),
        })
    body = {
        "schema": SIGNED_SCHEMA,
        "source": plan.get("source"),
        "epoch": epoch,
        "blocked_items": blocked,
        "evidence": evidence,
    }
    return {**body, "bundle_sha256": _canonical_digest(body)}


def append_signed(repo: Path, bundle: dict) -> int:
    """Verify and append a fresh signed bundle, or reject it without mutation."""
    if bundle.get("schema") != SIGNED_SCHEMA:
        raise AuditError("unsupported signed audit bundle")
    body = {key: value for key, value in bundle.items() if key != "bundle_sha256"}
    if bundle.get("bundle_sha256") != _canonical_digest(body):
        raise AuditError("signed audit bundle digest does not match")
    if bundle.get("source") != source_binding(repo):
        raise AuditError("signed audit bundle is stale; ledger or authority moved")
    rows = []
    for entry in bundle.get("evidence", []):
        signing.verify(entry["signed_verdict"])
        row = entry["ledger_row"]
        if entry.get("ledger_tsv") != ledger.serialize_row(row):
            raise AuditError("append-ready ledger row encoding changed")
        rows.append(row)
    existing = ledger.ledger_path(repo).read_text()
    proposed = existing + "".join(ledger.serialize_row(row) + "\n" for row in rows)
    parsed = ledger.parse(proposed)
    touched = {(row["board"], row["workload_class"]) for row in rows}
    for board, workload_class in sorted(touched):
        # Replay each touched cell under ITS board's era policy (TRACKS §7).
        policy = metrics.policy_from_epoch(
            ledger.epoch_for_board(repo, int(bundle["epoch"]), board)
        )
        metrics.score_class(
            parsed,
            int(bundle["epoch"]),
            board,
            workload_class,
            shrinkage_lambda=policy.shrinkage_lambda,
            audit_anchor_commit=policy.audit_anchor_commit,
        )
    ledger.ledger_path(repo).write_text(proposed)
    return len(rows)


def _write(path: str, value: dict) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Metrics-v2 audit controller")
    sub = parser.add_subparsers(dest="command", required=True)
    plan = sub.add_parser("plan")
    plan.add_argument("--repo", default=".")
    plan.add_argument("--board")
    plan.add_argument("--class", dest="workload_class")
    plan.add_argument("--out", required=True)
    run = sub.add_parser("run")
    run.add_argument("--repo", default=".")
    run.add_argument("--plan", required=True)
    run.add_argument("--out", required=True)
    run.add_argument("--runs-dir", required=True)
    run.add_argument("--max-items", type=int, default=1)
    finish = sub.add_parser("finalize")
    finish.add_argument("--repo", default=".")
    finish.add_argument("--unsigned", required=True)
    finish.add_argument("--out", required=True)
    append = sub.add_parser("append")
    append.add_argument("--repo", default=".")
    append.add_argument("--bundle", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "plan":
            result = plan_repository(
                Path(args.repo).resolve(),
                board=args.board,
                workload_class=args.workload_class,
            )
            _write(args.out, result)
            print(json.dumps({"due": len(result["items"]), "out": args.out}))
        elif args.command == "run":
            result = execute_plan(
                Path(args.repo).resolve(),
                json.loads(Path(args.plan).read_text()),
                Path(args.runs_dir),
                max_items=args.max_items,
            )
            _write(args.out, result)
        elif args.command == "finalize":
            _write(
                args.out,
                finalize(
                    Path(args.repo).resolve(),
                    json.loads(Path(args.unsigned).read_text()),
                ),
            )
        else:
            count = append_signed(
                Path(args.repo).resolve(), json.loads(Path(args.bundle).read_text())
            )
            print(f"appended {count} audit row(s)")
    except (AuditError, ledger.LedgerError, metrics.MetricsError, signing.SigningError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
