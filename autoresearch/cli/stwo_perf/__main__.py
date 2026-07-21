"""stwo-perf command surface (playbook F.3). Thin root: parse, dispatch, exit."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from . import __version__, ansi, config, ledger, manifest as manifest_mod, notes, render
from .github_auth import AuthError, device_login, whoami


def _fail(message: str) -> int:
    print(f"{ansi.style('error:', 'red', 'bold')} {message}", file=sys.stderr)
    return 1


def cmd_benchmark(_args) -> int:
    m = manifest_mod.load()
    print(render.benchmark_summary(m.raw))
    rows = ledger.load(m.root)
    print()
    print(f"  {len(rows)} judged promotion(s) in the ledger · epoch {ledger.current_epoch(m.root)['epoch']}")
    return 0


def cmd_frontier(_args) -> int:
    m = manifest_mod.load()
    rows = ledger.load(m.root)
    gates = m.gates
    anchors = m.raw["harness"].get("anchor_prove_ms") or {}
    owned = {group.board for group in m.groups()}
    classes_by_board = {
        board: m.class_names(
            board=board, scored_only=True, include_disabled=True,
        ) if board in owned else []
        for board in ledger.BOARDS
    }
    print(render.frontier_view(
        rows, list(ledger.BOARDS), classes_by_board, anchors,
        (gates["targeted_class_budget"], gates["matrix_row_budget"]),
    ))
    if m.anchor_commit is None:
        print()
        print(ansi.style("  anchor not frozen — drift budgets inactive, judged promotion disabled", "yellow"))
    return 0


def cmd_clone(args) -> int:
    from . import workspace
    m = manifest_mod.load()
    dest = workspace.clone(m.root, Path(args.dest))
    print(f"{ansi.OK} workspace created at {dest}")
    print(f"  next: cd {dest} && stwo-perf setup")
    return 0


def cmd_setup(_args) -> int:
    from . import workspace
    m = manifest_mod.load()
    built = workspace.setup(m.root, m)
    print(f"{ansi.OK} toolchain verified; bench targets built for group(s): "
          + ", ".join(built))
    return 0


def _resolve_board(args, m) -> str:
    """Explicit --board wins; otherwise route by the diff — a change that
    touches src/backends/metal/ can only show its effect on the Metal board,
    so scoring it on core_cpu records an honest but useless neutral."""
    if args.board:
        return args.board
    from . import runner
    if any(p.startswith("src/backends/metal/") for p in runner.changed_paths(m.root)):
        print(ansi.style(
            "  board auto-selected: core_metal (diff touches src/backends/metal/; "
            "pass --board to override)", "dim"))
        return "core_metal"
    return "core_cpu"


def cmd_run(args) -> int:
    from . import runner
    m = manifest_mod.load()
    out_dir = m.root / "autoresearch" / ".runs" / "latest"
    board = _resolve_board(args, m)
    if args.staged_calibration and not args.aa:
        return _fail("--staged-calibration is valid only with --aa")
    if args.staged_calibration and board != "riscv":
        return _fail("--staged-calibration is restricted to the RISC-V board")
    if args.aa:
        try:
            result = runner.evaluate_aa(
                m.root, m, args.workload_class, out_dir, board=board,
                allow_staged=args.staged_calibration,
            )
        except runner.RunError as exc:
            return _fail(str(exc))
        if args.out:
            calibration_out = Path(args.out)
            calibration_out.parent.mkdir(parents=True, exist_ok=True)
            calibration_out.write_text(json.dumps(result, indent=2) + "\n")
        print(ansi.kv_panel("A/A dispersion", [
            ("class", result["workload_class"]),
            ("board", result["board"]),
            ("workload", result["workload"]),
            ("rounds", str(result["rounds"])),
            ("A/A r", f"{result['aa_r']}"),
            ("CI half-width", ansi.style(f"{result['half_width']}", "bold")),
        ]))
        print()
        print("  record it: set aa_dispersion." + result["board"] + "."
              + result["workload_class"]
              + f" = {result['half_width']} in ledger/epochs.json via a reviewed PR")
        print("  anchor it: set anchor_prove_ms." + result["board"] + "."
              + result["workload_class"]
              + f" = {result['anchor_prove_ms']} in MANIFEST.json via the same PR")
        if args.out:
            print(ansi.style(f"  calibration written to {calibration_out}", "dim"))
        return 0
    if args.scope == "s2":
        return _fail("s2 is diagnostic-only; run s1 for kernels or s3+ for acceptance")
    predecessor = Path(args.predecessor).resolve() if args.predecessor else None
    if predecessor is None:
        return _fail(
            "--predecessor <worktree> is required: scoring is paired two-arm by "
            "contract (frozen reports are provenance, never a denominator)"
        )
    try:
        # The public CLI only ever evaluates claimed verdicts; judged runs are
        # minted exclusively by the judge bot, which signs them (signing.py).
        verdict = runner.evaluate(
            m.root, predecessor, m, args.workload_class, args.dimension,
            args.scope, judged=False, out_dir=out_dir, board=board,
            guards_mode=args.guards,
        )
    except runner.RunError as exc:
        return _fail(str(exc))
    out = Path(args.out) if args.out else out_dir / "verdict.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(verdict, indent=2) + "\n")
    print(render.verdict(verdict))
    print()
    print(ansi.style(f"  verdict written to {out}", "dim"))
    return 0


def cmd_calibrate_metal(args) -> int:
    from . import metal_calibration, metal_calibration_runner

    m = manifest_mod.load()
    try:
        if args.calibration_cmd == "measure":
            path = metal_calibration_runner.measure(
                m, Path(args.out_dir),
            )
            print(f"{ansi.OK} complete Metal calibration written to {path}")
            print("  review, then freeze it with `stwo-perf calibrate-metal freeze`")
            return 0
        if args.calibration_cmd == "freeze":
            path = metal_calibration.freeze(m, Path(args.report))
            print(f"{ansi.OK} Metal calibration frozen at {path}")
            print("  commit the artifact, MANIFEST.json, and ledger/epochs.json together")
            return 0
        if args.report:
            metal_calibration.validate_document(
                json.loads(Path(args.report).read_text(encoding="utf-8")), m,
            )
        if args.require_frozen or not args.report:
            metal_calibration.require_frozen(m)
        print(f"{ansi.OK} Metal calibration contract valid")
        return 0
    except metal_calibration.CalibrationError as exc:
        return _fail(str(exc))


def cmd_submit(args) -> int:
    from . import submitter
    _warn_harness_drift()
    m = manifest_mod.load()
    try:
        sub_dir = submitter.package(
            m.root, m, args.slug, Path(args.note_file),
            [Path(v) for v in args.verdict],
            Path(args.transcripts) if args.transcripts else None, args.model,
            transcripts_declined=args.transcripts_declined,
        )
    except submitter.SubmitError as exc:
        return _fail(str(exc))
    print(f"{ansi.OK} submission packaged: {sub_dir.relative_to(m.root)}")
    print("  next: commit the submission directory and your editable-path diff on a")
    print("  branch, then open a PR against teddyjfpender/stwo-zig. No label needed —")
    print("  the pipeline classifies submissions from the new submissions/ directory.")
    print("  Green validation + CI auto-merges collaborator PRs; first-time outside")
    print("  contributors get a human merge, which records your claimed verdict.")
    return 0


def cmd_update(_args) -> int:
    from . import update as update_mod
    m = manifest_mod.load()
    try:
        result = update_mod.update(m.root)
    except update_mod.UpdateError as exc:
        return _fail(str(exc))
    if result["commits"] == 0:
        print(f"{ansi.OK} already current: {result['new'][:12]}")
        return 0
    print(
        f"{ansi.OK} fast-forwarded {result['commits']} commit(s): "
        f"{result['old'][:12]} → {result['new'][:12]}"
    )
    if result["harness_changed"]:
        print(ansi.style(
            "  harness policy changed — the CLI runs from this repository, so the "
            "new rules are already in effect (nothing to rebuild or reinstall)",
            "yellow",
        ))
    else:
        print(ansi.style("  no harness policy changes; source updated", "dim"))
    return 0


def _warn_harness_drift() -> None:
    """Best-effort submit-time staleness nudge: source divergence is normal
    mid-effort, autoresearch/** divergence means stale rules."""
    from . import update as update_mod
    m = manifest_mod.load()
    drift = update_mod.harness_drift(m.root)
    if drift:
        print(ansi.style(
            f"warning: harness policy differs from origin/main ({len(drift)} file(s), "
            f"e.g. {drift[0]}) — run `stwo-perf update` in the canonical checkout "
            "(then `stwo-perf sync` in workspaces) so submissions follow current rules",
            "yellow",
        ), file=sys.stderr)


def cmd_promote_claimed(args) -> int:
    from . import promotion
    m = manifest_mod.load()
    sub_dir = m.root / "autoresearch" / "submissions" / args.submission
    verdicts = promotion.claimed_verdict_files(sub_dir)
    if not verdicts:
        return _fail(f"no verdicts under {sub_dir}")
    recorded = 0
    for verdict_path in verdicts:
        try:
            row = promotion.promote_claimed(m.root, args.submission, verdict_path.name)
        except promotion.PromotionError as exc:
            print(ansi.style(f"  {verdict_path.name}: {exc}", "dim"))
            continue
        kind = ansi.style("claimed", "yellow")
        print(
            f"✓ ledger row appended ({kind}): {args.submission} "
            f"[{row['workload_class']}] outcome={row['outcome']} R={row['judged_r']:.4f}"
        )
        recorded += 1
    if recorded == 0:
        return _fail("no verdict could be recorded")
    print(ansi.style(
        "  optimistic maintainer adjudication — a judged run supersedes these rows",
        "dim",
    ))
    return 0


def cmd_submissions(_args) -> int:
    m = manifest_mod.load()
    subs = sorted(
        (p for p in (m.root / "autoresearch" / "submissions").iterdir() if p.is_dir()),
        reverse=True,
    )
    styles = {"promoted": "iris", "neutral": "yellow", "rejected": "red"}
    rows = []
    ledger_by_sub = {r.submission_id: r for r in ledger.load(m.root)}
    for sub in subs:
        row = ledger_by_sub.get(sub.name)
        if row:
            outcome = str(row.values.get("outcome", "rejected"))
            state = ansi.style(outcome, styles.get(outcome, "red"))
        else:
            state = ansi.style("pending", "yellow")
        rows.append([sub.name, state, f"{row.judged_r:.4f}" if row else "—"])
    if not rows:
        print(ansi.style("no submissions yet", "dim"))
        return 0
    print(ansi.table(["submission", "state", "judged r"], rows))
    return 0


def cmd_submission_note(args) -> int:
    m = manifest_mod.load()
    matches = [
        p for p in (m.root / "autoresearch" / "submissions").iterdir()
        if p.is_dir() and p.name.startswith(args.prefix)
    ]
    if len(matches) != 1:
        return _fail(f"prefix matches {len(matches)} submissions; be more specific")
    print((matches[0] / "note.md").read_text())
    return 0


def cmd_notes(args) -> int:
    m = manifest_mod.load()
    if args.notes_cmd == "add":
        body = Path(args.note_file).read_text() if args.note_file else (args.note or "")
        if not body:
            return _fail("provide --note-file or --note")
        try:
            path = notes.add(m.root, args.title, body)
        except notes.NoteError as exc:
            return _fail(str(exc))
        print(f"{ansi.OK} note written: {path.relative_to(m.root)}")
        print("  commit it (or include it in your next PR) to share it")
        return 0
    found = (
        notes.search(m.root, args.query, args.author)
        if args.notes_cmd == "search"
        else notes.list_notes(m.root, args.author)
    )
    if not found:
        print(ansi.style("no notes found", "dim"))
        return 0
    for n in found[: args.limit]:
        print(ansi.rule(n.title))
        print(ansi.style(f"  {n.author} · {n.created_utc}", "dim"))
        print()
        print(n.body.strip())
        print()
    return 0


def latest_promoted_commit(rows) -> str | None:
    """Newest effective promoted row across every board: promotions land
    linearly on main, so the last-appended promoted row is the most complete
    tree regardless of which board it scored on. Append order also breaks
    the second-granularity judged_at ties a single recorder run produces."""
    from . import frontier as frontier_mod
    effective = frontier_mod.effective_rows(rows)
    return effective[-1].commit if effective else None


def cmd_sync(args) -> int:
    from . import workspace
    m = manifest_mod.load()
    promoted = latest_promoted_commit(ledger.load(m.root))
    try:
        restored = workspace.sync(m.root, m, promoted, force=args.force)
    except workspace.WorkspaceError as exc:
        return _fail(str(exc))
    source = promoted or "default-branch tip (ledger empty)"
    print(f"{ansi.OK} harness at tip; editable sets restored from {source}:")
    for spec in restored:
        print(f"   {ansi.ARROW} {spec}")
    return 0


def cmd_reset(args) -> int:
    from . import workspace
    m = manifest_mod.load()
    try:
        workspace.restore_editable_from(m.root, m, args.commit, force=args.force)
    except workspace.WorkspaceError as exc:
        return _fail(str(exc))
    print(f"{ansi.OK} editable paths restored from {args.commit}; harness stays at tip")
    return 0


def cmd_login(args) -> int:
    client_id = args.client_id or config.get("github_client_id")
    if not client_id:
        from . import remote
        try:
            client_id = remote.request(config.api_url(), "/v1/client-id")["github_client_id"]
        except (remote.RemoteError, KeyError):
            return _fail(
                "backend has no GitHub client id; pass --client-id once or configure it"
            )
    try:
        token = device_login(client_id)
        user = whoami(token)
    except AuthError as exc:
        return _fail(str(exc))
    config.set_value("github_client_id", client_id)
    config.set_value("github_token", token)
    print(f"{ansi.OK} logged in as {ansi.style(user, 'bold')} (token stored, chmod 600)")
    return 0


def cmd_apikey(_args) -> int:
    from . import remote
    token = config.github_token()
    if not token:
        return _fail("login first: stwo-perf login")
    try:
        data = remote.issue_key(config.api_url(), token)
    except remote.RemoteError as exc:
        return _fail(str(exc))
    config.set_value("api_key", data["key"])
    print(f"{ansi.OK} API key issued for {data['login']} and stored (scoped for CLI submissions)")
    return 0


def _remote_key() -> str:
    key = config.api_key()
    if not key:
        raise RuntimeError("no API key configured; run `stwo-perf apikey` first")
    return key


def cmd_whoami(_args) -> int:
    from . import remote
    try:
        data = remote.me(config.api_url(), _remote_key())
    except (remote.RemoteError, RuntimeError) as exc:
        return _fail(str(exc))
    identity = data["identity"]
    print(ansi.kv_panel("authenticated CLI identity", [
        ("GitHub", identity["login"]),
        ("name", identity["name"]),
        ("id", str(identity["github_id"])),
        ("profile", identity["profile_url"]),
    ]))
    return 0


def cmd_apikey_revoke(_args) -> int:
    from . import remote
    try:
        data = remote.revoke_key(config.api_url(), _remote_key())
    except (remote.RemoteError, RuntimeError) as exc:
        return _fail(str(exc))
    config.set_value("api_key", "")
    print(f"{ansi.OK} API key {data['key_id']} revoked and removed from CLI config")
    return 0


def cmd_submit_remote(args) -> int:
    from . import remote
    _warn_harness_drift()
    m = manifest_mod.load()
    receipt_path = Path(args.receipt)
    receipt_bytes = receipt_path.read_bytes()
    receipt = json.loads(receipt_bytes)
    note = Path(args.note_file).read_text()
    qualification = {"receipt": receipt}
    attestation_required = m.qualification_policy.get(
        "require_github_artifact_attestation", False
    )
    if args.artifact_digest or args.attestation_url or attestation_required:
        attestation = {
            "artifact_digest": args.artifact_digest
            or "sha256:" + hashlib.sha256(receipt_bytes).hexdigest(),
        }
        if args.attestation_url:
            attestation["url"] = args.attestation_url
        qualification["attestation"] = attestation
    payload = {
        "schema_version": 2,
        "source": {
            "repository": args.repository,
            "commit": receipt.get("candidate_commit"),
            "frontier_commit": receipt.get("frontier_commit"),
            "ref": args.ref,
        },
        "qualification": qualification,
        "claim": receipt.get("claim"),
        "note": note,
        "coauthors": args.coauthor,
    }
    try:
        data = remote.submit(config.api_url(), _remote_key(), payload)
    except (remote.RemoteError, RuntimeError) as exc:
        return _fail(str(exc))
    item = data["submission"]
    print(f"{ansi.OK} remote submission queued: {item['id']}")
    print(f"  state: {item['state']} · source: {item['source']['commit'][:12]}")
    if args.coauthor:
        print("  co-authors must accept with: stwo-perf coauthor-accept <id>")
    return 0


def cmd_remote_frontier(args) -> int:
    from . import remote
    m = manifest_mod.load()
    try:
        m.validate_workload_class(
            args.workload_class, board=args.board, include_disabled=True,
        )
    except manifest_mod.ManifestError as exc:
        return _fail(str(exc))
    try:
        data = remote.frontier(config.api_url(), args.board, args.workload_class)
    except remote.RemoteError as exc:
        return _fail(str(exc))
    print(data["repository_frontier_commit"])
    return 0


def cmd_submission_status(args) -> int:
    from . import remote
    try:
        data = remote.submissions(config.api_url(), _remote_key(), args.submission_id)
    except (remote.RemoteError, RuntimeError) as exc:
        return _fail(str(exc))
    items = [data["submission"]] if args.submission_id else data["submissions"]
    if not items:
        print(ansi.style("no remote submissions", "dim"))
        return 0
    rows = [[
        item["id"], item["state"], item["claim"]["board"],
        item["claim"]["workload_class"], f"{item['claim']['shipping_index']:.4f}",
    ] for item in items]
    print(ansi.table(["id", "state", "board", "class", "claimed R"], rows))
    return 0


def cmd_coauthor_accept(args) -> int:
    from . import remote
    try:
        data = remote.accept_coauthor(config.api_url(), _remote_key(), args.submission_id)
    except (remote.RemoteError, RuntimeError) as exc:
        return _fail(str(exc))
    print(f"{ansi.OK} co-authorship accepted for {data['submission']['id']}")
    return 0


def cmd_submission_withdraw(args) -> int:
    from . import remote
    try:
        data = remote.withdraw(config.api_url(), _remote_key(), args.submission_id)
    except (remote.RemoteError, RuntimeError) as exc:
        return _fail(str(exc))
    print(f"{ansi.OK} submission {data['submission']['id']} withdrawn")
    return 0


def cmd_config(args) -> int:
    if args.set:
        key, _, value = args.set.partition("=")
        if not value:
            return _fail("use --set key=value")
        config.set_value(key.strip(), value.strip())
        print(f"{ansi.OK} {key.strip()} updated")
        return 0
    data = config.load()
    redacted = {
        k: (v[:6] + "…" if isinstance(v, str) and ("token" in k or "key" in k) else v)
        for k, v in data.items()
    }
    print(ansi.kv_panel("config", [(k, str(v)) for k, v in sorted(redacted.items())] or [("(empty)", "")]))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="stwo-perf",
        description="Autoresearch harness for stwo-zig: judged scoring under "
                    "oracle-parity gates, submissions, and the promotions ledger.",
    )
    parser.add_argument("--version", action="version", version=f"stwo-perf {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("benchmark", help="show the fixed suite, gates, and ledger state")
    sub.add_parser("frontier", help="print the promotions ledger and Pareto frontier")

    p = sub.add_parser("clone", help="create a searcher workspace (git worktree)")
    p.add_argument("dest")

    sub.add_parser("setup", help="verify toolchain and build the bench target")

    sub.add_parser(
        "update",
        help="fast-forward the canonical checkout to origin/main — the CLI is "
             "repo-resident, so updating the checkout IS updating the CLI",
    )

    p = sub.add_parser("run", help="paired reward evaluation; emits a claimed verdict")
    p.add_argument("--scope", choices=["s1", "s2", "s3", "s4", "s5"], default="s3")
    p.add_argument(
        "--class", dest="workload_class", default="small",
        help="manifest-declared workload class (validated against --board)",
    )
    p.add_argument("--dimension", choices=["time", "rss", "energy"], default="time")
    p.add_argument(
        "--guards", choices=["auto", "all", "none"], default="auto",
        help="regression guards: auto = impact-mapped from the diff (default), "
             "all = full portfolio, none = objective only (inner-loop iteration; "
             "submissions still face the judged guard matrix)",
    )
    p.add_argument("--board", default=None,
                   choices=["core_cpu", "core_hybrid", "core_metal",
                            "heavy_native", "heavy_cairo", "stream", "riscv"],
                   help="scoring board (schema/scoring.md); kernels are never "
                        "boards. Default: auto — core_metal when the diff "
                        "touches src/backends/metal/, else core_cpu")
    p.add_argument("--predecessor", help="worktree of the paired A arm (required)")
    p.add_argument("--aa", action="store_true",
                   help="A/A dispersion measurement (both arms = this tree)")
    p.add_argument(
        "--staged-calibration", action="store_true",
        help="permit RISC-V A/A calibration before board activation; requires --aa",
    )
    p.add_argument("--out", help="verdict output path")

    p = sub.add_parser(
        "calibrate-metal",
        help="measure, freeze, or validate the epoch-pinned M5 Metal calibration",
    )
    calibration = p.add_subparsers(dest="calibration_cmd", required=True)
    measure = calibration.add_parser("measure", help="run every scored Metal class")
    measure.add_argument("--out-dir", required=True,
                         help="fresh output directory (keep outside the repository)")
    freeze = calibration.add_parser("freeze", help="install a reviewed calibration")
    freeze.add_argument("--report", required=True)
    validate = calibration.add_parser("validate", help="validate report/frozen state")
    validate.add_argument("--report")
    validate.add_argument("--require-frozen", action="store_true")

    p = sub.add_parser("submit", help="package a submission directory")
    p.add_argument("--slug", required=True)
    p.add_argument("--note-file", required=True)
    p.add_argument(
        "--verdict", required=True, action="append",
        help="claimed verdict.json from `run`; repeat once per board/class pair "
             "the change moves — every moved pair earns its suite credit",
    )
    p.add_argument(
        "--transcripts",
        help="directory of sanitized session transcripts (the default expectation; "
             "see skills/submission-transcripts)",
    )
    p.add_argument(
        "--transcripts-declined", action="store_true",
        help="record an explicit declination to publish session transcripts "
             "(the only accepted alternative to --transcripts)",
    )
    p.add_argument("--model", required=True, help='e.g. "Claude Fable 5"')

    sub.add_parser("submissions", help="list submissions and their judged state")

    p = sub.add_parser(
        "promote-claimed",
        help="maintainer-as-judge: record a merged submission's claimed verdict "
             "as an optimistic ledger row (superseded by a judged run later)",
    )
    p.add_argument("submission", help="submission directory name under autoresearch/submissions/")

    p = sub.add_parser("submission-note", help="print a submission's note")
    p.add_argument("prefix")

    p = sub.add_parser("notes", help="standalone working notes")
    ns = p.add_subparsers(dest="notes_cmd", required=True)
    pa = ns.add_parser("add")
    pa.add_argument("--title", required=True)
    pa.add_argument("--note-file")
    pa.add_argument("--note")
    for name in ("list", "search"):
        pl = ns.add_parser(name)
        if name == "search":
            pl.add_argument("query")
        pl.add_argument("--author")
        pl.add_argument("--limit", type=int, default=5)

    p = sub.add_parser("sync", help="fast-forward workspace to the promoted frontier")
    p.add_argument("--force", action="store_true")
    p = sub.add_parser("reset", help="restore editable paths from a promoted commit")
    p.add_argument("commit")
    p.add_argument("--force", action="store_true")

    p = sub.add_parser("login", help="GitHub device-flow login")
    p.add_argument("--client-id")
    sub.add_parser("apikey", help="issue and store a GitHub-bound CLI API key")
    sub.add_parser("apikey-revoke", help="revoke the configured CLI API key")
    sub.add_parser("whoami", help="verify the configured API key and show its GitHub identity")
    p = sub.add_parser("submit-remote", help="submit a fork commit and qualification receipt")
    p.add_argument("--receipt", required=True, help="qualification receipt JSON from fork CI")
    p.add_argument("--repository", required=True,
                   help="HTTPS URL of the GitHub fork containing the commit")
    p.add_argument("--ref", required=True, help="immutable source branch as refs/heads/<name>")
    p.add_argument("--note-file", required=True)
    p.add_argument("--artifact-digest",
                   help="override the automatically computed sha256 receipt digest")
    p.add_argument("--attestation-url", help="optional GitHub attestation audit URL")
    p.add_argument("--coauthor", action="append", default=[], metavar="GITHUB_LOGIN")
    p = sub.add_parser("remote-frontier", help="print the full canonical commit required by fork CI")
    p.add_argument("--board", default="core_cpu")
    p.add_argument(
        "--class", dest="workload_class", default="small",
        help="manifest-declared workload class (validated against --board)",
    )
    p = sub.add_parser("submission-status", help="list remote queue state or inspect one submission")
    p.add_argument("submission_id", nargs="?")
    p = sub.add_parser("coauthor-accept", help="accept requested Git co-authorship")
    p.add_argument("submission_id")
    p = sub.add_parser("submission-withdraw", help="withdraw your unjudged remote submission")
    p.add_argument("submission_id")
    p = sub.add_parser("config", help="show or set CLI configuration")
    p.add_argument("--set", metavar="KEY=VALUE")
    sub.add_parser("install-workflows",
                   help="copy autoresearch/workflows/*.yml into .github/workflows/")
    p = sub.add_parser("feed", help="compile the deterministic site feed (repo->website contract)")
    p.add_argument("--out", help="output path (default autoresearch/site/feed.json)")
    p.add_argument("--allow-dirty", action="store_true",
                   help="permit uncommitted input changes (feed is marked dirty; never publish)")
    return parser


def cmd_feed(args) -> int:
    from . import feed
    m = manifest_mod.load()
    try:
        out = feed.write_feed(m, Path(args.out) if args.out else None,
                              allow_dirty=args.allow_dirty)
    except feed.FeedError as exc:
        return _fail(str(exc))
    if args.allow_dirty:
        print(ansi.style("  ⚠ dirty inputs allowed — feed is marked dirty and "
                         "must not be published", "yellow"))
    data = json.loads(out.read_text())
    latest = data.get("latest_matrix") or {}
    try:
        display_path = out.relative_to(m.root)
    except ValueError:
        display_path = out
    print(f"{ansi.OK} feed written: {display_path}")
    print(ansi.kv_panel("feed", [
        ("schema", str(data["feed_schema_version"])),
        ("commit", str(data["provenance"]["repo_commit"])),
        ("boards", str(sum(1 for b in data["boards"].values() if b["entries"]))
                   + f"/{len(data['boards'])} populated"),
        ("latest matrix", str(latest.get("run_id", "none"))),
        ("matrix rows", str(len(latest.get("rows", [])))),
        ("submissions", str(len(data["submissions"]))),
    ]))
    return 0


def cmd_install_workflows(_args) -> int:
    import shutil
    m = manifest_mod.load()
    dest = m.root / ".github" / "workflows"
    dest.mkdir(parents=True, exist_ok=True)
    copied = []
    for src in sorted((m.root / "autoresearch" / "workflows").glob("*.yml")):
        shutil.copy2(src, dest / src.name)
        copied.append(src.name)
    print(f"{ansi.OK} copied into .github/workflows/: {', '.join(copied)}")
    print("  commit via normal review; require 'autoresearch-validate' AND")
    print("  'autoresearch-judge' as branch-protection checks on main")
    return 0


HANDLERS = {
    "benchmark": cmd_benchmark, "frontier": cmd_frontier, "clone": cmd_clone,
    "setup": cmd_setup, "run": cmd_run, "submit": cmd_submit,
    "submissions": cmd_submissions, "submission-note": cmd_submission_note,
    "promote-claimed": cmd_promote_claimed,
    "notes": cmd_notes, "sync": cmd_sync, "reset": cmd_reset,
    "login": cmd_login, "apikey": cmd_apikey,
    "apikey-revoke": cmd_apikey_revoke, "whoami": cmd_whoami,
    "submit-remote": cmd_submit_remote, "submission-status": cmd_submission_status,
    "remote-frontier": cmd_remote_frontier,
    "coauthor-accept": cmd_coauthor_accept,
    "submission-withdraw": cmd_submission_withdraw, "config": cmd_config,
    "install-workflows": cmd_install_workflows, "feed": cmd_feed,
    "update": cmd_update,
    "calibrate-metal": cmd_calibrate_metal,
}


def main(argv: list[str] | None = None) -> int:
    from . import workspace
    args = build_parser().parse_args(argv)
    try:
        return HANDLERS[args.cmd](args)
    except KeyboardInterrupt:
        print()
        return 130
    except manifest_mod.ManifestError as exc:
        return _fail(str(exc))
    except ledger.LedgerError as exc:
        return _fail(str(exc))
    except workspace.WorkspaceError as exc:
        return _fail(str(exc))
    except json.JSONDecodeError as exc:
        return _fail(f"invalid JSON: {exc}")
    except OSError as exc:
        return _fail(str(exc))


if __name__ == "__main__":
    raise SystemExit(main())
