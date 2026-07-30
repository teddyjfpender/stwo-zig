#!/usr/bin/env python3
"""Fail-closed CI gate for the pinned Sail/Spike retirement differential.

The pinned Sail model is the one non-self-referential oracle in this
repository, and its strongest evidence used to be a committed JSON snapshot
someone had to remember to regenerate. This gate makes the snapshot
mechanically un-stale-able and re-derives it live in hosted CI. It never
skips: when the pinned toolchain cannot be consulted the gate exits red,
naming exactly what was not checked. Decision record:
conformance/riscv-sail-differential-gate.md.

Subcommands:

  bind   No external tools. The committed evidence
         (conformance/riscv/formal-corpus-evidence.json) must describe
         exactly the committed corpus manifest and the pinned identities;
         any fixture, pin, count, or field-list change without regenerated
         live evidence fails in milliseconds. Runs on every PR through
         scripts/tests/test_riscv_sail_gate.py in the static lane.

  scope  Decide from a Git diff whether the live differential is required
         for this change (see LIVE_TRIGGER_PREFIXES for the policy and the
         gate document for why runner-only refactors are covered by the
         committed trace-digest parity instead).

  preflight
         Positive proof that the pinned toolchain is functional on THIS
         host, warm cache or cold: the SMT solver the pinned Sail compiler
         shells out to, the compiler itself at the pinned version, Spike's
         device-tree compiler, and the state of the workspace. It exists
         because provisioning faults otherwise surface as later steps that
         "did not run", which reads like a skip rather than a broken gate.

  run    The live gate: verify (or, with --prepare-on-miss, build) the
         pinned Sail/Spike workspace via scripts/riscv_formal_tools.py, run
         the full corpus differential via scripts/riscv_trace_vectors.py,
         and require the fresh attestation to re-derive the committed
         evidence on every field except the two build-nondeterministic
         binary hashes.

Exit codes: 0 pass; 1 pin/binding/differential/staleness failure;
3 the pinned toolchain is unavailable and the differential DID NOT RUN.
Both nonzero codes are red in CI -- 3 exists so a local caller can
distinguish "build the workspace" from "investigate a divergence".

`preflight` and `run` write machine-readable receipts to --github-output
(toolchain_health, cache_state, differential_ran, toolchain_state). The
workflow's verdict job requires those receipts, so a live job cannot report
success with its gate steps skipped: an unwritten receipt is empty and empty
is red.

  python3 scripts/riscv_sail_gate.py bind
  python3 scripts/riscv_sail_gate.py scope --base <sha> --head <sha>
  python3 scripts/riscv_sail_gate.py preflight --workspace /tmp/stwo-riscv-formal
  python3 scripts/riscv_sail_gate.py run --workspace /tmp/stwo-riscv-formal
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any, Iterable

if __package__:
    from scripts import check_upstream_pins
    from scripts import ci_scope_plan
    from scripts import riscv_equivalence as equivalence
    from scripts import riscv_formal_tools as formal_tools
    from scripts import riscv_trace_vectors as trace_vectors
else:  # direct execution: python3 scripts/riscv_sail_gate.py
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import check_upstream_pins
    import ci_scope_plan
    import riscv_equivalence as equivalence
    import riscv_formal_tools as formal_tools
    import riscv_trace_vectors as trace_vectors


ROOT = Path(__file__).resolve().parent.parent
EVIDENCE_PATH = Path("conformance") / "riscv" / "formal-corpus-evidence.json"
MANIFEST_PATH = Path("vectors") / "riscv_elfs" / "trace_vectors.json"
GATE_REPORT_SCHEMA = "stwo-riscv-sail-gate-report-v1"

EXIT_PASS = 0
EXIT_FAIL = 1
EXIT_TOOLCHAIN_UNAVAILABLE = 3

# Same resolution chain as scripts/riscv_sail_oracle.py: one documented
# workspace for every Sail consumer, overridable by one environment variable.
ENV_WORKSPACE = "STWO_RISCV_FORMAL_WORKSPACE"
DEFAULT_WORKSPACE = Path("/tmp/stwo-riscv-formal")

# The pinned Sail compiler shells out to an SMT solver for its constraint
# checks, so without one even `sail --version` dies with "SMT solver returned
# unexpected status 127". Naming the dependency in the preflight is the
# difference between a five-minute diagnosis and an afternoon inside Sail.
SMT_SOLVER = "z3"

# Changes here must re-run the live differential because they alter what the
# committed attestation means: the corpus, the pins, the comparator, the
# toolchain recipe, or this gate. Runner/ISA sources are included as
# belt-and-braces even though a semantic runner change cannot land silently:
# it moves trace digests, which fails the riscv_cpu parity lane until the
# fixtures are regenerated, which changes vectors/riscv_elfs/ and lands here
# anyway. Documentation-only paths never appear because every prefix below is
# an executable or machine-read artifact.
LIVE_TRIGGER_PREFIXES = (
    ".github/workflows/riscv-sail-differential.yml",
    "conformance/riscv",
    "conformance/upstream.md",
    "scripts/riscv_equivalence.py",
    "scripts/riscv_formal_tools.py",
    "scripts/riscv_sail_gate.py",
    "scripts/riscv_trace_vectors.py",
    "scripts/riscv_trace_vectors_lib",
    "src/frontends/riscv/isa",
    "src/frontends/riscv/runner",
    "vectors/riscv_elfs",
)

# The only evidence fields a fresh run may legitimately change: sail_riscv_sim
# and spike builds are not bit-reproducible (measured, 2026-07-26), so binary
# identity is established by pinned source revision plus --build-info, both of
# which ARE compared. Everything else must re-derive exactly.
VOLATILE_EVIDENCE_FIELDS = frozenset(
    {("sail", "binary_sha256"), ("spike", "binary_sha256")}
)

_SHA256_RE = re.compile(r"[0-9a-f]{64}")


def _load_json(path: Path, errors: list[str]) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        errors.append(f"{path}: unreadable: {error}")
        return None
    if not isinstance(value, dict):
        errors.append(f"{path}: root must be an object")
        return None
    return value


def bind_errors(root: Path = ROOT) -> list[str]:
    """Require the committed evidence to bind to the committed corpus and pins.

    This is the no-toolchain half of the gate. It cannot re-derive truth --
    only the live run consults Sail -- but it makes the snapshot impossible to
    leave stale: the comparison digest commits to every program's trace
    SHA-256, so any corpus or pin movement without regenerated live evidence
    fails here, on every PR. `root` is parameterized for tamper tests only;
    the module constants under scripts/ stay authoritative for the pins.
    """
    errors: list[str] = []
    evidence = _load_json(root / EVIDENCE_PATH, errors)
    manifest = _load_json(root / MANIFEST_PATH, errors)
    if evidence is None or manifest is None:
        return errors

    expected_scalars = {
        "schema": "stwo-riscv-formal-corpus-evidence-v1",
        "profile": equivalence.PROFILE,
        "result": "equivalent",
        "semantic_authority": "Sail",
        "independent_cross_check": "Spike",
        "comparison_fields": list(trace_vectors.SAIL_COMPARISON_FIELDS),
        "spike_comparison_fields": list(trace_vectors.SPIKE_COMPARISON_FIELDS),
    }
    for field, expected in expected_scalars.items():
        if evidence.get(field) != expected:
            errors.append(
                f"evidence {field} is {evidence.get(field)!r}, expected {expected!r}"
            )

    # check_upstream_pins ties these constants to the ledger, the formal
    # profile, and authority.zig; binding the evidence to the same constants
    # closes the ring without a second profile parser.
    expected_identity = {
        "sail": {
            "repository_revision": equivalence.PINNED_SAIL_REVISION,
            "model_tag": equivalence.PINNED_SAIL_TAG,
            "compiler_version": equivalence.PINNED_SAIL_COMPILER_VERSION,
            "transport_patch_sha256": equivalence.PINNED_RVFI_TRANSPORT_PATCH_SHA256,
        },
        "spike": {
            "repository_revision": equivalence.PINNED_SPIKE_REVISION,
            "banner": equivalence.PINNED_SPIKE_BANNER,
        },
    }
    for tool, expected_fields in expected_identity.items():
        identity = evidence.get(tool)
        if not isinstance(identity, dict):
            errors.append(f"evidence {tool} identity is missing")
            continue
        for field, expected in expected_fields.items():
            if identity.get(field) != expected:
                errors.append(
                    f"evidence {tool}.{field} is {identity.get(field)!r}, "
                    f"expected {expected!r}"
                )
        recorded_hash = identity.get("binary_sha256")
        if not isinstance(recorded_hash, str) or not _SHA256_RE.fullmatch(recorded_hash):
            errors.append(f"evidence {tool}.binary_sha256 is not a SHA-256")

    patch = root / "conformance" / "riscv" / "sail-rvfi-zkvm-entry.patch"
    try:
        patch_sha256 = hashlib.sha256(patch.read_bytes()).hexdigest()
    except OSError as error:
        errors.append(f"{patch}: unreadable: {error}")
    else:
        if patch_sha256 != equivalence.PINNED_RVFI_TRANSPORT_PATCH_SHA256:
            errors.append(
                f"{patch}: SHA-256 is {patch_sha256}, the pinned transport "
                f"patch is {equivalence.PINNED_RVFI_TRANSPORT_PATCH_SHA256}"
            )

    errors.extend(_corpus_binding_errors(evidence, manifest))
    return errors


def _corpus_binding_errors(
    evidence: dict[str, Any], manifest: dict[str, Any]
) -> list[str]:
    vectors = manifest.get("vectors")
    if not isinstance(vectors, list) or not all(
        isinstance(vector, dict) for vector in vectors
    ):
        return ["corpus manifest vectors are malformed"]
    errors: list[str] = []
    try:
        compared = [
            {
                "name": vector["name"],
                "retirements": vector["total_steps"],
                "trace_sha256": vector["trace_sha256"],
            }
            for vector in vectors
        ]
    except KeyError as error:
        return [f"corpus manifest vector is missing field {error}"]
    expected_counts = {
        "programs": len(vectors),
        "retirements": sum(vector["total_steps"] for vector in vectors),
        "negative_decode_and_trap_cases": len(
            trace_vectors.FORMAL_WORD_DISPOSITIONS
        ),
        "comparison_digest": trace_vectors.comparison_digest(compared),
    }
    for field, expected in expected_counts.items():
        if evidence.get(field) != expected:
            errors.append(
                f"evidence {field} is {evidence.get(field)!r}, expected "
                f"{expected!r} from the committed corpus manifest; the live "
                "differential must be re-run and the evidence regenerated"
            )
    return errors


def evidence_drift(
    fresh: dict[str, Any], committed: dict[str, Any]
) -> list[str]:
    """Fields where a fresh attestation fails to re-derive the committed one."""
    errors: list[str] = []
    for field in sorted(set(fresh) | set(committed)):
        fresh_value = fresh.get(field)
        committed_value = committed.get(field)
        if isinstance(fresh_value, dict) and isinstance(committed_value, dict):
            for sub in sorted(set(fresh_value) | set(committed_value)):
                if (field, sub) in VOLATILE_EVIDENCE_FIELDS:
                    continue
                if fresh_value.get(sub) != committed_value.get(sub):
                    errors.append(
                        f"{field}.{sub}: fresh={fresh_value.get(sub)!r} "
                        f"committed={committed_value.get(sub)!r}"
                    )
        elif fresh_value != committed_value:
            errors.append(
                f"{field}: fresh={fresh_value!r} committed={committed_value!r}"
            )
    return errors


def live_scope(changed_paths: Iterable[str]) -> tuple[bool, dict[str, str]]:
    """Map changed paths onto the live-differential trigger policy."""
    matched: dict[str, str] = {}
    for raw in changed_paths:
        path = ci_scope_plan.normalize_path(raw)
        for prefix in LIVE_TRIGGER_PREFIXES:
            if ci_scope_plan.owns(path, prefix):
                matched[path] = prefix
                break
    return bool(matched), matched


def _fail(errors: list[str], stage: str) -> int:
    for error in errors:
        print(f"riscv sail gate: {stage}: {error}", file=sys.stderr)
    return EXIT_FAIL


def _write_receipts(github_output: Path | None, receipts: dict[str, str]) -> None:
    """Append the step receipts the workflow requires before calling a run green."""
    if github_output is None:
        return
    with github_output.open("a", encoding="utf-8") as stream:
        for key, value in receipts.items():
            stream.write(f"{key}={value}\n")


def workspace_state(
    workspace: Path,
    profile: formal_tools.FormalProfile | None,
    compiler: Path | None,
) -> str:
    """warm (verifies), cold (never built), corrupt (present, unusable)."""
    if profile is None or compiler is None:
        return "unknown"
    paths = formal_tools.ToolPaths(workspace.expanduser().resolve())
    if not paths.sail_binary.exists() and not paths.spike_binary.exists():
        return "cold"
    try:
        formal_tools.verify(paths, profile, compiler)
    except (formal_tools.FormalToolsError, OSError):
        return "corrupt"
    return "warm"


def preflight(
    workspace: Path,
    sail_compiler: Path | None,
    cache_hit: bool,
    github_output: Path | None,
) -> int:
    """Assert the pinned toolchain is functional here, warm cache or cold.

    `run` already refuses to pass without consulting Sail, but everything it
    consults is provisioned by steps a warm cache can bypass, and a
    provisioning fault that lands mid-job reads as "the differential step did
    not run" -- indistinguishable, in a summary line, from a gate that was
    legitimately not selected. This runs unconditionally and exercises the
    pinned compiler itself, so a broken toolchain is red on the warm path
    too, naming the dependency that is absent. A cold or corrupt workspace is
    NOT a failure here: `run --prepare-on-miss` rebuilds it from pins and the
    differential still runs, which is the outcome this gate wants.
    """
    errors: list[str] = []
    proven: list[str] = []

    solver = shutil.which(SMT_SOLVER)
    if solver is None:
        errors.append(
            f"the pinned Sail compiler requires the {SMT_SOLVER} SMT solver; "
            "without it even `sail --version` dies with 'SMT solver returned "
            f"unexpected status 127 / {SMT_SOLVER}: not found'"
        )
    else:
        proven.append(f"{SMT_SOLVER} at {solver}")

    profile = None
    compiler = None
    try:
        profile = formal_tools.load_profile()
    except (formal_tools.FormalToolsError, OSError) as error:
        errors.append(f"the pinned formal profile is unusable: {error}")
    else:
        try:
            compiler = formal_tools.resolve_sail_compiler(
                sail_compiler, profile.sail_compiler
            )
        except (formal_tools.FormalToolsError, OSError) as error:
            errors.append(
                f"the pinned Sail compiler {profile.sail_compiler} does not "
                f"run on this host: {error}"
            )
        else:
            proven.append(f"Sail {profile.sail_compiler} at {compiler}")

    try:
        proven.append(f"dtc at {formal_tools.require_device_tree_compiler()}")
    except (formal_tools.FormalToolsError, OSError) as error:
        errors.append(str(error))

    if errors:
        for error in errors:
            print(f"riscv sail gate: toolchain preflight: {error}", file=sys.stderr)
        print(
            "riscv sail gate: PINNED TOOLCHAIN NOT FUNCTIONAL -- the "
            "differential cannot run on this host; this is a provisioning "
            "fault, not a Sail disagreement, and no receipt was written",
            file=sys.stderr,
        )
        return EXIT_TOOLCHAIN_UNAVAILABLE

    state = workspace_state(workspace, profile, compiler)
    if cache_hit and state != "warm":
        print(
            f"riscv sail gate: the restored toolchain cache is {state}; the "
            "gate rebuilds it from pins, and the run stays red if that "
            "rebuild fails",
            file=sys.stderr,
        )
    print(
        f"riscv sail gate: toolchain preflight PASS -- {', '.join(proven)}; "
        f"workspace {workspace} is {state}"
    )
    _write_receipts(
        github_output, {"toolchain_health": "functional", "cache_state": state}
    )
    return EXIT_PASS


def run_gate(
    workspace: Path,
    sail_compiler: Path | None,
    prepare_on_miss: bool,
    jobs: int,
    trace_dump_bin: Path | None,
    report_out: Path | None,
    github_output: Path | None = None,
) -> int:
    """Verified pinned toolchain, full live differential, evidence re-derived."""
    pin_errors = check_upstream_pins.validate_repository(ROOT)
    if pin_errors:
        return _fail(pin_errors, "pin drift")
    binding_errors = bind_errors(ROOT)
    if binding_errors:
        return _fail(binding_errors, "evidence binding")

    committed = json.loads((ROOT / EVIDENCE_PATH).read_text(encoding="utf-8"))
    try:
        profile = formal_tools.load_profile()
        compiler = formal_tools.resolve_sail_compiler(
            sail_compiler, profile.sail_compiler
        )
        paths = formal_tools.ToolPaths(workspace.expanduser().resolve())
        try:
            receipt = formal_tools.verify(paths, profile, compiler)
            toolchain_state = "verified"
        except formal_tools.FormalToolsError as error:
            if not prepare_on_miss:
                raise
            print(
                f"riscv sail gate: workspace failed verification ({error}); "
                "rebuilding it from pins because --prepare-on-miss is set",
                file=sys.stderr,
            )
            receipt = formal_tools.prepare(
                paths, profile, compiler, jobs, download_gmp=True
            )
            toolchain_state = "rebuilt"
    except (formal_tools.FormalToolsError, OSError) as error:
        # The single worst outcome would be reading this as coverage: say
        # precisely what was NOT checked and exit with the unavailability code.
        # The receipt says the same thing to the workflow, whose save step
        # must not publish this half-built workspace into the toolchain cache.
        _write_receipts(
            github_output,
            {"differential_ran": "false", "toolchain_state": "unavailable"},
        )
        print(
            f"riscv sail gate: SAIL TOOLCHAIN UNAVAILABLE -- the differential "
            f"did NOT run; {committed['programs']} programs / "
            f"{committed['retirements']} retirements were NOT re-checked "
            f"against pinned Sail/Spike: {error}",
            file=sys.stderr,
        )
        print(
            f"riscv sail gate: build the workspace with: python3 "
            f"scripts/riscv_formal_tools.py prepare --workspace {workspace}",
            file=sys.stderr,
        )
        return EXIT_TOOLCHAIN_UNAVAILABLE

    # The workspace is usable from here on, which is what the workflow's save
    # step keys on: a red differential should still warm the next run's cache,
    # a toolchain that never came up should not.
    _write_receipts(github_output, {"toolchain_state": toolchain_state})

    with tempfile.TemporaryDirectory() as scratch:
        fresh_path = Path(scratch) / "fresh-evidence.json"
        returncode = trace_vectors.gate(
            Path(scratch),
            sail_bin=paths.sail_binary,
            spike_bin=paths.spike_binary,
            formal_report=fresh_path,
            trace_dump_bin=trace_dump_bin,
        )
        # Sail was consulted on the full corpus. Record that before judging
        # the outcome: a disagreement is a run that happened and said no,
        # which is exactly the case the verdict must not confuse with a gate
        # that never executed.
        _write_receipts(github_output, {"differential_ran": "true"})
        if returncode != 0:
            print(
                "riscv sail gate: live differential FAILED (see errors above)",
                file=sys.stderr,
            )
            return EXIT_FAIL
        fresh = json.loads(fresh_path.read_text(encoding="utf-8"))

    drift = evidence_drift(fresh, committed)
    if drift:
        drift.append(
            f"the live differential passed but {EVIDENCE_PATH} does not "
            "describe it; regenerate the committed evidence from this exact "
            "corpus (riscv_trace_vectors.py --formal-report) and re-review"
        )
        return _fail(drift, "stale committed evidence")

    if report_out is not None:
        report_out.parent.mkdir(parents=True, exist_ok=True)
        report_out.write_text(
            json.dumps(
                {
                    "schema": GATE_REPORT_SCHEMA,
                    "result": "pass",
                    "toolchain": receipt,
                    "fresh_evidence": fresh,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
    print(
        f"riscv sail gate: PASS -- {fresh['programs']} programs, "
        f"{fresh['retirements']} retirements re-derived the committed "
        f"attestation against Sail {equivalence.PINNED_SAIL_TAG} "
        f"(compiler {equivalence.PINNED_SAIL_COMPILER_VERSION}) and pinned Spike"
    )
    return EXIT_PASS


def _cmd_scope(args: argparse.Namespace) -> int:
    if args.force_live:
        required, matched = True, {"(forced)": "--force-live"}
    else:
        if args.base is None:
            raise ci_scope_plan.PlanError("scope requires --base or --force-live")
        changed = args.changed_file or ci_scope_plan.git_changed_paths(
            ROOT, args.base, args.head
        )
        required, matched = live_scope(changed)
    print(
        json.dumps(
            {"live_required": required, "matched": matched},
            indent=2,
            sort_keys=True,
        )
    )
    _write_receipts(
        args.github_output, {"live_required": "true" if required else "false"}
    )
    return EXIT_PASS


def _add_workspace_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--workspace",
        type=Path,
        default=Path(os.environ.get(ENV_WORKSPACE, "") or DEFAULT_WORKSPACE),
        help="riscv_formal_tools.py workspace (default: "
        f"${ENV_WORKSPACE} or {DEFAULT_WORKSPACE})",
    )
    parser.add_argument("--sail-compiler", type=Path)
    parser.add_argument("--github-output", type=Path)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("bind", help="committed evidence must bind to corpus and pins")
    scope = sub.add_parser("scope", help="does this diff require the live gate?")
    scope.add_argument("--base")
    scope.add_argument("--head", default="HEAD")
    scope.add_argument("--changed-file", action="append", default=[])
    scope.add_argument("--force-live", action="store_true")
    scope.add_argument("--github-output", type=Path)
    check = sub.add_parser(
        "preflight", help="the pinned toolchain must be functional on this host"
    )
    _add_workspace_arguments(check)
    check.add_argument(
        "--cache-hit",
        default="",
        help="the runner's cache-hit output; 'true' means a restored "
        "workspace that fails verification is a corrupt cache, not a cold one",
    )
    run = sub.add_parser("run", help="live pinned Sail/Spike differential")
    _add_workspace_arguments(run)
    run.add_argument(
        "--prepare-on-miss",
        action="store_true",
        help="build the pinned toolchain when workspace verification fails",
    )
    run.add_argument("--jobs", type=int, default=max(1, os.cpu_count() or 1))
    run.add_argument(
        "--trace-dump-bin",
        type=Path,
        help="prebuilt riscv-trace-dump for local runs that must not `zig build`",
    )
    run.add_argument("--report-out", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "bind":
            errors = bind_errors()
            if errors:
                return _fail(errors, "evidence binding")
            print(
                "riscv sail gate: committed evidence binds to the committed "
                "corpus and pins"
            )
            return EXIT_PASS
        if args.command == "scope":
            return _cmd_scope(args)
        if args.command == "preflight":
            return preflight(
                args.workspace,
                args.sail_compiler,
                args.cache_hit == "true",
                args.github_output,
            )
        return run_gate(
            args.workspace,
            args.sail_compiler,
            args.prepare_on_miss,
            args.jobs,
            args.trace_dump_bin,
            args.report_out,
            args.github_output,
        )
    except (ci_scope_plan.PlanError, OSError, json.JSONDecodeError) as error:
        print(f"riscv sail gate: {error}", file=sys.stderr)
        return EXIT_FAIL


if __name__ == "__main__":
    raise SystemExit(main())
