#!/usr/bin/env python3
"""Run the Team B repin-and-regenerate cycle in the only correct order.

Every proof wave changes the audited theorem count, which drifts
``generated-manifest.json`` and, behind it, the refinement receipt. The
recovery sequence has historically lived in operator memory, and remembering
it wrong has produced a stale manifest behind a fresh pin and a stale receipt
behind both. This command owns that sequence and refuses to continue past a
failing step:

1. ``lake build`` -- the audit must see the current Lean environment.
2. ``riscv_refinement.py audited-theorems --write`` -- repin from the live
   axiom audit.
3. ``riscv_refinement.py generate --reuse-committed-sail-evidence
   --no-export-air --air-ir-dir <dir>`` -- rebuild the generated artifacts.
4. ``riscv_refinement.py check-generated ...`` -- the rebuild must be
   byte-identical when repeated.
5. ``riscv_team_b.py check`` and ``riscv_team_b_witnesses.py`` -- the Team B
   gates must accept the refreshed state.
6. A summary: theorem count before/after, which artifacts changed, coverage.

The default mode is a dry run that reports what would change and writes
nothing; regeneration requires an explicit ``--write``. Staged Git changes
refuse the run outright in either mode: a half-staged regeneration is exactly
how the manifest and receipt have gone out of step before.

The AIR IR directory is an input, exported beforehand with::

    zig build riscv-refinement-ir -Driscv-refinement-ir-dir=zig-out/team-b-ir

Examples::

    python3 scripts/riscv_team_b_refresh.py            # dry-run drift report
    python3 scripts/riscv_team_b_refresh.py --write    # refresh for real
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

if __package__:
    from .riscv_refinement_lib import audited_inventory
    from .riscv_refinement_lib.model import RefinementError
else:
    from riscv_refinement_lib import audited_inventory
    from riscv_refinement_lib.model import RefinementError

ROOT = Path(__file__).resolve().parents[1]
FORMAL_DIR = ROOT / "formal" / "riscv-refinement"
PIN_RELATIVE = Path("scripts/riscv_refinement_lib/audited_inventory.py")
PIN_FILE = ROOT / PIN_RELATIVE
COVERAGE_INDEX = FORMAL_DIR / "team-b-coverage.json"
GENERATED_AIR_DIR = FORMAL_DIR / "generated" / "air"
DEFAULT_AIR_IR_DIR = Path("zig-out") / "team-b-ir"

# Everything this cycle may rewrite, plus the receipt, which it never writes:
# a regeneration leaves the receipt stale behind the new manifest, and that
# staleness must be visible in the summary rather than silently carried.
WATCHED_ARTIFACTS = (
    PIN_RELATIVE.as_posix(),
    "formal/riscv-refinement/generated-manifest.json",
    "formal/riscv-refinement/refinement-receipt.json",
    "formal/riscv-refinement/RiscvRefinement/Air/Generated/Pilot.lean",
    "formal/riscv-refinement/RiscvRefinement/Sail/Generated/Pilot.lean",
)


class RefreshError(RuntimeError):
    """The refresh cycle refused to start, or one of its steps failed."""


def _execute(command: tuple[str, ...], cwd: Path) -> tuple[int, str]:
    """Sole subprocess boundary; tests replace this function."""
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError as error:
        raise RefreshError(
            f"{' '.join(command)} could not start: {error}"
        ) from error
    return completed.returncode, (completed.stdout + completed.stderr).strip()


def _run(command: tuple[str, ...], cwd: Path) -> str:
    status, output = _execute(command, cwd)
    if status != 0:
        raise RefreshError(
            f"step failed with exit status {status}, so the remaining "
            f"steps were not run: {' '.join(command)}\n{output}"
        )
    return output


def _refinement_command(*arguments: str) -> tuple[str, ...]:
    return (sys.executable, "scripts/riscv_refinement.py", *arguments)


def _generation_arguments(air_ir_dir: Path) -> tuple[str, ...]:
    return (
        "--reuse-committed-sail-evidence",
        "--no-export-air",
        "--air-ir-dir",
        str(air_ir_dir),
    )


def _refuse_staged_changes() -> None:
    status, output = _execute(
        ("git", "diff", "--cached", "--name-only"), ROOT
    )
    if status != 0:
        raise RefreshError(f"could not read the Git index: {output}")
    if output:
        raise RefreshError(
            "the Git index has staged changes; a half-staged regeneration "
            "is how the manifest and receipt go out of step. Commit or "
            "unstage first: " + ", ".join(output.splitlines())
        )


def _require_air_export(directory: Path) -> None:
    if not directory.is_dir() or not any(directory.glob("*.json")):
        raise RefreshError(
            f"{directory}: no exported AIR IR; run 'zig build "
            f"riscv-refinement-ir -Driscv-refinement-ir-dir={directory}' "
            "first"
        )


def pinned_theorem_count(pin_file: Path = PIN_FILE) -> int:
    try:
        text = pin_file.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise RefreshError(f"{pin_file}: unreadable pin file: {error}") from error
    try:
        theorems = audited_inventory.parse_source(text)
    except RefinementError as error:
        raise RefreshError(
            f"{pin_file}: the AUDITED_THEOREMS pin is not in its expected shape"
        ) from error
    return len(theorems)


def _artifact_digests() -> dict[str, str | None]:
    watched = [ROOT / relative for relative in WATCHED_ARTIFACTS]
    watched.extend(sorted(GENERATED_AIR_DIR.glob("*.json")))
    digests: dict[str, str | None] = {}
    for path in watched:
        key = path.relative_to(ROOT).as_posix()
        if path.is_file():
            digests[key] = hashlib.sha256(path.read_bytes()).hexdigest()
        else:
            digests[key] = None
    return digests


def _changed_artifacts(
    before: dict[str, str | None],
    after: dict[str, str | None],
) -> list[str]:
    names = sorted(set(before) | set(after))
    return [name for name in names if before.get(name) != after.get(name)]


def coverage_summary(index: Path = COVERAGE_INDEX) -> str:
    try:
        payload = json.loads(index.read_text(encoding="utf-8"))
        states = [
            (entry["mnemonic"], entry["state"])
            for entry in payload["certificates"]
        ]
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as error:
        raise RefreshError(
            f"{index}: unreadable coverage index: {error}"
        ) from error
    proved = [mnemonic for mnemonic, state in states if state == "proved"]
    unproved = sorted(
        mnemonic for mnemonic, state in states if state != "proved"
    )
    line = f"coverage: {len(proved)}/{len(states)} proved"
    if unproved:
        line += "; not proved: " + ", ".join(unproved)
    return line


def _detail(output: str) -> list[str]:
    return [
        f"  {line}" for line in output.splitlines()[-5:] if line.strip()
    ]


def refresh(air_ir_dir: Path, write: bool) -> list[str]:
    resolved = air_ir_dir if air_ir_dir.is_absolute() else ROOT / air_ir_dir
    _refuse_staged_changes()
    _require_air_export(resolved)
    before_count = pinned_theorem_count()
    if write:
        return _refresh_for_real(resolved, before_count)
    return _report_drift(resolved, before_count)


def _refresh_for_real(air_ir_dir: Path, before_count: int) -> list[str]:
    before = _artifact_digests()
    _run(("lake", "build"), FORMAL_DIR)
    _run(_refinement_command("audited-theorems", "--write"), ROOT)
    generation = _generation_arguments(air_ir_dir)
    _run(_refinement_command("generate", *generation), ROOT)
    _run(_refinement_command("check-generated", *generation), ROOT)
    _run(
        (
            sys.executable,
            "scripts/riscv_team_b.py",
            "check",
            "--air-ir-dir",
            str(air_ir_dir),
        ),
        ROOT,
    )
    _run(
        (
            sys.executable,
            "scripts/riscv_team_b_witnesses.py",
            "--air-ir-dir",
            str(air_ir_dir),
        ),
        ROOT,
    )
    after_count = pinned_theorem_count()
    changed = _changed_artifacts(before, _artifact_digests())
    return [
        f"audited theorems: {before_count} -> {after_count}",
        "changed artifacts: " + (", ".join(changed) if changed else "none"),
        coverage_summary(),
        "refresh complete: repin, regeneration, byte-identical check, and "
        "both Team B gates passed",
    ]


def _report_drift(air_ir_dir: Path, pinned_count: int) -> list[str]:
    _run(("lake", "build"), FORMAL_DIR)
    lines = ["dry run: nothing was written; pass --write to refresh"]
    status, output = _execute(_refinement_command("audited-theorems"), ROOT)
    if status == 0:
        lines.append(
            f"audited theorems: pinned exactly at {pinned_count}; "
            "--write would keep the pin"
        )
    else:
        lines.append(
            f"audited theorems: the {pinned_count}-theorem pin differs "
            "from the live audit; --write would repin"
        )
        lines.extend(_detail(output))
    status, output = _execute(
        _refinement_command(
            "check-generated", *_generation_arguments(air_ir_dir)
        ),
        ROOT,
    )
    if status == 0:
        lines.append(
            "generated artifacts: byte-identical; --write would keep them"
        )
    else:
        lines.append(
            "generated artifacts: drifted; --write would regenerate them"
        )
        lines.extend(_detail(output))
    lines.append(coverage_summary())
    return lines


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--write",
        action="store_true",
        help="run the refresh for real; without it only drift is reported",
    )
    mode.add_argument(
        "--dry-run",
        action="store_true",
        help="report what would change without writing (the default)",
    )
    parser.add_argument(
        "--air-ir-dir",
        type=Path,
        default=DEFAULT_AIR_IR_DIR,
        help="already exported AIR IR directory (see the module docstring)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        lines = refresh(args.air_ir_dir, write=args.write)
    except RefreshError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    for line in lines:
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
