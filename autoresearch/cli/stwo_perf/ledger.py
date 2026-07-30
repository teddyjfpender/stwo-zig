"""Append-only promotions ledger: parse, validate, append, and query."""

from __future__ import annotations

import copy
import json
import hashlib
import math
import re
from dataclasses import dataclass
from pathlib import Path

SCHEMA_VERSION = 3

# v1 column set — frozen forever as the file header (the file is append-only,
# so the header can never change; later versions extend rows, not the header).
COLUMNS = [
    "schema_version", "harness_commit", "epoch", "judged_at_utc", "commit",
    "scope", "board", "workload_class", "outcome", "judged_r", "ci_low",
    "ci_high", "prove_ms", "native_mhz", "peak_rss_mib", "waits", "dispatches",
    "energy_j", "gates", "holdout", "submission_id", "predecessor", "supersedes",
]

# v2 appends verdict_kind: `judged` (signed judge verdict) or `claimed`
# (maintainer-adjudicated optimistic promotion; superseded by a judged row).
COLUMNS_V2 = COLUMNS + ["verdict_kind"]

# v3 gives every physical row and logical observation an unambiguous identity.
# Aggregate evidence names the observations it covers and the active credit
# events it replaces; the header remains the immutable v1 header.
COLUMNS_V3 = COLUMNS_V2 + [
    "row_id", "observation_id", "evidence_kind", "covers",
    "credit_replaces", "evidence_sha256", "proof_bytes",
    "measurement_seconds", "measurement_rounds",
]

_COLUMNS_BY_VERSION = {1: COLUMNS, 2: COLUMNS_V2, 3: COLUMNS_V3}

VERDICT_KINDS = ("judged", "claimed")
EVIDENCE_KINDS = ("promotion", "span_audit", "direct_audit")

OUTCOMES = ("promoted", "neutral", "rejected")

# Scoring boards (schema/scoring.md). Kernel results never enter the ledger.
#
# APPEND ONLY. Removing a name silently drops its history from the site feed
# (TRACKS §6), so retired boards keep their entry forever. Campaign v3 (TRACKS
# §2, §3.4, §8) appends the wave-1 Cairo tracks plus the pr6_supremacy
# objective board, which must be registered here before it can ever write a
# row — objective boards that are absent from BOARDS are the current gap
# TRACKS §3.4 names explicitly.
BOARDS = (
    "core_cpu", "core_hybrid", "core_metal", "core_cuda",
    "heavy_native", "heavy_cairo", "stream", "riscv",
    "cairo_cpu", "cairo_metal", "pr6_supremacy",
)

_FLOAT_COLS = {"judged_r", "ci_low", "ci_high", "prove_ms", "native_mhz", "peak_rss_mib"}
_OPT_FLOAT_COLS = {"waits", "dispatches", "energy_j"}
_LIST_COLS = {"covers", "credit_replaces"}
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class LedgerError(RuntimeError):
    pass


@dataclass
class Row:
    values: dict
    physical_index: int = 0
    raw_line: str = ""
    supersedes_row_id: str = ""

    def __getattr__(self, name: str):
        try:
            return self.values[name]
        except KeyError as exc:
            raise AttributeError(name) from exc

    @property
    def gates_passed(self) -> bool:
        return self.values["gates"] == "G1..G5:pass"

    @property
    def is_legacy(self) -> bool:
        return self.values["schema_version"] < 3


def ledger_path(repo_root: Path) -> Path:
    return repo_root / "autoresearch" / "ledger" / "promotions.tsv"


def epochs_path(repo_root: Path) -> Path:
    return repo_root / "autoresearch" / "ledger" / "epochs.json"


def _sha256(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _legacy_row_id(physical_index: int, raw_line: str) -> str:
    payload = (
        b"stwo-zig-ledger-legacy-row-v1\0"
        + str(physical_index).encode("ascii") + b"\0"
        + raw_line.encode("utf-8")
    )
    return _sha256(payload)


def observation_id(submission_id: str, board: str, workload_class: str) -> str:
    payload = json.dumps(
        [submission_id, board, workload_class],
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("ascii")
    return _sha256(b"stwo-zig-ledger-observation-v1\0" + payload)


def evidence_sha256(payload: dict) -> str:
    """Digest a complete verdict object using its canonical JSON encoding."""
    canonical = json.dumps(
        payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("ascii")
    return _sha256(canonical)


def _canonical_cell(column: str, value) -> str:
    if value is None:
        return ""
    if column in _LIST_COLS:
        if isinstance(value, str):
            return value
        return json.dumps(list(value), ensure_ascii=True, separators=(",", ":"))
    if isinstance(value, float):
        return f"{value:.6f}"
    return str(value)


def compute_row_id(values: dict) -> str:
    """Digest the canonical v3 physical payload, excluding only ``row_id``."""
    payload = {
        column: _canonical_cell(column, values.get(column))
        for column in COLUMNS_V3 if column != "row_id"
    }
    canonical = json.dumps(
        payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("ascii")
    return _sha256(b"stwo-zig-ledger-row-v3\0" + canonical)


def _split_ids(cell: str, *, lineno: int, column: str) -> tuple[str, ...]:
    try:
        decoded = json.loads(cell)
    except json.JSONDecodeError as exc:
        raise LedgerError(
            f"line {lineno}: column {column} is not a compact JSON array"
        ) from exc
    if not isinstance(decoded, list) or any(not isinstance(item, str) for item in decoded):
        raise LedgerError(f"line {lineno}: column {column} must be a string array")
    canonical = json.dumps(decoded, ensure_ascii=True, separators=(",", ":"))
    if cell != canonical:
        raise LedgerError(f"line {lineno}: column {column} is not canonical JSON")
    values = tuple(decoded)
    if len(values) != len(set(values)):
        raise LedgerError(f"line {lineno}: column {column} contains duplicate IDs")
    for value in values:
        if not _SHA256_RE.fullmatch(value):
            raise LedgerError(
                f"line {lineno}: column {column} contains an invalid digest ID"
            )
    return values


def _validate_v3(values: dict, *, lineno: int) -> None:
    for column in ("row_id", "observation_id"):
        if not _SHA256_RE.fullmatch(values[column]):
            raise LedgerError(f"line {lineno}: column {column} is not a digest ID")
    expected_observation = observation_id(
        values["submission_id"], values["board"], values["workload_class"]
    )
    if values["observation_id"] != expected_observation:
        raise LedgerError(
            f"line {lineno}: observation_id does not match submission/board/class"
        )
    if values["evidence_kind"] not in EVIDENCE_KINDS:
        raise LedgerError(
            f"line {lineno}: evidence_kind must be one of {EVIDENCE_KINDS}"
        )
    if not _SHA256_RE.fullmatch(values["evidence_sha256"]):
        raise LedgerError(f"line {lineno}: evidence_sha256 is not canonical")
    kind = values["evidence_kind"]
    if kind == "promotion" and (values["covers"] or values["credit_replaces"]):
        raise LedgerError(f"line {lineno}: promotion cannot cover or replace evidence")
    if kind == "span_audit" and (
        not values["covers"] or values["credit_replaces"]
    ):
        raise LedgerError(
            f"line {lineno}: span_audit needs covers and cannot replace credit"
        )
    if kind == "direct_audit" and values["covers"]:
        raise LedgerError(f"line {lineno}: direct_audit cannot carry covers")
    if values["row_id"] != compute_row_id(values):
        raise LedgerError(f"line {lineno}: row_id does not match canonical row payload")


def parse(text: str) -> list[Row]:
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if not lines:
        raise LedgerError("ledger is empty (missing header)")
    header = lines[0].split("\t")
    if header != COLUMNS:
        raise LedgerError(
            "ledger header does not match schema v1; rows must be read per their "
            f"own schema_version (got {len(header)} columns)"
        )
    rows = []
    for physical_index, line in enumerate(lines[1:], start=1):
        lineno = physical_index + 1
        cells = line.split("\t")
        if not cells:
            raise LedgerError(f"line {lineno}: row is empty")
        try:
            version = int(cells[0])
        except (ValueError, IndexError) as exc:
            raise LedgerError(f"line {lineno}: schema_version is not an integer") from exc
        columns = _COLUMNS_BY_VERSION.get(version)
        if columns is None:
            raise LedgerError(f"line {lineno}: unknown schema_version {version}")
        if len(cells) != len(columns):
            raise LedgerError(
                f"line {lineno}: schema v{version} expects {len(columns)} columns, "
                f"got {len(cells)}"
            )
        values: dict = dict(zip(columns, cells))
        for col in _FLOAT_COLS:
            try:
                values[col] = float(values[col])
            except ValueError as exc:
                raise LedgerError(f"line {lineno}: column {col} is not a number") from exc
        for col in _OPT_FLOAT_COLS:
            values[col] = float(values[col]) if values[col] not in ("", "-") else None
        values["schema_version"] = version
        values["epoch"] = int(values["epoch"])
        if version == 1:
            # v1 predates the column; only the judge ever appended v1 rows.
            values["verdict_kind"] = "judged"
        elif values["verdict_kind"] not in VERDICT_KINDS:
            raise LedgerError(
                f"line {lineno}: verdict_kind must be one of {VERDICT_KINDS}"
            )
        if version < 3:
            row_id = _legacy_row_id(physical_index, line)
            values.update({
                "row_id": row_id,
                "observation_id": _sha256(
                    b"stwo-zig-ledger-legacy-observation-v1\0"
                    + row_id.encode("ascii")
                ),
                "evidence_kind": "promotion",
                "covers": (),
                "credit_replaces": (),
                "evidence_sha256": _sha256(line.encode("utf-8")),
                "proof_bytes": None,
                "measurement_seconds": None,
                "measurement_rounds": None,
            })
        else:
            proof_bytes_cell = values["proof_bytes"]
            try:
                values["proof_bytes"] = int(proof_bytes_cell)
            except ValueError as exc:
                raise LedgerError(
                    f"line {lineno}: proof_bytes is not a positive integer"
                ) from exc
            if (
                values["proof_bytes"] <= 0
                or proof_bytes_cell != str(values["proof_bytes"])
            ):
                raise LedgerError(
                    f"line {lineno}: proof_bytes is not a canonical positive integer"
                )
            measurement_cell = values["measurement_seconds"]
            try:
                values["measurement_seconds"] = float(measurement_cell)
            except ValueError as exc:
                raise LedgerError(
                    f"line {lineno}: measurement_seconds is not a positive number"
                ) from exc
            if (
                not math.isfinite(values["measurement_seconds"])
                or values["measurement_seconds"] <= 0
                or measurement_cell != f"{values['measurement_seconds']:.6f}"
            ):
                raise LedgerError(
                    f"line {lineno}: measurement_seconds is not canonical and positive"
                )
            rounds_cell = values["measurement_rounds"]
            try:
                values["measurement_rounds"] = int(rounds_cell)
            except ValueError as exc:
                raise LedgerError(
                    f"line {lineno}: measurement_rounds is not a positive integer"
                ) from exc
            if (
                values["measurement_rounds"] <= 0
                or rounds_cell != str(values["measurement_rounds"])
            ):
                raise LedgerError(
                    f"line {lineno}: measurement_rounds is not canonical and positive"
                )
            values["covers"] = _split_ids(
                values["covers"], lineno=lineno, column="covers"
            )
            values["credit_replaces"] = _split_ids(
                values["credit_replaces"], lineno=lineno, column="credit_replaces"
            )
            _validate_v3(values, lineno=lineno)
        rows.append(Row(values, physical_index, line))
    _prepare_corrections(rows)
    return rows


def _legacy_key(row: Row) -> str:
    return f"{row.judged_at_utc}+{row.commit}"


def _prepare_corrections(rows: list[Row]) -> None:
    """Validate later-only correction chains and attach canonical targets.

    Legacy ``judged_at+commit`` references are resolved inside the correction's
    epoch/board/class, where they are unambiguous. v3 references physical IDs.
    A correction may only replace the currently active physical row for its
    logical observation; this rejects forks and makes cycles impossible.
    """
    by_id: dict[str, Row] = {}
    active_by_observation: dict[str, Row] = {}
    legacy_by_key: dict[tuple[int, str, str, str], list[Row]] = {}
    seen_observations: set[str] = set()
    for row in rows:
        if row.row_id in by_id:
            raise LedgerError(f"duplicate row_id: {row.row_id}")
        target = None
        if row.supersedes:
            if row.schema_version >= 3:
                target = by_id.get(row.supersedes)
            else:
                candidates = legacy_by_key.get(
                    (row.epoch, row.board, row.workload_class, row.supersedes), []
                )
                if len(candidates) == 1:
                    target = candidates[0]
            if target is None:
                raise LedgerError(
                    f"row {row.row_id}: supersedes must name one earlier physical row"
                )
            if (target.epoch, target.board, target.workload_class) != (
                row.epoch, row.board, row.workload_class
            ):
                raise LedgerError(
                    f"row {row.row_id}: correction crosses epoch/board/class"
                )
            if row.schema_version < 3:
                row.values["observation_id"] = target.observation_id
            elif row.observation_id != target.observation_id:
                raise LedgerError(
                    f"row {row.row_id}: correction changed observation_id"
                )
            if active_by_observation.get(target.observation_id) is not target:
                raise LedgerError(
                    f"row {row.row_id}: correction target is no longer active"
                )
            active_by_observation.pop(target.observation_id)
        else:
            if row.observation_id in seen_observations:
                raise LedgerError(
                    f"row {row.row_id}: observation_id already exists without correction"
                )
            seen_observations.add(row.observation_id)
        row.supersedes_row_id = target.row_id if target else ""
        active_by_observation[row.observation_id] = row
        by_id[row.row_id] = row
        legacy_by_key.setdefault(
            (row.epoch, row.board, row.workload_class, _legacy_key(row)), []
        ).append(row)


def resolve_corrections(rows: list[Row]) -> list[Row]:
    """Return the exact active physical row for every logical observation."""
    _prepare_corrections(rows)
    retired = {row.supersedes_row_id for row in rows if row.supersedes_row_id}
    return [row for row in rows if row.row_id not in retired]


def load(repo_root: Path) -> list[Row]:
    return parse(ledger_path(repo_root).read_text())


def serialize_row(values: dict) -> str:
    try:
        columns = _COLUMNS_BY_VERSION[int(values["schema_version"])]
    except (KeyError, ValueError) as exc:
        raise LedgerError("row schema_version is missing or unknown") from exc
    cells = []
    for col in columns:
        v = values.get(col)
        if v is None:
            cells.append("")
        else:
            cells.append(_canonical_cell(col, v))
        if "\t" in cells[-1] or "\n" in cells[-1]:
            raise LedgerError(f"column {col} contains a separator character")
    return "\t".join(cells)


def append(repo_root: Path, values: dict) -> None:
    """Append one row after validating schema, epoch, and time ordering."""
    missing = [c for c in COLUMNS_V3 if c not in values]
    if missing:
        raise LedgerError(f"row missing columns: {missing}")
    if int(values["schema_version"]) != SCHEMA_VERSION:
        raise LedgerError("appends must use the current schema_version")
    if values.get("verdict_kind") not in VERDICT_KINDS:
        raise LedgerError(f"verdict_kind must be one of {VERDICT_KINDS}")
    if values.get("outcome") not in OUTCOMES:
        raise LedgerError(f"outcome must be one of {OUTCOMES}")
    if values.get("board") not in BOARDS:
        raise LedgerError(f"board must be one of {BOARDS}")
    epochs = known_epochs(repo_root)
    if int(values["epoch"]) not in epochs:
        raise LedgerError(f"unknown epoch {values['epoch']}; open it in epochs.json first")
    rows = load(repo_root)
    if rows and str(values["judged_at_utc"]) < str(rows[-1].judged_at_utc):
        raise LedgerError("judged_at_utc must be monotonically non-decreasing")
    serialized = serialize_row(values)
    current = ledger_path(repo_root).read_text()
    parse(current + serialized + "\n")
    with ledger_path(repo_root).open("a") as fh:
        fh.write(serialized + "\n")


def verify_append_only(base_text: str, head_text: str) -> None:
    """CI check: head must equal base plus zero or more appended rows."""
    if not head_text.startswith(base_text):
        raise LedgerError(
            "ledger is not append-only versus the base revision: existing rows "
            "were edited, reordered, or removed"
        )
    parse(head_text)


def known_epochs(repo_root: Path) -> dict[int, dict]:
    data = json.loads(epochs_path(repo_root).read_text())
    return {int(e["epoch"]): e for e in data["epochs"]}


# --- TRACKS §7 per-board eras -------------------------------------------------
#
# Global epochs stay authoritative and unchanged; a board may additionally own
# an era sequence in ``board_eras.boards``. Every resolver below falls back to
# the newest global epoch when a board declares no eras, so absent per-board
# data reproduces the pre-era behaviour exactly.

ERA_STATUSES = ("open", "banked")

# The scored boundary a board's era declares. ``prove_ms`` is today's behaviour
# everywhere; ``request_ms`` is the TRACKS §3.1 verified-request boundary that
# the RISC-V board adopts at its next era. Declaring it is gated on that era
# carrying its own recalibrated A/A dispersion (see ``_validate_era``).
SCORED_DIMENSIONS = ("prove_ms", "request_ms")
DEFAULT_SCORED_DIMENSION = "prove_ms"

RESOURCE_BUDGET_DIMENSIONS = ("peak_rss_mib", "energy_j", "proof_bytes")

_ERA_REQUIRED_KEYS = ("era", "epoch_ref", "opened_utc", "reason")
_ERA_KNOWN_KEYS = {
    *_ERA_REQUIRED_KEYS,
    "status", "closed_utc", "audit_anchor_commit", "aa_dispersion",
    "resource_budgets", "scored_dimension", "note",
}
_UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_COMMIT40_RE = re.compile(r"^[0-9a-f]{40}$")


def _epochs_document(repo_root: Path) -> dict:
    document = json.loads(epochs_path(repo_root).read_text())
    if not isinstance(document, dict) or not isinstance(document.get("epochs"), list):
        raise LedgerError("epochs.json must declare a list of global epochs")
    return document


def _era_block(document: dict) -> dict[str, list]:
    """Return the validated ``board -> era list`` map (``{}`` when absent)."""
    block = document.get("board_eras")
    if block is None:
        return {}
    if not isinstance(block, dict) or not set(block) <= {"note", "boards"}:
        raise LedgerError(
            "epochs.json board_eras must be an object with only 'note' and 'boards'"
        )
    if "note" in block and not isinstance(block["note"], str):
        raise LedgerError("epochs.json board_eras.note must be a string")
    boards = block.get("boards")
    if boards is None:
        return {}
    if not isinstance(boards, dict):
        raise LedgerError("epochs.json board_eras.boards must be an object")
    return boards


def _positive_finite(value: object) -> bool:
    return (
        not isinstance(value, bool)
        and isinstance(value, (int, float))
        and math.isfinite(float(value))
        and float(value) > 0
    )


def _validate_era(board: str, era: dict, epochs: dict[int, dict]) -> dict:
    """Fail closed on one era record; never invent a missing field."""
    where = f"board era {board}/{era.get('era')!r}"
    if not isinstance(era, dict):
        raise LedgerError(f"board eras for {board} must be objects")
    unknown = sorted(set(era) - _ERA_KNOWN_KEYS)
    if unknown:
        raise LedgerError(f"{where}: unknown key(s) {unknown}")
    for key in _ERA_REQUIRED_KEYS:
        if key not in era:
            raise LedgerError(f"{where}: missing required key {key}")
    if type(era["era"]) is not int or era["era"] < 1:
        raise LedgerError(f"{where}: 'era' must be a positive integer")
    if type(era["epoch_ref"]) is not int or era["epoch_ref"] not in epochs:
        raise LedgerError(
            f"{where}: 'epoch_ref' must name a global epoch declared in epochs.json"
        )
    for key in ("opened_utc", "closed_utc"):
        value = era.get(key)
        if key == "closed_utc" and value is None:
            continue
        if not isinstance(value, str) or not _UTC_RE.fullmatch(value):
            raise LedgerError(f"{where}: '{key}' must be ISO-8601 UTC (…T…Z)")
    if era["opened_utc"] < str(epochs[era["epoch_ref"]].get("opened_utc") or ""):
        raise LedgerError(
            f"{where}: 'opened_utc' precedes the global epoch it inherits"
        )
    if not str(era.get("reason") or "").strip():
        raise LedgerError(f"{where}: 'reason' must be a non-empty string")
    status = era.get("status", "open")
    if status not in ERA_STATUSES:
        raise LedgerError(f"{where}: 'status' must be one of {ERA_STATUSES}")
    if status == "banked" and era.get("closed_utc") is None:
        raise LedgerError(f"{where}: a banked era must record 'closed_utc'")
    if status == "open" and era.get("closed_utc") is not None:
        raise LedgerError(f"{where}: an open era must not record 'closed_utc'")
    if era.get("closed_utc") is not None and era["closed_utc"] < era["opened_utc"]:
        raise LedgerError(f"{where}: 'closed_utc' precedes 'opened_utc'")
    anchor = era.get("audit_anchor_commit")
    if anchor is not None and (
        not isinstance(anchor, str) or not _COMMIT40_RE.fullmatch(anchor)
    ):
        raise LedgerError(
            f"{where}: 'audit_anchor_commit' must be a 40-hex commit"
        )
    dispersion = era.get("aa_dispersion")
    if dispersion is not None:
        if not isinstance(dispersion, dict) or not dispersion:
            raise LedgerError(f"{where}: 'aa_dispersion' must be a non-empty object")
        for name, value in dispersion.items():
            if value is not None and not _positive_finite(value):
                raise LedgerError(
                    f"{where}: aa_dispersion/{name} must be positive and finite, or null"
                )
    budgets = era.get("resource_budgets")
    if budgets is not None:
        if not isinstance(budgets, dict) or not budgets:
            raise LedgerError(
                f"{where}: 'resource_budgets' must be a non-empty object"
            )
        for name, vector in budgets.items():
            if not isinstance(vector, dict) or set(vector) != set(
                RESOURCE_BUDGET_DIMENSIONS
            ):
                raise LedgerError(
                    f"{where}: resource_budgets/{name} must contain exactly "
                    f"{sorted(RESOURCE_BUDGET_DIMENSIONS)}"
                )
            for dimension, value in vector.items():
                if not _positive_finite(value):
                    raise LedgerError(
                        f"{where}: resource_budgets/{name}/{dimension} must be "
                        "positive and finite"
                    )
    dimension = era.get("scored_dimension", DEFAULT_SCORED_DIMENSION)
    if dimension not in SCORED_DIMENSIONS:
        raise LedgerError(
            f"{where}: 'scored_dimension' must be one of {SCORED_DIMENSIONS}"
        )
    if dimension != DEFAULT_SCORED_DIMENSION and era.get("aa_dispersion") is None:
        # TRACKS §3.1/§7: a boundary switch invalidates the inherited A/A
        # dispersion, so the era that switches must carry its own measured
        # recalibration. Nothing may be inherited across a boundary change.
        raise LedgerError(
            f"{where}: an era that scores {dimension} must declare its own measured "
            "aa_dispersion; boundary switches never inherit calibration"
        )
    return era


def board_eras(repo_root: Path, board: str) -> tuple[dict, ...]:
    """Return one board's validated era sequence; empty when it declares none."""
    boards = _era_block(_epochs_document(repo_root))
    raw = boards.get(board)
    if raw is None:
        return ()
    if not isinstance(raw, list) or not raw:
        raise LedgerError(f"board eras for {board} must be a non-empty list")
    if board not in BOARDS:
        raise LedgerError(
            f"board eras name {board}, which is not a registered scoring board"
        )
    epochs = known_epochs(repo_root)
    eras = [_validate_era(board, era, epochs) for era in raw]
    if [era["era"] for era in eras] != list(range(1, len(eras) + 1)):
        raise LedgerError(
            f"board eras for {board} must be numbered 1..n in ascending order"
        )
    for previous, era in zip(eras, eras[1:]):
        if era["epoch_ref"] < previous["epoch_ref"]:
            raise LedgerError(
                f"board eras for {board}: epoch_ref must never decrease"
            )
        if era["opened_utc"] <= previous["opened_utc"]:
            raise LedgerError(
                f"board eras for {board}: opened_utc must strictly increase"
            )
        if previous.get("status", "open") != "banked":
            raise LedgerError(
                f"board eras for {board}: only the newest era may stay open"
            )
        if previous["closed_utc"] > era["opened_utc"]:
            raise LedgerError(
                f"board eras for {board}: era {previous['era']} closes after "
                f"era {era['era']} opens"
            )
    return tuple(eras)


def current_era(repo_root: Path, board: str) -> dict | None:
    """The board's newest era as a normalized view, banked or open.

    ``None`` when the board declares no era sequence. The view fills declared
    defaults (``status``, ``scored_dimension``) and always carries every key,
    so consumers never have to distinguish "absent" from "defaulted"; the raw
    override blocks stay available through :func:`board_eras`.
    """
    eras = board_eras(repo_root, board)
    return _era_view(eras[-1], board) if eras else None


def _era_view(era: dict, board: str) -> dict:
    return {
        "board": board,
        "era": int(era["era"]),
        "epoch_ref": int(era["epoch_ref"]),
        "opened_utc": era["opened_utc"],
        "reason": era["reason"],
        "status": era.get("status", "open"),
        "closed_utc": era.get("closed_utc"),
        "scored_dimension": era.get("scored_dimension", DEFAULT_SCORED_DIMENSION),
        "note": era.get("note"),
    }


def _apply_era(epochs: dict[int, dict], era: dict, board: str) -> dict:
    """Resolve one era into a complete, board-effective epoch specification."""
    reference = int(era["epoch_ref"])
    spec = copy.deepcopy(epochs[reference])
    anchor = era.get("audit_anchor_commit")
    overrides_metrics = anchor is not None or era.get("resource_budgets") is not None
    metrics_v2 = spec.get("metrics_v2")
    if overrides_metrics and not isinstance(metrics_v2, dict):
        raise LedgerError(
            f"board era {board}/{era['era']} overrides Metrics v2 policy but epoch "
            f"{reference} declares none"
        )
    if anchor is not None:
        metrics_v2["audit_anchor_commit"] = anchor
    budgets = era.get("resource_budgets")
    if budgets is not None:
        by_class = dict(metrics_v2.get("resource_budgets") or {})
        for name, vector in budgets.items():
            by_class[name] = dict(vector)
        metrics_v2["resource_budgets"] = by_class
    dispersion = era.get("aa_dispersion")
    if dispersion is not None:
        by_board = spec.setdefault("aa_dispersion", {})
        merged = dict(by_board.get(board) or {})
        merged.update(dispersion)
        by_board[board] = merged
    spec["scored_dimension"] = era.get("scored_dimension", DEFAULT_SCORED_DIMENSION)
    spec["era"] = _era_view(era, board)
    return spec


def epoch_for_board(
    repo_root: Path, epoch: int, board: str | None = None,
) -> dict:
    """The board-effective specification of one named global epoch.

    ``board=None``, or a board with no era covering ``epoch``, returns the
    global epoch record unchanged.
    """
    epochs = known_epochs(repo_root)
    if int(epoch) not in epochs:
        raise LedgerError(f"unknown epoch {epoch}")
    if board is None:
        return epochs[int(epoch)]
    covering = [
        era for era in board_eras(repo_root, board)
        if int(era["epoch_ref"]) == int(epoch)
    ]
    if not covering:
        return epochs[int(epoch)]
    return _apply_era(epochs, covering[-1], board)


def current_epoch(repo_root: Path, board: str | None = None) -> dict:
    """The newest global epoch, or one board's current era resolved against it.

    A board whose newest era is banked stays pinned to that era's epoch even
    after later global epochs open — that is what retiring a board means
    (TRACKS §6): its history keeps being served and its scoring never drifts.
    """
    epochs = known_epochs(repo_root)
    if board is None:
        return epochs[max(epochs)]
    eras = board_eras(repo_root, board)
    if not eras:
        return epochs[max(epochs)]
    return _apply_era(epochs, eras[-1], board)


def scored_dimension(repo_root: Path, board: str | None = None) -> str:
    """The boundary a board's current era scores; ``prove_ms`` by default."""
    return str(
        current_epoch(repo_root, board=board).get(
            "scored_dimension", DEFAULT_SCORED_DIMENSION
        )
    )


def aa_dispersion(repo_root: Path, board: str, workload_class: str) -> float | None:
    by_board = current_epoch(repo_root, board=board).get("aa_dispersion", {})
    value = by_board.get(board, {}).get(workload_class)
    return float(value) if value is not None else None


def resource_budgets(
    repo_root: Path, workload_class: str, board: str | None = None,
) -> dict[str, float] | None:
    """Return the current epoch's complete resource budget vector.

    Legacy epochs predate Metrics v2 and return ``None``. Once Metrics v2 is
    declared, every class used by an evaluation must have an exact, positive,
    finite three-dimensional budget. TRACKS §8 keys budgets by (board, class):
    a board era may pin its own class vectors, and anything it does not pin
    falls back to the epoch's class-only vector.
    """
    metrics = current_epoch(repo_root, board=board).get("metrics_v2")
    if metrics is None:
        return None
    if not isinstance(metrics, dict):
        raise LedgerError("metrics_v2 must be an object")
    by_class = metrics.get("resource_budgets")
    if not isinstance(by_class, dict):
        raise LedgerError("Metrics v2 resource_budgets must be an object")
    raw = by_class.get(workload_class)
    if not isinstance(raw, dict):
        raise LedgerError(
            f"Metrics v2 resource budget missing for class {workload_class}"
        )
    required = {"peak_rss_mib", "energy_j", "proof_bytes"}
    if set(raw) != required:
        raise LedgerError(
            f"Metrics v2 resource budget for {workload_class} must contain "
            f"exactly {sorted(required)}"
        )
    budgets: dict[str, float] = {}
    for dimension, value in raw.items():
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(float(value))
            or float(value) <= 0
        ):
            raise LedgerError(
                f"Metrics v2 {workload_class}/{dimension} budget must be "
                "positive and finite"
            )
        budgets[dimension] = float(value)
    return budgets
