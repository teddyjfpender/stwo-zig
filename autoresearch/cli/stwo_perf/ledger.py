"""Append-only promotions ledger: parse, validate, append, and query."""

from __future__ import annotations

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
BOARDS = (
    "core_cpu", "core_hybrid", "core_metal", "core_cuda",
    "heavy_native", "heavy_cairo", "stream", "riscv",
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


def current_epoch(repo_root: Path) -> dict:
    epochs = known_epochs(repo_root)
    return epochs[max(epochs)]


def aa_dispersion(repo_root: Path, board: str, workload_class: str) -> float | None:
    by_board = current_epoch(repo_root).get("aa_dispersion", {})
    value = by_board.get(board, {}).get(workload_class)
    return float(value) if value is not None else None


def resource_budgets(
    repo_root: Path, workload_class: str,
) -> dict[str, float] | None:
    """Return the current epoch's complete resource budget vector.

    Legacy epochs predate Metrics v2 and return ``None``. Once Metrics v2 is
    declared, every class used by an evaluation must have an exact, positive,
    finite three-dimensional budget.
    """
    metrics = current_epoch(repo_root).get("metrics_v2")
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
