"""Reader for `zig-out/committed-trace/*.json`, the export written by
`src/frontends/riscv/prover/test_trace_dump.zig`.

Every field is validated on the way in.  A checker that silently accepted a
short column or an unknown schema would report "satisfied" about a trace it had
not actually read, which is the one failure mode a satisfaction checker must not
have.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .field import P, QM31, committed_placement, logical_index_from_committed

SCHEMA = "riscv-committed-trace/2"


class DumpError(ValueError):
    """Malformed or unrecognised export."""


@dataclass(frozen=True)
class Relation:
    z: QM31
    alpha: QM31

    def combine(self, values: list[QM31]) -> QM31:
        """`v_0 + alpha v_1 + ... + alpha^n v_n - z`, the LogUp denominator.

        Transcribed from the formula stated in `air/relation_challenges.zig`,
        which pins it to the Rust oracle's `schema.rs`.  There is no relation-id
        term and no challenge sharing between relations.
        """
        result = QM31()
        power = QM31(1, 0, 0, 0)
        for value in values:
            result = result + power * value
            power = power * self.alpha
        return result - self.z


@dataclass(frozen=True)
class OutputWord:
    addr: int
    value: int
    clock: int


@dataclass(frozen=True)
class IoEntries:
    input_start: int
    input_len: int
    input_words: tuple[int, ...]
    output_len: int
    output_len_addr: int
    output_data_addr: int
    output_words: tuple[OutputWord, ...]


@dataclass(frozen=True)
class PublicData:
    initial_pc: int
    final_pc: int
    clock: int
    initial_regs: tuple[int, ...]
    final_regs: tuple[int, ...]
    reg_last_clock: tuple[int, ...]
    program_root: int | None
    initial_rw_root: int | None
    final_rw_root: int | None
    completion_kind: str
    completion_address: int
    completion_value: int
    completion_clock: int
    io: IoEntries


@dataclass(frozen=True)
class Component:
    """One main-trace component's committed columns, in NATURAL row order.

    `rows[r][c]` is column `c` of logical row `r`.  The export carries committed
    (permuted) order; `load` undoes the permutation here so every consumer works
    in the order the AIR's column names describe. Lookup multiplicity tables
    retain only nonzero logical rows because their fixed domains reach 2^20.
    """

    family: str
    index: int
    log_size: int
    n_rows: int
    n_columns: int
    rows: tuple[tuple[int, ...], ...]
    class_: str = "opcode"
    sparse_rows: tuple[tuple[int, tuple[int, ...]], ...] = ()

    def domain_size(self) -> int:
        return 1 << self.log_size

    def is_sparse(self) -> bool:
        return bool(self.sparse_rows) or (self.class_ == "infra" and not self.rows)


@dataclass(frozen=True)
class Claim:
    label: str
    index: int
    total: QM31


@dataclass(frozen=True)
class Dump:
    path: Path
    public: PublicData
    relations: dict[str, Relation]
    opcode_claims: tuple[Claim, ...]
    infra_claims: tuple[Claim, ...]
    transcript_claims: tuple[Claim, ...]
    components: tuple[Component, ...]

    def claim_for(self, index: int) -> QM31:
        for claim in self.opcode_claims:
            if claim.index == index:
                return claim.total
        raise DumpError(f"no opcode claim for component {index}")

    def infra_claim_for(self, index: int) -> QM31:
        for claim in self.infra_claims:
            if claim.index == index:
                return claim.total
        raise DumpError(f"no infrastructure claim for component {index}")

    def transcript_claim_for(self, index: int) -> QM31:
        for claim in self.transcript_claims:
            if claim.index == index:
                return claim.total
        raise DumpError(f"no transcript claim for component {index}")

    def opcode_components(self) -> tuple[Component, ...]:
        return tuple(component for component in self.components if component.class_ == "opcode")

    def infra_components(self) -> tuple[Component, ...]:
        return tuple(component for component in self.components if component.class_ == "infra")


def _u32(raw: Any, where: str) -> int:
    if not isinstance(raw, int) or not 0 <= raw < (1 << 32):
        raise DumpError(f"{where}: expected a u32, got {raw!r}")
    return raw


def _u32_list(raw: Any, where: str, length: int | None = None) -> tuple[int, ...]:
    if not isinstance(raw, list):
        raise DumpError(f"{where}: expected a list")
    if length is not None and len(raw) != length:
        raise DumpError(f"{where}: expected {length} entries, got {len(raw)}")
    return tuple(_u32(value, f"{where}[{i}]") for i, value in enumerate(raw))


def _secure(raw: Any, where: str) -> QM31:
    if not isinstance(raw, list):
        raise DumpError(f"{where}: expected four coordinates")
    return QM31.from_list([int(value) for value in raw])


def _public_data(raw: dict[str, Any]) -> PublicData:
    completion = raw.get("completion")
    if not isinstance(completion, dict):
        raise DumpError("public_data.completion: absent, so the boundary is undefined")
    io = raw["io_entries"]
    return PublicData(
        initial_pc=_u32(raw["initial_pc"], "initial_pc"),
        final_pc=_u32(raw["final_pc"], "final_pc"),
        clock=_u32(raw["clock"], "clock"),
        initial_regs=_u32_list(raw["initial_regs"], "initial_regs", 32),
        final_regs=_u32_list(raw["final_regs"], "final_regs", 32),
        reg_last_clock=_u32_list(raw["reg_last_clock"], "reg_last_clock", 32),
        program_root=None if raw["program_root"] is None else _u32(raw["program_root"], "program_root"),
        initial_rw_root=None
        if raw["initial_rw_root"] is None
        else _u32(raw["initial_rw_root"], "initial_rw_root"),
        final_rw_root=None
        if raw["final_rw_root"] is None
        else _u32(raw["final_rw_root"], "final_rw_root"),
        completion_kind=str(completion["kind"]),
        completion_address=_u32(completion["address"], "completion.address"),
        completion_value=_u32(completion["value"], "completion.value"),
        completion_clock=_u32(completion["clock"], "completion.clock"),
        io=IoEntries(
            input_start=_u32(io["input_start"], "io.input_start"),
            input_len=_u32(io["input_len"], "io.input_len"),
            input_words=_u32_list(io["input_words"], "io.input_words"),
            output_len=_u32(io["output_len"], "io.output_len"),
            output_len_addr=_u32(io["output_len_addr"], "io.output_len_addr"),
            output_data_addr=_u32(io["output_data_addr"], "io.output_data_addr"),
            output_words=tuple(
                OutputWord(
                    addr=_u32(word["addr"], "io.output_words.addr"),
                    value=_u32(word["value"], "io.output_words.value"),
                    clock=_u32(word["clock"], "io.output_words.clock"),
                )
                for word in io["output_words"]
            ),
        ),
    )


def _component(raw: dict[str, Any]) -> Component:
    log_size = int(raw["log_size"])
    n_columns = int(raw["n_columns"])
    n_rows = int(raw["n_rows"])
    class_ = str(raw["class"])
    if class_ not in {"opcode", "infra"}:
        raise DumpError(f"component class must be opcode or infra, got {class_!r}")
    size = 1 << log_size
    if n_rows > size:
        raise DumpError(f"{raw['label']}: {n_rows} real rows exceed the domain {size}")
    columns = raw["columns"]
    if len(columns) != n_columns:
        raise DumpError(
            f"{raw['label']}: declares {n_columns} columns and carries {len(columns)}"
        )
    encoding = raw.get("encoding")
    if encoding == "dense_committed":
        for position, column in enumerate(columns):
            if len(column) != size:
                raise DumpError(
                    f"{raw['label']} column {position}: {len(column)} values "
                    f"for a domain of {size}"
                )
            for value in column:
                if not isinstance(value, int) or not 0 <= value < P:
                    raise DumpError(
                        f"{raw['label']} column {position}: {value} is not in [0, p)"
                    )
        placement = committed_placement(log_size)
        rows = tuple(
            tuple(columns[column][placement[row]] for column in range(n_columns))
            for row in range(size)
        )
        sparse_rows: tuple[tuple[int, tuple[int, ...]], ...] = ()
    elif encoding == "sparse_committed":
        logical: dict[int, list[int]] = {}
        seen: set[tuple[int, int]] = set()
        for column_index, column in enumerate(columns):
            for item_index, item in enumerate(column):
                if not isinstance(item, list) or len(item) != 2:
                    raise DumpError(
                        f"{raw['label']} column {column_index} sparse item "
                        f"{item_index}: expected [committed_row, value]"
                    )
                committed_row, value = item
                if (
                    not isinstance(committed_row, int)
                    or not 0 <= committed_row < size
                    or not isinstance(value, int)
                    or not 0 < value < P
                ):
                    raise DumpError(
                        f"{raw['label']} column {column_index} sparse item "
                        f"{item_index}: invalid index or nonzero M31 value"
                    )
                key = (column_index, committed_row)
                if key in seen:
                    raise DumpError(
                        f"{raw['label']} column {column_index}: duplicate sparse "
                        f"committed row {committed_row}"
                    )
                seen.add(key)
                row = logical_index_from_committed(committed_row, log_size)
                logical.setdefault(row, [0] * n_columns)[column_index] = value
        sparse_rows = tuple(
            (row, tuple(values)) for row, values in sorted(logical.items())
        )
        rows = ()
    else:
        raise DumpError(f"{raw['label']}: unknown column encoding {encoding!r}")
    return Component(
        family=str(raw["label"]),
        index=int(raw["index"]),
        log_size=log_size,
        n_rows=n_rows,
        n_columns=n_columns,
        rows=rows,
        class_=class_,
        sparse_rows=sparse_rows,
    )


def load(path: str | Path) -> Dump:
    location = Path(path)
    payload = json.loads(location.read_text(encoding="utf-8"))
    if payload.get("schema") != SCHEMA:
        raise DumpError(
            f"{location}: schema {payload.get('schema')!r} is not {SCHEMA!r}; "
            "regenerate the export or update this reader deliberately"
        )
    if payload.get("modulus") != P:
        raise DumpError(f"{location}: modulus {payload.get('modulus')} is not {P}")

    relations = {
        name: Relation(
            z=_secure(value["z"], f"relations.{name}.z"),
            alpha=_secure(value["alpha"], f"relations.{name}.alpha"),
        )
        for name, value in payload["relations"].items()
    }
    components = tuple(_component(raw) for raw in payload["components"])
    opcode_claims = tuple(
        Claim(str(raw["family"]), int(raw["index"]), _secure(raw["total"], "claims.opcode"))
        for raw in payload["claims"]["opcode"]
    )
    infra_claims = tuple(
        Claim(str(raw["kind"]), int(raw["index"]), _secure(raw["total"], "claims.infra"))
        for raw in payload["claims"]["infra"]
    )
    transcript_claims = tuple(
        Claim(
            str(raw["component"]),
            int(raw["index"]),
            _secure(raw["total"], "claims.transcript"),
        )
        for raw in payload["claims"]["transcript"]
    )
    opcode_components = tuple(c for c in components if c.class_ == "opcode")
    infra_components = tuple(c for c in components if c.class_ == "infra")
    if len(opcode_claims) != len(opcode_components):
        raise DumpError(
            f"{location}: {len(opcode_claims)} opcode claims for "
            f"{len(opcode_components)} opcode components"
        )
    if len(infra_claims) != len(infra_components):
        raise DumpError(
            f"{location}: {len(infra_claims)} infrastructure claims for "
            f"{len(infra_components)} infrastructure components"
        )
    return Dump(
        path=location,
        public=_public_data(payload["public_data"]),
        relations=relations,
        opcode_claims=opcode_claims,
        infra_claims=infra_claims,
        transcript_claims=transcript_claims,
        components=components,
    )
