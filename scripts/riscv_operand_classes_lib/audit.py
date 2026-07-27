"""Measure which operand classes an existing trace corpus actually touches.

The enumeration in `classes` defines the operand space worth testing; this
module answers "which of it does the current corpus exercise?". Input is
canonical retirement traces (`riscv-trace-dump` output). Operand values
are recovered by replaying each trace's retired instruction words through
the pinned Sail model and folding Sail's rd_value stream into a register
file -- the same Sail-derived recovery generation uses -- so the coverage
verdict is grounded in the oracle rather than in a Python re-execution of
our own semantics.

The report's `untouched` list is the finding: every (opcode, class) pair
the enumeration reaches and the audited corpus never does.
"""

from __future__ import annotations

import dataclasses
import subprocess
import tempfile
from pathlib import Path

try:
    from scripts import riscv_equivalence as equivalence
except ImportError:  # direct execution with scripts/ on sys.path
    import riscv_equivalence as equivalence

from . import classes, encoding, session

# The trace-vector guests the repository commits, mirrored from
# `src/tests/riscv/rigidity_corpus.zig` CORPUS: the honest-row corpus every
# rigidity property samples, which makes it the corpus whose operand
# coverage decides what the witness audits can ever see. `crypto/ecdsa.elf`
# is excluded there for not terminating; excluded here for the same reason.
DEFAULT_CORPUS = (
    "vectors/riscv_elfs/shift_logic.elf",
    "vectors/riscv_elfs/mem_ls.elf",
    "vectors/riscv_elfs/mul_div.elf",
    "vectors/riscv_elfs/alu_test.elf",
    "vectors/riscv_elfs/branch_fib.elf",
    "vectors/riscv_elfs/jal_jalr.elf",
    "vectors/riscv_elfs/mulhu_only.elf",
    "vectors/riscv_elfs/memcpy_loop.elf",
    "vectors/riscv_elfs/bubble_sort.elf",
    "vectors/riscv_elfs/sieve_primes.elf",
    "vectors/riscv_elfs/gcd_euclid.elf",
    "vectors/riscv_elfs/collatz.elf",
    "vectors/riscv_elfs/xorshift_prng.elf",
    "vectors/riscv_elfs/fib_iter.elf",
    "vectors/riscv_elfs/fence.elf",
    "vectors/riscv_elfs/declared_region.elf",
    "vectors/riscv_elfs/multi_shard_addi.elf",
    "vectors/riscv_elfs/crypto/sha2_input.elf",
    "vectors/riscv_elfs/crypto/keccak_input.elf",
    "vectors/riscv_elfs/crypto/poseidon2_m31.elf",
)

MAX_STEPS = 200_000


class AuditError(RuntimeError):
    """The audit inputs or the replay transport failed."""


@dataclasses.dataclass
class Coverage:
    """Hit counts per enumerated (opcode, class) pair, plus what fell
    outside the enumeration entirely."""

    enumerated: dict[tuple[str, str], int]
    # Tags per opcode, so half a million retirements evaluate ~10 predicates
    # each instead of the full pair table.
    tags_by_op: dict[str, list[str]]
    retirements: int = 0
    no_class_match: dict[str, int] = dataclasses.field(default_factory=dict)
    operand_unknown: int = 0

    def record(self, obs: classes.Obs) -> None:
        self.retirements += 1
        hit = False
        for tag in self.tags_by_op.get(obs.op, ()):
            if classes.PREDICATES[tag](obs):
                self.enumerated[(obs.op, tag)] += 1
                hit = True
        if not hit:
            self.no_class_match[obs.op] = self.no_class_match.get(obs.op, 0) + 1

    def untouched(self) -> list[tuple[str, str]]:
        return sorted(pair for pair, count in self.enumerated.items() if count == 0)


def empty_coverage() -> Coverage:
    pairs = {(case.op, case.tag) for case in classes.all_cases()}
    tags_by_op: dict[str, list[str]] = {}
    for op_name, tag in sorted(pairs):
        tags_by_op.setdefault(op_name, []).append(tag)
    return Coverage(
        enumerated={pair: 0 for pair in sorted(pairs)},
        tags_by_op=tags_by_op,
    )


def replay_trace(sail_bin: Path, trace: dict, coverage: Coverage) -> None:
    """Walk one canonical trace's retirements through a fresh Sail session.

    Register values come from Sail's own rd_value stream. The trace is the
    runner's; Sail re-executes the same words, and the committed
    formal-corpus evidence already established field-level equivalence on
    this corpus, so the recovered operands are simultaneously Sail's state
    and the runner's.
    """
    registers = session.RegisterFile()
    label = "corpus replay"
    with session.SailSession(sail_bin) as sail:
        for row in trace["retirements"]:
            ret = sail.step(row["instruction"])
            if ret.trap or ret.halt or ret.intr:
                raise AuditError(
                    f"Sail trapped replaying 0x{row['instruction']:08x} "
                    f"at retirement {row['order']}"
                )
            if ret.pc != row["pc"]:
                raise AuditError(
                    f"replay diverged at retirement {row['order']}: "
                    f"Sail pc 0x{ret.pc:08x}, trace pc 0x{row['pc']:08x}"
                )
            decoded = encoding.decode(ret.insn)
            if decoded is None:
                raise AuditError(f"trace word 0x{ret.insn:08x} is outside RV32IM")
            try:
                coverage.record(registers.observe(ret, label))
            except session.SessionError:
                # A source register no earlier retirement wrote (e.g. an
                # ELF-initialised sp read before any write). The operand
                # value cannot be recovered Sail-side, so the retirement is
                # counted but not classified -- visibly, never as a guess.
                coverage.operand_unknown += 1
            registers.apply(ret)


def dump_trace(zig_bin: Path, elf: Path) -> dict:
    """One canonical retirement trace from the release trace-dump binary."""
    with tempfile.NamedTemporaryFile(suffix=".json") as scratch:
        output = Path(scratch.name)
        result = subprocess.run(
            [str(zig_bin), "--elf", str(elf), "--output", str(output),
             "--max-steps", str(MAX_STEPS)],
            cwd=equivalence.ROOT,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise AuditError(
                f"riscv-trace-dump failed for {elf}: {result.stderr.strip()}"
            )
        return equivalence.load_trace(output)


def audit_corpus(
    sail_bin: Path,
    zig_bin: Path,
    elf_paths: tuple[str, ...] = DEFAULT_CORPUS,
) -> tuple[Coverage, list[str]]:
    """Coverage over the given guests, plus the guests that could not be
    audited (reported, never silently dropped)."""
    coverage = empty_coverage()
    skipped = []
    for path in elf_paths:
        elf = equivalence.ROOT / path
        if not elf.is_file():
            skipped.append(f"{path}: missing")
            continue
        try:
            trace = dump_trace(zig_bin, elf)
            replay_trace(sail_bin, trace, coverage)
        except (AuditError, equivalence.EquivalenceError, OSError) as error:
            skipped.append(f"{path}: {error}")
    return coverage, skipped


def report(coverage: Coverage, skipped: list[str]) -> dict:
    touched = {
        f"{op_name}/{tag}": count
        for (op_name, tag), count in sorted(coverage.enumerated.items())
        if count
    }
    return {
        "schema": "stwo-riscv-operand-class-audit-v1",
        "retirements": coverage.retirements,
        "enumerated_pairs": len(coverage.enumerated),
        "touched_pairs": len(touched),
        "untouched": [f"{op_name}/{tag}" for op_name, tag in coverage.untouched()],
        "touched": touched,
        "no_class_match": coverage.no_class_match,
        "operand_unknown_retirements": coverage.operand_unknown,
        "skipped_guests": skipped,
    }
