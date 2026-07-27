"""RVFI-DII execution of operand-class cases on the pinned Sail model.

One fresh Sail process per case: the DII transport keeps architectural
state across injected instructions, so a shared session would let one
case's registers or memory leak into the next and the recorded expectation
would no longer be the body's own. Transport plumbing (port reservation,
connection, packet framing, pinned-identity verification) is imported from
`riscv_equivalence`, which remains the one owner of the RVFI-DII wire
format; this module adds only the source-register fields the coverage
audit needs, which the canonical retirement comparison deliberately
excludes.
"""

from __future__ import annotations

import dataclasses
import struct
import subprocess
from pathlib import Path

try:
    from scripts import riscv_equivalence as equivalence
except ImportError:  # direct execution with scripts/ on sys.path
    import riscv_equivalence as equivalence

from . import classes, encoding

ENTRY = equivalence.RVFI_DII_ENTRY
# A body may retire each instruction at most once (the trampolines are
# built that way), so anything past this bound is a malformed case looping.
MAX_RETIREMENTS_FACTOR = 2


class SessionError(RuntimeError):
    """The Sail RVFI-DII session or a case body misbehaved."""


@dataclasses.dataclass(frozen=True)
class Retirement:
    """One Sail retirement, as `decode_rvfi_dii_v1` reports it.

    The packet's rs1/rs2 data words are NOT decoded: the pinned Sail build
    leaves them zero (measured, not assumed -- see the register-file
    tracking in `RegisterFile` for how operand values are recovered from
    Sail's rd_value stream instead)."""

    pc: int
    next_pc: int
    insn: int
    rd: int
    rd_value: int
    mem_addr: int
    mem_rdata: int
    mem_wdata: int
    mem_rmask: int
    mem_wmask: int
    trap: bool
    halt: bool
    intr: bool


def _decode_retirement(packet: bytes) -> Retirement:
    row = equivalence.decode_rvfi_dii_v1(packet)
    return Retirement(
        pc=row["pc"],
        next_pc=row["next_pc"],
        insn=row["instruction"],
        rd=row["rd"],
        rd_value=row["rd_value"],
        mem_addr=row["memory"]["address"],
        mem_rdata=row["memory"]["read_value"],
        mem_wdata=row["memory"]["write_value"],
        mem_rmask=row["memory"]["read_mask"],
        mem_wmask=row["memory"]["write_mask"],
        trap=row["trap"],
        halt=row["halt"],
        intr=row["intr"],
    )


PC_TAINT_OPS = frozenset(("auipc", "jal", "jalr"))


class RegisterFile:
    """Sail-derived register values, folded from the rd_value stream.

    The pinned build's RVFI packets carry no rs1/rs2 data, so operand
    values are recovered the only Sail-derived way there is: every value a
    register holds mid-stream was written by some earlier retirement, and
    that retirement's rd_value is Sail's own report of the write. Reading
    a register no earlier retirement wrote is an error here rather than a
    zero: a zero would silently convert "unknown" into an operand claim.

    A register whose value derives from the pc (an AUIPC result, a jump
    link, or anything computed from one) is additionally marked tainted:
    its absolute value is specific to the generation session's addresses
    and must not be committed as an expectation a guest at another base
    could meet.
    """

    def __init__(self) -> None:
        self._values: dict[int, int] = {0: 0}
        self._tainted: set[int] = set()

    def read(self, reg: int, context: str) -> int:
        if reg not in self._values:
            raise SessionError(f"{context}: reads x{reg} before any Sail write")
        return self._values[reg]

    def tainted(self, reg: int) -> bool:
        return reg in self._tainted

    def apply(self, ret: Retirement) -> None:
        if ret.rd == 0:
            return
        self._values[ret.rd] = ret.rd_value
        decoded = encoding.decode(ret.insn)
        taints = decoded["op"] in PC_TAINT_OPS or any(
            self.tainted(decoded[source])
            for source, reads in (("rs1", classes.READS_RS1), ("rs2", classes.READS_RS2))
            if decoded["op"] in reads
        )
        if taints:
            self._tainted.add(ret.rd)
        else:
            self._tainted.discard(ret.rd)

    def observe(self, ret: Retirement, context: str) -> classes.Obs:
        """Project a retirement into the class-predicate view, reading its
        source operands from the pre-retirement register state. Must be
        called before `apply`, or `rd == rs1` instructions would observe
        their own result as an operand."""
        decoded = encoding.decode(ret.insn)
        if decoded is None:
            raise SessionError(f"{context}: 0x{ret.insn:08x} is outside RV32IM")
        op_name = decoded["op"]
        return classes.Obs(
            op=op_name,
            rs1=self.read(decoded["rs1"], context) if op_name in classes.READS_RS1 else 0,
            rs2=self.read(decoded["rs2"], context) if op_name in classes.READS_RS2 else 0,
            imm=decoded["imm"],
            rd_idx=decoded["rd"],
            rs1_idx=decoded["rs1"],
            rs2_idx=decoded["rs2"],
            pc=ret.pc,
            next_pc=ret.next_pc,
            mem_addr=ret.mem_addr,
            mem_rmask=ret.mem_rmask,
            mem_wmask=ret.mem_wmask,
            mem_rdata=ret.mem_rdata,
        )


class SailSession:
    """One live RVFI-DII v1 session against an already-verified binary."""

    def __init__(self, sail_bin: Path, timeout_seconds: float = 10.0):
        port = equivalence._reserve_tcp_port()
        command = [str(sail_bin), "--rv32"]
        for override in equivalence.SAIL_CONFIG_OVERRIDES:
            command.extend(("--config-override", str(override)))
        command.extend(("--rvfi-dii", str(port)))
        self._timeout = timeout_seconds
        self._process = subprocess.Popen(
            command,
            cwd=equivalence.ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            self._connection = equivalence._connect_rvfi(
                self._process, port, timeout_seconds
            )
            self._connection.settimeout(timeout_seconds)
        except BaseException:
            self._terminate()
            raise

    def step(self, instruction: int) -> Retirement:
        self._connection.sendall(struct.pack("<Q", (1 << 48) | instruction))
        packet = equivalence._recv_exact(
            self._connection, equivalence.RVFI_DII_V1_BYTES
        )
        return _decode_retirement(packet)

    def close(self) -> None:
        """EndOfTrace, halt acknowledgement, clean exit -- or raise."""
        try:
            self._connection.sendall(struct.pack("<Q", 0))
            halt_packet = _decode_retirement(
                equivalence._recv_exact(
                    self._connection, equivalence.RVFI_DII_V1_BYTES
                )
            )
            if not halt_packet.halt:
                raise SessionError("Sail RVFI-DII did not acknowledge EndOfTrace")
            self._connection.close()
            _, stderr = self._process.communicate(timeout=self._timeout)
            if self._process.returncode != 0:
                raise SessionError(
                    f"Sail exited {self._process.returncode}: "
                    f"{stderr.decode(errors='replace').strip()}"
                )
        except BaseException:
            self._terminate()
            raise

    def _terminate(self) -> None:
        try:
            self._connection.close()
        except (OSError, AttributeError):
            pass
        self._process.terminate()
        try:
            self._process.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            self._process.kill()
            self._process.communicate()

    def __enter__(self) -> "SailSession":
        return self

    def __exit__(self, kind, value, traceback) -> None:
        if kind is None:
            self.close()
        else:
            self._terminate()


@dataclasses.dataclass(frozen=True)
class CaseObservation:
    """Sail's execution of one case body: which body indices retired, in
    order, each retirement, and the pre-retirement operand view of each.
    Every index retires at most once. The taint flags say whether the
    under-test source operands are pc-derived and therefore not portable
    as absolute expectations."""

    retired: tuple[int, ...]
    by_index: dict[int, Retirement]
    obs_by_index: dict[int, classes.Obs]
    rs1_pc_derived: bool = False
    rs2_pc_derived: bool = False

    def under_test(self, case: classes.CaseSpec) -> Retirement:
        return self.by_index[case.under_test]

    def under_test_obs(self, case: classes.CaseSpec) -> classes.Obs:
        return self.obs_by_index[case.under_test]


def observe_case(sail_bin: Path, case: classes.CaseSpec) -> CaseObservation:
    """Execute one case body on pinned Sail, following its control flow.

    The DII transport feeds whatever word we send regardless of pc, so the
    driver must itself walk the static body by Sail's reported next_pc --
    injecting the fall-through word after a taken branch would execute an
    instruction the embedded guest never reaches. Sail decides every
    branch; this loop only follows.
    """
    body = case.body
    retired: list[int] = []
    by_index: dict[int, Retirement] = {}
    obs_by_index: dict[int, classes.Obs] = {}
    rs1_pc_derived = False
    rs2_pc_derived = False
    registers = RegisterFile()
    with SailSession(sail_bin) as session:
        index = 0
        for _ in range(MAX_RETIREMENTS_FACTOR * len(body) + 4):
            ret = session.step(body[index])
            _check_retirement(case, index, ret, first=not retired)
            if index in by_index:
                raise SessionError(f"{case.name}: body index {index} retired twice")
            retired.append(index)
            by_index[index] = ret
            obs_by_index[index] = registers.observe(ret, f"{case.name}[{index}]")
            if index == case.under_test:
                decoded = encoding.decode(ret.insn)
                rs1_pc_derived = case.op in classes.READS_RS1 and registers.tainted(decoded["rs1"])
                rs2_pc_derived = case.op in classes.READS_RS2 and registers.tainted(decoded["rs2"])
                if (rs1_pc_derived or rs2_pc_derived) and (ret.mem_rmask or ret.mem_wmask):
                    # A pc-derived memory address would make the recorded
                    # absolute mem_addr wrong at any other base; no case may
                    # be shaped that way.
                    raise SessionError(f"{case.name}: memory access through a pc-derived base")
            registers.apply(ret)
            delta = (ret.next_pc - ENTRY) & 0xFFFF_FFFF
            if delta % 4:
                raise SessionError(f"{case.name}: next_pc 0x{ret.next_pc:08x} misaligned")
            index = delta // 4
            if index == len(body):
                if case.under_test not in by_index:
                    raise SessionError(f"{case.name}: under-test word never retired")
                return CaseObservation(
                    tuple(retired), by_index, obs_by_index,
                    rs1_pc_derived=rs1_pc_derived, rs2_pc_derived=rs2_pc_derived,
                )
            if index > len(body):
                raise SessionError(f"{case.name}: control flow left the body")
    raise SessionError(f"{case.name}: body did not terminate")


def _check_retirement(
    case: classes.CaseSpec, index: int, ret: Retirement, first: bool
) -> None:
    """Reject traps and transport surprises, and require Sail's decode of
    the injected word to name the registers the encoder intended -- the
    cross-check that keeps an encoder bug from becoming a silent case."""
    if ret.trap or ret.halt or ret.intr:
        raise SessionError(
            f"{case.name}[{index}]: Sail reported trap/halt/intr for "
            f"0x{case.body[index]:08x}"
        )
    if ret.insn != case.body[index]:
        raise SessionError(
            f"{case.name}[{index}]: Sail echoed 0x{ret.insn:08x}, "
            f"sent 0x{case.body[index]:08x}"
        )
    if first and ret.pc != ENTRY:
        raise SessionError(
            f"{case.name}: transport entry 0x{ret.pc:08x}, expected 0x{ENTRY:08x}"
        )
    expected_pc = (ENTRY + 4 * index) & 0xFFFF_FFFF
    if ret.pc != expected_pc:
        raise SessionError(
            f"{case.name}[{index}]: retired at 0x{ret.pc:08x}, "
            f"expected 0x{expected_pc:08x}"
        )
    decoded = encoding.decode(case.body[index])
    if decoded["op"] in classes.WRITES_RD and ret.rd != decoded["rd"]:
        raise SessionError(
            f"{case.name}[{index}]: Sail wrote x{ret.rd}, encoder meant x{decoded['rd']}"
        )


