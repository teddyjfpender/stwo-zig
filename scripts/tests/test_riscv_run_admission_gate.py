"""The run-admission gate has one definition and every sibling path calls it.

`src/integrations/riscv_cpu/proof_adapter.zig` fail-closed on a non-provable
completion reason; `src/tools/riscv/bench/runner.zig` had no equivalent, accepted
an ECALL-terminated trace, and died deep inside the prover (issue #152 item 5).
The fix hoists the rule into `src/frontends/riscv/prover.zig`. This gate is what
stops the copies coming back: a behavioural test can prove the shared function
works, but only a structural check can prove neither sibling grew a private
version of it or dropped the call.

`CALLERS` is the enumeration itself, and it is the deliverable as much as the
assertions are: hoisting the rule for two paths left a *third* one -- the hosted
block-proving pipeline -- outside it, because nothing listed the callers. A new
function that hands a `RunResult` to the prover belongs in that list.

Hoisting logic also moves it out of whatever enumerated its old home, so the
locations are named here explicitly rather than discovered.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
GATE = ROOT / "src" / "frontends" / "riscv" / "prover.zig"
CALLERS = {
    "production ELF adapter": (
        ROOT / "src" / "integrations" / "riscv_cpu" / "proof_adapter.zig",
        "prover.admitRunForProving(&run_result)",
    ),
    "benchmark runner": (
        ROOT / "src" / "tools" / "riscv" / "bench" / "runner.zig",
        "riscv_prover.classifyRunAdmission(&run_result)",
    ),
    # The third path, missed when the rule was hoisted for the first two: it runs
    # a real guest through the hosted syscall ABI and handed the result straight
    # to the prover, so a completion no statement can bind -- `.host_halt`, which
    # is how every SP1-style guest terminates -- reached the prover and failed
    # there instead of at the entry point.
    "hosted block proving pipeline": (
        ROOT / "src" / "frontends" / "riscv" / "host" / "prove_block.zig",
        "prover_mod.admitRunForProving(&run_result)",
    ),
}
# A completion-reason comparison outside the gate is a private copy of the rule,
# whatever it is spelled like.
PRIVATE_COMPLETION_TEST = re.compile(
    r"completion_reason\s*(?:!=|==)|switch\s*\(\s*[a-z_.]*completion_reason\s*\)",
)
# An enumeration of *both* proof-bearing completions, in either spelling the
# codebase uses: a switch prong naming the pair, or two equality tests joined.
#
# `.halt_flag` must be an enum literal, so it may not follow an identifier
# character. Without that guard the pattern also matches
# `runner/mod.zig`'s `.halt_flag => elf_info.halt_flag,` / `.self_loop => ...`,
# where the text `.halt_flag,` is the tail of a *field access* and the two prongs
# select a completion address rather than deciding admissibility -- a false
# positive that would make this sweep unrunnable, and did in the original.
PROOF_BEARING_PAIR = re.compile(
    r"(?<![\w)\]])\.(?:halt_flag|self_loop),\s*\.(?:halt_flag|self_loop)\s*=>"
    r"|==\s*\.(?:halt_flag|self_loop)\b[^;{}]*?==\s*\.(?:halt_flag|self_loop)\b",
)


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _encloser(text: str, offset: int) -> str:
    """Return the top-level Zig declaration ``offset`` sits inside.

    ``zig fmt`` puts every top-level declaration at column zero, so the nearest
    preceding column-zero line that is neither a comment nor a closing delimiter
    is the declaration in hand. That is all the resolution needed here: whether
    the enclosing declaration is a ``test``.

    An indented ``test`` block would resolve to its container and be reported --
    the fail-closed direction, and the right one, since a rule restated inside a
    generic container is not obviously test-only.
    """
    enclosing = ""
    for line in text[:offset].splitlines():
        if not line or line[0].isspace() or line.startswith(("//", "}", ")", "]", "{")):
            continue
        enclosing = line
    return enclosing


class RunAdmissionGateTest(unittest.TestCase):
    def test_the_gate_is_declared_once_in_the_frontend(self) -> None:
        text = read(GATE)
        for declaration in (
            "pub fn admitRunForProving(",
            "pub fn classifyRunAdmission(",
            "pub fn classifyCompletion(",
            "pub fn classifyPublicIo(",
            "pub const RunAdmissionError = error{",
        ):
            self.assertIn(declaration, text, f"{GATE} must declare {declaration!r}")
        self.assertEqual(1, text.count("pub fn admitRunForProving("))
        # The two proof-bearing completions are enumerated once *in this file*.
        # That the file is also the only place in `src` that enumerates them is a
        # separate, repository-wide obligation below -- this line cannot state it,
        # because it only ever looked at `prover.zig`.
        self.assertEqual(1, len(PROOF_BEARING_PAIR.findall(text)))

    def test_no_src_source_outside_the_gate_enumerates_the_pair(self) -> None:
        """The claim above, asserted where it is actually made: over ``src``.

        Counting inside ``prover.zig`` proves the gate does not restate its own
        rule. It says nothing about a sibling growing a private copy, which is the
        defect (issue #152 item 5): the rule lived in the ELF adapter, the bench
        runner had no equivalent, and an ECALL-terminated trace reached the prover.
        ``test_no_sibling_keeps_a_private_completion_test`` covers the callers this
        file already names; a caller nobody has named yet is exactly the one that
        will drift, so the sweep is over the tree.

        Restricted to non-test code. A test that asserts the rule must state the
        rule -- `prove_admission_gate_test.zig` enumerates the pair to check the
        gate classifies every reason, and that is its job, not a second
        implementation.
        """
        offenders: list[str] = []
        scanned = 0
        for source in sorted(SRC.rglob("*.zig")):
            if ".zig-cache" in source.parts or source == GATE:
                continue
            scanned += 1
            text = read(source)
            for match in PROOF_BEARING_PAIR.finditer(text):
                if _encloser(text, match.start()).startswith("test"):
                    continue
                line = text.count("\n", 0, match.start()) + 1
                offenders.append(f"{source.relative_to(ROOT).as_posix()}:{line}")
        self.assertEqual(
            [],
            offenders,
            "a private copy of the admission rule lives outside "
            f"{GATE.relative_to(ROOT).as_posix()}",
        )
        # Fails closed: a sweep that found no files would report no offenders.
        self.assertGreater(scanned, 200)
        # And the pattern still matches the rule it is looking for, in the one
        # place that is allowed to hold it.
        self.assertEqual(1, len(PROOF_BEARING_PAIR.findall(read(GATE))))

    def test_every_sibling_path_calls_the_shared_gate(self) -> None:
        for label, (path, call) in CALLERS.items():
            with self.subTest(label):
                self.assertIn(call, read(path), f"{path} must route through the gate")

    def test_no_sibling_keeps_a_private_completion_test(self) -> None:
        for label, (path, _) in CALLERS.items():
            with self.subTest(label):
                text = read(path)
                self.assertIsNone(
                    PRIVATE_COMPLETION_TEST.search(text),
                    f"{path} reimplements the completion rule the gate owns",
                )

    def test_the_trace_only_entrypoint_states_its_limitation_and_guards_it(self) -> None:
        text = read(GATE)
        self.assertIn("pub fn proveRiscVTraceOnlyNoPublicIo(", text)
        self.assertIn("pub fn proveRiscVTraceOnlyNoPublicIoUsingChannel(", text)
        # The guard is the first statement of the body, so a run this path cannot
        # represent is refused before any proving work happens.
        body = text.split("pub fn proveRiscVTraceOnlyNoPublicIoUsingChannel(", 1)[1]
        first_statement = body.split(") !ProveOutput {", 1)[1].strip().splitlines()[0]
        self.assertIn("classifyPublicIo(opt_memory, PublishedIo.none)", first_statement)

    def test_the_trap_name_is_gone_from_the_repository(self) -> None:
        """The shorter, more inviting name was the broken one (item 1)."""
        offenders: list[str] = []
        for directory in ("src", "scripts", "build_support"):
            for path in sorted((ROOT / directory).rglob("*")):
                if not path.is_file() or path.suffix not in {".zig", ".py", ".json", ".md"}:
                    continue
                if "__pycache__" in path.parts or path.name == Path(__file__).name:
                    continue
                if re.search(r"proveRiscVWithEngine(?:UsingChannel)?\b", read(path)):
                    offenders.append(str(path.relative_to(ROOT)))
        self.assertEqual([], offenders)


if __name__ == "__main__":
    unittest.main()
