"""The run-admission gate has one definition and every sibling path calls it.

`src/integrations/riscv_cpu/proof_adapter.zig` fail-closed on a non-provable
completion reason; `src/tools/riscv/bench/runner.zig` had no equivalent, accepted
an ECALL-terminated trace, and died deep inside the prover (issue #152 item 5).
The fix hoists the rule into `src/frontends/riscv/prover.zig`. This gate is what
stops the copies coming back: a behavioural test can prove the shared function
works, but only a structural check can prove neither sibling grew a private
version of it or dropped the call.

Hoisting logic also moves it out of whatever enumerated its old home, so the
locations are named here explicitly rather than discovered.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
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
}
# A completion-reason comparison outside the gate is a private copy of the rule,
# whatever it is spelled like.
PRIVATE_COMPLETION_TEST = re.compile(
    r"completion_reason\s*(?:!=|==)|switch\s*\(\s*[a-z_.]*completion_reason\s*\)",
)


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


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
        # The two proof-bearing completions are enumerated in exactly one place.
        self.assertEqual(1, len(re.findall(r"\.halt_flag,\s*\.self_loop\s*=>", text)))

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
