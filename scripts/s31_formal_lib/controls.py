"""Kernel-rejected false witnesses and mutations of real gadget definitions."""
from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

from .checks import FormalError

# The true controls use the same imports, types, definitions and tactic as the
# false controls. A missing tool or broken import cannot count as rejection.
WITNESSES = (
    ("byte", "Radix.byteConstraint 255 (255*256)",
     "Radix.byteConstraint 256 65536", "Radix.byteConstraint"),
    ("carry", "Radix.addConstraint 65536 65535 1 0 0 1",
     "Radix.addConstraint 65536 65535 1 0 0 0", "Radix.addConstraint"),
    ("borrow", "Radix.subConstraint 65536 0 1 0 65535 1",
     "Radix.subConstraint 65536 0 1 0 65535 0", "Radix.subConstraint"),
    ("boolean", "bit (1 : Field.F)", "bit (2 : Field.F)", "bit"),
    ("selector", "selectConstraint (1 : Field.F) 3 7 7",
     "selectConstraint (2 : Field.F) 3 7 11", "selectConstraint bit"),
    ("signed_overflow", "Signed.addOverflow (0 : Field.F) 1 1",
     "Signed.addOverflow (0 : Field.F) 0 1", "Signed.addOverflow"),
    ("quotient", "Bitcoin.divisionConstraint 100 7 14 2",
     "Bitcoin.divisionConstraint 100 7 13 2", "Bitcoin.divisionConstraint"),
    ("remainder", "Bitcoin.divisionConstraint 100 7 14 2",
     "Bitcoin.divisionConstraint 100 7 13 9", "Bitcoin.divisionConstraint"),
    ("terminal_carry", "Schoolbook.columnConstraint 256 0 0 1",
     "Schoolbook.columnConstraint 256 0 0 0", "Schoolbook.columnConstraint"),
    ("digest", "RiscvRefinement.M31.reduce (2^32-1) = 1",
     "RiscvRefinement.M31.reduce (2^32-1) = 0", ""),
)

SOURCE_MUTATIONS = (
    ("byte_range", "Radix.lean", "word < 65536 ∧ scaled < 65536",
     "word < 65536 ∧ scaled < 16777216"),
    ("carry_base", "Radix.lean", "digit + (base : Field.F) * cout",
     "digit + ((base - 1 : Nat) : Field.F) * cout"),
    ("signed_guard", "Signed.lean",
     "def addOverflow (sa sb sr : Field.F) : Prop := (1 - (sa - sb)^2) * (sa - sr)^2 = 0",
     "def addOverflow (sa sb sr : Field.F) : Prop := (1 - (sa - sb)^2) * (sa - sr)^2 = 1"),
)


def compile_lean(lake: str, project: Path, source: Path) -> subprocess.CompletedProcess:
    try:
        return subprocess.run([lake, "env", "lean", str(source)], cwd=project,
                              capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise FormalError(f"cannot run Lean control: {error}") from error


def run(root: Path, lake: str) -> dict:
    project = root / "formal/s31"
    preamble = "import S31\nnamespace S31.MutationControls\nopen Gadgets\n"
    with tempfile.TemporaryDirectory(prefix="s31-lean-controls-") as temporary:
        directory = Path(temporary)
        source = directory / "Control.lean"
        true_theorems = []
        for name, honest, _, unfold in WITNESSES:
            tactic = f"unfold {unfold}; " if unfold else ""
            true_theorems.append(f"theorem honest_{name} : {honest} := by {tactic}decide\n")
        source.write_text(preamble + "".join(true_theorems) + "end S31.MutationControls\n")
        result = compile_lean(lake, project, source)
        if result.returncode != 0:
            raise FormalError("honest Lean controls did not compile:\n" + result.stdout + result.stderr)
        for name, _, false_claim, unfold in WITNESSES:
            tactic = f"unfold {unfold}; " if unfold else ""
            source.write_text(preamble + f"theorem forged_{name} : {false_claim} := by {tactic}decide\n"
                              + "end S31.MutationControls\n")
            result = compile_lean(lake, project, source)
            output = result.stdout + result.stderr
            if result.returncode != 1 or "is false" not in output:
                raise FormalError(f"{name}: Lean did not reject the false proposition as expected:\n{output}")
        for name, module, before, after in SOURCE_MUTATIONS:
            original = (project / "S31/Gadgets" / module).read_text()
            if original.count(before) != 1:
                raise FormalError(f"{name}: source mutation anchor changed")
            source.write_text(original)
            result = compile_lean(lake, project, source)
            if result.returncode != 0:
                raise FormalError(f"{name}: unmodified gadget did not compile")
            source.write_text(original.replace(before, after))
            result = compile_lean(lake, project, source)
            output = result.stdout + result.stderr
            if (result.returncode != 1 or "error:" not in output or
                    any(marker in output for marker in ("unknown module", "unknown identifier",
                                                       "object file", "failed to synthesize"))):
                raise FormalError(f"{name}: mutated gadget did not fail its proof:\n{output}")
    return {"honest_witnesses": len(WITNESSES), "rejected_false_witnesses": len(WITNESSES),
            "rejected_gadget_mutations": len(SOURCE_MUTATIONS)}
