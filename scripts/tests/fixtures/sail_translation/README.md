# Reconstructed generated-Sail definition fixtures

**These files are NOT captured generated output.** No Sail compiler is installed
in the environment where they were written, and this repository does not commit
a copy of the pinned theorem-backend file

`build/riscv-refinement/Lean_RV32IM/LeanRV32IM/InstsEnd.lean`

so there was nothing to capture. `execute_UTYPE.lean` and `execute_ITYPE.lean`
are *reconstructions*: hand-written Lean text pinned to the literal strings that
`scripts/riscv_refinement_lib/sail.py::_validate_semantic_shapes` already
asserts must appear in the real generated definitions, plus the surrounding
syntax those strings imply (a `def` header with binders, a monadic `do` body, a
pure `let`, a monadic `let ... ←` holding the selector `match`, a `wX_bits`
write statement, and a terminal `(pure RETIRE_SUCCESS)`).

The strings carried over verbatim from `_validate_semantic_shapes` are:

| definition | pinned string |
| --- | --- |
| `execute_UTYPE` | `sign_extend (m := 32) (imm +++ 0x000#12)` |
| `execute_UTYPE` | `\| .LUI => (pure off)` |
| `execute_UTYPE` | `(wX_bits rd` |
| `execute_UTYPE` | `(pure RETIRE_SUCCESS)` |
| `execute_ITYPE` | `sign_extend (m := 32) imm` |
| `execute_ITYPE` | `\| .ADDI => (pure ((← (rX_bits rs1)) + immext))` |
| `execute_ITYPE` | `(wX_bits rd` |
| `execute_ITYPE` | `(pure RETIRE_SUCCESS)` |

Everything else — the `AUIPC` alternative, the five non-`ADDI` `iop`
alternatives, the binder types, and the `SailM Retired` result type — is
inferred from the pinned Sail source (`model/extensions/I/base_insts.sail`)
and from how a Lean backend must render it. It is plausible, it is not
authoritative, and it may differ from the real backend in whitespace, in
operator spelling, or in how `zero_extend`/`bool_to_bits` are emitted.

## What the fixtures are therefore evidence for

They exercise `scripts/riscv_refinement_lib/sail_translation.py`: that the
parser, the normalization pass, and the receipt are total on this syntax, that
they extract the right observable effects, and above all that they **fail
closed** on drift. They are evidence about the receipt machinery.

They are **not** evidence about the pinned Sail model. The receipt only becomes
evidence about Sail when it is re-derived from the real generated
`InstsEnd.lean` slices on a host that has the pinned Sail 0.20.2 compiler. Until
then the open obligation stands exactly as issue #137 states it, and no comment,
receipt field, or test name in this directory may be read as closing it.

If the real generated syntax turns out to differ, the correct response is to
extend the parser and regenerate the receipt — never to relax the parser into
accepting unparsed text.
