# Local recursive AIR checks

The focused Lean gate checks 10 local theorems using the existing Lean 4.29.0 project and its concrete canonical M31 arithmetic modulo 2,147,483,647. No dependency was added. These polynomial and additive identities do not require a primality assumption. They do not establish whole-prover soundness or production security.

```sh
python3 formal/riscv-refinement/check_recursive_air.py
# Source admission only, without compiling:
python3 formal/riscv-refinement/check_recursive_air.py --source-only
```

The command checks the reviewed 15-source mapping, builds the two theorem modules, freshly audits all 10 public theorems, then rechecks sources against concurrent drift. It uses the repository's heavy-job lock. The retained `formal/riscv-refinement/recursive-air-check-report.json` contains exact commands, timings and axiom output. The current proofs depend only on `propext` and `Quot.sound`; the gate rejects nonstandard axioms and incomplete theorem discovery.

| Runtime boundary | Lean result | Scope |
| --- | --- | --- |
| `poseidon2_universal_degree3_v1.zig`, `Fill.sbox` / `Evaluate.sbox` | `CompactPoseidon.accepted_output` and `honest_witness` | `square - x*x = 0` and `fifth - x*(square*square) = 0` imply exactly `fifth = x^5` in M31. The implication has no enabler premise and applies to padding too. |
| Shared `poseidon2_degree3_schedule.zig` and matrix functions in `poseidon2_air_runtime.zig` | `CompactPoseidon.unchanged_context` | Pointwise S-box equality permits substitution into any unchanged enclosing context. The correspondence to the actual round sequence, constants and Zig code is explicitly reviewed and source-pinned; it is not an extracted full-program refinement. |
| `universal_typed_component_component_for_manifest.zig`, `evaluateBaseRowInto` / `frameworkConstraint` | `FrameworkBoundary.telescope` and `row_boundary` | Nonfinal batches are **same-row** cumulative differences. Only the final batch subtracts the previous row and adds the claim shift. The zero-based same-row prefix telescopes for any batch count, including one. |
| `framework_interaction.zig`, `generatePreparedIntoInternal` | `FrameworkBoundary.rows_boundary`, `sum_constant`, `claim_boundary`, `secure_claim_boundary` | A cyclic final-column prefix makes the sum of normalized row contributions equal the claim, provided `trace_size * shift = claim`. Arbitrary common prefix offsets are allowed; the witness generator chooses the representative ending at zero. Addition/subtraction are treated coordinatewise over four M31 coordinates, matching QM31's additive representation. |

The implementation uses **x^5**, not x^7. The permutation constants, degree-three materialization and exact runtime equations determine the formal statement.

`frameworkConstraint` multiplies the normalized difference by the paired denominator and subtracts its numerator. The boundary theorems start after that relation has been normalized. Nonzero denominators, inverse correctness, `shift = claim / trace_size`, challenge security and global lookup soundness remain explicit external obligations. The bulk inversion's zero-denominator rejection and division checks are runtime gates, not newly proved field-inverse theorems.

The source map is `formal/riscv-refinement/recursive-air-source-map.json`. Drift fails the command and requires reviewing the equation correspondence before updating a pin. This mapping is not a proof that Zig's optimized field operations, vector reductions, compiler or backend implement Lean's arithmetic. Existing differential and complete-proof gates remain necessary. Both theorem modules are imported by the normal refinement root so its broader axiom audit also sees them.

The component's backend capability callback exports the same admitted equations to the Metal generator. The exporter and generated Metal program are outside this local formal mapping; their contract checks and actual GPU parity gate remain separate evidence.
