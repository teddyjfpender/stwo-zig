# Track C5: RV64 composition IR export

Composition evaluation is 36% of prove time (`cost-per-cell.md`). The GPU plan needs one
generated kernel body per component. This track exports every Word16 v3 component's
constraint evaluation into a field-generic DAG, checks it bit for bit against the native
evaluators, and publishes per-component kernel weights in `composition-ir-stats.json`.

## Format: `secure_polynomial_program_v2` (compatible extension of v1)

`src/prover/air/secure_polynomial_program_v2.zig`. It keeps v1's `Op` encoding, its
topological node order, parameters as ordered invocation data that the identity does not
cover, and roots as ordered residuals folded with reversed random powers. It adds the
things v1 cannot express:

- signed mask offsets per input (Keccak reads rows −2..+2), where v1 only has `previous`;
- per-program layouts in place of v1's six fixed `Kind` shapes, and larger caps;
- the secure field as a compile-time parameter: `ProgramFor(QM31)` today, `ProgramFor(OM31)`
  for the 128-bit route. Constants live in a table sized to the field degree.

`fromV1` converts any v1 equations program without loss; a test checks this.
`BuilderFor(F)` hash-conses nodes (common-subexpression elimination) and applies only exact
field rewrites: literal folding, x+0, x·1, x·0, x−x, −(−x). Dead nodes are removed.

## Recording: the symbolic lane

`src/frontends/riscv/rv64/air/symbolic_lane.zig`, dispatched in `evaluation.zig` through
`isSymbolicLane` branches. It is a native-constant lane: `ConstFor(Lane) == QM31`. Each
component's own Q-typed instance, the same one the prover runs, executes its generic
`emitFor(F, …)` (or its generic point authority) with F set to the symbolic lane:

| Source in the component | IR node |
|---|---|
| Mask read | `input(tree, local column, offset)` |
| `qFor` integer literal | `constant` |
| `splatFor` / `scalarFor` (FS challenges, claims, public counts) | `parameter` |

No equation was copied or rewritten. Integer publics that a component passes through
`qFor` directly (LS-D64 `rows`, bulk-memory row counts) stay literals, so those kernels are
specialised to that row count. Moving them to `scalarFor` would make them parameters.

## Coverage and parity

`src/integrations/riscv_cpu/composition_ir/`:

| File | Contents |
|---|---|
| `catalog.zig` | CPU-proof core: CPU classic / fused tail / U8 pairs / compact decode (plus the log-23 wide-clock fused CPU, statistics only), ROM, JALR, register boundary, range16/8 tables, ALU classic/fused, BINARY, AND and AND-pair tables, SHIFT, SHIFT table, DIV, MUL classic/pairs, LS32 / INIT / TEARDOWN classic and fused pairs, LS selection |
| `catalog_services.zig` | Service bridges: Keccak bridge; secp bridge for add, double, sha256, arith256_mod and 7 curve families; bulk desc/copy/set/ucopy/cdesc/cmp/jdesc/jscan/jtab (JUMPDEST); sponge call/perm; LS-D64 plain/fused pairs |
| `catalog_truths.zig` | Truths: Keccak permutation for triple_v2, throughput, quartet and r27, plus chi/xor5 tables; secp add/double product/linear and bytes; SHA-256; arith256_mod; 7 curve ops; secp row add/double |

- **Random-trace parity**, all 75 cases. Random trace polynomials are evaluated on the
  evaluation domain. The component's real prover domain evaluator (packed, native or coset
  kernels, with the vanishing division) must equal the IR reference interpreter
  (`record.zig: evaluateDomain`) on every row. The test also requires a non-vacuous result
  and rejects a forged constant.
- **Honest-trace parity**. A test-only observer on
  `ComponentProvers.computeCompositionEvaluationForBackendDiagnosed`, compiled out of
  non-test builds, captures the committed trace and every live handle of real v3 proofs.
  It recognises each handle's type by its static vtable, records that exact instance, and
  checks the IR against the native evaluator on the component's real columns
  (`honest.zig`, `test_honest.zig`).
- **Honest coverage (measured).** `test-riscv64-composition-ir-honest` runs 11 tests over 17
  real fixture proofs: v3 services in the classic, fused-tail, byte-pair and compact-decode
  layouts; LS-D64 plain and all-fused; JUMPDEST; unaligned copy and compare; all 7 curve ops
  on the fused-pair + LS-D64 layout; and the Keccak sponge with triple_v2 and throughput
  Keccak-f truths. Every observed handle was recognised (0 unrecognised), and all 66
  distinct component kinds were bit-exact on their real committed columns.
  Covered by random traces only: secp truths (product, linear, bytes), secp row truths,
  secp_bridge.add/double, and the Keccak quartet/r27 permutations. The log-23 wide-clock CPU
  is recorded for statistics only.
- **Generated C**. `emit_c.zig` emits one statement per IR node, so subexpressions are
  shared. It uses M31 scalar code for base nodes and QM31 code only after a parameter enters,
  and fuses the random-power fold with the vanishing-inverse scale. `test_emit_c.zig`
  compiles the CPU fused-tail row with `cc`, loads it, and checks it bit for bit against the
  IR and the native evaluator.

Run the checks with `zig build test-riscv64-composition-ir{,-services,-truths,-honest}
-Doptimize=ReleaseSafe` and the statistics with `zig build rv64-composition-ir-stats`, then
`zig-out/bin/rv64-composition-ir-stats OUT.json`.

## Reading the statistics

All counts are per evaluation-domain row. `distinct_subexpressions` is the node count after
CSE and folding. `requested_lane_ops` is what the native emitter calls before folding and
CSE. `m31_mul_equiv_per_row_{qm31,om31}` counts:

- expression products, weighted base·base = 1, base·secure = degree, secure·secure = 9 (QM31)
  or 27 (OM31);
- the fold: one power times each residual;
- the final scale by the vanishing inverse.

It does not count additions or memory traffic. `eval_rows_per_trace_row` is the
evaluation-domain expansion: 2 for degree 3, 4 for Keccak, secp and secp-row at degree 4–5.
