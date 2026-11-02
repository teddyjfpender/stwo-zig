# Shared GKR verifier authority and actual circuit cost gate

Experimental engineering qualification. Production Word16 services, proof acceptance and security profiles remain unchanged. There is no production GKR receiver, whole recursive GKR proof,128-bit certificate or GPU qualification in this change.

The numerical verifier now has one authority in `src/prover/lookups/verifier_kernel.zig`. Existing QM31 GKR and sumcheck entry points are compatibility wrappers; the circuit adapter executes that same control flow and arithmetic on `rv64_recursion/circuit_lane.Lane` wires. It supplies equality gates instead of host comparisons and the existing native-protocol Blake channel gadget instead of host transcript hashing. Prover algorithms and wire format are unchanged.

`logup_gkr/circuit_verifier.zig:wireProof` guesses proof coefficients, layer masks and output claims. It never interns those witness values as constants. Coefficient lengths are structural metadata from the admitted experimental proof; no circuit-side value-based trimming occurs. Production still needs a receiver-owned fixed frame/shape policy and whole-leaf binding. The adapter latches channel allocation errors, and callers must check both channel completion and the lane's finish before accepting a graph.

The native verifier preserves its error mapping and transcript order, including the historical `Gate.eval` allocation error mapping. Its final claim ownership transfer is now failure-atomic: all optional claims are validated and both output allocations complete before ownership moves. A test injects failure at every native allocation. `MAX_DEGREE` is shared by sumcheck and its numerical kernel.

The mini-AIR's MLE point, row/lane weights, carry selector, anchors and weighted-prefix residuals likewise share numerical authority between QM31 and circuit wires. The core geometry conversion accepts the existing `fromBase` lane interface. The circuit lane's inverse now guesses zero for an invalid zero denominator and emits the usual nonzero inverse equality, producing an unsatisfied graph instead of panicking in value-mode division. Valid inverse witnesses retain the original guess/mul/equality order and topology.

## Actual graph evidence

The real input is the previously qualified **historical, pre-LS32-inheritance** LS range witness captured from Ethereum packet0: LS log20 plus tail log18, U16 log16 and U8 log8,16 fractions per row. Current LS32/LS7 has4U16+4U8 queries and no old physical U8 map; this16-lane mini-family is not the current service lane's complete debt or saving estimate. Capture now refuses unsupported layouts explicitly instead of compiling stale columns or inventing a new mapping. Produce/verify of pinned historical witnesses remains supported. The original bundle's SHA256 is `d6a9de7f3f31f115f72746ba9e1690a4cdada0993fd6147f192b03981b442255`. The oracle independently fresh-verifies that whole mini-AIR proof with receiver-selected q70/P26 geometry before building its circuit fragment.

| Graph stage | Blake G gates | QM31-op rows | M31→u32 rows | Triple-XOR rows | Equality rows | Variables |
|---|---:|---:|---:|---:|---:|---:|
| GKR partial verifier, actual raw-Blake transcript | 83,040 | 25,280 | 5,520 | 8,304 | 300 | 372,595 |
| Plus root fraction closure, terminal numerator checks, binding arithmetic/residuals and finalization | 83,440 | 42,107 | 5,576 | 8,344 | 1,171 | 389,787 |

The circuit component authority assigns MAIN+INTER widths8(EQ),20(QM31ops),16(M31→u32),44(triple-XOR) and104(Blake-G). That converts the measured stages to9,597,856 and9,985,620 active cells respectively, before preprocessed/fixed providers or padding. The receipt includes the per-role calculation. Existing production registry padding to log23 for both QM31ops and Blake-G can mask small raw gate savings unless the admitted target also shrinks.

The first stage emits exactly1,038 Blake compressions, matching the earlier numerical transcript count, rather than treating hash outputs as host constants. The second stage adds855 constrained inversions in total. QM31-op rows include packed pointwise operations used by hash conversion; they should not be read as a count of scalar extension multiplications. Operation counters are retained separately in the JSON.

A source-sized log22 row-point initialization plus carry/anchor evaluation emits9,428 QM31-op rows,560 equalities and557 inversions; lifting a global log25 point down to that row log adds21 op rows. Tests also cover local/lifted logs3,5 and10. This is the concrete O(n²) selector cost omitted by an opening-width-only model.

The fragment builds in roughly5ms in one ReleaseFast diagnostic process, with approximately16.7MB peak RSS and15.8MB peak memory footprint in the measured run. **This is graph construction/checking, not circuit proving or recursive verification time.** No speedup is claimed from these numbers. Both recorded runs emitted identical graph counts.

For the isolated LS pair, classic INTER width88 becomes32. At70 trace queries this removes at most280 leaf-hash compressions, versus1,038 introduced by the GKR transcript alone, before binding arithmetic. Direct Blake-backed GKR is therefore a poor recursion tradeoff for this isolated family. A larger batch of proof-local relations can amortize the common sumcheck transcript differently; its full, equally secure leaf must be measured before production adoption. No comparison against a96-control establishes the128-bit target.

## What the diagnostic verifies

`rv64-gkr-circuit-cost` takes a native bundle and four receiver-selected logs. It verifies the full native mini-AIR, reconstructs the native transcript prefix, guesses the corresponding prefix/witness wires, executes shared numerical GKR and checks exact transcript agreement. It builds root-fraction closure, terminal numerator equalities, shared row/lane binding weights, actual OODS seed mapping, local-point lifting, carry/anchor expressions and the weighted-prefix residuals on actual native-authenticated sampled values.

Source review also found a pre-existing rare-branch limitation in the reused native-channel gadget: its comment says draws containing any raw word >=2p are rejected, but `drawSecureFelt(s)` currently reduces the selected words and does not constrain this condition on all eight words. Native raw Blake sampling instead rejects the whole draw and retries. Our recorded bundles match exactly, but universal transcript parity and the comment's claimed fail-closed behavior are not qualified. This is a protocol discrepancy, not by itself a demonstrated AIR-unsoundness attack. It must be repaired or explicitly analyzed before production GKR/whole-protocol certification. A separate nonretry profile could constrain all eight packed-u32 words away from0xfffffffe/ffffffff, rejecting rare native-redraw proofs; implementing retries or changing admitted leaf topology needs separate qualification. This change does not silently alter that shared hash authority.

The resulting graph is checked for satisfaction. It is deliberately a **fragment**: the prefix seed, challenges, roots and sample inputs still rely on the independent native verifier. Diagnostic equalities compare binding values/residuals with native oracle values; they do not replace their full PCS/DEEP/FRI authentication inside a recursive circuit. That remaining integration is a necessary production gate. Returning a GKR artifact without connecting its terminal input claims is explicitly not complete verification.

The smaller prover-backed mixed-height fixture has a stronger isolated terminal test: it evaluates the entire input MLE directly from guessed input values inside the circuit, then uses the shared terminal equality authority. It rejects altered sumcheck coefficients, masks, terminal claims and input expressions by unsatisfied constraints. Native mutation paths retain their expected errors. A degenerate row binding point is rejected natively and yields an unsatisfied circuit without a value-mode panic.

## Reproduce

```
zig build test-riscv64-gkr-circuit -Doptimize=ReleaseSafe -j4
zig build test-riscv64-gkr-circuit -Doptimize=ReleaseFast -j4
zig build test-riscv64-logup-gkr-prototype -Doptimize=ReleaseSafe -j4
zig build test-riscv64-logup-gkr-prototype -Doptimize=ReleaseFast -j4
zig build test-riscv64-recursion-circuit -Doptimize=ReleaseSafe -j4
zig build rv64-gkr-circuit-cost -Doptimize=ReleaseFast -j4
zig-out/bin/rv64-gkr-circuit-cost PROOF.bin 20 18 16 8
```

The receipt retains the381,800-byte original qualified real bundle as `real-ls20-tail18.proof.bin`, so the cost oracle and fresh native verification are reproducible without the41.9MB captured witness. A fresh producer run on that original witness under the shared heavy lock regenerated the exact same proof bytes and passed a separate receiver. The witness is intentionally retained outside source control. The module owns no worker pool, starts no prover processes and retains no global caches. The CLI uses a bounded16MiB input file and a caller-owned graph context; all scratch and artifact allocations are released at exit. Original worktrees are untouched.

Next steps are a reviewed whole-protocol security architecture, a fixed production GKR shape/framing, a complete in-circuit binding/PCS join under that authority, and an equally secure classic-versus-GKR complete-leaf proving comparison. The negative isolated-family hashing result should inform that choice rather than be hidden behind native cell savings.
