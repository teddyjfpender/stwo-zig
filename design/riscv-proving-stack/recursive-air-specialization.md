# Recursive AIR specialization: measured parent route

This pass reduces the work represented by the recursive verifier. On three alternating rounds using the same retained q193 children, the complete parent request fell **22.770 → 13.244 seconds on CPU (41.8%)** and **16.519 → 10.886 seconds on Metal (34.1%)**. Each producer exited before a fresh verifier accepted the serialized proof. The optimized parents also compose into freshly verified four-segment CPU and Metal trees. A changed memory input passes under the same seven circuit keys.

The authoritative [measurement index](../../vectors/reports/riscv-proving-stack-reset-20260908/small-detached-recursion-v1/air-fusion-measurements.json) links the original reports, source pins, frozen binaries, build receipts, static accounting and diagnostic profiles. The twelve paired roots and two diagnostic roots passed **386 acceptance/rejection cases** in total. The baseline and candidate each reproduce identical artifact bytes across CPU, Metal and repeats. Their proof bytes differ across AIR versions, while the independently supplied public root remains identical.

## Endpoint and comparison

The endpoint proves verification of two retained parent children from the four-segment development workload: 227 retired RISC-V instructions and one memory address. It does not regenerate the native leaves or the children during this request. The complete producer request includes preparation, fixed-column/key admission, proof generation and serialization. Fresh standalone verification is a separate process and a separate timing.

The q193 profile remains experimental: 193 FRI queries, fold 4, PCS proof-of-work 16 bits and interaction proof-of-work 10 bits. These parameters and the child-proof checks are unchanged. This is not a certified production-security result or an Ethereum-block benchmark. CSP benchmarks were excluded by user instruction.

Each backend used three rounds in before/after, after/before, before/after order. The baseline is the frozen `ee7de71f` parent implementation; the candidate is pinned in `air-fusion-final-source.json`. Compare the paired observations here, rather than treating older runs under different conditions as the baseline. CPU and Metal ran serially.

| Median metric | CPU before → after | Metal before → after |
| --- | ---: | ---: |
| Complete parent request | 22.770 → 13.244 s | 16.519 → 10.886 s |
| Preparation | 3.921 → 3.574 s | 3.996 → 3.735 s |
| Fixed columns/key preparation | 3.412 → 1.243 s | 1.225 → 0.587 s |
| Proof generation | 15.153 → 8.220 s | 10.833 → 6.367 s |
| Peak process RSS | 5.664 → 3.643 GiB | 7.035 → 4.085 GiB |
| Fresh STARK verification | 77.013 → 70.089 ms | 76.638 → 70.328 ms |
| Fresh verifier request | 79.739 → 71.794 ms | 79.457 → 72.185 ms |
| Serialized proof | 2.317 → 2.192 MiB | 2.317 → 2.192 MiB |

Peak RSS is the maximum process resident set reported by `/usr/bin/time -l`, not a separately attributed GPU allocation. Medians of component phases need not sum to the median complete request. The roughly 70-ms fresh STARK verifier is distinct from the seconds spent proving that verification recursively.

## What changed

**Multiply-add AIR.** The detached parent now uses an explicitly admitted degree-two multiplication/multiply-add component at row 30. It fuses a multiply with add/subtract only when the product has exactly one authenticated use. The intermediate consume/emit pair disappears; all external wire occurrences and final output multiplicities remain unchanged. Main plus interaction storage falls from 56 cells for a separate multiply/linear pair to 25 cells for the fused row. Plain multiplications use the same new component. Fixed schedule coordinates live in preprocessing instead of being duplicated in the main trace.

**Opening accumulation AIR.** A second degree-two component at the previously unused parent slot 14 directly constrains an accumulator plus four QM31 products. Its matcher runs before ordinary multiply-add fusion and reserves all eight replaced operation nodes. Every hidden intermediate must have exactly one authenticated use, including graph outputs and cross-circuit exports. The retained root contains 238,914 such rows; 218,754 (91.6%) come from the two PCS opening graphs. The remaining FRI arithmetic also benefits from the shared multiply-add matcher: 110,031 matches in each FRI graph. No separate FRI-fold component was added in this pass.

**Poseidon layout.** A versioned universal provider uses two witness columns per S-box while retaining cubic constraints, all permutation rounds, padding constraints and the existing narrow/wide/atomic-IO relation semantics. Main width falls from 445 to 303 columns. The root still performs 185,430 provider permutations; this is cheaper representation of the same required permutations, not removal of Merkle/transcript checks. The legacy and new degree-three providers share one schedule/component implementation where their responsibilities coincide.

All new constraints and lookup effects come from the typed AIR or authenticated shared provider definitions. Native verification and recursive recording select legacy/new adapters from exact admitted geometry, including semantic identity. Retained legacy children therefore keep their original constraints. The new parent receives a new independently supplied key; incompatible input keys are rejected.

Preparation scratch, original lowering buffers, match indices and growable row buffers are separated from the immutable final rows. Compact indices use four bytes per graph node. Final rows are copied once into their owner, and scoped scratch is destroyed before downstream proving allocations.

## Trace attribution, not isolated runtime attribution

The [static trace accounting](../../vectors/reports/riscv-proving-stack-reset-20260908/small-detached-recursion-v1/air-fusion-static-trace-costs.json) uses actual retained row counts, authenticated component widths and power-of-two padding. Those counts were rechecked against the final candidate producer. Total preprocessing, main and interaction trace storage falls **1,648,523,712 → 935,492,032 bytes (43.25%)**, before polynomial expansion.

| Sequential trace counterfactual | Main/interaction bytes saved | Preprocessing bytes saved |
| --- | ---: | ---: |
| Compact arithmetic and multiply-add fusion | 219 MiB | 253 MiB |
| Four-term accumulation beyond multiply-add | 39 MiB | 27 MiB |
| Compact Poseidon provider | 142 MiB | 0 MiB |

The arithmetic-only counterfactual replaces each four-term row with four multiply-add rows and recomputes table padding. Attribution is order-dependent because components share padded tables. These are storage counterfactuals, not three independently timed implementations; their percentages must not be added as runtime savings. The combined implementation is the route measured end to end.

## Remaining measured work

One additional candidate profile was recorded per backend. These observations explain the remaining work; they are not medians or isolated optimization effects.

| Diagnostic phase | CPU | Metal |
| --- | ---: | ---: |
| Fixed columns/key | 1.359 s | 0.564 s |
| Main filling, range construction and exact lookup closure | 2.507 s | 2.641 s |
| Main commitment | 1.400 s | 0.660 s |
| Transcript and interaction filling | 1.600 s | 1.611 s |
| Interaction commitment | 0.931 s | 0.341 s |
| Composition evaluation | 0.968 s | 0.944 s |

Preparation still takes roughly 3.6–3.7 seconds in the paired medians, and main finalization plus interaction filling is now larger than composition. Exact lookup closure and composition both execute successfully in the complete root proof. Their cost has been reduced, not eliminated.

Recursive composition on the Metal route still uses the optimized host evaluator. Metal accelerates other proving phases; these results do not establish GPU execution of every recursive component. The separate admission work described in [recursive Metal composition](recursive-metal-composition.md) remains necessary before claiming that boundary has moved to the GPU.

## Gates and remaining promotion work

Completed local gates include signed arithmetic and exact wire-boundary differential checks, genuine graph fan-out/export/reservation cases, degree checks, every-coordinate mutation checks, and standalone serialized Poseidon proofs with producer destruction and fresh verification. The arithmetic focused gate passed 17 tests; the expanded opening gate passed 89; the final Poseidon semantic/admission gate passed 12. Source and frozen binary hashes were rechecked against the successful CPU and Metal build receipts, which report no source changes during compilation.

The first focused loops took seconds to compile and under a second to execute. The final CPU producer/verifier build command elapsed 159.2 seconds and the Metal producer command 256.2 seconds; those command observations can include the serial build-lock wait and are not isolated incremental-compilation measurements. The existing frontend inventory has 156 pre-existing missing test-bearing paths, retained in its audit report; no full-inventory pass is claimed.

The final integration gates pass:

- A root consuming two optimized intermediate parents passes all 28 fresh-process cases.
- Complete CPU and Metal four-segment trees each pass 136 cases. All 21 proof/key/claim artifacts match across backends.
- A second CPU tree changes the initial memory word from 13 to 14, retains all seven circuit keys, changes all seven proofs, and passes another 136 cases.
- The final artifact audit rechecks source, binary, input, step-log and proof pins. It counts 878 fresh acceptance/rejection cases across the paired/profile roots, three bootstrap parents and three complete trees.

| Complete four-segment production | CPU | Metal |
| --- | ---: | ---: |
| Native leaves plus leaf wrappers | 40.750 s | 33.649 s |
| Three recursive parents | 39.018 s | 32.186 s |
| Total production | 79.768 s | 65.835 s |
| Complete gate including hostile cases | 83.351 s | 69.507 s |
| Peak process RSS | 3.629 GiB | 4.070 GiB |

These tree timings are single observations, separate from the paired root medians. The previous retained tree observations were 103.949 s CPU and 82.435 s Metal; those historical comparisons are not paired measurements. Leaf proof/key/claim bytes remain identical to the earlier route. The current maintained command and separately reviewed admission are in [the small proof guide](small-recursive-benchmark.md).

The initial gate failure is retained: its old assertion expected row14 to be inactive, while the new AIR correctly rejected the changed claim at lookup closure. The corrected gate determines activity from the admitted manifest and additionally rejects a balanced active-claim mutation. No rejected proof was accepted to make the gate pass.

This completes the three-candidate optimization pass on the small functioning route. Production-security admission and GPU execution of recursive composition remain separate work.
