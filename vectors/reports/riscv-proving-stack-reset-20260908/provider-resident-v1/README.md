# Recursive provider composition on resident Metal

This continues the strict Metal goal from `80e73583`. The 227-instruction,
one-address fixture contains four native proofs, four leaf wrappers, two
intermediate parents and one root. It is not an Ethereum block or a
production-security benchmark.

## Verified result

All recursive composition components now have executed GPU coverage:
**39/39 wrapper components and 31/31 parent components**. The authenticated
extension has 51 kernels. Wrappers dispatch 38 framework jobs plus four direct
Poseidon partitions and one Poseidon lookup; parents dispatch 30 framework jobs
plus the same five provider jobs. Each recursive receipt reports zero host
composition components. These counts describe component evaluation, not every
operation required to construct a proof.

Both the full CPU/GPU composition-parity tree and the unshadowed tree pass all
136 fresh acceptance/rejection cases. Producers exit and release their owners
before independent verification. All 21 serialized proof/key/claim artifacts
are byte-identical to the retained `framework-resident-v1` tree, which itself
matches the original e5 baseline. Exact commands, environments, executable pins,
report hashes and artifact hashes are in the adjacent top-level tree receipts.

| Measurement | Observation |
| --- | ---: |
| Complete unshadowed production | 61.206 s |
| Complete hostile-input gate | 65.010 s |
| Maximum process RSS | 4,381,343,744 bytes |
| Root request on identical retained children | 10.311 s |
| Root composition evaluation | 0.163565 s |
| Root framework kernels | 12.148 ms |
| Root Poseidon direct kernels | 11.939 ms |
| Root Poseidon lookup kernel | 1.026 ms |

The original core route's diagnostic composition was 0.993760 s; the intermediate
partially accelerated route was 2.281791 s because its remaining Poseidon host
worker dominated. The new observation removes about 84% of the original
composition time and 93% of the intermediate phase. Entire-tree observations
were previously 65.835 s and 71.690 s respectively. These are single observations,
not paired medians or evidence of an orders-of-magnitude complete-request gain.
The parity tree takes 129.726 s production because it deliberately repeats CPU
work; never use it as an optimized timing.

Root preparation (3.678 s), main filling/closure (2.593 s) and interaction filling
(1.660 s) now dominate. Native composition still reports nine host components:
six fixed tables, program, Merkle and clock update. Witness generation,
preparation, lookup closure and interactions also remain host work. Strict tree
and parent requests still reject with `MetalHostWitnessGenerationForbidden`
and `MetalHostRecursivePreparationForbidden`; their exact negative requests
are retained. Full strict GPU-only proving is **not passed**.

## One equation authority and explicit layout

Legacy universal Poseidon exposes its existing backend DAGs. Compact universal
Poseidon specializes the existing narrow exporter around its native evaluator;
narrow IDs and behavior remain unchanged. Both preserve native independent
running sums and per-batch claims. No AIR, transcript or proof parameters change.

Range uses the existing authenticated bridge and native component coordinates.
The shared program adds `independent_prefix_v1`, with an explicit preprocessing
selector slot and one raw claim per batch. Each batch reads its own previous-row
sum; it never borrows the framework's same-row-prefix or mean-shift rule.
Relation-only programs have genuinely zero direct roots. Existing layout1
identity encoding remains unchanged. Kernels and invocation packing consume
this same explicit layout; no handwritten range AIR was added to Metal.

The scheduler resolves direct and framework AOT programs before bulk expansion
or ambient host work, and releases legacy scratch after its final device/parity
consumer before framework groups acquire the bounded owner window. It no longer
requires overlapping scratch owners for the two families. The recursive AOT
profile dispatches small mixed providers without the core profile's crossover
threshold. Core shaders and default profile remain unchanged.

The bundle is `.git/local-riscv-proving-stack/provider-aot-m4-v1`, manifest
`98703ad708efeb6aee92403f0d818498fb97b91174b3a597b42925d64fd82da7`.
`aot-bundle-pin.json` records every artifact. The source catalog is reproduced by
the maintained `test-riscv-metal-recursive-aot` command; generation and two exact
source-check receipts are retained. Composition coverage is complete;
`strict_coverage_complete` deliberately remains false.

## Focused gates and source scope

- Compact provider/native parity: 231/231 tests. Distinct relation challenges,
  modes, padding, altered rows, selectors and claim order are exercised.
- Shared range export: 238/238 tests in ReleaseFast, also passed ReleaseSafe.
  Mapped inputs, extension-field parity, zero direct roots, changed tuples,
  multiplicities, selectors, previous sums, claims and allocation failures are
  covered. The initial invalid-constructor negative fixture is retained with
  its failure; the corrected test mutates an explicit malformed field limb.
- Actual generated Metal: 15/15 tests, 135 cases, 180 GPU dispatches and 36,960
  coordinates. The new layout includes two distinct claims and previous sums,
  non-Boolean off-domain selectors, zero direct roots, arities 33/2/1 and
  quotient geometries 2/4/8 across both circle halves.
- Final backend/codegen/ownership checks: 31/31 tests. Profile/coverage CLI
  checks: five Python tests. Exact catalog regeneration and both producer
  builds pass. The two initial misspelled test-step invocations are retained.
- Formal source correspondence still passes unchanged; this does not add a
  new theorem or certify the whole proof system.

`producer-source-snapshot.json` pins the successful binaries' source. After
those proofs, host-component accounting moved past AOT admission so an early
decline is not counted again by terminal fallback. Host coefficient-fill
admission also moved from the framework caller into the shared scratch owner,
closing the semantic/lookup caller gap before allocation or runtime access.
Hybrid field arithmetic is unchanged. The shared scratch gate passes 20/20
tests, including strict rejection with no available allocation or initialized
runtime. The final source snapshot identifies these post-build deltas; full-tree
timings refer to the frozen binaries, not to a silently relabeled build.

## Next measured boundary

Parent interaction filling still selects the serial Poseidon writer, whereas
the leaf uses the existing chunked batch-inversion writer. Reusing that writer
is a small measurable algorithm improvement; it does not establish GPU coverage.
For device interactions, prepare a claims-free immutable lookup program from
existing admitted plans before challenges are drawn, then supply actual
challenges and return claims. Reuse GPU block scans/scatter, but add independent
prefix finalization and explicit zero-denominator rejection. Preserve typed
padding's zero numerator/unit denominator semantics. Do not fabricate admitted
components with placeholder claims or silently normalize independent providers.
