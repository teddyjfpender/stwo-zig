# Field-selected GKR numerical authority

`gkr_prover.ForField(S)` and `gkr_verifier.ForField(S)` select one numerical
implementation for QM31 or OM31. The original public names remain aliases of
`ForField(QM31)`; the original channel and proof arithmetic order remain intact.
The `*_field.zig` files contain the algorithms, while the original modules keep
compatibility entrypoints and their tests. `mle.MleFor(S, Value)` stores either
M31 values (including signed multiplicities) or values of the selected extension.
No production frontend is selected by importing this API.

A caller builds `P.Layer` values and calls `P.proveBatch(allocator, channel,
layers)`. The result owns its proof and terminal artifact. Each MLE may borrow or
own its input slice; borrowed inputs must survive the call. The prover clones
its input and constructs owned binary layers. This is not a streaming or
constant-memory prover: admission must include those layers, working oracles,
and caller-owned inputs. `result.deinit(allocator)` releases all result owners.
Partially constructed owners are released on failure; the focused tests inject
failure at every allocation in a mixed-height proving and verification run.
Legacy public error mapping sometimes reports allocation failures as
`ShapeMismatch` or `InvalidSumcheck`; the failure-injection test normalizes those
errors only for its fixed, independently accepted input.

The verifier entrypoint is `V.partiallyVerifyBatch(allocator, gates, &proof,
channel)`. It returns a **partial** artifact, not an authenticated lookup result.
For each instance the artifact uses the suffix of the common OOD point with
length `n_variables_by_instance[i]`. The receiver must authenticate the actual
numerator and denominator MLE evaluations at that point, then call the shared
`verifier_kernel.verifyTerminalInputs(S, &artifact, expected, checks)` authority.
Applying a gate to MLE evaluations is not a replacement for binding the MLE of
the actual row expression. MAIN commitment, relation challenge order, fixed
inputs, claim closure, global RAM/Keccak/wire obligations, and PCS authentication
remain responsibilities of the embedding protocol.

LogUp outputs are projective pairs `(N,D)`. The core proves that arithmetic
circuit without division. The embedding receiver must reject **each** zero root
denominator before evaluating `N/D`, even when `N == 0`; otherwise a pole allows
an undefined claim. The root denominator is the product of all input row
denominators. Do not redraw challenges after a proof-dependent pole.

The OM31 tests use the actual explicitly tagged
`core.channel.raw_mod_m31.Om31Channel`. This channel is distinct from the legacy
rejection-sampled QM31 transcript. It is not a whole-protocol 128-bit security
certificate. The wider field, GKR alone, or its proof acceptance cannot establish
that claim; PCS, OODS/DEEP, FRI, global lookup arguments and recursion must all use
an admitted protocol and complete security accounting.

Focused qualification commands, run from the repository root:

```
zig test -OReleaseSafe --dep stwo_core -Mroot=src/prover/lookups/om31_test.zig -Mstwo_core=src/core/mod.zig
zig test -OReleaseFast --dep stwo_core -Mroot=src/prover/lookups/om31_test.zig -Mstwo_core=src/core/mod.zig
zig build test-riscv64-logup-gkr-prototype test-riscv64-gkr-circuit -Doptimize=ReleaseSafe -j2
zig build test-riscv64-logup-gkr-prototype test-riscv64-gkr-circuit -Doptimize=ReleaseFast -j2
```

The focused root covers mixed-height GrandProduct, generic LogUp, M31 signed
multiplicities, singles, independent direct output arithmetic, terminal MLE
binding, sumcheck/mask/output/input mutations and allocation-failure cleanup.
It also executes the inherited QM31 numerical unit tests. Production-service
adapters and OM31 circuit-wire tests are separate integration gates.
