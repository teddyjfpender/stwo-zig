# OM31 numerical GKR circuit fragment

This additive, experimental fragment emits an accepting circuit for actual
OM31 GKR proofs. It does not select a production receiver, alter the legacy QM31
protocol, or establish a whole-protocol 128-bit security claim.

## Shared authority and interface

`rv64_recursion/om31_circuit_lane.zig` represents OM31 by two existing QM31
circuit lanes. Arithmetic uses `core.fields.om31.Quadratic`; fixed nonresidue
multiplication and the inner inverse are the only specialized operations.
`guess(context, value)` creates two guessed QM31 wires, covering all eight M31
coordinates. `fromOm31` and `fromM31Array` are for independently known public
constants, never proof witness values. A guessed zero inverse emits the same
constraint topology as a nonzero inverse and is unsatisfied.

`logup_gkr/om31_circuit_verifier.zig` guesses every coefficient, mask and root
claim, then executes the existing `lookups.verifier_kernel`. Its channel uses
the actual circuit `raw_mod_channel.Om31Channel`, including its distinct profile
tag and all eight reduced challenge coordinates. Builder allocation errors are
latched and must be reported; `verify` checks channel and arithmetic failures
before returning an artifact. The caller must also finish channel/lane emission
after terminal arithmetic. The QM31 lane gains only an additive `check()` peek
at its existing error latch.

## Qualification

`zig build test-riscv64-gkr-circuit -Doptimize=ReleaseSafe -j2` and the matching
ReleaseFast gate exercise native and actual circuit arithmetic, rather than a
mock channel or a second copy of the verifier equations. The suite includes:

- Honest native OM31 proof replay with different instance heights; matching all
  OODS coordinates, Blake digest and draw counter.
- GrandProduct, LogUpGeneric, LogUpMultiplicities and LogUpSingles together,
  including zero and negative base-field multiplicities.
- Independent terminal MLE evaluation on guessed input arrays. Every LogUp root
  denominator is constrained nonzero, and each root's rational value is bound
  to an independently calculated public fixture claim.
- Sumcheck coefficient, layer mask, terminal input and terminal claim mutation.
  Separate loops corrupt each of the eight base coordinates of coefficients,
  terminal claims and terminal inputs. A projective root pole is rejected.
- Guessed zero inverse rejection with identical gate counts and variable count
  to nonzero inversion. Every allocation failure in a small tower emission
  cleans up and releases the thread-local lane binding.
- Existing QM31 circuit and native replay controls remain in the same gate.

The small two-LogUp fixture (8 and 4 input rows) uses 18,596 variables, 3,760
Blake G gates, 2,844 QM31 operation gates and 98 guesses. These are graph counts
for this fixture, not a production leaf cost or a speed measurement. Its input
arrays are independently evaluated in circuit; they are not PCS-authenticated
by this numerical-fragment test.

## Production obligations remain explicit

A production receiver must admit proof topology and resource bounds from its
own protocol authority before wiring a producer's structural lengths. It must
bind each terminal input expression to the authenticated committed columns and
bind output claims to its global/statement closure. GKR alone is projective and
does not reject poles; every output denominator needs a nonzero constraint.
The fixture demonstrates these checks but does not supply the full services
binding adapter, PCS/DEEP/FRI circuit, recursive outer proof, or full security
budget. The new raw-mod challenge sampler's density bound remains a separate
algebraic budget component; it is not a whole-protocol certificate. Legacy
rejection-sampler circuit parity remains separately documented and is not
silently changed by this module.
