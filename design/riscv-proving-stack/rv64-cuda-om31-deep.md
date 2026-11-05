# Resident OM31 DEEP quotient construction

The native CUDA lane now constructs DEEP numerator aggregates from compact
source coefficients and combines their independently sized LDEs into an OM31
quotient. This is a numerical PCS qualification, not an accepting Ethereum GPU
proof. The complete resident transcript/PCS controller remains unfinished.

The [resident sampling qualification](rv64-cuda-om31-samples.md) now connects
the device channel, OODS point/sample generation and DEEP in one flow. Its
additional native oracle does not upload points, sample values or the DEEP
challenge. Earlier standalone cases remain useful numerical controls.

The implementation follows `core/constraints.zig` and
`core/pcs/quotients/row_evaluation_family.zig`. OM31 quadratic conjugation
negates the upper four coordinates. The conjugate line has coefficients
`a = alpha^k (conj(value)-value)`,
`c = alpha^k (conj(point.y)-point.y)` and
`b = alpha^k value (conj(point.y)-point.y) - a point.y`.
Its denominator is a QM31 value, not the CM31 denominator of the older
four-coordinate GPU quotient path. Zero denominators and degenerate lines
fail explicitly.

For each sample point and coefficient height, the preparation kernels combine
the original base coefficients with their secure `c` weights. Only the eight
coordinate planes of each aggregate need an LDE. They use the existing
addressed-arena base-field LDE, with independently sized groups. No per-source
expanded column slab is retained or reconstructed for this operation. The
final kernel lifts each group's evaluations by the native physical-row map,
subtracts its summed `a*y+b`, divides by the QM31 denominator and sums groups.
Eight denominators share one inverse. Constant-index tiles avoid local arrays:
NVCC 12.8/sm120 reports zero stack and zero spills for the final kernels.
This is a compiler resource result, not a measured prover speedup.

The immutable opening descriptors retain explicit source tree, coefficient
offset, sample group and transcript-power index. Their order must be derived
from the admitted native PCS masks, including periodic samples. They are not
producer-selected verifying authority. This primitive does not independently
establish that the supplied sample values are evaluations of committed columns;
the OODS/commitment/controller protocol must establish that binding.

All buffers belong to one native context; mutable ranges cannot overlap any
borrowed range. Validation occurs before descriptor-dependent accesses and
before arithmetic kernels consume a group. Preparation and combination use a
two-word control buffer and sticky numerical verdict. The same assigned lane,
or explicit dependencies between lanes, must order preparation, LDE and
combination. Enqueue success never means numerical or proof acceptance.
Typed Zig commands additionally validate device generation, capacity and lane
ownership and poison failed jobs.

## Qualification

`rv64_deep_fixture_main.zig` exports expectations from the native polynomial,
conjugate-line and quotient authorities, rather than a second CUDA formula.
Four honest cases cover one, three and ten groups; mixed coefficient/evaluation
heights; nontrivial powers in reverse term order; eight-coordinate samples;
and the scalar and fused LDE schedules. The largest case has 131,072 quotient
rows, 229,376 aggregate coefficient cells and 917,504 aggregate evaluation
cells. All coefficients, line weights, summed linear terms, aggregate LDEs and
quotient coordinates are compared exactly.

Nineteen malformed/tampered cases cover missing trees, reserved fields,
destination overlap, noncanonical points/values/coefficients/alpha/domain,
degenerate points, term partitions, source bounds, exponent bounds, geometry,
sticky failure and changes to evaluations, geometry, control or points between
stages. Output guards and host-side alias/allocation rejection are checked.
No numerical H2D/D2H occurs between aggregate preparation, LDE and combination;
actual outputs are downloaded only after the whole pipeline joins.

The RTX5090 normal run and memcheck, racecheck, initcheck and synccheck are
recorded under `vectors/reports/rv64-cuda-om31-deep-20261103/`. The qualification
tool pins input and executable hashes and refuses to publish a receipt if its
inputs changed during the run. ReleaseSafe/ReleaseFast host suites also compile
the real native FFI calls. Neither this receipt nor the kernel timings elsewhere
establish complete GPU block proving, recursive-root acceptance or a new
security profile.

Reproduction:

```sh
zig build --build-file src/integrations/riscv_cuda/build.zig rv64-deep-fixtures \
  -Doptimize=ReleaseSafe -- /tmp/rv64-deep-fixtures
python3 scripts/rv64_cuda_deep_qualify.py \
  --fixtures /tmp/rv64-deep-fixtures --build /tmp/rv64-deep-qualified \
  --context-object /path/to/context.o --lde-object /path/to/transform-lde.o \
  --n2b-object /path/to/transform-n2b.o --channel-object /path/to/rv64-channel.o
```

The dependency objects are the existing qualified native context, channel and
transform objects; their exact hashes enter the receipt. Hardware qualification
requires NVIDIA CUDA, not the host-only test environment.

## Remaining accepting-proof path

Connect the qualified OODS sampling, joined composition, DEEP, OM31 FRI and
Merkle openings to the actual complete native proof transcript and
proof format; and pass a fresh, independently keyed native receiver on real
Ethereum execution. GKR root denominators and lookup closure must be checked
in addition to numeric sumcheck parity. Truth-provider witness generation and
cross-shard RAM/KIO/Wire closure must remain bound to the complete manifest.
No host field-value feedback may substitute for those resident stages.
