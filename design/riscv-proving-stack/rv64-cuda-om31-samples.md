# Resident OM31 PCS sampling

The CUDA lane derives OODS points, evaluates compact base-field circle
polynomials, mixes the sampled values into the native raw-Blake OM31 channel
and draws the DEEP random coefficient without intermediate field-value
transfers. A connected native-oracle case then constructs the complete DEEP
quotient through the compact aggregate/LDE path. This is numerical PCS
qualification; it does not establish an accepting GPU Ethereum proof.

## Native semantics

One device channel draw supplies the stereographic parameter. The base point
is `((1-t²)/(1+t²), 2t/(1+t²))`. A pole fails explicitly. Each independently
derived mask recipe contains a base-circle offset, a doubling count and a
coefficient log. The original shifted point is retained for the DEEP conjugate
line; polynomial evaluation uses the repeatedly doubled point, matching
`sampled_values_field.zig`. These two points must not be interchanged.

Folding factors are stored in coefficient-bit order: `y, x, T2(x), ...`.
Eight coefficients fold in registers before a 128-thread shared-memory
reduction. A first pass consumes 1,024 coefficients per block; later passes
reduce at most 256 secure partials per block. There is no extension-field
array the size of each source polynomial. For 512 columns with coefficient
log22, both scratch banks together require 128 MiB. The two banks are reused
across independently sized batches. NVCC 12.8/sm120 reports zero stack and
zero spills for every sampling kernel; first/reduce kernels use 48/47 registers
and 4/8 KiB shared memory respectively.

Term output slots preserve the admitted tree/column/sample ordering. They are
mixed once as contiguous AoS OM31 coordinates, after all selected batches
finish, then the same device channel draws alpha for DEEP. Independently
derived recipes and source descriptors are setup, not producer-declared
verifying authority. Neither successful enqueue nor a valid numerical
transcript independently authenticates an execution or a commitment root.

## Qualification on RTX5090

| Gate | Coverage |
|---|---|
| Native polynomial oracle | 18 sampled polynomials across logs1,2,3,5,10,11,12,17,22; all four input trees; shifted and repeatedly doubled points |
| Native channel oracle | Parameter draw, ordered sampled-value mix, DEEP alpha and complete terminal channel state |
| Connected sampling/DEEP | Six additional samples, three independently sized groups; exact native aggregate coefficients, LDEs and final quotient; no point/value/alpha upload |
| Tamper rejection | 17 sampling and 19 DEEP mutants, plus alias, capacity, alignment and output-guard checks |
| Hardware tools | Normal runs and memcheck/racecheck/initcheck/synccheck for both flows |
| Host checks | 63 tests in ReleaseSafe/ReleaseFast, plus compilation of real native FFI calls |

The native fixture exporters use the existing circle, polynomial, quotient and
channel implementations as authorities. The largest sampled source polynomial
contains 4,194,304 base coefficients. This is a correctness workload, not an
Ethereum proving-time or ns-per-cell benchmark. Both qualification receipts,
compiler resource reports and complete logs are in
`vectors/reports/rv64-cuda-om31-samples-20261103/`.

All pointers are generation-checked context allocations. Mutable ranges cannot
overlap borrowed inputs. Eight-byte source/group descriptor alignment is
checked before dispatch. Point readiness is a strict Boolean and malformed
metadata, noncanonical fields, missing sources, poles or invalid geometry
produce sticky numerical failure. The receiving proof controller must check
that verdict and its independently bound channel completion before publication.

Reproduction:

```sh
zig build --build-file src/integrations/riscv_cuda/build.zig rv64-samples-fixtures \
  -Doptimize=ReleaseSafe -- /tmp/rv64-samples-fixtures
python3 scripts/rv64_cuda_deep_qualify.py --mode samples \
  --fixtures /tmp/rv64-samples-fixtures --build /tmp/rv64-samples-qualified \
  --context-object /path/to/context.o --channel-object /path/to/rv64-channel.o
```

For the connected DEEP flow, regenerate `rv64-deep-fixtures` and run the same
tool in its default `deep` mode with the context, channel, LDE and N2B objects.
There are now five honest DEEP cases, including the connected sampling case;
the earlier four standalone cases retain their version1 fixture bytes.

## Remaining complete-proof work

Join sampling and DEEP with the actual commitment/composition/FRI/opening
controller and native proof serialization, rather than synthetic checkpoint
fixtures. Complete GPU witness generation and physical binding for every
admitted CPU/truth role, enforce GKR root closure, and verify a real Ethereum
bundle with an independently keyed fresh native receiver. Preserve complete
manifest and cross-shard RAM/KIO/Wire closure. No new security profile,
recursive-root qualification or complete-block speedup is claimed here.
