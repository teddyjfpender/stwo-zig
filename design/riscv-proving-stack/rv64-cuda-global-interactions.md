# Resident native global interaction witnesses

The RTX 5090 qualification covers the 28 CPU-shard roles carrying global RAM,
Keccak I/O or Wire debt. It includes general LS, LS-D64 head/tail, every service
bridge, bulk operations, sponge roles and execution INIT/TEARDOWN. It does not
yet produce an accepting GPU Stark or Ethereum execution bundle.

`constraint_authority.emitGlobalQueries` exposes the existing native tuple
emitters, including the public sponge first-permutation ID as a wire. The cold
CUDA recorder uses these emitters, not a second set of tuple formulas. It
derives each denominator from the shared relation challenge and combines two
fractions as `N=w0*D1+w1*D0`, `D=D0*D1`; an odd terminal query keeps its original
numerator and denominator. Parameters retain semantic IDs and use the same
joined public/shared reservoirs. The recorder does not specialize on live
challenge values.

The generated projection uses a second grid dimension for denominator pairs.
Each pair schedules only its reachable polynomial nodes. This avoids keeping
the whole sponge row's secure temporaries live: the original monolithic sponge
kernels used 255 registers and 3,440/4,600 bytes of stack; the qualified pair-grid
kernels use 168 registers with zero stack or spills. These are compiler resource
measurements, not an end-to-end speedup claim.

The interaction driver performs one OM31 inversion per warp and pair using
prefix/suffix products, writes inverse columns, sums pair contributions per row,
then invokes the previously qualified logical-coset prefix scan. Its output is
byte-exact against `classic_witness.Witness`, including physical circle storage,
the final claim, and subtraction of that claim from every prefix row. The inverse
kernel uses 72 registers and zero stack/spills on sm120.

Each call has exactly one relation claim. RAM and KIO/Wire use separate calls,
output regions and claim slots; they cannot cancel through a combined prefix.
Pole checks are unconditional, including zero-weight rows. Noncanonical values
and poles set a sticky device verdict. The existing ownership registry rejects
undersized, aliased, cross-context and retired allocations before enqueue;
typed commands validate generation, geometry and capacities and poison further
dispatch after a native enqueue failure. Row logs are currently 5 through 22,
with at most 29 denominator pairs per relation.

The AOT projection is a numerical kernel, not an accepting invocation owner.
Its source ranges, offsets, exact cold artifact identity and launch pair count
must come from receiver-derived geometry. Public/shared parameters must use the
canonical checked joined gather. Before execution acceptance the controller
must commit these interaction columns, mix each physical claim into its native
transcript, verify the physical proofs and enforce manifest-wide RAM/KIO/Wire
closure. Numerical witness parity alone does none of those jobs.

## Qualification

Generate the native oracle and immutable projection source:

```
zig build --build-file src/integrations/riscv_cuda/build.zig \
  rv64-global-fixtures -Doptimize=ReleaseSafe -- /tmp/rv64-global-pairgrid-fixtures
```

The exporter independently evaluates the recorded roots against native tuple
emission on every fixture row, then generates expected complete interaction
columns and claims using the native bounded classic witness producer. The GPU
driver constructs projections, inverses and prefixes without intermediate
field-value readback or CPU arithmetic. It compares complete outputs only after
joined completion. One LS fixture has 16,384 rows; the remaining 27 layouts use
32 rows, including the maximum 29-RAM/25-KIO-pair sponge role. Padding guards,
four numerical/sticky-verdict mutants and six preflight rejection classes are
checked. These synthetic MAIN rows qualify arithmetic, not valid execution.

`scripts/rv64_cuda_global_qualify.py` builds the kernels on NVIDIA, runs the normal
driver and memcheck/racecheck/initcheck/synccheck, and pins source, fixtures,
dependency objects, executable and gate-log hashes. All five gates pass.
The typed host integration suites pass 67/67 in ReleaseSafe and ReleaseFast;
the actual native FFI also compiles in both modes. Receipts are under
`vectors/reports/rv64-cuda-global-interactions-20261103/`.

This stage does not cover truth-internal lookup witness generation, GKR root
sum closure, complete joined-domain composition, the full native PCS controller,
or an Ethereum fresh receiver. Those remain delivery gates for GPU execution.
