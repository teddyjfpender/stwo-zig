# 2026-08-15 — prepared temporal pair authentication evidence

## Result

The current temporal V2 pair authority pays all statement and identity hashing
once during cold preparation.  Re-authenticating the immutable prepared node
executes no scalar Poseidon2-M31 permutation and performs no heap allocation.
This is now enforced by runtime call-site instrumentation in addition to the
compile-time preimage-width ledger.

This result is deliberately narrower than recursive proving.  It measures the
native authenticated pair-authority boundary; it does not prove or verify a
temporal parent STARK and is not a whole-recursion throughput result.

## Distinguishing the two pair authorities

The older R-009 V1 core/provider shadow and temporal V2 are different
protocols and their counts must not be combined:

| Authority path | Scalar permutations |
| --- | ---: |
| V1 conservative original audit estimate | 229 |
| V1 current convenience root | 94 |
| V1 suite-prepared root | 55 |
| V1 context-prepared hot root | 38 |
| Temporal V2 `prepareRootContext` historical pre-dedup cold path | 499 |
| Temporal V2 current `prepareRootContext` cold path | 281 |
| Temporal V2 eliminated cold duplicate work | 218 |
| Temporal V2 prepared hot authentication | 0 |

The approximately 229-permutation opportunity was the conservative V1 audit
estimate.  The production-direction temporal protocol has larger statement
preimages, so its independently derived historical cold call tree is 499, not
229.  One-pass derivation removes exactly 218 of those permutations (43.7%)
without changing any authenticated identity.  More importantly for repeated
use, `PreparedRootContextV2` snapshots the authority, canonical record, root
pin, and fully derived result by value.  Its hot function performs the three
complete fixed-size equality checks and returns the cached result, so all 281
remaining permutations are amortized across repeated authentication.

These 499/281 counts cover the pair node's `prepareRootContext` hash tree.
The integration-level `prepareInto` also performs verifier-custody admission,
V2 adjacency binding, and integration authority identities once on its cold
path; those are separate admission work and are not folded into this count.
Its repeated `authenticatePrepared` call delegates directly to the zero-hash
pair-node function measured here.

The zero claim applies only to temporal V2's prepared path.  V1's current
context-prepared path still performs four evidence folds and the node hash,
totalling 38 permutations.

## Executed-path regression

`temporal_pair_node.zig` now exposes a test-only dynamic audit.  Every actual
scalar hashing call site records both one invocation and the exact number of
permutations implied by its canonical preimage width.  The namespace is empty
outside `zig test`; production builds retain neither a public instrumentation
capability nor a counter branch.

The focused ReleaseFast test establishes:

- one complete-pair cold preparation executes 13 hashes and 281 scalar
  permutations;
- 4,096 successful calls to
  `authenticateRootWithPreparedContext` execute zero hashes and zero
  permutations; and
- prepared-path rejection of a mutated child capture identity also executes
  zero hashes and zero permutations.

The static ledger still pins every preimage width and aggregate count at
compile time.  The two mechanisms catch different regressions: the dynamic
audit catches a newly executed hash, while the static ledger catches a changed
hash width or accounting formula.

```text
zig build --build-file src/frontends/riscv/build.zig \
  test-recursion-temporal-pair -Doptimize=ReleaseFast -j1
```

## Integration-authority validation and real-source receipt

The integration authority now validates an untrusted prepared pair by
reconstructing the complete `PreparedRootContextV2` once and comparing the
result by value.  The former validator independently validated the embedded
authority and record, repeating their hash trees, then compared several
cached result fields with themselves.  That was both redundant and an
integrity gap: coherent mutations of seven duplicate cached-result fields
could survive the old audit.

The focused integration test retains that old schedule as a test-only RED
baseline and executes both validators under the scalar-permutation audit:

| Successful integration validation | Hash invocations | Scalar permutations | Heap allocations |
| --- | ---: | ---: | ---: |
| Historical independent-snapshot audit | 23 | 543 | 0 |
| Current one-pass reconstruction | 19 | 433 | 0 |
| Work removed | 4 | 110 | 0 |

The current validator therefore removes 20.3% of scalar permutation work at
this boundary while strengthening the binding between authority, canonical
record, pin, and cached result.  Exact constants are pinned in production and
checked against the executed counters; the test fails if either side drifts.
A seven-case mutation fleet changes cached format, protocol, session, job,
parent geometry, and child identity fields.  Every mutation demonstrates the
historical acceptance and current `PairIdentityMismatch` rejection.

The same test calls `authenticatePreparedPairForSource`, the production seam
used at all three pair-authentication sites in temporal rows 0--17.  Across
4,096 calls it records exactly zero hashes, zero scalar permutations, and zero
heap allocations, with deep parity against cold authentication and no
mutation of the prepared capability.  The integration hot path directly
publishes the validated immutable result.  It no longer passes the
capability's three embedded snapshots to a generic helper which could only
compare each snapshot with itself; the exact hot snapshot-equality count is
therefore also pinned from three to zero.

```text
python3 scripts/typed_air_zig_lane.py --label pair-perf -- \
  zig build --build-file src/integrations/riscv_cpu/build.zig \
  test-recursive-temporal-pair-prepared-perf -Doptimize=ReleaseFast
```

## Focused wall-time observation

An environment-gated ABBA microbenchmark compares the current convenience
root, which repeats cold preparation, with the immutable prepared hot path.  A
20,000-operation ReleaseFast sample on the 18-core Apple M5 Max development
host reported:

| Path | Nanoseconds per operation |
| --- | ---: |
| Temporal V2 convenience/cold authentication | 170,764 |
| Temporal V2 prepared hot authentication | 764 |

That sample is approximately 223.5x for this native microbenchmark.  It has no
timing threshold and makes no portable speed guarantee.  It is evidence that
removing the permutations materializes at this boundary, not a prediction of
parent-proof or end-to-end zkVM speed.

```text
STWO_TEMPORAL_PAIR_BENCH_ITERATIONS=10000 zig build \
  --build-file src/frontends/riscv/build.zig \
  test-recursion-temporal-pair -Doptimize=ReleaseFast -j1
```

For comparison, the separately gated legacy V1 sample on the same host and
iteration count reported 56,239 ns/op for 94 permutations, 32,851 ns/op for
55, and 22,814 ns/op for the 38-permutation context-prepared path.  This
confirms rather than obscures the protocol distinction: V1 is reduced but not
hash-free; temporal V2 prepared authentication is hash-free.

The integration-path ABBA harness independently measured the exact production
wrapper.  With 20,000 operations per arm on the same development host it
reported 178,130 ns/op for convenience/cold authentication, 736 ns/op for the
former prepared wrapper's three self-equality walks, and 27 ns/op for the
current direct prepared source path.  Removing the ineffective equality walks
is approximately 27.3x at this narrow hot boundary.  The same caveats apply:
this is a non-normative local observation with no timing threshold, not a
claim about end-to-end prover throughput.

```text
STWO_TEMPORAL_PAIR_INTEGRATION_BENCH_ITERATIONS=20000 \
  python3 scripts/typed_air_zig_lane.py --label pair-perf-abba -- \
  zig build --build-file src/integrations/riscv_cpu/build.zig \
  test-recursive-temporal-pair-prepared-perf -Doptimize=ReleaseFast
```

## Boundary retained

`recursive_temporal_pair_authority_v2.PreparedTemporalPairAuthorityV1` uses
the same `PreparedRootContextV2` and delegates `authenticatePrepared` directly
to its hash-free hot function.  Callers crossing an untrusted mutation
boundary must still run the one-pass full reconstruction in `validate` first.
Caching is safe only for the immutable by-value snapshots admitted during
cold preparation.

`COMPLETE_PARENT_PROOF_AVAILABLE` remains false.  This evidence closes the
known native pair-authentication hashing opportunity; it does not change the
honest status of the temporal parent proof, whole frontend, or proof-system
soundness work.
