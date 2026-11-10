# Width24 P2 power-of-two multiplication: rejected numeric experiment

Both candidates were reverted. No core implementation, parameter, domain,
transcript, profile or circuit authority change is included in this commit.

The numeric w24 INTERNAL_DIAGONAL entries3..23 are powers2^2..2^22. Canonical
M31 multiplication by2^k equals a31-bit rotation. We tried a numeric optional
`mulPow2` hook in scalar NativeOps and packed Sponge4.Ops, guarded by the exact
unchanged diagonal. Circuit adapters without the hook preserved the original
constant→mul→add operation stream. Candidate1 unrolled the21 diagonal updates;
candidate2 kept a bounded numeric loop with compile-time exact-diagonal checks.

Each micro sample is2048 evolving packed permutations (8192 independent state
permutations), initialized from0..23 in each lane, one thread, ReleaseFast. Each
variant warms up128iterations;16 paired samples alternate which variant runs
first. Control uses the original numeric multiplication through Ops without a
hook. All resulting states are compared exactly and consumed to prevent removal.

| Variant | Control median | Candidate median | Result |
|---|---:|---:|---|
| Unrolled rotations |2.720708ms|2.829187ms|about4% slower|
| Bounded-loop rotations |2.572021ms|2.573792ms|noise-level difference|

ReleaseSafe qualification passed14tests with the opt-in micro skipped: pinned
KAT, independent dense vectors, all shifts0..30 with canonical edge/random scalar
and packed operands, random complete packed permutations, unchanged parameter
identity, existing absent-hook operation-stream parity and extra generic internal
trace parity. No full native/root proof was necessary or performed. Compiler
constant simplification or register/code-size effects might explain the lack of
gain, but **the codegen explanation is unconfirmed**.

The stable control median gives2.572021ms/8192 ≈314ns per state. Kona's actual
MAIN census contains109,700,992 intermediate-leaf +16,777,216 final-leaf +
33,554,430 internal-node state permutations =160,032,638. Multiplying gives
50.245 single-core compute-seconds, or3.140s under an ideal16equal-core division,
versus approximately3.81s measured MAIN Merkle time. This is an optimistic
micro-derived compute reference, **not a hardware lower bound**: real cores are
heterogeneous, and cache, memory, state scheduling and instruction mix differ.
It does not establish an available1.21x gain. It does argue against expecting
another order-of-magnitude improvement from equivalent SIMD permutation rewrites.
Less encoded execution/provider work remains the structural lever.

The compact JSON receipt records all32timing samples per candidate, baseline and
candidate source/binary hashes, commands, full qualification scope, and scratch
recovery patch paths/SHA256. No large logs or candidate implementation are added.
Scratch patch artifacts may disappear; they are for recovery, not acceptance.
Reapply a candidate patch only in an isolated checkout of the pinned baseline,
then use the receipt's exact build/run commands. The unrolled source snapshot has
additional test-only edge checks added after that micro binary was built; its
algorithm and measured micro function are unchanged. The loop snapshot matches
its binary build.
