# Allocate the complete immutable plan once

`normalize.lowerInto` validates all coefficients, source IDs, constants, output capacity and input/output overlap before writing any stage. It advances the caller's next ID only after success. The original allocating `lower` API is unchanged. The complete pairing adapter now writes directly into its once-allocated stage array instead of allocating, copying and freeing an array for each of31,996 expressions.

ReleaseSafe tests compare every stage, hint, event, source-ID mapping, assertion and fanout against the allocating reference. Failure cases leave both output storage and the next ID unchanged. The adapter still has six owned allocations and validates all six initialization failure paths. The test-only old adapter retains its first/last per-expression OOM controls.

A quiet bounded ABBA on Apple M5 Max measured32,002→6 allocations and10,738,308→5,793,292 cumulative allocated bytes. All plan metadata hashes were exactly `8dbe484c3fe8ac535d5bc08d6295a30c263ffd6cb98ca1a7f7d47cc55372a628`. Under the testing allocator used by the qualification profile, construction fell0.350755→0.007160 seconds: the eliminated debug allocation/mapping tax explains the earlier kernel time and faults. With the production-style SMP allocator,0.007257→0.007071 seconds is only1.026×, close to noise. This is not a49× production proving speedup.

The change removes needless allocation custody in both prover setup and fresh authority reconstruction, without changing any stage coefficient, ID, fanout, FIXED value or witness value. Whole-physical requalification is batched with the measured witness encoder and16-worker path under one updated conservative source fingerprint. No AIR, security profile, VM or production admission changed.
