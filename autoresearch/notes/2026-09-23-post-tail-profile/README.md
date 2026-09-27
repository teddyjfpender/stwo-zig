# CPU Keccak profile after prefix reuse and bulk tail updates

Six canonical Keccak-128 CPU proofs ran using the frozen bulk-tail candidate, 16 workers, 70 queries / 26 PoW bits. macOS sample attached for 12 seconds at its default 1 ms interval. All six proofs passed in process and the retained proof hash matched the original canonical full-suite artifact. Exact command and binary hash are retained. Instrumented timings are diagnostic, not performance results.

Two dominant `prepareMain -> writeColumnsAt` branches contain 563 and 296 inclusive sampled hits (859 combined). They still spend their time projecting logical witness rows into committed columns despite the preceding tiling improvement. These are stack samples, not a wall-time percentage; worker counts and waits preclude interpreting aggregate totals as end-to-end shares.

The next experiment splits independent destination column ranges across at most four explicitly leased workers. Each append joins before its source rows can be released. Small chunks and unavailable capacity keep the serial writer. Exact layout/padding parity and bounded fallback must pass before considering E2E timings. This targets shared final-layout witness projection and is not an AIR or hash-function change.
