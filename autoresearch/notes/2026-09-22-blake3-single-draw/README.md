# Native single-challenge consumption — 2026-09-22

The previous turn made verified progress on ordered draw admission. This turn
extends that same builder to the single-QM31 calls used by PCS deep randomness
and FRI folding alphas. Production transcript integration remains unfinished.

Statement consumption is an enum: one or two secure field elements. Both modes
check the entire eight-word block. The one-element mode emits four scalar wires,
discards the other four outputs, and advances the complete draw counter. It does
not reuse the discarded half for the next call. The existing typed validity and
rejection constraints are unchanged. Single mode removes four unconsumed public
boundary rows; no production speedup is claimed.

Validation command:

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-draw test-blake3-challenge test-blake3-challenge-proof -Doptimize=ReleaseSafe --summary all
```

Six guarded tests pass. The draw test now compares consecutive native single
calls, checks exact four-versus-eight output multiplicities, independent fixed
columns, and ignores unused statement coordinates. Earlier rejection tests still
cover invalid words in the unused half. The proof test produces and verifies one
complete CPU STARK for each consumption mode, including changed-output and
substituted preprocessing-root rejection.

Unit runtime: 509 ms for draws and 482 ms for challenge constraints. Both proofs
together: approximately 6 seconds, max RSS 347 MiB. These remain focused M5 Max
development fixtures (eight queries, blowup 1, zero PoW), not production proof
latency or security qualification. Formatting and diff checks pass. The changed
manual source files remain well below the repository's source-size ceiling; no
repository-wide conformance rerun was needed for these small additions.

Still required: private transcript state transitions and admission of starting
counters, raw-u32 query extraction, PCS/FRI path geometry, PoW, production source
admission, new protocol/key identities, Metal and parent-of-parent verification.
Production still selects Poseidon. The original scheduling, fused PCS/DEEP,
final-layout witness and separate parameter-experiment goal remains active.
