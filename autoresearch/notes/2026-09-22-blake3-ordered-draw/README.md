# BLAKE3 ordered draw admission — 2026-09-22

The previous goal turn made verified progress on challenge reduction. This turn
adds a reusable ordered-draw witness/preprocessing builder and moves the complete
CPU proof onto that builder. Production migration and the original recursion
performance objective remain unfinished.

`blake3_draw_witness.zig` accepts a statement containing namespace, transcript
state, starting u64 draw counter, attempt count and eight final M31 outputs.
It builds canonical draw frames for consecutive counters. Every hash digest feeds
an authenticated challenge component. Intermediate status boundaries require
rejection; the final status requires acceptance. Only the final component emits
scalar outputs. This forbids selecting a later favorable draw while omitting an
accepted earlier draw. Counter increments and circuit namespaces are checked for
overflow before allocation. Trusted preprocessing builds the same fixed schedule
without evaluating hash rounds or receiving intermediate digest bytes.

The builder owns its arrays in an arena, finalizing allocations before transferring
ownership. The previous hand-assembled one-draw proof fixture was replaced, not
kept as a parallel implementation.

Validation:

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-draw test-blake3-challenge-proof -Doptimize=ReleaseSafe --summary all
```

All three guarded tests pass:

- Native scalar-output parity, exact independently reconstructed fixed columns,
  and every backing allocation failure.
- An extra attempt after an accepted draw fails status constraints; changed
  output values fail boundary constraints. Zero attempts, overflowing draw
  counters and invalid namespaces are rejected. The last non-overflowing native
  counter increment is accepted by schedule construction.
- Complete CPU BLAKE3 STARK verification through the core verifier, real table
  providers and independently authenticated preprocessing. Changed scalar output
  and substituted preprocessing roots fail trusted admission.

Unit runtime: 454 ms. Proof runtime: approximately 3 seconds, max RSS 345 MiB.
These are development diagnostics on M5 Max with eight queries, blowup 1 and
zero PoW. They are not production-security or end-to-end speed claims. The real
proof uses one accepted attempt; rare rejected hash preimages are not fabricated.
Exact invalid-u32 behavior is covered by the earlier challenge component tests.

Limits: state/start/count/output values are public in this gate. Production must
bind state transitions and starting counters to the actual child transcript.
The builder currently exposes all eight outputs. Single-QM31 consumption and
batching must respect the native channel's discarded half-block behavior.
PCS query extraction is a separate obligation: core/queries.zig masks raw u32s
from drawU32s, without the field challenge rejection/reduction. Sorted deduplication,
folding and lifted path geometry must preserve these semantics. PoW, child-proof
source admission, protocol/key identities, Metal and parent-of-parent qualification
also remain. Production still selects Poseidon.

Source conformance retains the same 103 prior finding identities; formatting and
diff checks pass. This evidence snapshot does not modify previous manifests.
