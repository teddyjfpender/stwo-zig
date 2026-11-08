# CPU-first OP continuation on Apple M5 Max

The [qualification receipt](qualification.json) records two complete native OP
Mainnet execution proofs from a rebuilt canonical GLV guest, plus the first
successful full synthetic ordered application fold on this machine. These are
qualification runs with compilation or other tests potentially active, not quiet
benchmark medians or a measured speedup over another prover.

| OP Mainnet block | Instructions | CPU / service proofs | Production wall | Fresh receive wall | Production peak RSS |
| --- | ---: | ---: | ---: | ---: | ---: |
| 120794432 | 796,520 | 1 / 2 | 6.995 s | 1.312 s | 3.662 GiB |
| 121057303 | 5,928,533 | 6 / 7 | 34.606 s | 3.665 s | 4.932 GiB |

Both cases match the independent native Kona output and Unicorn machine/service
oracle. Each fresh native receiver rebuilds authority and accepts the full
bundle, then rejects physical CPU proof corruption both before and after the
transport hash is recomputed. The request uses 1,048,575-step batches, eight
proof workers and two setup builders; the receiver uses four setup helpers and
12 GiB requested-live admission. Geometry, exact commands, profiles, hashes and
per-child wall/user/system/RSS data are in the receipt. The host has 64 GiB RAM.
Guest/build/proof products are retained outside the source checkout.

The native profile remains `conjectured128_b2_q108_p20_fold4` with
`security_qualified=false`. No proof parameter or Ethereum engine code changed.
The corrected resource collector interprets macOS RSS as bytes and Linux RSS as
KiB; old receipts have not been silently rewritten.

The synthetic public-fold fixture builds two actual child STARKs over fixed
OD/OP public values and a parent STARK, reconstructs its authority without
assignments, verifies the encoded parent, and rejects output mutation and swapped
roles. It completed with 22,544,384 circuit variables and a 706,584-byte root
under a 32 GiB requested-live budget. This qualifies the fixture's physical
folding path, not Kona derivation, a real OP recursive root or settlement.

Validation: 38 OP Python tests; 93 CI planner/selection tests; 36 pinned Rust
execution/derivation/precompile tests. The actual new `opstack_python` CI lane
also passes from a fresh virtual environment. Explicit OP lanes prevent tooling
changes from triggering the unrelated Cairo/Metal fallback, while unknown files
and shared-engine changes retain their existing coverage. The first attempted
push hit that unrelated Metal AOT gate; the pre-commit source-layout failures
are also outside the changed files. Both exceptions are recorded in the receipt.

The [delivery checklist](../../../opstack/COMPLETION.md) remains open for a
physical anchored transition proof, real recursive closure, an accumulating
checkpoint and practical complete STARK settlement. The 3.07-billion-instruction
anchored transition still exceeds the admitted 256-proof roster. Its retained
witness archive has not been located locally; execution-only fixtures are not a
substitute for that transition.
