# Field wrapper and complete native bundle checkpoint

This checkpoint distinguishes actual proof acceptance from preparation tests.
The source tree is the uncommitted PR 198 worktree based on
`6b7f08af51204dc8e96252879c772a8bed874748`; that commit alone does not reproduce
these changes. `logs.json` pins the retained logs beside this file.

## Accepted evidence

- The small field-profile native pair was produced, serialized, its producer
  destroyed, and freshly verified: 1/1 test, 127.979 s complete request,
  1,180,026,464 B lifetime peak footprint. Both leaves include genuine native
  proofs; this is the development fixture, not mainnet block proving.
- The two-leaf bundle was independently verified in a fresh process, followed
  by six retained negative cases: 7/7 accepted/rejected as expected. Its
  genuine request took 6.948 s and peaked at 281,199,360 B. The bundle manifest
  SHA-256 is `236ba1eca6ddb23704778e4ca911040f3b5bd321453d7ba1af889d12e2a1a1e8`.
  Artifacts and mutation receipts are in
  `.git/local-ethereum/field-bound-v4-bundle-check-run-v2/`.
- The bundle verifier rejects that valid small bundle when independently
  admitted against the real block's different job: `EthereumBundleJobMismatch`.
- Real campaign segment9 now passes CPU proof production for core and every
  provider, serialization, producer destruction and fresh verification. The
  complete request took 1,190.960 s, peaked at 26,345,901,712 B (24.54 GiB), and
  published a 62,552,044 B native proof. It used one actual worker and separate
  16 GiB composition / 24 GiB PCS budgets under a 32 GiB sampled stop. This is
  one segment, not a whole-block proof or recursive root. See the
  [real campaign evidence](../2026-09-07-real-campaign-v1/README.md) for source,
  artifact and follow-up separate-process/Metal checks.
- Witness-free verifier components and native Tree0 admission: 10/10 tests.
  Global statement projection and full-width clock arithmetic: 9/9 tests.
  These checks do not substitute for a complete recursive proof.
- All actual typed AIR parameter/padding checks passed on the field fixture.
  Exact lookup audit v3 passed 1/1: all 68,891,361 contributions close.
  The earlier v2 failure was an obsolete diagnostic schema assertion (12 versus
  15); both logs are retained. Clean request: 254.888 s, lifetime peak
  32,193,634,136 B.
- The original lookup failure is retained. The repairs share transcript-step
  grouping with the native emitter and publish the global statement digest
  consistently; their combined focused suite passed 120/120.

## Measured bottlenecks and limits

| Operation | Observation | Engineering implication |
| --- | --- | --- |
| Native pair cold verification | Test ~45 s; standalone ~6.4 s | Essentially equal instruction counts. Standalone uses multiple cores; tests have no global pool. Compare declared, actually enforced worker policies. |
| Allocator ABBA probe | Testing 47.29 s; tracked SMP 45.22 s | 4.38% difference, not the explanation for the apparent sevenfold gap. Keep allocators unchanged. |
| Field AIR preflight | 123.878 s; 17.845 GB lifetime peak | Compilation excluded. Native verification and full circuit preparation remain substantial even before PCS. |
| Exact source ledger v1 | 68.9 million entries; 17.77 s fill, 27.61 s classification | 9.37 GB used entry storage. Its 20.11 GB reserved capacity is not a measured physical footprint. |
| Field cohort v2 | 254.6 s request; 32.19 GB lifetime peak | Includes admission and independent fixed Tree0 derivation; not proof generation. |
| PCS input AIR | 8,402,046 logical rows, padded to 16,777,216 | Only 13,438 rows above the 8,388,608 boundary. Reducing authenticated input expansion is a concrete candidate, not an established saving. |
| QM31 multiplication / linear AIR | 9,686,456 / 9,440,446 logical rows; each padded to 16,777,216 | Scalar arithmetic lowering and power-of-two padding dominate geometry even for the tiny child. |

The field9 complete-proof gate now passes 3/3: serialize, destroy producer,
verify from only the pinned key/public inputs/proof, then native-assisted cold
replay and retained mutation checks. The independent root request took
0.209213458 s (verification 0.119234291 s), proof 3,033,435 B. The complete
development command took 2,303.037399375 s, lifetime footprint peak
52,653,710,168 B. See `complete-proof-field9-v1.json` for artifact/source pins
and retained logs. The separate-process root gate now passes 5/5 using only
an independently pinned key, public inputs and proof. The genuine request took
0.197734708 s (verification 0.110557000 s), with 53,379,432 B process footprint
peak. Wrong key, changed claim, changed nonce and changed proof were rejected
by the key, claim-closure, interaction-PoW and canonical-proof checks respectively.
See `fresh-process-root-v1.json`; originals and verifier bytes remained unchanged.
This establishes the tiny field leaf wrapper, not the whole-block fold.
The native bundle endpoint is not a succinct recursive root; the whole-block
fold still needs exact child-proof verification and continuation under
independently admitted keys.

The 99% proof-time reduction is a target, not a measured result. Do not compare
the tiny fixture with a real block, CPU-count defaults with worker 1, proof-only
phases with complete requests, or a native bundle with Zisk's final proof.
CSP performance promotion still requires the unchanged 16-case CPU/Metal
suite under admissible host conditions; earlier noisy runs do not establish it.

## Poseidon acceleration scope

The retained Tree0 sample spends 1,564 of 1,691 samples in bounded-tail native
Merkle construction. It samples a phase, not the entire proof. These hashes
commit the prover's own columns; a guest syscall/precompile does not remove
that work. Dedicated Poseidon AIR already handles recursive hash checks,
and Metal already has Poseidon leaf/resident/parent kernels. The active
wrapper's CPU preparation choice is being made explicit for a same-root
Metal comparison with authenticated AOT and no host fallback.

An opt-in CPU tail cache reuses two parity sponge states per native-height
group, preserving absorption order and every leaf. Existing CSP callers
retain the original path. The actual Poseidon gate passes 4/4, including
all-layer equality at 1/2/3 workers and uneven partitions. A small
same-tail-ratio ReleaseFast comparison measured median 161.272500 ms
before versus 100.418208 ms after (1.606x), with an additional 11,776 B
of cache stack per worker. Ethereum field preparation/proving explicitly
selects this path for field9; the real field4 leaf baseline and other callers
keep the existing default. Source hashes,
all samples and the exact command are in `poseidon-tail-reuse-v1.json`.
The original benchmark guard failure is retained: the direct launcher had
scoped its optimization flag after the module declarations, leaving the
root in Debug. The corrected launcher scopes the mode before every module;
its five command tests pass, and the benchmark asserts ReleaseFast at run time.
For the observed Tree0 tail (41 columns at log21, 63 at log25), native absorptions are 2,199,912,448 versus 3,489,660,928
replayed: 37% less tail work, not a demonstrated proof-time reduction or
an orders-of-magnitude estimate. Cache stack storage is reported separately
from retained prefix/leaf heap bytes.

The selected native leaf verifier and root verifier rebuild passed alongside
19/19 focused admission tests. The separate CPU/Metal Tree0 comparison command
also compiled (4 minutes, 6 GB compiler RSS), using the same retained fixture
and existing preparation owner. It requires authenticated AOT, exact CPU/Metal
root equality, one resident Poseidon commitment, and zero host Merkle commits.
CPU/Metal Tree0 runtime parity now passes, including equality with the earlier
independently verified field9 key. The paired commitment phases measured
268.804677666 s CPU versus 7.768282875 s authenticated Metal (34.60x), with one
device Poseidon commitment and zero host Merkle fallbacks. The grouped layout
adopted all 4,559,583,744 B of source coefficients with zero additional backing.
The complete probe took 465.804882625 s and peaked at 32,193,470,320 B.
See `tree0-cpu-metal-v2.json` for frozen source/binary/AOT pins and logs.

This is a commitment-phase comparison, not a new wrapper proof or a CSP
performance promotion. It releases the cohort before Metal preparation, so it
does not establish the production cohort's combined peak. The completed Metal
epoch used direct lifted leaves; its modeled column reads remain higher than
the staged route. The separate real-leaf Metal attempt stopped before proof
publication at 37.97 GB footprint under its sampled 32 GiB guard.
