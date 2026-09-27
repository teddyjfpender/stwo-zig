# BLAKE3 circle-to-line FRI prover qualification — 2026-09-22

The resident circle-to-line transaction now admits the exact BLAKE3 hasher and
channel pair. Unsupported suites/channels are rejected before drawing the first
fold challenge. BLAKE2s admission remains supported. The transaction reuses the
qualified suite-specialized cascade and its existing ownership/receipt path;
there is no new folding algorithm or scheduling policy.

The new test exercises the real FriProver with 16,384 circle evaluations and
8,192 initial line evaluations, at the normal device-inverse admission threshold.
Input is the nonconstant QM31 circle polynomial with coordinates x, y, x+y, 19,
evaluated in bit-reversed canonical circle order. Configuration is blowup log 1,
terminal degree-bound log 2, three queries and fold step 1. This is a bounded FRI
qualification, not canonical CSP parameters or a complete STARK proof.

A minimal CPU backend supplies only CPU Merkle commitments, so generic host FRI
folding provides the oracle. Compare first and all inner commitment roots, every
inner coordinate column, final transcript state, and the complete FRI proof
(including terminal polynomial and all opening witnesses). Queries are drawn
from the resulting BLAKE3 transcript. The independent core FRI verifier commits
the Metal proof, samples matching queries, and verifies against the original
polynomial evaluations. Post-query verifier/prover transcript states match.
Telemetry asserts exactly one FRI cascade epoch; decommit consumes the owned
provers and the testing allocator checks resource cleanup.

Command:

```
python3 scripts/zig_serial_build.py --cwd src/backends/metal test-blake3-fri-cascade -Doptimize=ReleaseSafe --summary all
```

Terminal result: 3/3 steps, 8/8 tests pass. Test run 798 ms / 71 MiB maximum RSS;
compile 8 s / 658 MiB. These are test execution times, not prover benchmarks.
The initial compile caught an unmutated local binding in the test; it was changed
to const. Both the initial failure and intermediate parity pass are archived.

Remaining: combined quotient/FRI BLAKE3 transaction, complete Metal STARK and CSP
qualification, production recursion and remaining prover-owned Poseidon statement
identities. No default promotion or speed improvement is claimed by this gate.
