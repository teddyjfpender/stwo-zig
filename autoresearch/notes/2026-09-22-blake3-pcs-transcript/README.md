# PCS transcript constraints in the combined FRI proof

Previous turn: progress. All FRI hash paths and arithmetic shared private values
in one outer proof, while challenges/queries were public input boundaries.

The combined gate now includes the actual standalone PCS transcript from initial
BLAKE3 state: trace commitment roots, sampled-value absorption, DEEP draw, each
FRI root and alpha draw, terminal coefficients, PoW verification, separate nonce
absorption and raw queries. Twelve typed components now participate in one proof.
The same public auxiliary values drive transcript output constraints, arithmetic
inputs and path statements. These outputs remain public; this change constrains
them as transcript results, not private cross-component wires. The 1,224 FRI
opening coordinates remain private shared producers across all 34 groups.

`blake3_pcs_transcript.appendOpening` accepts a caller-owned channel and operation
prefix, preserving the integration boundary for a later full STARK prefix.
Native replay validates captured DEEP/FRI challenges and raw queries and records
whole-block rejection attempt counts. PoW checking does not absorb its nonce;
nonce absorption is an explicit next operation. Appending is transactional: a
mismatch or allocation failure does not partially advance caller state or append
a partial sequence. Returned query storage has explicit caller ownership;
other payload slices borrow the capture until witness preparation completes.

Tests reject changed alpha and raw query, check unchanged state/prefix on both
early and late mismatch, and inject failures at every transcript allocation.
The complete proof, independent fixed-column reconstruction, exact global wire
ledger, private-emission tamper audit and false-preprocessing rejection remain.

Command:

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-combined-fri -Doptimize=ReleaseSafe --summary all
```

Final guarded result: all four steps succeeded; one test passed, approximately
6 seconds runtime and 776 MiB max RSS; compilation took 30 seconds on M5 Max.
Formatting and diff checks pass. See tests.log. This is a standalone PCS fixture with
17 queries and 4-bit PoW; outer proof uses 8 queries, blowup1 and zero PoW.
Timings are development qualification costs, not production speedups.

Remaining: constrain PCS DEEP arithmetic and authenticated trace openings;
include the full outer-STARK transcript prefix and composition/OODS admission;
then production trusted suite/key/artifact identities, CPU/Metal integration and
parent-of-parent qualification. The fixture's constant sample point is not an
outer STARK's transcript-derived OODS point. Production stays on Poseidon and
no stronger soundness or end-to-end speedup is claimed. Goal remains active.
