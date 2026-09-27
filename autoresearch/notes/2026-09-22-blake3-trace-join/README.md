# Private trace paths joined to PCS DEEP, FRI and transcript

Previous turn: progress; canonical PCS DEEP was in the combined proof, but its
queried trace values were public boundaries.

All 17 captured trace paths now enter the SAME outer proof as the standalone
PCS transcript, canonical DEEP/FRI arithmetic and all 34 FRI groups. The trace
has two mixed-size columns with extended logs [6,4]. Leaf values follow the
native stable lifted order [1,0], and each path reaches the public trace root.
Each queried scalar is canonically encoded and consumed by DEEP arithmetic.

A new scalar wire component has one main field, six fixed fields, two lookup
events, one interaction batch and no direct arithmetic roots. It emits only
(value,0,0,0), enforcing scalar shape even when the encoder's other coordinate
outputs have zero uses. An optional scalar consume routes a canonical producer
into a query-specific PCS input node. Its final semantic digest is:
`0e9790e1ea7f067a8fdfb5c82d3da5ed184bb81cf44aef07493f7c67a6a005de`.
The initial producer-only draft was extended before qualification; no previously
published production identity changed.

Lifted-row consistency is constrained, not just host-checked. One private
producer per (column, projected-row) supplies all query-specific routes. Routing
uses fixed projection geometry and exact multiplicities. The 17 queries into
the 16-row shorter column necessarily exercise repeated projected rows. Each PCS
input then emits its arithmetic use count plus one hash-encoding read. All trace
queried-value public boundaries are removed. Other public PCS inputs remain.

The scalar unit gate checks emitted/consumed tuple shape, zero padding, boundary
field values and invalid coordinates/self-routing. The complete proof's exact
recursion-wire ledger closes across all thirteen components. Altering a routed
trace value breaks its canonical-producer balance; the private FRI tamper audit
and false-public-preprocessing rejection still pass. Native roots and the
complete core verifier also pass.

Command:

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-scalar-wire-source test-blake3-combined-fri -Doptimize=ReleaseSafe --summary all
```

Final results: all eight steps succeeded, two guarded tests passed. Scalar test
772ms/1 MiB RSS, compilation 4 seconds. Combined proof approximately 7 seconds/
1 GiB RSS, compilation 31 seconds on M5 Max. Formatting/diff checks pass. These
are development qualification costs, not production benchmark comparisons.

Limitations: this remains a standalone PCS fixture with an explicit constant
OODS seed, public sampled values/DEEP answers and public transcript outputs tied
through the same statement. The fixed-column fixture builder still receives the
verified capture for its native oracle checks; production trusted admission is
not replaced. The full outer-STARK prefix, composition/OODS verification and
production suite/key/artifact transition remain, followed by CPU/Metal and
parent-of-parent qualification. Production still uses Poseidon. No zero-knowledge,
stronger-security or end-to-end speed claim is made. The active goal is unfinished.
