# Independent expected setup in the memory completion pipeline

The selected CPU completion path derives PAGE16 and RAM19 node keys from their
original admitted plans and fixed verifier recipes before reading node proofs.
Each catalogue retains compact specs and an authenticated inventory; selecting
a node authenticates its spec and at most four direct node children rather than
replaying the full catalogue. Both fixed setup and live witness work use bounded
lanes under the caller's aggregate budget. They do not consume the smaller
metadata-only cap.

PAGE semantic constants are pinned in policy version 2. The original Job records
the proposed semantic claims before proving, checks them against fresh original
verification, and exports them with the durable source policy. The independent
receiver checks that policy against its expected file pin. Legacy version 1
remains readable, but cannot supply missing expected constants to the canonical
fixed path. Received proofs never nominate expected claims or keys.

The V20 page/memory join borrows the two genuinely derived catalogues and checks
their independent IDs, exact root membership, common epoch, census and original
public closure. It derives one expected join key and statement frame. Lower
fixed rows are released before live join witness construction. The compact
authenticated join setup survives for FINAL22, which compares it with the actual
fresh join source and reuses it without rebuilding either memory forest.

PUBLIC21 and FINAL22 use internal direct key factories. These factories create
the complete fixed assembly, invoke the original fixed commitment once, copy
only the key and public schedule, and release the fixed owner. External-owned
assembly APIs retain their original cold validation. No caller-supplied key,
proof-file record or flag bypasses the expected setup factory.

Publication still freshly verifies original children, constructs the actual
private witness, partitions the original G rows, and compares context, row logs
and public routing with the independent expectation. The original producer
commits the live fixed columns and admits exactly the expected preprocessed
root. A structural comparison is not a substitute for that commitment check.
Reconstruction reads the pinned staged proof and performs actual fresh
verification against the independent key. It does not construct a private
verifier witness just to recover that key.

Supplemental RAM/range publication retains one independent expected-key cache
and one original producer worker per family. Every instance validates its own
source admission and public values. Worker reuse checks live fixed geometry and
digests, and the independent expected key before proving. The CPU driver lends
its bounded thread pool; the Session shuts down its joined coordinators and
workers before that pool dies. Cold proving consumes source rows and releases
the producer before encoding and fresh verification.

The completion preflight requires matching PAGE, memory and final transcript
capacities, before collection or proving. Teardown drops the final Fresh before
its metadata owner, V20 setup before its borrowed catalogues, and catalogues
before original forests, leaf scopes and schedules. PAGE and memory ownership
transfer only after their full stage succeeds; publication rollback removes
only newly published files.

An unsuccessful CPU driver exit also rolls back supplemental recursive leaf
files after every family and forest reader has joined. Each original writer's
successful publication pins identify the files it owns; pending slots and
reader inventories cannot authorize deletion. Cleanup allocates no memory and
the OPEN manifest is removed only when this session successfully published it.
Existing destinations rejected by exclusive publication are preserved. Normal
successful teardown retains the durable files.
Aggregate report totals are combined inside completion's publication rollback
scope. The driver performs no fallible count arithmetic after that stage has
returned success, so an overflow cannot strand its newly published files.

This is implementation of setup reuse and removal of redundant reconstruction
work. Focused scalar, transport, allocation-fault and actual-body compilation
gates are recorded in the performance ledger. Positive fixed/live root parity,
full independent block acceptance, isolated proving time and peak RSS remain
runtime obligations. Segment/proving runs are stopped. These changes alone do
not establish CompleteBlock authority or an end-to-end speedup.
