# Persistent two-child preparation pipeline

The previous turn made progress: bounded parallel child preparation, canonical
qualification, matched 33.3% root-preparation reduction and 5.1% complete-tree reduction.
This change carries that explicit scheduling option into the persistent prepare/prove
pipeline with resource admission. It makes no new canonical speed claim.

`Sizing.preparation_workers` defaults to one and accepts one or two. Two workers require
an adapter that implements `prepareWithPool`; other adapters reject this request rather
than silently oversubscribing or pretending to parallelize. Admission counts proof
workers plus preparation workers and includes the extra helper stack. Invalid counts,
insufficient CPU tokens and excess memory are rejected before dispatch.

The producer owns one preparation pool for its entire job sequence. Tree preparation
receives that pool and uses the existing two-child implementation. One queue slot,
per-job shared allocation budgets, cancellation, worker plan reuse and output ownership
remain intact. This overlaps preparation with proving without allocating a new pool per
job. Defaults remain serial preparation; canonical throughput promotion still needs a
matched measurement under an adequate total budget.

## Qualification

The new narrow `test-riscv-blake3-tree-pipeline` target runs the native four-leaf tree,
without Ethereum cases. ReleaseSafe qualification passed under the checked allocator.
The target's suite guard requires the named four-leaf test to execute. Initial root
dispatch failed because its catalog proxy was missing; the catalog entry was added and
the successful final run is retained. No proof ran during the initial dispatch failure.

The fixture checks one extra CPU token and exactly one helper stack versus serial
preparation, rejects counts zero/three, rejects three tokens where four are required,
and rejects excess memory. It forces a preparation allocation failure, then runs two
jobs with two preparation and two proof workers. Both outputs independently verify
after worker destruction, including a fresh codec decode. Authenticated proving-plan
and fixed-column pointers remain reused. The complete root binds four actual segments
and six cycles; original nodes remain valid.

Receipt: cpu_tokens=4, reserved_bytes=25,811,766,224; worker peak=3,675,590,334 bytes
under 8 GiB. Measured preparation/proving overlap=1,516,368,417 ns. Root artifact=130,294
bytes. This is **diagnostic q8/PoW0**, not canonical q70/PoW26, and the overlap interval
is not a throughput speedup. Full canonical multi-job timing remains outstanding.

```sh
python3 scripts/zig_serial_build.py test-riscv-blake3-tree-pipeline -Doptimize=ReleaseSafe --summary all
```

Formatting and whitespace checks pass. Changed-source snapshots, relative patch and
raw qualification logs are retained. The broader goal remains active; the user's new
priority is like-for-like ZisK primitive comparisons and qualified hash precompiles as
the default. See the adjacent zisk-compression-comparison note for the first measurement.
