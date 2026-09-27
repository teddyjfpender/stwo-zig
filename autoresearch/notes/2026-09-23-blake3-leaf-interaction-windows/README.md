# Bound full-width leaf hash interaction scratch

Status: focused all-component parity passed (49 seconds, 3 GiB maximum RSS).
The updated Metal combined gate is compiling; no completed device result yet.

A one-second sample of the canonical Metal Ethereum fixture found the leaf's
hash interaction generator executing on the coordinator while helper threads
waited. This identifies one active serial phase, not its fraction of total time.
The sample is retained in `metal-leaf-interactions-live-sample.txt`.

The leaf commitment owner previously retained a complete three-plane inversion
workspace for every hash component. It now retains windows capped at 8192 rows
per component, using the same owned tiled writer as the recursive parent.
Interaction output is owned per column; descriptors are reserved before output
generation so their ownership transfer cannot fail. Failure cleanup frees all
previously transferred columns. The shared window size has one named authority.

The existing integration test now compares every hash component's claim and all
output columns to the original contiguous generator, instead of checking only
the memory-boundary component. Public I/O, plan re-admission, relation closure,
and component geometry checks remain in that fixture.

```sh
python3 scripts/zig_serial_build.py --cwd . test-riscv-blake3-execution-commitments '-Driscv-test-filter=BLAKE3 execution commitment integration binds native and hash components' -Doptimize=ReleaseSafe --summary all
```

No latency or peak-memory improvement has been measured. CPU interaction
parallelization remains a separate possible follow-up; this change bounds scratch
and reuses the existing writer without adding another implementation.
