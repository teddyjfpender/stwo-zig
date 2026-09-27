# Project small witness chunks directly into committed positions

Status: focused ReleaseSafe parity passed (7 seconds build/run, 844 MiB build MaxRSS); no measured speedup yet.

A live canonical Metal sample at 10:01 local time spent its main-thread sample in
CPU PreparedVerifier initialization, mostly writeColumnsAt during trusted memory
path emission. The writer scanned every destination row for every chunk, including
chunks much smaller than the trace domain. The operation therefore scaled with
chunk count times total domain size rather than emitted witness size.

Chunks smaller than half the domain now scatter directly using committedRow.
Larger writes retain the existing tiled traversal. Empty chunks write nothing.
The regression enumerates every offset and length of a 32-row domain, both trees,
and checks untouched sentinel cells and values using the independent inverse
permutation. It exercises both paths and the half-domain transition.

The already running Metal v3 binary predates this change. Queued CPU canonical and
base-tree builds will include it. A separate focused parity test is also queued:

```sh
python3 scripts/zig_serial_build.py --cwd . test-riscv-blake3-execution-commitments '-Driscv-test-filter=BLAKE3 execution commitment chunk projection' -Doptimize=ReleaseSafe --summary all
```
