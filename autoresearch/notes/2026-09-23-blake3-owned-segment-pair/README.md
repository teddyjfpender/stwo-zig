# Release completed segment witnesses before proving the next child

Status: implemented, syntax checked; diagnostic proof regressions queued.

The pair pipeline previously retained both execution owners and both custody
preparations until the complete pair had been lowered. The shared implementation
now releases the first custody preparation immediately after its recursive
preparation finishes. A new preparePairOwnedWithPool entry point additionally
consumes execution owners, releasing each immediately after its child preparation.
Reusable prepared verifiers remain borrowed and independently admitted.

Both children are fully admitted before either proof starts. The borrowed API
retains its original owner-lifetime contract. The owned API destroys both distinct
owners on every failure path, or destroys an aliased owner once. Recursive output
preparations own their columns. Base four-leaf and Ethereum aggregation fixtures
now exercise the owned success path; existing negative borrowed-admission cases
remain in place.

The live canonical aggregation binary predates this change. No measured peak
memory reduction or runtime improvement is claimed yet.

Qualification command:

```
python3 scripts/zig_serial_build.py --cwd . test-riscv-blake3-aggregation '-Driscv-test-filter=adjacent segments' -Doptimize=ReleaseSafe --summary all
```

Log: `/tmp/blake3-owned-segment-pair-aggregation.log`.
This selects the base two-segment, base four-leaf/two-level and Ethereum two-segment
diagnostic proof fixtures. Canonical requalification remains required.

The base tree fixture now also tests consuming failure cleanup with a rejected second key and aliased ownership. Runtime results remain pending.
