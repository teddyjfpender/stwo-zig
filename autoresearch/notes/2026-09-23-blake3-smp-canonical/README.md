# Canonical Metal parent with stateless SMP allocation

Status: implemented and queued; no runtime result yet.

The existing canonical Ethereum Metal fixture now accepts its allocator from the
test wrapper. The checked-allocator leaf/parent gates are unchanged in purpose.
A separate filtered SMP gate uses exactly the same fixture, admissions, codec,
CPU verification, Metal-dispatch requirements, 70-query/26-PoW configuration and
36 GiB worker cap. This tests successful stateless allocation end-to-end after the
undefined allocator-context comparisons were removed, and includes compact fixed
parent rows. The earlier passing Metal v4 run used the checked allocator and the
older full-row fixed representation.

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_metal test-blake3-ethereum-parent-smp-aot -Dmetal-core-aot-bundle=/tmp/stwo-blake3-core-aot-20260922 -Doptimize=ReleaseSafe --summary all
```

The gate requires an authenticated absolute AOT bundle, including the same missing
and invalid-path failure wiring as the existing canonical Metal gate.
