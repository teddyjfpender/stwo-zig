---
title: Full-width BLAKE3 Ethereum leaf recursively verifies through shared parent machinery
author: Teddy Pender
created_utc: 2026-09-22T21:23:34Z
---

# Full-width BLAKE3 Ethereum recursive verifier integration

Status: diagnostic CPU leaf-to-parent proof and independent verification passed;
shared legacy-recorder and canonical base-parent regressions also passed.

The fourteen-component Ethereum equation recorder now accepts a symbolic scalar,
layout and relation adapter. The legacy entry point uses the same shared body;
the new BLAKE3 adapter obtains extension masks from production component vtables
with full-width native/hash column offsets. No scalar-root statement projection
is needed. Wide extension relations use the same generic compiler with the
universal native buses supplied by the BLAKE3 recorder.

Composition records native, hash and extension equations in verifier order.
Detailed extension claims and component aggregates enter as separate transcript
inputs; batch sums are constrained to their aggregates before global closure.
Scalar table claims are represented once. The B3EH transcript replay exports
47 universal pairs plus 13 extension pairs and checks the final native channel.
The shared challenge router explicitly selects the 60-pair profile for Ethereum.
DEEP geometry uses the full admitted assembly, including six-point Keccak masks.
Existing FRI, PCS path, opening, payload and final hash-column emitters are reused.

The diagnostic test proves a real signer-recovery + Keccak leaf, captures its
successful verification, prepares the complete recursive verifier and proves a
parent with a 24 GiB worker allocation cap. It then releases the worker and
prepared parent rows, encodes/decodes the artifact and independently verifies it.
Both leaf and parent use q8/PoW0 for this first integration gate. The existing
canonical q70/PoW26 leaf artifact test remains separate and unchanged in scope.

```sh
python3 scripts/zig_serial_build.py --cwd . test-riscv-blake3-execution-commitments '-Driscv-test-filter=BLAKE3 execution commitment Ethereum recursive parent independently verifies' -Doptimize=ReleaseSafe --summary all
```

The initial compile caught comptime inference making the extension owner a plain
pointer instead of an optional. Its declaration now explicitly names the optional
pointer type. The corrected build compiles successfully.

Canonical recursive Ethereum qualification, Span/custody integration for Ethereum
segments, multi-segment orchestration, Metal and production default switching
remain unfinished. No latency improvement or complete Poseidon removal is claimed.

## Diagnostic parent result

Passed: the real signer-recovery + Keccak leaf is captured and recursively
verified by the new parent. The parent artifact is encoded, decoded and verified
after releasing the proving worker and prepared parent rows. Both child and
parent are q8/PoW0; the parent contains 8 raw verifier queries.

- Complete build/test gate: 14 minutes, 30 GiB peak RSS, four proof workers.
- Prepared parent retained bytes: 2,231,719,096; input count: 299,058.
- Tracked parent worker peak: 10,155,522,628 bytes, under its 24 GiB cap.
- Parent artifact: 132,105 bytes.
- Existing shared lowering reports 112,883 dot4 and 87,210 FMA operations,
  565,445 arithmetic rows, and 2,184 query fusion groups removing 8,736 scalars.

These figures describe this integration fixture. They are not a before/after
speedup, isolated proving latency, canonical-security recursion, or production
Ethereum segment/custody qualification.

## Legacy recorder regression

The existing Ethereum recording-scalar, production-mask and cold verifier program
gate passes 6/6 tests. Compilation takes 5 minutes / 6 GiB; execution takes
2 seconds / 78 MiB. This qualifies the shared refactor through the original
recorder entry point as well as the new BLAKE3 parent fixture.

```sh
python3 scripts/zig_serial_build.py --cwd src/frontends/riscv test-ethereum-vm-composition-program -Doptimize=ReleaseSafe --summary all
```

## Canonical base-parent regression

Passed at q70/PoW26 for both leaf and recursive parent. The 4-minute / 23 GiB
gate preserves the previous 860,503-byte artifact, 4,214,454,616 prepared bytes,
376,119,932 metadata bytes and 19,514,934,660-byte tracked worker peak under the
25,769,803,776-byte cap. This confirms the non-extension path through the shared
composition/transcript/DEEP/challenge machinery remains qualified.

```sh
python3 scripts/zig_serial_build.py --cwd . test-riscv-blake3-canonical-chain -Doptimize=ReleaseSafe --summary all
```
