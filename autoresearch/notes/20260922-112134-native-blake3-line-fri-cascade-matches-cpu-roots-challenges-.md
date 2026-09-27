---
title: Native BLAKE3 line FRI cascade matches CPU roots challenges and folds
author: Teddy Pender
created_utc: 2026-09-22T11:21:34Z
---

# Native Metal BLAKE3 line FRI cascade

2026-09-22. Extended the existing line cascade through a versioned hash-family
ABI. BLAKE3 uses the canonical 11-word channel state; the retained BLAKE2s wrapper
continues to use 10 words. Buffer copies, error checks and handoff bounds follow
the selected layout. BLAKE3 zero seeds/prefix and initial error state are checked.

Two BLAKE3 fused kernels retain existing field arithmetic and combine coordinate
extraction/folding with canonical leaf hashing. BLAKE3 parent-tail reduction now
absorbs the root and draws its challenge using the previously qualified transcript
helper. Ordinary-parent and nonfused transcript paths select the same family.
The existing inverse-coordinate cache and single-command schedule are shared.
No new FRI arithmetic, hash protocol or production default was introduced.

The CPU-oracle cascade test is shared across suites. Nine levels fold 1,024 QM31
values down to two. For BLAKE3 and BLAKE2s, cold and warm cache runs compare every
root, final channel digest/counter and final field values with CPU Merkle/channel/
fold computations. That covers 36 roots across four complete cascades. Each run
has one command buffer, one wait, one compute encoder; cold runs have 29 dispatches
including inverse generation, warm runs 20. Cache-generation receipts match.

Qualification: initial cascade/parent/shader gate passes 11/11 tests, 9/9 steps.
Final cascade gate additionally executes ABI parameter and AOT-profile assertions:
6/6 tests, 3/3 steps, 617ms test runtime/57MiB MaxRSS. Versioned FFI parameter
count/types are checked alongside retained legacy declarations. Core inventory
now has 177 kernels; Ethereum 182; source/declaration pins match. Tests used
source JIT, not AOT execution. GPU speedup or canonical CSP timing is not claimed.

Commands:
```sh
python3 scripts/zig_serial_build.py --cwd src/backends/metal update-abi-declaration-digests -Doptimize=ReleaseSafe --summary all
python3 scripts/zig_serial_build.py --cwd src/backends/metal test-blake3-fri-cascade test-blake3-parent-chain test-shader-authority -Doptimize=ReleaseSafe --summary all
python3 scripts/zig_serial_build.py --cwd src/backends/metal test-blake3-fri-cascade -Doptimize=ReleaseSafe --summary all
```

Remaining: the runtime cascade is qualified, but resident_fri_transaction.zig
still admits only the BLAKE2s channel and serializes a 10-word state. Its exact
BLAKE3 admission, channel packing/restoration, circle entry and receipt integration
are next. Prior resident-channel buffer handoff and circle-source BLAKE3 modes
are not covered by this line-only gate. Query draws, full Metal STARK/recursion
qualification, CSP timing and prover-owned Poseidon identities remain.
