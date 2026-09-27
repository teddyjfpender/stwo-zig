---
title: Canonical Ethereum recursion exceeds 36 GiB; bounded interaction scratch passes exact parity checks
author: Teddy Pender
created_utc: 2026-09-23T05:11:19Z
---

# Bounded interaction scratch for canonical BLAKE3 recursion

Status: both focused parity/failure gates passed. Canonical proof retry running
at the unchanged 36 GiB worker cap.

The canonical Ethereum leaf/parent gate failed at its unchanged 36 GiB worker
cap. Direct execution of the original compiled test reproduced
`ParentWorkerHostBudgetExceeded`; the parent preparation retained
10,150,562,296 bytes outside that worker budget. The admitted canonical leaf
artifact was reused only after independent admission and verification.

The parent producer previously allocated three QM31 scratch planes sized to the
largest complete interaction trace, retaining them while all owned interaction
columns accumulated. The new owned-output writer uses windows of at most 8192
rows. It evaluates/inverts each window, writes same-row cumulative secure columns
directly to owned storage, and accumulates the global claim. Its final secure
column temporarily holds row totals, then is replaced in place by the shifted
global prefix. The final prefix must close to zero.

Only owned output uses this writer. Any failure destroys all partially written
columns; the borrowed output API retains its original failure-atomic behavior.
Both writers share source alias checks. The worker reuses one scratch allocation
across components. Neither proof parameters nor the 36 GiB canonical worker cap
were relaxed. Pool-backed CPU admission-key derivation is also enabled in the
next canonical retry, so runtime changes cannot be attributed solely to tiling.

Focused coverage compares every output field and claim against the original
writer across multiple tile sizes, live/padding boundaries, every allocation
failure, and zero-denominator rejection. Existing borrowed-output mutation,
alias and failure-atomicity tests remain in the same focused target.

```sh
python3 scripts/zig_serial_build.py --cwd src/frontends/riscv test-recursion-framework-interaction -Doptimize=ReleaseSafe --summary all
```

No completed proof, peak-memory reduction, or speedup is claimed yet.

## Completed focused checks

- Framework interaction gate: 4/4 tests passed, 5-second compilation and
  478 ms test execution. Includes borrowed failure atomicity and owned tiled
  parity/failure cleanup.
- Compact metadata gate: selected named test passed through the nonempty-selection
  guard; 9 seconds total build/run. Exact claims/columns match across windows
  of 1, 2, 4 and 8 rows, including allocation rollback for each geometry.

```sh
python3 scripts/zig_serial_build.py --cwd . test-riscv-blake3-memory-update '-Driscv-test-filter=BLAKE3 memory update proves compact parent metadata' -Doptimize=ReleaseSafe --summary all
STWO_B3EH_LEAF_ARTIFACT=/tmp/stwo-b3eh-canonical-leaf.artifact python3 scripts/zig_serial_build.py --cwd . test-riscv-blake3-execution-commitments '-Driscv-test-filter=BLAKE3 execution commitment Ethereum canonical recursive parent independently verifies' -Doptimize=ReleaseSafe --summary all
```

The second command is still running. It now prints the parent error explicitly
if proving fails, avoiding another direct rerun solely to recover an error name.
