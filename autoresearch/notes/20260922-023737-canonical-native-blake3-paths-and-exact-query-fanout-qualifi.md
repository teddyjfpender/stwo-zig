---
title: Canonical native BLAKE3 paths and exact query fanout qualified
author: Teddy Pender
created_utc: 2026-09-22T02:37:37Z
---

# Canonical BLAKE3 paths on native RISC-V captures

The full-STARK path builder is now blake3_stark_paths, shared by the existing
recursive fixture and real native BLAKE3 captures. The fixture-only source file
was removed and both fixture callers now import the canonical module. Production
path/input preparation no longer imports the proof fixture or uses testing
allocators/assertions. Root, geometry and read mismatches return explicit errors.
The same Merkle plans, root ports, typed selectors, scalar opening bindings,
lifted projections and read-only alias consistency rows remain in use.

The real nonfinal native capture prepares every trace/FRI path: 39,816 G rows,
2,352 selector rows and 781 private opening-value sources. Each recomputed root
must match its captured commitment. A high-bit sibling mutation rejects with
InvalidStarkPathRoot. Query path counters roll back on failure. Successful
replanning resets/replaces the complete path inventory's counters rather than
accumulating duplicate reads. The regression runs successful preparation twice.

Native query rows now support applyPathReads after path planning. It adds exact
path-selector and lifted-projection counts to graph use counts plus the FRI
consumer. All candidate counts and destination identities are admitted before
any row changes. Reapplication derives weights from the graph and is idempotent;
both fixed and live rows are updated consistently. The gate checks idempotence.

Arena ownership is transferred after both row lists finish allocating, preventing
stale arena ownership if list finalization grows its storage. The opening-input
module uses direct core/boundary imports rather than proof fixture aliases.

Serial qualification command:

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-native-segment test-blake3-combined-fri -Doptimize=ReleaseSafe --summary all
```

The initial batch passed 8/8 steps and 4/4 tests, including the existing complete
joined FRI/recursive fixture proof (32 s / 7 GiB; compile 42 s / 2 GiB) and native
segment gate (20 s / 1 GiB; compile 1 min / 4 GiB). Final replan-regression batch
also reached terminal exit 0: 8/8 steps, 4/4 tests passed, with the same reported
runtime/memory summaries. Formatting and git diff --check pass. No broad suite
ran and no live build remains.

Scope: native path preparation and a shared-builder fixture parent proof. This
is not yet a complete native recursive parent proof. Opening scalar producers,
root/nonce connections, public-boundary authority and complete roster integration
remain. Statement-independent keys, production artifact admission, Metal and
parent-of-parent qualification remain open; tiny native q1/PoW0 results establish
no production speedup.
