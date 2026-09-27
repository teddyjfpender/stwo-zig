# Lifted queried-value consistency — 2026-09-22

The previous turn made verified progress on framed payload wiring. This turn
adds a checked opening-batch boundary to the lifted leaf geometry plan.

`admitQueries` validates column/query shapes and position bounds, then projects
every position through the native parity-preserving column index. Repeated
projected rows must carry equal M31 values. This checks both duplicate tree
positions and distinct tree positions that alias one row of a shorter column.
One hash map is reused across columns, giving expected linear work in the number
of queried values and avoiding a pairwise scan.

Focused command:

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-lifted-path -Doptimize=ReleaseSafe --summary all
```

The gate admits real native BLAKE3 decommitments for mixed logs [3,1,2,3], rejects
a changed value at a repeated short-column row, rejects a truncated column and an
out-of-domain query, and exercises allocation failures. The existing complete
typed path proof to the native root remains part of this gate.

This is an opening-data consistency boundary, not standalone cryptographic
admission. Root/path verification still authenticates values; PCS DEEP/FRI
composition and private child-proof source wiring remain unfinished. The helper
is exercised before leaf construction in the integration fixture and has not yet
replaced the production child-proof admission path. Production identities, Metal
and parent-of-parent qualification also remain. Poseidon is still the default;
no production speed/security claim is made and the original goal remains active.

The guarded integration test passes, including native verification and the
complete core-verifier path proof. Runtime was approximately 3 seconds, max RSS
353 MiB on M5 Max, with 21 seconds compilation. The proof uses development
parameters (eight queries, blowup 1, zero PoW). Formatting and diff checks pass;
changed sources remain below the manual source-size ceiling. Prior evidence
snapshots are preserved.
