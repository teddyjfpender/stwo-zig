# Native lifted BLAKE3 leaf geometry — 2026-09-22

The previous turn connected raw queries to ordinary Merkle paths. This turn checks
lifted leaf geometry against the actual native commitment/decommitment pipeline.

The native column projection is
`((position >> (max_log - column_log + 1)) << 1) | (position & 1)`.
It preserves the low bit; ordinary right-shift folding is not interchangeable.
Columns are serialized in ascending log size, retaining original index order for
equal sizes. `blake3_lifted_leaf_plan.zig` exposes those checked rules and orders
queried values without changing the existing typed hash/path implementation.

Focused command:

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-lifted-path -Doptimize=ReleaseSafe --summary all
```

The gate commits real BLAKE3 columns of log sizes [3,1,2,3], decommits every row,
and passes the native lifted verifier with path capture. Every projected column
index is checked against native queried values, including both parity cases and
equal-size column ordering. It then produces a complete typed depth-three path
proof for a captured opening to the native commitment root. Siblings stay outside
the public statement; trusted preprocessing does not calculate them.

The proof's wrong-statement case exchanges values from equal-sized columns,
checking their canonical tie order. Additional checks reject out-of-range
positions, mismatched row shape and unsupported column sizes, with allocation
failure coverage for the plan and ordered row allocation.

Scope: this qualifies lifted leaf ordering/projection and a captured path, not
PCS DEEP equations or a complete FRI verifier. Queried leaf values are public
auxiliary statement coordinates here. Sampled-value/source admission, private
payload integration, complete PCS/FRI composition, production identities, Metal
and parent-of-parent qualification remain. Development proofs use eight queries,
blowup 1 and zero PoW; no production speed/security claim is made. Production
still selects Poseidon and the full goal remains active.

The guarded test passes, including native lifted verification and the complete
core-verifier typed proof. Runtime was approximately 3 seconds, max RSS 353 MiB
on M5 Max; compilation took 21 seconds. Formatting and diff checks pass. New
manual source files remain below the source-size ceiling; earlier snapshots
remain unchanged.
