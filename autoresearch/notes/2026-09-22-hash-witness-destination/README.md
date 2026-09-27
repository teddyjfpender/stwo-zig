# Canonical full-hash witness into caller-owned rows

Added Destination and prepareInto to blake3_hash_witness. The caller can reserve
exact G, XOR and boundary slices and generate into them without an intermediate
owning Rows result. The internally built canonical hash plan determines exact
shapes; mismatches reject before destination mutation. Caller owns the slices and
must discard partial output on later failure. Graph and wire workspace remain local.

Owning prepare and borrowed prepareInto use the same writePlan evaluation loop.
Live generation now allocates uninitialized final arrays and fills them once,
removing the prior fixed G/XOR initialization that was immediately overwritten.
Trusted fixed-row generation remains independently derived from the plan. Boundary
construction is shared without using the live witness as verifier authority.

## Qualification

ReleaseSafe test-blake3-hash and test-blake3-frame-witness: exit 0, 8/8 steps,
4/4 tests. Hash tests run 589 ms / 17 MiB; routed frame test 676 ms / 2 MiB.
Across empty, block, chunk and unbalanced-tree lengths through 8,193 bytes,
both APIs match standard BLAKE3 digests and every typed row coordinate. Existing
trusted fixed-row parity, exact lookup-closure mutation checks and graph partial
allocation cleanup also pass. Wrong destination shape rejects before the checked
sentinel changes. No full native proof or timing benchmark was repeated for this
focused kernel change, and no end-to-end speedup is claimed.

The destination API is not yet wired into adapter buffer reservations or committed
columns. Next transfer adapter reservations directly to this kernel, avoiding the
current prepare/append copy, and qualify complete native proofs. This is groundwork
for direct generation, not completion of the direct-layout or production migration
objectives. Other outstanding scope remains in the main migration report.
