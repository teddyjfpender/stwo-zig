# Canonical BLAKE3 query-to-path admission — 2026-09-22

The previous turn qualified transcript PoW. This turn connects authenticated raw
query coordinates to exact sorted/deduplicated Merkle path positions.

`blake3_query_path_plan.zig` validates domain/folding bounds, reuses native
Queries.init and Queries.fold, and retains a binary-search mapping from each raw
coordinate to its canonical unique path. Admission requires exact ordered path
positions, rejecting missing, extra, changed or reordered entries. Duplicate raw
queries remain represented in the mapping while sharing one path.

The new complete proof fixture uses nine raw queries over a two-leaf tree. The
same public auxiliary raw list is constrained by BLAKE3 draws and deterministically
used by trusted preprocessing to choose the two unique private-sibling paths.
Changing raw coordinates cannot bypass their draw constraints; supplying a
separate incompatible path list fails admission. Trusted preprocessing computes
neither sibling hashes nor intermediate Merkle digests.

Focused command:

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-query-path-plan test-blake3-query-path-proof -Doptimize=ReleaseSafe --summary all
```

Unit coverage includes duplicate/order mapping, each folding depth of a small
domain, the full 31-bit index edge, empty queries, invalid domain/folding bounds,
missing/reordered/substituted paths and every allocation failure. The complete
six-AIR proof combines query hashing/masking, routed Merkle hashing and bounded
private siblings, with real tables, core verification and independent trusted
preprocessing. Missing/reordered path lists and changed roots are negative cases.

Scope: raw query indices and leaf payloads are public auxiliary statement data
in this gate. This enables deterministic trusted normalization; it is not a
private sorting AIR. Folded mappings are unit-qualified, but the complete proof
uses unfolded depth-one paths. Lifted PCS/FRI geometry, sampled-value/source
admission and private payload integration remain required. Production identities,
Metal and parent-of-parent qualification also remain. Development proofs use
eight queries, blowup 1 and zero PoW; no production performance/security claim is
made. Production still selects Poseidon and the full goal remains active.

Both guarded tests pass, including the complete core-verifier proof. Mapping tests
ran in 489 ms; the combined proof took approximately 3 seconds, max RSS 359 MiB
on M5 Max. Formatting and diff checks pass. New manual sources remain below the
source-size ceiling, and prior evidence snapshots remain intact.
