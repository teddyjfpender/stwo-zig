# Shared digest frame routing — 2026-09-22

Progress toward authenticating private transcript state. The previous turn
qualified native challenge consumption; this turn generalizes the existing
Merkle byte router and removes its duplicate implementation.

`blake3_frame_route.zig` binds up to two named digest roles to authenticated
producer wire ranges. The native Frame.write method supplies framing constants
and digest provenance; the existing byte-route AIR selects their bytes into
canonical hash input words. Source multiplicities account for each actual word
consumer. Missing, unused or duplicate role bindings, overlapping producer
namespaces, invalid wire ranges and destination aliasing are rejected.
`blake3_node_route.zig` is now a 25-line compatibility adapter.

The router never uses bound digest byte values as fixed constants. Other payloads
remain public constants: private field/word payload conversion is not supplied
by this helper. Caller assembly must replace hash input boundary rows with these
routes and authenticate all producer multiplicities.

Validation:

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-byte-route test-blake3-routed-proof -Doptimize=ReleaseSafe --summary all
```

Four guarded tests pass. New tests reconstruct native draw, integer absorption,
root absorption and PoW frame bytes, including partial-word padding, high counter
bytes, one/two digest sources, malformed bindings and every allocation failure.
Existing typed byte mutation/export and Merkle frame tests pass. The existing
complete CPU routed Merkle proof also passes after switching to the shared
router. A complete private transcript transition proof is still required; these
frame tests do not establish that broader result.

Unit runtime: 526 ms. Complete Merkle proof runtime: approximately 3 seconds,
max RSS 347 MiB. These are development-loop measurements, not production speed
claims (proof fixture: eight queries, blowup 1, zero PoW). Formatting and diff
checks pass. Changed manual sources remain below the source-size ceiling.

Next integration: bind transcript state producers through these routes into
absorption/draw hash graphs, then connect ordered challenge attempts and raw-u32
query extraction. Production source admission, PCS/FRI geometry, PoW constraints,
keys, Metal and parent-of-parent qualification remain. Production still uses
Poseidon; the full migration and original recursion optimization goal are active.
