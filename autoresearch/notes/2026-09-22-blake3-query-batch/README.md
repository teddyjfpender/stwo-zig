# Authenticated BLAKE3 query batches — 2026-09-22

The previous turn qualified raw query masks. This turn assembles complete native
query batches from an authenticated state producer, including partial blocks.

`blake3_query_witness.zig` builds consecutive draw frames and routes the same
private state into each. Every requested raw word feeds a bytewise mask; unused
final digest words have zero consumer multiplicity. Zero queries consume no
blocks. A partial final block advances the counter once and discards its suffix.
Output order and duplicates are retained exactly as native drawQueries emits them.
No field reduction or rejection is introduced. Namespaces, counters, output
ranges and summed state-use counts are checked.

The earlier eight-query public-state proof fixture is replaced by a nine-query
proof whose state comes privately from native mixU64(198). It authenticates the
producer, two consecutive draws, routing, masks and public expected indices in
one five-component CPU STARK. Trusted preprocessing never computes or receives
the private intermediate digest. The ninth index exercises a partial second block.

Focused command:

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-query-batch test-blake3-query-proof -Doptimize=ReleaseSafe --summary all
```

Unit cases compare counts 0,1,7,8,9,17 with the actual native drawQueries API,
including 31-bit domains and nonzero starting counters. They check every emitted
index, fixed columns reconstructed with placeholder state, zero-query uses,
invalid ranges, counter/namespace overflow, producer overlap and every backing
allocation failure for a partial two-block batch. The complete proof gate also
checks changed expected output and substituted preprocessing-root rejection.

Remaining: integrate raw query batches into the complete transcript sequence,
authenticate sorted/deduplicated/folded indices and paths, then PoW, private
payload/source admission, identities, Metal and parent-of-parent qualification.
Private here means outside the public statement, not a zero-knowledge claim.
Development fixtures use eight proof queries, blowup 1 and zero PoW; no production
speed/security claim is made. Production still selects Poseidon; the full goal
remains active.

Both guarded tests pass, including the complete core-verifier proof. Unit runtime
was 509 ms; proof runtime approximately 3 seconds, max RSS 350 MiB on M5 Max.
Formatting and diff checks pass. New manual sources remain below the source-size
ceiling; earlier evidence snapshots are unchanged.
