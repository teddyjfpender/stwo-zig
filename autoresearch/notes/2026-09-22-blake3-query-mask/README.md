# Exact BLAKE3 raw query masking — 2026-09-22

The previous turn qualified native absorption variants. This turn implements the
raw-u32 query mask used by core/queries.zig, separately from field challenges.

`blake3_query_mask.zig` uses four canonical bytewise AND lookups, an authenticated
packed-word input and a packed-word output. It has eight main columns, ten fixed
columns, six relation events, twelve interaction columns and no direct roots.
Fixed mask coordinates are typed bytes. Its semantic identity is:
`e0820aaef9e85ecc3c61f993e547a2f2399d7f5a36b50952c3f739029ba8a183`.

Every supported domain log 0..31 is checked. Output indices remain packed bytes:
2^31-1 is a valid 31-bit index, and representing it as a single M31 would alias
zero. Raw words fffffffe and ffffffff are accepted and masked normally; the
field-challenge rejection predicate must not be applied to queries.

Focused commands:

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-query-mask test-blake3-query-proof -Doptimize=ReleaseSafe --summary all
```

The unit gate pins semantics, authenticates the relation plan, exports the
framework program and checks every log with boundary words, actual table
membership and each output-byte mutation. Invalid domain logs and source/output
namespace collisions are rejected. The proof gate hashes a canonical draw and
binds all eight raw words to 20-bit indices through the new component and real
providers, with independently rebuilt trusted preprocessing.

The proof fixture's state and index are public. Remaining integration includes
private-state raw draw batching, sequence counters, partial blocks, query ordering,
deduplication, folding and path admission. PoW, private payload/source admission,
production identities, Metal and parent-of-parent qualification also remain.
Development proofs use eight queries, blowup 1 and zero PoW; no production speed
or security claim is made. Production still selects Poseidon and the full goal
remains active.

Both focused gates pass. The complete proof passed in the combined run; the unit
assertion was then corrected to distinguish ValueOutOfRange (a byte mutated from
255 to 256) from InvalidTuple (an incorrect in-range byte), and the unit-only rerun
passed. Both terminal logs are preserved. No prover constraint changed for that
assertion correction. The core verifier rejects changed expected indices and
substituted preprocessing roots through trusted admission.

Proof runtime: approximately 2 seconds, max RSS 347 MiB. Final unit runtime:
515 ms on M5 Max. Formatting and diff checks pass; changed manual sources remain
below the source-size ceiling. Earlier evidence snapshots remain unchanged.
