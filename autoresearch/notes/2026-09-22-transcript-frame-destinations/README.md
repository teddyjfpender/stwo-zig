# Transcript direct frame destinations and scoped adapter storage

Mix/root/payload and PoW frames now emit G/XOR rows directly into transcript-owned
unused ranges. The canonical output plan is built before generation and reused
for output wiring. Producers remain indices, so list growth preserves digest-use
updates. State resets, PoW low-bit sinks, transcript bytes and fixed/live equations
are unchanged. PoW frame cleanup is installed before fallible payload-read append.

Frame receipts and plans use the bounded backing allocator. Query, bounded-draw
and fixed-attempt-draw temporary results also use scoped backing allocation. Their
rows and inline output endpoints are copied before destruction, so their temporary
arenas no longer accumulate in transcript metadata storage. Draw/query row copies
still exist; these adapters do not yet emit into final transcript columns.

## Qualification and measurements

ReleaseSafe transcript-plan/native gates pass 8/8 steps, 4/4 tests. The expanded
allocation-failure fixture covers routed mix, private PoW nonce, raw queries,
secure output and later state reset. Both parent proofs independently verify;
codec, handoff parity and allocator ownership checks pass. Plan tests run 1 s /7
MiB reported MaxRSS; native tests 46 s /1 GiB. Separate transcript-sequence gate
passes 2/2 (4 s /394 MiB), including a complete CPU proof and fixed-attempt path.

| Tracked measurement | Before | After |
| --- | ---: | ---: |
| Preparation peak bytes | 622,506,697 | 382,427,223 |
| Handoff retained bytes | 130,557,704 | 130,557,704 |
| Worker peak bytes | 982,008,191 | 982,008,191 |

Preparation peak falls 240,079,474 bytes (38.57%). This resolves the previous
preparation regression, also falling below the older 600,657,997-byte baseline.
The successful threaded preparation/handoff is now explicitly tested with a
512 MiB cap. One-byte and 64 MiB caps still reject. Pipeline reservation settings
and security profiles are unchanged. No timing A/B or latency win is claimed.

The first run stopped at a stale test expecting 512 MiB preparation to fail;
it actually succeeded with peak 416,243,999 bytes. The unexpected-success assertion
left its returned owner unfreed, producing test-only leak output. The assertion
was corrected and the final full tests report no leaks. Further adapter lifetime
changes produce the final 382,427,223-byte peak. Initial logs are retained.

Key remains `0fa2bf60222d4e62cf05dbed0c8892a8c8ba39a62b960d22abc2e65975f9fc46`;
canonical codec remains 116,382 bytes. Diagnostic child q1/PoW0 and parent q8/PoW0
profiles are unchanged. This is not production security qualification.

Next: query/secure-draw direct emission and final committed-column destinations
across transcript/path assembly. Reusable production keys, distinct-child and
parent-of-parent recursion, Metal/default migration and separately reviewed
parameter experiments remain incomplete.
