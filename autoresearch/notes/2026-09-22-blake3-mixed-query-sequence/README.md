# Mixed raw-query and secure-challenge sequencing — 2026-09-22

The previous turn qualified private-state query batches. This turn integrates
those batches into the same transcript sequence as absorption and secure draws.
The operation list now determines query starting counters; callers do not supply
an independent starting counter at this layer.

A query operation preserves private state and advances the shared counter by
ceil(query_count/8). An empty batch advances nothing. Subsequent secure draws
continue at that counter, and absorption resets it. The sequence reuses the
existing batch builder and accumulates its producer uses alongside every other
state consumer. The test-only roster now supports the sixth AIR for query masks;
production rosters and protocol identities are unchanged.

Focused command:

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-transcript-sequence -Doptimize=ReleaseSafe --summary all
```

The native comparison and complete proof fixture now contain sixteen operations:
all absorption types, consecutive secure draws, a nine-query raw batch followed
by another secure draw, absorption reset, empty raw queries and a final secure
draw. Eight secure challenges and nine raw indices are compared to native
behavior. Fixed columns are independently rebuilt across all six AIRs; the full
proof includes real table providers and trusted preprocessing admission checks.

Remaining: query sorting/deduplication/folding and path admission, PoW, private
payload/source admission, production identities, Metal and parent-of-parent
qualification. Public operation payloads and expected outputs remain fixture
statement data; intermediate transcript state remains private. These are not
zero-knowledge or production-security claims. Development proofs use eight
queries, blowup 1 and zero PoW. Production still uses Poseidon and the full
recursion optimization goal remains active.

Both guarded tests pass, including the complete core-verifier proof. Total test
runtime was approximately 4 seconds, max RSS 380 MiB on M5 Max; compilation took
22 seconds. Formatting and diff checks pass. Changed manual sources remain below
the source-size ceiling. Previous evidence snapshots are preserved.
