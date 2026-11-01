# Combined Word16 services prefix

This concrete protocol joins one native-2n CPU proof per shard to present Keccak,
ADD and DOUBLE bridges, and independently sized native-4n arithmetic truth
proofs. Absent bridge columns and their five debts are omitted/zero. The accepted
LE-v2 native tags are exactly 0x10001, 0x20011 and 0x20012. Existing plain,
Keccak-only and secp-only routes retain their narrower acceptance rules.

Every immutable fixed key and actual MAIN root enters the complete ordered
manifest before shared RAM14, Keccak IO11 and secp Wire35 challenges. Local
chi/XOR/polynomial/range challenges remain independently scoped. Physical claims
are transcript-bound before interaction commitment. Each STARK is verified;
then three independent RAM/IO/Wire sums must close. CPU-local closure excludes
only those declared shared debts. INIT and TERM claims retain independently
validated expected-image anchors. Call-ID covers, epochs, CPU boundaries,
permissions, alignment, full-u64 pointer spans and query masses are admitted
before proof allocation.

`execution.produce` is a bounded qualification coordinator, retaining multiple
PCS owners across the manifest barrier. It does not establish arbitrary fanout
memory bounds. CPU MAIN and INTER handoffs consume combined original backing
allocations; narrow advice survives until interaction publication. Truth MAIN
currently uses the qualified borrowed-column path. No CPU degree lift or repeated
CPU proof per service is required.

`wire.read` bounds metadata, counts, geometries, masses, sidecars and proofs before
key construction. Transport hashes detect corruption; they do not establish
acceptance. The caller constructs trusted keys and Expected independently and
calls `execution.verify`. Only one binary INIT/TERM sidecar is serialized.

The retained fixture proves seven native instructions in two shards, three
service calls on the same cross-page buffer, and three truth proofs. It checks
actual locally valid false reset/output proofs against the global receiver.
This is an accepting prefix mechanism, not a terminal Ethereum block proof,
recursion result or whole-block performance measurement. q70/P26/blowup1 has
nominal configuration 96; whole-protocol security bits including rational lookup
mass and union bounds are not established by that number.

`execution.produceWithStorage(..., ?*retained_main_store.Store)` optionally moves
sealed compact MAIN coefficients for both CPU and truth workers into unlinked
file mappings before the manifest barrier. The default `produce` passes null.
The Store must outlive the call; mappings release through the existing PCS
teardown owner on success and failure. This preserves the complete manifest,
physical claims, proofs and wire bytes. Each source retires immediately after
its final proof and receiver obligations have been encoded, so CPU narrow advice
is not retained through later truth composition. These ownership changes carry
no standalone RSS or whole-block timing claim.

The operator harness `scripts/rv64_word16_schedule_sweep.py` measures the
Ethereum driver's lane configurations against pinned artifact hashes. From the
repository root, run `python3 -I scripts/rv64_word16_schedule_sweep.py --help`
for its request, job-tape, reference-hash and receipt arguments. Use `--count=0`
for a complete block and `--verify=all` to freshly verify every measured run.
The default count is a four-CPU prefix. The harness uses macOS `lockf` and
`/usr/bin/time -l`; its transient admission estimates are not hard RSS limits.
