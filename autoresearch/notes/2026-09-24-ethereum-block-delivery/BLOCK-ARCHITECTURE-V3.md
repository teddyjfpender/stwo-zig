# Block-v3 execution and memory binding

Status: implementation in progress; there is no verified Ethereum block receipt.
The canonical q70/PoW26 unmodified SHA/Keccak/SHA one-segment receiver now
passes through freshly verified opcode and 103-access extension sidecars,
sorted memory, the public image, both range-table families, a 977,154-byte
recursive leaf, and a 936,468-byte exact outer root. The fixture has 108 total
accesses; leaf proving took 34.04 s and outer proving 14.37 s, with
13,729,830,183 bytes tracked recursion peak. This is a complete one-segment
qualification, not a multi-segment or mainnet block measurement. The scoped
machine-readable result is in `canonical-v4-sha-keccak-one-segment.json`.
The canonical q70/PoW26 one-segment, no-precompile combined receiver test now
passes: 11 execution accesses close against memory, a 966,588-byte recursive
leaf and 933,424-byte singleton exact root freshly verify, and a wrong outer
key is rejected. Leaf proving took 50.96 s, outer proving 19.16 s, with
13.73 GB tracked recursion peak. This qualifies the combined receiver shape,
not SHA/Keccak execution or block-scale performance.
The two-segment diagnostic q8/PoW0 v3 no-custody recursive fixture passes with
fresh native and sidecar verifiers and rejects a wrong initial-image anchor.
A three-segment 2+1 exact forest also passes with three fresh sidecar and leaf
proofs, a fresh dyadic proof, and a single fresh-verified outer root; a wrong
independently pinned outer key is rejected. The fixture's arena allocator grew
to about 27 GB RSS, so this is a correctness qualification, not a memory target.
The one-segment no-precompile leaf path has also passed canonical q70/PoW26
qualification; the multi-segment forest remains diagnostic security only.
The one-segment SHA-profile diagnostic core fixture now also fresh-verifies
native execution, its opcode-access sidecar, sorted memory, the public initial
image, and both byte-range table families under one SourceSeal. It uses a real
terminal segment and has 11 matching runner/sidecar accesses, but contains no
precompile calls. The unmodified SHA/Keccak/SHA fixture correctly fails the
global bus at 5 sidecar events versus 108 runner events; the 103 omitted
events are exactly SHA26 + Keccak51 + SHA26. Committed extension-column
adapters now have a diagnostic q8 proof that fresh-verifies all 103 accesses
from the same native commitments and rejects a wrong independently pinned
witness root. The unmodified 108-access SHA/Keccak/SHA fixture now passes the
combined q8 core: opcode and extension sidecars, sorted memory, public initial
image, and separate range-table families close under one sealed statement.
Malformed sparse extension proof rosters and altered counts are rejected before
PCS work. A real multi-segment block receipt remains to qualify.
A focused production-artifact audit of the genuine three-NOP segmented fixture
found 11 runner accesses, 11 typed accesses, and an 11-event packaged opcode
sidecar. All three `ADDI x0,x0,0` rows are present. The earlier 11-versus-5
attribution to NOP elision was stale or conflated with the unmodified
SHA/Keccak workload's five opcode accesses plus 103 precompile accesses. No
global x0 filtering is applied.

The public initial RW image is checked against an independently pinned BLAKE3
root. Its complete first-touch roster is sealed before the shared relation
challenges. This avoids a separate sparse-tree STARK for each 4,096-leaf
source chunk on the public mainnet path. The measured full roster check covers
666,708 nonzero words and 3,142,932 first touches in 0.226 s with 118.9 MB
tracked peak; this is a scoped source check, not a block proof.
At a 4,096-word cap, proving the image as independent chunks would require
`ceil(666708 / 4096) = 163` source proofs. The cap is per proof, not a claim
that one 4,096-leaf proof covers the whole root. The public-image receiver
recomputes the whole root once and authenticates the first-touch roster, so
this 163-proof cost is absent from the selected public mainnet path.
That choice carries the public source records to the receiver: at the measured
mainnet counts, the nonzero-image file is 5,333,664 bytes and the first-touch
file is 31,429,320 bytes, or 35.06 MiB together. The 0.226 s measurement is
the scoped verification of those records and root, not a succinct proof of a
private image. A verifier that cannot obtain the public image needs a different
source-proof route.

The block-v3 recursion statement carries that initial root as an invariant
memory anchor. A segment's ordinary native RW roots are **not** expected to
match adjacent segments at public I/O boundaries: native custody omits public
input on entry and output on exit. Each native proof and same-root typed access
sidecar retains its own native root pair. The sidecar covers every committed
opcode access slot. The sorted-memory proof and shared transition relation
must close *all* execution events against one global ordering, and the initial
source relation must close against the pinned public image. Only that complete
batch establishes memory continuity; the invariant anchor alone does not.
The complete receiver must derive and pin that anchor independently; a
producer-supplied endpoint root alone cannot establish it.

A two-segment [canonical q70/PoW26 fixture](block-v4-two-segment-recursive-q70.json)
passes the complete v4 receiver with real SHA/Keccak calls, one sorted replay,
one initial image, shared opcode/extension tables, two recursive leaves, a
dyadic parent, and one exact outer root. A later
[unpadded q70 run](block-v4-two-segment-unpadded-recursive-q70.json) also passes
with a native-verified zero-opcode terminal leaf; changed empty-sidecar root,
proof bytes, and claims are rejected. The unpadded core took 10.907 s and
recursive proving took 165.352 s on this CPU host. Both recursive fixtures
have empty public I/O payloads and external calls in both segments.

A separate [signer-plus-Keccak q70 fixture](block-v4-signer-keccak-complete-q70.json)
also passes the complete receiver: 103 events comprise 9 opcode, 43 signer,
and 51 Keccak accesses. The recursive leaf took 33.804 s to prove and the
exact singleton outer root 13.722 s, with a 13.734 GB tracked recursion peak.
This is a one-segment correctness qualification, not block throughput.

The typed load/store bridge address-unit mismatch is fixed. A bounded
[q8/PoW0 production assembler fixture](block-v4-cpu-multi-real-io-q8.json)
now fresh-verifies two consecutive segments with a four-byte public input and
output, zero precompile calls in the first leaf, and 51 Keccak caller accesses
in the terminal leaf. It covered 70 memory events in 8.467 s with 819.8 MB
tracked peak. This fixture verifies the v4 core but does not produce recursive
proofs. Output publication must remain in the terminal leaf so its native
statement proves local output-address access.

The new leaf protocol ID is versioned and depends on the security config, but
not on SourceSeal. Manifest statement IDs are needed to construct SourceSeal,
so including the seal in the job ID would create a cycle. Instead, a leaf's
binding identity includes its statement ID, native key, native root pair,
sidecar witness root, event count, transition sum, and sealed channel digest.
The complete receiver must fresh-verify both proof artifacts and recompute
every roster and challenge seed. A host-created receipt is never authority.
The exact-count outer proof also needs an independently pinned outer key ID
and forest roster digest; neither may be taken from the proof bundle itself.

Execution byte requests have their own exact-count table shard family. The
existing memory table shards reserve at most 35 requests per sorted event;
mixing the sidecar's 14 additional requests into that cap would invalidate the
field-safe shard plan. The two families are sealed separately before the
relation challenge and their claims must close independently.

The complete receiver has fresh-verified two-leaf q70 proofs, but its fixture
fills the expected outer key and forest digest from newly produced proofs.
Production admission must pin those identities independently before reading
recursive bytes. The bounded two-segment assembler retains all native witnesses
and proof bytes across both segments. A separate two-pass producer now replays
one segment at a time, seals a per-segment root/counter roster, and stages hashed
proof files. Its two-segment real-I/O q8 fixture passed with matching SourceSeal
and first-round digest; its measured 7.442 s ends before the verification
callback, so it is producer time only. A third pinned replay lets a private
incremental receiver fresh-verify staged execution files one at a time and
retain only small public-data/receipt arrays. A later strict
[two-segment real-I/O q8 run](block-v4-cpu-streaming-incremental-real-io-q8.json)
passed with clean allocator teardown: production took 7.507 s and fresh
incremental core verification took 4.508 s. Its 356.8 MB receiver allocator
peak excludes staged-loader buffers allocated through the producer. That
replay is bounded but is not succinct verification. The streaming complete
receiver then passed a joined
[two-segment real-I/O q8 fixture](block-v4-cpu-streaming-complete-real-io-q8.json)
with two recursive leaves, a dyadic parent, exact outer root, wrong-pin
rejections and clean teardown. Staged production took 7.627 s, recursive
proof generation 33.908 s and fresh complete verification 5.180 s. This
fixture still makes recursive proofs from a bounded in-memory assembly, not
the new staged-leaf producer, and derives test pins from those proofs. The
same real-I/O shape then passed the
[canonical q70/PoW26 complete receiver](block-v4-cpu-streaming-complete-real-io-q70.json)
with clean teardown: staged core production took 10.148 s, recursive proof
generation 167.262 s and fresh complete verification 5.600 s. It closed 70
events, including 51 Keccak accesses in the terminal leaf; the first leaf had
zero external calls. That earlier canonical fixture retains an in-memory
recursive producer and test-derived pins. A later
[canonical file-backed run](block-v4-cpu-file-complete-real-io-q70.json) staged
each leaf, its dyadic parent, and the exact outer proof separately, then
fresh-verified the complete statement by loading and releasing one recursive
file at a time. Core-plus-leaf generation took 106.840 s, forest proving
41.722 s, outer proving 63.101 s, and fresh file verification 5.473 s. A
wrong independently supplied final-manifest SHA is rejected before proof
access; receiver-budget teardown has zero live bytes. No tracked receiver or
process peak was logged for that run. A subsequent
[detached bundle q70 run](block-v4-cpu-detached-bundle-real-io-q70.json)
persisted and reopened the core/recursion metadata, used separately pinned
candidate/final manifests and recursion policy, and freshly verified all
staged proofs. Core-plus-leaf generation took 105.111 s, forest proving
41.144 s, outer proving 62.869 s, and detached complete verification 5.435 s.
Bundle, final-manifest and recursion-policy hash tampering is rejected;
tracked allocations close to zero. The enclosing build-and-test process took
402.31 s with 14,192,869,376 B max RSS, which is not a receiver-only peak. The
[q8 staged run](block-v4-cpu-staged-outer-real-io-q8.json) rejects changed
parent and outer files on hash-pinned reload. These are two-segment fixtures;
their policy hashes are generated within the test, then supplied separately
to the receiver. The v4 producer and verifier CLI roots compile in ReleaseFast.
The command-line path still needs a run with independently provisioned policy
pins. A full 218-segment claim also needs that integration and measured wall
time and peak memory on the admitted block.

The old-custody 218-segment mainnet geometry replay shows 818,809 declared-program rows
in every native segment and roughly 9–10 million BLAKE3 commitment rows in
early segments. The program provider already uses verifier-authenticated
fixed rows; it does not prove a separate ROM Merkle path per word. A versioned
active-row schedule can omit zero-fetch program rows while retaining the full
ROM root check. The larger RW-boundary work remains inside native proofs and
cannot be removed until a versioned native relation delegates that authority
to the complete block-wide sorted-memory proof.
