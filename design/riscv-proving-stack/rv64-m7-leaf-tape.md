# M7 leaf seed tapes

Status: the opt-in v3 emitter/cache is qualified for byte identity and fresh
reception on both development blocks. It remains opt-in pending final combined
configuration selection. V1/V2 latency regressions remain in the receipts.

`STWO_RV64_LEAF_SEED_TAPE=check` records leaf seeds directly from the
independently verified native proof capture and public inputs, builds the full
trace-only graph, and compares every seed coordinate against its origin metadata.
`=1` enables graph-free preparation after an in-process class template and PP
have been constructed from the full graph. The code default remains off.

The CPU emitter follows `proof.guess`, `Cpu.Statement.init`, and the local GKR
`wireProof` order. Every other guessed value in the verifier body is a derived
witness hint. Truth/Keccak emitters follow their respective statement prologues.
The shared proof emitter is the M6 fold emitter, including Merkle cap order.

Class keys bind the source FIXED root, any canonical binding identity, full PCS
geometry and mask offsets, exact local GKR roster and proof structure, outer
profile and padding shape. Scalars represented as public guessed wires remain
per-request seed data. Receiver code never trusts a class key or reads a tape.
The existing plan template checks seed count, constants, capabilities and plan
identity. A bounded-template cache miss rebuilds the ordinary graph. Durable
proof restoration and non-pipelined paths retain full graph construction.

This step removes warm per-leaf graph and host plan construction. It does not
yet replace the device's approximately 146k dependency levels with parallel
Blake compression fills, preinstall cold leaf/fold classes, or claim to meet the
M7 RSS limit. Native verification/capture and fresh outer verification remain
mandatory on the producer, and the independent receiver is unchanged.

## Retained negative measurements

All numbers below are loaded-pod observations [M], not quiet-run gains.
The same-session M6 warm control was 13.44/13.52 s on 26235156 and
18.82/18.93 s on 24628607. V1 tape-on measured 13.35/13.37 s and
24.06/23.07 s, respectively. V2 compressed leaf host templates with a
portable varint codec and restored request-leased leaf device placement:
13.27/12.76 s and 22.98/21.64 s. Neither variant is promoted.

V1 and V2 each passed every complete proof-artifact comparison over six
requests and fresh cache-disabled M6 receivers on both blocks. Each check
mode compared all seed coordinates on 56 leaf builds. V2 additionally
compared decoded template tasks and PP columns against fresh full graphs.
Exact WIP source patches and their SHA-256 lists are retained beside the
receipts under `vectors/reports/rv64-m7-20261105/leaf-tape/`; source labels
must not be confused with a later integrated binary.

The cache limits exposed two real problems: partial PP/plan cache pairs
caused redundant fallback work, and using the fold's immutable device
placement for leaf task plans caused churn. V2 fixes those but still has
raw fold entries consuming the shared caps and slow varint decoding.
## V3: complete host templates within bounded cache caps

V3 uses independent 16,384-word blocks, per-field modular deltas and byte
planes, optionally compressed with the system LZ4 block API. It decodes on
the existing bounded proof pool. Linux loads `liblz4.so.1` once; other builds
retain the portable codec. No proof, verifier, transcript or persistent cache
format depends on this library. The exact loaded library SHA is in each gate's
provenance. `STWO_RV64_PACK_FOLD_CACHE=1` applies the same storage to folds.

All ten changed runtime files matched the gate's source SHA list. The full
matched 128-oracle CUDA image passed the source catalogue gate. Codec tests
passed 3/3 [M]; check mode passed full seed, decoded PP and decoded task
comparisons on both blocks, with all four requests M6-byte-identical and fresh
receivers accepting both. Production OFF and ON arms each passed all six
artifact sets and fresh receivers on the first pair [M].

Both arms use the same driver/library, compact native ingress, packed fold
caches, EAGER loading, no persistent store and composition enqueue disabled.
Warm request medians are [M] 14.243 -> 12.172 s on 26235156 and 19.326 ->
17.809 s on 24628607. Warm recursion medians are [M] 8.926 -> 6.970 s and
12.414 -> 10.706 s. One-minute pod loads before OFF/ON were [M] 22.61/16.26;
these are shared-pod observations, not isolated causal estimates.

ON peak RSS is [M] 23.962 GiB (OFF 22.961 GiB). The earlier separate-binary
M6 control was [M] 33.784 GiB: that reduction includes the combined capture,
compact ingress and cache changes. Auto-arena device usage remains [M] about
31.5 GB, above target. The explicit 22 GiB arena completed all four requests
in its two-repeat gate, every artifact matched M6 and both fresh receivers
accepted [M]. Sampled whole-device peak was [M] 27.815 GB, RSS 24.172 GiB,
warm small/headline request 12.122/18.459 s. This establishes those four
observations; a separate composed graph experiment failed its sixth request,
so four successes are not a universal memory-admission guarantee.

Over the six-request ON producer, [M] 37 PP templates occupied 427,237,186 B
versus 22,741,171,200 logical B. Task payloads occupied [M] 586,301,378 B
versus 19,422,077,984 logical B, with total plan-cache ownership 738,024,070 B
including indices/seeds/levels. There were [M] zero cap refusals and 57 cached
leaf uses. PP/task decode medians were [M] 110.2/77.2 ms. Cached leaf host
preparation still took [M] median 611.6 ms, so the 100 ms target is open.

Receipts `v3-*-daemon.json`, every artifact fingerprint in `v3-*-parity.json`,
source/library provenance and raw cache counters are retained beside V1/V2.
Root proofs remain [M] 750,136/708,696 B; no proof-size reduction is claimed.
