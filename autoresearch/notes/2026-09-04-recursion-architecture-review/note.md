# Recursion architecture review: soundness, correctness, parallelisability

Date 2026-09-04. Branch `autoresearch/metal-ecdsa-subsecond-20260829` on top of `6084a979`, with the
working tree's uncommitted throughput work. Method: four parallel readers mapped the pipeline (leaf
statement, recursion/aggregation, campaign control plane, provider-shard protocol), four dimension
finders produced 47 findings against code they read, and each non-informational finding was put to three
adversarial refuters (correctness, exploitability, does-the-code-reproduce-it) with a majority rule.
15 survived, 16 were refuted, 16 were confirmed-sound observations. The synthesis pass was cut for cost;
this note is written from the retained finding and verdict records.

Scope note: everything below describes the tree as it stands. Every production activation flag in the
recursion path is deliberately `false`, and most of what follows is a statement of what must be true
before any of them flips, not a report of shipped-and-broken behaviour.

## 1. Architecture as built

**Leaf.** A SegmentV2 leaf statement binds the RV32 execution trace, the sparse memory-provider
commitments, role-aware public data and the completion record. `stage101-metal-autoresearch-v1` proves
one segment per process on the authenticated-AOT Metal engine and cold-verifies it with the CPU engine.
The Poseidon memory provider is proved today as a native 445-column component inside Tree 1/Tree 2 of the
same four-tree proof.

**Provider shards.** `ProviderShardPlanV1` partitions the leaf's 6,671,301 Poseidon2 calls into 26 log18
shards. Two protocols exist: the standalone D5 order proof (what today's sweep uses) and the omit
protocol (`ethereum_omit_protocol_v1`), which projects the provider out of the core and closes
core-plus-N under one shared relation draw.

**Aggregation.** `SpanStatement`/`NodePublicV2` fold children in native Zig; Stage102/Stage104 cold-open
replays Stage101 and both children transitively. The campaign control plane (Python) schedules a DAG over
a content-addressed store with journal and worker-acceptance layers.

## 2. Soundness verdict

Confirmed sound, by code reading and adversarial challenge:

- The leaf prover and cold verifier replay an identical Fiat-Shamir schedule; every root, public input and
  claim is mixed before the challenge that depends on it. The cold verifier re-derives geometry, the
  Tree 0 root, proof of work, relation draws and global cancellation rather than trusting proof bytes.
- The Poseidon2-M31 channel encoding is injective and draws are domain-separated: each mix starts a fresh
  tag-0 sponge, absorbs the previous eight-word digest as exactly one rate block, then the payload, then a
  fixed marker. Today's GPU proof-of-work search is host-verified against that channel.
- Stage102 leaf `NodePublic` statement words come from the freshly verified native capture, not from the
  caller.
- The artifact store fails closed on collision, truncation, mode drift and mid-read mutation, and is
  concurrency-safe across processes.
- Today's uncommitted changes hold up: the threadlocal symbolic arena fails closed across threads, the
  owner-window semaphore is paired on every path, the D5 batch pools propagate per-shard errors
  all-or-none, and removing the prover-side ordered-call self-check costs nothing because the verifier
  recomputes that claim from the admitted call slice.

Findings that survived refutation, in priority order:

1. **Memory and program Merkle roots are single 31-bit words.** `hashPair` returns Poseidon2 output lane 0,
   and the V2 wire carries entry/exit continuation roots as scalar `u32`
   (`src/frontends/riscv/air/memory_commitment/poseidon2.zig:16`, `sparse_merkle.zig:4-9,365`,
   `statement_v2.zig:520-540`). The cross-leaf fold compares only `MachineState`, so a forged entry
   snapshot colliding on a 31-bit root would be authenticated by the leaf's Merkle relation and accepted
   by the fold. That is roughly 2^31 permutations to target a specific root. This is the one finding that
   must be fixed before any production claim: widen the node/root commitment to at least four M31 lanes
   through the sparse tree, the Merkle AIR tuple, the V2 wire, `canonicalCorePublicData` and
   `MachineState`.
2. **The standalone D5 shard proofs are not bound to any leaf.** Each shard draws its own LogUp relation
   context; the only link is a SHA-256 transport session, and the batch owner says so
   (`PROTOCOL_BOUND=false`, `TRANSCRIPT_MIXED=false`). This is exactly why the route flip must go through
   the omit protocol and not through the standalone prover: with a projected core, an unbound shard set
   would leave an open Poseidon bus residual that no field equation closes. The chosen plan does this.
3. **The standalone shard draw skips the 10-bit interaction proof of work** that the leaf protocol
   requires before relation challenges. Same fix: use the omit protocol's single PoW-then-draw.
4. **No recursive proof verifies its children yet.** Parent relations, leaf omission/duplication/reordering
   defenses and root binding are enforced by native host code, and every activation gate is false. Until
   the fold AIR proves child verification in-circuit, campaign output should be called a verified segment
   collection, never a single recursive root.
5. **Host knobs reach proof identity.** `ProviderShardPlanV1.identity` absorbs the residency request
   identity, whose preimage includes owner count, host byte budget and reserved bytes, so shard statements
   are not machine-independent. Today's sweep already demonstrates the symptom: nine owners produced a
   different proof identity. The route-flip plan's `ProviderOmissionPinsV1` graft fixes this by making the
   request comptime pins.
6. **The leaf cold verifier does not re-derive the V2 statement's public input/output digests** from the
   role-aware IO words it uses for LogUp compensation; consistency currently rests on campaign-input
   custody.
7. **STWIEF04 decode runs `postcard.deserializeProof` without the allocation-free preflight**, so
   prover-supplied length prefixes size allocations.

## 3. Correctness and engineering

- The frontend test-inventory guard is red: 121 test-bearing files are compiled by no canonical test
  binary, so the package's own gate cannot signal regressions. This predates today's work but blocks using
  that gate as a control.
- Pooled composition scratch buffers bypass the shared runtime's resident-resource gate, so
  `shutdown()`'s live-resource check cannot see them, and `OWNER_WINDOWS` has no cross-module check
  against `D5_COMPOSITION_DOMAIN_SCRATCH_CONCURRENT_OWNERS`. Both are cheap to close and worth closing
  since I introduced the pool today.
- `defer MetalCommitBackend.shutdown() catch unreachable` in the leaf command turns a legitimate
  fail-closed shutdown error into undefined behaviour in ReleaseFast.
- The GPU proof-of-work search is verified for validity but no test compares its result with
  `Channel.grind`'s minimality on a real channel. The host replay test added today covers the candidate
  function; the end-to-end minimality comparison is still owed.
- Stale protocol flags in `memory_provider_shards/authority.zig:22-28` contradict the V2 modules that
  consume them.

## 4. Parallelisability verdict

Sound foundations: leaves are independent (a native leaf build depends only on immutable CAS inputs and
takes no leases), the CAS is multi-process safe, and the scheduler already supports streaming aggregation
in principle, since a node's dependents become ready as soon as both children commit.

What actually limits throughput today:

1. **The production DAG executes one node at a time.** `ZigWorkerAdapter.max_parallelism = 1`, and the
   scheduler's pool is the minimum over adapters, so there is no cross-node parallelism anywhere in the
   control plane (`scripts/recursive_pipeline_registry.py:72`).
2. **The Zig worker proves leaves on CPU**, not on the Metal engine
   (`recursive_pipeline_worker_native_leaf_v4.zig:38`).
3. **Transitive cold-open makes verification O(N log N)** native re-verifications: every fold and wrapper
   cold-open replays Stage101 for the whole subtree, and the CAS rehashes each object on every reopen.
   For a 210-leaf tree that is hundreds of gigabytes of SHA-256.
4. **Per-leaf fixed costs repeat block-wide work**: each leaf process reopens the entire campaign,
   re-parses the ELF and re-derives the call corpus, which is the ~50 s prefix the sweep measures.
5. **Hard segment-count and cycle caps**: transport pins 210 segments and the V2 statement caps global
   cycles at 2^24, while the block in `ETHEREUM_BLOCK.md` is 389 segments and 1.63 G cycles. The
   389-leaf block cannot be published or scheduled without a protocol change. This is a scope fact worth
   surfacing early: today's 210-leaf campaign is not the full block.
6. **Process-global Metal serialization**: one runtime per process, one leaf per process, and a two-permit
   composition-scratch semaphore shared by all proofs in that process.

The order I would fix these: worker adapter parallelism and Metal-engine leaf proving first (they are
configuration-shaped and unlock the 18-core host), then the per-leaf fixed prefix (prepared-program
cache), then incremental verification to replace transitive cold-open, then the segment-count and
cycle-cap protocol change that the real 389-segment block needs.

## 5. What this means for the route flip

The plan in `autoresearch/notes/2026-09-03-leaf-route-flip-plan/note.md` is consistent with this review:
it routes through the omit protocol (fixing findings 2 and 3 for the flipped leaf), makes the residency
request comptime pins (finding 5), and keeps every production flag false. Finding 1 (31-bit memory roots)
is independent of the flip and is the gating item for any production claim.
