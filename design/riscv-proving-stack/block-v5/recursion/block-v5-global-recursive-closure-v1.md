# Heterogeneous recursive block closure, v1 design

Status: integration design from a read-only source audit. This document does not activate a receiver, claim a complete recursive block proof, or qualify a new proof run. Execution segments, STARKs, devices, and benchmarks remain stopped. The existing fresh all-family detached receiver remains mandatory.

## Current acceptance boundary

`block_v5_cpu_detached_receive_impl_v1.ForCapacity(capacity).verify` reopens independently hash-pinned receiver metadata, derives proof policies, loads the bundle manifest and four source files, and calls the real `Global.verifyCompleteDetached`. It requires every admitted base proof file to be consumed. Receiver metadata, file hashes, public receipts, and reconstructed source sums do not replace cryptographic verification.

`block_v5_global_receiver_impl_v1.ForStack(Stack)` is the existing semantic specification for complete block acceptance. `Pins.validate` admits the execution recipe, common B5SS roster, native catalog, program plan, canonical sorted-memory subtype, caller roster, register windows, and exact block span. `verifyFresh` calls `Programs.admitRoster` before provider consumption, obtains real native/caller/fused receipts inside the fresh verification call, closes RAM and lookup joins, and checks the final accounting equation. `verifyWithTransport` then reconstructs native recursive policies from those private native receipts and verifies the exact execution forest under independently pinned recursive keys/schedules.

Consequently, its current `CompleteBundle` proves two different things: fresh base proofs establish all-family closure; the execution forest establishes the recursive native verifier equations and exact execution span. The forest does not currently replace caller, fused projection, source, RAM, range, ROM, or lookup verification. Its `native_open_sum` is intentionally open rather than zero.

The four new provider families have genuine verifier adapters and public supplies:

| Recursive family | Actual statement and export | Existing bus / receipt constructor |
| --- | --- | --- |
| Native capacity | B5CT actual row counts/activity, frame retirements, first roots, instance/template identity, public compensation, native open sum | `block_v5_capacity_recursive_public_bus_v1.Values.fromCapacity` |
| Sorted RAM lanes | Actual `row_log`, full pinned first/prior/last transitions and ordinals, roots/census, 23 interaction planes, derived 61 equation inputs | `block_v5_ram_lanes_recursive_public_bus_v1.Values.fromLanes` |
| Range16 | Exact contiguous RAM-instance shard, request count, range sum, plan/seal and first roots | `block_v5_range16_recursive_public_bus_v1.Values.fromRange` |
| ROM table | Actual program root/plan, native roster/seal, first roots, exact fetch count and open program claim | `block_v5_program_table_recursive_public_bus_v1.Values.fromTable` |
| Native lookup | Exact contiguous execution group, six demand bounds and six separate claims, plan/seal and first roots | `block_v5_native_lookup_recursive_public_bus_v1.Values.fromLookup` |

These buses supply actual verifier inputs, transcript words and committed roots; their `supply` terms close each recursive leaf's `recursion_wire` obligations under that leaf's own recursive challenges. They do not close the base program/memory/lookup relations with one another. Proposed file claims become usable only after the corresponding real `Leaf.verify` succeeds.

There is no corresponding complete canonical caller-arithmetic, native B5CF fused, caller B5CF fused, or public source verifier adapter in this audit. Those are required additions, not fields that can be filled from host verification receipts.

## Final public statement

Introduce a distinct versioned `BlockStatement`, protocol/key domain and typed receiver. Do not reinterpret the execution OpenV2 statement. Its public identity must bind:

- The actual job ID, ELF/source image identity, execution recipe and versions, public input identity/length, program root, initial and final full sparse RW roots, and initial/final PC and register state.
- The exact B5SS seed, complete logical roster and counts, independently derived native capacity catalog, program/memory/range/lookup plans, initial-source and RW-endpoint plans, register-window mode/version/plan, and caller protocol/profile identities.
- The base PCS configuration, every recursively used key's configuration and child configuration, exact execution count and inclusive cycle span, RAM event count, program fetch count, lookup group count and byte request count.
- The typed child proof coverage and canonical aggregation topology. A subtype/coverage digest must distinguish native B5CT, old NativeV3, RAM lanes and old word RAM, native fused and caller fused, and the actual caller circuit profile. An identical Seal family number cannot select a different verifier.

Any statement descriptor represented only by an external digest requires an explicit trust recipe. Either independently pin its full canonical contents at the verifier boundary and include that boundary in the product contract, or prove the canonical encoding/hash and its relation to all consumed inputs inside recursion. A proof cannot authenticate arbitrary full descriptors merely by taking their producer-supplied digest as a public input. If the desired product is one proof plus compact block public state, the latter hashing/membership route is required for the roster/plans/endpoint descriptors that are currently externally supplied.

All changing public fields must be routed through authenticated child transcript/public-input supplies or a new constrained statement source. They must not become fixed setup constants or free host-computed scalar corrections. In particular, outer closure must connect the RAM bus's normalized/endpoint fraction inputs to the raw claim/pin/challenges it consumes, rather than accepting independently adjustable derived values. The existing admission computes this relation for an independently supplied policy; moving that relation into a compact recursive statement requires equations and authenticated inputs.

## Three challenge contexts

Keep these contexts separate throughout folding:

1. Base universal relations drawn from the one prechallenge B5SS seal. Native/caller arithmetic, ROM/program and native lookup claims cancel only in the domains of their actual original transcripts.
2. Packed word-memory suffix challenges, including the shared range16 challenge, drawn with the exact current `Word.Challenges` ordering. These govern transitions, predecessor links, first touches, endpoints and range16. Reuse `drawFromChannel`; do not redraw a new independent suffix in the outer proof.
3. Each recursive leaf/parent's own relation context. Its `recursion_wire` public supply and recursive framework claims close under its own actual transcript, independently of the base open sums it exports.

The ROM adapter's authenticated channel restart preserves its original two-channel transcript; it is not permission to linearize ROM or reuse the wrong relation draws. Ordinary no-restart protocols retain their bytes and schedule identities. A heterogeneous parent must replay the precise typed child prefix/claim framing, channel resets where present, roots, DEEP/FRI queries, Merkle paths and PoW. Child capture mutation seals or metadata hashes alone cannot satisfy that verifier.

## Exact closure equations

The following equations reproduce the checks in the fresh receiver. All operands must be authenticated child outputs or constrained public-source providers. Canonical integers require checked limb arithmetic/range constraints; a field equality alone is insufficient for arbitrary u64 counts or clocks.

### ROM and terminal fetches

`block_v5_program_table_proof_v1.closed` requires the actual ROM claim plus every ordinary program projection, public terminal-fetch boundary, and sparse caller program projection to sum to zero. Fetch counts must sum to the exact ROM plan count. Every term uses the original program seal/channel.

`block_v5_program_native_batch_common_v1` places three ordered request contributions per execution: native projection, public completion boundary, and an optional caller projection (zero only for independently admitted caller absence). Derive the public boundary with the semantics of `block_v5_program_boundary_v1.deriveFromPinnedNativePublic`: halt contributes zero, whereas an unretired fetch/self-loop consumes one decoded program tuple. The outer circuit must constrain this decoding/inverse computation from authenticated native public completion data, or consume an independently proved boundary provider. It cannot import the host-derived boundary sum as authority.

### Registers, native state and clocks

For each execution window separately, the current table join closes:

`public_registers_state + native_registers_state_projection + caller_state_projection = 0`.

In canonical mode1 it additionally requires, for each execution window separately:

`window_register_compensation + native_register_memory_projection + native_register_clock_projection + caller_register_memory_projection = 0`.

Do not pool these equations over executions. The frozen register tuple has no execution ordinal; positive and negative claims from different local-clock windows could cancel incorrectly. Preserve `block_v5_register_windows_v1.Plan`: exact window ordinals, consecutive global spans, final-to-next-initial register equality, independently pinned first/final register arrays, local access-clock bounds, and version2 x0-local-zero ABI with x0 value/last-clock zero. The PC/clock-only execution span does not itself prove these register edges.

Auxiliary clock-memory claims remain a distinct signed partition used by the final accounting equation. Caller counts, external retirements and the caller's execution binding must match the actual native window. A caller proof must attest arithmetic/call ABI and the same-root caller projection; neither can stand in for the other.

### Native lookup groups and byte limbs

For every independently admitted lookup group `g` and each of the six kinds `k`:

`lookup_provider[g,k] + sum(native_request[i,k] + caller_request[i,k] + memory_byte_request[i,k], i in g) = 0`.

Only `range_check_8_8` receives sidecar byte requests. Preserve all six kinds rather than accepting their total alone. `block_v5_native_lookup_plan_v1.validateDemandRoster` derives bounds from native shapes, caller counts and ordinary/external event census; groups form an exact disjoint contiguous execution partition. Each group's total requests stays strictly below M31 characteristic. These bounds prevent characteristic-many invalid requests from disappearing. Exact event-to-byte request conversion and group placement must be constrained or independently authenticated, not selected by provider proof metadata.

### Sorted RAM and range16

Use the canonical mode1 lane subtype, actual physical `row_log`, first/prior/last transition tuples and exact event ordinals from the independently reconstructed lane plan. Preserve all integer spaces/addresses/full u64 clocks and odd-tail activity rules.

The existing `block_v5_ram_lanes_receiver_v1.verify` requires:

- Sum of predecessor link claims equals zero, with the admitted shard first/prior/last boundary chain and exact global event coverage.
- Sum of initial RAM claims plus the public first-touch provider equals zero.
- Sum of RAM endpoint claims minus the public endpoint provider equals zero, and endpoint counts match exactly.
- For each exact range shard, range16 provider sum plus the covered RAM instances' 17 range-plane sums equals zero. The shard request count matches the independently derived plan; providers cannot overlap or omit RAM instances.
- Register endpoint count/sum is zero in RW-only mode1. Registers are handled by per-window custody, not silently reintroduced into sorted RAM.

`block_v5_word_memory_join_impl_v1.finish` additionally checks ordinary plus caller event counts equal the global RAM event count and their packed transition sums cancel the sorted RAM transition sum. Ordinary and caller universal memory opposites remain separate exports for the final residual. The new RAM/range leaves cannot supply these execution-side claims; genuine fused projection recursive verifiers are required.

The zero-RW case must prove requester absence from the actual native/caller schedule, require zero touch/endpoint/range census, and preserve equal initial/final full roots. It has no RAM/range proof leaf. It must not create an empty literal proof, claim-zero receipt or dummy leaf.

### Initial and final source providers

`block_v5_word_memory_sources_v1.check` currently authenticates source files and derives challenge-dependent packed sums on the host. `block_v5_initial_source_receiver_v1` validates input words, sparse initial RW image and typed first touches. `block_v5_rw_endpoint_sources_v1.check` validates canonical endpoint ordering/full clocks, exact touch roster, address classification, independent input SHA/length, and full initial/final sparse roots.

The final image merge preserves untouched nonzero words and input/output/completion words. Program-address touches/endpoints are rejected on this RW path. The initial source and endpoint file hash/length pins are only transport custody. To eliminate these host checks from the cryptographic acceptance boundary, add a source recursive verifier for an actual source STARK or constrain the canonical stream, classification, public-input binding, sparse Merkle root reconstruction and its first-touch/final-tuple sums. Existing host sums or `Claims` structs are not sufficient. This is a substantial outstanding source family, even after all four provider leaves are integrated.

### Final residual

After the independent partitions above close, reproduce exactly `Global.verifyFresh`:

```text
native_open + caller_open + public_program_boundary + ROM_provider
  + native_lookup_provider + ordinary_universal_memory_opposite
  + caller_universal_memory_opposite - auxiliary_clock_memory
  + register_window_compensation + sum(memory_byte_request) = 0
```

This residual does not substitute for any partition equation, multiplicity check or endpoint authentication. Its signs and compensation policy come from the versioned canonical recipe; changing them requires a new protocol/key authority. Sum the authenticated native open exports once; do not demand each native leaf be claim-zero.

## Proof coverage and topology

Separate logical B5SS entries, physical proof artifacts and recursive leaves. The current native B5CF proves multiple native projection and packed-access partitions in one physical STARK, while native arithmetic remains a separate B5CT proof. Caller arithmetic and caller B5CF are similarly distinct proofs. A fused proof may satisfy multiple logical entry obligations; a one-entry-one-file assumption would either duplicate verification or omit partitions.

Define an independently derived `CoveragePlan` whose typed records map each required physical verifier invocation to the exact B5SS entry/partition set it covers. Every required logical obligation appears exactly once, every nonempty physical proof has exactly one verifier leaf, and independently proved empty schedules add no invented proof. Require the actual caller sparse execution indices, equal caller family11/12/13 coverage, one ROM table, all execution ordinals, all RAM instances/range shards and all lookup groups. Zero counts remain explicit, and the `Seal.memory` entry family selects RAM lanes only under the canonical mode1 recipe.

Provider leaves have no execution PC span. Do not assign fake spans to feed current `OpenV2.Child`. Introduce a versioned typed child wrapper with common job/seal/security identity, family/protocol/subtype, coverage range, authenticated claim vector/census and optional genuine execution span. Normalize exact child transcript frames and supplies separately from the exported base claim vector.

For exact heterogeneous folds, use deterministic bounded fan-in and canonical coverage order. Pair/quartet folds and odd-count exact forests need no power-of-two dummy proofs. At each node constrain disjoint adjacent coverage and summed vectors/counts. At the outer node constrain full coverage against the independent plan and all final equations. Retain the current exact execution forest for PC/cycle continuity; provider aggregation can use a separate exact tree whose root feeds the final block kernel. A shared heterogeneous tree is possible only after the node statement explicitly represents the different coverage spaces and optional spans.

## Key trust and reusable setup

The final receiver accepts independent `TemplatePolicy` records, not keys/schedules selected by a manifest. Verify key identity, exact actual graph/routing/source authority, first fixed-root admission, schedule digest and use counts, common base configuration, recursive configuration/profile, and `context.child_config` before proof consumption. Carry the original typed verifier protocol/profile/capacity geometry, relation registry and all AIR masks/degrees/normalizations in its source authority. A dynamic child-key digest without membership in the independent catalog cannot select arbitrary verifier code.

Parent setup should depend on typed child verifier geometry, fan-in, claim schema and authenticated routing. Dynamic seal/instance/root/endpoints/counts/claims remain public inputs. Multiple geometry/profile families require a bounded independently authenticated parent-template catalog or an explicitly admitted universal dispatcher; they cannot reuse a key merely because their public claim vectors have the same width.

The source-level transport pieces are reusable: `recursive_provider_definition/codec/store_v1`, stable owned `recursive_provider_templates_v1`, and `ArtifactFiles.publishParts/readPinned`. Files contain only a proposed claim and expected key ID; reader policies retain the trusted Prepared/key/schedule. Publication consumes stage artifacts only after synced exclusive publication; failed reads are terminal. Keep policy/catalog/source owners alive until workers/readers join, and match stage/store artifact allocators. A verified transport leaf is still open global output until the outer circuit authenticates its exported claim vector and coverage.

## Reusable equation kernels and missing source

Existing kernels that can be reused without claiming a finished global AIR:

| Kernel | Reuse boundary |
| --- | --- |
| `composition_graph_recorder` and typed compiler/framework | Symbolically record arithmetic, secure inverses, exact existing generic AIR and outer closure checks |
| `blake3_execution_parent_preparation.State`, shared composition/DEEP/transcript/roots | Actual child verifier constraints, original FRI/Merkle/PoW and ownership; exact capture dispatch remains typed |
| `block_v5_open_parent_composition_v2`, packed source cohorts | Symbolic recursive public-supply closure and child claim equations; extend with a new heterogeneous statement, not an alias |
| OpenV2 exact receiver/stage/queue/manifest and bounded setup caches | Exact topology, durable publication, admission, queue/budget/join behavior; new family coverage semantics are required |
| `public_logup_arithmetic`, program decoding/boundary and register-window definitions | Semantics for constrained public compensation/boundary/source inputs, with actual authenticated child values |
| RAM interaction normalization/endpoints and native lookup/range plans | Exact closure geometry/census/tuple recipes; host plan construction alone is not proof |

`air/block/memory_global_closure.zig` is a host structural checker of already verified legacy block-v2 receipts. `binary_global_closure_outer_source` is explicitly a verifier-side 35-row/47-domain framework decomposition boundary, not a new AIR or parent prover; its contract states `PARENT_PROOF_VERIFICATION`, `PARENT_PROOF_PRODUCTION` and `PRODUCTION_ACTIVATION` are false. It cannot be relabeled as the new block kernel. The legacy `provider_wrapper_fold_statement_v1` is a different field-native statement/hash protocol and does not authenticate these BLAKE3 heterogeneous children. No existing module in this audit supplies all required block equations and source authentication as a closed production AIR.

Concrete source sequence:

1. Add actual borrowed captures and symbolic verifier adapters for capacity native fused and caller arithmetic/fused proofs, exporting every partition/census/binding. Preserve original transcripts, capacity activity/count equations and masks; pair native/caller first roots and execution identity in the new bus.
2. Add a typed heterogeneous child frame/public bus/claim vector and independently derived coverage plan. Extend new parent equations to verify original child proofs and their complete public supplies; keep existing NativeV3/B5CT defaults intact.
3. Add genuine initial/final source authentication and constrain register-window/public completion providers. Prove descriptor-to-public-root/census bindings where the final product does not retain full independently trusted policy arrays.
4. Implement a new final closure graph using the equations above, with limb-safe census/continuity and independently catalog-admitted keys/schedules. Reuse exact scheduling and bounded caches through a distinct protocol/receiver.
5. Only then extend Global/Detached with an explicit heterogeneous result. Continue fresh all-family verification while qualifying parity and independently reopened outputs; remove any redundant base acceptance only after the new cryptographic coverage is complete and explicitly authorized. CLI/default activation is outside this design.

Safe qualification before any execution: pure symbolic graph parity against each existing partition check; mutation of one typed claim, family/profile/seal/key/schedule/root, endpoint/census/window, lookup kind/group, range membership and coverage edge; crossed-window cancellation rejection; integer overflow/noncanonical inputs; empty-family absence; exact odd-count topology; exhaustive allocation failures and joined publication/read lifetime. Retain real cap/legacy receiver, provider verifier, heterogeneous parent and final closure bodies in compile-only roots. These checks establish source contracts and code generation, not successful STARK proofs, GPU execution or block performance. A later fresh real heterogeneous proof is required to qualify cryptographic composition.
