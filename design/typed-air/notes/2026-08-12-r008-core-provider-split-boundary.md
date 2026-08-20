# R-008 core/provider split boundary

**Date:** 2026-08-12
**Status:** implemented component substrate, role-separated canonical leaf
envelopes, independently owned main traces, real role-owned PCS Tree-0/Tree-1
state across a failure-atomic manifest barrier, and genuine standalone provider
and base-plus-caller STARKs with independent native verification. AIR-bound
ordered-call commitment, joint PoW, production activation, bounded paired
scheduling and performance evidence, and recursive verification are not
complete.

## Outcome

The current guest Poseidon2 proof can be separated at the component boundary
without copying either AIR:

- the core leaf retains the base RISC-V components and appends only the
  caller/request component;
- the provider leaf contains only the existing Poseidon2 provider component;
- the terminal physical LogUp batch of each component is already an isolated
  `guest_poseidon2_io@1` event; and
- after successful leaf verification, each side can close every local term by
  removing that terminal sum and export the exact signed residual for ordered
  pair closure.

The implementation is
[`split_component_assembly.zig`](../../../src/frontends/riscv/prover/guest_precompile/split_component_assembly.zig).
The role-separated admission envelope is
[`split_leaf_statement.zig`](../../../src/frontends/riscv/prover/guest_precompile/split_leaf_statement.zig).
The detached main-trace path is
[`split_main_trace.zig`](../../../src/frontends/riscv/prover/guest_precompile/split_main_trace.zig).
The two-stage shadow prepare/barrier path is
[`split_leaf_prepare.zig`](../../../src/frontends/riscv/prover/guest_precompile/split_leaf_prepare.zig).
The real two-tree PCS transaction is
[`split_pcs_prepare.zig`](../../../src/frontends/riscv/prover/guest_precompile/split_pcs_prepare.zig),
standalone provider Tree 2/proving/verification is
[`split_provider_finish.zig`](../../../src/frontends/riscv/prover/guest_precompile/split_provider_finish.zig),
and complete base-plus-caller Tree 2/proving/verification is
[`split_caller_finish.zig`](../../../src/frontends/riscv/prover/guest_precompile/split_caller_finish.zig).
Every new path remains research-only. Both roles now prove and independently
verify genuine STARKs, but neither proof is an accepted split leaf until the
ordered public call commitment is AIR-bound, the joint transcript/PoW protocol
is accepted, and recursive pair verification is complete.

## Source authority and comparison boundary

The Stark-V reference reviewed for this lane is
`origin/chore/scratchpad-cleanups` at
`59172a201bd01f2f4b699bc2f7d4442d8ee81597`, not the checkout's unrelated
`outbound/metal-backend` worktree state.

Stark-V establishes two useful facts:

1. `crates/prover/src/precompile.rs` contains a working two-proof LogUp
   handshake prototype, including a 32-word Poseidon2 example. Both main
   commitments exist before one shared relation is drawn, each proof binds the
   shared seeds into its own transcript, and the binder verifies both proofs
   before checking signed-sum cancellation.
2. The production split is not solved there. Its roadmap marks binary
   recursion `REC-007` done while `PRE-001` remains pending. The precompile
   document explicitly says the VM still contains Poseidon2, segment artifacts
   do not carry a provider proof, recursion does not verify the pair, and the
   prototype still uses legacy manual component plumbing.

That distinction is load-bearing: Stark-V validates the handshake shape, not
an implementation that can be transplanted or cited as completed production
precompile recursion.

## Existing one-proof authority map

| Fact | Current authority | Current binding |
| --- | --- | --- |
| core statement and public boundary | `RiscVStatement` | mixed before Tree 0 and checked by the base verifier |
| caller/provider geometry | `ExtensionStatement` plus `component_registry` | one combined two-component statement and artifact |
| caller rows | frozen runner calls and guest retirement rows | committed in the common Tree 1 |
| provider permutation rows | same frozen calls, recomputed by the Poseidon2 AIR witness | committed in the common Tree 1 |
| guest challenge | appended thirteenth relation draw | derived after the common Tree 1 |
| caller residual | caller batch 76 | mixed as part of the caller claim and constrained by its recurrence |
| provider residual | provider batch 1 | mixed as part of the provider claim and constrained by its recurrence |
| relation closure | `cancellation.verifyDetailed` | caller and provider cancel inside one proof before composition |

The component registry pins why the split is mechanically small. Caller batch
76 is the singleton event 152, a negative `guest_input_output` request.
Provider batch 1 contains the coefficient-zero legacy event 2 and the positive
`provider_input_output` event 3. Provider claim validation requires batch 0 to
be exactly zero, so the exported provider residual is exactly batch 1.

## Split protocol dependency and authority map

The smallest sound production protocol has two barriers and one ordered pair
boundary.

### Barrier A: commit independently

| Value | Producer | Admission authority | Consumer |
| --- | --- | --- | --- |
| frozen ordered call buffer | RISC-V execution | runner/profile validation | caller and provider trace generators |
| core statement digest | core statement builder | core verifier policy | session manifest and caller transcript |
| caller AIR/artifact digest | typed component registry | verifier-owned protocol manifest | session manifest and caller verifier |
| provider AIR/artifact digest | typed component registry | verifier-owned protocol manifest | session manifest and provider verifier |
| preprocessed roots | trusted preprocessing | accepted protocol identity | session manifest and each leaf verifier |
| caller main root | core/caller commitment phase | caller proof transcript | session manifest |
| provider main root | provider commitment phase | provider proof transcript | session manifest |
| ordered call commitment and count | execution/call-commitment builder | both role statements; ultimately AIR-bound | session manifest and pair verifier |

No interaction trace, shared challenge, interaction proof of work, or leaf
completion is permitted before every descriptor is frozen in the canonical
manifest. This prevents either side choosing relation-determining rows after
learning the random evaluation point.

### Barrier B: derive once, finish independently

The R-007 prepared session hashes the complete ordered manifest and derives
one guest `(z, alpha)` pair from the resulting session digest. Base RISC-V
relations stay leaf-local. Each leaf transcript must bind:

1. protocol and role-specific statement identity;
2. session digest, leaf index, and complete descriptor identity;
3. both commitment-phase roots (through the session digest);
4. the recomputed shared guest pair;
5. a joint interaction PoW authority selected by the accepted protocol; and
6. its detailed physical claims before the random composition coefficient.

After that prefix, Tree 2, composition, OODS, FRI, and openings can run in
parallel for the two leaves. Different trace sizes and PCS shapes are allowed;
the shared relation accumulator is independent of those shapes.

### Ordered pair boundary

The recursive leaf branch, not either child, has final authority. It must:

1. replay and verify both complete leaf proofs;
2. compare their role, protocol, statement, artifact, preprocessed-root, and
   main-root identities against the manifest rather than self-declared child
   metadata;
3. recompute the same session digest and shared relation challenge;
4. reconstruct each signed residual from the proof-bound terminal claim;
5. prove the public ordered call commitment and count match each leaf's
   committed relation rows;
6. require left `core_request` at `2*j` and right `poseidon2_provider` at
   `2*j+1`; and
7. require equal counts/commitments and an exact zero QM31 residual.

Only then may it emit a closed parent statement. Higher recursion nodes consume
closed parents and never receive an unmatched leaf residual.

## Implemented substrate

The new module contributes the following reusable pieces without modifying the
current production proof:

- verifier-owned caller/provider authority reconstruction from an R-007
  prepared session;
- base-relative caller placement and zero-relative standalone-provider
  placement;
- caller-owned, stable prover and verifier assemblies with no allocation and no
  hot-loop dispatch;
- replacement of only the guest relation pair with the session-derived pair;
- exact local-remainder equations that remove rather than cancel the exported
  guest term;
- comparison of verifier-replayed statement, artifact, preprocessing, and main
  identities against manifest descriptors;
- typed caller/provider candidates and an ordered native pair closure; and
- explicit optional-ingress rejection for omitted children.

The adversarial suite covers wrong challenge, changed local non-guest sum,
swapped roles, omitted caller, omitted provider, cross-session reuse, changed
main-root replay, and resolving the wrong role.

## Role-separated canonical leaf envelopes

`CallerLeafStatementV1` and `ProviderLeafStatementV1` are statically distinct
types over one reviewed body and writer. They bind the complete selected R-007
descriptor, its cached descriptor digest, the prepared-session digest, the
shared challenge-context digest and exact `(z, alpha)` limbs, and the canonical
role-specific component descriptor. A caller statement cannot be passed where
a provider statement is expected without an explicit reconstruction.

Authority flows in the verifier direction:

- `VerifierOwnedProtocolIdentityV1` starts from the verifier-accepted R-007
  proof-protocol and relation-registry digests and pins the execution and
  relation schema constants;
- `VerifierOwnedArtifactIdentityV1` supplies the accepted role, AIR artifact
  digest, preprocessing root, and exact component geometry independently of
  the manifest; and
- construction and every later encoding compare those accepted identities to
  both the prepared session header and selected descriptor. There is no helper
  that launders artifact authority out of a self-declared descriptor.

The V1 wire is 133 little-endian `u32` words (532 bytes). A single streaming
word writer owns the word array, byte encoding, and domain-separated Blake2s
preimage; none of those paths allocate. The caller and provider have distinct
magic and digest domains. For the deterministic 17-call fixture, the pins are:

| Identity | Digest |
| --- | --- |
| caller wire SHA-256 | `bbe2908dcaa2b8315612e36be0156ee3a426929f67efafc3ec5dd25d9a68745a` |
| provider wire SHA-256 | `8cea3d88f928eaeab4b5d3ad61ab97310c2fdd411f083ed85dab37b195a3a66d` |
| caller envelope Blake2s | `48aa712519a6ed5c4980d1547f737cf2f151ef977916b11079cb4e080f12d51d` |
| provider envelope Blake2s | `6ac0c74db4d8360c3e56f865cfa1a0c4800b49c23dc21fcdf577ba15661ee8e8` |

This is intentionally a **session-bound envelope**, not a replacement for the
descriptor's `leaf_statement_digest`. That descriptor field is committed
before the session digest and shared challenge exist. Feeding the envelope
digest back into it would create a cycle. Production activation therefore
still needs a canonical pre-session role statement whose digest populates the
descriptor, followed by this session binding in each proof transcript.

The tranche-two tests independently compare word, byte, streaming, and hash
paths; pin both role vectors; exercise 42 body-field mutations and 18
verifier-owned identity mutations for each role; and cover role swaps,
sibling-only cross-session changes, call commitment/count changes, cached-leaf
mutation, zero-call commitments, and failure-atomic short buffers. The focused
guest suite passes all 496 tests in Debug, ReleaseSafe, and ReleaseFast. On the
validation host, the clean optimized builds took 50.06 seconds / 3.13 GB peak
RSS and 52.34 seconds / 2.69 GB peak RSS respectively; these are whole-suite
compile-and-run measurements, not claims about proving-path speed.

## Independently owned shadow main traces

The combined C-007 generator remains the production path and differential
oracle. It does not call through the R-008 implementation. Its only additive
surface is a narrow shadow seam that returns the already completed production
preflight authority and exposes the existing caller/provider row kernels for
an admitted destination set.

The detached path then enforces a two-phase ownership transaction:

1. `prepareInto` repeats the exact production statement, component authority,
   frozen-log, ordering, clock, canonical-value, mode, permutation-output, and
   geometry checks. It validates all 731 destination slices globally, including
   cross-role aliasing, with a fixed stack array and an allocation-free
   `O(C log C)` address-range sort. No destination is changed.
2. The admitted value contains copied caller and provider slice descriptors
   plus one immutable borrowed record authority. `finishCaller` and
   `finishProvider` have no error or allocation path, zero and populate only
   their own columns, perform no dynamic dispatch, and may run concurrently.

`generateOwned` preflights before storage exists, then makes exactly two
allocations: 286 caller columns and 445 provider columns. Failure of either
allocation rolls the other role back. Exhaustive allocator injection confirms
there is no leak or partially returned owner, while malformed witness data
induces no allocation at all. A future shared worker pool can move the two
owners independently without changing their backing addresses.

Differential tests cover 0, 1, 2, 17, and 31 calls. Every active and padded
cell of every caller and provider column is row-for-row equal to the unchanged
combined generator in committed circle-bit-reversed order. Log size, domain
size, row count, descriptor count, and guest call count are exact. Two
allocation-free shadow digests pin the complete 17-call committed-order role
traces:

| Role | Shadow trace Blake2s |
| --- | --- |
| caller | `93a6cb829e1fcaf026e83e92630e551edcd2f0f30296a61435f6108820cec7ae` |
| provider | `62291f5181b0bbd9bb8d496bf3081b6b78b3d69de1f75d6f619a001930f6577b` |

These digests are differential seals, explicitly **not PCS commitments**.
Tree-1 commitment parity cannot mean equal roots after the proof is genuinely
split: the two role commitments intentionally have different leaf sets from
the current combined base-plus-extension tree.

The adversarial suite rejects wrong lengths, same-role aliases, cross-role
aliases, and semantic witness changes before a guard cell moves. It also runs
both admitted finishes on separate native threads and compares the result to
the oracle. The focused guest suite now passes all 502 tests in Debug,
ReleaseSafe, and ReleaseFast. The optimized whole-suite gates took 51.29
seconds / 3.17 GB peak RSS and 55.54 seconds / 2.74 GB peak RSS on the validation
host.

A paired nine-sample ReleaseFast measurement over 64 active rows recorded a
244,708 ns combined median and a 129,709 ns sequential split median, or 0.530x
the combined time (1.887x throughput). This measures full preflight,
destination admission, zeroing, and both role fills. It is encouraging but not
an end-to-end proving result: part of the gain is the shadow path's fixed-stack
`O(C log C)` alias admission versus the oracle's unchanged `O(C^2)` scan, and
the sample excludes PCS commitment, interaction generation, composition, FRI,
and recursive verification. Concurrent finish correctness is established, but
critical-path speedup must be measured through the eventual shared prover work
pool rather than thread creation inside a microbenchmark.

## Failure-atomic shadow pre-challenge preparation

Before moving PCS ownership, the shadow tranche established the statement,
trace, and manifest transaction without changing production proof meaning. It
remains the allocation-cheap differential oracle for the stronger PCS path
described below; its Blake2s seals are not used as proof commitments.

`split_leaf_prepare.zig` therefore uses the narrowest truthful state:

- `PreparedCallerLeafV1` owns exactly the caller component's two selector
  columns and 286 main columns; it explicitly does **not** include the base
  RISC-V Tree 0 or Tree 1 columns required by a complete core leaf;
- `PreparedProviderLeafV1` owns the provider component's two selector columns
  and 445 main columns;
- each role independently repeats the exact production statement, construction
  authority, frozen-log, ordering, clock, canonicality, and Poseidon2-output
  preflight before allocating;
- each successful role uses exactly two contiguous backing allocations, one
  for selectors and one for main columns, with no self-relative pointer, so the
  prepared value is move-safe and the two preparations can run concurrently;
- complete committed-order component columns receive domain-separated Blake2s
  seals. These values populate the native shadow descriptor only and are
  explicitly not Merkle/PCS roots;
- the duplicate-preserving ordered `(input[16], output[16])` list receives one
  canonical count- and position-bound digest. It intentionally excludes
  caller-local clocks/memory metadata and is explicitly not AIR-constrained;
  and
- the pre-session declaration hashes every descriptor and component fact except
  the digest being defined. This supplies the missing non-cyclic
  `leaf_statement_digest`; the existing session envelope remains the second,
  post-barrier binding.

`ManifestBarrierV1` validates and re-hashes both retained role states, compares
the externally accepted protocol plus exact job/call pair facts, then makes one
heap-stable allocation containing two canonical descriptors, two prepared-leaf
records, and the R-007 session. Its borrowed `session.leaves` slice is rebound
in the final heap address. The shared `(z, alpha)` is derived exactly once and
only after both roles pass. A failed validation allocates nothing; allocation
or manifest failure destroys the sole barrier object and never consumes either
role owner.

For the deterministic 17-call fixture, the shadow V1 pins are:

| Identity | Blake2s digest |
| --- | --- |
| ordered IO calls | `c887aa5cf1d7ab32070e4fa0df7e29a217b5ea698ccf2ebd9ff89d5c24f6b6b9` |
| caller selectors | `789b53a754ba7b33210e6395a2f67ae0249a1ba0e3476086b717599ef8b5684a` |
| provider selectors | `ba131f33fc38dde9f600cbe2c8dfe77eccfd84e4f84fecbccc0bbf686ef6efe2` |
| caller component main | `93a6cb829e1fcaf026e83e92630e551edcd2f0f30296a61435f6108820cec7ae` |
| provider component main | `62291f5181b0bbd9bb8d496bf3081b6b78b3d69de1f75d6f619a001930f6577b` |
| caller pre-session declaration | `b0eaced8eb351a4755dcf88c2f3efb905b05881a8ddf32fe792e5f3a9e501059` |
| provider pre-session declaration | `8b3850b8161af4138493e4345503a60bfdcc20256d95b42a623fb4f513427f0d` |
| prepared two-leaf session | `89f3151bc56adf87e2b6d49230087a83b4daf67225a8439460855d8abc972e7f` |

The tests prepare the roles on separate native threads with separate
allocators, move both results into one deterministic barrier, construct both
typed session envelopes, and reject selector/main/descriptor mutation,
cross-job, cross-count, cross-protocol, cross-session, non-canonical call words,
and allocation failure. Exhaustive injected failures prove two allocations per
role and complete rollback; the barrier uses exactly one allocation and leaves
both role owners valid on abort. The complete focused guest-precompile suite
passes all 510 tests in Debug, ReleaseSafe, and ReleaseFast. Golden auditing
regenerates selector columns through the production selector oracle and uses a
separate raw Blake2s encoder for ordered-call and declaration preimages.

## Real PCS barrier and standalone leaf proofs

`split_pcs_prepare.zig` replaces the shadow descriptor's selector/main seals
with roots returned by the production PCS while retaining a private scheme and
channel per role. The committed ownership is exact:

| Role | Tree 0 | Tree 1 | post-Tree-1 relation source |
| --- | --- | --- | --- |
| caller | all canonical base preprocessing, then two caller selectors | every base main column, then exactly 286 caller columns | exactly 158 caller projection columns |
| provider | exactly two provider selectors | exactly 445 provider columns | exactly 33 columns: enabled, input 16, output 16 |

The caller has two entry points. The low-level research fixture accepts an
owned base `MainCommitment`; the preferred
`prepareCallerFromPublishedBase` bridge takes the commitment from the published
production `Prepared` epoch only after proving retained-statement pointer
identity. The production owner remains external through Tree 1, then the caller
finish consumes it as the sole authority for base opcode, clock, and
lookup-counter state. Its extension-aware plan separately authenticates
statement-wide retirements and ordinary RISC-V rows, requiring
`ordinary_steps = total_steps - n_guest` and exact equality among guest
retirements, frozen calls, and guest execution rows.

Source-plan assembly performs zero field-cell copies. Before Tree 1 consumes
its arenas, the implementation copies exactly the 158/33-column projections
needed for later LogUp generation. That is 191 retained columns in total, the
same projection width as the integrated prover. The generic CPU PCS is allowed
to detach supplied arenas internally, so the receipt reports all Tree-0 plus
Tree-1 cells as a conservative backend detach-copy upper bound. It does not
misreport an end-to-end zero-copy result without backend adoption telemetry.

The transcript is a strict two-phase state machine:

1. each role mixes PCS configuration, its role frame, verifier-replayable
   statement/protocol/job/artifact/call/component facts, then commits Tree 0
   and Tree 1 in canonical order;
2. the manifest barrier validates both live schemes against their cached roots
   and descriptors and derives the shared guest `(z, alpha)` once; and
3. each role mixes its role-specific frame followed by the complete canonical
   133-word session envelope. This transition performs no challenge draw.

Serial caller-first, provider-first, and genuinely threaded preparations with
private allocators produce identical roots and channel states. A one-call CPU
fixture pins these production PCS roots:

| Commitment | Root |
| --- | --- |
| caller Tree 0 | `0603151d4eae9956bde55420e55111025c8e153d0de26547d828d9df69b35ff3` |
| caller Tree 1 | `e86307a7ff9f2f7e0470222189f58098e6e10c998989377dd5d3981787da71ce` |
| provider Tree 0 | `c590890b9d851f9e5a11d0e0ab5c9be3c3d9e9c4775ad12eb6ac3afe899d592e` |
| provider Tree 1 | `960e0c362cad3b30c7fadfca5fedc19e46295ed7fb9a425548ff7375608bc246` |

The zero-call geometry has independent pins for all four roots. Base-only
mutation changes the caller Tree-1 root and declaration while leaving the
provider root unchanged. Swapped roles, protocol or session substitution,
cached-root mutation, incomplete base ownership, pre-commit cancellation,
injected commit failure, and every allocator failure abort without publishing
a prepared leaf or leaking ownership. Neither path creates a work pool, so it
cannot nest or oversubscribe the production pool.

`split_provider_finish.zig` then completes the first genuine role STARK. It
constructs only the provider's two physical LogUp batches from the retained 33
columns, using one eight-column output allocation and one bounded batch-inverse
scratch allocation. It mixes the detailed provider claim, commits a real
eight-column Tree 2, and retains a three-tree scheme. The one-call Tree-2 root
is
`f88a5480135a3ea5a0164f8713206fda8a37ce4e5804233696cbaa870b35865b`.
The same production engine then produces a complete proof, and an independent
verifier reconstructs the provider selectors, checks their PCS root, replays
the exact pre-tree and post-barrier transcript, binds the manifest-derived
relation, and verifies the STARK.

Only `guest_poseidon2_io@1` is live in the standalone provider relation set.
The legacy compatibility event in provider batch zero has coefficient zero,
and the canonical claim requires that batch sum to be zero; all other relation
slots therefore use deterministic dummy values on both prover and verifier
without weakening a nonzero event.

The provider alone has cubic constraints but lacks the wider base components
that raise the integrated composition domain. A research-only prover/verifier
adapter therefore raises its maximum constraint log-degree bound by one bit;
it does not change row equations or trace geometry and preserves prepared and
parallel domain-evaluator callbacks. This is a correctness requirement for the
standalone proof, not a measured performance win. The caller retains its base
components and their unchanged degree bound, so this provider-only policy is
not applied there.

`split_caller_finish.zig` completes the second genuine role STARK. Before the
base lookup multiplicity columns are finalized, the independently owned caller
columns register their exact fixed-table demands into the same reduced base
counters. The caller then draws the twelve leaf-local base relations after the
manifest barrier, copies the manifest-derived guest relation without a local
draw, executes the unchanged production base Tree-2 kernel, and appends exactly
77 caller LogUp batches in 308 columns. The caller-only interaction owner uses
one exact output allocation and, for a non-empty active prefix, one bounded
inverse-scratch allocation; the zero-call path requests no scratch. The finish
path creates no work pool. Its proof composition receives the same explicit
CPU execution request as Tree 2.

The genuine proof contains every unchanged base component followed by the
caller component. Independent verification regenerates the complete base plus
caller selector Tree 0, checks manifest and declaration identity, replays the
pre-tree and post-barrier transcript, re-derives all twelve base relations,
binds the shared guest relation, checks local closure, and verifies the STARK.
No verifier input is promoted to a typed verified split-leaf output because the
ordered call digest is still only natively authenticated, not constrained by
either leaf AIR. A zero-call extension plan is byte-identical to the base plan,
while nonzero extension preparation rejects mismatched ordinary rows, frozen
calls, guest execution rows, or retained Tree-1 geometry.

The one-call caller Tree-2 root is
`c61eeeff3c06976a99ab4848478d26714dc439dbc5a107c16964ba0335c9bc1f`.

The focused guest-precompile gate passed 526/526 tests in Debug, ReleaseSafe,
and ReleaseFast after the caller addition. The RISC-V CPU integration gate
passed 16/16 tests in Debug, ReleaseSafe, and ReleaseFast. It includes real
threaded PCS preparation, genuine caller and provider proof generation with
independent verification, post-barrier cancellation, and allocator leak
checks. These are correctness and ownership receipts; no end-to-end split
proving speedup is claimed from them.

### Research joint-PoW candidate

`split_joint_pow.zig` closes the transcript-order ambiguity at the research
boundary without changing the accepted V1 manifest or either production proof.
It authenticates the complete canonical session after every leaf Tree-0/Tree-1
root is frozen, grinds one 10-bit nonce, mixes the nonce, and only then derives
the shared `(z, alpha)` pair from the resulting PoW-bound digest. Thus a valid
nonce cannot be bolted onto the old pre-PoW R-007 challenge: the relation itself
changes and verifier replay rejects that substitution.

The candidate also defines a failure-atomic role-local binding frame over the
session digest, PoW context and nonce, shared relation context, role/index, and
canonical descriptor digest. Golden vectors pin the nonce, both context
digests, and distinct caller/provider terminal channel digests. Negative tests
cover wrong and cross-session nonces, mutated canonical session storage, old-V1
challenge substitution, relation/context mutation, swapped role/index, and
unchanged channel state on every rejection. Preparation is allocation-free and
O(1) beyond the required PoW search after the manifest's existing O(n) scan.

This is deliberately a candidate rather than activation: production needs a
new session/wire version and an accepted ADR before leaf transcripts consume
it. The existing `PreparedSessionV1.challenge` and proof roots are unchanged.

### Original-scope acceptance mapping

This tranche advances, but does not close, three clauses in
[`ORIGINAL-SCOPE.md`](../ORIGINAL-SCOPE.md):

| Original production exit | Evidence added here | Still required for acceptance |
| --- | --- | --- |
| Parallel core trace and precompile proving | complete caller base-plus-286 and exact-445 provider Tree-1 PCS owners; genuine Tree-2, quotient/FRI proofs, and independent verification for both roles; deterministic serial/threaded roots; cancellation and exact ownership receipts | one bounded proof pool spanning both leaves, accepted joint PoW, `N=1/2/4` proof identity, budgets, and wall/CPU/RSS/proof/verifier scaling receipts |
| Session-bound two-to-one recursion | non-cyclic declarations, canonical two-leaf manifest over actual PCS roots, one shared relation pair with no local guest draw, typed envelopes, and two real session-bound native STARKs | AIR-bound call-list equality, typed verified outputs for both leaves, recursive dual-proof branch, canonical `2 -> 1` node, adversarial and crossover evidence |
| Stable manifests and digests | verifier-selected protocol/artifact inputs, actual three-tree roots, exact transcript replay helpers, fixed role/component/call/column domains, and independent selector-root/proof replay for both roles | production protocol version/ADR, proof-wire adoption, accepted joint-PoW transcript, activation gates, and typed-compiler identity for every recursion-local component |

It does **not** advance the production completion state of the felt-language,
opcode SSOT, component-composition retirement, or recursion-local typed
compiler rows. Those remain separate original-document obligations.

## Why this is not yet an accepted proof split

Four gaps remain before R-008 can be claimed:

1. **Proof-bound ordered call commitment.** R-007 correctly requires more than
   randomized accumulator equality. Neither leaf AIR constrains the public
   digest of the duplicate-preserving ordered call list. Both proofs are
   therefore genuine STARKs but not accepted split leaves until a streaming
   commitment component, or a reviewed equivalent commitment/opening scheme,
   proves that link on both sides.
2. **Joint PoW and production protocol activation.** A tested research
   candidate now proves the required order—session, one PoW, then shared
   relation—and supplies role-local failure-atomic transcript binding. The
   accepted protocol must still freeze it in a versioned ADR/wire and activate
   new native prover/verifier return types behind fail-closed compatibility
   gates. The current production combined proof remains unchanged.
3. **Bounded paired scheduling and performance evidence.** Each role has
   failure-atomic ownership and neither path creates a nested pool, but both
   proofs are not yet scheduled as one proof-scoped graph. Acceptance requires
   deterministic `N=1/2/4` proof identity plus total-work, critical-path, RSS,
   proof-size, and verifier-time receipts against the combined proof.
4. **Recursive dual-proof verification.** Native pair closure is an oracle and
   test target, not recursive verification. The universal recursion AIR must
   replay both leaf transcripts and PCS proofs, verifier-owned identities,
   shared relation, AIR-bound call equality, and signed residual closure in one
   proved branch before canonical `2 -> 1` recursion can consume the result.

## Implementation sequence

1. **Complete:** define `CallerLeafStatementV1` and
   `ProviderLeafStatementV1` from the R-007 descriptor schema, route words,
   bytes, and hash identity through one canonical writer, and pin golden and
   mutation matrices. The result remains detached from production proof
   semantics until the following stages land.
2. **Complete in shadow mode:** split main-trace generation into independently
   owned caller and provider destinations. The unchanged combined generator is
   retained as a row-for-row differential oracle; complete role digests, counts,
   failure behavior, parallel finish safety, and paired throughput are pinned.
3. **Complete in shadow mode:** role selectors/main columns, non-cyclic
   declarations, and the manifest barrier establish a cheap differential and
   failure-injection oracle.
4. **Complete in research PCS mode:** retain independent real schemes for
   caller complete base-plus-286 and provider exact-445 Tree 1, form the
   manifest from actual roots, and bind the shared pair into each transcript
   without a local draw.
5. **Complete in research PCS mode:** provider-only and base-plus-caller Tree 2,
   proof generation, and independent native verification are real. Neither
   verifier returns an accepted leaf while call-list equality remains outside
   the AIR.
6. Introduce proof-bound call-list commitment AIR. Prefer one streaming
   Poseidon2-M31 accumulator over ordered `(input, output)` rows with a
   length/domain terminator; prove its endpoints as public values and measure
   its recursive cost against committing/opening the complete tuple vector.
7. **Candidate complete, activation pending:** review the implemented joint
   interaction-PoW order, then freeze it in the accepted versioned split proof
   wire/transcript while preserving the current combined proof until explicit
   activation.
8. Make each native verifier return a typed verified leaf output only after
   checking the proof and every manifest identity. Use the current candidate
   finalizer as the last allocation-free step.
9. Extend the recursion leaf statement with the two fixed child proof shapes
   and pair-closure predicate. Keep caller left/provider right at the type and
   wire levels.
10. Differentially test integrated versus split traces, exported sums, and
   accepted statements; then benchmark total work, critical path, proof bytes,
   verifier work, RSS, failure cleanup, and crossover before selecting any
   production profile.

## Performance posture

The split is an optimization opportunity, not an assumed win. It removes the
445-column provider table from the core proof's widest shared commitment and
permits caller/provider Tree 1, Tree 2, composition, and PCS work to overlap
around one manifest synchronization point. It also adds a complete second PCS
proof, another proof transcript, and will require recursive verification of
that proof.

The present implementation preserves the integrated prover's 191-column
post-Tree-1 guest projection width. The caller constructs its exact 77 batches
and appends 308 columns to the unchanged base Tree 2; the provider constructs
only its two batches in eight columns instead of running the combined
79-batch generator. That is concrete work isolation, not yet an end-to-end
speedup. Conversely, the standalone provider proof needs one additional
composition-domain bit because it no longer inherits the base components'
degree bound, and the split introduces another complete proof. Both effects
must be measured in the final paired proof graph. Actual threaded commitment
identity is established, and the caller threads one explicit execution request
through Tree 2 and composition, but the two roles are not yet one bounded
proof-scoped schedule.

The implementation should retain these engineering constraints:

- no tuple hash maps or per-row allocation on proving paths;
- exact-capacity or caller-owned fixed storage for manifests and assemblies;
- one shared proof-scoped worker pool with no nested borrowing;
- deterministic manifest and transcript order independent of task completion;
- failure-atomic prepare/finish transactions; and
- separate reporting of wall time, total CPU work, RSS, proof size, verifier
  time, and recursive constraint/trace cost.

The expected benefit is therefore parallel critical-path reduction and a
smaller core AIR/commitment shape. Correctness improves because the component
contract and cross-proof ownership become explicit, but only after the four
activation gaps above are closed. Neither aggregate work nor proof size is
guaranteed to improve.
