# Real Ethereum leaf readiness — 2026-09-07

Read-only source/artifact inventory. No builds or proving runs were performed
for this note. The successful small native-assisted wrapper is not a real-block
benchmark or a root-only proof. Existing commands below are source-wired;
their current-head compilation and proof outcomes remain unverified here.

## Existing complete leaf route

The CPU product `stwo-ethereum-block-proof` exposes:

```sh
stwo-ethereum-block-proof ethereum-incremental-full-leaf-replay-produce-v4 \
  --retained-materialization-result <durable-campaign>/authority/materialization-v2.json \
  --publication-root <durable-campaign>/run/publication-parent/ethereum-incremental-capture-v4 \
  --segment-index 1 --output <new-output>/segment-000001.stwief04
```

Build target: repository-root `stwo-ethereum-block-proof`. Dispatch lives in
`src/products/riscv_cpu/ethereum_block_proof_main.zig`; implementation is
`src/integrations/riscv_cpu/ethereum_incremental_full_leaf_replay_command_v4.zig`.
It authenticates retained capture/program/publication inputs, replays the leaf
without executing the VM again, proves the complete native Ethereum leaf and
providers, encodes STWIEF04, releases the producer transaction/proof owners,
then cold-opens with the CPU verifier before create-only publication. It retains
authenticated source inputs/snapshots for verification; this is not a separate
verifier process receiving only proof bytes. It also does not measure original
block execution/capture inside the proving timer.

The CPU CLI currently selects the legacy preparation path and default execution
options. The prepared one-pass API with explicit process policy is
`runPreparedWithEnginesAndExecution(ProducerEngine, VerifierEngine, ..., policy)`.
The Metal experiment already calls that API with a Metal producer and CPU
verifier. Its executable is `stage101-metal-autoresearch-v1`; build/install
targets are `build-stage101-leaf-autoresearch-v1` and
`install-stage101-leaf-autoresearch-v1` in `src/integrations/riscv_metal`.
It accepts the same four flags above, without the CPU subcommand.

Metal additionally requires `STWO_RISCV_METAL_AOT_BUNDLE`,
`STWO_ZIG_STAGE101_REFERENCE_ARTIFACT`, `STWO_ZIG_STAGE101_WORKER_COUNT`,
`STWO_ZIG_STAGE101_HOST_BYTE_BUDGET`, and
`STWO_ZIG_STAGE101_HOST_BYTE_LIMIT`. The optional
`STWO_ZIG_STAGE101_BUDGET_MS` explicitly records four phase budgets; the default
five-second target rejects slower runs before publication. The native control
uses no `--provider-route` flag; the degree-five omission experiment is separate.

Historical evidence in `autoresearch/notes/2026-09-03-d5-leaf-metal-host-throughput/note.md`
records a successful Metal segment-1 run on 2026-09-04: 18 workers, 234.17 s leaf
transaction, 24.29 s CPU cold verification, 302.13 s wall, and a 57,928,628-byte
artifact with SHA-256
`20baa3ae632cf116b94a5e7af36ce084e82c5dc1eeaaafd568684afb61c3effa`.
Those are historical note-backed observations, not remeasured current-source
results. No current CPU/Metal complete-leaf A/B pass is established by this note.

## Surviving inputs and missing campaign authority

These files exist; ELF, runner-input and output hashes were freshly checked:

| File under `.git/local-ethereum/` | Bytes | SHA-256 |
| --- | ---: | --- |
| `rebuilt-guest-v1/stwo-ethereum-guest.elf` | 3,412,588 | `f3657d077b88da313369ff002aafbe8b6bf4912e8fd1ef1d1b76a6dc0f1d40a7` |
| `projected-input-recheck/stwo-runner-input.bin` | 2,700,692 | `faaf02583929396faed177914da27b4a493766993001357bd1720340ca1ddabb` |
| `projected-input-recheck/host-output.bin` | 43 | `730396807814bc71f14405b3ecf27237778a5359732001b32c93692c3275a8c5` |

Also surviving: `projected-input-recheck/canonical-input.ssz` (2,700,688 bytes),
`rebuilt-guest-v1/source-receipt.json`, and
`rebuilt-guest-full-block/{plan.json,execution.ndjson,receipt.json}`. The retained
execution receipt reports 61 segments, 253,646,998 cycles, a 4,194,304-step segment
budget, 32,835 Keccak calls and 66 signer-recovery calls. Its explicit claim is
`execution-only-not-a-proof`, with `segment_statement_v2_admissible=false`.
No execution was rerun for this inventory.

The historical dependencies named by the successful real-leaf route are absent:

- `/private/tmp/stwo-stage101-profile.8iE8D4/segment-000001.stwief04`
- `/private/tmp/stwo-incremental-capture-v4-hoisted-release.VSdg8m/authority/materialization-v2.json`
- `/private/tmp/stwo-incremental-capture-v4-hoisted-release.VSdg8m/run/publication-parent/ethereum-incremental-capture-v4`
- `/private/tmp/stwo-metal-poseidon-aot-v25.hizW2m/share/stwo-zig/metal/core`

The surviving `aot-m4/stwo_zig_core.{manifest.json,metallib}` is not evidence of
the exact v25 Stage101 admission; the Metal harness pins its manifest and
reference proof. Restore/rebuild and authenticate the required bundle before use.

The V4 retained authority/materializer currently requires exactly 210 segments
(`capture_publication_v4.CANONICAL_SEGMENT_COUNT`, with explicit checks in
`capture_retained_authority_v4` and `capture_materializer_v4`). The surviving
61-segment guest cannot enter unchanged. Admit campaign geometry explicitly from
authenticated execution in a versioned route, retaining the old 210-segment
fixture as a regression. Changing a constant from 210 to 61 would not establish
this boundary. A journal alone is not the retained memory/compact replay corpus.

## Smallest next real-leaf action

Restore the old authenticated campaign if available; otherwise make the bounded
campaign-admission change above and materialize durable inputs from the surviving
guest. Select one real segment whose core/provider geometry fits a measured
host budget; keep one leaf in flight. Reuse the same prepared CPU/Metal API and
explicit worker/memory policy, serialize, destroy producer state, and freshly
verify before reporting full-request latency and peak memory. The 4M-step
historical segment size and 48-GiB budget are not laptop defaults; use a separately
admitted smaller segment budget when required. Keep the original execution and
capture costs separately accounted for. Preserve CSP paths and require their
existing per-case A/B promotion gate independently.

The Python block controller is not yet this route's launcher. Its
`ethereum-block-leaf-producer` invokes the older streamed V3 artifact producer;
`ethereum_block_leaf_support.zig` fixes eight workers and a 48-GiB product budget.
The controller runs fresh verifier subprocesses, but its leaf route still needs
an explicit connection to the admitted retained STWIEF04 profile. Do not launch
it unchanged as a portable full-block benchmark.

## Clock-boundary cross-check

The real retained leaf route does **not** stop when the block passes 2^24
absolute cycles. `segment_statement_v2_contract.statementRange` and
`public_data_v2.metadataFromView` enforce that ceiling, but the V4 capture
observer first uses the existing versioned
`segment_leaf_local_projection_v3.ProjectionV3` adapter. Its
`localStatementFromMetadata` sets the native statement's `first_cycle` to zero
and job `total_cycles` to the leaf's cycle count. It retains the segment
index/count, program/job context and CPU/memory endpoints. The borrowed runner
view likewise resets `global_first_cycle` to one. Consequently native V2
admission checks **local** clocks; later real leaves can be proved if each leaf
fits the local ceiling and other resource/authority checks pass.

The concrete source chain is `ethereum_incremental_capture_observer_v4.zig`
(projection and local-wire creation, lines 146–164), retained wire validation
in `ethereum_incremental_capture_raw_transport_v4.validateWireAgainstRetainedMetadata`,
the STWIEF04 decoder and full verifier, then
`recursive_common_ethereum_incremental_leaf_input_v4.statementWordsFromFresh`.
That final method returns the authenticated native wire's **local** 412-word
span. It does not restore the absolute block position.

The existing global authority is
`segment_leaf_local_authority_v3.MetadataV3`: global start/end are u64, local
count remains at most 2^24, and validation joins the global span with local
CPU/memory/clock boundaries. `segment_leaf_local_verified_link_v3.VerifiedLinkV3`
can bind this metadata to a freshly verified local receipt natively. These are
already-versioned building blocks; widening shared V2 is unnecessary.

Whole-block publication still needs this exact global-to-local relation in its
active proof route. STWIEF04/FreshInputV4 alone publishes the local span, not
the global metadata/link. The older
`recursive_temporal_ethereum_leaf_bridge_v1.CompiledBridgeV1` explicitly records
that its MetadataV3/VerifiedLinkV3 AIR constraints remain missing and keeps
recursive production activation false. Reuse that relation definition when
binding the active wrapper; a native SHA/Poseidon custody seal is not its
in-circuit replacement. This is a global-position/continuation integration
requirement, **not** evidence of a native leaf failure after 16M block cycles.
No large-position proof or clock regression was executed for this cross-check.

## Worker scope of the current wrapper replay

`STWO_ROLE0_GENUINE_WORKER_COUNT=1` requests one worker for native-fixture proving,
materializer work, and the wrapper prover's explicit `ProofExecutionPool`.
It does **not** establish single-thread independent verification.
`verifyColdWithReplay` has no execution-policy argument or scoped pool.
Its preprocessed-root reconstruction calls `Engine.init` and commits Tree0.
In a test binary without a scoped pool, `work_pool.getGlobalPool()` returns null;
lifted Merkle code can still create its own executor/shared fallback pool.
`vcs_lifted/parameters.parallelWorkersForLayer` uses detected CPU count unless
`STWO_ZIG_MERKLE_WORKERS` supplies an override. The fallback pool is implemented
in `vcs_lifted/layers.zig`.

The parent observed 1265% CPU during `cold.verify` in PID 80454. That observation
is compatible with these unscoped Merkle paths; this inventory does not attribute
the entire sample to one function. Report **requested proof/materializer workers:
1; verifier thread count not bounded by that setting**. No environment or process
policy was changed during the measured replay.
