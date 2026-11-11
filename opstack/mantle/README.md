# Mantle execution and CPU proving

Private Mantle execution owner for [issue #377](https://github.com/teddyjfpender/stwo-zig/issues/377).
Its workspace, lockfile and pinned consensus/EVM dependencies are separate from
ordinary OP/Ethereum execution. It accepts an execution only when the complete
computed header matches an independently supplied expected block hash. This
proves execution under a pinned parent/configuration, not L1 derivation,
finality or settlement.

The host supports the original four-position native replay command and the
versioned guest-input envelope:

```text
stwo-mantle-native FIXTURE.json PREIMAGES.json EXPECTED_CONFIG_SHA256 EXPECTED_BLOCK_HASH
stwo-mantle-native guest-input INPUT.json
```

Native execution receipts explicitly report no STARK/derivation acceptance.
`build.py --variant mantle-services --guest-opt-level s` builds the alloc-only
RV64 guest using existing v3 Keccak-sponge/SHA services; `mantle-software` is the
software control. Use the existing `opstack/benchmark.py --network mantle` and
`opstack/cpu.py` entrypoints for agreement and complete CPU proof reception.
No new AIR, service opcode, proof wire or top-level launcher is introduced.

The guest's 43-byte public statement is
`SHA256("stwo/mantle/execution/v1\0" || SHA256(raw_input) || computed_block_hash)`
followed by success byte 1, little-endian chain ID 5000 and `ME`. The computed
hash must first equal the independent block pin. Program/image, exact input,
terminal state and output remain authenticated by the generic prover/receiver.
An arbitrary program emitting ME43 is not Mantle execution authority.

Config SHA256 uses recursively sorted JSON object keys, compact separators and
no trailing newline. Preimages are an array of `{"hash":"0x…","data":"0x…"}`
records. Missing, malformed, hash-invalid or duplicate records reject. Trace
access suggestions never establish state authority. Correct an incomplete input;
never weaken the expected header or proof checks.

## Sources and fixture provenance

- Mantle consensus/Kona: `mantle-xyz/mantle-v2` at
  `305d78b348748e47bd0fe2d4d95bb29ddb10f9ba` (MIT OR Apache-2.0).
- All thirteen revm-family patches: `mantle-xyz/revm` at
  `835cb4eb742698c5884248f546c68c9d716cc995` (MIT).
- The graph is contained in this unpublished crate. Removing the crate and its
  CI command rolls it back without changing OP/Ethereum dependencies. Hosted
  dependency-policy checks remain required; source pinning is not an advisory
  audit or execution qualification.

The live public fixture is Mantle mainnet block **103132217**, expected hash
`0xbac88cdc801196ab975bb07717bd964f87b14b093ac94997f47f768ed7ff1fcc`.
Its account/storage proofs and bytecode were authenticated against parent block
103132216, state root
`0xc2ee5cb1429c7044f0ac1d25b743b71a1ed132777ac2a5918d913bb5b06caf32`.
The fixture retains exact transaction bytes, rather than removing Mantle's
`ethValue` field. It contains no RPC credentials.
Its 77 authenticated preimages include the blockhash and beacon-root system
contracts and the withdrawal-message passer. Transaction-only prestate traces
omit system calls, so their account/code and required storage proofs are fetched
separately against the same parent root.

Execution configuration starts from `mantlenetworkio/networks` revision
`f6e0f07ce813bd2f9965fceb7c32756b2f55d383`, `mainnet/rollup.json`.
That historical file lacks modern fork timestamps. The fixture explicitly adds
Mantle BaseFee/Everest/Skadi/Limb/Arsia and the OP fork alignment from
`mantle-xyz/op-geth` revision `a45c5d3f59d6ae31470e5ebb8db1be8830c119ef`,
`params/mantle.go` and `tests/mantletest/replay/chainconfig.go`.
This is a source-derived **execution configuration**, not an assertion of L1
derivation or a live node's exported rollup configuration. Its pinned SHA256 is
`b9583f9b493763c945cc961535b9298070c92d538be1af77523b27053f4a23de`.
Payload attributes come from the authenticated child header and raw transactions;
Jovian fee parameters/minimum come from its exact 17-byte extraData.

## Capture completeness and regression inputs

The bounded, hash-pinned archive in `tests/fixtures/` retains blocks 103132217,
103132921, 103133433, 103133561 and 103133753. Its manifest pins each exact raw
input and both compressed/decoded identities. It contains public state/code,
headers and transactions, with no RPC credentials. Retain it while the regression
is supported; replacements require reviewed identity pins and fresh execution
and proof admission. Benchmark receipts and durable proofs stay outside source.

Opcode traces omit the VM's intrinsic fee reads. Pinned Mantle revm
`835cb4e`, `crates/op-revm/src/{l1block,constants}.rs`, reads GasPriceOracle
slot 0 (token ratio), L1Block slots 1/3/5/6/7/8 and fee-recipient accounts for
normal transactions. Their parent-state proofs and bytecode are included and
tested independently against the expected parent root.

Block 103133753 creates a contract. Capture also needs the parent-state absence
proof at CREATE(sender, nonce), even when the prestate tracer omits that new
account. Tests bind the actual transaction/nonce, derived address and retained
nodes. RPC all-zero absent-account metadata is ignored; authenticated secure-key
trie absence is the authority. No shared proof validator is relaxed.

## Qualification and reproduction

All five inputs have native/RV64/Unicorn agreement and complete native CPU proofs
accepted by fresh receivers on the user-authorized 64 GiB M5 Max. Both native
transport corruption and a rehashed corrupted proof reject. Block 103132217 also
has a freshly accepted M7 recursive execution root; changing a root byte rejects
with `RecursiveReceiverArtifactMismatch` (an artifact-integrity test).
Changing both the root alias and final-fold proof together also rejects with
`RootMismatch` at cryptographic verification. Both controls restore exact bytes.

[PR #372](https://github.com/teddyjfpender/stwo-zig/pull/372) records the measured
table, exact source/binary/input identities and external report/receipt manifest.
The local cohort uses 16 workers, one lane, 1,048,575-step batches, native
`d2_native_b4_q54_p20_fold4` and outer
`m7_outer_gkr_k4_cap3_r1_b2_q108_p20_fold4_v1`. Operator runtime admissions are
4 GiB fixed setup, 16 GiB native lane, 32 GiB native receiver and 48 GiB recursive
producer/receiver; the repository ceilings are unchanged. These are individual
qualification observations, not quiet-run medians or hosted/Mac speedup claims.
The failed 12 GiB hosted folds are a separate, insufficient-capacity cohort.

The existing `mantle-cpu-qualification` workflow reproduces the build, fixture
materialization, agreement and strict proof commands. `mantle_suite=five-block`
runs independent native jobs; `single` selects a pinned `mantle_block` and tests
a root only for 103132217; `replay` stops after execution agreement. Hosted prover
builds pin `x86_64_v3` and record CPU features. Native-target artifacts must not
be reused on a different CPU from their byte hash alone. Benchmark the Mac
cohort locally using its pinned native binary and recorded resources.

The security label is **128-bit target under documented assumptions**, not
certified whole-protocol security. Other four recursive roots, broader sample
coverage and L1-anchored Mantle derivation remain open. The five-point multivariate
native timing fit fails leave-one-block-out validation and must not forecast
new blocks. The OP chain-10 guard and default Ethereum route remain unchanged.
