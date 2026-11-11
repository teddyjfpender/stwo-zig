# Mantle native replay

Private, host-only execution adapter owned by the OP integration. This is the
native replay gate in [issue #377](https://github.com/teddyjfpender/stwo-zig/issues/377).
It does not admit Mantle to the RV64 prover, recursive receiver or settlement.

The ordinary OP workspace remains independent. This crate has its own workspace,
lockfile and pinned Mantle consensus/EVM dependency graph. It authenticates every
supplied preimage, requires independent configuration and expected-block pins,
and accepts execution only when the complete resulting header hash matches.
A receipt explicitly reports `proof_verified=false` and
`derivation_verified=false`.

On a build host, run the locked crate tests through the existing `opstack_kona`
CPU CI lane. The native executable takes four positional arguments:

```text
stwo-mantle-native FIXTURE.json PREIMAGES.json EXPECTED_CONFIG_SHA256 EXPECTED_BLOCK_HASH
```

The caller supplies both pins independently of the fixture. Config SHA256 is
computed over the raw configuration JSON with recursively sorted object keys,
compact separators and no trailing newline. Preimages are an array of
`{"hash":"0x…","data":"0x…"}` records. Missing data fails execution; trace-derived
access lists are capture advice, never state authority. Malformed or duplicate
records reject. Resource limits are enforced before execution, including CLI
file-size bounds. Errors do not publish an accepted receipt; retry requires
correcting the input, never weakening the expected hash.

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

Capture identity checks already pass for 32 sampled blocks. Native execution,
guest agreement, proofs and timing-model validation require their own gates;
none follows from codec or dependency-resolution success.

The native gate passed on source `e0f4ceb5356955fe39cbeb2976728dbbd56f6686`:
[hosted CPU run 43026706096](https://github.com/teddyjfpender/stwo-zig/actions/runs/43026706096).
Both Mantle tests passed, including exact real-block replay and wrong-config,
wrong-block and missing-witness rejection; all 41 existing OP Rust tests also
passed. This is native correctness evidence, not a proving-time benchmark.
Mantle RV64 execution, proof/recursive reception and timing-model validation
remain unqualified; the existing OP chain-10 admission guard remains in force.

The five-block qualification input bundle in `tests/fixtures/` retains blocks
103132217, 103132921, 103133433, 103133561 and 103133753. The manifest records
raw-input, compressed and decoded SHA256 identities. The bounded Python loader
pins both bundle hashes and checks every input statement before materializing
it. These are live public header, transaction, bytecode and authenticated state
inputs, not benchmark receipts. Retain them while this regression is supported;
replacement requires reviewed identity pins and fresh native/proof admission.
No RPC credential is needed to execute the suite. Native replay must establish
witness completeness; capture authentication alone does not establish it.

The hosted CPU qualification first independently receives each native proof and
runs corruption trials. Recursion follows as a separate gate, preserving native
results if folding fails. The initial four-child M7 attempt exhausted its 12 GiB
live budget; the next root gate uses the existing three-child M6 diet profile
under the same budget. These outer profiles must be reported separately; this
is not a security-profile equivalence claim or a raised memory ceiling.
