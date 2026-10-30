# Pinned Ethereum guest statement and terminal-memory ABI

Status: source-level architecture audit, 2026-10-28. This does not qualify a new
proof protocol or change the existing v5/v6 acceptance rules. It supplies the
semantic boundary for the [terminal-memory proposal](ethereum-terminal-memory-statement-20261028.md).

## Exact source examined

The local Ethereum guest pins `paradigmxyz/stateless` commit
`a134a621bad7229ff7f980e42dfca8e22d101491` in
`autoresearch/benchmarks/guest_runtime/ethereum/Cargo.toml:20`; its `Cargo.lock`
records that exact revision. No local checkout was present, so the immutable
revision was fetched for this audit. Its Reth dependencies, also present in the
guest lockfile, pin `3d270d933daeeb90c5735d81ff7f80c00322d6de`.
References below point to those revisions, not moving branches.

The Cargo revision is reproducibility evidence, not sufficient proof admission:
the verifier must select the exact compiled ELF/program and execution profile.
Different compiler flags or `collect-evm-hints` produce a different executable.

## What the 43 bytes mean

[`guest.rs:35-52`](https://github.com/paradigmxyz/stateless/blob/a134a621bad7229ff7f980e42dfca8e22d101491/crates/stateless-validator-reth/src/guest.rs#L35)
decodes the schema-prefixed input, hashes the decoded payload request, runs
validation, and serializes this result. The exact layout has a source test in
[`output.rs:15-46`](https://github.com/paradigmxyz/stateless/blob/a134a621bad7229ff7f980e42dfca8e22d101491/crates/stateless-validator-common/src/guest/output.rs#L15).

| Output bytes | Meaning | Required public admission |
|---|---|---|
| 0–31 | SSZ hash-tree root of `NewPayloadRequest` | Expected payload request root, independently computed with this schema |
| 32 | Successful validation boolean | Exactly 1 |
| 33–40 | Chain ID, little endian u64 | Expected chain, e.g. 1 for Ethereum mainnet |
| 41–42 | Schema ID, little endian u16 | Expected fork and schema revision for this job |

This root is **not the Ethereum block hash**, nor a pre/post-state root pair.
It commits the full request, including payload parent hash, post-state root,
receipts root, bloom, block number, gas fields, timestamp, block hash and
transactions; later request versions include withdrawals, blob/sidecar fields
and execution requests. See
[`new_payload_request.rs:126 onward`](https://github.com/paradigmxyz/stateless/blob/a134a621bad7229ff7f980e42dfca8e22d101491/crates/stateless-validator-common/src/guest/input/new_payload_request.rs#L126)
and the conversions in
[`convert.rs:129-202`](https://github.com/paradigmxyz/stateless/blob/a134a621bad7229ff7f980e42dfca8e22d101491/crates/stateless-validator-reth/src/guest/convert.rs#L129).
The expected root cannot be taken from the received proof as its own authority.

Local `ethereum/src/main.rs:177-198` reads the input length, calls this validator,
requires length 43 and success byte 1, then writes result, output length and halt
flag. Malformed input returns the all-zero unsuccessful sentinel upstream;
the local assertion prevents publishing it as successful completion.

## What success verifies, and what it does not

The observed dependency chain is:

1. Decode the fork-specific SSZ request, witness, chain ID and transaction public
   keys. Input schema prefix is **big endian**, unlike the result's schema field.
   Unsupported fork/revision or incompatible request shape is rejected
   ([`input.rs:130-148`](https://github.com/paradigmxyz/stateless/blob/a134a621bad7229ff7f980e42dfca8e22d101491/crates/stateless-validator-common/src/guest/input.rs#L130)).
2. Reconstruct the execution payload/header. Require computed block hash to equal
   its declared block hash; validate Shanghai/Cancun/Prague field compatibility
   ([`convert.rs:337-375`](https://github.com/paradigmxyz/stateless/blob/a134a621bad7229ff7f980e42dfca8e22d101491/crates/stateless-validator-reth/src/guest/convert.rs#L337)).
3. Require exactly one supplied public key per transaction and verify recovered
   signer equality, parity and Homestead low-s handling
   ([`recover_block.rs:28-93`](https://github.com/paradigmxyz/stateless/blob/a134a621bad7229ff7f980e42dfca8e22d101491/crates/stateless/src/recover_block.rs#L28)).
4. Keccak-hash and decode ancestor headers, require a parent, cap the list at 256,
   and require every parent hash and block number to link to its child. Validate
   the current header against its parent and perform pre-execution consensus
   checks ([`validation.rs:255-283,350-400`](https://github.com/paradigmxyz/stateless/blob/a134a621bad7229ff7f980e42dfca8e22d101491/crates/stateless/src/validation.rs#L255)).
5. Initialize the sparse trie at that authenticated parent header's state root.
   Hash all witness trie nodes and contract code; access nodes through their
   authenticated trie/code hashes
   ([`zeth.rs:115-161`](https://github.com/paradigmxyz/stateless/blob/a134a621bad7229ff7f980e42dfca8e22d101491/crates/tries/src/zeth.rs#L115)).
6. Execute the block, check post-execution results, compute the updated state
   root and require equality to the current header state root
   ([`validation.rs:285-340`](https://github.com/paradigmxyz/stateless/blob/a134a621bad7229ff7f980e42dfca8e22d101491/crates/stateless/src/validation.rs#L285)).
   The pinned Reth checker compares gas used, receipts root/logs bloom, and
   fork-dependent execution requests and block-access-list hashes
   ([Reth `validation.rs:43-121`](https://github.com/paradigmxyz/reth/blob/3d270d933daeeb90c5735d81ff7f80c00322d6de/crates/ethereum/consensus/src/validation.rs#L43)).

The pre-state root is consequently bound through the payload's parent hash and
the supplied parent's hashed header; it need not be separately returned to bind
this payload-validation statement. A consumer wanting an explicit pre-state
root must authenticate its opening from that parent header, not label arbitrary
metadata as proved.

This is not proof of canonical-chain inclusion, finality, or beacon consensus.
The caller must select the desired payload/chain/schema and its chain anchor.
In particular, the validator constructs a chain configuration with all forks up
to the **input-selected fork active at genesis**, not a full historical mainnet
activation schedule (`convert.rs:59-107`). Chain ID alone is insufficient.
The pinned conversion also contains an Amsterdam-specific validation TODO
(`convert.rs:373`); this audit does not certify that fork's complete semantics.

## Can the witness become private?

Yes, as a statement-design inference: an existential witness is sufficient for
the above payload-validation claim when the verifier independently pins the
43-byte result and program/profile. Ancestor headers, trie nodes, code preimages
and transaction public keys are checked against committed payload/header or
signature data by the guest. They need not be separately exposed in the public
statement. Unused witness material does not affect the claim. Here “private”
means existential, nonpublic statement input; it does not assert that the
current proof encoding provides zero-knowledge confidentiality.

This does **not** preserve the current stronger exact-input VM statement.
`prover/block_v4_cpu_runner_source.zig:19-35,88-96` independently pins and checks
ELF/input/oracle SHA-256 values. `block_v5_cpu_driver_admission_common_v1.zig:41-55`
mixes those hashes, program root, final RAM root, schedule and execution recipe
into source identity. `block_v5_initial_sources_v1.zig:20-61` separately binds
input length/hash and the initial memory plan. Dropping the input hash requires
a new protocol/statement version and cannot silently retain the old claim.

Private input still has to be one committed, consistent initialized buffer:
commit its value table before memory challenges; constrain length/bounds and
all first-touch reads against it. No source may read arbitrary unconstrained
memory outside the explicitly private input region. ELF initial data, BSS,
heap/stack zero rules and any ABI defaults remain fixed by independent policy.
The current host-only SHA/source checks are not a substitute for these AIR and
detached-verifier obligations.

Optional recovery hints are not authoritative. In the local
`ethereum/src/evm_recovery.rs:7-31`, false/unsupported hints use software recovery;
true supported hints invoke proved recovery with normalized signature/parity.
`evm_hints.rs:68-78` checks the supplied hint count. The collection feature
appends a footer to output and therefore must be excluded from this 43-byte
terminal policy by exact program admission, not merely assumed absent.

## Exact terminal memory ABI

For the current `ethereum/linker.ld:9-16`:

| Memory address | Terminal read | Constraint |
|---|---|---|
| `0x00c00000` | Halt flag u32 | 1 |
| `0x00c00004` | Output length u32 | 43 |
| `0x00c00008` … `0x00c0002c` | First ten aligned output words | Public output bytes 0–39 |
| `0x00c00030` | Eleventh aligned output word | Low three bytes equal public bytes 40–42 |

Thus 13 aligned read events suffice for the result/control boundary. The high
byte at `0x00c00033` is outside the output; authenticate the full word in RAM but
do not accidentally add a public zero-padding claim about that byte. Canonical
zero padding of an encoded public result is a separate representation rule.
The byte at output offset 32 is in the word at `0x00c00028`.

These addresses must come from the independently admitted ELF ABI, not received
proof metadata. `runner/elf_loader.zig:166-217` extracts symbols/layout after
profile admission. The input region is `0x00800000..0x00c00000`; the guest reads
its u32 length prefix, canonical SSZ bytes after it, and optional hints in the
remaining region. Terminal-only output reads do not replace initial input
authority or complete guest memory proving.

## Smallest sound v7 qualification fixture

Use a deliberately small, independently pinned two-segment RV32 program first;
do not label it an Ethereum validation proof. Initialize one nonzero ELF word,
one private input word, one BSS zero word and zeroed output/control cells. In the
first segment read/modify input and scratch; in the second read the persisted
values and write a 43-byte result, length and halt flag. Include a word never
written by the guest and a partial final output word. Bind the thirteen terminal
reads to strictly later, checked-u64 clocks in the same RAM relation. Authenticate
every first touch via the new ELF/private-input/zero classifier, close exact
native/precompile/global source counts, and verify the detached root after
deleting every source/capture file.

Reject wrong initialized values, false zeros, stale output versions, omitted
terminal reads, wrong length/success/chain/schema, substituted program, clock
wrap and broken cross-segment/shard links. Then extend the fixture with genuine
precompile reads/writes before executing the unchanged pinned Ethereum guest.
The final Ethereum gate must compare the admitted payload root and exact 43-byte
output, preserve all original cryptographic/security parameters, and independently
verify the completed root. No implementation or performance claim is made here.
