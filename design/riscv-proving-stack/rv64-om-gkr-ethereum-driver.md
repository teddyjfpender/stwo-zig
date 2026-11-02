# Experimental OM/GKR Ethereum control driver

The explicit `rv64-word16-ethereum-gkr` tool connects the production Ethereum
capture/planner and independently reconstructed setup to the OM/GKR services
coordinator. It does not replace `rv64-word16-ethereum` or certify a security
profile. `describe` prints the receiver-owned parameters. All acceptance reports
identify `experimental-om31-local-gkr-q70-p26-fold4` and set
`security_qualified: false`.

## Authority and completion

The config pins the ELF, input, ABI symbols, expected output, terminal PC and step
budget. The receiver needs only that config and the durable output directory;
it does not read execution packets. Geometry declarations pass native preflight
before setup, but cannot supply program identity, fixed-tree authority, manifest
challenges or transcript parameters.

Both native routes call one Ethereum admission implementation through a typed
request view. It checks trusted genesis, epoch/PC/register adjacency, full
nonterminal batch lengths, step budget and, for complete acceptance, the pinned
terminal PC. The wide receiver independently verifies every physical proof,
the ordered stage-one child proofs and separate RAM/KIO/Wire closures before
checking the authenticated terminal RAM against the expected 43-byte ABI output.
A verified prefix returns no Ethereum output and reports completion as false.

## Commands

```
zig build rv64-word16-ethereum-gkr -Doptimize=ReleaseFast -j2
zig-out/bin/rv64-word16-ethereum-gkr describe
zig-out/bin/rv64-word16-ethereum-gkr plan CONFIG JOBS PREFIX_COUNT
zig-out/bin/rv64-word16-ethereum-gkr produce-control CONFIG JOBS NEW_OUT PREFIX_COUNT RESOURCES.json
zig-out/bin/rv64-word16-ethereum-gkr verify-prefix-control CONFIG OUT
zig-out/bin/rv64-word16-ethereum-gkr verify-control CONFIG OUT
```

`PREFIX_COUNT=0` selects all packets and requires the pinned Ethereum endpoint.
Use the prefix receiver for a nonzero prefix. Output directories must be new;
exclusive proof/manifest writes and metadata-last publication prevent overwrites.

Resources are an explicit operational JSON input with `gkr_bytes`,
`global_bytes`, `retained_frontend_bytes`, `disk_bytes` and `schedule` (the shared
services lane policy, including a nonzero `memory_cap_bytes`). Every byte limit
must be nonzero. They govern allocations/admission, never proof statements.
The coordinator refuses an inventory that exceeds its admitted capacities before
consuming the native traces. The driver enables full MAIN coefficient/node
parking; no witness generation, FFT or commitment is repeated on restore.

The frontend retention estimate does not bound complete process RSS. Independently
owned image/setup/capture, allocator caches and PCS scratch must also fit the host.
Choose the schedule from the actual per-role retention plan, not instruction count.
No example resource numbers here constitute a qualified full-block memory plan.

## Qualification status

The durable transport is qualified in ReleaseSafe/ReleaseFast on two CPU shards
and K/ADD/DOUBLE truth proofs with independent fresh keys, changed-key rejection,
canonicality/framing/resource checks and reader allocation-failure cleanup.

The Ethereum adapter physical tests pass for honest completion, early prefixes,
incorrect halt/length/output, altered genesis and corrupt proofs. The combined
ReleaseFast gate builds the CLI and passes the truth-GKR, Ethereum terminal,
MAIN parking and wide fixed-setup suites. The Ethereum receiver also passes its
ReleaseSafe gate.

The first actual packet prefix covers 4,194,303 instructions and no service
truths. It proves, survives a fresh-process receiver, and rejects both complete
block promotion and a corrupted CPU proof with its transport hash refreshed.
The measured scalar path takes 143.34 seconds to prove and peaks at 16.43 GB RSS
on a shared host. This is a performance regression, not a GKR speedup claim.
A live sample shows serial OM31 sumcheck with the worker pool idle. Parallel
reductions/folding and M31 leaf arithmetic specialization are work in progress;
their improvement must be measured on the same request before promotion.
See `vectors/reports/rv64-om-ethereum-20261101/prefix1-scalar-v1/`.

Full-block GKR qualification, equally secure LogUp comparison, candidate 128-bit
worker authority, new-profile recursion and GPU qualification remain open.
Declaration preflight limits geometry/counts, but the experimental receiver does
not yet provide a hard total setup-memory cap for hostile declarations. It is
not a public bounded-memory verification service. No complete-block timing,
GPU result or whole-protocol 128-bit claim follows from the prefix tests.
