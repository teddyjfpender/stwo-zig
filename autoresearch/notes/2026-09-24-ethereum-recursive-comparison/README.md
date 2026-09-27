# Ethereum subsystem comparison with recursive completion

Status: accelerated transaction-authentication CPU measurements and recursive
qualification are recorded in [RESULTS.md](RESULTS.md), with raw data in
`summary.json`. The sections below retain the broader workload specification.
This replaces the software SHA chain as the next architectural comparison. It
does not replace that campaign's retained observations or claim block proving.

## Workloads and statement

1. **Transaction authentication:** batches of signed EIP-1559 transaction
   envelopes. Parse the typed/RLP encoding, reconstruct the signing payload,
   Keccak-hash it, recover the secp256k1 public key, derive the sender address,
   and commit ordered transaction hashes and senders. Enforce the selected
   transaction type's signature and canonical encoding rules. This proves
   authentication, not balances, nonces, gas accounting or EVM execution.
2. **State witness verification:** verify account/storage Merkle Patricia trie
   inclusion and exclusion against an authenticated state root, with real RLP,
   hex-prefix paths and embedded-node/hash-reference handling. Use pinned
   fixture bytes with independent expected values. This adds variable memory
   access and parsing to Keccak work; it is not a state transition proof.
3. **SHA-256 workload:** SSZ Merkle branch verification, with explicit depth,
   generalized index and root binding, plus variable-length SHA-256 calls for
   the EVM SHA operation as a separate fixture. SSZ is consensus-related and
   must not be presented as the execution-layer MPT algorithm.

Start with transaction authentication, then add state witnesses. SHA acceleration
has a local integration gap below and should not delay the first two workloads.
Use deterministic valid cases and a separate rejection corpus: malformed RLP,
invalid signatures, wrong roots, modified nodes, wrong path/index and reordered
records. Rejection proofs are not mixed into valid-case latency measurements.

Bind a versioned workload/program identity, input commitment, item count, ordered
result commitment and any roots in the final public statement on both systems.
Inputs are runtime data, not hardcoded answers. Independent host implementations
provide the expected results; host hints never substitute for proved constraints.

Calibrate powers-of-two batch sizes around a local roughly 20-second complete
recursive transaction where feasible, then freeze identical inputs for the peer.
Keep smaller/larger sizes to expose padding and amortization. Do not select a
different item count for each prover, force equal ISA instruction counts, or
force equal leaf counts: native packing and segmentation are part of the design.
If recursion's fixed cost already exceeds 20 seconds, report that floor honestly.

## Current implementation evidence

| Facility | STWO-Zig evidence | ZisK pinned source |
|---|---|---|
| Keccak | Joined guest/Keccak/signer proof gate in `src/integrations/riscv_cpu/ethereum_precompile_proof_test.zig`; `ethereum_main.zig` consumes authenticated call records | `ziskos/entrypoint/src/zisklib/lib/keccak256.rs`, backed by Keccak syscall |
| secp256k1 recovery | `src/frontends/riscv/isa/ethereum_signer_recovery.zig` ABI and joined proof gate | `zisklib/lib/secp256k1/ecdsa.rs::ecdsa_recover_secp256k1`, native field/curve operations and hints |
| SHA-256 | Fixed-64-byte pair candidate only: `sha256_pair_direct_candidate_v1.zig` explicitly has production, CPU dispatch and memory linkage disabled | `zisklib/lib/sha256.rs::sha256` calls SHA compression syscall |
| Recursive completion | Native BLAKE3 parent supports Ethereum capture; canonical four-leaf tree qualified on a six-cycle base fixture | Prior peer host produces and verifies a final aggregated BLAKE3 proof |

The existence of the local tiny tree does not qualify a large precompile-heavy
tree. Reuse the typed Ethereum capture/extension and actual segment boundaries;
prove the new guest through the entire tree and independently verify its final
serialized artifact. The older recursion-CSP script explicitly classifies its
output as a verifier-subsystem diagnostic and must not supply the headline result.

Local SHA work needs production registration/dispatch, caller and memory linkage,
full proof integration and recursion coverage. The candidate has 2,162 main
columns and 128 active rows per pair: low guest instruction count alone would
not establish a fast precompile. Measure trace volume and padding before promoting
its layout; support general compression/variable-length hashing separately from
the fixed-pair optimization.

Peer source inspected: ZisK `5c5f81c96929abed88894473ec6060b1b545b5c5` already
provisioned by the guest-e2e campaign. Use its native SHA, Keccak and recovery
libraries, not ordinary unpatched crypto crates. Confirm actual precompile use
from execution and AIR-instance telemetry. Preserve native arithmetic/GLV/hint
paths and default efficient proof scheduling; do not mimic our internal ABI.

## Measurement boundary

Primary metric: runtime input to one independently verified recursive artifact
binding the complete batch. Retain native STARK completion on both systems;
exclude any extra Ethereum on-chain SNARK wrapper unless added on both sides.
Record setup/key preparation separately, and distinguish warm service latency
from fresh-process latency. Include per-input hint generation in end-to-end time,
or report it separately with an additional inclusive total. Precomputed hints
must never be a hidden advantage.

Report execution/hints, witness, base proofs, recursion preparation, each aggregate
level, final verification, proof bytes, peak footprint, AIR rows/padding and
precompile counts. Record overlap with timestamps: overlapping phase sums are
not wall latency. ZisK's existing `GENERATING_INNER_PROOFS` timer includes base
proving and inner recursion; it needs finer instrumentation before attributing
cost to either. Diagnostic nonaggregated runs can isolate base costs but are not
the final headline. Report base/recursive resources and critical path together.

Use two hardware tracks:

- Same-host CPU with comparable total CPU/memory budgets, native precompiles,
  hints and scheduling enabled. This is implementable on the current Mac, but
  its emulator backend is not ZisK's full optimized Linux/assembly/CUDA stack.
- Best supported accelerated configurations: our Metal and ZisK CUDA. Record
  devices, counts, RAM/VRAM, power state and software configurations. Different
  hardware is a deployment comparison, not a controlled prover speed ratio.
  No CUDA machine has been established in this investigation; do not describe
  the existing Mac CPU run as ZisK at full hardware capability.

Keep our 70-query/26-PoW profile. Pin ZisK's official BLAKE3 configuration and
record all leaf/recursive security parameters and soundness claims. Equal query
counts do not imply equal security across different fields and FRI schedules.
No security-normalized ratio until both final statements and soundness targets
have been justified. Final recursive completion is necessary, not sufficient,
for that claim.

## Roadmap driven by measurements

1. Build the transaction-authentication fixture/adapters on existing Keccak and
   recovery paths; check outputs and observed precompile use before expensive
   proving. Reuse the retained peer toolchain/key/build harness.
2. Qualify local accelerated leaves through recursive completion at canonical
   settings and peer native aggregation. Instrument the base/recursion split.
3. Run matched batch-size sweeps, then repeated samples at the frozen target.
   Attribute fixed recursion cost versus incremental cost per transaction.
4. Add MPT state-witness workload, measuring memory/caller linkage and padding.
5. Finish SHA production integration and qualify accelerated SSZ/EVM SHA cases.
6. Optimize measured bottlenecks: precompile constraints/packing if leaves
   dominate; verifier hash/PCS geometry if recursion dominates; bounded branch
   parallelism and overlap if critical-path idle time dominates. Seek CUDA
   evidence before drawing conclusions about ZisK's production block latency.

This is deliberately narrower than full Ethereum. BN254/BLS/KZG, complete EVM
execution and full state-transition validation remain later coverage; the three
initial primitive families alone cannot establish block-proving readiness.

## Sources

- [ZisK precompiles](https://0xpolygonhermez.github.io/zisk/getting_started/precompiles.html)
- [ZisK Ethereum client, hints and backend controls](https://github.com/0xPolygonHermez/zisk-eth-client)
- [ZisK 1.3.0-alpha scheduling, packing and recursion changes](https://github.com/0xPolygonHermez/zisk/releases/tag/v1.3.0-alpha)
- [Prior native CPU guest measurements](../2026-09-24-zisk-guest-e2e/README.md)
- [Canonical local tree qualification](../2026-09-24-canonical-aggregation-tree/README.md)
