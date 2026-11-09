# Draft RFC: explicit CPU circuit collaboration boundary

Status: draft; no issue, invariant-owner approval or contract edit is recorded.
Owners: `riscv-cpu-integration`, `circuit-cpu-integration`; consult `proof-wire`.

## Problem and exact decision requested

The complete hosted RISC-V CPU integration build at `9677e799a` clears its five
missing circuit-frontend bindings, then fails on two existing imports of
`stwo_circuit_cpu_integration`: `rv64_recursion/om31_outer.zig` and
`rv64_recursion/root_verify.zig`. The package manifest does not name that provider.
The provider already exports `om31`, but its public ledger omits that namespace.
Its build also already depends on proof wire, which its dependency ledger omits.

Approve only this additive contract transaction:

| Package | Exact contract change | Version |
| --- | --- | --- |
| `stwo_circuit_cpu_integration` | Add `stwo_proof_wire: ../../waist/proof_wire` to dependencies; add existing `om31` to the sorted public API ledger | `0.1.0` to `0.2.0` |
| `stwo_riscv_cpu_integration` | Add `stwo_circuit_frontend: ../../frontends/circuit` and `stwo_circuit_cpu_integration: ../circuit_cpu` to dependencies | `0.1.0` to `0.2.0` |

The circuit-frontend edge and provider's proof-wire edge already exist in their
build manifests. The circuit-CPU consumer edge needs a matching build-manifest
entry and canonical module binding. Update the two build-manifest versions and
owner guides with the approved contracts. Do not change any other API ledger,
dependency, layer, protocol identifier, profile registry, artifact or golden.

This adds three declared graph edges. With the current contracts, the graph
would have 100 edges instead of 97 and must remain acyclic. This is a concrete
proposal, not authorization to increase that count for unrelated findings.
Hundreds of other workspace findings remain outside this decision.

## Collaboration and ownership

The CPU RISC-V consumer uses the existing OM31 program, proof and wire authorities
for its fold/root receiver. Construct the provider through its existing package
build, sharing canonical core, prover, CPU backend and circuit-frontend modules.
The provider owns its generated CPU composition module and existing teardown.
The consumer owns request admission, receiver policy, tree coverage and publication.

The added declaration does not qualify every nested helper in the existing
namespace. Acceptance here covers CPU consumers and their existing wire identity.
No device execution, GPU-native promotion or hardware/performance claim follows.
Existing experimental or unavailable paths remain so.

## Compatibility and tests before the ledger change

No symbol is removed or renamed, and the existing `om31` namespace is not
implemented anew. Keep its concrete OM31 field, plain Blake2s Merkle family,
raw-mod transcript authority, profile selection and wire framing unchanged.
Unknown profile IDs, altered native VK sections, producer-supplied tables and
invalid tree adjacency must retain their existing rejection behavior.

Before updating ledgers, add provider-owned signature/authority checks for the
existing namespace and consumer-driven coverage of the actual fold/root use.
Use the already registered bounded roots, including
`test-riscv64-m5-vk-table` and `test-riscv64-m5-rootverify`, retaining their named
cases and discovery floors. Keep the dedicated complete BLAKE3 proof corpus.
Then implement the canonical binding and run:

- Circuit CPU package tests and its existing OM31 contract root.
- Complete RISC-V CPU integration tests and the dedicated proof corpus.
- The named receiver/VK refusal roots in Debug and ReleaseFast where bounded.
- Exact dependency graph, cycle, owner-routing and focused-CI contract checks.

Do not weaken a check, declare a package module as an opaque injection to hide
the edge, or remove a failing receiver test. A passing namespace test alone
does not establish complete recursion, block proving or production qualification.

## Budget, rollback and process

Implementation allowance: at most +40 net code/test lines, zero runtime flags,
zero scripts or launchers. Count documentation, configuration and receipts
separately. The positive allowance owns explicit provider/consumer contracts and
canonical module identity. Rollback reverts the additive binding and ledgers;
no historical artifact reader or proof format is retired.

ENGINEERING_STANDARDS.md BC-R2 and AC-1 require an approved RFC issue for these
dependency/API changes. This draft requests an owner decision and separate
authorization to open the RFC issue and record that decision. It records no
approval and applies none of the proposed contract changes.
