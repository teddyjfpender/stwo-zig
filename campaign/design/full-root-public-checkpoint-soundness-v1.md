# Full-root soundness with public intermediate checkpoints

The intermediate snapshots do **not** have to be trusted execution oracles.
They can be untrusted, prover-supplied auxiliary receiving data. Acceptance must
come from the transition proofs and boundary/link checks, not from believing
that a checkpoint-capture program ran honestly.

The current construction has one recursive STARK proof, but it also requires
large public receiving data and receiver-reconstructed, statement-specific
keys. It is **not** a universal fixed-key verifier that accepts only bounded
ELF/input/output hashes and the root proof. The approximately 2.7 GB checkpoint
package remains part of receiving and of the measurement's communication/setup
cost. A small `root.proof` file alone is insufficient.

## Claim and assumptions

Let X be the independently selected ELF, input bytes, expected output bytes,
total instruction count, execution profile and security configuration. Let A
contain the candidate snapshots, ordered window/tree description, source
metadata, physical claims and commitment nominations. The effective verifier is

    V(X, A, proof):
        canonicalize/check A;
        derive the permitted instances and expected keys K(X,A);
        verify the root against those keys, links and full boundary policy.

Subject to the soundness of the admitted VM/caller/RAM/recursive AIR and PCS
implementations, hash collision resistance and the usual Fiat–Shamir/adaptive
statement assumptions, accepting some A and proof implies a valid complete
execution for X. A need not have been independently certified beforehand.
This is an argument with large public auxiliary receiving data. The end-to-end
execution claim follows by existentially projecting away A; the current
verification algorithm still needs A to check that claim.

A manifest/hash pin selects and protects a particular auxiliary package for
transport and reproducibility. It is not evidence that its intermediate states
are truthful. Supplying a different candidate package is not inherently a
soundness failure: the verifier must reconstruct its keys and reject unless the
proof establishes all its transitions and the same independently selected X.

## Why untrusted snapshots cannot simply invent a transition

1. `Window.deriveSpanBoundary` recomputes snapshot identities, validates sorted,
   aligned words and fixed ELF/read-only contents, and derives incoming values
   and **every** changed address from the complete candidate states. Missing
   mutable words have the explicit zero semantics used by the initializer.
2. `Window.selectAddresses` unconditionally adds all changed cells, the halt
   word and, at the terminal boundary, all thirteen halt/length/output words.
   Producer-selected first-touch addresses cannot hide a changed cell.
3. `Compact.fixedBoundary` reconstructs fixed incoming/outgoing values from
   this checked window. Its boundary selector is Boolean, and its AIR forces
   every changed row to be selected. Initial and final lookup planes close
   separately against sorted RAM. A changed but untouched address cannot be
   omitted; an unchanged, touched but uninitialized value cannot cancel itself
   through a delta-only argument.
4. Native/mixed originals authenticate the actual local memory transitions;
   the late bridge binds the same endpoint commitments under the global draw.
   Each window closes RAM against its own boundary table. Residual changes from
   different windows cannot be aggregated to excuse an invalid transition.
5. Snapshot identity and CPU equality connect adjacent windows. A candidate
   false boundary state would require either a valid transition leading to it,
   a failed proof-system/hash assumption, or a bug in the admitted equations or
   receiving implementation. The capture program's honesty is not an extra
   mathematical premise.

Relevant authorities are
`prover/block_v7_real_window_policy_v2.zig` (`deriveSpanBoundary`,
`selectAddresses`, `validateSnapshot`, `mix`),
`prover/block_v8_compact_ram_proof_v1.zig` (`fixedBoundary`, `closeClaims`), and
`prover/block_v8_compact_ram_component_v1.zig` (`BoundarySpec.equationsFor`).

## Key-to-statement coupling

This coupling depends on the **receiving factory**, not on a producer-supplied
verification key or a successful host-verification receipt:

- `block_v8_window_root_receiver_v1.deriveLeaf` and the mixed metadata receiver
  derive `Window`, source scopes and the global policy from the same external
  ELF/snapshot data. No serialized VK is accepted.
- `block_v8_window_root_profile_v1.Owned.deriveJoin` derives both the exact Join
  admission/key and `WindowSpan` from that same global `Window`. The window's
  CPU, snapshot identities, interval selection, complete changes and boundary
  ports enter the policy/epoch framing. Its fixed RAM table also fixes the
  corresponding values. The profile identity seals admission, span and root.
- `RootAdmission.snapshot` preserves the original protocol prefix and exact
  typed public-supply coordinates. `block_v5_open_parent_composition_v2`
  replays the child parent-AIR equations and constrains the symbolic claim sum
  against those coordinates under the child transcript's actual challenges.
  It does not replace this equation with a host success flag.
- The upper graph checks exact CPU/snapshot adjacency and coverage, preserves
  only the first initialization and final terminal ports, and binds its result
  to the independently reconstructed aggregate statement.
- `Tree.verifyFull` reconstructs the profiles, checks the exact independently
  derived boundary selection and full span, then verifies the root and its
  nominated fixed/main commitments.

Some span and public-supply values are pinned into the compiled instance rather
than recomputed from raw snapshot bytes inside the fold AIR. This is acceptable
only because the trusted receiving code reconstructs the expected circuit/key
and these values together from canonical A. It is precisely why snapshot IDs
plus an opaque prover-nominated VK would be insufficient. Low-level APIs that
accept prepared profiles require independently derived profiles; the
publication/receiving boundary is `Tree.verifyFull`, not trusting such objects
from a producer.

The permitted key family and geometry must remain checked: exact admitted ISA
semantics, all physical claims, count/range bounds, mandatory caller/halt/RAM
constraints and pinned q70/26 configuration. An arbitrary VK or an unchecked
metadata-driven omission of constraints would invalidate this reasoning.

## Initial and terminal anchors

`FullBoundary.Owned.derive` reconstructs S0 from the pinned ELF and input through
the authoritative loader/session initializer. Full receiving requires first
cycle 1, the exact initial snapshot/CPU and initialization policy ID, total
coverage, and the independently selected terminal policy ID. The expected halt
word, length and output bytes are authenticated by the terminal RAM boundary
AIR. Earlier nonzero halt accesses remain forbidden by native/caller guards.
Thus an untrusted initial or final snapshot cannot replace initialization or
expected-output verification.

## Architectural and publication limits

Receiving must retain the selected plan, checkpoint/source data, thin metadata
and their transport identities. It must hash/validate large snapshots, rebuild
boundary tables and recursively reconstruct keys; it does not merely verify a
small constant public-input proof. It also exposes intermediate memory and may
expose input bytes: this interface provides no checkpoint-privacy claim.

Appropriate wording is: **one independently verified recursive STARK root for
the execution, using public checkpoint data and receiver-reconstructed keys**.
Do not call it a standalone bounded-public-input proof, a universal fixed-VK
wrapper, or a proof that relies on trusted execution checkpoints.

This audit found no additional soundness hole caused merely by supplying the
intermediate snapshots untrusted. It is a code-path audit, not a formal proof of
every underlying AIR and not evidence that the retained full-block run has
already completed. Completing and profiling that actual run remains required.
