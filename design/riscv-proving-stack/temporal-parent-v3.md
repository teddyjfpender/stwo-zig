# V3 temporal parent proof boundary

The V3 parent must verify two **independent, ordered child proofs** before it
can publish an interval. A child may be a leaf wrapper or an earlier V3
temporal parent. An odd child is carried unchanged to the next layer; no
empty proof is invented. Three leaves therefore require two actual parent
proofs: `(leaf 0, leaf 1) -> parent 0`, then `(parent 0, leaf 2) -> root`.

`temporal_parent_inputs_v3.zig` defines the canonical 1,869-word field frame
for a binary parent candidate. It records both child families and pinned key
identities, each child's 412-word statement, entry and exit sparse-memory
boundary, endpoint metadata identities and final completion. It also records
the corresponding parent values and the 64-bit join cycle. `Layout` assigns
stable coordinates so the future verifier-source and boundary AIRs can read
the same frame without caller-selected offsets. `CandidateInputsV3.init`
checks the frame against a freshly derived `PairPreflightV3`; it is a native
preparation check, not proof verification.

The `temporal_child` key pin identifies an earlier parent proof being consumed.
It does not claim to be the key of the new parent. That distinction avoids a
self-referential verification-key preimage while the recursive key schedule is
still being designed.

`temporal_parent_roster_v3.zig` fixes the versioned component order and stage
identity. Its statement-input row uses the qualified log-12 row-11 typed AIR,
including the graph, binding and preprocessed identities. The other six
roster obligations remain unqualified: left and right child verifiers,
the arithmetic statement graph, boundary/completion joins,
endpoint-identity joins, and shared lookup provider. Their geometry is
deliberately absent rather than filled with
invented zero-column components. The stage identity is not a verification
key, and `requireVerificationKey` and `requireVerifiedParent` fail closed.

To activate a parent transaction, the remaining work is:

1. Construct family-specific leaf-wrapper and temporal-parent verifier AIRs
   under independently pinned keys. Their successful outputs must supply
   every `ChildSourceV3` word, including family and key identity; a host-built
   `ChildSourceV3` cannot serve as that output.
2. Commit typed source and boundary AIRs that join all 1,869 input words to
   those verifier outputs and to the parent public statement. Constrain the
   64-bit cycle join, CPU state, sparse snapshot identity/count/root,
   endpoint metadata identities and final-only completion. The existing
   row-11 session checks the three 412-word statements natively and emits its
   typed input trace; the arithmetic graph still needs committed AIR.
3. Bind the completed component roster, exact shared lookup closure,
   preprocessed root, protocol/security profile and proof bytes in one fresh
   parent verifier transaction. Only its successful result may publish a
   parent proof and eventually enable the production flag.

The older parent proof key and its row-11 graph remain unchanged.
