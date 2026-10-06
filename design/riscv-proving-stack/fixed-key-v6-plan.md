# V6 fixed-key template for a direct RISC-V leaf

This is an implementation plan and a **blocking audit**, not an admitted key or
proof. The [50-row inventory](fixed-key-v6-audit.tsv) covers every preprocessed
component in the V5 candidate. `template_rebuild` means the field must be
regenerated from a verifier-pinned template for an admitted shape; it does **not**
mean the current writer has passed an invariance test. `move_leaf_values` names
known request-dependent fields that must leave preprocessing. No row is cleared
for a shape-only key yet.

## Current key failure

`segment_leaf_wrapper_roster_direct_v5.Plan` embeds the V4 plan. V4 copies
`base_manifest.seal` into `base_manifest_seal` and includes that value in its
plan seal and transcript authority mix. The V2 manifest seal includes transcript,
statement, public, and boundary source identities. It is explicitly different
across honest leaves. VPR6 hashes the V5 plan seal; VPK6 then hashes VPR6 and
the preprocessed root. Thus the current VPK6 is **not** a reusable shape key,
even when row geometry agrees. Removing only the seal from VPK6 would be unsafe:
the actual preprocessed columns can still contain leaf values.

The highest-confidence leaf-value leaks are:

* Row 4's V2 `constant_value` is copied from `frame.words` for non-payload
  words. The V4 Tree0 export changes lookup behavior but does not turn every
  such value into a fixed template constant.
* Row 5's `constantPayload(.public_geometry, ...)` path places geometry and
  lookup identity words behind a fixed-value mask. Some fields are truly shape
  data; others are statement/activation identities. They need an explicit
  origin classification and source equality, rather than a blanket claim that
  all `public_geometry` words are constant.
* V4 row 42 placed ProgramV2 expected words in preprocessing. V5's typed
  bridge puts words in main and fixes only format/profile constants, but its
  `NPV2` producer coverage is incomplete. Moving words alone does not bind
  them to the executed native verifier.

The 50-row inventory conservatively includes every other preprocessed schedule
as a template-rebuild obligation. Rows 11–19 contain authenticated graph and
public-claim schemas. Rows 20–33 contain query, Merkle, FRI, and arithmetic
schedules. These can be fixed **per admitted shape** only if reconstructed from
the pinned verifier and PCS profile, not accepted from a leaf or a host-authored
manifest. Row 47's descriptor constants are permitted only when the descriptor
list itself is part of that pinned shape. If a descriptor encodes a leaf value,
it moves to main with an AIR relation.

## Minimal versioned migration

1. Define `TemplateShapeV6` from verifier-owned inputs: exact native and
   wrapper PCS/interaction profiles, AIR semantic digests, full 50-row
   geometry, native verifier opcode and graph schedules, public-claim schema,
   component/infra descriptors, and six Poseidon call capacities. A shape is
   allowed to distinguish honest leaves with different geometry. A client or
   proof must not choose the template identity.
2. Build `TemplateManifestV6` from that shape. Its seal includes only fixed
   schedules and geometry. It does not inherit V2 `Manifest.seal`, native
   `Program.identity`, wire ID, statement digest, Tree0 root, source receipt,
   proof ID, or any claimed sum. Keep the V2 manifest as checked child evidence,
   not as the wrapper key. Derive a versioned VPR7 from the template seal and
   security profile, and VPK7 from VPR7 plus the independently computed
   template preprocessed root. Keep VPR6/VPK6 unchanged for diagnostics.
3. Version row 4 with a fixed-word selector: genuine padding/domain constants
   remain preprocessed and checked; all frame words that can depend on a proof
   are main. Preserve the Tree0 frame export and its exact multiplicity.
   Version row 5 with explicit fixed versus dynamic payload origins. Dynamic
   public-geometry and identity words are main, and consume typed producers
   from the executed native statement/geometry. Retain exact transcript order.
4. Select V5 row 42's main-word bridge only after every canonical ProgramV2
   index has one checked origin: fixed format/profile constants or a native
   `NPV2` producer. The existing 14 row-5 words and partial row-4 descriptor
   export do not complete this coverage. A second self-hashed table is not an
   origin. Keep LAS2's 24 externally expected words as a separate verifier-owned
   public boundary.
5. Populate all remaining preprocessed columns by calling deterministic
   template writers. Compare two distinct real leaves of the same admitted
   shape **column by column**, including padding, and require identical
   preprocessed roots. Mutating each dynamic main source must either change the
   proof/public statement consistently or fail a typed relation. Test a changed
   shape to ensure a different admitted template/key.
6. The detached verifier chooses the template from trusted admission data,
   reconstructs its root and VPK7 independently, and checks the proof against
   that key. It mixes the template commitment, child native identity, and
   verifier-owned LAS2 expectations before relation draws. It never accepts a
   child-carried key or host label as authority. Publication remains disabled
   until the complete 50-row proof, fresh verifier, global lookup closure,
   public I/O binding, and adversarial tests pass.

The reusable part of V5 is substantial: its 50-row geometry, typed router,
hash call ranges, LAS2 boundary, and main-valued row-42 bridge. The migration
primarily changes how the base verifier schedule and manifest are admitted, and
which row-4/5 values are fixed versus witness data. It must preserve the same
native verifier equations and transcript byte order; a shape-only key cannot
be obtained by simply deleting varying fields from a hash.
