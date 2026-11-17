# Future CPU-B2 / provider-B4 native policy: closed design audit

This is a policy/interface audit, not implementation or execution admission.
Existing uniform-profile guards are correct and remain intact. No protected
R5 source, Profile enum, native wire format or production default is changed.

## Decision scope

The selected four-member source model shows that changing ONLY the CPU verifier
shape from B4/q72 to B2/q144 leaves its complete R7 group's padded643,035,136 cells
unchanged, despite the isolated CPU wrapper growing1.949x. This motivates a
bounded candidate, not a speed guarantee. Native CPU LDE work halves as a model;
query buffers/dot terms grow. Homogeneous CPU groups/heavy shapes may cross
padding cliffs. Terminal-onlyB2 is independent and supplies no native evidence.

A minimal future receiver-pinned suite would map **all CPU workers** to existing
`op_control_b2_q144_p0_fold4_v1` and **all detached/catalog/Miller providers** to
`op_target_b4_q72_p0_fold4_v1`. The receiver's trusted option selects this mapping;
producer metadata never chooses each worker's profile. The old uniform suite
remains unchanged. Use a distinct versioned suite/domain and explicit new route,
not a generic removal of equality tests or an unchecked profile vector. Native
suite and internal/terminal outer profile are separate policy axes.

## Existing seams that must change explicitly in a future implementation

* `sponge_cpu/key.zig` already constructs/binds either nonreference profile.
  Key identity includes profile, independently derived source geometry and FIXED
  root; statement includes config through the original CPU statement. Worker PCS
  config, capture geometry, verifier expected key/config and leaf transcript all
  derive from that key. This is reusable machinery, not whole-route admission.
* `sponge_cpu/inventory.zig::Inventory.init` currently takes ONE profile and checks
  every CPU/detached/catalog/Miller key against it, generating every Expected with
  that profile. A new source-owned constructor must derive each expected profile
  from trusted kind/suite before key construction, preserve exact ordered coverage,
  first IDs, source authority and all SourceBounds/security preflights.
* `sponge_cpu/manifest.zig::validateExpected` currently enforces uniformity. A new
  typed suite validator must check the exact deterministic mapping. Manifest
  emission already includes each entry's profile, source identity, statements,
  FIXED/MAIN/local receipt, relation masks and masses. Bind the new suite/version
  and all entries BEFORE shared global challenge draws. Do not merely reinterpret
  an old digest under a new validator or reuse a local child for another scope.
* `sponge_cpu/runtime.zig` metadata, producer/source-directory loader and receiver
  currently take a single pinned profile/schema. New metadata must bind a distinct
  suite version, reject absent/unknown/downgraded policy before wide FIXED keys,
  and derive profile-specific resource estimates independently. Existing native
  fragment records remain full typed36-byte P2 roots/OM31 claims; there is no
  hash-family conversion or justification to weaken cap/EOF/canonicality checks.
* `native_group/source.zig::Stream.append` currently checks `member.profile()==
  self.profile`; `native_group/topology.zig::Group.require` and Topology also check
  every member against one profile. New grouped authority must instead bind the
  ordered source-owned member profile/key/config vector and the trusted suite.
  Keep exact ordinal/fixed-identity coverage, canonical span/tree policy and
  independently selected outer profile. A nativeB2 member does NOT implyB2 for
  an intermediate fold or let a proof select the terminal profile.
* Root metadata/header policy, source walk/template construction and fresh root
  receiver must reconstruct the same suite-specific keys/shapes, preserve complete
  RAM/KIO/Wire and terminal43B policy, and reject a valid same-output root for the
  wrong suite. No native-proof reads are needed for a succinct fresh receiver.

## Immutable keys versus proof/request custody

The CPU B2 FIXED key/root must be reconstructed under B2: identical raw FIXED
polynomials do NOT make the B4 Merkle root reusable at a different LDE height.
Existing identity(profile,geometry,root) separation is appropriate. Source ROM,
AIR recipes and raw coefficient data may be shared only where independently
identical, with checked ownership and profile-specific derived roots.

B4 provider immutable keys can be reused for unchanged provider geometry. Their
request statement/call spans and manifest remain request-specific; no source key
may incorporate producer-selected endpoint/claim authority. **All native physical
proofs must be regenerated** for the new execution manifest, including B4 truths:
MAIN roots may coincidentally match but shared challenges, interactions and
transcripts bind the new full manifest. Old CPU/truth/local proofs cannot simply
be transplanted into the new bundle. Cache identities need source/profile/geometry
and protocol flavor; pooling a cache under just worker kind is insufficient.

## Shared relations and composed assumptions

Different PCS query counts do not by themselves prevent shared OM31 RAM/KIO/Wire
closure: the same exact tuple relations, common late-bound global challenges and
source-owned per-worker masses must still close across EVERY physical proof.
No cross-shard local-GKR shortcut is introduced. Keep individual and aggregate
signed masses below M31 characteristic, current256-worker envelope and full CPU
adjacency/image/endpoints. This does not solve the independent larger-execution
hierarchy problem.

`sponge_cpu/security.zig::finish` and the underlying policy/FRI envelope currently
receive one profile. A future ledger must count each worker's actual PCS query
and FRI error term, query/transcript draws, DEEP/pole terms and hash queries, then
union local GKR/tuple/rational/late-binding terms and all recursive/terminal proofs.
Do not apply a uniformB4 check and call mixed proofs qualified. Both candidates
have nominal144 query-times-blowup FRI bits under the existing conjectured model;
this is not a composed128-bit theorem. B2 can alter code-rate/list-decoding
assumptions and opening costs even with equal nominal products. The unchanged
field entropy and P2 capacity/output assumptions still require explicit framing
and aggregate hash/FS accounting. Label remains **128-bit security target under
documented assumptions**, `security_qualified=false`, until reviewed otherwise.

## Mandatory gates before considering promotion

1. Conditional native CPU B2 proof with independent B2 key, fresh receiver and
   exact same guest/source workload; no block/root acceptance claim from fragment.
2. New source-owned suite policy and preflight, metadata/domain/transcript parity,
   key/profile/geometry/cap and wrong-suite negatives; old suite byte regressions.
3. Regenerate the complete selected mixed bundle and prove its actual R7 group;
   fresh native and native-proof-free root receivers, full global/terminal closure,
   same expected execution/output, wrong-valid-suite/root substitutions rejected.
4. Measure source/FIXED/native/recursive/end-to-end stages, CPU/pagefault/RSS and
   encoded bytes, including extra query costs; assess CPU-heavy grouping cliffs.
5. Review complete per-worker composed assumption ledger and settle whether the
   bounded measured gain justifies this extra suite. No performance promotion from
   topology alone and no new protocol implementation is part of this audit.
