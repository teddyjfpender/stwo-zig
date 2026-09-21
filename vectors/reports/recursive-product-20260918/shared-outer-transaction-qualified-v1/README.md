# Shared outer transaction, publication and continuation repair

Five implementation owners moved from CPU integration into shared recursion:

- `segment_outer_transaction_v2.zig`: complete producer/serialization/destruction/
  fresh-verifier transaction and private publication/witness mint. Backend and
  composition diagnostics are explicit integration bindings.
- `segment_outer_transaction_support_v2.zig`: alias checks, encoding and verifier
  tree assembly, with protocol channel types instead of a CPU engine dependency.
- `segment_verified_publication_v2.zig`: pointer-free publication validation and
  native identity construction.
- `segment_verified_artifact_v2.zig`: fixed witness, transcript and admission
  receipt validation.
- `binary_verified_publication.zig`: shared binary publication owner.

Existing public integration names remain aliases. The private storage and support
shims were removed; detached leaf and parent producers reference shared transaction
storage directly. Three named test wrappers remain at the integration boundary.
The transaction still publishes its capture, publication and witness together only
after successful fresh verification. No caller-selected claim/component input was
added to that boundary.

## Dependency repairs in the same batch

`canonical_proof_identity_v1.zig` owns streaming canonical identities independently
of binary publication/preparation. Its code and encoding are unchanged; the helper
now exposes the six errors it can actually return, while binary publication retains
its full error union.

`engine_protocol.zig` owns recursion hash/channel/proof types; the prover engine
reexports those same types. Child admission no longer imports proving code merely
to obtain the verifier hash suite. Native Ethereum mask orders moved unchanged into
one shared mask-layout owner used by both components and sample-layout validation.

`segment_public_wire_boundary_v2.zig` owns the boundary value, identity and primitive
validation. Cohort preparation aliases it. Publication and fixed-witness validation
now exclude prover, backend, integration and witness-generation dependencies. The
recorded two-publication source closure contains 249 files, and the maintained guard
also covers standalone proof identity, protocol and wire-geometry roots.

The source transfer audit checks 24 moved bodies, helpers, constants and masks after
explicit import/type-binding transformations. Original source and transformation
scripts are retained with this report. The 16 ownership tests pass.

## Real continuation defect repaired

The combined focused gate verified the real 39-row legacy proof and all 47 domains,
then failed at child admission with `DimensionMismatch`. Its old fixed-wire profile
contained stale sample/query literals: 2,245 samples and 6,255 queried values.

`segment_outer_wire_geometry_v2.zig` now derives these counts from the 37 typed AIR
owners, two native providers, and the core prover contract's composition split.
The expected counts are 2,287 and 6,381. Admission still checks exact equality against
the independently verified capture; shape is never selected by that capture. The
other eight geometry axes remain unchanged. The suffix shares the authoritative
profile instead of duplicating those two numeric literals.

The initial derivation omitted the default composition split and failed closed
at 2,283 / 6,369. It was corrected to use `core.verifier_types.compositionColumnCount`
and `COMPOSITION_LOG_SPLIT`. Both failure logs are retained; neither failure was
accepted as qualification. Test-only mismatch diagnostics now display both shapes.

The real proof/continuation gate passes after this repair: fresh verification,
truncated/trailing artifact rejection, publication and fixed-witness checks,
transcript replay, opaque child admission, captured FRI, recorder reconstruction,
and finalized row-18 evaluation. Its SegmentV2 closure residual is exactly zero.
The successful legacy proof has 91,749 canonical bytes and zero live tracked
producer allocations after destruction.

## Validation scope

Five source moves and related dependency repairs were batched before one focused
build. Twenty focused tests passed on that build; the failing real-proof target
was rerun alone while repairing its admission boundary. The final selected coverage
is 21 tests, plus 16 ownership checks and 24 source-transfer checks.

One final fresh CPU/Metal four-segment gate passes 384 acceptance/rejection checks.
All 21 serialized key/claim/proof artifacts match both backends and the canonical
baseline. Metal retains all 1,020 required native/leaf/parent interaction dispatches.
Binary hashes, commands, input pins, source snapshot and timings are in the JSON
summaries. The cumulative patch covers the frozen validated source; this report
and the following documentation update are outside that snapshot.

The separately saved `shared-producer-accounting-qualified-v1` checkpoint qualified
the integrated device path on the complete 16-address 1/2/4/8 ladder (1,110 checks,
78 baseline-identical artifacts). That full ladder was not repeated for this owner
move. The standalone detached gates and the legacy native-assisted transaction
remain distinct verification contracts. No production-security admission or
performance improvement is claimed here.
