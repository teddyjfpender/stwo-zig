# Compact range-provider implementation contract

This is an unimplemented architecture experiment. Production still uses full
fixed tables. Demand counts are field-nonzero signed multiplicities, not raw
request counts; the existing shared lookup census is the authority.

Use one typed provider for each of range20, range8/11, and range8/8/4. Preserve
the original relation domains. Each provider row emits the original tuple with
negative multiplicity and requests range8/8 membership for two byte limbs.
The current relation registry declares these domains request-only: use the
existing signed-request convention, not an unregistered emit role. Reconstructed
values must satisfy the typed uint20/uint11/uint4 interface through reviewed
typed lowering; field arithmetic alone is not a type or range proof.
Constrain high limbs with boolean equations; reconstruct original tuple values
inside the AIR rather than storing redundant tuple columns.

| Relation | Witness besides multiplicity | Reconstructed original tuple |
| --- | --- | --- |
| range20 | a, b, four bits c0..c3 | a + 256*b + 65536*sum(2^i*ci) |
| range8/11 | a, b, three bits c0..c2 | (a, b + 256*sum(2^i*ci)) |
| range8/8/4 | a, b, four bits c0..c3 | (a, b, sum(2^i*ci)) |

Enforce ci*(ci-1)=0 and range8/8(a,b) on every padded row, independent of its
multiplicity. Zero padding has zero multiplicity and zero limbs; its byte
lookup still contributes one request, so register the entire padded provider
height into the byte-table census. This avoids unconstrained padding or a
selector multiplication on every bit constraint. The original signed
multiplicity is a base-field value, preserving the existing table convention.

No sorting/uniqueness premise is needed for range membership: every row proves
its tuple is in the original range, and the original relation balances the
sum of multiplicities. The honest generator can nevertheless scan canonical
counter order to produce deterministic unique rows. Soundness still requires
an explicit bound on relation terms and the same collision analysis used by
admission; do not copy old full-table bounds without deriving the new counts.

Implementation order:

1. Add canonical typed definitions, semantic identities, and direct final-layout
   generation for the three providers. Test every boundary and malformed limb,
   nonboolean high bit, tuple reconstruction, signed multiplicity, and padding.
2. Integrate the providers into shared native component assembly, source
   bindings, statement geometry, column plans, lookup census, and extension
   term admission. Prover and verifier derive one roster from authenticated
   descriptors. No workload-name switches.
3. Version and bind the new geometry in transcripts, keys, manifests/codecs,
   prepared verifiers, and recursive captures. Old keys must fail admission.
4. Qualify base/extension proofs, fresh CPU/Metal verification, and native parent
   plus parent-of-parent proofs. Compare canonical CSP results with source-pinned
   binaries. Do not weaken 70-query/26-bit parameters.

A geometry threshold for dense workloads needs evidence and must be an
admitted protocol choice, not a hidden prover-only branch. Smaller tables can
have more columns or a larger per-row constraint degree. Cost and recursive
verification geometry must be measured, not inferred from raw row reduction.
The small bitwise and byte providers remain necessary; deleting large range
tables alone does not remove their domain floor or large-workload G domains.
