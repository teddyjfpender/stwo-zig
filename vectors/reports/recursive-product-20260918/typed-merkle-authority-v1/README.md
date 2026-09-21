# Typed native Merkle admission, 2026-09-18

Added an independent typed definition for the native sparse-Merkle provider's ten
main columns, seven direct roots and five ordered Merkle/Poseidon lookup events.
It does not import the executable specialization. VM AIR profile derivation now
admits the executable against that definition for Merkle components, for both
native capture and cold verifier reconstruction. The check covers every direct
root, all three LogUp recurrences, ordered lookup metadata/numerators/tuples, and
the three additional external-provider zero-multiplicity constraints. Existing
protocol geometry, ordered identities and pinned keys are unchanged.

Shared cold polynomial replay and symbolic relation construction were extracted
from compact-Poseidon admission. Compact Poseidon uses those same helpers, avoiding
parallel copies. Symbolic admission now has an explicit recoverable allocation
mode: scalar operations latch failure, and admission checks it before consuming
the recorded DAG. Default tooling behavior remains unchanged. The Merkle admission
allocation-failure sweep verifies cleanup and rejection across allocation sites.

Focused validation:

- `test-merkle-authority`: 150 passed, one skipped, including seven specialization
  mutations, arbitrary extension-field rows, degree and allocation failure.
- `test-compact-poseidon-authority`: 127 passed; its canonical identity is unchanged.
- `test-vm-air-profile-v2`: 21 passed, exercising the profile hook.
- 36 product/source checks and both test-inventory checks passed.

Counts include imported tests and overlap between targets; they are not unique
Merkle-only test counts. The new focused target has four purpose-built tests.
Fresh CPU/Metal/AOT four-segment products passed 384 checks. All 21 canonical
artifacts remained baseline-identical, and both products used the same frozen
source snapshot. The complete-product summaries record commands and evidence.

This closes Merkle's typed equation admission on the canonical recursive ingress.
It does not certify every native infrastructure component or production security.
The adjacent registry inventory identifies the next group: program, memory and
clock definitions/admission, plus the existing wide-Poseidon and table-schema
authority audit. Final useful 1/2/4/8 continuation qualification follows the
remaining authority cleanup. Speed work remains deferred.
