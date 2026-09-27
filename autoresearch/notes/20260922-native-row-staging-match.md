# Eliminate padded logical-row staging in the native producer

Task: reuse owned canonical prepared rows directly while projecting committed
columns and generating interactions. This is removal of redundant materialization,
not a new algorithm or changed witness equation.

Evidence: blake3_native_parent_producer.proveWithWorkspace allocates/copies one
power-of-two Air.Row array per component and rewrites proof selectors. The original
prepared inverse/linear rows already contain the canonical segment selectors, which
validateRows compares against trusted fixed metadata. row_columns.project allocates
zero-filled final columns and writes only supplied rows. framework_interaction uses
paddingPairs for omitted rows (zero numerators), so omitted logical rows have inert
interactions without allocating their full width.

Selected transfer: borrow prepared.rows during the synchronous call, eliminate
padded copies and selector rewriting, project/register/generate from those slices.
Preserve the owned input lifetime and independent output allocation. The caller
must keep prepared alive, as already documented. Full native proof, codec,
independent verification and worker lifetime gate must pass. Compare tracked worker
peak and proof bytes; no timing-speedup claim without controlled measurement.

This removes one staging layer; it does not complete direct witness generation
from adapters into committed column layout or remove canonical prepared row storage.
