# Direct selected Merkle witness rows

Task: preserve exact selected-lane trace/FRI Merkle logical rows and all admission
checks while removing padded column staging and the subsequent transpose/copy.
Model: streaming materialization and loop fusion, an exact change of output sink.
Input provenance: current detached parent buildRows allocates MAIN_COLUMN_COUNT *
2^log_size columns for four Merkle components, then selects one of three lanes.
Existing stateful hashing and packed-subtree ordering must remain unchanged.

Candidates: retain full padded columns (current oracle); emit dense selected logical
rows (chosen intermediate toward final-layout generation); write directly into final
cohort columns (ultimate target, requires changing cohort ownership/interaction reads).
The selected transformation removes O(columns * padded height) initialization and
staging storage, retaining O(selected logical rows) output. It does not remove the
later cohort copy, final transpose or immutable authority construction.

Transfer: shared row emitter with column and compact logical sinks; no alternative
hash implementation. This applies the witness-traffic reduction identified in the
source-pinned architecture comparison, including StarkWare canonical column pools
and zkDTVM fused/local verification components. No external code copied.

Correctness: bulk reference/schedule/witness validation before allocation/emission;
logical outputs are fresh allocations with no borrowed mutable aliases; inactive
rows retain canonical zeros, parameters and metadata. Keep full-column generation
as an oracle and compare both selected lanes, every logical row, provider input and
output. Independently verify fresh CPU/Metal proofs and require byte identity.

Prediction/hypothesis: less row-generation staging time and peak memory. No projected
full-parent multiplier without measurement. Falsifier: divergent rows, changed proof
bytes, rejection behavior, memory regressions or no measured process improvement.
The four-part goal remains active; this is not completion of final-layout generation
or fused PCS/DEEP verification components.
