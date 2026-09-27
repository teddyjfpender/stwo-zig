# Canonical query-to-path admission

Task: derive exact Merkle path positions from authenticated raw query outputs.
Reuse core.queries.Queries.init and fold, which sort/deduplicate then shift/fold
and deduplicate. Retain a raw-position-to-unique-path map found by binary search.
Validate raw domain bounds and folding width before native normalization. Admit
only an exact ordered path list; no missing, extra, duplicate or reordered paths.
Complexity: native O(n log n) normalization plus O(n log u) mapping, u unique paths.

The raw queries are public auxiliary statement coordinates in current proof
gates and are independently constrained by draw hashing. Thus trusted preprocessing
can deterministically derive path indices from those same coordinates; a private
sorting AIR is not required for this public-coordinate integration. Do not claim
this solves private query-index representation or lifted PCS geometry.

Gate: mapping parity/boundaries/fault injection; combined raw-query and private
sibling Merkle proof, sharing one trusted raw list. Wrong path lists fail admission
and wrong roots fail trusted preprocessing. Use existing typed components, no new
AIR or table. Folded mapping unit coverage does not establish a full FRI opening.
