# Transcript queries and dynamic Merkle directions

Task: one ordered raw query source must determine DEEP/FRI arithmetic inputs and
all lifted trace / FRI path directions. Preserve raw duplicates, lifting shifts,
folding offsets, and native masked draws. Existing field-byte encoding with a
negative output multiplicity binds a canonical DEEP query position to the masked
transcript word. Canonical binding tags map all query bits and position nodes.

Canonical match: bit decomposition plus conditional permutation in a dataflow
circuit, joined by existing LogUp multiset equality. Reference lookup mechanism:
https://eprint.iacr.org/2022/1530 (already inspected). Conditional swap is elementary:
left = current + bit*(sibling-current), right = sibling + bit*(current-sibling).
A typed byte-word selector consumes one bit and two four-byte tuples, and emits
two words. Constrain bit*(bit-enable)=0 and eight byte equations, degree two.
Reuse current hashing/framing and relation compiler; no external code copied.
Alternative host selection leaves witness-dependent fixed paths; generic QM31
arithmetic requires more conversions/wiring for the same four-byte operation.

Selected variant: constant topology, witness-selected left/right words per path
level, with eight word rows per level. Match raw bit (lifting-tree_log+level) for
trace paths; cumulative fold bits plus level for FRI groups. Build exact read
multiplicities at canonical DEEP bit nodes. All 31 bits share sources with FRI.
FRI derived positions/offsets remain private witnesses checked by its arithmetic.
O(queries*31 + total_path_depth*8) mapping/selector work and storage (derived).

Falsifier: any swapped bit, altered query word, or wrong direction passes the
constraints/tuple conservation; native joined proof fails; fixed schedules vary
with direction. Verify typed selector identity/export and mutations first, then
mapping admission and full parent proof in focused serial gates. Root/key anchors
remain intact. Query domain is admitted by existing M31-based arithmetic profiles;
do not silently widen to an unrepresentable 31-bit all-ones position. PoW nonce,
rejection schedule and production key/backend qualification remain later work.

Implementation review correction: native trace projection preserves raw bit zero;
only higher direction bits use lifting-tree_log+level. FRI uses the consecutive
shift originally described. The final mapping test compares against native PCS
projection for a nonzero lifting difference. Lifted alias sharing remains a
separate per-capture schedule obligation, not removed in this stage.
