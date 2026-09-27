# Emit frame G/XOR witnesses into their Merkle group destination

Task: remove per-frame G/XOR staging followed by group concatenation. A group has
leaf_count leaf frames and leaf_count-1+depth node frames in canonical order.
Canonical hash plans determine exact row counts from the two encoded lengths.

Transfer: preallocate checked final G/XOR slices once, lend exact nonoverlapping
ranges to each frame, and update XOR output multiplicities in those final ranges.
Frames retain ownership of their smaller boundary/routing metadata; borrowed hash
rows belong to the group. Both live and independently constructed fixed rows use
the destination API. Shared fixed-row writer preserves original equations.

This is exact-size destination allocation and concatenation elimination, not a
new hash or traversal algorithm. Existing node order, namespace checks, input
validation, root linking, payload use counts and boundary filtering remain.
Preallocation avoids invalidating node slices when later frames append. All size
arithmetic is checked and destination geometry is admitted before hash writes.

Prediction: eliminate the group's duplicate G/XOR buffers and their arena growth.
Actual preparation peak may instead be dominated by another adapter. No timing
claim without a dedicated comparison. This still emits logical rows at the group
boundary; final native columns and transcript emission are subsequent work.

Validation: borrowed/owned live and fixed frame parity, invalid destination
unchanged before writing, borrowed buffers surviving receipt destruction,
allocation failures; native independent parent proof and recorded memory metrics.

First qualification: group/native proofs pass, but routed preparation peak rises
600,657,997 -> 622,506,697 bytes. Final slabs and nested frame allocations still
share the enclosing group arena; freeing plans does not necessarily return them.
Follow-up: frame receipts allocate from the ordinary bounded backing allocator,
while borrowing group-owned G/XOR ranges. Group explicitly destroys every appended
receipt, and each not-yet-appended receipt has error cleanup. Smaller boundary and
route rows are copied before receipt destruction; only inline digest/use data and
borrowed final hash rows survive. This separates transient plan/receipt lifetime
from final group storage. Measure again rather than infer a peak improvement.
