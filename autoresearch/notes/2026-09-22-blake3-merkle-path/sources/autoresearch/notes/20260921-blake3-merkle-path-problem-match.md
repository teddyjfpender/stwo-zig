# BLAKE3 Merkle path composition

Task: extend the typed two-leaf composition to a binary authentication path.
Public statement: leaf values, expected root, index, depth. Siblings are witness
values, not public preprocessing. Canonical algorithm: bottom-up binary Merkle
fold, using low index bits to order current/sibling at each level. Reuse canonical
leaf/node frames, hash graph, byte routing and graph-derived copy multiplicities.

A sibling needs no independent preimage proof: it is an arbitrary bounded digest
whose authentication comes from reaching the public root. Add a typed private
word source with two byte-pair range requests and one wire emission, rather than
masquerading as an authenticated child hash or using disabled public constraints.

The path's index/depth are verifier-owned in this gate. Production recursion
still needs query-index binding to constrained Fiat–Shamir challenges; do not
claim a fixed-index fixture discharges that obligation. Namespace allocation is
fixed and disjoint among current hashes and sibling sources.

Validation: compare complete paths to native commitments over four leaves, cover
both direction bits and depth zero; fixed projection must not read sibling data;
malformed index/depth rejected; actual STARK with private siblings reaches native
root. Existing typed/table/proof harness is reused, not copied. No production key
or security-parameter change.
