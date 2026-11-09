# Canonical source names after the version-copy sweep

Owner-directed C2 slice, tracked in #333, based on merged main `99f2e13f7`.

The merged-main census contained 512 `_vN` basenames in 510 normalized
families, plus 103 files inside versioned directories: 615 matching paths.
478 singleton filenames and four directory owners (94 further Zig files) move
to canonical names, and live source/build/test references
follow them. Their exported names, protocol versions, domains, shapes and
algorithms are unchanged. Moves receive no code-removal credit.

The remaining 43 files have live compatibility consumers or protect those
consumers. Their exact paths, package owners and reasons are listed in
`conformance/versioned-readers.json`; package contract schemas stay unchanged.
They include fixed-kind versus field-generic polynomial IR, V1/V2 segment
geometry, classic/extended truth declarations, distinct Metal lookup IR and
terminal-binding reference coverage. Removing them is a contract/reader change,
not deletion of an unused copy.

The retained count comprises 34 basename-level compatibility/coverage files
and nine finite-image LS reference files under load_store_v1. The current
LS19/RAM14 implementation takes the canonical load_store directory while
public versioned export names remain unchanged. No _partN paths were present
in this census; source partitions are not folded or brought above their ceilings. Historical evidence,
proof vectors, frozen proof bytes and formal receipts are not rewritten. Source
binding regeneration remains the explicit #328 follow-up; no candidate pin is
accepted by this mechanical change.

Acceptance uses the hosted affected CPU suites and the frozen Native CPU proof
byte-identity gate. No GPU execution or qualified timing result is claimed.
