# Snapshot-derived BLAKE3 memory openings

The shared sparse byte-tree traversal now optionally observes computed child
roots. TreeHasher.opening uses it to derive a root and one 30-sibling opening
without a second hash traversal, heap allocation or full node trace. Empty
subtrees use cached defaults. Input validation is shared with root construction.
Legacy callers retain the same root traversal with no observer.

The focused ReleaseSafe statement-codec gate passed in 34 seconds (1 GB reported
peak RSS). Checks cover present, absent, explicit-zero and boundary addresses in
a multi-branch sparse snapshot, independent path reconstruction, sibling changes,
empty snapshots and invalid input. The full memory-path STARK fixture now derives
siblings from a three-entry snapshot rather than hand-constructing all defaults.
Its proof gate passed in 26 seconds build/run and rejects a changed root claim.

Proof settings remain diagnostic 8 queries/0 PoW; the source byte is a public
fixture. This does not authenticate a runner-owned retained snapshot or prove
memory transitions. Those integrations, full-width production continuation
claims, key/artifact admission and multi-level recursion remain outstanding.
