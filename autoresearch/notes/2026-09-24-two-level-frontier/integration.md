# Native integration still required

1. Before each trace/FRI tree, derive a private frontier witness from its verified
   capture. Hash lower leaf groups and path prefixes natively to recover the ordered
   penultimate input pair for the first query in each top-bit branch. An unqueried
   branch uses an opaque top sibling digest and arbitrary dummy preimages. Native
   consistency checks are supplementary; never omit the typed query equalities.

2. Reserve the frontier's seven node/control namespaces plus one query selection
   namespace per query independently of positions. Retain existing per-opening span
   reservation. Use the frontier for depth >= 2 and at least two queries; keep root-only
   sharing for depth 1 and existing handling for other shapes.

3. Extend group emission to stop before its last two hashes. Keep the penultimate
   authenticated bit-select that produces the ordered preimages. Its two output words
   each have one consumer, the frontier query equality. Append the frontier's 17
   query selectors and 17 equality rows. Do not also append the old per-query root
   equality: the frontier already supplies all query-count root equalities. A native
   recomputation may preserve the early malformed-witness check against the capture root.

4. Feed 17 high-bit uses instead of the old eight into query-link accounting, matching
   the exact mapped raw-bit endpoint (lifted trace parity handling must remain intact).
   Existing rollback of query use counts on preparation failure must remain atomic.
   Do not change lower-bit use counts or DEEP/FRI scalar consumers.

5. Add three node hashes per tree to preallocation and remove two per opening. Ensure
   direct main-column emission and independent trusted fixed metadata agree. The
   primitive currently owns full rows for its three small hashes; integrate with the
   canonical final-column views before relying on production memory measurements.
   Trusted fixed schedules must be independent of activity and query positions;
   deriving them from a dummy witness must not trust live G/XOR metadata.

6. Preserve root admission, disjoint namespaces, owned-buffer cleanup and typed
   roster/key binding. Update the remaining-sharing census to subtract all already
   implemented sharing. Test both FRI group widths and lifted trace paths, including
   a tree whose queries all choose one top branch.

7. Run focused constraint/lookup tests and the actual canonical four-leaf tree at
   q70/PoW26. Then compare frozen executables with matched parameters and allocator,
   recording the complete fixture, each preparation/proof phase, per-cohort domains,
   independent artifact verification, next-level sizes and process/routed memory.
   Retain only on net evidence; the G-only projection is not acceptance evidence.
