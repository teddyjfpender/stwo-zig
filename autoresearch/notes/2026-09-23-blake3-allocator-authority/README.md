# BLAKE3 allocator ownership admission

Status: focused ReleaseSafe allocator regression passed; checked-allocator canonical Metal retry failed at interaction commitment.

Zig 0.15.2 defines the SMP and page allocators with undefined context pointers.
The parent row-transfer admission compared allocator context pointers. Reading
these contexts is undefined behavior. The first failed Metal binary omitted
row assembly between preparation-state initialization and cleanup, consistent
with this defect; no successful fixed stateless-allocator parent run is claimed.

Row transfer now takes its allocation authority directly from the transferred
hash-column owner. Both preparation paths use this interface. The scratch-alias
guard compares the known arena vtable before reading its context. A focused
regression covers SMP/page allocators, malformed metadata rejection, and same
versus different arena identities. It passed its focused ReleaseSafe build/run (10 seconds, 840 MiB build MaxRSS).

The checked-allocator Metal retry predates these fixes and cannot validate them.
A live sample at 09:51 local time shows that retry past row preparation and key
admission, inside parent lookup registration. Its sampled physical footprint was
15.3 GiB, with a 25.1 GiB process peak so far. These were partial-run observations. The completed retry failed with
`ParentWorkerHostBudgetExceeded` in `interaction_commitment`, at 36,176,603,674
tracked peak live bytes against a 38,654,705,664-byte limit. The refused
allocation was not included in the peak. The leaf again verified on CPU with
162 Metal dispatches and 3 fallbacks. Canonical parent qualification is open.
