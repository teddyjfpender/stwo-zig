# Supplemental recursive worker lifetime

The CPU publication Session owns one original setup/worker cache for each of its
seven supplemental families: RAM lanes, range16, ROM, native lookup, caller
arithmetic, caller fused, and native capacity fused. Workers start lazily and
borrow the driver's bounded helper pool. Family callbacks are serial within a
family; independent families retain separate typed caches. All live allocations
remain charged through the original aggregate driver allocator. Per-worker caps
do not reserve that many bytes eagerly or increase the aggregate heap limit.

The shared cache's consuming preflight API executes on its existing joined
request lane. It first acquires the genuine original worker and admission,
checks an independently required key where supplied, then notifies the source
owner before proving. Callback failure skips proving. The cache still verifies
the exact fixed-row digest, row geometry, public routing and current public
values on every hit. Dynamic admissions are rebound for every instance.

RAM/range retain their proof-independent fixed-policy factories and expected
metadata caches. The other five families derive their setup from the genuine
fresh original verifier rows. Worker reuse does not turn that derivation into a
proof-independent factory. The independent supplemental receiver still verifies
original proofs and reconstructs its own expectations.

Family stages share a producer-lifetime helper for proving and encoding. Cold
plans and workspaces end before encoding/fresh receive; capture storage ends
after its final original witness consumer where retained receipt/claim storage
is independently owned. Stages retain their original producer fixed-root
admission, distinct fresh recursive verification and typed artifact publication.

The driver joins family and forest jobs before Session destruction. Every
request lane joins before cache/source metadata or the borrowed driver pool can
die. Failure publication rollback remains allocation-free and uses only actual
successful writer pins. Cache creation publishes each optional owner only after
successful construction, so partial initialization unwinds through the same
Session destructor.

The CPU result records each family's actual setup hit/miss counters, request
thread starts/completions, retained entry, and the cache allocator's live/peak
bytes after joined work. These counters distinguish real setup reuse from an
option merely being enabled. Cache peaks are scoped allocator measurements;
they are not process RSS and must not be summed as a concurrent peak.

Focused metadata, failure-lifetime and retained-production-body qualification is
separate from genuine warm-cache proof acceptance, complete recursive closure,
peak memory and end-to-end speed. No proof, segment or GPU run is authorized by
these source changes.

The persistent specialization retains only by-value template key and fixed
metadata while idle. Constructor setup releases its initial admission borrow;
every lease return clears the current admission before unlocking. Warm fixed
checks validate the supplied current admission, never earlier public arrays.
Default producer/worker borrowing APIs share the same kernels and fixed guards.

The cohesive Debug gate passes41/41 with2189 unchanged source pins, including
partial allocation failure, current admission custody, all original fixed-row
guards and retained actual driver/receiver/CLI bodies. Exact receipt:
`autoresearch/notes/2026-09-24-ethereum-block-delivery/cpu-performance-gates-v1/cpu-performance-assembly-qualified-v1.json`.
The CLI records whether supplemental workers were selected. Cache-hit proof
acceptance, measured setup savings and complete block performance remain open.
