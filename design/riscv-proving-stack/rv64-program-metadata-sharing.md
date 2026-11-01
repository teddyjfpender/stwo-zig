# Owned Program metadata sharing

This opt-in cache shares decoded immutable entries and ROM edge maps across
request geometries. It changes no AIR, transcript, column order, PCS Suite or
proof schema. Existing constructors, including the fixed-native-cache APIs,
keep their signatures and behavior. `ImmutableCaches` adds independent optional
native-coefficient and Program-metadata owners; no process-global cache is used.

A cache node owns only `entries`, `word_rows`, `row_to_entry` and `row_taken`.
It never retains the expected image's raw words or address arrays. Every Program
view borrows those arrays from its current independently derived authority, which
must outlive that view. The original authority can be destroyed after its Program
is destroyed while the metadata node remains reusable by another authority.

Prelookup compares every raw instruction and full64 address, the execution
profile and feature identity. It does not trust request counts, a producer digest
or an executed-PC subset. First adoption independently checks decoded entries,
edge maps, opcode mask, geometry and canonical Program identity before transferring
ownership. Cache nodes retain their actual origin allocator and managed-budget
lease. All fallible allocation and validation precedes transfer; concurrent losers
free their private arrays exactly once. Immutable Program views and the manager
hold explicit ARC leases. Capacity misses keep ordinary private ownership.

Fixed ROM matrices are still constructed from the same entry authority for every
geometry. Fixed interpolation, LDE and Merkle construction are unchanged. The
cache avoids repeated metadata construction after the first hit; these receipts
do not establish a controlled setup-time improvement. Original fixed retirement
and native coefficient sharing remain separate operations.

The focused suite has 13 actual runtime tests (11 named metadata cases, the root
and one imported arithmetic-bus control). Safe/Fast gates cover full64 sparse PCs,
invalid words and padding, changed raw/address/profile/digest misses, malformed
maps/decoded semantics, disabled/capacity modes, concurrent publication, forced
duplicate adoption, all Program allocation failures, cache-hit allocation retry,
SMP/mixed allocators and source-budget lifetime. Complete q70 F1/F4 proof bytes
and claims equal uncached controls, and fresh retired-fixed receivers accept.
The existing 14-test fixed-native-cache suite also passes on the joined source.

The same-binary key-only audit reconstructs all 25 CPU setups and five truth
instances from the pinned pristine Image. All 30 fixed roots match the retained
accepted block. It performs no VM execution, Tape reading, CPU MAIN construction
or new full-block proving. Both runs enable the 256-MiB native cache and retire
original fixed witnesses after constructing the inventory. The candidate adds
a 64-MiB metadata cache. The audit rejects an enabled cache with no payload or
useful hits.

| Requested retained payload | Native cache only | Native + metadata |
|---|---:|---:|
| Program metadata | 773,785,350 B | 30,951,414 B |
| Native coefficients, including private truths | 291,137,920 B | 291,137,920 B |
| All audited setup allocations | 2,275,890,654 B | 1,533,057,070 B |

One owned program has 540,147 raw words and 572,754 ROM edge rows. Its 24 prelookup
hits avoid rebuilding 742,833,936 metadata bytes. Cache control allocations add
352 bytes, giving a net retained reduction of 742,833,584 bytes. Native cache
statistics and all fixed roots are unchanged.

Key-only maximum RSS observations were 8,999,632,896 B and 8,157,478,912 B. These
runs overlapped engineering work; they are neither controlled timings nor
full-block peak measurements. The tool source is CPU47/LS71 based on `87df8e6a5`;
the retained block was originally proved with CPU50 source `f4f9cc5ab`. Matching
fixed roots does not claim proof compatibility across those CPU layouts. The
q70 byte comparisons use matched current-source cached/uncached controls.

Exact source, tool, input, gate and audit pins are recorded in
`vectors/reports/rv64-word16-execution-20261101/program-metadata-sharing-v1.json`.
