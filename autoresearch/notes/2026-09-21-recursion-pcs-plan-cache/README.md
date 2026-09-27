# Authenticated PCS graph reuse checkpoint

The four-part recursion objective remains active: persistent plans and bounded
scheduling with overlap, fused PCS/DEEP components, final-layout witness generation,
and a separately reviewed parameter experiment. This checkpoint addresses only
part of immutable plan reuse.

A worker-owned two-entry cache retains deep-owned PCS graphs under exact profile
matching, including ordered column and sample layouts. Reference-counted leases
keep evicted graphs alive until their request finishes. Proof-dependent inputs,
evaluations and transcript values remain fresh. Temporary capture owners now
release their leases explicitly before arena destruction. The byte budget bounds
retained graph payload, not process peak memory or temporary construction.

## Measured scope

Apple M5 Max, 64 GiB; unchanged developmental `recursive_q193_v1` (193 queries,
16 PCS PoW bits, 10 interaction PoW bits, log blowup 1, fold step 4). This is not
the CSP 70-query profile or a production-security qualification.

The same Metal binary ran two repeated root-parent requests per process, cache
disabled versus enabled. Each arm had one excluded warmup batch, then three
off/on/on/off rounds: six measured batches per arm. Cold cache construction is
included. No build ran during the timed batches.

| Two-request process | Median seconds |
| --- | ---: |
| Cache disabled | 10.962578334 |
| Cache enabled | 10.615220667 |

The paired enabled/disabled ratio is 0.969898876 (about 3.01% improvement), with
the driver's bootstrap 95% interval [0.968996082, 0.970924832]. This local result
is a two-request batch measurement, not a single-parent or complete-tree speedup.
The enabled arm builds one graph and reuses it three times, retaining 35,197,331
bytes. Median process RSS rises from 4,393,050,112 to 4,427,735,040 bytes.
Summed child-capture time per batch falls from about 0.877 to 0.518 seconds.

All 28 comparison proofs independently verified after producer exit. Additional
qualification verified two CPU proofs, seven Metal parents with distinct keys
and fresh parent dependencies, and the legacy single-request Metal route: **38
fresh independently verified proofs**, matching qualified artifact hashes.
CPU batch time was 17.923 seconds and seven-parent Metal batch time 38.737 seconds;
these are diagnostic observations without controlled speedup claims. Tree leaves
were retained inputs. Scratch retention remains zero on this profile.

Three guarded cache tests cover matching, eviction with live leases, zero budget,
and allocation failures. Three workspace tests also pass. Both producers built
in ReleaseSafe. Source conformance still reports 103 existing failures, with no
new finding identities relative to the preceding checkpoint.

`evidence/` retains commands, provenance, logs, summaries and verifier receipts;
`sources/` captures the implementation and benchmark driver. Full proof bundles
remain under `/tmp/stwo-recursion-pcs-cache-20260921`. `manifest.json` pins this
checkpoint's files. This result confirms that graph caching alone is insufficient
for a large speedup. Authority construction, arithmetic witness size and repeated
materialization remain targets; integrating persistent workers with the bounded
scheduler and overlapping preparation/proving also remains unfinished.
