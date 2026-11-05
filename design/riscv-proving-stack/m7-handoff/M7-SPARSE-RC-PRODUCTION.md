# Sparse Keccak RC: production proof qualification

**Measured and qualified:** both development blocks complete cold and warm at the22GiB arena, under BOTH the M6 native profile and D2+truth coalescing. All8 requests match every accepted native binary, bundle, recursive node proof and tree byte. Four fresh CPU receiver processes accept (one per block/profile; warm artifacts are byte-identical). This is a capacity/correctness result. Global admission and two lanes remain OFF.

| Profile | Block | Cold request seconds (measured) | Warm request seconds (measured) | Whole-artifact byte parity | Fresh CPU |
|---|---:|---:|---:|---|---|
| D2+coalescing |26235156|24.836|10.506|2/2|accepted|
| D2+coalescing |24628607|30.332|12.290|2/2|accepted|
| M6 |26235156|23.330|11.499|2/2|accepted|
| M6 |24628607|33.944|15.325|2/2|accepted|

All runs had load averages above the quiet protocol threshold. These timing samples establish no robust latency gain. Headline D2 warm native proving is4.658s and recursion5.251s. Sparse native Keccak combined LDE+row work is included in its rows span; full native RC measured536.640GPU-ms, compared with the earlier accepted D2 diagnostic461.506GPU-ms. This is the measured memory/time trade, with no new wall A/B claim.

Source23c7b1db8 is pinned by the exact driver source hashes in `receipts/device-service/sparse-rc/driver-build.json`. Driver SHA `bb888e6e00b53c4b258a8cd3632d91bf6eb38edbc9dc76fc4456a9ac5554656f`, frozen a25 base, sparse addon SHA `e66ab0cfa50e4869351de87a1081792ce1d3385ce44f79ff1f4b3debc06cb278`. All sparse calls use original Keccak source18/eval20 geometry, one selected role per request; smaller roles use the existing implementation. No source19 qualification is inferred.

The source-bound selected role replaces its14,750,402,976-byte arena with4,294,967,296 cache bytes plus3,913,880 scratch bytes; its33,554,432-byte bucket remains caller-owned. This does not describe the whole request's peak. The actual static arena physical highwater is23,622,320,128bytes. Native source coefficients, all other roles, PCS, recursion and fixed driver/module resources remain charged separately.

**Whole-process28GB gate remains open.** The observational preload run for small M6 measured terminal occupation27,903,983,616/27,906,080,768bytes from cudaMemGetInfo, with default pool UsedMemHigh and ReservedMemHigh both0. Terminal occupation is not a transient highwater. The joined-stage observer and explicit default-pool highwater API are independently checked separately; a new activation build must reconcile all phases and fixed driver/module reservation before claiming the strict process bound.

An earlier small M6 observer trial failed during warm publication with `NoSpaceLeft`; its original producer logs and partial run are preserved. It is excluded from the8 passing requests. After guarded cache pruning, an exact retry passed. Lossless hardlink dedup of237 already-qualified proof files, each with full SHA and size equality to its pinned control, recovered519,172,096bytes while retaining every path and proof byte.

A subsequent source-only hardening checkpoint adds checked scratch/cache retirement, single-owner bucket transfer even when clear fails, the exact sparse cost variant and beta2 separate-coefficient cost correction. Its semantic/CPU/observer gates do not retroactively qualify a different driver binary; the next integrated activation build still needs its proof gates.
