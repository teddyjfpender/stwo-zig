# RISC-V CPU profiling evidence index

This index consolidates evidence without treating different proof contracts or workload identities as interchangeable. `all-runs.csv` contains27 synthetic attempts (25 successful, two retained failures) and six proving observations plus three fresh-process verification observations for actual Ethereum-derived windows. `all-stages.csv` contains2,107 stage rows, including eight explicitly derived real-window overhead residuals. Raw reports and logs remain in their original directories. `audit.json` records checked hashes, binary/compiler provenance and limitations.

| Evidence | Contract / measurement | Status | Location |
|---|---|---|---|
| Keccak8, memory4096, mixed8 | Complete synthetic original STARK; three clean samples per case | Verified; known overlapping samples retained but excluded | `../analysis/` |
| Actual native, recovery, Keccak windows | Three canonical32,768-cycle partial leaves with externally admitted endpoints | Proofs and metadata saved; fresh-process reload verified | `../../block-v7-real-window-corpus-20261029/` |
| Mixed421 | Complete synthetic original STARK;1,726,115 cycles /421 Keccak /one recovery | Verified after producer destruction; one clean sample | `../ratio-matched-421-actual-ram/` |
| Original mixed421 attempts | Event-cap rejection, then auxiliary-clock closure rejection | Both preserved as failures; no successful times inferred | `../ratio-matched-421/`, `../ratio-matched-421-policy/` |
| Shared Keccak8 and32 | Same ELF, statement, output, cycles, cuts, events, fetches, security and RAM policy as baseline | Eight matched attempts verified;8-call ABBAAB three samples each,32-call one pair | `../keccak-matched-actual-ram/` |

## Scope and timing

Synthetic cases include workload construction/execution, witnesses and source commitments, provider preparation, interactions, composition, sampled-value evaluation, DEEP/FRI, openings, serialization and independent verification. Sort/provider work is included in preparation scopes; it does not yet have a separate sorting-only timer. Stage durations are nested: sum exclusive times or use inclusive parent times, never both. Synthetic checkpoint read/write counters are explicitly zero because these runs do not use checkpoint transport. Recursion is not executed and its timing is null.

The real windows prove complete machine-state transitions between explicit endpoints, including the existing memory-Merkle argument. The skipped Ethereum prefix is replayed for input preparation and is **not authenticated by these partial proofs**. Their source-to-verified request timer includes this replay; `prepared_window_to_verified_ns` separates it. They do not prove a complete block or measure the new v7 complete-union architecture, and cannot supply a same-contract speedup comparison. Real timings are shared-host diagnostics; recovery and Keccak instrumented repeats preserve exact original proof bytes. The original native timing retains its null RSS; a distinct same-binary repeat records9,579,806,720 bytes with byte-identical proof and metadata. Real-window checkpoint I/O is0 by the in-memory code contract. Logical artifact payload reads/writes are counted in `artifact-io.csv` in the real corpus; physical disk traffic remains unmeasured. Publication writes occur after the reported verification-completion timer. Cold-verifier Python validation/decompression I/O is separately accounted outside the Zig timer.

Every synthetic success has a validated stage tree, a complete source-bound binary manifest, canonical q70/PoW26, a proof hash, allocation/RSS data, and verification after producer destruction. Synthetic proof transport is verified in process and hashed; the daily harness does not retain its binary envelope. Actual partial-leaf artifacts are retained and separately reloaded in a fresh process. Their guest sources and proof binaries are hash-pinned; an exact historical prover-source build manifest was not captured before those builds and remains an explicit provenance limitation.

Raw benchmark stdout has two conservative/legacy labels: `timing=shared_host_diagnostic` also appears in manually coordinated idle campaigns, and `exact_physical_claims=false` denotes that an additional original-oracle comparison was disabled. It does not mean proof claims were unbound. Use the retained JSON verification fields and documented timing selection, without rewriting raw logs.

## Principal measured results

| Case / boundary | Time | Allocation peak | RSS peak | Evidence quality |
|---|---:|---:|---:|---|
| Synthetic Keccak8, original small-basket request |2.355s median|308.5MB|258.3MB|Three selected idle samples; prior layout identity |
| Synthetic memory4096 request |2.145s median|400.8MB|348.6MB|Three selected idle samples |
| Synthetic mixed8 request |5.464s median|526.2MB|473.4MB|Three selected idle samples |
| Synthetic mixed421 request |113.412s|9.048GB|8.719GB|One idle sample, explicit actual-event RAM layout |
| Matched Keccak8 baseline → shared request |2.568 →1.340s|308.5 →257.4MB|258.6 →205.2MB|Three idle samples each; identical output contract |
| Matched Keccak32 baseline → shared request |4.095 →2.281s|489.9 →391.7MB|421.4 →302.3MB|One idle pair; not a latency distribution |

At421, DEEP/FRI42.974s, composition37.522s and native interaction preparation17.054s account for about86% of request time. The shared Keccak route substantially reduces DEEP/FRI but increases composition. PoW is included in primary request times and reported separately in the matched comparison, so nonce luck is not attributed to the architecture. These data do not establish a full-block latency or a10× end-to-end improvement.

Rebuild and validate this index from the retained reports (no proofs are rerun):

```sh
python3 vectors/reports/ethereum-daily-profiling-20261029/dataset-index/build_index.py
```

The indexer checks raw-log/report/artifact hashes, source-manifest identities, successful report contracts and stage containment before writing the consolidated tables. It retains different contracts and timing selection as explicit columns.

The consolidated real rows now include exact logical artifact payload I/O and three cold-verification measurements. Cold Zig input payload reads are46,894,808 /62,785,865 /68,962,267 bytes for native/recovery/Keccak respectively. These are successful file-API payload counts, not storage-device telemetry. Byte-identical native RSS repeat evidence is retained separately from the earlier observation.

The machine-readable requirement matrix is `requirements.json`. For actual-window timings, use the original corpus table rather than mixing them into the synthetic complete-proof latency model:

| Actual32,768-cycle observation | Preparation | Proving | Fresh verification | Prepared window → verified | Scope |
|---|---:|---:|---:|---:|---|
| Native RSS repeat |11.076s|26.879s|5.540s|43.726s|Explicit endpoint partial leaf; shared-host diagnostic |
| Recovery instrumented |8.594s|19.942s|3.984s|32.760s|32Keccak +6recovery; same partial contract |
| Keccak instrumented |16.545s|34.159s|6.644s|57.588s|228Keccak; same partial contract |

These partial leaves include the existing machine-memory Merkle argument and metadata of about16–17MB per window. Their cost is not directly comparable to a synthetic complete-union proof. Prefix capture and separate cold-process verification measurements remain available in `all-runs.csv`.
