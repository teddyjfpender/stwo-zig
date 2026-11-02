# Full Word16 genesis-prefix qualification

The new concrete path proves all 4,194,303 instructions in round5 packet0 and passes a fresh-process receiver. It consumes the accepted CompactTape directly, with one transient retirement per row and no VM replay or batch Retirement array. The independently pinned pristine image supplies INIT authority. All 17 independently sized CPU, ROM, arithmetic, memory and table roles share one PCS/FRI proof and one reusable program/geometry fixed commitment.

The final observation took 17.73 s with 12.255 GB maximum RSS; the paired retained legacy worker took 29.31 s with 33.776 GB. These are sequential observations, not a statistical benchmark or a whole-block prediction. All 32 initial/final register values and clocks, both PCs, and every one of 708,957 RAM word boundaries/clocks/rights match the retained baseline exactly. Its historical proof bytes remain unchanged. The new protocol intentionally has different proof bytes.

The STARK is 1,142,752 bytes. Its public RAM sidecar is 32,612,038 bytes and statement JSON 11,868 bytes, making 33,766,658 bytes in total. The new path exposes these boundaries; it does not replace the legacy protocol's privacy properties.

CPU and the other cubic/quadratic chips evaluate constraints on 2n. Existing DIV/MUL retain 4n. The integration uses the existing weighted-quotient q1→q2 extension for every q1 role before common four-part composition. This adds quotient-vector work; it does not evaluate every CPU source column on 4n. The report distinguishes native evaluation domains from composition contribution bounds. FFT execution and sampled-value counts were not separately extracted.

The largest measured stages are interaction generation 3.924 s, composition 3.014 s, source construction 2.228 s, main commitment 1.697 s and interaction commitment 1.725 s. Further work should follow those measurements and account for mandatory padded provider rows and public boundary transport. Fixed-key reuse is implemented; exact capacities still determine distinct immutable geometry keys.

Safe/Fast qualification covers native 16, circuit 4, source 6, SHIFT 7, coordinator 17, memory 8 and separate global-memory prototype 4 runtime tests. The coordinator includes an actual joined proof, independently rebuilt receiver, all-role native residual audit, five actual false-prover attempts after native admission, and balanced-claim/final-PC rejection. A full 4096-window regression fixes an inferred-width scratch-allocation overflow first exposed by the real packet.

This is a genesis-prefix proof with zero ECALLs. Service closure, cross-batch/global memory acceptance, terminal output/halt certification, whole-block proofs, recursive aggregation and GPU execution are not activated by this milestone. The separate global-boundary prototype is not a full execution receiver. See [real-packet0-v1.json](real-packet0-v1.json) for exact pins, stage observations, proof/public bytes, limits and qualification logs.

## Subsequent qualified slices

| Observation | Instructions | Process wall | Peak RSS |
| --- | ---: | ---: | ---: |
| Paired legacy batch 0 | 4,194,303 | 29.31 s | 33.78 GB |
| Joined Word16, parallel CPU/LS/boundaries | 4,194,303 | 15.03 s | 11.60 GB |
| Independent-boundary global RAM harness | 8,388,606 | 31.62 s | 15.51 GB |

The single-batch pipeline, including native witness preparation and excluding
separately measured immutable setup, is 13.622 s. Scheduling and boundary changes
preserve the exact V4 proof SHA `46d18eef8e69bea3839e832b3828d7050fbd0dd8cdc2b26b34af59fa3b8b407c`.
The observations are not statistical or whole-block speed estimates.

The separate global protocol now fresh-verifies two real CPU shards, one
initialization and one teardown, closing all shared RAM obligations after
physical verification. All 712,789 RAM words and CPU states match the accepted
legacy prefix. Its independent attack gate proves locally valid false-reset
fragments and rejects them at global closure. It remains a no-services execution
prefix: no terminal/halt certificate, complete block, recursion or GPU claim.

Owned stage-one workers release MAIN after sealing and accept the complete
manifest before deriving RAM challenges. The convenience harness remains
centralized; production multi-process scheduling and narrow streaming advice
transport remain work. Optional independent INIT/TEARDOWN geometry preserves
old default fixed roots and removes 155,184,512 padded fixed/main/interaction
cells in the two-shard case. Global wireV2 streams public cells separately;
converting the old real artifact preserves both original proofs exactly and
reduces JSON 304,297,459→31,079 bytes, with 32,788,310 bytes of RAM sidecar.

See the per-slice receipts for source pins, security parameters, tests and
limitations. q70/P26 is the retained nominal configuration; a whole-protocol
security claim requires a separate lookup-degree/mass and union-bound budget.

## Combined-prefix BINARY, owned MAIN, and native page preparation

`binary-merged-prefix-v2.json` qualifies BINARY 28→24 interaction columns,
52→50 constraints, with one combined prefix, strict inverses and degree three.
The encoding identity changes explicitly. `owned-main-v1.json` qualifies direct
transfer of original MAIN allocations to PCS, preserving exact proof bytes
against borrowed streaming; only small AND/SHIFT multiplicity copies remain.

`interaction-pages-v1.json` is a same-binary OFF/ON/ON/OFF comparison on the real
packet. Before bit-reversed parallel stores, one word per output OS page is
written synchronously. Workers subsequently write every actual output value.
The page preparation leaves proof bytes identical and adds no retained cache.

| Page preparation | Whole-process wall | Interaction generation | Interaction system CPU |
|---|---:|---:|---:|
| Disabled, two runs | 15.28–15.76 s | 2.290–2.359 s | 16.230–16.854 s |
| Enabled, two runs | 14.09–14.14 s | 1.399–1.420 s | 0.087–0.088 s |

Peak RSS is about 11.55 GB. All four proofs have SHA256
`7b9f5ffa28e601599e4d69644c6d174683b4960876196b6671de381e0d16acc8`;
fresh independent receivers accepted both arms. Architectural state and every
public initial/terminal RAM byte agree with the earlier qualified layout.
These two samples per arm establish the mechanism on this host, not p50/p99,
other-host NUMA performance or a whole-block projection. Set
`STWO_RV64_DISABLE_INTERACTION_PAGE_PREPARATION=1` for the operational control.
