# Fewer native leaves and D2/D3 cost census

Status: source/receipt arithmetic [D] and proposed layout estimates [E]. No new-format proof or performance qualification. Inputs are the accepted cap128/M6-byte-identical cold proof pairs for blocks 26235156 and 24628607. The complete source-generated tables and exact source/input hashes are in `model.json`.

| Block | Layout | Native leaves | MAIN + INTER cells | Largest native-GKR RC plane |
|---|---|---:|---:|---:|
| 26235156 | [D] M6 geometry + native GKR | 11 | 2.436 billion | 8.309 GB |
| 26235156 | [D, unproved] One truth per family + native GKR | 9 | 2.823 billion | 16.618 GB |
| 26235156 | [E] CPU23 compact extension + truth1 | 7 | 2.736 billion | 16.618 GB |
| 26235156 | [E] CPU23 wide47 + truth1 | 7 | 2.904 billion | 16.618 GB |
| 26235156 | [E] CPU24 compact extension + truth1 | 6 | 2.786 billion | 16.618 GB |
| 24628607 | [D] M6 geometry + native GKR | 17 | 3.606 billion | 8.309 GB |
| 24628607 | [D, unproved] One truth per family + native GKR | 12 | 3.775 billion | 16.618 GB |
| 24628607 | [E] CPU23 compact extension + truth1 | 9 | 3.758 billion | 16.618 GB |
| 24628607 | [E] CPU23 wide47 + truth1 | 9 | 4.030 billion | 16.618 GB |
| 24628607 | [E] CPU24 compact extension + truth1 | 7 | 4.048 billion | 16.618 GB |

The RC plane is one expanded source plane, before retained coefficients, bucket/FFT buffers, cache charge and allocator rounding. It is a lower bound on stage memory, not peak memory. The proposed CPU counts coalesce adjacent old segments. Public LS/D64/service counts choose minimal source-valid head/tail capacities; unavailable private ALU/BINARY/SHIFT event counts use the sum of old usable capacities. Those CPU layouts require a fresh capture, source authority and receiver classes.

The five active truth families are Keccak, add, double, SHA256 and arith256. One proof per family changes truth leaves 7→5 and 10→5. Both blocks require one r27 Keccak log-19 trace. Permutation rows grow from 286720→524288 and 409600→524288; the repeated chi/xor tables shrink from three copies to one. Consequently, merging truth proofs increases own-height MAIN/classic-INTER volume by 23.7% / 8.8%, despite fewer proofs.

Memory admission is the limiting gate. Merged Keccak has exact FIXED/MAIN/classic-INTER widths 32/1923/1560. Its classic RC plane at log19 is 29,494,345,728 bytes. Native GKR reduces this plane to 16,617,832,448 bytes (16 INTER + 10 auxiliary columns), but the current full product-tree GKR workspace is 19,541,918,976 bytes; adding decoded source and its own committed MAIN already exceeds 27.7 GB. No other proofs need be live to violate a 22 GiB arena. The streamed/chunk frontier and global planner are prerequisites.

CPU23 is a supported classic wide-clock geometry only with fused tail and without byte pairs, so its current MAIN is 47 columns rather than compact37. The authenticated GKR source scope and typed CPU policy currently stop at 22. CPU24 exceeds `MAX_LOG=23`; its register-gap high limb needs 10 bits, so the current wide scale128 is insufficient (a scale64 variant needs fresh equations/query authority). The compact37 extension columns are a design estimate, not an existing class. Current full-tree CPU24 GKR workspaces are 28.6–31.4 GB before decoded sources.

The 4-ary fold count used by the observed inventories is ceil((leaves−1)/3). CPU23 + truth1 yields 7/9 native leaves and 9/12 outer nodes, so the headline block still misses ten nodes. CPU24 yields 6/7 leaves and 8/9 nodes, but its source and memory gates are open. A separate candidate is two authenticated CPU proofs per typed recursion leaf: the headline CPU23 physical inventory remains9 proofs but uses7 leaves/9nodes. That needs a new multi-verifier leaf and measured cell/admission gates.

D2/D3 comparison on the same proposed compact23 + truth1 geometry:

| Block | Profile | Four-tree LDE cell work volume | Trace-leaf query-word proxy |
|---|---|---:|---:|
| 26235156 | [E] M6_b2_q108 | 6.409 billion | 2,382,264 |
| 26235156 | [E] D2_b4_q54 | 12.819 billion | 1,191,132 |
| 26235156 | [E] D3_b8_q36 | 25.637 billion | 794,088 |
| 24628607 | [E] M6_b2_q108 | 8.928 billion | 3,029,292 |
| 24628607 | [E] D2_b4_q54 | 17.855 billion | 1,514,646 |
| 24628607 | [E] D3_b8_q36 | 35.711 billion | 1,009,764 |

D3 doubles D2 LDE work volume for a further one-third reduction in the query-word proxy. Commitment streams columns, so LDE work volume is not a claim that all these cells reside simultaneously. The proxy omits FRI, authentication-path sharing, OODS and numerical-GKR verification. Poseidon2 changes hash/Fiat–Shamir circuit work; this report supplies hash-independent geometry and makes no Poseidon cell or wall-time forecast. Both candidate profiles require new domains, FIXED roots and VKs, and retain their conjectured-security qualification boundary.

Executed gates: source census on both original bundles and both one-family declarations; independent Python GKR Plan layout agrees with the qualified 188288-byte GPU source-batch fixture. No proposed Ethereum proof was run.
