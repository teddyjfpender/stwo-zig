# Adjacent-height paired FRI cascade: experimental design

This brief specifies an iterative verifier for source heights `k, k-1, …, k-(h-1)` with a common blowup exponent `b`. It extends the fixed two-height arithmetic of P2F02, with a one-root transposed source tree at every height. The [S-two whitepaper Protocols 3–4 and Eq. 68](https://www.researchgate.net/publication/407022099_S-two_Whitepaper) are the target; no security theorem is claimed for the native codec.

The later [sparse CAS05/XDM04 opening](SPARSE_CASCADE_EXPERIMENTAL.md) authenticates only two source and line rows per height. This brief continues to describe the CAS04 full-fiber mechanics harness and its limits.

## Row geometry and one sampled query

Let `h >= 2`. Draw one uniform raw row `r` from the largest bit-reversed circle domain of size `2^k`. Set `base = r & ~(2^h-1)`. At source height `i`, authenticate `2^(h-i)` rows starting at `base >> i`; this is the full local fiber bundle used by all remaining folds. Each projection removes the next squaring-fiber bit while preserving the native sign bit. The actual sampled point traces through circle doubling; opening the whole fiber bundle supplies the conjugate siblings needed to check every local fold. A production theorem must still prove the bundle-query event bound, rather than assume independent checks.

At fold step `i=0`, pair adjacent largest-height circle words and check the first committed line layer. At each later step `i=1,…,h-1`, pair words of the previous line layer and insert a pair of height-`i` circle words:

```text
T_i(j) = FoldLine(L_i(2j), L_i(2j+1); x_i(j), alpha_i)
       + alpha_i² FoldCircle(H_i(2j), H_i(2j+1); y_i(j), alpha_i).
```

Here the native inverse butterfly is `N(a,b;u,alpha)=a+b+alpha*(a-b)/u`; the published normalized butterfly is `F=N/2`. Let `C_i` be the native line after `i` folds and `P_i=C_i/2^i`. At insertion height `i>=1`, the current native recurrence `C_(i+1)=N(C_i)+alpha_i² N(H_i)` therefore implies

```text
P_(i+1) = F(P_i) + alpha_i² * 2^-i * F(H_i).
```

The published Eq. 68 insertion has coefficient `alpha_i²` on its unscaled height-`i` source batch. Exact correspondence thus needs an explicit `2^-i` source-batch rescaling in the published model, or a `2^i` insertion multiplier in the native model, followed by a source/batch degree and commitment refinement. The scalar identity is tested at `i=1,2,3`; this version has **not** made that protocol change. For `i<h-1`, `T_i` is authenticated against the next committed line root. At `i=h-1`, it must equal the terminal polynomial evaluated at the projected line point. The terminal degree bound is `2^(k-h-b)`; the verifier accepts exactly that many ordered coefficients and checks the local evaluations. A full conservative profile must also enforce the paper's small terminal bound `B`.

The largest source bundle has `2^h` rows. Across all source heights this is `2^(h+1)-2` rows per raw query; line layers add `2^h-2` rows. This is exactly 8/4/2 source rows and 4/2 line rows for `h=3`. **This exponential full-fiber layout is a small-geometry mechanics harness, not a scalable proving protocol.** Near a full cascade from a largest domain around `2^20` rows to a small terminal, it would open on the order of `2^20` source rows *per query*. The experimental implementation caps `h` at 8 and `k` at 16, allocates dense `O(2^k)` Merkle level arrays, and recomputes domain and terminal data within raw-query loops. A production path needs a per-layer two-row query trace with separately authenticated siblings (`O(h)` rows per query), sparse authentication maps, and cached domains/twiddles/terminal evaluations. That alternative still needs its own transcript and theorem mapping.

Source values at each height are authenticated before any quotient or fold answer is used. Per source row, the batch is `f_0 + lambda*q_0 + lambda²*f_1 + lambda³*q_1 + …`, with each `q_j` derived from that authenticated `f_j` and its own OOD claim.

## One-root XDM03 source wire

```text
S31XDM03 | version=3:u16 | reserved=0:u16 | total_len:u32
largest_log:u32 | height_count:u16 | reserved=0:u16 | query_count:u32
column_count:u16[height_count] | transposed_source_root:[32]u8
for each sampled raw query:
    raw_row:u32
    for height i=0..height_count-1:
        original_source_values:M31[2^(height_count-i)][column_count[i]]
witness_count:u32 | shared_sibling_hashes:[32]u8[witness_count]
```

All integers are little-endian. Largest values are leaves. At tree level `k-i`, the two child hashes combine and the height-`i` values are inserted into that node for every `i>=1`; higher nodes use an ordinary two-child hash. Native bit-reversed child positions are `c0(j)=(j&1)+4*(j>>1)`, `c1(j)=c0(j)+2` except the root pair. The verifier reconstructs every opened subtree from all supplied heights, then consumes one sorted, compressed sibling multiproof above the lowest inserted level. Repeated raw queries must agree at every overlapping node. XDM03 has fresh leaf, insertion, and upper-node Blake2s tags, a 64 MiB wire cap, strict canonical M31 parsing, and a preallocation bound on the total source values. An outer verifier receives source values only after the complete expected-root and expected-query check succeeds.

## Transcript and wire staging

An outer version selects the number of heights before replay. The verifier compares every source root, OOD claim, degree bound, column count, and query count with an independently supplied public statement. It then stages the entire transcript: bind version and source roots/profile; draw and check one OOD point; bind claims and draw one shared `lambda`; for each fold step draw `alpha_i` and mix the next line root if one exists; mix exact terminal coefficients; draw raw queries. Source and line Merkle authentication plus all fold checks occur before the staged channel is published. No lower-level source fragment or caller-constructed answer slice is a complete verifier entry point.

`S31CAS04` is the strict, canonical experimental outer encoding. Its header includes magic, version 4, zero reserved fields, exact total length, profile and per-height column counts, then the source root, sampled OOD point, claims, nested XDM03 byte length and bytes, line roots/queried coordinates/witnesses, and terminal coefficients. Every field element, including values inside XDM03, is parsed canonically before transcript replay. The sole complete wire entry point requires an independently supplied statement containing the expected profile, source root, and claims; it authenticates source and line openings internally and publishes the caller's transcript only after all checks succeed. P2F01/P2F02 and production PCS do not dispatch this magic.

The tree inserts values at every smaller-height internal level and authenticates the projected query trace under one root. `src/core/pcs/paired_cascade_experimental.zig` stages the complete transcript, verifies XDM03 internally, derives every own-quotient batch, authenticates each line layer, and iterates the same fold transition through the terminal polynomial. `src/prover/pcs/paired_cascade_experimental.zig` constructs deterministic three- and four-height fixtures. The tests reject truncated/trailing/noncanonical bytes, versions, shape/statement mismatch, transcript divergence, invalid openings, and a validly opened false terminal fold. Production remains fail-closed.

## Measured native fixtures

These are exact deterministic test sizes. The payload subtotal is XDM03 source wire + all queried line coordinates (`4` bytes per M31 coordinate) + line roots + line witness hashes + terminal QM31 coefficients. The final column is the complete `S31CAS04` encoding, including sampled point, claims, profile, lengths, and framing.

| Source rows | Raw queries | XDM03 source wire | Line witness hashes | Queried line coordinates | Payload subtotal | Complete CAS04 wire |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 32 / 16 / 8 | 5 | 434 B | 1 + 1 | 480 B | 1058 B | 1236 B |
| 64 / 32 / 16 / 8 | 3 | 572 B | 2 + 2 + 2 | 672 B | 1548 B | 1752 B |

The three-height fixture uses `f=x` at the first two heights and a constant at the third; the four-height fixture adds a constant at the fourth. Both end in one terminal QM31 coefficient. The query counts are tiny mechanics checks. No proving-time speedup, production wire advantage, or security level follows from these numbers.

## Remaining proof obligations

The native two-point quotient degree/correlated-agreement reduction, conditional OOD distribution, concrete Blake2s/Fiat–Shamir BCS game, derived-oracle substitution, exact normalized source-batch correspondence, full-domain/coset checks, PoW and conservative error bound all remain open. A finite counting lemma gives a conditional bridge for *ideal independent uniform* raw draws: when every row in each selected bundle is checked, the set of draws whose bundle hits fixed bad rows includes those bad rows, so the probability all `s` draws miss bad bundles is at most `(good-row density)^s`. The native full-bundle acceptance implication and masked Fiat–Shamir draw distribution remain separate proof obligations. This conditional lemma does not make the exponential bundle layout viable. A three-height fixture or a terminal with only a few coefficients establishes no proven security bits.
