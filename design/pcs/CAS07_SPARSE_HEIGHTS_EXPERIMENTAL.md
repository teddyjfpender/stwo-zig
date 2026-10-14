# CAS07/XDM05: candidate sparse-height geometry

This experiment extends the isolated CAS05/XDM04 paired-FRI harness to a
one-height source and source rosters with absent interior heights. The new
outer bytes use `S31CAS07`/version 7; the nested source opening uses
`S31XDM05`/version 5. CAS05/XDM04 and the production legacy format are
unchanged. The production format gate reserves the CAS07 magic against
legacy or CAS05 parsing; no production verifier selects CAS07.

## The representation

Let the largest source circle domain have `2^k` rows. Source height `i` has
domain `2^(k-i)` and a vector of `c_i` columns. A profile has `H` positions,
one at every integer height `0..H-1`; its first and last counts are positive.
An absent interior height has **`c_i=0`**, an empty claim vector, and no
source words. The height still exists in the folding schedule. This is a
different representation from a present all-zero source column.

For a native transposed Merkle node at source height `i`, let `L,R` be its
two squaring-fiber children. XDM05 computes

```text
if c_i > 0: node = hashInserted(L, R, row_i[0..c_i])
if c_i = 0: node = hashUpper(L, R)
```

The second case is the ordinary upper-parent hash. It does not call
`hashInserted` with an empty or zero-filled row. Leaves require `c_0>0`;
levels above the last source height always use `hashUpper`. An XDM05 opening
still carries the same two adjacent source rows per sampled query at every
height. An absent row contributes zero bytes, while missing child hashes are
provided by the ordered Merkle witness as at present heights. The verifier
rejects an inconsistent duplicate row, unused or missing witness, wrong root,
profile, query, canonical field element, version, or total length.

The source/line pair indices remain `b_i(r)=2 floor(r/2^(i+1))`. For each
height, including an absent one, CAS07 consumes one challenge `α_i` and one
fold. Write `P(a,b,u,α)=a+b+α(a-b)/u`, with the native unnormalized
butterfly. If `Q_i^0,Q_i^1` are the independently recomputed paired source
answers, the checked relation is

```text
F_0 = P(Q_0^0, Q_0^1, y_0, α_0)
F_i = P(L_(i-1)^0, L_(i-1)^1, x_i, α_i)
      + α_i² P(Q_i^0, Q_i^1, y_i, α_i)       (i > 0)
```

For `c_i=0`, the claim and answer arrays are empty/zero, so the inserted
term is identically zero and the line fold remains. Skipping the challenge,
line layer, or query projection would change the protocol. For `H=1`, there
are no intermediate line commitments: the sole circle fold directly becomes
the revealed terminal line polynomial. The proof still samples its one
challenge and checks every sampled source pair against that polynomial.

## Gate geometry and cost

The current Gate roster's log sizes and column counts map to `k=20`, `H=17`:

| Source log size | Height `i` | Columns |
| ---: | ---: | ---: |
| 20 | 0 | 51 |
| 18 | 2 | 8 |
| 16 | 4 | 15 |
| 14 | 6 | 8 |
| 9 | 11 | 28 |
| 8 | 12 | 8 |
| 4 | 16 | 193 |

Ten intermediate heights have `c_i=0`. The candidate cap is `H<=20`,
`k<=22`, `c_i<=256`, with a 64 MiB proof-wire bound. With blowup log 2,
the Gate shape has a two-coefficient terminal polynomial. The focused test
validates this full *profile*; it does not construct the full Gate proof or
claim that its AIR columns are mapped to this roster.

| Gate source-only count | Value |
| --- | ---: |
| Present source field words | 56,708,112 |
| Present source bytes | 216.32 MiB |
| Resident transposed tree hashes | 64.00 MiB |
| Source-plus-tree estimate | 280.32 MiB |
| Explicit one-column zero fillers at ten gaps | 2.68 MiB extra source |
| Sparse source-wire saving against those fillers | 80 bytes per raw query; 2,560 bytes at 32 queries |

The host commitment limits that source-plus-tree estimate to 384 MiB. It
does **not** bound the complete prover: paired batches, intermediate FRI line
trees, source copies, the outer proof, and allocator overhead also reside in
memory. The tree still has the same number of nodes, and CAS07 still performs
all 17 folds. Zero-column gaps mainly avoid filler column work and bytes;
these figures do not demonstrate a large speedup. A complete Gate cost run
and a reliable peak-memory cap remain required.

## Evidence and admission gaps

The focused `test-xdm05-sparse-heights` suite authenticates H=1 and a gapped
H=4 tree, checks `hashUpper` against a present zero-column root, measures
source-wire savings, and attacks version, profile, and opened values. It
also opens the exact Gate height positions `0,2,4,6,11,12,16` with one
column at each present height on a `2^20`-row top domain. This exercises
the 17-level topology but does not construct Gate's actual 311 columns.
`test-cas07-sparse-heights` proves and verifies H=1 and gapped H=4 complete
candidate proofs; it rejects a wrong statement, old-format interpretation,
wrong version, a changed candidate S31 roster prelude, and honestly
committed but false line/terminal data. These are finite implementation
tests, not a PCS soundness proof.

The S31 audit preflight accepts a caller-supplied Gate manifest. Its roster
derivation is deterministic, but the API alone does not establish that the
manifest came from the compiler or installed verification key. Production
must reconstruct and bind that manifest within its trusted key/statement
path before selecting any candidate PCS mode.

The published-paper and existing CAS05/XDM04 refinements do not transfer
automatically. Admission requires a new sparse-height source commitment and
row-custody refinement, including the `hashUpper` branch; the H=1 terminal
case; a polynomial-degree and normalized-fold argument for zero batches;
the actual Gate source-to-AIR/claim mapping; complete prover memory and cost
qualification; and a conservative BCS/ROM and paper theorem instantiation.
The target is a published-proof work-factor bound `ε(T)/T <= 2^-96` for a
declared, justified hash-query budget `T`. `T=2^32` is only a provisional
paper-fixture illustration. Native proven security bits remain unknown and
production admission remains closed.

Focused checks:

```sh
zig build --build-file src/prover/build.zig test-xdm05-sparse-heights test-cas07-sparse-heights -j2 -Doptimize=ReleaseSafe
```
