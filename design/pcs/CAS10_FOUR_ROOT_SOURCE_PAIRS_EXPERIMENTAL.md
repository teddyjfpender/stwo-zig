# CAS10: four-root Gate source-pair custody

**Status:** experimental source-opening slice stacked on CAS09. This is not a
Gate AIR proof, a two-track FRI proof, or a production PCS mode. It assigns no
soundness bits and changes no release selector.

The honest prover commits four independent source trees using the production
`Blake2sPlainMerkleHasher` and lifted Merkle construction. The order is fixed,
main, interaction, composition. The verifier takes the four roots and the
FRI-extended column logs from an **external accepted transcript statement**;
the proof does not authorize its own roots. This slice does not itself perform
the fixed/main/interaction/composition challenge transitions. A future full
CAS10 verifier must retain their exact native order and use a versioned,
role-framed transcript.

For each externally supplied raw query `r` at lifting height `k`, the new
source opening authenticates both adjacent lifted leaves:

```text
(r & ~1, r | 1)
```

The lifted tree's native leaf projection maps these two leaves to a conjugate
pair in every shorter source column. One pair of leaf positions per raw query
therefore supplies both original values needed by the first circle fold at
all present source heights. Repeated raw positions stay repeated in the
queried-value arrays; the Merkle verifier deduplicates only its internal
authentication traversal. All eight composition columns are required and
opened under the fourth root.

The focused honest proof has one fixed, one main, one shorter interaction,
and eight composition columns. It commits four roots, decommits the lifted
pairs with duplicates, and verifies each tree's values against its root using
the production plain Merkle verifier. It also checks out-of-domain raw query
shape rejection. This proves only the implementation's local source-opening
custody for that shape. The test does not run the Gate AIR or test any
whole-oracle degree.

The next protocol slice must serialize this source-opening subproof and bind
it to a new post-OOD two-track FRI transcript. It must recompute each own
quotient from **its own** verifier-owned OOD claim, authenticate both FRI line
tracks, and check folds and terminal polynomials. CAS09's existing source root
uses a different Merkle hasher and one pre-OOD epoch; it cannot be substituted
for these four production plain roots. The published multi-domain theorem's
batch width is `M = max_i M_i`, where each domain batch is zero-padded to the
common width. If the reviewed Gate source-log-4 bucket's 193 columns map
uncompressed to one such batch, `M >= 193`; the own quotients may enlarge it.
The exact native-to-paper ensemble and `M` remain unproved. If the paper's
`D0=N B²` mapping also holds at `N=2^20`, then at `B>=2` and QM31 that
conditional width already makes the paper's batching error expression exceed
the selected `epsilon(T)/T <= 2^-96` target. Increasing
query count does not alter that term.

Focused check:

```sh
zig build --build-file src/prover/build.zig test-four-root-pair-openings -j4 -Doptimize=Debug
```
