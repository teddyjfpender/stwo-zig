# CAS05 transcript and the BCS/ROM proof boundary

CAS05/XDM04 is an experimental paired PCS. It is absent from production PCS
dispatch. [The S-two theorem map](https://github.com/starkware-libs/stwo/blob/dev/.agents/papers/llm/Stwo_Whitepaper.llm.md)
states the noninteractive BCS expression
`(T+R) max_i ε_i + 3(T²+1)/2^λ` for its specified interactive protocol and
random-oracle model. **That expression cannot yet be applied to CAS05.**
The CAS05 sparse query event, paired quotient degree reduction, and the
Fiat–Shamir/Merkle instantiation have no matching proved round errors.

The [source audit](../../scripts/check_cas05_bcs_join.py) records the exact
deterministic transcript schedule below. It fails on changes to a reviewed
source anchor and emits an explicit ledger of unfilled theorem inputs. It
does not infer Zig semantics, a random-oracle law, or a security level.

| Order | Verifier operation | What is fixed before the next draw |
| ---: | --- | --- |
| 1 | absorb `S31CAS06`, outer version 6, XDM04 version 4 | protocol version |
| 2 | absorb a profile tag and words, then a source-root tag and XDM04 root | height and columns, log blowup, raw query count, source commitment |
| 3 | draw OOD seed and map to a checked circle point | source commitment |
| 4 | absorb claim-group tag and each tagged, indexed, length-bound height claim array; draw batch coefficient | OOD claims |
| 5 | for each nonterminal height `i`: draw `α_i`, then absorb tagged line root `i` | line layer `i` may depend on `α_i`; its root precedes `α_(i+1)` |
| 6 | draw final `α_(h−1)`; absorb tagged, length-bound terminal coefficients | all line commitments precede raw queries |
| 7 | draw raw positions, authenticate XDM04 source rows and every line pair, check every fold and terminal evaluation | channel state is published only if all checks succeed |

There is **no CAS05 proof-of-work nonce**. The experimental extractor's
channel type is the raw-output `Blake2sChannel`; the production S31 direct
Gate uses a distinct M31-reduced channel and two grinding stages. Its P07
transcript conclusions and parameters do not transfer to CAS05.

## Why outer version 6 changed the bytes

Outer version 5 had a **real encoding ambiguity**. At the same channel digest
`d`, `mixRoot(root)` and `mixFelts([a,b])` both hashed `d || payload`, where
the payload is 32 bytes. If `root` was the canonical little-endian bytes of
the two QM31 values, the hash *input* was identical. This required no BLAKE2s
collision. The new version absorbs distinct eight-byte tags before source
roots, line roots, height claims, and terminal coefficients. It also absorbs
height/layer indices and array lengths. The wire magic remains `S31CAS05`
as the family identifier, while outer wire version 6 and transcript tag
`S31CAS06` reject old proofs and old challenge schedules.

For a fixed prior digest, two different role tags make the first hash inputs
distinct. If BLAKE2s has no collision on those inputs, their next digests
differ and so do the following payload hash inputs. This is a **conditional
input-separation argument**; it does not prove collision resistance or
adaptive random-oracle freshness over the whole transcript. The
[native test](../../src/tests/native/prover/paired_fri_bcs_fixture_test.zig)
exhibits the old ambiguity and checks the separated new digest states.

The typed transcript tags alone did **not** make transcript hashes disjoint
from every Merkle hash input. For example, the line tree uses a 64-byte prefix
`L = "leaf" || 60 zero bytes` and hashes a four-M31 row `r` as
`H(L || LE32(r₀) || LE32(r₁) || LE32(r₂) || LE32(r₃))`. At a hypothetical
channel digest `d = "leaf" || 28 zero bytes`, an absorption of three QM31
values `(0, 0, QM31(r₀,r₁,r₂,r₃))` hashes exactly the same 80-byte input:

```text
channel: d (32 B) || zero QM31 (16 B) || zero QM31 (16 B) || r (16 B)
line leaf: "leaf" || 60 zero bytes (64 B) || r (16 B)
```

Similarly, a six-QM31 claim can match the 128-byte line-parent input when
its digest equals the first 32 bytes of `"node" || 60 zero bytes`. The
CAS05 verifier and prover now check the digest immediately before either
claim absorption and reject the matching prefix. The operation is staged,
so rejection does not publish a partially advanced channel state.

Here is the complete input-length audit for a **`validateProof`-accepted
CAS05 proof**. A channel word absorption hashes 40 bytes, a root hashes
64 bytes, a query/challenge draw hashes 37 bytes, and a felt-array absorption
hashes `32+16n` bytes. XDM03 source leaves and inserted nodes have lengths
`10+4m` and `42+4m`, both 2 modulo 4; source upper nodes have length
72 bytes. A CAS05 line leaf has four M31 columns and hashes 80 bytes;
its parent hashes 128 bytes. Thus only felt arrays of length three or six
can equal a line hash input by length. Terminal arrays have power-of-two
length and cannot be three or six. The two digest-prefix checks exclude the
remaining claim cases by their first 32 bytes. This establishes byte-input
separation for that enumerated, validated CAS05 call roster, conditional on
the source roster remaining as checked. It does not prove that different
inputs have different BLAKE2s outputs, that adaptive hash queries are fresh,
or that the full BCS/ROM theorem applies. Native soundness bits stay unset.

## The precise raw-query fact

For a source domain of size `2^k`, one draw hashes
`digest || LE32(counter) || 0x00`, reads eight little-endian 32-bit words,
and takes `word & (2^k−1)` for each raw position. XDM04 admits
`4 ≤ k ≤ 22` and at most `2^14` raw positions. Thus the query phase uses
at most `ceil(2^14/8) = 2048` hash blocks. Repeated positions remain
logical query occurrences; XDM04 authenticates the exact raw sequence,
including duplicates and projections to lower heights.

**Conditional elementary lemma.** If these query hash inputs are fresh in an
ideal 256-bit random oracle even after the committed transcript is fixed,
then every low-`k`-bit word is exactly uniform because `2^k` divides
`2^32`. The eight words in a fresh block, and words in distinct fresh blocks,
are independent. If a predetermined bad subset has size `b`, all `q`
independent raw draws land in it with probability `(b/2^k)^q`. This is an
elementary query event only: the correct CAS05 bad set, adaptive committed
oracles, projected lower-height rows, and published FRI round error are still
unproved. Assuming independent hash outputs without excluding prior oracle
queries and cross-role input reuse would be circular.

S31's [QuerySampling.lean](https://github.com/teddyjfpender/s31/blob/main/formal/s31/S31/Gadgets/PcsFri/QuerySampling.lean)
proves the with-replacement finite fraction and a conditional union bound.
Its native refinement, Merkle budget, and Fiat–Shamir budget are explicit
premises. S31's [M31RejectionSampler.lean](https://github.com/teddyjfpender/s31/blob/main/formal/s31/S31/Gadgets/PcsFri/M31RejectionSampler.lean)
covers the production M31-reduced challenge sampler; CAS05's raw masked
query words do not use that sampler.

The shared channel now checks its u32 draw-counter increment before hashing.
If a secure-field rejection loop or any other caller reaches exhaustion, it
traps before reusing a draw input. Digest absorption resets the counter.
This closes deterministic *counter wrap*, not the random-oracle freshness
condition across digest epochs or against adversarial hash queries.

## Audited round and internal hash budget

The [round-cost checker](../../scripts/check_cas05_round_cost.py) follows the
version-6 complete statement-bound verifier and the dense host reference
prover. It source-checks the transcript audit, source-tree hash sites, and
line-tree verifier hash sites before evaluating the formulas. Its units are
**BLAKE2s finalizations (oracle calls)**, not BLAKE2s compression blocks,
wall time, or a security level. For a verifier-admitted XDM04 profile write
`k` for the largest log domain, `h` for the number of source heights, `β`
for log blowup, and `q` for raw queries. The caps are `2≤h≤8`,
`h+2≤k≤22`, `1≤β≤k−h`, `1≤q≤16384`, each column count `1..64`, and the
XDM04 fixed-row 64 MiB bound. An outer CAS05 wire has further byte limits.

There are exactly **`h+2` commitment-to-challenge barriers** in the native
transcript: source root → OOD seed; OOD claims → batch and first fold
challenges; `h−1` line roots → the next fold challenges; terminal coefficients
→ the entire raw-query vector. The batch and first fold challenges are two
sequential draws after one prover message. Counting *logical random
reductions* instead gives **`h+3`**: OOD, batch, `h` folds, and query.
Published Protocol 3 by itself has `h+2` reductions (batch, `h` folds,
query), with an explicit batch-oracle commitment between batch and first
fold. CAS05 adds OOD claims but derives its batch rather than committing it
as the paper does. Thus `h+2` is the exact native barrier count and `h+3`
is the exact logical draw-stage count; **neither is yet a justified value of
`R` in Theorem 6 for a CAS05 soundness claim**. A BCS refinement must specify
how the two same-message challenges are grouped and prove the derived-oracle
substitution and the new OOD reduction. Treating them as separate rounds may
require a virtual message and a new round-error argument.

The transcript makes exactly `8h+11` digest absorptions. It requests `h+2`
secure challenges and exactly `⌈q/8⌉` raw-query hash blocks. Secure draws use
rejection sampling, so `8h+11 + h+2 + ⌈q/8⌉` counts finalizations **only when
every secure sample succeeds on its first block**. There are `h+1` digest
epochs containing secure draws: OOD; batch plus first fold; and one after
each line root. The checked `u32` counter makes the hard upper bound for a
nontrapping execution

```text
transcript ≤ 8h+11 + (h+1)(2^32−1) + ⌈q/8⌉.
```

This intentionally enormous bound is deterministic. A useful smaller bound
would need an enforced rejection cap or a separately budgeted ideal-oracle
tail event; neither exists in CAS05 today.

The source Merkle verifier hashes `2q` presented leaves, at most `2q`
inserted nodes per later height (two finalizations each), and at most `2q`
nodes at each of the `k−h+1` upper levels. Its bound is **`2q(k+h)`**.
Line tree `j`, for `1≤j<h`, hashes at most `2q` leaves and `2q` parents at
each of its `k−j` levels, giving **`2q(1+k−j)`**. The complete verifier's
Merkle bound is therefore

```text
2q(k+h) + Σ[j=1..h−1] 2q(1+k−j).
```

The audit-only accepted-relation extractor reruns the full verifier, replays
the transcript, and reauthenticates source and line openings. Its internal
hash bound is twice the complete-verifier bound; it does not change the
production protocol or attacker query budget. For the dense host prover,
where `k≤16`, the full source tree uses exactly
`3·2^k−2^(k−h+1)−1` finalizations, and its `h−1` full line trees use
`Σ[j=1..h−1](2·2^(k−j)−1)`. These host counts do **not** extend the dense
prover's admission to the verifier's `k=22` maximum.

For a hand check, take `k=7,h=3,β=2,q=13` and two columns at each height.
There are five native barriers, six logical reductions, 35 absorptions, five
secure challenges, and two query blocks. With no secure rejection, the
transcript uses 42 hashes. The source verification upper bound is 260 and
the two line bounds are 182 and 156, so the complete verifier uses at most
**640** internal hashes in that case. The dense host trees use exactly 351
source and 190 line hashes. The checker prints these terms separately.

At the broad verifier caps `k=22,h=8,β=1,q=16384` with one column per
height, the Merkle upper bound is 5,341,184; the no-rejection transcript
uses 2,133 hashes. This is a structural budget for any accepted proof with
those dimensions, not a feasible dense-host-prover claim. The hard
nontrapping transcript bound is far larger because of unchecked secure
rejection loops.

**`T` remains the adversary's external random-oracle query budget.** The
internal prover/verifier counts above are separate; neither can be silently
substituted for `T` in Theorem 6's expression. A full game must account for
the adversary's ability to query the same BLAKE2s oracle on transcript and
Merkle inputs, including cross-role collisions and freshness. The
round-by-round errors and native security bits remain unset.

Run `python3 -B scripts/check_cas05_round_cost.py --k 7 --h 3
--log-blowup 2 --queries 13 --columns 2,2,2` and
`python3 -B -m unittest scripts.tests.test_cas05_round_cost -v`.

For a hand example, take `h=3`, `k=7`, `q=13`. The transcript draws `α₀`,
absorbs line root 0, draws `α₁`, absorbs line root 1, draws `α₂`, absorbs
terminal coefficients, then consumes two 256-bit query blocks. Its first
13 low-seven-bit words are 13 raw positions in `[0,127]`; repeated positions
are legal. A fixed bad set of 64 positions would give `2^-13` **only under
the conditional lemma**, with no claim about whole-proof soundness.

## Open BCS theorem inputs

1. Specify the exact CAS05 interactive relation and prove its per-round
   `ε_i`, including sparse two-row query projections, paired degree-corrected
   quotient, normalized insertion, terminal degree, and conditional OOD
   support. The standard multi-domain FRI formula is not a substitution.
2. Prove correspondence from every accepting native path, canonical byte
   decoder, source and line commitments, and channel execution to those
   interactive rounds. The current source audit and successful differential
   tests are narrower evidence.
3. Specify the random-oracle/BCS game for the *same* raw BLAKE2s function in
   transcript and both Merkle trees. Bound all adversarial hash work `T`,
   refine the counted native barriers to the theorem's `R`, and prove freshness and binding with
   an explicit cross-role collision budget. XDM03 hashes have leaf/upper/
   insertion tags and line trees use prefixed Merkle hashes. The CAS05
   transcript's root and field roles now have distinct tags. A reduction must
   still cover adaptive transcript states, prove the accepted-input roster
   refinement above, all Merkle inputs, and collisions in the shared hash
   function.
4. Prove the exact query law under adaptive transcript sampling, including
   all raw occurrences and overlapping lower-height projections. A fixed
   source schedule and a near-wrap test do not establish this distribution.
5. Select a conservative profile only after all premises above are discharged
   and the complete error expression meets the target. No CAS05 `λ`,
   soundness bits, or production admission are currently assigned.

Run `python3 -B scripts/check_cas05_bcs_join.py` to inspect the JSON ledger.
`--require-proven` deliberately exits nonzero while these inputs are open.
Run `python3 -B -m unittest scripts.tests.test_cas05_bcs_join -v` for the
hostile source controls.
