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
| 1 | absorb `S31CAS05`, outer version 5, XDM04 version 4 | protocol version |
| 2 | absorb profile words and the XDM04 source root | height and columns, log blowup, raw query count, source commitment |
| 3 | draw OOD seed and map to a checked circle point | source commitment |
| 4 | absorb claim tag and each profile-sized height claim array; draw batch coefficient | OOD claims |
| 5 | for each nonterminal height `i`: draw `α_i`, then absorb line root `i` | line layer `i` may depend on `α_i`; its root precedes `α_(i+1)` |
| 6 | draw final `α_(h−1)`; absorb terminal coefficients | all line commitments precede raw queries |
| 7 | draw raw positions, authenticate XDM04 source rows and every line pair, check every fold and terminal evaluation | channel state is published only if all checks succeed |

There is **no CAS05 proof-of-work nonce**. The experimental extractor's
channel type is the raw-output `Blake2sChannel`; the production S31 direct
Gate uses a distinct M31-reduced channel and two grinding stages. Its P07
transcript conclusions and parameters do not transfer to CAS05.

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
   identify interactive round count `R`, and prove freshness and binding with
   an explicit cross-role collision budget. XDM03 hashes have leaf/upper/
   insertion tags and line trees use prefixed Merkle hashes. Transcript root
   and field absorptions are not operation-tagged; a 32-byte root and two
   QM31 values produce equal bytes after the same digest. Fixed call order
   might suffice, but needs a reduction.
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
