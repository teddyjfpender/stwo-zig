# Bounded terminal hash and Fiat–Shamir review

The claim is **128-bit security target under documented assumptions**. This
note is accounting for review, not a certificate, a new admission policy, or a
claim of failure probability below2^-128 for every adversary budget.
`security_qualified=false`; production and settlement admission remain closed.
The measured R6 and R7 roots establish implementation agreement and rejection
controls. They do not establish cryptographic assumptions.

## Exactly what changes

Only the final proof's PCS Merkle hash and Fiat–Shamir channel change. Native
proofs, their GKR/LogUp arguments, manifest challenges, full frames and ordered
P2 public root remain unchanged. All earlier recursive group/fold proofs remain
P2 when present. A final Blake proof is never fed into an existing P2 recursive
verifier: those circuits implement P2 hashing and a different transcript. Valid
P2 and Blake positive controls reject each other's formats. A new parent circuit
or settlement verifier would require a separately specified suite and review.

The terminal codec is selected by code, not a proof tag that dispatches into an
arbitrary verifier. R6 uses `STB26G01`, six claims and its original domain; R7
uses `STB28G01`, eight claims and a distinct domain. R7 keeps the genuine Dot,
Input, Var and range authorities. Its original P2 source identity also binds the
input-origin seal. No source root is truncated to32bytes. Both a real P2 FIXED
construction and an independent Blake FIXED construction are currently paid.

The key binds the suite identity, original complete source identity, and Blake
FIXED root. Original source identity binds ordered heights/widths, AIR authority,
producer fanout, public-output count and native source class. Source-only
reception independently reconstructs that authority; metadata supplies no VK.

## Concrete budgets

These are conservative engineering envelopes to audit against the implementation,
not newly enforced counters. Replays of identical hash inputs do not create new
*distinct* random-oracle queries. Wall-time costs and primitive compression calls
are different quantities. A long leaf message may require many compression
blocks although its full-message hash counts once in the hash-oracle model.

| Scope | Geometry/query envelope | Full-message hash budget |
| --- | --- | --- |
| Measured selected R6 terminal | largest source log24, b2 extension gives tree height25; four PCS trees; FRI heights strictly decrease | four trees `4*(2^26-1)` plus FRI `<2^27`, hence `<2^29` Merkle hash queries |
| Selected terminal receiver |144queries, height≤25, fold step≤4,≤16positions per fold opening; use twice the independent path bound | trace+FRI `<2^21` hash evaluations, before deduplication savings |
| Terminal FS transcript | P0, fixed144queries; roots/config/claims/OODS/FRI mixing and draws | reserve `<2^16` full-message mix/draw calls per proof |
| Prior native/internal P2 proof | conservative circle-tree height ceiling31, four PCS trees and geometrically decreasing FRI trees | `<2^35` Merkle hash queries per proof |
| Prior FS transcript | existing source cap `MAX_ROUND_COUNT=2^20`, local instances≤128 and GKR variables≤30 | reserve `2^20` mix/draw calls per proof, including local argument transcript work |
| Source/program identities | SHA-256 of explicit domains, code/image identities and canonical source metadata | reserve `<2^40` honest full-message hashes across the admitted execution; instrument before promotion |

For a binary tree of height h, count at most `2^(h+1)-1` leaf/internal hashes.
Summing *every* possible strictly decreasing FRI height0..h is conservative for
fold4. For receiver work use `2*q*(h+1)` per trace tree and
`2*q*16*sum(j=1..h+1)j` for FRI: at h25 the sum is1,647,360,<2^21.
This includes loose path duplication rather than assuming ideal multiproofs.

The selected log24 is measured in `source.json`; composition splitting reduces
the degree-+1 quotient to the same mask log before the b2 extension. R7 outer
keys explicitly cap all role logs at26. R6's base roles are also constrained by
gather mass below the M31 characteristic; the general engineering envelope above
uses the wider circle ceiling31 rather than silently assuming a new log26 guard.
Native caps currently include trace log22, public boundary log23, AIR degree≤5
and≤256workers. Larger or different source policies require redoing this table.

For N≤256 native workers and G≤N groups there are N native STARKs and
`2G-1` outer STARKs, including the terminal. Thus at most767 STARKs, of which
at most766 are prior native/internal P2 proofs. Do not apply the native256 cap
to the *combined* proof count. With the deliberately loose per-proof envelopes,
reserve `<2^46` honest P2 hash queries including additional source-FIXED setup,
and `<2^30` prior FS mix/draw calls. Actual selected runs have four native
proofs, one terminal, and zero intermediate fold proofs. Local GKR instances
add algebraic/transcript obligations; they are not extra FRI STARKs.

## Conditional error expression

Let `B`, `S` and `P` be **all distinct queries**, honest plus adversarial, to
Blake256, SHA256 and the P2 sponge model respectively. In idealized hash models,
include at least

```
Blake collision term: B*(B-1) / 2^257
SHA collision term:   S*(S-1) / 2^257
P2 output collision: P*(P-1) / (2*p^9), p=2^31-1
```

P2 also needs its permutation/sponge assumption: W24/R12/C12/D9 has a12-field
capacity and nine-field output. The output is about279bits, giving nominal
139.5-bit birthday work; Blake256 and SHA256 give nominal128-bit birthday work.
Switching the terminal to Blake therefore reduces nominal output-collision
margin. Its faster measurement does not justify omitting this term.

Honest query counts are **not an adversarial budget**. For example, allowing an
adversary2^80Blake queries gives collision probability on the order of2^-97,
not2^-128, despite the conventional128-bit birthday *work factor*. The target
label uses the work-factor convention and the documented proof-system
assumptions. It does not promise a universal2^-128 per-execution failure bound.
Any concrete deployment must declare adversarial query/time budgets too.

The complete expression must additionally union:

- all source-derived tuple/rational identity and pole terms, including zero-weight
  padded denominator slots and every prior native/local argument;
- each prior/internal/terminal FRI error under the selected FRI theorem;
- adaptive Fiat–Shamir/grinding/extraction loss and transcript collisions;
- P2 indifferentiability/permutation assumptions and any multi-target/hash-mode
  losses, plus external program/input identity assumptions.

Under the *simplified* per-STARK assumption `epsilon_FRI≤2^-144`, the767-proof
union is `<2^-134.4`. The products72*2 and144*1 alone do not prove that assumption
for the concrete Stwo FRI construction. One must account for actual code rate,
fold4, degree bounds, query sampling and transcript adaptation. No PoW amplification
or grinding benefit is claimed: P0 is explicit.

For the terminal lookup challenges the reused raw-mod OM31 channel has maximum
point mass `3^8/2^256`, about2^-243.32, rather than exactly1/p^8. Original
finite-characteristic/fanout/gather-mass checks and full Var/range closure stay in
force. Existing conditional ledgers and their raw-mod loss still apply; unchanged
AIR does not mean that these algebraic and FS terms can be discarded. Adversarial
attempts over alternative legal coefficient-length templates must be included in
the FS budget; a source-derived class key prevents authority substitution, not
all grinding over valid statements/classes.

## Exact promotion blockers

1. Independently audit these query envelopes and instrument actual Merkle/FS
   counters, including source-key setup and the complete prior-proof inventory.
2. Pin the FRI assumption/theorem and concrete adversarial-budget convention;
   compose native, GKR/LogUp, internal and terminal terms without double counting
   or treating the interactive bound as an automatic Fiat–Shamir theorem.
3. Review plain Blake leaf/node framing and lifted-tree geometry binding under
   the chosen hash model. Source-owned geometry is mandatory; a producer VK is
   never authority.
4. Promote only an explicit receiver-selected suite/format with all source-only
   inventory, terminal, cross-suite and mutation gates. No auto-detection from
   untrusted bytes and no shared default change.
5. Specify a new Solidity/settlement verifier if this suite is used on chain.
   Existing P2 verification and recursion do not accept a Blake terminal proof.
6. Keep cold P2-plus-Blake FIXED costs in benchmarks until a separately qualified
   materializer/cache removes them. No heavy-block speed claim follows from the
   selected-small measurements, and the tenfold heavy-block goal is still open.
