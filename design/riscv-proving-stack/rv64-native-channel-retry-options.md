# Legacy native retry parity and new-profile options

Source audit only for the legacy repair options. No legacy channel or accepting
protocol is changed here. The additive raw-mod primitives are documented in
`rv64-raw-mod-channel-profile.md`; neither change establishes whole-protocol128.

## Existing discrepancy and state machine

`src/core/channel/blake2s.zig:91` hashes `digest || LE32(counter) || 00`, then
increments the wrapping u32 counter. `drawBaseFelts:267` rejects the ENTIRE
8-word block when any raw word is>=2p, i.e. `fffffffe` or `ffffffff`.
It retries with unchanged digest and the next counter. Scalar QM31 takes only
the first4 words of the first accepted block; bulk calls take two values per
accepted block, discarding an unused half at the end of an odd call.

`src/frontends/circuit/native_verifier/channel.zig:114` instead reduces the
selected words without enforcing any all8 rejection predicate. The header's
claimed fail-closed treatment is not implemented. This is a protocol equivalence
gap, not by itself a demonstrated AIR-unsoundness attack. It affects the native
leaf verifier and its reused GKR channel adapter alike. Raw query draws must NOT
be changed to retry: native `drawU32s`/query sampling accepts every raw block.

The GKR fragment at `logup_gkr/circuit_cost_main.zig:102` also seeds its channel
counter from a native checkpoint. A production leaf must derive that digest AND
counter from authenticated circuit prefix execution, not unchecked host advice.

## Exact cheap all8 predicate

A raw u32 wire is packed as `(low16, high16,0,0)` in QM31. Let A and B be the
packed constants for `fffffffe` and `ffffffff`. Define

    P(words) = product(i=0..7) (word[i]-A)*(word[i]-B).

QM31 is a field and the packed-u32 representation is injective. Therefore P=0
iff some raw word is forbidden. This needs15 extension multiplications per
block, not bit decompositions. Crucially, compute it BEFORE modulo reduction;
valid raw0/p must not alias forbidden2p. Existing Blake gate/u32 range authority
must continue constraining every packed hash output.

Skipped blocks require P=0. The chosen block requires P*inverse=1. That proves
every skip is justified and the chosen block is the FIRST valid one; merely
checking the chosen block permits challenge grinding. Unused words4..7 and an
odd call's unused second QM31 still participate in every validity predicate.

## Option1: public retry-count topology hints

For each receiver-known logical secure block, accept a bounded integer hint r.
Hash exactly r rejected blocks and one chosen block at consecutive counters.
Constrain every rejected P=0 and the chosen P nonzero. The hint is not trusted:
wrong skips, skipped valid blocks or an invalid chosen block cannot satisfy the
circuit. Counters can remain static host constants because the admitted count
vector fixes the graph, provided all values are constraint-checked as above.

Before constructing any graph/key, independently verify the hint vector's
expected length, per-draw cap, total cap and checked total graph/hash budget.
The number of logical draws derives from the receiver's admitted verifier
shape/control flow, not from a producer count. Avoid unbounded allocation or
loops on malicious hint metadata.

The receiver derives or admits the circuit/VK from trusted builder authority,
field/sampler profile, proof shape and bounded retry-pattern digest. The outer
leaf statement/key identity must bind this pattern; do not mix it into the
native Fiat–Shamir transcript. `rv64_recursion/root_admission.zig` currently
checks independently expected circuit hashes/layouts; extend that authority,
not a producer-self-admitted topology manifest. Cache immutable setup by that
complete identity, separately from each request's transcript/witness.

This hashes once in the common r=0 case and pays only actual retries. But it
creates pattern-specific topology/key classes and possible receiver setup cost.
A fixed registry containing only the zero-retry class is NOT complete retry
support. One practical alternative is a strict common no-retry class plus a
separately trusted fixed-budget retry fallback below, keeping only a small
number of reusable keys per admitted layout.

## Option2: fixed-K exact legacy fallback

For each secure block compute K candidate raw blocks at counters n..n+K-1.
Boolean selectors s[j] sum to1. Set skip[j]=sum(k>j)s[k] and constrain
skip[j]*P[j]=0. Constrain selectedP=sum(s[j]*P[j]) nonzero with ONE inverse.
Select the returned packed words and counter-after from the same selectors.
This constrains first-valid selection without inverting any rejected zero.
Unselected suffix blocks must not advance the actual channel counter.

The channel counter must become a constrained packed-u32 wire, not the current
host-only `n_draws`: add16-bit limbs with Boolean carries to obtain wrapping
counter increments; select the counter-after belonging to the accepted slot.
Raw draws advance once, and every mix/PoW nonce mix resets the counter to0.
A value-mode host shadow may generate hints but must never choose graph shape.
The NoValue and value graphs must be identical for every retry trajectory.

K is a receiver-owned topology/resource constant. Overflow rejects explicitly;
it never truncates to a different challenge. A finite fixed circuit cannot
provide unbounded native-loop completeness. Authorized larger fallback classes
can wrap the SAME native proof after a smaller class overflows. Both common and
fallback classes need independent root topology admission. Overflow probability
is a completeness/resource issue, not permission to charge an unmodeled
acceptance discrepancy to a128-bit soundness ledger.

## Option3: NEW degree8 biased raw-mod profile

The additive `core.channel.raw_mod_m31.Om31Channel` and matching circuit profile
consume one raw8-word block and reduce every word modulo p. They do not retry.
This is a newly tagged protocol profile, not a redefinition of legacy QM31.
Each field residue0/1 has3 u32 preimages, all others2. Max relative coordinate
density is rho=3p/2^32<1.5. For8 coordinates rho^8≈25.62890615, losing4.6797bits.
Under a separately established univariate degree d<=2^27, the algebraic bound is
rho^8*d/p^8≈2^-216.3203. Conditioning on other independent challenges preserves
this max-density bound; unions/adaptive Fiat–Shamir grinding still need their
own justified accounting. Exact uniformity is sufficient for the standard
bound, but not necessary if the proof uses this explicit density bound.

The raw hash must really be256-bit Blake output, not M31-reduced digests. OM31
field arithmetic, exceptional OODS seeds, FRI, PCS/Merkle binding, wire formats,
recursion and all whole-protocol terms remain separate gates. The QM31 additive
control loses2.33985bits and is not automatically nominal96-qualified.

## Cost comparison (source model, not a proving benchmark)

The retained historical GKR example makes348 logical scalar draws and1,038
Blake compressions, or83,040 G gates (10 rounds*8G per compression).

| Option | Extra hash work | Additional predicate/routing work |
|---|---|---|
| Hinted exact legacy |80G per ACTUAL rejected block; zero extra hashes at r=0|15 QM31 multiplications per block, plus selected inverse equality; independent pattern/key admission |
| Fixed K=2 legacy |27,840 additional G gates for348 draws (+33.5% of that fragment's hash gates)|All candidate predicates, one-hot words/counter routing and constrained counter carries |
| Fixed K=4 legacy |83,520 additional G gates for348 draws|Same fixed structure at larger budget |
| New OM31 raw-mod |One hash per OM31 value, no retry hashes/guards|Eight canonical reductions and degree8 arithmetic; not comparable to a full legacy leaf by hash count alone |

Bulk QM31 packs2 values per hash while OM31 packs1; scalar QM31 already spends
one hash and discards half. Comparison must use actual scalar/bulk call counts.
New degree8 verifier arithmetic/openings can dominate the removed retry cost.
Measure the equally secure FULL leaf before selecting a production protocol.

## Required adversarial qualification

- Each forbidden raw value in every position0..7; multiple bad words count as
  one rejected block, including unused upper halves and odd bulk tails.
- Zero, one and multiple retries; skipped VALID block; chosen INVALID block;
  wrong skip count, all-zero/two-active/non-Boolean selectors; overflow cap.
- Counter-after, following raw/query draws, counter wrap at2^32, mix reset,
  zero-bit PoW mix reset and no accidental query rejection.
- Exact reduction boundaries p-1,p,p+1,2p-1,2p,2p+1; packed predicate must
  distinguish valid0/p from forbidden2p even though reductions coincide.
- Fixed real Blake rejection fixture plus scripted raw-block predicate tests;
  mutable output/counter/skip witnesses must fail circuit constraints.
- Same NoValue/value topology for fixed-budget trajectories; hinted classes
  reject swapped/unadmitted patterns, producer keys and unauthenticated prefix
  digest/counters. Test both native leaf and GKR adapter completion/error paths.

An actual raw Blake fixture has zero digest, counter107289826, word2=ffffffff;
it is stored in the additive profile tests. Native legacy retries; the new
profile intentionally consumes that exact block once. No search runs in CI.
