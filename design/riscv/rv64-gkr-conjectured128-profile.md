# OM31/GKR route: the `conjectured128_b2_q108_p20_fold4` PCS profile

Status: **default profile of the v3 GKR candidate route** (`rv64-word16-ethereum-gkr
produce-candidate | verify-candidate | verify-prefix-candidate`). Security model:
**128-bit CONJECTURED** security with ethSTARK-style FRI accounting, accepted by the
project owner on 2026-11-02. It is not a proven bound. `security_qualified` stays
`false`; no whole-protocol certificate exists. Recursion and wrap layers are
outside this document.

## Decision

| | conjectured128 (new default) | proven model (kept, by name) |
|---|---|---|
| Profile name | `conjectured128_b2_q108_p20_fold4` | `proven_beta2_q256_p0_fold4` |
| Receiver label | `experimental-om31-local-gkr-conjectured128-b2-q108-p20-fold4-engineering` | `experimental-om31-local-gkr-beta2-q256-p0-fold4-engineering` |
| Field / channel / hash | OM31 (degree 8), raw-mod Blake2s channel, Blake2s prefixed Merkle | same |
| log_blowup (blowup) | 1 (2) | 2 (4) |
| FRI queries | 108 | 256 |
| Proof of work | 20 bits | 0 |
| Fold step / last layer | 4 / degree bound 1 (log 0) | same |
| Security argument | ethSTARK conjecture: 1·108 + 20 = **128 conjectured bits** | #310 bounded unique-decoding review (`rv64-v3-bounded-security-review.md`) |

Rationale (owner + coordinator): target hardware is 4x RTX 5090 (32 GB). Blowup 2
halves the LDE/commit/DEEP work and the extended-trace VRAM per base proof, so two
to three 2^22 segment proofs fit one 32 GB GPU; a 20-bit grind is milliseconds on a
GPU; 108 queries keep the proof and the recursion leaf verifier small. Recursion and
wrap layers may choose a higher blowup with fewer queries; that is left to the
recursion track. Fold-4 is kept.

## How the profile is selected and bound

- **Selection is receiver policy.** The driver takes `--security-profile NAME`
  before the mode (default `conjectured128_b2_q108_p20_fold4`). Nothing in a proof,
  bundle metadata or `report.json` selects it. Unknown names fail
  (`UnknownOm31CandidateProfile`); the flag on a control mode fails.
- **Exact parameters.** `om31_security_candidate.configFor(profile)` is the only
  source of the PCS config. `worker_protocol.validateCandidateConfig` admits a
  rate-1 (blowup 2) candidate config **only** if it equals the conjectured profile
  exactly; any other query count, PoW, fold step or last-layer bound is
  `UnsupportedWideServicesConfig`. The blowup-4 family keeps its historical
  structural check (the proven profile plus fixture-sized test configs), so its
  bytes are unchanged.
- **Transcript and statement binding.** Every CPU/truth worker channel starts
  with `PcsConfig.mixInto` (PoW bits, blowup, queries, last-layer bound, fold step).
  The receiver requires `proof.config == receiver config`. For the conjectured
  profile the fixed-authority binding additionally hashes
  `profileIdentity(conjectured)` (SHA-256 over a distinct domain
  `rv64-om31-rawblake-native-localgkr-128-CONJECTURED-ethstark/v1`, the profile name,
  the channel profile identity, every PCS parameter, the conjectured bit count and
  the receiver caps) into the worker statement, the worker channel and the
  execution identity. Fixed setup is sealed at the profile's blowup, so the fixed
  identity and root differ as well.
- **Old bundles.** The proven profile mixes no new bytes: `profileIdentity(proven)`
  equals the historical `identity()` and is not added to statements. Bundles proved
  before this change verify with `--security-profile proven_beta2_q256_p0_fold4`;
  the proven V3 model replays byte-equal (`check_v3_model.py`).
- **Proof of work.** The OM31 PCS verifier checks the grind nonce after the last
  FRI commitment and before query derivation, then mixes the nonce
  (`core/pcs/verifier_family.zig`). That order is what allows the 20 bits to be
  credited to the query phase.

Tests (`services/gkr_local/conjectured_profile_test.zig`, in `test-riscv64-truth-gkr`):
parameter/name selection and rejection of every single-parameter deviation; a real
two-CPU + truth execution under the conjectured profile proves and verifies from
independently derived fixed authority; it is rejected by a proven-profile receiver,
by a receiver whose config and authority disagree, by a non-candidate receiver, by
a 107-query receiver, by a proof claiming 107 queries or the proven config, and with
a tampered PoW nonce in each CPU proof; the profile is bound in statement and channel.

## Security accounting (conjectured)

Exact-rational model:
`vectors/reports/rv64-composed-security-20261102/model.py --v3-source-bounds ...
--security-profile conjectured128_b2_q108_p20_fold4` (bundle mode, or
`--parameters-only` on the #310 reviewed envelope). Envelope: 18 native proofs
(7 CPU local-GKR + 11 truth), ≤ 7,444 columns, ≤ 7,751 constraints, traces ≤ 2^22,
≤ 5 samples per column, ≤ 36 local GKR instances with ≤ 26 variables, #310's
lookup degrees. Receipts: `vectors/reports/rv64-gkr-route-speedups-20261102/`.

**1. FRI / queries (the conjecture).** ethSTARK Conjecture (list decoding up to
capacity for the Reed–Solomon / circle code): a cheating prover passes one query with
probability at most the rate ρ = 1/2, i.e. 1 bit per query at blowup 2. One full
attempt passes with probability 2^-108; each attempt needs a fresh 20-bit grind, so
the success per random-oracle query is 2^-108 / 2^20 = **2^-128**. This term does not
grow with the number of proofs: every attempt targets one proof transcript. (A
single, non-grinding attempt across all 18 proofs fails with probability ≥ 1 −
18·2^-108 = 1 − 2^-103.8; this is the same per-work bound, not an extra loss.)

**2. Algebraic terms in OM31.** The challenge field has 2^248 elements; the raw-mod
channel's maximum point probability is μ = 3^8 / 2^256 = 2^-243.3. #310's degree
weights, with the DEEP/FRI domain at blowup 2 (2N instead of 4N):

| Term | weight | bits (μ·weight) |
|---|---:|---:|
| Joint cleared LogUp identity, all scopes | 1,482,915,616 | 212.9 |
| Conservative physical-pole allowance | 1,482,915,616 | 212.9 |
| GKR cubic sumchecks (7·36·3·26·25/2) | 245,700 | 225.4 |
| GKR instance / layer mixing | 6,916 | 230.6 |
| GKR late eta bindings | 252 | 235.3 |
| Composition random-coefficient mix | 139,518 | 226.2 |
| OODS circle correspondence (P·C·S·32N) | 8.99e13 | 197.0 |
| DEEP batching (P·C·S·2N) | 5.62e12 | 201.0 |
| FRI fold / curve (P·8·15·2N) | 9.06e9 | 209.2 |
| **Union** | | **196.9** |

These terms keep #310's conditional assumptions (nonzero cleared rational identities,
source integer/range/characteristic semantics, the GKR binding/late-mix argument).
In the conjectured regime the FRI commit-phase and DEEP terms are covered by the same
conjecture; the 2^-196.9 union leaves about 2^68 of room for any list-size factor
before it reaches 2^-128.

**3. LogUp-GKR and sumcheck.** Unchanged from #310's bounded review: the GKR sumcheck,
instance-mix and late-binding terms depend on the field, instance count and variable
count, not on the PCS rate. They contribute below 2^-225 each.

**4. Fiat–Shamir.** Ideal-hash assumptions for raw Blake2s (channel, PoW, Merkle) and
SHA-256 (identities); adaptive multi-scope BCS reduction with the conservative
per-scope collision term H·(T²+1)/2^256, H = 3·(18+7+1)+1 = 79, round bound
R = 2^22:

`eps(T) ≤ (T/2^20)·2^-108 + (T+2^22)·Σweights·μ + 79·(T²+1)/2^256`

| Total RO queries T | 2^20 | 2^64 | 2^100 | 2^120 | 2^128 |
|---|---:|---:|---:|---:|---:|
| Success per query (bits) | 128.0 | 128.0 | 128.0 | 127.6 | 121.7 |

Uniform over 1 ≤ T ≤ 2^120: success per query **2^-127.6**. The FRI/PoW term is
exactly 2^-128; the 0.4-bit loss is the conservative collision term (79·2^-136 at
T = 2^120), not the PCS. Near T = 2^128 the 256-bit hash reduction's constants are
insufficient, as already documented for the proven profile.

**Conclusion.** Conjectured FRI security 128 bits (1·108 + 20); algebraic OM31 terms
~2^-197; LogUp/GKR/sumcheck terms below 2^-225; overall per-work success ≈ 2^-127.6
for T ≤ 2^120 under the ethSTARK conjecture and ideal hashes. Comparison: the proven
profile's bounded review gives 2^-129.7 per query from a proven unique-decoding
query term (18·(41/64)^256 = 2^-160.3).

## What this does not cover

- The ethSTARK conjecture itself (no proof for circle FRI at rate 1/2 exists here).
- Independent audit; formal whole-protocol certificate.
- Outer recursion / wrap: their field, profile and error accounting are separate.
- The numerical instantiation is pinned to the block 24,628,607 V3 roster envelope;
  another guest or geometry needs its own run of the model.
