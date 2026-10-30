# Explicit nonterminal execution with complete state continuity

Problem-match brief, before implementation.

**Task:** prove actual RV32 execution from an independently selected complete
incoming state to an independently selected complete outgoing state. Preserve
the guest, genuine unretired completion, all register windows and native/caller
WORD events. Neither a fake halt nor a producer replay receipt is authority.

**Inputs/model:** retained Ethereum ELF and 1.5–2.8 million initialized words,
32,768 instructions initially, then 128K/512K bounded windows. CPU field work,
committed cells, peak memory and artifact I/O matter. The source is the qualified
`block-v7-real-window-corpus-20261029`; its previous proofs use the older Merkle
partial-leaf route and are comparison oracles, not a new-path measurement.

| Candidate | Relationship | Cost/fit | Risk |
| --- | --- | --- | --- |
| Original partial-leaf Merkle roots | Existing exact implementation | Qualified, but repeated hash witness dominates | Expensive baseline |
| Read every final word through terminal events | Exact reduction | Millions of unnecessary RAM rows | Poor scaling |
| New next-row final-touch table | Exact alternative | Requires new masks, boundary cases and provider | More algebra/keys |
| Initial snapshot intervals plus state-delta LogUp | Chosen exact algebraic reduction | Two extra interaction planes; no new private main cells | Requires initial-value authority and complete challenge binding |

**Mapping (derived):** first-touch initialization is reconstructed from the
incoming snapshot, with no private-input exception. Existing sorted WORD AIR
enforces address/clock order and `previous.after = current.before`. For each
event and address, accumulate `1/D(address,after) - 1/D(address,before)`.
Internal values telescope. Equality to the independently computed outgoing
minus incoming snapshot sum therefore binds the complete final state; unchanged
addresses cancel during host preprocessing, and a changed untouched address
cannot disappear. Initial authority is essential: delta equality alone would
accept equal but incorrect initial/final values.

**Source:** the reciprocal multiset identity is the existing LogUp mechanism;
see [Haböck, logarithmic derivative lookups](https://eprint.iacr.org/2022/1530.pdf).
We reuse local original sorted-memory equations, interval provider, field
operations and PCS. No external implementation is copied. Tuple compression
and challenge sampling retain the existing cryptographic assumptions, not an
absolute collision-free claim. All event/count bounds stay below the base-field
characteristic; both snapshot digests and all original roots precede draws.

**Integration:** explicit window policy and joint-memory variant; 88 RAM main
columns remain, 29 interaction planes become 31. Existing terminal routes and
identities stay unchanged. Nonterminal halt memory starts zero and cannot become
nonzero at a real event: reuse original halt constraints with the sole allowed
clock zero, while authenticated source events have strictly positive clocks.
No terminal read is synthesized. Existing per-window PC/register/caller closure
remains mandatory.

**Complexity (derived):** ordered endpoint validation is O(snapshot words),
interval preprocessing O(nonzero RAM words log words), public delta evaluation
O(changed words). RAM overhead is eight base-field interaction columns and two
degree-four equations per packed row; no new relation draws, using the existing
five-limb WORD initial namespace under a distinct policy/epoch identity.

**Falsifier/qualification:** genuine native/Keccak/recovery windows must verify
after producer destruction; compare every original native/caller export. Attack
initial values, changed untouched cells, endpoints, clocks, halt, ordinal order,
physical sums and fully recommitted source substitutions. Test algebra against
an explicit per-address reference before original proofs. Canonical q70/pow26,
source manifest before builds, stage profiles/RSS/logical I/O on increasing real
windows; no full-block or recursive qualification until independently completed.

**Open:** complete recursive key/closure integration and bounded large-window
memory are separate gates. This design is not yet qualified or measured.
