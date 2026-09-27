# BLAKE3 compression constraint foundation

Task: make the seven-round compression schedule reusable by native execution and
native typed AIR authorship, with exact modulo-2^32 addition, XOR and rotation.
This advances the BLAKE3 migration; it does not switch production proof keys.

Canonical mapping: BLAKE3's ARX compression is 56 invocations of G, each containing
six binary additions and four XOR/rotations. A bit-decomposed ripple-carry adder
is an exact Boolean circuit representation; translating its Boolean relations to
M31 yields degree-two equations with integer sums at most 3, hence no modular
aliasing. XOR is x+y-2xy; rotated outputs are index permutations.

Candidates: existing limb/XOR-lookup Blake round AIR is the eventual efficient
provider candidate, but is not authored in the canonical RISC-V typed language.
A bit circuit is selected as a typed correctness oracle and shared operation
schedule, not as the production row layout. It has 704 input/witness bits per G
and avoids enormous XOR tables, but would be much too wide to select blindly.
Production must lower packed limbs/lookup providers and demonstrate exact
arithmetic and relation closure against this reference. Reusing BLAKE2's complete
scheduler is rejected: its schedule/round count and initialization differ.

Sources: BLAKE3 specification and the pinned Proofman blake3_core.rs inspected in
20260921-blake3-protocol-problem-match.md. No external code copied. Selected
transfer is the canonical seven-round message permutation, initialized state,
feedforward, and shared G operation schedule. The existing std BLAKE3 wrapper
remains the independently implemented native hash oracle.

Invariants: lossless u32 inputs; all witness bits constrained; carry out discarded
only at the word boundary; XOR rotations 16/12/8/7; exact message permutation;
block length <=64; fixed initialization and feedforward; no claim that a
compression permutation alone authenticates BLAKE3's chunk tree or transcripts.

Validation: independent standard-library hashes for all single-block lengths;
degree analysis and semantic digest for typed G; native/typed agreement on
zero, all-one, carry-heavy and random words; mutation of every witness bit plus
non-Boolean input rejection. Then integrate the bounded-limb provider and
framing/call relations before any recursive proof claim.

Prediction: this supplies a falsifiable arithmetic oracle for later packing,
not a speed improvement. Replacing production with this wide bit circuit without
measuring and qualifying the complete parent would falsify the design choice.
